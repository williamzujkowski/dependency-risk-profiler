"""Analyzer for Go dependencies."""

import logging
import re
from typing import Dict, List, Optional

from ..analysis_helpers import analyze_repository
from ..go_modules import GoModuleResolver
from ..models import DependencyMetadata
from .base import BaseAnalyzer
from .common import cloned_repo, fetch_json

logger = logging.getLogger(__name__)


class GoAnalyzer(BaseAnalyzer):
    """Analyzer for Go dependencies."""

    def __init__(self, timeout: int = 30):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        # Cache for package metadata
        self.metadata_cache: Dict[str, Dict[str, object]] = {}
        # Module path -> repository. A module path is an import path, not a
        # repository URL: see ..go_modules for the three rules between them.
        self.resolver = GoModuleResolver()

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Go dependencies and collect metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        repositories = self._resolve_repositories(dependencies)
        if self.clone_repos:
            self._analyze_repositories(dependencies, repositories)
        return dependencies

    def _resolve_repositories(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, List[str]]:
        """Collect proxy metadata and map each module to its repository.

        Returns:
            Repository URL -> the dependency names hosted in it. Modules that do
            not resolve are absent, so their repository-derived signals stay
            unmeasured rather than guessed.
        """
        repositories: Dict[str, List[str]] = {}
        for name, dep in dependencies.items():
            logger.info(f"Analyzing Go package: {name}")
            # Set the OSV ecosystem explicitly; the URL heuristic only matches
            # module paths that happen to contain a "go" token, so packages
            # like github.com/sirupsen/logrus would otherwise misroute to PyPI.
            dep.additional_info["ecosystem"] = "golang"

            try:
                # Get latest version from proxy.golang.org. This uses the full
                # module path, major-version suffix included — that is what the
                # module proxy is keyed on.
                latest_version = self._get_latest_version(name)
                if latest_version:
                    dep.latest_version = latest_version
                    # Store minimal metadata in cache
                    self.metadata_cache[name] = {
                        "name": name,
                        "latest_version": latest_version,
                    }

                repository = self.resolver.resolve(name)
                if repository is None:
                    logger.debug("No source repository resolved for %s", name)
                    continue
                dep.repository_url = repository.url
                if repository.subdirectory:
                    # Many modules can share one repository; record where this
                    # one lives so a shared repository URL is not confusing.
                    dep.additional_info["module_subdirectory"] = repository.subdirectory
                repositories.setdefault(repository.url, []).append(name)
            except Exception as e:
                logger.error(f"Error analyzing {name}: {e}")

        return repositories

    def _analyze_repositories(
        self,
        dependencies: Dict[str, DependencyMetadata],
        repositories: Dict[str, List[str]],
    ) -> None:
        """Clone each repository once and analyze every module it hosts.

        Subdirectory modules mean one repository can back dozens of
        dependencies; cloning per repository rather than per dependency keeps
        that from multiplying the network cost by the same factor.
        """
        for repo_url, names in repositories.items():
            # Clone the repository into a self-cleaning temp dir
            # (skipped for org scans, which use API signals instead).
            with cloned_repo(repo_url) as clone_result:
                if not clone_result:
                    continue
                repo_dir, _ = clone_result
                for name in names:
                    try:
                        # Helper avoids circular imports.
                        dependencies[name] = analyze_repository(
                            dependencies[name], repo_dir
                        )
                    except Exception as e:
                        logger.error(f"Error analyzing repository for {name}: {e}")

    def _get_latest_version(self, package_name: str) -> Optional[str]:
        """Get the latest version of a Go package.

        Args:
            package_name: Name of the Go package.

        Returns:
            The latest version string, or None if fetching failed.
        """
        # Query the Go module proxy's JSON endpoint instead of scraping HTML —
        # it is stable and version-correct (pseudo-versions, +incompatible).
        # The proxy escapes uppercase letters in the module path as "!<lower>".
        escaped = re.sub(
            r"[A-Z]", lambda match: "!" + match.group(0).lower(), package_name
        )
        data = fetch_json(f"https://proxy.golang.org/{escaped}/@latest", self.timeout)
        if isinstance(data, dict):
            version = data.get("Version")
            if isinstance(version, str) and version:
                return version
        return None
