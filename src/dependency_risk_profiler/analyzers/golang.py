"""Analyzer for Go dependencies."""

import logging
import re
from typing import Dict, Optional

from ..analysis_helpers import analyze_repository
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
        self.metadata_cache = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Go dependencies and collect metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info(f"Analyzing Go package: {name}")
            # Set the OSV ecosystem explicitly; the URL heuristic only matches
            # module paths that happen to contain a "go" token, so packages
            # like github.com/sirupsen/logrus would otherwise misroute to PyPI.
            dep.additional_info["ecosystem"] = "golang"

            try:
                # Get latest version from proxy.golang.org
                latest_version = self._get_latest_version(name)
                if latest_version:
                    dep.latest_version = latest_version
                    # Store minimal metadata in cache
                    self.metadata_cache[name] = {
                        "name": name,
                        "latest_version": latest_version,
                    }

                # Check if GitHub repository
                if "github.com" in name:
                    # Extract GitHub repo path
                    github_path = re.sub(r"^github\.com/", "", name)

                    # Format repository URL
                    repo_url = f"https://github.com/{github_path}"
                    dep.repository_url = repo_url

                    # Clone the repository into a self-cleaning temp dir
                    # (skipped for org scans, which use API signals instead).
                    if self.clone_repos:
                        with cloned_repo(repo_url) as clone_result:
                            if clone_result:
                                repo_dir, _ = clone_result

                                try:
                                    # Helper avoids circular imports.
                                    dep = analyze_repository(dep, repo_dir)
                                except Exception as e:
                                    logger.error(
                                        f"Error analyzing repository for {name}: {e}"
                                    )

            except Exception as e:
                logger.error(f"Error analyzing {name}: {e}")

        return dependencies

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
