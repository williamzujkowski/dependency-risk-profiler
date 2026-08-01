"""Analyzer for Node.js dependencies."""

import logging
from typing import Dict, Optional

from ..analysis_helpers import analyze_repository
from ..models import DependencyMetadata
from .base import BaseAnalyzer
from .common import (
    check_for_vulnerabilities,
    cloned_repo,
    fetch_json,
    is_cloneable_repo_url,
)

logger = logging.getLogger(__name__)


class NodeJSAnalyzer(BaseAnalyzer):
    """Analyzer for Node.js dependencies."""

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
        """Analyze Node.js dependencies and collect metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info(f"Analyzing npm package: {name}")
            # Route vulnerability lookups to the npm OSV ecosystem explicitly;
            # relying on the repository-URL heuristic misroutes packages whose
            # repo URL lacks an "npm"/"node" token (e.g. lodash) to PyPI.
            dep.additional_info["ecosystem"] = "nodejs"

            try:
                # Get npm package information
                npm_data = self._get_npm_package_info(name)
                # Store in cache for other analyzers to use
                if npm_data:
                    self.metadata_cache[name] = npm_data

                if npm_data:
                    # Update metadata from npm
                    if "version" in npm_data:
                        dep.latest_version = npm_data["version"]

                    if "deprecated" in npm_data and npm_data["deprecated"]:
                        dep.is_deprecated = True

                    if "repository" in npm_data and npm_data["repository"]:
                        repo_url = npm_data["repository"]
                        if isinstance(repo_url, dict) and "url" in repo_url:
                            repo_url = repo_url["url"]

                        # Clean repository URL
                        repo_url = repo_url.replace("git+", "").replace(".git", "")
                        if repo_url.startswith("git@github.com:"):
                            repo_url = f"https://github.com/{repo_url[15:]}"

                        dep.repository_url = repo_url

                    # Check for known vulnerabilities
                    dep.has_known_exploits = check_for_vulnerabilities(name, "npm")

                    # Get additional info from GitHub if available
                    if self.clone_repos and is_cloneable_repo_url(dep.repository_url):
                        # Clone the repository into a self-cleaning temp dir.
                        with cloned_repo(dep.repository_url) as clone_result:
                            if clone_result:
                                repo_dir, _ = clone_result

                                # Helper avoids circular imports.
                                dep = analyze_repository(dep, repo_dir)

            except Exception as e:
                logger.error(f"Error analyzing {name}: {e}")

        return dependencies

    def _get_npm_package_info(self, package_name: str) -> Optional[dict]:
        """Get package information from npm registry.

        Args:
            package_name: Name of the npm package.

        Returns:
            Dictionary with package information, or None if fetching failed.
        """
        # Handle scoped packages
        if package_name.startswith("@"):
            encoded_name = f"@{package_name.split('@')[1].replace('/', '%2F')}"
        else:
            encoded_name = package_name

        url = f"https://registry.npmjs.org/{encoded_name}"
        return fetch_json(url, self.timeout)
