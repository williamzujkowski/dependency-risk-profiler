"""Analyzer for Node.js dependencies."""

import logging
from typing import Dict, Optional

from ..models import DependencyMetadata
from ..scorecard.branch_protection import check_branch_protection
from ..scorecard.dependency_update import check_dependency_update_tools
from ..scorecard.security_policy import check_security_policy
from ..scorecard.signed_commits import check_signed_commits
from .base import BaseAnalyzer
from .common import (
    check_for_vulnerabilities,
    check_health_indicators,
    clone_repo,
    count_contributors,
    fetch_json,
    get_last_commit_date,
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
                    if dep.repository_url and ("github.com" in dep.repository_url):
                        # Try to clone the repository
                        clone_result = clone_repo(dep.repository_url)

                        if clone_result:
                            repo_dir, _ = clone_result

                            # Get last commit date
                            last_commit_date = get_last_commit_date(repo_dir)
                            if last_commit_date:
                                dep.last_updated = last_commit_date

                            # Count contributors
                            contributor_count = count_contributors(repo_dir)
                            if contributor_count:
                                dep.maintainer_count = contributor_count

                            # Check for health indicators
                            has_tests, has_ci, has_contribution_guidelines = (
                                check_health_indicators(repo_dir)
                            )
                            dep.has_tests = has_tests
                            dep.has_ci = has_ci
                            dep.has_contribution_guidelines = (
                                has_contribution_guidelines
                            )

                            # Check for security policy
                            has_security_policy, security_policy_score, issues = (
                                check_security_policy(dep, repo_dir)
                            )

                            # Log security policy issues
                            for issue in issues:
                                logger.info(
                                    f"Security policy issue for {name}: {issue}"
                                )

                            # Check for dependency update tools
                            has_update_tools, update_tools_score, update_issues = (
                                check_dependency_update_tools(dep, repo_dir)
                            )
                            dep.security_metrics.has_dependency_update_tools = (
                                has_update_tools
                            )

                            # Log dependency update tools issues
                            for issue in update_issues:
                                logger.info(
                                    f"Dependency update tools issue for {name}: {issue}"
                                )

                            # Check for signed commits
                            (
                                has_signed_commits,
                                signed_commits_score,
                                signed_commits_issues,
                            ) = check_signed_commits(dep, repo_dir)
                            dep.security_metrics.has_signed_commits = has_signed_commits

                            # Log signed commits issues
                            for issue in signed_commits_issues:
                                logger.info(f"Signed commits issue for {name}: {issue}")

                            # Check for branch protection
                            (
                                has_branch_protection,
                                branch_protection_score,
                                branch_protection_issues,
                            ) = check_branch_protection(dep, repo_dir)
                            dep.security_metrics.has_branch_protection = (
                                has_branch_protection
                            )

                            # Log branch protection issues
                            for issue in branch_protection_issues:
                                logger.info(
                                    f"Branch protection issue for {name}: {issue}"
                                )

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
