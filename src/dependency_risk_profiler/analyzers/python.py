"""Analyzer for Python dependencies."""
import logging
import re
from typing import Dict, Optional
from packaging import version

from ..models import DependencyMetadata
from .base import BaseAnalyzer
from .common import (
    check_for_vulnerabilities,
    check_health_indicators,
    clone_repo,
    count_contributors,
    fetch_json,
    fetch_url,
    get_last_commit_date,
)

logger = logging.getLogger(__name__)


class PythonAnalyzer(BaseAnalyzer):
    """Analyzer for Python dependencies."""
    
    def analyze(self, dependencies: Dict[str, DependencyMetadata]) -> Dict[str, DependencyMetadata]:
        """Analyze Python dependencies and collect metadata.
        
        Args:
            dependencies: Dictionary mapping dependency names to their metadata.
            
        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info(f"Analyzing Python package: {name}")
            
            try:
                # Get PyPI package information
                pypi_data = self._get_pypi_package_info(name)
                
                if pypi_data:
                    # Update latest version
                    if "info" in pypi_data and "version" in pypi_data["info"]:
                        dep.latest_version = pypi_data["info"]["version"]
                    
                    # Check if deprecated
                    if "info" in pypi_data and "description" in pypi_data["info"]:
                        description = pypi_data["info"]["description"].lower()
                        if any(term in description for term in ["deprecated", "unmaintained", "abandoned"]):
                            dep.is_deprecated = True
                    
                    # Update repository URL
                    if "info" in pypi_data and "project_urls" in pypi_data["info"] and pypi_data["info"]["project_urls"]:
                        project_urls = pypi_data["info"]["project_urls"]
                        repo_url = None
                        
                        # Try to find repository URL
                        for key, url in project_urls.items():
                            if any(term in key.lower() for term in ["repository", "source", "code", "github", "gitlab", "bitbucket"]):
                                repo_url = url
                                break
                        
                        if repo_url:
                            dep.repository_url = repo_url
                    
                    # Fallback to homepage if repository not found
                    if not dep.repository_url and "info" in pypi_data and "home_page" in pypi_data["info"]:
                        home_page = pypi_data["info"]["home_page"]
                        if any(host in home_page for host in ["github.com", "gitlab.com", "bitbucket.org"]):
                            dep.repository_url = home_page
                    
                    # Check for known vulnerabilities
                    dep.has_known_exploits = check_for_vulnerabilities(name, "pypi")
                    
                    # Get additional info from repository if available
                    if dep.repository_url and any(host in dep.repository_url for host in ["github.com", "gitlab.com", "bitbucket.org"]):
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
                            has_tests, has_ci, has_contribution_guidelines = check_health_indicators(repo_dir)
                            dep.has_tests = has_tests
                            dep.has_ci = has_ci
                            dep.has_contribution_guidelines = has_contribution_guidelines
            
            except Exception as e:
                logger.error(f"Error analyzing {name}: {e}")
        
        return dependencies
    
    def _get_pypi_package_info(self, package_name: str) -> Optional[dict]:
        """Get package information from PyPI.
        
        Args:
            package_name: Name of the Python package.
            
        Returns:
            Dictionary with package information, or None if fetching failed.
        """
        url = f"https://pypi.org/pypi/{package_name}/json"
        return fetch_json(url, self.timeout)
    
    def _normalize_version(self, version_str: str) -> str:
        """Normalize version string for comparison.
        
        Args:
            version_str: Version string to normalize.
            
        Returns:
            Normalized version string.
        """
        if version_str.startswith(">") or version_str.startswith("<") or version_str.startswith("="):
            # Extract version without operators
            match = re.search(r'[0-9].*', version_str)
            if match:
                return match.group(0)
        return version_str