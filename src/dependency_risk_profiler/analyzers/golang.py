"""Analyzer for Go dependencies."""
import logging
import re
from typing import Dict, Optional

from ..models import DependencyMetadata
from .base import BaseAnalyzer
from .common import (
    check_for_vulnerabilities,
    check_health_indicators,
    clone_repo,
    count_contributors,
    fetch_url,
    get_last_commit_date,
)

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
    
    def analyze(self, dependencies: Dict[str, DependencyMetadata]) -> Dict[str, DependencyMetadata]:
        """Analyze Go dependencies and collect metadata.
        
        Args:
            dependencies: Dictionary mapping dependency names to their metadata.
            
        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info(f"Analyzing Go package: {name}")
            
            try:
                # Get latest version from proxy.golang.org
                latest_version = self._get_latest_version(name)
                if latest_version:
                    dep.latest_version = latest_version
                    # Store minimal metadata in cache
                    self.metadata_cache[name] = {
                        "name": name,
                        "latest_version": latest_version
                    }
                
                # Check if GitHub repository
                if "github.com" in name:
                    # Extract GitHub repo path
                    github_path = re.sub(r'^github\.com/', '', name)
                    
                    # Format repository URL
                    repo_url = f"https://github.com/{github_path}"
                    dep.repository_url = repo_url
                    
                    # Try to clone the repository
                    clone_result = clone_repo(repo_url)
                    
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
                        try:
                            has_tests, has_ci, has_contribution_guidelines = check_health_indicators(repo_dir)
                        except Exception as e:
                            logger.error(f"Error checking health indicators: {e}")
                            has_tests, has_ci, has_contribution_guidelines = False, False, False
                        dep.has_tests = has_tests
                        dep.has_ci = has_ci
                        dep.has_contribution_guidelines = has_contribution_guidelines
                
                # Check for known vulnerabilities
                dep.has_known_exploits = check_for_vulnerabilities(name, "go")
            
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
        # Check package on pkg.go.dev
        html = fetch_url(f"https://pkg.go.dev/{package_name}", self.timeout)
        if not html:
            return None
        
        # Parse the latest version from the HTML
        latest_version_match = re.search(r'Latest version: <[^>]*>([^<]+)<', html)
        if latest_version_match:
            return latest_version_match.group(1)
        
        # If GitHub repo, try to get latest tag
        if "github.com" in package_name:
            github_path = re.sub(r'^github\.com/', '', package_name)
            tags_html = fetch_url(f"https://github.com/{github_path}/tags", self.timeout)
            
            if tags_html:
                # Find the latest tag (simplified)
                latest_tag_match = re.search(r'href="/[^/]+/[^/]+/releases/tag/([^"]+)"', tags_html)
                if latest_tag_match:
                    return latest_tag_match.group(1)
        
        return None