"""Utility functions used across multiple modules."""

import json
import logging
import re
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


def fetch_url(url: str, timeout: int = 30) -> Optional[str]:
    """Fetch content from a URL.

    Args:
        url: URL to fetch.
        timeout: Timeout in seconds.

    Returns:
        Content of the URL or None if fetching fails.
    """
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        return None


def fetch_json(url: str, timeout: int = 30) -> Optional[Dict]:
    """Fetch JSON from a URL.

    Args:
        url: URL to fetch.
        timeout: Timeout in seconds.

    Returns:
        JSON content or None if fetching fails.
    """
    content = fetch_url(url, timeout)
    if not content:
        return None

    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {url}: {e}")
        return None


def clone_repo(repo_url: str) -> Optional[Tuple[str, str]]:
    """Clone a git repository to a temporary directory.

    Args:
        repo_url: URL of the repository.

    Returns:
        Tuple of (repo_dir, repo_name) or None if cloning fails.
    """
    try:
        # Extract repo name from URL
        parsed_url = urlparse(repo_url)
        path_parts = parsed_url.path.strip("/").split("/")
        if len(path_parts) < 2:
            logger.error(f"Invalid repository URL: {repo_url}")
            return None

        repo_name = path_parts[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="dep-profiler-")
        repo_dir = f"{temp_dir}/{repo_name}"

        # Clone the repository
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, repo_dir],  # nosec B603, B607
            check=True,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes timeout for clone
        )

        if result.returncode == 0:
            return repo_dir, repo_name
        else:
            logger.error(f"Error cloning {repo_url}: {result.stderr}")
            return None
    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.error(f"Error cloning {repo_url}: {e}")
        return None


def get_last_commit_date(repo_dir: str) -> Optional[str]:
    """Get the date of the last commit in a repository.

    Args:
        repo_dir: Path to the repository.

    Returns:
        Date of the last commit in ISO format or None if fetching fails.
    """
    try:
        # Execute git command to get the last commit date
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cI"],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )

        commit_date = result.stdout.strip()
        if commit_date:
            return commit_date
        else:
            logger.error(f"No commit date found in {repo_dir}")
            return None
    except subprocess.SubprocessError as e:
        logger.error(f"Error getting last commit date: {e}")
        return None


def count_contributors(repo_dir: str) -> Optional[int]:
    """Count contributors to a repository.

    Args:
        repo_dir: Path to the repository.

    Returns:
        Number of contributors or None if counting fails.
    """
    try:
        # Execute git command to count contributors
        result = subprocess.run(
            [
                "git",
                "shortlog",
                "-s",
                "-n",
                "--all",
                "--no-merges",
            ],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )

        contributors = result.stdout.strip().split("\n")
        if contributors and contributors[0]:
            return len(contributors)
        else:
            logger.warning(f"No contributors found in {repo_dir}")
            return 0
    except subprocess.SubprocessError as e:
        logger.error(f"Error counting contributors: {e}")
        return None


def check_health_indicators(repo_dir: str) -> Tuple[bool, bool, bool]:
    """Check for health indicators in a repository.

    Args:
        repo_dir: Path to the repository.

    Returns:
        Tuple of (has_tests, has_ci, has_contribution_guidelines).
    """
    repo_path = Path(repo_dir)
    
    # Check for tests directory or test files
    test_patterns = ["test/", "tests/", "spec/", "specs/", "*_test.py", "*_spec.js", "test_*.py"]
    has_tests = False
    for pattern in test_patterns:
        if "*" in pattern:
            # Handle filename patterns
            for file_path in repo_path.glob(pattern):
                if file_path.exists():
                    has_tests = True
                    break
        else:
            # Handle directory patterns
            if repo_path.joinpath(pattern).exists():
                has_tests = True
                break

    # Check for CI configuration
    ci_patterns = [
        ".github/workflows/",
        ".travis.yml",
        ".circleci/",
        ".gitlab-ci.yml",
        "azure-pipelines.yml",
        "Jenkinsfile",
    ]
    has_ci = False
    for pattern in ci_patterns:
        if repo_path.joinpath(pattern).exists():
            has_ci = True
            break

    # Check for contribution guidelines
    contribution_patterns = [
        "CONTRIBUTING.md",
        ".github/CONTRIBUTING.md",
        "docs/CONTRIBUTING.md",
        "CONTRIBUTE.md",
        ".github/CONTRIBUTE.md",
        "docs/CONTRIBUTE.md",
    ]
    has_contribution_guidelines = False
    for pattern in contribution_patterns:
        if repo_path.joinpath(pattern).exists():
            has_contribution_guidelines = True
            break

    return has_tests, has_ci, has_contribution_guidelines


def check_for_vulnerabilities(package_name: str, ecosystem: str) -> bool:
    """Check if a package has known vulnerabilities.

    This is a simple placeholder that should be replaced with actual vulnerability checking.
    In a real implementation, this would query vulnerability databases.

    Args:
        package_name: Name of the package.
        ecosystem: Package ecosystem (e.g., npm, pypi).

    Returns:
        True if vulnerabilities are found, False otherwise.
    """
    # This is a placeholder implementation
    # In a real implementation, this would query vulnerability databases
    # like OSV, GitHub Advisory, etc.
    
    # For demonstration purposes, just check if the package name contains
    # known vulnerable library patterns
    vulnerable_patterns = ["log4j", "shelljs", "prototype", "lodash"]
    return any(pattern in package_name.lower() for pattern in vulnerable_patterns)


def extract_github_repo_info(repo_url: str) -> Optional[Tuple[str, str]]:
    """Extract owner and repo name from a GitHub URL.

    Args:
        repo_url: GitHub repository URL.

    Returns:
        Tuple of (owner, repo) or None if not a GitHub URL.
    """
    if not repo_url:
        return None

    # Clean the URL
    repo_url = repo_url.strip()

    # Handle various GitHub URL formats
    github_patterns = [
        r"github\.com[/:]([^/]+)/([^/]+)(\.git)?/?$",
        r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git|/)?$",
    ]

    for pattern in github_patterns:
        match = re.search(pattern, repo_url)
        if match:
            owner = match.group(1)
            repo = match.group(2)
            if repo.endswith(".git"):
                repo = repo[:-4]
            return owner, repo

    return None