"""Common analysis functions shared across different ecosystems."""

import logging
import re
import subprocess  # nosec B404
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

import requests

logger = logging.getLogger(__name__)


def fetch_url(url: str, timeout: int = 30) -> Optional[str]:
    """Fetch content from a URL safely.

    Args:
        url: URL to fetch.
        timeout: Request timeout in seconds.

    Returns:
        The content as a string, or None if the request failed.
    """
    try:
        headers = {
            "User-Agent": "dependency-risk-profiler/0.2.0 (https://github.com/username/dependency-risk-profiler)"
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logger.debug(f"Error fetching {url}: {e}")
        return None


def fetch_json(url: str, timeout: int = 30) -> Optional[dict]:
    """Fetch JSON from a URL safely.

    Args:
        url: URL to fetch.
        timeout: Request timeout in seconds.

    Returns:
        The parsed JSON as a dictionary, or None if the request failed.
    """
    try:
        headers = {
            "User-Agent": "dependency-risk-profiler/0.2.0 (https://github.com/username/dependency-risk-profiler)"
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as e:
        logger.debug(f"Error fetching JSON from {url}: {e}")
        return None


def clone_repo(repo_url: str) -> Optional[Tuple[str, str]]:
    """Clone a git repository to a temporary directory.

    Args:
        repo_url: URL of the git repository.

    Returns:
        Tuple of (temporary directory path, git command output), or None if cloning failed.
    """
    try:
        # Convert HTTPS URLs to git URLs if needed
        if "github.com" in repo_url and not repo_url.startswith(("git@", "git://")):
            if repo_url.startswith("https://github.com/"):
                repo_url = repo_url.replace("https://github.com/", "git@github.com:")
            elif repo_url.startswith("http://github.com/"):
                repo_url = repo_url.replace("http://github.com/", "git@github.com:")

            # Ensure .git suffix
            if not repo_url.endswith(".git"):
                repo_url += ".git"

        temp_dir = tempfile.mkdtemp(prefix="dependency-risk-profiler-")
        logger.debug(f"Cloning {repo_url} to {temp_dir}")

        # Clone with depth 1 for speed
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, temp_dir],  # nosec B603, B607
            check=True,
            capture_output=True,
            text=True,
        )

        return temp_dir, result.stdout
    except subprocess.SubprocessError as e:
        logger.debug(f"Error cloning repository {repo_url}: {e}")
        return None


def get_last_commit_date(repo_dir: str) -> Optional[datetime]:
    """Get the date of the last commit in a git repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        The date of the last commit, or None if the command failed.
    """
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cd", "--date=iso"],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        date_str = result.stdout.strip()
        return datetime.fromisoformat(date_str.replace(" ", "T").replace(" -", "-"))
    except (subprocess.SubprocessError, ValueError) as e:
        logger.debug(f"Error getting last commit date: {e}")
        return None


def count_contributors(repo_dir: str) -> int:
    """Count the number of contributors to a git repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        The number of contributors, or 0 if the command failed.
    """
    try:
        result = subprocess.run(
            ["git", "shortlog", "-s", "-n", "--all"],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        contributors = result.stdout.strip().split("\n")
        return len(contributors)
    except subprocess.SubprocessError as e:
        logger.debug(f"Error counting contributors: {e}")
        return 0


def check_health_indicators(repo_dir: str) -> Tuple[bool, bool, bool]:
    """Check for the presence of tests, CI configuration, and contribution guidelines.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Tuple of (has_tests, has_ci, has_contribution_guidelines).
    """
    try:
        repo_path = Path(repo_dir)

        # Check for tests
        test_patterns = ["test", "spec", "tests", "specs"]
        has_tests = False

        # Check for test directories
        for pattern in test_patterns:
            for p in repo_path.glob("**/*"):
                if (
                    p.is_dir()
                    and not p.name.startswith(".")
                    and pattern in p.name.lower()
                ):
                    has_tests = True
                    break
            if has_tests:
                break

        # Also check for test files directly if no test directories found
        if not has_tests:
            for p in repo_path.glob("**/*"):
                if p.is_file() and not p.name.startswith("."):
                    filename = p.name.lower()
                    if any(pattern in filename for pattern in test_patterns):
                        has_tests = True
                        break

        # Check for CI configuration
        ci_files = [
            ".travis.yml",
            ".circleci/config.yml",
            "azure-pipelines.yml",
            ".gitlab-ci.yml",
            "Jenkinsfile",
            "appveyor.yml",
            ".drone.yml",
        ]
        has_ci = False

        # Check individual CI files
        for file in ci_files:
            if repo_path.joinpath(file).exists():
                has_ci = True
                break

        # Check for GitHub workflows
        if not has_ci and repo_path.joinpath(".github").exists():
            if repo_path.joinpath(".github").joinpath("workflows").exists():
                has_ci = True

        # Check for contribution guidelines
        contribution_files = [
            "CONTRIBUTING.md",
            "CONTRIBUTING.rst",
            "CONTRIBUTE.md",
            "docs/CONTRIBUTING.md",
            "docs/contributing.md",
            "DEVELOPMENT.md",
            "HACKING.md",
        ]
        has_contribution_guidelines = False

        # Check individual contribution files
        for file in contribution_files:
            if repo_path.joinpath(file).exists():
                has_contribution_guidelines = True
                break

        # Check for GitHub contribution guidelines
        if not has_contribution_guidelines and repo_path.joinpath(".github").exists():
            if repo_path.joinpath(".github").joinpath("CONTRIBUTING.md").exists():
                has_contribution_guidelines = True

        return has_tests, has_ci, has_contribution_guidelines
    except Exception as e:
        logger.error(f"Error checking health indicators: {e}")
        return False, False, False


def check_for_vulnerabilities(package_name: str, ecosystem: str) -> bool:
    """Check for known vulnerabilities for a package.

    Args:
        package_name: Name of the package.
        ecosystem: Package ecosystem (npm, pypi, go).

    Returns:
        True if vulnerabilities were found, False otherwise.
    """
    # This is a simplified approach - in a production tool, you would want to use
    # a more comprehensive vulnerability database or API
    vulnerability_urls = {
        "npm": f"https://www.npmjs.com/advisories/search?q={package_name}",
        "pypi": f"https://pypi.org/project/{package_name}/",
        "go": f"https://pkg.go.dev/{package_name}",
    }

    url = vulnerability_urls.get(ecosystem)
    if not url:
        return False

    content = fetch_url(url)
    if not content:
        return False

    # Simple pattern matching for vulnerability indicators
    vulnerability_patterns = [
        r"security",
        r"vuln",
        r"CVE-\d{4}-\d+",
        r"advisory",
        r"exploit",
        r"malicious",
        r"remote code execution",
        r"injection",
        r"XSS",
        r"CSRF",
    ]

    return any(
        re.search(pattern, content, re.IGNORECASE) for pattern in vulnerability_patterns
    )
