"""Utility functions used across multiple modules."""

import json
import logging
import os
import re
import shutil
import subprocess  # nosec B404
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple
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
        # Explicitly cast response.text to str to help mypy
        return str(response.text)
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return None


def fetch_json(url: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
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
        # Properly type the result to avoid mypy errors
        result: Dict[str, Any] = json.loads(content)
        return result
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {url}: {e}")
        return None


# A shallow clone of a normal repo finishes in a few seconds; a large cap
# only exists to bound pathological cases without letting one repo stall a
# whole scan (git:// / auth-required URLs used to hang for minutes).
CLONE_TIMEOUT_SECONDS = 60
_CLONEABLE_HOSTS = ("github.com", "gitlab.com", "bitbucket.org")


def normalize_clone_url(repo_url: str) -> Optional[str]:
    """Return a plain https clone URL for a supported host, or None to skip.

    Package metadata spells repository URLs many ways (``git+https://``,
    ``git://``, ``git@host:owner/repo``, ``ssh://``, ``.git`` suffixes). This
    normalizes them to https and rejects anything that would make ``git clone``
    hang or fail — notably ``git://`` (GitHub disabled it in 2022) and
    ssh/auth URLs — so a single bad URL can't stall a scan for minutes.
    """
    url = repo_url.strip()
    if url.startswith("git+"):
        url = url[4:]
    scp_match = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", url)
    if scp_match:
        url = f"https://{scp_match.group(1)}/{scp_match.group(2)}"
    elif url.startswith("git://"):
        url = "https://" + url[len("git://") :]
    elif url.startswith("ssh://"):
        url = "https://" + url[len("ssh://") :].split("@", 1)[-1]
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    host = parsed.netloc.split("@")[-1].lower()
    if not any(host == h or host.endswith("." + h) for h in _CLONEABLE_HOSTS):
        return None
    return url


def is_cloneable_repo_url(repo_url: Optional[str]) -> bool:
    """Return True if the URL is a cloneable https repo on a supported host.

    Uses full URL parsing (not a substring host check) so lookalike hosts such
    as ``https://github.com.evil.example/x/y`` are correctly rejected.
    """
    if not repo_url:
        return False
    return normalize_clone_url(repo_url) is not None


def clone_repo(repo_url: str) -> Optional[Tuple[str, str]]:
    """Clone a git repository to a temporary directory.

    Args:
        repo_url: URL of the repository.

    Returns:
        Tuple of (repo_dir, repo_name) or None if cloning fails or the URL is
        not a cloneable https URL for a supported host.
    """
    normalized_url = normalize_clone_url(repo_url)
    if normalized_url is None:
        logger.debug("Skipping non-cloneable repository URL: %s", repo_url)
        return None
    try:
        parsed_url = urlparse(normalized_url)
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

        # Never let git block on a credential/host prompt — fail fast instead.
        clone_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}

        # Clone the repository (shallow, no tags, non-interactive).
        result = subprocess.run(
            [  # nosec B603, B607
                "git",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                normalized_url,
                repo_dir,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            env=clone_env,
        )

        if result.returncode == 0:
            return repo_dir, repo_name
        else:
            logger.error(f"Error cloning {repo_url}: {result.stderr}")
            return None
    except Exception as e:
        logger.error(f"Error cloning {repo_url}: {e}")
        return None


@contextmanager
def cloned_repo(repo_url: str) -> Iterator[Optional[Tuple[str, str]]]:
    """Clone a repository into a temp dir and always remove it afterward.

    Yields the ``(repo_dir, repo_name)`` tuple from :func:`clone_repo`, or
    ``None`` if the clone failed. The temporary clone directory is deleted on
    exit regardless of how the ``with`` block terminates, so short-lived repo
    inspection never leaks ``dep-profiler-*`` directories into the temp dir.
    """
    result = clone_repo(repo_url)
    temp_root: Optional[str] = None
    if result is not None:
        repo_dir, _ = result
        temp_root = os.path.dirname(repo_dir)
    try:
        yield result
    finally:
        if temp_root is not None and os.path.isdir(temp_root):
            shutil.rmtree(temp_root, ignore_errors=True)


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
    except Exception as e:
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
    except Exception as e:
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
    test_patterns = [
        "test/",
        "tests/",
        "spec/",
        "specs/",
        "*_test.py",
        "*_spec.js",
        "test_*.py",
    ]
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

    This is a simple placeholder that should be replaced with actual
    vulnerability checking.
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
