"""Community metrics analyzer for dependencies."""

import logging
import re
import subprocess  # nosec B404
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from ..analyzers.common import fetch_json, fetch_url
from ..models import CommunityMetrics, DependencyMetadata

logger = logging.getLogger(__name__)


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


def extract_star_count(html_content: str) -> Optional[int]:
    """Extract star count from GitHub repository HTML.

    Args:
        html_content: GitHub repository HTML content.

    Returns:
        Star count or None if not found.
    """
    if not html_content:
        return None

    # Look for star count in HTML
    star_patterns = [
        r'aria-label="([0-9,]+) users starred this repository"',
        r'<span class="Counter js-social-count">([0-9,k]+)</span>',
        r'<a class="social-count js-social-count" [^>]*>([0-9,k]+)</a>',
    ]

    for pattern in star_patterns:
        match = re.search(pattern, html_content)
        if match:
            count_str = match.group(1).replace(",", "")
            if "k" in count_str.lower():
                # Handle cases like "1.2k"
                count_str = count_str.lower().replace("k", "")
                try:
                    return int(float(count_str) * 1000)
                except ValueError:
                    continue
            else:
                try:
                    return int(count_str)
                except ValueError:
                    continue

    return None


def extract_fork_count(html_content: str) -> Optional[int]:
    """Extract fork count from GitHub repository HTML.

    Args:
        html_content: GitHub repository HTML content.

    Returns:
        Fork count or None if not found.
    """
    if not html_content:
        return None

    # Look for fork count in HTML
    fork_patterns = [
        r'aria-label="([0-9,]+) users forked this repository"',
        r'<span class="Counter">([0-9,k]+)</span> forks',
        r'<a class="social-count" [^>]*>([0-9,k]+)</a>',
    ]

    for pattern in fork_patterns:
        match = re.search(pattern, html_content)
        if match:
            count_str = match.group(1).replace(",", "")
            if "k" in count_str.lower():
                # Handle cases like "1.2k"
                count_str = count_str.lower().replace("k", "")
                try:
                    return int(float(count_str) * 1000)
                except ValueError:
                    continue
            else:
                try:
                    return int(count_str)
                except ValueError:
                    continue

    return None


def calculate_commit_frequency(repo_dir: str, months: int = 6) -> Optional[float]:
    """Calculate commit frequency over the last N months.

    Args:
        repo_dir: Path to the git repository.
        months: Number of months to look back.

    Returns:
        Average number of commits per month or None if calculation failed.
    """
    try:
        # Get the date N months ago
        date_threshold = (datetime.now() - timedelta(days=30 * months)).strftime(
            "%Y-%m-%d"
        )

        # Count commits since that date
        result = subprocess.run(
            [
                "git",
                "rev-list",
                "--count",
                f"--since={date_threshold}",
                "HEAD",
            ],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )

        commit_count = int(result.stdout.strip())

        # Calculate average commits per month
        return commit_count / months
    except (subprocess.SubprocessError, ValueError) as e:
        logger.error(f"Error calculating commit frequency: {e}")
        return None


def analyze_github_community_metrics(
    dependency: DependencyMetadata,
) -> DependencyMetadata:
    """Analyze GitHub community metrics for a dependency.

    Args:
        dependency: Dependency metadata.

    Returns:
        Updated dependency metadata with community metrics.
    """
    if not dependency.repository_url:
        return dependency

    repo_info = extract_github_repo_info(dependency.repository_url)
    if not repo_info:
        return dependency

    owner, repo = repo_info
    logger.info(f"Analyzing GitHub community metrics for {owner}/{repo}")

    # Initialize community metrics
    community_metrics = CommunityMetrics()

    # Set contributor count from already collected data
    if dependency.maintainer_count:
        community_metrics.contributor_count = dependency.maintainer_count

    # Fetch repository HTML to extract star and fork counts
    html_content = fetch_url(f"https://github.com/{owner}/{repo}")
    if html_content:
        community_metrics.star_count = extract_star_count(html_content)
        community_metrics.fork_count = extract_fork_count(html_content)

    # Set community metrics
    dependency.community_metrics = community_metrics

    return dependency


def analyze_npm_community_metrics(
    dependency: DependencyMetadata, npm_data: Dict
) -> DependencyMetadata:
    """Analyze npm community metrics for a dependency.

    Args:
        dependency: Dependency metadata.
        npm_data: npm package data.

    Returns:
        Updated dependency metadata with community metrics.
    """
    if not dependency.community_metrics:
        dependency.community_metrics = CommunityMetrics()

    # Extract download count if available
    if "downloads" in npm_data:
        if (
            isinstance(npm_data["downloads"], dict)
            and "last-month" in npm_data["downloads"]
        ):
            dependency.community_metrics.downloads_count = npm_data["downloads"][
                "last-month"
            ]

    # Extract maintainer count if not already set
    if dependency.maintainer_count is None and "maintainers" in npm_data:
        if isinstance(npm_data["maintainers"], list):
            dependency.maintainer_count = len(npm_data["maintainers"])
            dependency.community_metrics.contributor_count = dependency.maintainer_count

    # Extract release count and last release date
    if "time" in npm_data:
        if isinstance(npm_data["time"], dict):
            # Exclude metadata fields
            release_dates = {
                k: v
                for k, v in npm_data["time"].items()
                if k not in ["created", "modified", "updated"]
            }

            dependency.community_metrics.releases_count = len(release_dates)

            if release_dates:
                latest_release = max(release_dates.items(), key=lambda x: x[1])
                try:
                    dependency.community_metrics.last_release_date = (
                        datetime.fromisoformat(latest_release[1].replace("Z", "+00:00"))
                    )
                except ValueError:
                    pass

    return dependency


def analyze_pypi_community_metrics(
    dependency: DependencyMetadata, pypi_data: Dict
) -> DependencyMetadata:
    """Analyze PyPI community metrics for a dependency.

    Args:
        dependency: Dependency metadata.
        pypi_data: PyPI package data.

    Returns:
        Updated dependency metadata with community metrics.
    """
    if not dependency.community_metrics:
        dependency.community_metrics = CommunityMetrics()

    # Extract release count and last release date
    if "releases" in pypi_data:
        dependency.community_metrics.releases_count = len(pypi_data["releases"])

        latest_release_date = None
        for version, releases in pypi_data["releases"].items():
            if releases:
                for release in releases:
                    if "upload_time" in release:
                        try:
                            release_date = datetime.fromisoformat(
                                release["upload_time"].replace("Z", "+00:00")
                            )
                            if (
                                latest_release_date is None
                                or release_date > latest_release_date
                            ):
                                latest_release_date = release_date
                        except ValueError:
                            pass

        if latest_release_date:
            dependency.community_metrics.last_release_date = latest_release_date

    # Try to get download stats from PyPI Stats API (this is a simple approach, actual PyPI does not provide this directly)
    try:
        download_stats = fetch_json(
            f"https://pypistats.org/api/packages/{dependency.name}/recent"
        )
        if download_stats and "data" in download_stats:
            if "last_month" in download_stats["data"]:
                dependency.community_metrics.downloads_count = download_stats["data"][
                    "last_month"
                ]
    except Exception as e:  # nosec B110
        logger.debug(f"Could not fetch PyPI download stats for {dependency.name}: {e}")
        # Continue without download stats

    return dependency


def analyze_community_metrics(
    dependency: DependencyMetadata, metadata: Dict = None
) -> DependencyMetadata:
    """Analyze community metrics for a dependency.

    Args:
        dependency: Dependency metadata.
        metadata: Package metadata.

    Returns:
        Updated dependency metadata with community metrics.
    """
    logger.info(f"Analyzing community metrics for {dependency.name}")

    try:
        # Initialize community metrics if not already present
        if not dependency.community_metrics:
            dependency.community_metrics = CommunityMetrics()

        # Analyze GitHub metrics if repository URL is available
        if dependency.repository_url:
            dependency = analyze_github_community_metrics(dependency)

        # Analyze package registry specific metrics
        if metadata:
            if "name" in metadata and dependency.name.startswith("@"):
                # npm package
                dependency = analyze_npm_community_metrics(dependency, metadata)
            elif "info" in metadata and "name" in metadata["info"]:
                # PyPI package
                dependency = analyze_pypi_community_metrics(dependency, metadata)

    except Exception as e:
        logger.error(f"Error analyzing community metrics for {dependency.name}: {e}")

    return dependency
