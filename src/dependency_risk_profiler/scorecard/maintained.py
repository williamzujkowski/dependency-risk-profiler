"""Enhanced maintained status check for dependencies."""

import logging
import subprocess  # nosec B404
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import DependencyMetadata

logger = logging.getLogger(__name__)


def analyze_commit_frequency(repo_dir: str, months: int = 12) -> Dict[str, float]:
    """Analyze commit frequency over time to determine maintenance trends.

    Args:
        repo_dir: Path to the git repository.
        months: Number of months to analyze.

    Returns:
        Dictionary with monthly commit frequencies and trend indicators.
    """
    result = {}

    try:
        # Get current date
        now = datetime.now()

        # Calculate monthly commit frequencies
        monthly_counts = []
        for i in range(months):
            start_date = (now - timedelta(days=30 * (i + 1))).strftime("%Y-%m-%d")
            end_date = (now - timedelta(days=30 * i)).strftime("%Y-%m-%d")

            cmd = [
                "git",
                "rev-list",
                "--count",
                f"--since={start_date}",
                f"--until={end_date}",
                "HEAD",
            ]
            output = subprocess.run(
                cmd,
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True,  # nosec B603
            ).stdout.strip()

            try:
                count = int(output)
                monthly_counts.append(count)
            except ValueError:
                monthly_counts.append(0)

        # Calculate average commit frequency
        if monthly_counts:
            avg_frequency = sum(monthly_counts) / len(monthly_counts)
            result["average_monthly_commits"] = avg_frequency

        # Calculate trend (are commits increasing or decreasing?)
        if len(monthly_counts) >= 3:
            # Compare recent months to earlier months
            recent = sum(monthly_counts[:3]) / 3  # Last 3 months
            earlier = (
                sum(monthly_counts[3:6]) / 3 if len(monthly_counts) >= 6 else recent
            )

            if earlier == 0:
                trend = 0  # No earlier activity to compare
            else:
                trend = (recent - earlier) / earlier

            result["commit_trend"] = trend

        # Calculate frequency stability
        if len(monthly_counts) >= 3:
            variations = [
                abs(monthly_counts[i] - monthly_counts[i + 1])
                for i in range(len(monthly_counts) - 1)
            ]
            avg_variation = sum(variations) / len(variations) if variations else 0
            stability = 1.0 - (
                avg_variation / (max(monthly_counts) if max(monthly_counts) > 0 else 1)
            )
            result["commit_stability"] = max(0, stability)  # Ensure non-negative

    except Exception as e:
        logger.error(f"Error analyzing commit frequency: {e}")

    return result


def analyze_release_cadence(
    repo_dir: str, package_data: Optional[Dict] = None
) -> Dict[str, float]:
    """Analyze release cadence to determine if project is regularly released.

    Args:
        repo_dir: Path to the git repository.
        package_data: Optional package metadata from registry.

    Returns:
        Dictionary with release cadence metrics.
    """
    result = {}

    try:
        # Try to use tag information from git
        try:
            # Get tag dates
            cmd = [
                "git",
                "for-each-ref",
                "--sort=-creatordate",
                "--format=%(creatordate:iso)",
                "refs/tags",
            ]
            output = subprocess.run(
                cmd,
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True,  # nosec B603
            ).stdout.strip()

            tag_dates = []
            for line in output.split("\n"):
                if line.strip():
                    try:
                        tag_date = datetime.fromisoformat(
                            line.replace(" ", "T").replace(" -", "-")
                        )
                        tag_dates.append(tag_date)
                    except ValueError:
                        continue

            if tag_dates:
                # Calculate days between releases
                intervals = [
                    (tag_dates[i] - tag_dates[i + 1]).days
                    for i in range(len(tag_dates) - 1)
                ]
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    result["average_days_between_releases"] = avg_interval

                # Days since last release
                if tag_dates:
                    days_since_last = (datetime.now() - tag_dates[0]).days
                    result["days_since_last_release"] = days_since_last

                    # Calculate expected next release date
                    if "average_days_between_releases" in result:
                        expected_next = tag_dates[0] + timedelta(
                            days=result["average_days_between_releases"]
                        )
                        result["release_overdue_days"] = max(
                            0, (datetime.now() - expected_next).days
                        )

        except subprocess.SubprocessError:
            logger.debug("Could not get tag information from git")

        # Fall back to package data if available
        if package_data and not result:
            # Implementation depends on the package registry format
            # This is a simplified example
            if "time" in package_data and isinstance(package_data["time"], dict):
                # For npm-like registries
                release_dates = []
                for version, timestamp in package_data["time"].items():
                    if version not in ["created", "modified"]:
                        try:
                            release_date = datetime.fromisoformat(
                                timestamp.replace("Z", "+00:00")
                            )
                            release_dates.append(release_date)
                        except ValueError:
                            continue

                if release_dates:
                    release_dates.sort(reverse=True)

                    # Calculate days between releases
                    intervals = [
                        (release_dates[i] - release_dates[i + 1]).days
                        for i in range(len(release_dates) - 1)
                    ]
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        result["average_days_between_releases"] = avg_interval

                    # Days since last release
                    days_since_last = (datetime.now() - release_dates[0]).days
                    result["days_since_last_release"] = days_since_last

                    # Calculate expected next release date
                    if "average_days_between_releases" in result:
                        expected_next = release_dates[0] + timedelta(
                            days=result["average_days_between_releases"]
                        )
                        result["release_overdue_days"] = max(
                            0, (datetime.now() - expected_next).days
                        )

            elif "releases" in package_data:
                # For PyPI-like registries
                # Implementation would be specific to the PyPI data structure
                pass

    except Exception as e:
        logger.error(f"Error analyzing release cadence: {e}")

    return result


def analyze_issue_activity(repo_path: str) -> Dict[str, float]:
    """Analyze issue activity to determine project responsiveness.

    Args:
        repo_path: Path to the git repository.

    Returns:
        Dictionary with issue activity metrics.
    """
    result = {}

    # This would typically require API access to GitHub/GitLab/etc.
    # For a complete implementation, you would need to use the GitHub API
    # Here we just look for indicators in the repo itself

    try:
        repo_path_obj = Path(repo_path)

        # Check for GitHub issue templates (a sign of maintained projects)
        issue_template_paths = [
            ".github/ISSUE_TEMPLATE",
            ".gitlab/issue_templates",
            "docs/issue-templates",
        ]

        has_issue_templates = any(
            repo_path_obj.joinpath(path).exists() for path in issue_template_paths
        )
        result["has_issue_templates"] = has_issue_templates

        # Look for CODEOWNERS file (indicates active maintainership)
        codeowners_paths = [
            "CODEOWNERS",
            ".github/CODEOWNERS",
            "docs/CODEOWNERS",
        ]

        has_codeowners = any(
            repo_path_obj.joinpath(path).exists() for path in codeowners_paths
        )
        result["has_codeowners"] = has_codeowners

        # Look for active maintainership indicators
        maintainership_files = [
            "MAINTAINERS",
            "OWNERS",
            ".github/MAINTAINERS.md",
            "docs/MAINTAINERS.md",
        ]

        has_maintainership = any(
            repo_path_obj.joinpath(path).exists() for path in maintainership_files
        )
        result["has_maintainership_info"] = has_maintainership

    except Exception as e:
        logger.error(f"Error analyzing issue activity: {e}")

    return result


def calculate_maintained_score(
    commit_data: Dict[str, float],
    release_data: Dict[str, float],
    issue_data: Dict[str, float],
) -> float:
    """Calculate an overall maintained score from various metrics.

    Args:
        commit_data: Commit frequency analysis results.
        release_data: Release cadence analysis results.
        issue_data: Issue activity analysis results.

    Returns:
        Maintained score between 0.0 (unmaintained) and 1.0 (well maintained).
    """
    # Initialize score components
    commit_score = 0.5  # Default
    release_score = 0.5  # Default
    issue_score = 0.5  # Default

    # Calculate commit frequency score
    if "average_monthly_commits" in commit_data:
        # More commits is better, but with diminishing returns
        commit_avg = commit_data["average_monthly_commits"]
        if commit_avg >= 30:  # Daily commits
            commit_score = 1.0
        elif commit_avg >= 15:  # Every other day
            commit_score = 0.9
        elif commit_avg >= 7:  # Weekly
            commit_score = 0.8
        elif commit_avg >= 4:  # Bi-weekly
            commit_score = 0.7
        elif commit_avg >= 1:  # Monthly
            commit_score = 0.5
        elif commit_avg > 0:  # Some activity
            commit_score = 0.3
        else:  # No activity
            commit_score = 0.0

    # Adjust for trend
    if "commit_trend" in commit_data:
        trend = commit_data["commit_trend"]
        if trend > 0.5:  # Significantly increasing
            commit_score = min(1.0, commit_score + 0.2)
        elif trend > 0.1:  # Slightly increasing
            commit_score = min(1.0, commit_score + 0.1)
        elif trend < -0.5:  # Significantly decreasing
            commit_score = max(0.0, commit_score - 0.2)
        elif trend < -0.1:  # Slightly decreasing
            commit_score = max(0.0, commit_score - 0.1)

    # Calculate release score
    if "days_since_last_release" in release_data:
        days = release_data["days_since_last_release"]
        if days <= 30:  # Released in the last month
            release_score = 1.0
        elif days <= 90:  # Released in the last quarter
            release_score = 0.8
        elif days <= 180:  # Released in the last 6 months
            release_score = 0.6
        elif days <= 365:  # Released in the last year
            release_score = 0.4
        else:  # No release in over a year
            release_score = 0.2

    # Adjust for release regularity
    if (
        "release_overdue_days" in release_data
        and "average_days_between_releases" in release_data
    ):
        avg_interval = release_data["average_days_between_releases"]
        overdue = release_data["release_overdue_days"]

        if avg_interval > 0:
            overdue_ratio = overdue / avg_interval
            if overdue_ratio > 2:  # Significantly overdue
                release_score = max(0.0, release_score - 0.2)
            elif overdue_ratio > 1:  # Somewhat overdue
                release_score = max(0.0, release_score - 0.1)

    # Calculate issue score
    issue_score_components = []

    if "has_issue_templates" in issue_data:
        issue_score_components.append(0.7 if issue_data["has_issue_templates"] else 0.3)

    if "has_codeowners" in issue_data:
        issue_score_components.append(0.8 if issue_data["has_codeowners"] else 0.4)

    if "has_maintainership_info" in issue_data:
        issue_score_components.append(
            0.7 if issue_data["has_maintainership_info"] else 0.3
        )

    if issue_score_components:
        issue_score = sum(issue_score_components) / len(issue_score_components)

    # Calculate final score with weights
    # Commit activity is the most important indicator of maintenance
    final_score = commit_score * 0.5 + release_score * 0.3 + issue_score * 0.2

    return final_score


def check_maintained_status(
    dependency: DependencyMetadata,
    repo_dir: Optional[str] = None,
    package_data: Optional[Dict] = None,
) -> Tuple[float, List[str]]:
    """Check if a dependency is actively maintained.

    Args:
        dependency: Dependency metadata.
        repo_dir: Optional path to cloned repository.
        package_data: Optional package registry data.

    Returns:
        Tuple of (maintained_score, list of maintenance issues).
    """
    maintenance_issues = []

    # Default maintenance score
    maintained_score = 0.5

    if repo_dir:
        try:
            # Analyze commit patterns
            commit_data = analyze_commit_frequency(repo_dir)

            # Analyze release cadence
            release_data = analyze_release_cadence(repo_dir, package_data)

            # Analyze issue activity
            issue_data = analyze_issue_activity(repo_dir)

            # Calculate maintained score
            maintained_score = calculate_maintained_score(
                commit_data, release_data, issue_data
            )

            # Add maintenance issues based on analysis
            if (
                "average_monthly_commits" in commit_data
                and commit_data["average_monthly_commits"] < 1
            ):
                maintenance_issues.append(
                    "Low commit activity (less than monthly commits)"
                )

            if "commit_trend" in commit_data and commit_data["commit_trend"] < -0.2:
                maintenance_issues.append("Declining commit frequency")

            if (
                "days_since_last_release" in release_data
                and release_data["days_since_last_release"] > 365
            ):
                maintenance_issues.append("No release in over a year")

            if (
                "release_overdue_days" in release_data
                and release_data["release_overdue_days"] > 0
            ):
                avg_interval = release_data.get("average_days_between_releases", 90)
                if release_data["release_overdue_days"] > avg_interval * 2:
                    maintenance_issues.append("Release significantly overdue")

            # Log results
            logger.info(
                f"Maintenance score for {dependency.name}: {maintained_score:.2f}"
            )
            for issue in maintenance_issues:
                logger.info(f"Maintenance issue for {dependency.name}: {issue}")

        except Exception as e:
            logger.error(f"Error checking maintained status: {e}")
    else:
        maintenance_issues.append(
            "No repository information available for maintenance analysis"
        )

    return maintained_score, maintenance_issues
