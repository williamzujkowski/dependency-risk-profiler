"""Enhanced maintained status check for dependencies."""

import logging
import subprocess  # nosec B404
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, TypedDict

from ..forge_paths import (
    CODEOWNERS_PATHS,
    ISSUE_TEMPLATE_PATHS,
    MAINTAINERS_PATHS,
    any_exists,
)
from ..models import DependencyMetadata
from .unmeasured import no_repository_issue, read_failed_issue

logger = logging.getLogger(__name__)


def analyze_commit_frequency(repo_dir: str, months: int = 12) -> Dict[str, float]:
    """Analyze commit frequency over time to determine maintenance trends.

    Args:
        repo_dir: Path to the git repository.
        months: Number of months to analyze.

    Returns:
        Dictionary with monthly commit frequencies and trend indicators.

    Raises:
        ValueError: If ``git rev-list --count`` answered with something that is
            not a count. A month git could not count is not a month with no
            commits, and there is no way to leave a hole in this series: the
            trend compares ``monthly_counts[:3]`` against ``[3:6]``, so dropping
            an element slides the comparison windows onto the wrong months, and
            filling it is the fabrication itself. The series is unanswerable, so
            the caller records the signal as unmeasured (#236).
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
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
            except ValueError as e:
                raise ValueError(
                    f"git rev-list --count answered {output!r} for "
                    f"{start_date}..{end_date}, which is not a commit count"
                ) from e
            monthly_counts.append(count)

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
                trend = 0.0  # No earlier activity to compare
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
        raise

    return result


def _parse_git_iso_date(value: str) -> Optional[datetime]:
    """Parse a git ``creatordate:iso`` string as a tz-aware UTC datetime.

    Git emits e.g. ``2025-06-14 13:34:58 -0700``; this normalizes to UTC so
    cadence subtractions never mix offset-naive and offset-aware datetimes.
    Returns None if the value can't be parsed.
    """
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _require_git_iso_date(value: str, *, source: str) -> datetime:
    """Parse a release date, or refuse to leave it out of the series.

    :func:`_parse_git_iso_date` answers None for a value it cannot read, and
    every caller used to drop those silently. The cadence series is sorted and
    then differenced between adjacent entries, so a dropped date does not
    shorten the series — it merges the two intervals either side of it into one
    that never happened, and a project all of whose dates fail to parse reads as
    a project that has never released (#236).

    Args:
        value: The date string as the source emitted it.
        source: What produced it, so the failure names its own origin. Required
            and keyword-only: an error that cannot say where the value came
            from is most of the way back to silence.

    Returns:
        The parsed date as a tz-aware UTC datetime.

    Raises:
        ValueError: If the value cannot be parsed.
    """
    parsed = _parse_git_iso_date(value)
    if parsed is None:
        raise ValueError(f"{source} {value!r} is not a date this code can read")
    return parsed


def analyze_release_cadence(
    repo_dir: str, package_data: Optional[Dict] = None
) -> Dict[str, float]:
    """Analyze release cadence to determine if project is regularly released.

    Args:
        repo_dir: Path to the git repository.
        package_data: Optional package metadata from registry.

    Returns:
        Dictionary with release cadence metrics. Empty means the sources were
        read and this project has never tagged a release — a measurement, and
        only reachable when a read actually succeeded.

    Raises:
        ValueError: If a tag date could not be read. The cadence series is
            ordered and adjacent-differenced, so a dropped element silently
            merges two release intervals into one: a partial series is not a
            partial measurement of the same quantity, it is a different and
            wrong one. Dropping every unparseable date also made a project whose
            dates git formats unexpectedly read as having no releases at all
            (#236).
        subprocess.SubprocessError: If git could not enumerate the tags and no
            other source answered either.
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result = {}

    try:
        # Not swallowed any more. A git failure here used to fall straight
        # through to the ``package_data`` fallback, and when that was absent —
        # which is every call from ``analyze_repository``, which passes None —
        # the empty ``result`` was returned as though the question had been
        # settled, indistinguishable from a project that has never tagged a
        # release. The fallback reads a genuinely different source, so it is
        # still allowed to answer; what it may not do is cover for a failure
        # with silence (#236).
        tag_read_error: Optional[subprocess.SubprocessError] = None

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

            tag_dates = [
                _require_git_iso_date(line.strip(), source="git tag date")
                for line in output.split("\n")
                if line.strip()
            ]

            if tag_dates:
                # All dates are tz-aware UTC, so subtractions never mix
                # offset-naive and offset-aware datetimes.
                now = datetime.now(timezone.utc)

                # Calculate days between releases
                intervals = [
                    (tag_dates[i] - tag_dates[i + 1]).days
                    for i in range(len(tag_dates) - 1)
                ]
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    result["average_days_between_releases"] = avg_interval

                # Days since last release
                days_since_last = (now - tag_dates[0]).days
                result["days_since_last_release"] = days_since_last

                # Calculate expected next release date
                if "average_days_between_releases" in result:
                    expected_next = tag_dates[0] + timedelta(
                        days=result["average_days_between_releases"]
                    )
                    result["release_overdue_days"] = max(0, (now - expected_next).days)

        except subprocess.SubprocessError as e:
            logger.debug("Could not get tag information from git: %s", e)
            tag_read_error = e

        # Fall back to package data if available
        if package_data and not result:
            # Implementation depends on the package registry format
            # This is a simplified example
            if "time" in package_data and isinstance(package_data["time"], dict):
                # For npm-like registries
                release_dates = []
                for version, timestamp in package_data["time"].items():
                    if version not in ["created", "modified"]:
                        release_dates.append(
                            _require_git_iso_date(
                                timestamp.replace("Z", "+00:00"),
                                source=f"registry release date for {version}",
                            )
                        )

                if release_dates:
                    release_dates.sort(reverse=True)
                    # All release_dates are tz-aware UTC (see _parse_git_iso_date).
                    now = datetime.now(timezone.utc)

                    # Calculate days between releases
                    intervals = [
                        (release_dates[i] - release_dates[i + 1]).days
                        for i in range(len(release_dates) - 1)
                    ]
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        result["average_days_between_releases"] = avg_interval

                    # Days since last release
                    days_since_last = (now - release_dates[0]).days
                    result["days_since_last_release"] = days_since_last

                    # Calculate expected next release date
                    if "average_days_between_releases" in result:
                        expected_next = release_dates[0] + timedelta(
                            days=result["average_days_between_releases"]
                        )
                        result["release_overdue_days"] = max(
                            0, (now - expected_next).days
                        )

            elif "releases" in package_data:
                # For PyPI-like registries
                # Implementation would be specific to the PyPI data structure
                pass

        # Nothing answered. An empty result is only allowed to mean "read, and
        # this project has never released" — if the read that would have said so
        # failed, the caller gets the failure instead.
        if not result and tag_read_error is not None:
            raise tag_read_error

    except Exception as e:
        logger.error(f"Error analyzing release cadence: {e}")
        raise

    return result


class IssueActivity(TypedDict, total=False):
    """Repository-local signals that issues are actively triaged.

    Every key is optional: when the analysis raises, callers must still be able
    to tell "not checked" apart from "checked and absent".
    """

    has_issue_templates: bool
    has_codeowners: bool
    has_maintainership_info: bool


def analyze_issue_activity(repo_path: str) -> IssueActivity:
    """Analyze issue activity to determine project responsiveness.

    Args:
        repo_path: Path to the git repository.

    Returns:
        Dictionary with issue activity metrics.

    Raises:
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result: IssueActivity = {}

    # This would typically require API access to GitHub/GitLab/etc.
    # For a complete implementation, you would need to use the GitHub API
    # Here we just look for indicators in the repo itself

    try:
        repo_path_obj = Path(repo_path)

        # Issue templates, across every forge that has the concept (#291).
        # This check already knew half the answer — it read ``.gitlab`` beside
        # ``.github`` — and the missing half was Gitea's and Forgejo's, which
        # is what made the Codeberg ``django-allauth`` clone report ``False``
        # while ``.gitea/ISSUE_TEMPLATE/`` sat in the tree.
        result["has_issue_templates"] = any_exists(repo_path_obj, ISSUE_TEMPLATE_PATHS)

        # Look for CODEOWNERS file (indicates active maintainership)
        result["has_codeowners"] = any_exists(repo_path_obj, CODEOWNERS_PATHS)

        # Look for active maintainership indicators
        result["has_maintainership_info"] = any_exists(repo_path_obj, MAINTAINERS_PATHS)

    except Exception as e:
        logger.error(f"Error analyzing issue activity: {e}")
        raise

    return result


def calculate_maintained_score(
    commit_data: Dict[str, float],
    release_data: Dict[str, float],
    issue_data: IssueActivity,
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
) -> Tuple[Optional[bool], Optional[float], List[str]]:
    """Check if a dependency is actively maintained.

    Args:
        dependency: Dependency metadata.
        repo_dir: Optional path to cloned repository.
        package_data: Optional package registry data.

    Returns:
        Tuple of (is_maintained, maintained_score, list of maintenance issues).
        The first two are None when the signal could not be measured — no
        repository to read, or a git read that raised — and the issue list says
        which of the two it was. This check used to open on a default score of
        0.5, from which ``is_maintained = score > 0.6`` derived a confident
        ``False`` that no repository had been read to produce (#218).
    """
    maintenance_issues: List[str] = []

    maintained_score: Optional[float] = None

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
            # The read failed part-way through. Whatever was gathered before it
            # failed is not an answer, so nothing is returned as one. This path
            # used to log and say nothing at all, leaving the caller with the
            # default score and no way to tell it apart from a measurement.
            logger.error(f"Error checking maintained status: {e}")
            maintained_score = None
            maintenance_issues.append(read_failed_issue("Maintained status", e))
    else:
        maintenance_issues.append(no_repository_issue("Maintained status"))

    # Consider a package maintained if score is greater than 0.6. An unmeasured
    # score yields an unmeasured verdict rather than a threshold comparison
    # against a number nobody produced.
    is_maintained = None if maintained_score is None else maintained_score > 0.6

    return is_maintained, maintained_score, maintenance_issues
