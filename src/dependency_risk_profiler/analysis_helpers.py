"""Helper functions for repository analysis.

This module serves as a bridge between analyzers and scorecard modules,
helping to avoid circular imports.
"""

import logging
from datetime import datetime

from .community.analyzer import calculate_commit_frequency
from .models import CommunityMetrics, DependencyMetadata, SecurityMetrics
from .release_dates import apply_repository_activity_date
from .scorecard.branch_protection import check_branch_protection
from .scorecard.dependency_update import check_dependency_update_tools
from .scorecard.maintained import check_maintained_status
from .scorecard.security_policy import check_security_policy
from .scorecard.signed_commits import check_signed_commits
from .signals import FieldSource, ProvenancedField
from .utils import check_health_indicators, count_contributors, get_last_commit_date

logger = logging.getLogger(__name__)


def analyze_repository(
    dependency: DependencyMetadata, repo_dir: str
) -> DependencyMetadata:
    """Analyze a git repository for a dependency.

    Args:
        dependency: Dependency metadata.
        repo_dir: Path to the cloned repository.

    Returns:
        Updated dependency metadata.
    """
    try:
        # Last commit date, applied only when the registry published no release
        # date of its own (#146). A commit says when someone touched the
        # source; the registry says when consumers last received anything, and
        # that is what a manifest pins.
        last_commit_date = get_last_commit_date(repo_dir)
        if last_commit_date:
            # get_last_commit_date returns str; last_updated stores datetime.
            # We'll convert the ISO format string to datetime here
            try:
                apply_repository_activity_date(
                    dependency,
                    datetime.fromisoformat(last_commit_date),
                    source=FieldSource.REPOSITORY_CLONE_HISTORY,
                )
            except ValueError:
                logger.warning(f"Could not parse date format: {last_commit_date}")
                # Keep as is if we can't parse it
                pass

        # Count contributors. ``count_contributors`` answers None for a count
        # it could not take (a shallow clone, a git failure) and an int for one
        # it did, so the guard is on None: a measured zero is an answer, and
        # ``if contributor_count:`` threw it away as though nobody had looked.
        # The commit-cadence read below already guards this way (#217).
        contributor_count = count_contributors(repo_dir)
        if contributor_count is not None:
            dependency.maintainer_count = contributor_count
            dependency.record_field_source(
                ProvenancedField.MAINTAINER_COUNT,
                FieldSource.REPOSITORY_CLONE_HISTORY,
            )

        # Development cadence, read from the clone we already have. Half of the
        # community score is supposed to be commits-per-month, and until #166 no
        # caller ever produced it, so the "composite" was the star bucket alone.
        commit_frequency = calculate_commit_frequency(repo_dir)
        if commit_frequency is not None:
            if dependency.community_metrics is None:
                dependency.community_metrics = CommunityMetrics()
            dependency.community_metrics.commit_frequency = commit_frequency
            dependency.record_field_source(
                ProvenancedField.COMMIT_FREQUENCY,
                FieldSource.REPOSITORY_CLONE_HISTORY,
            )

        # Check for health indicators
        has_tests, has_ci, has_contribution_guidelines = check_health_indicators(
            repo_dir
        )
        dependency.has_tests = has_tests
        dependency.has_ci = has_ci
        dependency.has_contribution_guidelines = has_contribution_guidelines
        dependency.record_field_source(
            ProvenancedField.HAS_TESTS, FieldSource.REPOSITORY_CLONE_WORKTREE
        )
        dependency.record_field_source(
            ProvenancedField.HAS_CI, FieldSource.REPOSITORY_CLONE_WORKTREE
        )

        # Check for security policy
        has_security_policy, security_policy_score, security_issues = (
            check_security_policy(dependency, repo_dir)
        )

        # Log security policy issues
        for issue in security_issues:
            logger.info(f"Security policy issue for {dependency.name}: {issue}")

        # Check for dependency update tools. Each of the four writes below is
        # guarded on ``is not None`` for the reason the contributor count above
        # is: the check answers None for a signal it could not measure — no
        # repository, or a read that raised — and None is not a finding. Writing
        # it would be indistinguishable from "we looked and the tooling isn't
        # there", which is what the scorer counts as evidence (#218).
        has_update_tools, update_tools_score, update_issues = (
            check_dependency_update_tools(dependency, repo_dir)
        )

        # Initialize security metrics if not already present
        if dependency.security_metrics is None:
            dependency.security_metrics = SecurityMetrics()

        if has_update_tools is not None:
            dependency.security_metrics.has_dependency_update_tools = has_update_tools

        # Log dependency update tools issues
        for issue in update_issues:
            logger.info(f"Dependency update tools issue for {dependency.name}: {issue}")

        # Check for signed commits
        has_signed_commits, signed_commits_score, signed_commits_issues = (
            check_signed_commits(dependency, repo_dir)
        )

        # Initialize security metrics if not already present (redundant but safe)
        if dependency.security_metrics is None:
            dependency.security_metrics = SecurityMetrics()

        if has_signed_commits is not None:
            dependency.security_metrics.has_signed_commits = has_signed_commits

        # Log signed commits issues
        for issue in signed_commits_issues:
            logger.info(f"Signed commits issue for {dependency.name}: {issue}")

        # Check for branch protection
        has_branch_protection, branch_protection_score, branch_protection_issues = (
            check_branch_protection(dependency, repo_dir)
        )

        # Initialize security metrics if not already present (redundant but safe)
        if dependency.security_metrics is None:
            dependency.security_metrics = SecurityMetrics()

        if has_branch_protection is not None:
            dependency.security_metrics.has_branch_protection = has_branch_protection

        # Log branch protection issues
        for issue in branch_protection_issues:
            logger.info(f"Branch protection issue for {dependency.name}: {issue}")

        # Check for maintained status
        is_maintained, maintained_score, maintained_issues = check_maintained_status(
            dependency, repo_dir, None  # Pass None for package_data
        )

        # Set is_maintained on dependency if security_metrics is available
        if dependency.security_metrics is None:
            dependency.security_metrics = SecurityMetrics()

        if is_maintained is not None:
            dependency.security_metrics.is_maintained = is_maintained

        # Log maintained status issues
        for issue in maintained_issues:
            logger.info(f"Maintained status issue for {dependency.name}: {issue}")

    except Exception as e:
        logger.error(f"Error analyzing repository for {dependency.name}: {e}")

    return dependency
