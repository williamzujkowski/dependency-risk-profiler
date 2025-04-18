"""Helper functions for repository analysis.

This module serves as a bridge between analyzers and scorecard modules,
helping to avoid circular imports.
"""

import logging
from datetime import datetime
from typing import List, Optional, Tuple, cast

from .models import DependencyMetadata, SecurityMetrics
from .scorecard.branch_protection import check_branch_protection
from .scorecard.dependency_update import check_dependency_update_tools
from .scorecard.maintained import check_maintained_status
from .scorecard.security_policy import check_security_policy
from .scorecard.signed_commits import check_signed_commits
from .utils import check_health_indicators, count_contributors, get_last_commit_date

logger = logging.getLogger(__name__)


def analyze_repository(dependency: DependencyMetadata, repo_dir: str) -> DependencyMetadata:
    """Analyze a git repository for a dependency.

    Args:
        dependency: Dependency metadata.
        repo_dir: Path to the cloned repository.

    Returns:
        Updated dependency metadata.
    """
    try:
        # Get last commit date
        last_commit_date = get_last_commit_date(repo_dir)
        if last_commit_date:
            # Since last_updated is Optional[datetime] but get_last_commit_date returns str
            # We'll convert the ISO format string to datetime here
            try:
                dependency.last_updated = datetime.fromisoformat(last_commit_date)
            except ValueError:
                logger.warning(f"Could not parse date format: {last_commit_date}")
                # Keep as is if we can't parse it
                pass

        # Count contributors
        contributor_count = count_contributors(repo_dir)
        if contributor_count:
            dependency.maintainer_count = contributor_count

        # Check for health indicators
        has_tests, has_ci, has_contribution_guidelines = check_health_indicators(repo_dir)
        dependency.has_tests = has_tests
        dependency.has_ci = has_ci
        dependency.has_contribution_guidelines = has_contribution_guidelines

        # Check for security policy
        has_security_policy, security_policy_score, security_issues = check_security_policy(
            dependency, repo_dir
        )

        # Log security policy issues
        for issue in security_issues:
            logger.info(f"Security policy issue for {dependency.name}: {issue}")

        # Check for dependency update tools
        has_update_tools, update_tools_score, update_issues = check_dependency_update_tools(
            dependency, repo_dir
        )
        
        # Initialize security metrics if not already present
        if dependency.security_metrics is None:
            dependency.security_metrics = SecurityMetrics()
        
        # Make sure security_metrics is not None before accessing it
        if dependency.security_metrics:
            dependency.security_metrics.has_dependency_update_tools = has_update_tools

        # Log dependency update tools issues
        for issue in update_issues:
            logger.info(f"Dependency update tools issue for {dependency.name}: {issue}")

        # Check for signed commits
        has_signed_commits, signed_commits_score, signed_commits_issues = check_signed_commits(
            dependency, repo_dir
        )
        
        # Initialize security metrics if not already present (redundant but safe)
        if dependency.security_metrics is None:
            dependency.security_metrics = SecurityMetrics()
        
        # Make sure security_metrics is not None before accessing it
        if dependency.security_metrics:
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
        
        # Make sure security_metrics is not None before accessing it
        if dependency.security_metrics:
            dependency.security_metrics.has_branch_protection = has_branch_protection

        # Log branch protection issues
        for issue in branch_protection_issues:
            logger.info(f"Branch protection issue for {dependency.name}: {issue}")

        # Check for maintained status
        is_maintained, maintained_score, maintained_issues = check_maintained_status(
            dependency, repo_dir
        )
        # No need to set any attribute on dependency from this function

        # Log maintained status issues
        for issue in maintained_issues:
            logger.info(f"Maintained status issue for {dependency.name}: {issue}")

    except Exception as e:
        logger.error(f"Error analyzing repository for {dependency.name}: {e}")

    return dependency