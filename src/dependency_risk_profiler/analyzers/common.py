"""Analysis logic shared across the ecosystem adapters.

This module holds adapter logic that has nowhere else to live, not a second
name for :mod:`dependency_risk_profiler.utils`. Import the HTTP and git
helpers straight from ``..utils``; a re-export here only adds a hop a reader
has to follow before they learn where the function actually is.
"""

import logging
from typing import Optional

from ..analysis_helpers import analyze_repository
from ..models import DependencyMetadata
from ..utils import cloned_repo, is_cloneable_repo_url

logger = logging.getLogger(__name__)

__all__ = ["collect_repository_signals"]


def collect_repository_signals(
    dependency: DependencyMetadata,
    repository_url: Optional[str],
    clone_repos: bool,
) -> DependencyMetadata:
    """Fill the repository-derived signals from a clone of the source repo.

    Eight of the scorer's signals — staleness, health indicators, and the five
    OpenSSF-style security checks — can only be read out of the package's own
    source tree. Every adapter that resolves a repository URL needs the same
    guarded clone-and-analyze step, and an ecosystem that skips it scores
    UNKNOWN for every dependency (#127, #132). One implementation keeps the
    guards identical: org scans set ``clone_repos`` False and derive the same
    signals from the GitHub API instead, unhosted or unparseable URLs are
    skipped rather than handed to ``git clone``, and a failed clone leaves the
    signals honestly unmeasured (#74) rather than defaulting them to zero.

    Args:
        dependency: Dependency metadata to enrich.
        repository_url: Canonical repository URL, or None when the registry
            publishes no repository for the package.
        clone_repos: Whether cloning is enabled for this run.

    Returns:
        The dependency, enriched when a clone was available and unchanged
        otherwise.
    """
    if not clone_repos or not repository_url:
        return dependency
    if not is_cloneable_repo_url(repository_url):
        logger.debug(
            "Skipping repository signals for %s: %s is not a cloneable repo URL",
            dependency.name,
            repository_url,
        )
        return dependency

    with cloned_repo(repository_url) as clone_result:
        if clone_result is None:
            return dependency
        repo_dir, _ = clone_result
        return analyze_repository(dependency, repo_dir)
