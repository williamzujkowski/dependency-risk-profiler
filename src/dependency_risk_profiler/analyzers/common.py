"""Common analysis functions shared across different ecosystems."""

import logging

from ..utils import (
    check_health_indicators,
    clone_repo,
    cloned_repo,
    count_contributors,
    fetch_json,
    fetch_url,
    get_last_commit_date,
    is_cloneable_repo_url,
)

logger = logging.getLogger(__name__)

# Re-export utilities for backwards compatibility
__all__ = [
    "fetch_url",
    "fetch_json",
    "clone_repo",
    "cloned_repo",
    "is_cloneable_repo_url",
    "get_last_commit_date",
    "count_contributors",
    "check_health_indicators",
]
