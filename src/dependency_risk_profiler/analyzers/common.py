"""Common analysis functions shared across different ecosystems."""

import logging
from typing import Optional, Tuple

from ..utils import (
    check_for_vulnerabilities,
    check_health_indicators,
    clone_repo,
    count_contributors,
    fetch_json,
    fetch_url,
    get_last_commit_date,
)

logger = logging.getLogger(__name__)

# Re-export utilities for backwards compatibility
__all__ = [
    "fetch_url",
    "fetch_json",
    "clone_repo",
    "get_last_commit_date",
    "count_contributors",
    "check_health_indicators",
    "check_for_vulnerabilities",
]