"""OpenSSF Scorecard-inspired health checks for dependency analysis."""

from .maintained import check_maintained_status
from .security_policy import check_security_policy
from .dependency_update import check_dependency_update_tools
from .signed_commits import check_signed_commits
from .branch_protection import check_branch_protection

__all__ = [
    "check_maintained_status",
    "check_security_policy",
    "check_dependency_update_tools",
    "check_signed_commits",
    "check_branch_protection"
]