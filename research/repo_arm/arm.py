"""Assembling the repository arm's inputs for the shipped scorer.

The registry inputs come from ``abandonment_pilot.features.build_metadata``
unchanged, so the repository arm is the registry arm plus a block rather than a
second scoring path that has to be kept in step with it. The repository inputs
are then attached to the same object, and the shipped ``RiskScorer`` decides
what is measured — this module never touches a weight.

``community_popularity`` is deliberately not attached: ``star_count`` stays
None, the scorer reports the signal unmeasured, and it leaves both the
numerator and the denominator. That is the honest encoding of "GH Archive was
not obtainable", and it is why no current star count appears anywhere here.
"""

from __future__ import annotations

from typing import Optional

from abandonment_pilot.cohort import CohortMember
from abandonment_pilot.features import PILOT_SIGNALS, build_metadata
from abandonment_pilot.snapshot import PackageRecord
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    SecurityMetrics,
)

from .signals_at_t import RepoSignals


def build_arm_metadata(
    record: PackageRecord,
    member: CohortMember,
    signals: Optional[RepoSignals],
) -> DependencyMetadata:
    """Build the as-of-T inputs for the registry-plus-repository arm.

    Args:
        record: The package's snapshot record.
        member: The cohort member, carrying the release index in force at T.
        signals: The repository reconstruction, or None when no repository was
            readable — in which case the repository block is simply absent and
            the scorer reports those signals unmeasured.

    Returns:
        Metadata carrying only as-of-T inputs.
    """
    dependency = build_metadata(record, member, PILOT_SIGNALS)
    if signals is None or signals.error is not None:
        return dependency

    dependency.has_tests = signals.has_tests
    dependency.has_ci = signals.has_ci
    dependency.has_contribution_guidelines = signals.has_contribution_guidelines

    security = dependency.security_metrics or SecurityMetrics()
    security.has_security_policy = signals.has_security_policy
    security.has_dependency_update_tools = signals.has_dependency_update_tools
    security.is_maintained = signals.is_maintained
    dependency.security_metrics = security

    community = dependency.community_metrics or CommunityMetrics()
    community.commit_frequency = signals.commit_frequency
    # star_count stays None on purpose. See the module docstring.
    dependency.community_metrics = community
    return dependency
