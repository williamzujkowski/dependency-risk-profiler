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

**Stage 7's ablation is absence, not substitution.** ``enabled`` withholds a
signal's *input*, so the shipped scorer reports it unmeasured and renormalises
over the remaining weights (#74). Substituting a neutral value instead would
score a signal nobody measured, which is the defect #141 shipped. The default
attaches the whole block, so stages 2-4 read exactly as they did before the
parameter existed.
"""

from __future__ import annotations

from typing import FrozenSet, Optional

from abandonment_pilot.cohort import CohortMember
from abandonment_pilot.features import PILOT_SIGNALS, build_metadata
from abandonment_pilot.snapshot import PackageRecord
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    SecurityMetrics,
)
from dependency_risk_profiler.signals import (
    SIGNAL_COMMUNITY_ACTIVITY,
    SIGNAL_DEPENDENCY_UPDATE,
    SIGNAL_HEALTH_INDICATORS,
    SIGNAL_MAINTAINED,
    SIGNAL_SECURITY_POLICY,
)

from .signals_at_t import RepoSignals

#: The repository block as stage 3 actually measured it. **Five, not six.**
#: ``community_popularity`` needed cumulative GH Archive ``WatchEvent`` back to
#: 2015 and the only queryable public mirror starts 2023-01-13, so it could only
#: have been supplied as a proxy, which §4b forbids. ``signed_commits`` and
#: ``branch_protection`` were unevaluable at any past date before the study
#: began (§4). Nothing here may quietly grow back to six.
REPO_SIGNALS: FrozenSet[str] = frozenset(
    {
        SIGNAL_HEALTH_INDICATORS,
        SIGNAL_SECURITY_POLICY,
        SIGNAL_DEPENDENCY_UPDATE,
        SIGNAL_COMMUNITY_ACTIVITY,
        SIGNAL_MAINTAINED,
    }
)


def build_arm_metadata(
    record: PackageRecord,
    member: CohortMember,
    signals: Optional[RepoSignals],
    enabled: FrozenSet[str] = REPO_SIGNALS,
) -> DependencyMetadata:
    """Build the as-of-T inputs for the registry-plus-repository arm.

    Args:
        record: The package's snapshot record.
        member: The cohort member, carrying the release index in force at T.
        signals: The repository reconstruction, or None when no repository was
            readable — in which case the repository block is simply absent and
            the scorer reports those signals unmeasured.
        enabled: Which repository signals to supply inputs for. Dropping one is
            the ablation; the scorer then reports it unmeasured and
            renormalizes over the remaining weights.

    Returns:
        Metadata carrying only as-of-T inputs.
    """
    dependency = build_metadata(record, member, PILOT_SIGNALS)
    if signals is None or signals.error is not None:
        return dependency

    if SIGNAL_HEALTH_INDICATORS in enabled:
        dependency.has_tests = signals.has_tests
        dependency.has_ci = signals.has_ci
        dependency.has_contribution_guidelines = signals.has_contribution_guidelines

    security = dependency.security_metrics or SecurityMetrics()
    if SIGNAL_SECURITY_POLICY in enabled:
        security.has_security_policy = signals.has_security_policy
    if SIGNAL_DEPENDENCY_UPDATE in enabled:
        security.has_dependency_update_tools = signals.has_dependency_update_tools
    if SIGNAL_MAINTAINED in enabled:
        security.is_maintained = signals.is_maintained
    dependency.security_metrics = security

    community = dependency.community_metrics or CommunityMetrics()
    if SIGNAL_COMMUNITY_ACTIVITY in enabled:
        community.commit_frequency = signals.commit_frequency
    # star_count stays None on purpose. See the module docstring.
    dependency.community_metrics = community
    return dependency
