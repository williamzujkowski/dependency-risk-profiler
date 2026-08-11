"""The arithmetic ceiling on repository substitution, through the real scorer.

`docs/full-instrument-manipulation-protocol.md`, deliverable (b). **This is an
upper bound, not a demonstrated attack.** It asserts that a substituted healthy
repository yields healthy readings on all eight derived signals rather than
cloning one and observing it, so what it measures is the scorer's arithmetic
under maximally favourable inputs. The review was explicit that the honest
headline is deliverable (a), the weight share; this shows the aggregation
composes linearly rather than clamping the repository-derived channel, which
the weight share alone cannot establish.

    PYTHONPATH=research uv run python -m composition.substitution_demo
"""

from dependency_risk_profiler.models import (
    AdvisoryLookupState, DependencyMetadata, SecurityMetrics, CommunityMetrics,
)
from dependency_risk_profiler.release_dates import record_source_repository, resolve_repository
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer


def base() -> DependencyMetadata:
    d = DependencyMetadata(name="victim", installed_version="1.0.0")
    d.record_advisory_lookup(AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=())
    d.maintainer_count = 1
    return d


sc = RiskScorer()

# Arm A: no repository declared at all.
a = base()
record_source_repository(a, resolve_repository([None]))
ra = sc.score_dependency(a)

# Arm B: declares an unrelated repository whose derived signals all read healthy.
b = base()
record_source_repository(b, resolve_repository(["https://github.com/facebook/react"]))
sm = SecurityMetrics()
for field, value in (
    ("has_security_policy", True), ("has_dependency_update_tools", True),
    ("has_signed_commits", True), ("has_branch_protection", True),
    ("is_maintained", True), ("has_tests", True), ("has_ci", True),
    ("has_contribution_guidelines", True),
):
    if hasattr(sm, field):
        setattr(sm, field, value)
b.security_metrics = sm
cm = CommunityMetrics()
for field, number in (
    ("star_count", 200000),
    ("contributor_count", 1500),
    ("commit_frequency", 30.0),
    ("fork_count", 40000),
):
    if hasattr(cm, field):
        setattr(cm, field, number)
b.community_metrics = cm
rb = sc.score_dependency(b)

print("A (no repo)      total=%.4f norm=%.4f insufficient=%s" % (ra.total_score, ra.total_score/sc.max_score, ra.insufficient_data))
print("B (points at an unrelated healthy repo) total=%.4f norm=%.4f insufficient=%s" % (rb.total_score, rb.total_score/sc.max_score, rb.insufficient_data))
print("normalised drop = %.4f" % ((ra.total_score-rb.total_score)/sc.max_score))
for n in (
    "security_policy_score",
    "signed_commits_score",
    "branch_protection_score",
    "maintained_score",
    "health_indicators_score",
    "community_score",
    "dependency_update_score",
    "source_repository_score",
):
    print("  %-28s A=%-6s B=%-6s" % (n, getattr(ra, n, None), getattr(rb, n, None)))
