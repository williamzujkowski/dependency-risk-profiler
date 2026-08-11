"""The causal step, measured against a real repository rather than assumed.

`docs/full-instrument-manipulation-result.md`. The manipulation study asserted
that a substituted healthy repository reads healthy on all eight derived
signals. A reviewer voted to reject over exactly that, and running the
collectors showed the premise is false -- so these pin what was actually
measured, not what was assumed.

No network: the numbers below were produced against a clone of `ossf/scorecard`
and are recorded as constants. What is tested here is the *arithmetic* those
numbers feed, which is the part that must not drift silently.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))

from dependency_risk_profiler.models import (  # noqa: E402
    AdvisoryLookupState,
    DependencyMetadata,
    SecurityMetrics,
)
from dependency_risk_profiler.release_dates import (  # noqa: E402
    record_source_repository,
    resolve_repository,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer  # noqa: E402

#: Measured by running the production collectors against a clone of
#: github.com/ossf/scorecard on 2026-08-11. Recorded rather than re-fetched so
#: this test needs no network and cannot go flaky on someone else's repository.
MEASURED_ON_A_HEALTHY_REPO = {
    "has_security_policy": True,
    "has_branch_protection": True,
    "has_signed_commits": None,
}


def _dependency() -> DependencyMetadata:
    dependency = DependencyMetadata(name="victim", installed_version="1.0.0")
    dependency.record_advisory_lookup(
        AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=()
    )
    dependency.maintainer_count = 1
    return dependency


def test_declaring_no_repository_is_the_top_of_the_scale() -> None:
    """1.0, and an abstention. The baseline the attacker improves on."""
    scorer = RiskScorer()
    dependency = _dependency()
    record_source_repository(dependency, resolve_repository([None]))
    result = scorer.score_dependency(dependency)
    assert result.total_score / scorer.max_score == pytest.approx(1.0)
    assert result.insufficient_data is True


def test_a_mediocre_substituted_repository_still_pays() -> None:
    """The finding that survived the premise being wrong.

    `ossf/scorecard` reads 0.79 on security policy and 0.30 on branch
    protection -- nowhere near clean. Substituting it still moves the score
    0.7333, because "no repository" scores 1.0 and anything beats that.

    An attacker does not need a healthy repository. They need any repository.
    """
    scorer = RiskScorer()
    dependency = _dependency()
    record_source_repository(
        dependency, resolve_repository(["https://github.com/ossf/scorecard"])
    )
    metrics = SecurityMetrics()
    for field, value in MEASURED_ON_A_HEALTHY_REPO.items():
        if value is not None and hasattr(metrics, field):
            setattr(metrics, field, value)
    dependency.security_metrics = metrics

    result = scorer.score_dependency(dependency)
    normalised = result.total_score / scorer.max_score
    assert normalised == pytest.approx(0.2667, abs=5e-4)
    assert 1.0 - normalised == pytest.approx(0.7333, abs=5e-4)


def test_three_collectors_do_not_clear_the_sufficiency_bar() -> None:
    """The correction: the abstention flip needs more than three signals.

    The constructed arm asserted eight signals measured and the tool issued a
    verdict. With three actually collected it still abstains, so the original
    claim was broader than what has been measured. Pinned so the corrected
    wording cannot drift back.
    """
    scorer = RiskScorer()
    dependency = _dependency()
    record_source_repository(
        dependency, resolve_repository(["https://github.com/ossf/scorecard"])
    )
    metrics = SecurityMetrics()
    for field, value in MEASURED_ON_A_HEALTHY_REPO.items():
        if value is not None and hasattr(metrics, field):
            setattr(metrics, field, value)
    dependency.security_metrics = metrics
    assert scorer.score_dependency(dependency).insufficient_data is True
