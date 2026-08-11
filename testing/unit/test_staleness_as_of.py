"""`staleness` must be computable for a date other than now (#376).

Before this the reference was always `datetime.now()` with no way to supply
another, so the signal could not be computed for any past date. On the pinned
two-year-old snapshot it came out **1.0 for all 2,906 packages** -- a constant,
which distinguishes nothing while still counting toward the sufficiency bar
that decides whether a verdict is issued.

Two things need guarding: that supplying `as_of` actually changes the answer,
and that omitting it changes nothing for a live run.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from dependency_risk_profiler.models import AdvisoryLookupState, DependencyMetadata
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

T = datetime(2024, 8, 1, tzinfo=timezone.utc)


def _dependency(published: datetime) -> DependencyMetadata:
    dependency = DependencyMetadata(name="pkg", installed_version="1.0.0")
    dependency.record_advisory_lookup(
        AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=()
    )
    dependency.last_updated = published
    return dependency


def test_staleness_is_measured_from_as_of_when_given() -> None:
    """A release ten days before T is fresh at T, whatever today is."""
    scorer = RiskScorer()
    fresh_at_t = T - timedelta(days=10)
    assert scorer._calculate_staleness_score(fresh_at_t, as_of=T) == 0.0


def test_the_same_release_saturates_when_measured_from_now() -> None:
    """The defect, pinned: without `as_of` an old snapshot is all top-band.

    This is why the composition study saw staleness=1.0 across the entire
    cohort. If this ever stops holding, the default reference has changed and
    live behaviour with it.
    """
    scorer = RiskScorer()
    fresh_at_t = T - timedelta(days=10)
    from_now = scorer._calculate_staleness_score(fresh_at_t)
    assert from_now is not None and from_now > 0.5, (
        "a release from 2024 no longer reads as stale from wall-clock now, so "
        "either the bands moved or the default reference did"
    )


@pytest.mark.parametrize(
    "age_days,expected",
    [(1, 0.0), (29, 0.0), (45, 0.25), (120, 0.5), (200, 0.75)],
)
def test_the_bands_are_the_same_whichever_reference_is_used(
    age_days: int, expected: float
) -> None:
    """`as_of` moves the reference, not the thresholds.

    A parameter that quietly re-banded as well as re-referenced would make
    historical scores incomparable with live ones, which is the whole point of
    adding it.
    """
    scorer = RiskScorer()
    published = T - timedelta(days=age_days)
    assert scorer._calculate_staleness_score(published, as_of=T) == expected

    now = datetime.now(timezone.utc)
    assert scorer._calculate_staleness_score(now - timedelta(days=age_days)) == expected


def test_omitting_as_of_leaves_live_scoring_byte_identical() -> None:
    """The compatibility guarantee: a live run must not notice this change."""
    scorer = RiskScorer()
    recent = datetime.now(timezone.utc) - timedelta(days=5)
    default = scorer.score_dependency(_dependency(recent))
    explicit = scorer.score_dependency(
        _dependency(recent), as_of=datetime.now(timezone.utc)
    )
    assert default.total_score == pytest.approx(explicit.total_score)
    assert default.staleness_score == explicit.staleness_score


def test_a_naive_as_of_is_read_as_utc_rather_than_local() -> None:
    """Two clocks in one subtraction is a bug this repository has had before."""
    scorer = RiskScorer()
    published = T - timedelta(days=10)
    naive = T.replace(tzinfo=None)
    assert scorer._calculate_staleness_score(published, as_of=naive) == 0.0


def test_scoring_as_of_a_past_date_no_longer_saturates_a_whole_cohort() -> None:
    """The payoff: at T, packages differ instead of all reading 1.0.

    The composition study could not adjudicate its shipped-versus-ablated
    comparison because `staleness` was constant. With `as_of` the signal
    varies, which is what makes that comparison answerable at all.
    """
    scorer = RiskScorer()
    ages = (5, 45, 120, 200, 500)
    scores = {
        scorer._calculate_staleness_score(T - timedelta(days=age), as_of=T)
        for age in ages
    }
    assert len(scores) == len(ages), f"staleness still collapses at T: {scores}"
