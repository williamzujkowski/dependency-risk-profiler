"""The arithmetic behind the per-ecosystem floors, pinned on its own (#136).

``signal_floors`` used to hold two jobs in one number. Every ecosystem was
floored at seven measured signals, and seven was chosen because seven of
fourteen is exactly where the scorer flips to UNKNOWN — an interesting property
about the scorer, and a useless regression floor, because an ecosystem sitting
at eight could lose a field, collapse to all-UNKNOWN, and still pass.

The floors now sit at what each ecosystem measures. The edge arithmetic is
still worth documenting, so it lives here, where it can be true without being
load-bearing.

These tests reuse the recorded crates.io payload from ``test_crates_adapter``
rather than a synthetic score: the claim is about a real adapter reaching a
real threshold, and a hand-built score would only restate the inequality it is
supposed to demonstrate.
"""

import copy
from typing import Dict

from signal_floors import (
    MIN_MEASURED_SIGNALS,
    REGISTRY_MEASURED_SIGNALS,
    SCORES_FROM_REGISTRY_ALONE,
)
from test_crates_adapter import (
    ANYHOW_CRATE_RESPONSE,
    ANYHOW_OWNERS_RESPONSE,
    _score_crate_offline,
)

from dependency_risk_profiler.models import DependencyRiskScore, RiskLevel

# The floor that #136 replaced. Kept as a literal so the test below can show
# what it used to admit rather than describe it.
SUPERSEDED_FLOOR = 7


def _crate_response_without_license() -> Dict[str, object]:
    """Return the anyhow payload with the license field the adapter reads removed."""
    payload = copy.deepcopy(ANYHOW_CRATE_RESPONSE)
    versions = payload["versions"]
    assert isinstance(versions, list)
    for version in versions:
        assert isinstance(version, dict)
        version.pop("license", None)
    return payload


def _owners_response_without_owners() -> Dict[str, object]:
    """Return an owners payload that lists nobody, as a 404-shaped answer does."""
    payload = copy.deepcopy(ANYHOW_OWNERS_RESPONSE)
    payload["users"] = []
    return payload


def _collapsed_score() -> DependencyRiskScore:
    """Score anyhow two registry fields short of the real payload.

    Two, not one, since #204: reading the dependencies endpoint took cargo from
    eight measured signals to nine, so the ecosystem now has exactly one signal
    of headroom above the edge. Losing the licence *and* the owner list is what
    puts it back on the collapsed side, and that is the whole content of the
    re-baseline — a floor of nine fails on the first loss, one step before the
    verdict disappears.
    """
    return _score_crate_offline(
        _crate_response_without_license(), _owners_response_without_owners()
    )


def test_a_healthy_crate_clears_the_bar_by_exactly_one_signal() -> None:
    """Cargo measures nine and is unmeasured on seven, one clear of the edge.

    The seventh unmeasured signal is the community pair, which counts once —
    an absent community record is one gap, not two (#166). Before #204 this
    read eight and eight, clearing by nothing; the dependency list is the
    signal that bought the margin.
    """
    score = _score_crate_offline(ANYHOW_CRATE_RESPONSE)

    assert score.measured_signal_count == 9
    assert score.unknown_signal_count == 7
    assert score.insufficient_data is False


def test_losing_two_registry_fields_collapses_the_whole_ecosystem() -> None:
    """The #127 / #132 failure reproduced, at the depth it now takes to reach."""
    score = _collapsed_score()

    assert score.measured_signal_count == 7
    assert score.insufficient_data is True
    assert score.risk_level is RiskLevel.UNKNOWN


def test_one_lost_field_still_reaches_a_verdict_and_still_fails_the_floor() -> None:
    """The margin the floor is supposed to catch, shown from both sides.

    A floor that only fired once the ecosystem had already collapsed would be
    reporting the fire after the building was gone. cargo losing one field is
    exactly the state the floor exists to fail on: eight measured, still a
    verdict, and already below nine.
    """
    score = _score_crate_offline(_crate_response_without_license())

    assert score.measured_signal_count == 8
    assert score.insufficient_data is False
    assert score.risk_level is not RiskLevel.UNKNOWN
    assert score.measured_signal_count < MIN_MEASURED_SIGNALS["cargo"]


def test_the_superseded_floor_of_seven_admitted_a_collapsed_ecosystem() -> None:
    """Why the floors were re-baselined: seven passed the state it existed to catch."""
    score = _collapsed_score()

    assert score.risk_level is RiskLevel.UNKNOWN
    assert score.measured_signal_count >= SUPERSEDED_FLOOR
    assert score.measured_signal_count < MIN_MEASURED_SIGNALS["cargo"]


def test_an_ecosystem_that_reaches_a_verdict_is_floored_above_the_edge() -> None:
    """A floor at the edge cannot fail before the ecosystem has already collapsed.

    golang is the only exception left, and it is a registry difference rather
    than an unfinished adapter: proxy.golang.org publishes no licence, no owner
    list, and a scopeless ``go.mod``, so Go modules sit below the edge offline
    and are recorded as not reaching a verdict unaided. npm was beside it until
    #204. Every ecosystem that does reach a verdict must be floored above the
    edge, or its floor is decoration.
    """
    for ecosystem, floor in MIN_MEASURED_SIGNALS.items():
        if SCORES_FROM_REGISTRY_ALONE[ecosystem]:
            assert floor > SUPERSEDED_FLOOR, (
                f"{ecosystem} reaches a verdict from registry metadata but is "
                f"floored at {floor}, which a collapsed ecosystem also passes"
            )
        else:
            assert floor <= SUPERSEDED_FLOOR, (
                f"{ecosystem} is floored at {floor} but recorded as short of a "
                f"verdict; one of the two is stale"
            )


def test_the_tables_describe_the_same_ecosystems() -> None:
    """The module asserts this at import; a named test says so out loud.

    #129 added nuget to the floors while #146 was independently adding the
    verdict table, and the mismatch surfaced at a rebase as a KeyError inside
    an adapter test rather than as a message about the tables.
    """
    ecosystems = set(MIN_MEASURED_SIGNALS)

    assert set(SCORES_FROM_REGISTRY_ALONE) == ecosystems
    assert set(REGISTRY_MEASURED_SIGNALS) == ecosystems


def test_each_floor_equals_the_signals_it_names() -> None:
    """The count and the named set are two views of one measurement."""
    for ecosystem, floor in MIN_MEASURED_SIGNALS.items():
        named = sorted(REGISTRY_MEASURED_SIGNALS[ecosystem])
        assert floor == len(named), f"{ecosystem}: floor {floor} but names {named}"
