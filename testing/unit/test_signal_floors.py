"""The arithmetic behind the per-ecosystem floors, pinned on its own (#136).

The floors in ``signal_floors`` sit at what each ecosystem measures. The edge
arithmetic that used to *be* the floor is still worth documenting, so it lives
here, where it can be true without being load-bearing.

The edge: the scorer reports UNKNOWN when ``unmeasured > measured``, so with
sixteen weighed signals a dependency reaches a verdict at eight measured and
loses it at seven. A floor of seven therefore admits a fully collapsed
ecosystem — the all-UNKNOWN state of #127 / #132 — while still reporting
green, which is what :data:`SUPERSEDED_FLOOR` is kept as a literal to show.

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
    REGISTRY_ONLY_CEILING,
    REGISTRY_UNANSWERED_SIGNALS,
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


def _one_field_short() -> DependencyRiskScore:
    """Score anyhow one registry field short of the real payload.

    One is enough. cargo measures eight of sixteen and the edge sits at seven,
    so dropping the licence is the whole distance between a verdict and the
    all-UNKNOWN state of #127 / #132.
    """
    return _score_crate_offline(_crate_response_without_license())


def _two_fields_short() -> DependencyRiskScore:
    """Score anyhow two registry fields short, one step past the edge."""
    return _score_crate_offline(
        _crate_response_without_license(), _owners_response_without_owners()
    )


def test_a_healthy_crate_clears_the_bar_by_exactly_nothing() -> None:
    """Cargo measures eight and is unmeasured on eight, which is the edge itself.

    ``insufficient_data`` is ``unmeasured > measured``, so eight against eight
    reaches a verdict with no margin at all: cargo cannot lose a signal and
    still be scored. The eighth unmeasured signal is the community pair, which
    counts once — an absent community record is one gap, not two (#166).

    The margin cargo used to appear to have was the exploit signal, and it was
    not a measurement: no advisory source is asked in this mode, and the score
    came from ``has_known_exploits``'s default (#321).
    """
    score = _score_crate_offline(ANYHOW_CRATE_RESPONSE)

    assert score.measured_signal_count == 8
    assert score.unknown_signal_count == 8
    assert score.insufficient_data is False
    assert "exploit" in score.unknown_signals


def test_losing_one_registry_field_collapses_the_whole_ecosystem() -> None:
    """The #127 / #132 failure reproduced, at the depth it now takes to reach."""
    one_short = _one_field_short()
    two_short = _two_fields_short()

    assert one_short.measured_signal_count == 7
    assert one_short.insufficient_data is True
    assert one_short.risk_level is RiskLevel.UNKNOWN

    assert two_short.measured_signal_count == 6
    assert two_short.insufficient_data is True
    assert two_short.risk_level is RiskLevel.UNKNOWN


def test_the_superseded_floor_of_seven_admitted_a_collapsed_ecosystem() -> None:
    """Why the floors are set where they are: seven passes the state it exists to catch."""
    score = _one_field_short()

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


def test_every_floor_is_the_ceiling_minus_what_its_registry_withholds() -> None:
    """Each floor is a subtraction with a named subtrahend, not a tuned number.

    A floor is only worth what its attribution is worth. Nine numbers with a
    prose column beside them can drift apart silently: swap an ecosystem's
    missing signal for a different one and the count is unmoved, so every
    arithmetic check still passes while the recorded reason is false. Naming
    the withheld signals as data is what makes the reason falsifiable.

    Deliberately *not* derived from the scorer or the signal catalog. A floor
    computed from whatever the code measures cannot disagree with the code,
    which is the one thing a floor exists to be able to do.
    """
    for ecosystem, floor in MIN_MEASURED_SIGNALS.items():
        withheld = REGISTRY_UNANSWERED_SIGNALS[ecosystem]

        unknown = sorted(withheld - REGISTRY_ONLY_CEILING)
        assert not unknown, (
            f"{ecosystem} is recorded as not answering {unknown}, which a "
            "registry-only scan could not reach in any ecosystem; subtracting "
            "it from the ceiling would explain a gap that was never there"
        )
        assert floor == len(REGISTRY_ONLY_CEILING) - len(withheld), (
            f"{ecosystem} is floored at {floor}, but the ceiling is "
            f"{len(REGISTRY_ONLY_CEILING)} and it is recorded as not answering "
            f"{sorted(withheld)}. Fix whichever of the two is wrong; do not "
            "move the floor to match an implementation."
        )
        assert REGISTRY_MEASURED_SIGNALS[ecosystem] == (
            REGISTRY_ONLY_CEILING - withheld
        ), (
            f"{ecosystem} names {sorted(REGISTRY_MEASURED_SIGNALS[ecosystem])} "
            f"as measured, but the ceiling minus {sorted(withheld)} is "
            f"{sorted(REGISTRY_ONLY_CEILING - withheld)}"
        )


def test_the_two_signals_no_registry_only_scan_reaches_are_outside_the_ceiling() -> None:
    """``exploit`` and the repository-derived signals are absent by name.

    The ceiling is the subtrahend every floor is measured against, so what it
    leaves out is load-bearing. ``exploit`` is out because this mode asks no
    advisory source anything, and it scored a confident ``0.0`` here until
    #321. ``maintained`` stands for the seven that need a clone or a token.
    """
    assert "exploit" not in REGISTRY_ONLY_CEILING
    assert "maintained" not in REGISTRY_ONLY_CEILING
    assert len(REGISTRY_ONLY_CEILING) == 8
