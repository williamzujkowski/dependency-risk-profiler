"""The arithmetic behind the per-ecosystem floors, pinned on its own (#136).

The floors in ``signal_floors`` sit at what each ecosystem measures. The edge
arithmetic that used to *be* the floor is still worth documenting, so it lives
here, where it can be true without being load-bearing.

The edge: the scorer reports UNKNOWN when ``unmeasured > measured``, so with
fifteen weighed signals a dependency reaches a verdict at eight measured and
loses it at seven. Seven is also the most a registry document can supply, so
in this mode the edge is out of reach and every ecosystem reports UNKNOWN —
see :data:`~signal_floors.SCORES_FROM_REGISTRY_ALONE`, which records it.

That is not a floor being set too high. A floor of seven admits a fully
collapsed ecosystem — the all-UNKNOWN state of #127 / #132 — while still
reporting green, which is what :data:`SUPERSEDED_FLOOR` is kept as a literal to
show; what makes the floors still worth having is that they name the signals
behind the count, so an ecosystem that quietly stops reading one fails here
rather than at the next release.

These tests reuse the recorded crates.io payload from ``test_crates_adapter``
rather than a synthetic score: the claim is about a real adapter reaching a
real threshold, and a hand-built score would only restate the inequality it is
supposed to demonstrate.
"""

import copy
from typing import Dict

from dependency_risk_profiler.signals import SCORED_SIGNALS
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

# What a verdict costs, in measured signals, out of the THIRTEEN the composite
# weighs since #339. ``unmeasured > measured`` is the bar, so seven against six
# clears it and six against seven does not. It was eight of fifteen before two
# signals that always needed a clone -- and could never be measured from a
# registry document -- came out of the weighted set.
VERDICT_THRESHOLD = 7


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
    """Score anyhow one weighed registry field short of the real payload.

    The owner list, because it is a field the composite actually weighs. The
    licence is read from the same payload and weighs nothing, so removing it
    is not a step toward the edge at all — which is what
    ``test_dropping_the_licence_moves_neither_the_count_nor_the_score``
    pins from the other side.
    """
    return _score_crate_offline(
        ANYHOW_CRATE_RESPONSE, _owners_response_without_owners()
    )


def test_a_healthy_crate_now_clears_the_verdict_bar() -> None:
    """Cargo measures seven of thirteen and is unmeasured on six.

    ``insufficient_data`` is ``unmeasured > measured``, so seven against six
    clears it. **This inverted in #339** and the inversion is deliberate: two
    signals that always required a clone left the weighted set, so a
    registry-only run no longer counts them as evidence still to come.

    Nothing new is measured and the score does not move -- it is renormalized
    over measured weights either way. What changed is that the crate stops
    being reported UNKNOWN for want of two readings that could not have been
    taken in this mode, and could not have informed the verdict if they had.

    The ``license`` history still stands (#340): six ecosystems once cleared
    this bar at eight against eight, carried by the one signal measured to make
    the forecast worse. They no longer need carrying.

    ``exploit`` is still unmeasured here, and it is still the single largest
    weight in the scale, so a verdict from this mode rests on a scan that asked
    nobody about vulnerabilities.
    """
    score = _score_crate_offline(ANYHOW_CRATE_RESPONSE)

    assert score.measured_signal_count == 7
    assert score.unknown_signal_count == 6
    assert score.insufficient_data is False
    assert score.risk_level is not RiskLevel.UNKNOWN
    assert "exploit" in score.unknown_signals


def test_dropping_the_licence_moves_neither_the_count_nor_the_score() -> None:
    """REGRESSION #340: the licence is reported, and weighs exactly nothing.

    The same crate scored twice, differing only in whether crates.io declared
    a licence. Both numbers have to be identical: the weighted mean because the
    licence carries no weight, and the measured count because a signal outside
    the composite is not evidence the composite rests on.

    Asserted against a real recorded payload rather than a constructed score,
    so a weight reintroduced anywhere in the scorer fails here.
    """
    with_license = _score_crate_offline(ANYHOW_CRATE_RESPONSE)
    without_license = _score_crate_offline(_crate_response_without_license())

    assert with_license.license_score is not None
    assert without_license.license_score is None

    assert without_license.total_score == with_license.total_score
    assert without_license.measured_signal_count == (
        with_license.measured_signal_count
    )
    assert without_license.total_signal_count == with_license.total_signal_count
    assert without_license.risk_level is with_license.risk_level


def test_losing_one_weighed_registry_field_costs_a_signal_and_moves_the_score() -> None:
    """The counterweight to the test above: a weighed field is felt.

    The owner list is read from the same registry, in the same mode, and its
    absence moves both the count and the mean. Without this the licence test
    would be satisfied by a scorer that had stopped reading anything.
    """
    full = _score_crate_offline(ANYHOW_CRATE_RESPONSE)
    one_short = _one_field_short()

    assert one_short.measured_signal_count == full.measured_signal_count - 1
    assert one_short.total_score != full.total_score
    assert one_short.risk_level is RiskLevel.UNKNOWN


def test_the_superseded_floor_of_seven_admitted_a_collapsed_ecosystem() -> None:
    """Why the floors are set where they are: seven passes the state it exists to catch."""
    score = _one_field_short()

    assert score.risk_level is RiskLevel.UNKNOWN
    assert score.measured_signal_count < MIN_MEASURED_SIGNALS["cargo"]
    assert SUPERSEDED_FLOOR >= MIN_MEASURED_SIGNALS["cargo"], (
        "a fixed floor of seven is at or above every ecosystem's measured "
        "coverage, so it forbids nothing any adapter was going to do"
    )


def test_the_verdict_table_is_derived_from_the_ceiling_not_asserted() -> None:
    """Which ecosystems reach a verdict alone, computed rather than looked up.

    Was named ``test_no_ecosystem_reaches_a_verdict_from_a_registry_document_alone``
    and asserted the ceiling sat strictly below the bar. #339 retired two
    signals that a registry-only run could never measure, so the bar fell from
    eight of fifteen to seven of thirteen and the ceiling now MEETS it: the six
    ecosystems floored at seven carry a verdict, the three floored at five do
    not.

    The derivation is what matters and is unchanged -- a floor raised past the
    edge without the table being updated still fails here.
    """
    assert len(REGISTRY_ONLY_CEILING) >= VERDICT_THRESHOLD, (
        "the registry-only ceiling no longer reaches a verdict; "
        "SCORES_FROM_REGISTRY_ALONE should be all False again"
    )

    for ecosystem, floor in MIN_MEASURED_SIGNALS.items():
        assert floor <= len(REGISTRY_ONLY_CEILING), f"{ecosystem} is above the ceiling"
        assert SCORES_FROM_REGISTRY_ALONE[ecosystem] is (floor >= VERDICT_THRESHOLD), (
            f"{ecosystem} is floored at {floor} and recorded as "
            f"{'reaching' if SCORES_FROM_REGISTRY_ALONE[ecosystem] else 'short of'}"
            f" a verdict; a verdict costs {VERDICT_THRESHOLD}"
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


def test_the_signals_no_registry_only_scan_reaches_are_outside_the_ceiling() -> None:
    """``exploit`` and the repository-derived signals are absent by name.

    The ceiling is the subtrahend every floor is measured against, so what it
    leaves out is load-bearing. ``exploit`` is out because this mode asks no
    advisory source anything, and it scored a confident ``0.0`` here until
    #321. ``maintained`` stands for the seven that need a clone or a token.
    ``license`` is out for a third reason: every registry but Go's answers it,
    and the composite weighs nobody's answer, so it is coverage of an axis the
    floor is not measuring (#340).
    """
    assert "exploit" not in REGISTRY_ONLY_CEILING
    assert "maintained" not in REGISTRY_ONLY_CEILING
    assert "license" not in REGISTRY_ONLY_CEILING
    assert len(REGISTRY_ONLY_CEILING) == 7


def test_the_verdict_bar_is_pinned_so_a_signal_change_surfaces_loudly() -> None:
    """Retiring or adding a signal moves the abstention bar. Make it say so.

    The bar is ``unmeasured > measured`` over the SCORED set, so its height is
    a function of how many signals are scored. #340 moved it once when
    ``license`` came out and nobody wrote it down; #339 moved it again and the
    effect -- six ecosystems going from UNKNOWN to a verdict on identical
    evidence -- was found while fixing unrelated tests rather than announced by
    one.

    This is the announcement. Change the scored set and this fails, which is
    the prompt to decide whether the abstention shift is intended and to say so
    in the changelog.
    """
    scored = len(SCORED_SIGNALS)
    assert scored == 13, (
        f"the scored set is now {scored} signals, not 13. The verdict bar "
        "moves with it, so packages will change between UNKNOWN and a verdict "
        "on unchanged evidence -- confirm that is intended and record it."
    )
    # `unmeasured > measured` with an odd count: a verdict needs the majority.
    assert VERDICT_THRESHOLD == scored // 2 + 1

    reaching = {e for e, v in SCORES_FROM_REGISTRY_ALONE.items() if v}
    assert reaching == {
        "cargo",
        "composer",
        "nodejs",
        "nuget",
        "python",
        "rubygems",
    }, (
        "which ecosystems can reach a verdict from a registry document alone "
        "has changed; this is user-visible and belongs in the changelog"
    )
