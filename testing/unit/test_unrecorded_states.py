"""Two questions nobody asked, and the answers the scorer used to invent.

Both defects here are one shape in two fields, which is why they are one
module. A signal's input carried a type whose most reassuring inhabitant was
also its default, so a caller that established nothing published a confident
clean answer:

* ``advisory_lookup_state`` was ``Optional`` and an unset state read as
  *measured*, so ``exploit`` scored ``0.0`` from ``has_known_exploits`` for
  every dependency nobody asked an advisory source about — at the tool's
  largest single weight, 0.5 of 3.5 (#321).
* ``is_deprecated`` was a ``bool`` defaulting to ``False``, so ``deprecation``
  was *always* measured and an adapter had no way to say nobody looked — which
  is the only honest answer for Maven Central, which publishes no retirement
  marker at all (#320).

The scale is not hypothetical. Driving the production scorer over a pinned
2,906-package npm cohort at a past date, an unrecorded advisory state put a
fabricated ``0.0`` into the weighted mean for every package and left the HIGH
bucket entirely empty; recording the honest ``NOT_ATTEMPTED`` moved **174
packages** out of LOW and MEDIUM into HIGH. A reader of the first table would
have concluded the thresholds were unreachable.

That corpus is a research artifact rather than a fixture, so what is asserted
here is the mechanism it measured: an unasked lookup scores a package strictly
higher than a lookup that ran and found nothing, and it does so by leaving the
signal out of the denominator rather than by scoring it badly.

Assertions are on **values**, not counts (AGENTS.md rule 6). A count cannot
tell "always measured correctly" from "always measured wrong", and which of
``None`` and ``0.0`` comes back is the entire question.
"""

from typing import List, Tuple, cast

import pytest
from adapter_conformance import CASES, score_case

from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    LicenseCategory,
    LicenseInfo,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    SIGNAL_DEPRECATION,
    SIGNAL_EXPLOIT,
    AdvisoryLookupState,
    MeasurementState,
    SourceRepositoryState,
    UnmeasuredReason,
)

#: Ecosystems whose registry publishes no retirement marker, so their adapters
#: record nothing and the signal must come back unmeasured. Maven Central has
#: no POM element and no ``maven-metadata`` field for it; the nearest thing is
#: ``<distributionManagement><relocation>``, which says an artifact moved
#: rather than that it was retired (#179). Gradle inherits the fact by
#: publishing Maven coordinates and resolving against Maven Central.
NO_RETIREMENT_MARKER: Tuple[str, ...] = ("maven", "gradle")


def _cohort() -> List[DependencyMetadata]:
    """Return dependencies spread across the verdict scale.

    Spread on purpose: a cohort clustered at one end cannot show a bucket
    boundary being crossed, and crossing one is what the pilot observed. Each
    member measures enough to reach a verdict rather than abstaining, because
    a cohort of UNKNOWNs cannot show verdict movement either.
    """
    cohort: List[DependencyMetadata] = []
    for index, (maintainers, latest) in enumerate(
        ((7, "1.0.0"), (4, "1.1.0"), (2, "2.0.0"), (1, "9.9.9"))
    ):
        dependency = DependencyMetadata(
            name=f"package-{index}",
            installed_version="1.0.0",
            latest_version=latest,
            maintainer_count=maintainers,
            license_info=LicenseInfo(
                license_id="MIT",
                category=LicenseCategory.PERMISSIVE,
                is_approved=True,
                risk_level=RiskLevel.LOW,
            ),
        )
        dependency.record_deprecation(deprecated=False)
        dependency.transitive_source = "manifest"
        # Declares no source, so the repository-derived signals are silenced by
        # one measured fact rather than seven independent gaps (#146) and the
        # cohort reaches verdicts instead of abstaining.
        dependency.source_repository_state = SourceRepositoryState.UNDECLARED
        cohort.append(dependency)
    return cohort


def _scored(dependency: DependencyMetadata) -> DependencyRiskScore:
    """Score one dependency at the shipped weights.

    Args:
        dependency: The metadata to score.

    Returns:
        The scored dependency.
    """
    return RiskScorer().score_dependency(dependency)


# --- #321: an advisory lookup nobody ran -----------------------------------


def test_metadata_built_by_hand_reports_exploit_unmeasured() -> None:
    """REGRESSION #321: an embedder who asks nothing gets no answer.

    The acceptance criterion, stated as it was filed: a ``DependencyMetadata``
    built by hand and handed to ``score_dependency`` must report ``exploit``
    UNMEASURED. Any embedder that builds the model and scores it without
    running the aggregator is on this path, and so is every offline run of the
    tool itself.
    """
    dependency = DependencyMetadata(name="flask", installed_version="1.0.0")

    score = _scored(dependency)

    assert dependency.advisory_lookup_state is AdvisoryLookupState.NOT_ATTEMPTED
    assert dependency.has_known_exploits is False
    assert score.exploit_score is None

    measurement = score.measurements[SIGNAL_EXPLOIT]
    assert measurement.state is MeasurementState.UNMEASURED
    assert measurement.reason is UnmeasuredReason.LOOKUP_NOT_ATTEMPTED
    assert SIGNAL_EXPLOIT in score.unknown_signals


def test_the_two_ways_of_saying_nobody_looked_score_identically() -> None:
    """There is one spelling of "not attempted", and the type admits no other.

    This is what makes the fix structural rather than a convention. A caller
    that records the state explicitly and a caller that records nothing
    produce the same object and the same score, so the pilot's fabricated
    ``0.0`` is not merely discouraged at the call sites — it is unreachable
    from any of them.
    """
    recorded = DependencyMetadata(name="flask", installed_version="1.0.0")
    recorded.record_advisory_lookup(
        AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=()
    )
    silent = DependencyMetadata(name="flask", installed_version="1.0.0")

    assert recorded.advisory_lookup_state is silent.advisory_lookup_state
    assert _scored(recorded).total_score == _scored(silent).total_score
    assert _scored(silent).measurements[SIGNAL_EXPLOIT] == (
        _scored(recorded).measurements[SIGNAL_EXPLOIT]
    )


def test_an_unasked_lookup_scores_higher_than_one_that_answered_clean() -> None:
    """REGRESSION #321, the shape the abandonment pilot measured at scale.

    A lookup that ran and found nothing scores ``exploit`` at ``0.0`` and
    keeps its weight in the denominator. A lookup nobody ran scores nothing
    and takes the weight out. The second is strictly the higher score for
    every package that carries any risk at all, because the reassuring zero it
    used to average in was never a measurement.

    On the pilot cohort that difference emptied the HIGH bucket; here it is
    asserted per package, plus the bucket crossing that made it visible.
    """
    higher = 0
    crossings = 0
    for dependency in _cohort():
        unasked = _scored(dependency)

        dependency.record_advisory_lookup(
            AdvisoryLookupState.COMPLETE, sources_unavailable=()
        )
        answered_clean = _scored(dependency)

        assert answered_clean.exploit_score == 0.0
        assert unasked.exploit_score is None
        assert unasked.total_score >= answered_clean.total_score
        assert unasked.risk_level is not RiskLevel.UNKNOWN
        if unasked.total_score > answered_clean.total_score:
            higher += 1
        if unasked.risk_level is not answered_clean.risk_level:
            crossings += 1

    assert higher == 4, "the fabricated zero deflated every package that carries risk"
    assert crossings, (
        "no package changed verdict, so this cohort cannot show the bucket "
        "movement the pilot found; widen it rather than dropping the assertion"
    )


def test_a_failed_lookup_is_a_different_reason_from_one_nobody_ran() -> None:
    """Provenance survives the collapse to one score (#219 beside #321).

    Both states leave ``exploit`` unmeasured, and at the scoring boundary that
    is the same fact: a consumer reading a value cannot tell either from
    "checked and clean". They are not the same fact to an operator, so the
    reason is what keeps them apart, and it comes from the existing
    vocabulary rather than a parallel one.
    """
    failed = DependencyMetadata(name="flask", installed_version="1.0.0")
    failed.record_advisory_lookup(
        AdvisoryLookupState.FAILED, sources_unavailable=("OSV",)
    )
    unasked = DependencyMetadata(name="flask", installed_version="1.0.0")

    failed_score = _scored(failed)
    unasked_score = _scored(unasked)

    assert failed_score.exploit_score is None
    assert unasked_score.exploit_score is None
    assert (
        failed_score.measurements[SIGNAL_EXPLOIT].reason
        is UnmeasuredReason.SOURCE_LOOKUP_FAILED
    )
    assert (
        unasked_score.measurements[SIGNAL_EXPLOIT].reason
        is UnmeasuredReason.LOOKUP_NOT_ATTEMPTED
    )
    assert any("did not answer" in factor for factor in failed_score.factors)


# --- #320: a registry that publishes no retirement marker -------------------


def test_metadata_built_by_hand_reports_deprecation_unmeasured() -> None:
    """REGRESSION #320: a ``bool`` could only say "affirmatively not retired"."""
    dependency = DependencyMetadata(name="flask", installed_version="1.0.0")

    score = _scored(dependency)

    assert dependency.is_deprecated is None
    assert score.deprecation_score is None

    measurement = score.measurements[SIGNAL_DEPRECATION]
    assert measurement.state is MeasurementState.UNMEASURED
    assert measurement.reason is UnmeasuredReason.NO_DATA_FROM_SOURCE
    assert SIGNAL_DEPRECATION in score.unknown_signals


def test_recording_false_is_a_measurement_and_saying_nothing_is_not() -> None:
    """The distinction the field could not express, asserted from both sides."""
    live = DependencyMetadata(name="flask", installed_version="1.0.0")
    live.record_deprecation(deprecated=False)
    retired = DependencyMetadata(name="flask", installed_version="1.0.0")
    retired.record_deprecation(deprecated=True)
    unknown = DependencyMetadata(name="flask", installed_version="1.0.0")

    assert _scored(live).deprecation_score == 0.0
    assert _scored(retired).deprecation_score == 1.0
    assert _scored(unknown).deprecation_score is None

    assert SIGNAL_DEPRECATION not in _scored(live).unknown_signals
    assert SIGNAL_DEPRECATION not in _scored(retired).unknown_signals
    assert SIGNAL_DEPRECATION in _scored(unknown).unknown_signals


def test_an_unmeasured_deprecation_leaves_the_denominator() -> None:
    """#74's rule for the signal that could not reach it.

    A constant cannot change a ranking, which is why this never showed up as
    an AUC movement. It changes absolute scores: a confident ``0.0`` in the
    denominator pulls every score toward zero and moves which packages land in
    which verdict bucket.
    """
    measured = DependencyMetadata(
        name="drifted",
        installed_version="1.0.0",
        latest_version="9.9.9",
        maintainer_count=1,
    )
    measured.record_advisory_lookup(
        AdvisoryLookupState.COMPLETE, sources_unavailable=()
    )
    measured.record_deprecation(deprecated=False)

    unmeasured = DependencyMetadata(
        name="drifted",
        installed_version="1.0.0",
        latest_version="9.9.9",
        maintainer_count=1,
    )
    unmeasured.record_advisory_lookup(
        AdvisoryLookupState.COMPLETE, sources_unavailable=()
    )

    assert _scored(unmeasured).total_score > _scored(measured).total_score


def test_record_deprecation_refuses_a_value_nobody_classified() -> None:
    """The runtime half of rule 4, for the same reason the recorders next door have it.

    Types already forbid this and mypy does not run in production. A registry
    field handed straight in — a non-empty string, a dict, ``None`` — is
    exactly the shape this signal exists to stop reading as an answer, and
    coercing it would put the judgment back in the adapter.
    """
    dependency = DependencyMetadata(name="flask", installed_version="1.0.0")

    rejected: Tuple[object, ...] = ("true", 1, None, {})
    for value in rejected:
        with pytest.raises(TypeError):
            dependency.record_deprecation(deprecated=cast(bool, value))

    assert dependency.is_deprecated is None


@pytest.mark.parametrize("ecosystem", NO_RETIREMENT_MARKER)
def test_an_adapter_that_reads_no_retirement_marker_records_nothing(
    ecosystem: str,
) -> None:
    """#320's acceptance criterion, driven through the production adapter.

    The point of running the real analyzer over a captured payload rather than
    building metadata by hand: what is asserted is that **production code**
    leaves the field alone, not that this test did. A harness that recorded
    the state on the adapter's behalf would prove only that the harness works,
    which is the failure this repository has hit before.
    """
    cases = [case for case in CASES if case.ecosystem == ecosystem]
    assert cases, f"no captured conformance case for {ecosystem}"

    for case in cases:
        score = score_case(case)
        assert score.dependency.is_deprecated is None, case.slug
        assert score.deprecation_score is None, case.slug
        assert (
            score.measurements[SIGNAL_DEPRECATION].state is MeasurementState.UNMEASURED
        ), case.slug
        assert SIGNAL_DEPRECATION in score.unknown_signals, case.slug


def test_a_registry_that_does_publish_one_records_both_answers() -> None:
    """The other side of the same rule: silence must not become the only answer.

    An ecosystem whose registry states retirement has to record ``False`` as
    well as ``True``, or the fix trades a signal that was always measured
    wrong for one that is never measured at all. Both branches are pinned by
    value against captured payloads, so this is the count that says every
    ecosystem which can answer does.
    """
    answered = {
        case.ecosystem: case.expected_deprecated
        for case in CASES
        if case.expected_deprecated is not None
    }
    both = {
        ecosystem
        for ecosystem in {case.ecosystem for case in CASES}
        if {case.expected_deprecated for case in CASES if case.ecosystem == ecosystem}
        == {True, False}
    }

    assert set(answered) == {
        "cargo",
        "composer",
        "golang",
        "nodejs",
        "nuget",
        "python",
        "rubygems",
    }
    assert both, "no ecosystem pins both branches; the non-default one is the #142 shape"


def test_a_registry_only_scan_measures_neither_signal() -> None:
    """The two fixes meet here, and this is what the floors were re-baselined for.

    Every captured conformance case runs with cloning off, no token, and no
    advisory lookup. ``exploit`` is therefore unmeasured in all of them, and
    ``deprecation`` in the two ecosystems whose registry does not state it.
    Both leave numerator and denominator per #74, and the per-ecosystem floors
    in ``signal_floors`` are the subtraction written down.
    """
    for case in CASES:
        score = score_case(case)
        exploit = score.measurements[SIGNAL_EXPLOIT]

        assert exploit.state is MeasurementState.UNMEASURED, case.slug
        assert exploit.reason is UnmeasuredReason.LOOKUP_NOT_ATTEMPTED, case.slug
        assert score.risk_level is not RiskLevel.CRITICAL or score.total_score > 0.0

        if case.ecosystem in NO_RETIREMENT_MARKER:
            assert score.deprecation_score is None, case.slug
        else:
            assert score.deprecation_score is not None, case.slug


def test_security_metrics_cannot_reintroduce_the_score_without_a_lookup() -> None:
    """A populated metrics block is not a lookup somebody ran.

    ``_calculate_exploit_score`` reads ``counted_vulnerability_count`` before
    anything else, and the aggregator is what writes it. Reaching that read
    without an advisory state would let a half-populated model re-enter the
    scored path, so the state is checked first and there is no way past it.
    """
    dependency = DependencyMetadata(
        name="flask",
        installed_version="1.0.0",
        security_metrics=SecurityMetrics(
            vulnerability_count=1,
            counted_vulnerability_count=1,
            max_cvss_score=9.8,
            max_vulnerability_severity="CRITICAL",
        ),
    )

    assert _scored(dependency).exploit_score is None

    dependency.record_advisory_lookup(
        AdvisoryLookupState.COMPLETE, sources_unavailable=()
    )
    assert _scored(dependency).exploit_score == 1.0
