"""Unit tests for the handover study's stage 3-6 harness.

The two claims these exist to hold down are the ones the write-up rests on and
that no other test in this repository covers:

1. :func:`handover_study.features.staleness_input` makes the **shipped**
   ``RiskScorer`` compute the as-of-T staleness bucket, at every threshold
   boundary. The scorer's staleness is wall-clock-relative, so this is an
   arithmetic claim about an input, and an off-by-one at a boundary would
   silently reclassify packages.
2. ``version`` is degenerate at T. The equality branch of the shipped
   difference scorer fires before anything else, so every package scores 0.0.

The permutation tests cover the third: the pre-registered negative control is a
within-cluster shuffle, and on a cohort of mostly singleton clusters it cannot
move most of the vector. :func:`invariant_share` measures exactly that, and it
is the number the stage-3 report is read against.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

import pytest
from abandonment_pilot.cohort import CohortMember
from abandonment_pilot.snapshot import PackageRecord
from handover_study.analysis import (
    cluster_block_permutation,
    global_shuffle,
    invariant_share,
    permuted_auc,
    within_cluster_shuffle,
)
from handover_study.features import (
    HANDOVER_SIGNALS,
    HandoverBaselines,
    baseline_value,
    build_handover_baselines,
    build_handover_metadata,
    literal_staleness_input,
    staleness_days_at_t,
    staleness_input,
)
from handover_study.stage2 import Comparison
from handover_study.stage3_6 import (
    BaselineComparison,
    compare_baselines,
    falsification_line_1,
    label_for,
)

from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    SIGNAL_MAINTAINER,
    SIGNAL_SOURCE_REPOSITORY,
    SIGNAL_STALENESS,
    SIGNAL_VERSION,
    MeasurementState,
)

T = datetime(2024, 8, 1, tzinfo=timezone.utc)


def _member(name: str = "pkg", staleness_days: int = 100) -> CohortMember:
    """Build a cohort member whose release in force at T is that old."""
    return CohortMember(
        name=name,
        index_at_t=1,
        last_release_before_t=T - timedelta(days=staleness_days),
        first_release=T - timedelta(days=2000),
        releases_before_t=2,
        abandoned=False,
        maintainers=("alice",),
    )


def _record(name: str = "pkg") -> PackageRecord:
    """Build a two-release snapshot record with everything the scorer reads."""
    return PackageRecord(
        name=name,
        releases=(
            ("1.0.0", T - timedelta(days=800)),
            ("1.2.3", T - timedelta(days=100)),
        ),
        maintainers=((0, ("alice",)),),
        repository=((0, "https://github.com/example/pkg"),),
        license=((0, "MIT"),),
        dep_count=((0, 4),),
        raw_sha256="0" * 64,
    )


# --- staleness: the reconstruction, at every threshold boundary -------------


@pytest.mark.parametrize(
    "days,expected",
    [
        (0, 0.0),
        (29, 0.0),
        (30, 0.25),
        (89, 0.25),
        (90, 0.5),
        (179, 0.5),
        (180, 0.75),
        (364, 0.75),
        (365, 1.0),
    ],
)
def test_staleness_input_reproduces_the_as_of_t_bucket(
    days: int, expected: float
) -> None:
    """The shipped scorer, given the reconstructed input, buckets T's staleness."""
    member = _member(staleness_days=days)
    reference_now = datetime.now(timezone.utc)
    assert staleness_days_at_t(member, T) == days

    scorer = RiskScorer()
    score = scorer._calculate_staleness_score(staleness_input(member, T, reference_now))
    assert score == expected


def test_the_literal_publish_time_is_the_exposure_window_and_is_degenerate() -> None:
    """Handing the scorer the raw publish time measures now, not T.

    Every cohort member's release in force at T is at least two years old by
    the harvest, so the literal reading collapses to the ceiling bucket for all
    of them. That is the whole reason the model is not given it.
    """
    scorer = RiskScorer()
    buckets = {
        scorer._calculate_staleness_score(
            literal_staleness_input(_member(staleness_days=days))
        )
        for days in (1, 100, 200, 365)
    }
    assert buckets == {1.0}


# --- version: degenerate at T, and no input fixes it ------------------------


@pytest.mark.parametrize("version", ["1.2.3", "0.0.1", "2024.4.1", "4.0.0-beta.2"])
def test_version_is_zero_when_installed_equals_latest(version: str) -> None:
    """At T the release in force is the latest release, so the signal cannot vary."""
    scorer = RiskScorer()
    assert scorer._calculate_version_difference_score(version, version) == 0.0


def test_version_equality_short_circuits_the_calendar_path() -> None:
    """Equal calendar versions never reach the drift scorer, whatever the dates."""
    scorer = RiskScorer()
    early = T - timedelta(days=3000)
    assert (
        scorer._calculate_version_difference_score("2019.9.11", "2019.9.11", early, T)
        == 0.0
    )


# --- metadata: ablation is absence ------------------------------------------


def test_full_model_supplies_all_four_admissible_signals() -> None:
    """Every §4 signal comes back MEASURED, and none of the excluded ones do."""
    reference_now = datetime.now(timezone.utc)
    metadata = build_handover_metadata(_record(), _member(), T, reference_now)
    result = RiskScorer().score_dependency(metadata)
    measured = {
        name
        for name, measurement in result.measurements.items()
        if measurement.state is MeasurementState.MEASURED
    }
    assert HANDOVER_SIGNALS <= measured
    assert "license" not in measured
    assert "deprecation" not in measured
    assert "exploit" not in measured


@pytest.mark.parametrize(
    "ablated",
    [SIGNAL_STALENESS, SIGNAL_VERSION, SIGNAL_MAINTAINER, SIGNAL_SOURCE_REPOSITORY],
)
def test_ablation_leaves_the_signal_unmeasured(ablated: str) -> None:
    """Dropping a signal from ``enabled`` leaves its input unset, not zeroed."""
    reference_now = datetime.now(timezone.utc)
    metadata = build_handover_metadata(
        _record(), _member(), T, reference_now, HANDOVER_SIGNALS - {ablated}
    )
    result = RiskScorer().score_dependency(metadata)
    states = {
        name: measurement.state for name, measurement in result.measurements.items()
    }
    assert states.get(ablated) is not MeasurementState.MEASURED
    for other in HANDOVER_SIGNALS - {ablated}:
        assert states[other] is MeasurementState.MEASURED


# --- baselines ---------------------------------------------------------------


def test_exposure_window_is_measured_to_the_harvest_not_to_t() -> None:
    """Baseline 5 is days from the frozen release to the stage-1 harvest."""
    member = _member(staleness_days=100)
    harvested_at = T + timedelta(days=740)
    baselines = build_handover_baselines(
        member, T, _record(), {}, {}, harvested_at
    )
    assert baselines.exposure_window_days == 840
    assert baseline_value(baselines, "exposure_window_days") == 840.0


def test_a_missing_baseline_is_none_and_never_zero() -> None:
    """A package GitHub never answered for has no star count, not zero stars."""
    baselines = build_handover_baselines(
        _member(), T, _record(), {}, {}, T + timedelta(days=740)
    )
    assert baseline_value(baselines, "stars_today") is None
    assert baseline_value(baselines, "downloads_at_t") is None


def test_baseline_value_rejects_an_unknown_name() -> None:
    """A typo in a baseline name is a bug, not a silent None."""
    baselines = build_handover_baselines(
        _member(), T, _record(), {}, {}, T + timedelta(days=740)
    )
    with pytest.raises(ValueError):
        baseline_value(baselines, "downloads")


# --- permutations -------------------------------------------------------------


def _labels_and_clusters() -> Tuple[List[bool], List[int]]:
    """A cohort with two singletons and two multi-member clusters."""
    labels = [True, False, True, False, True, False, False]
    clusters = [0, 0, 0, 1, 1, 2, 3]
    return labels, clusters


def test_within_cluster_shuffle_permutes_only_inside_a_cluster() -> None:
    """Each cluster keeps its own label multiset; singletons cannot move."""
    labels, clusters = _labels_and_clusters()
    rng = random.Random(7)
    for _ in range(50):
        drawn = within_cluster_shuffle(labels, clusters, rng)
        for cluster in set(clusters):
            positions = [i for i, c in enumerate(clusters) if c == cluster]
            assert sorted(labels[i] for i in positions) == sorted(
                drawn[i] for i in positions
            )
        assert drawn[5] == labels[5]
        assert drawn[6] == labels[6]


def test_invariant_share_counts_rows_a_within_cluster_shuffle_cannot_move() -> None:
    """Singletons and label-homogeneous clusters are frozen; mixed ones are not."""
    labels, clusters = _labels_and_clusters()
    # cluster 0 is mixed (3 rows), cluster 1 is mixed (2 rows), 2 and 3 are
    # singletons and therefore frozen.
    assert invariant_share(labels, clusters) == pytest.approx(2 / 7)
    assert invariant_share([True, False], [0, 1]) == 1.0
    assert invariant_share([], []) == 0.0


def test_global_shuffle_preserves_the_label_multiset() -> None:
    """The pilot's control destroys every association and nothing else."""
    labels, clusters = _labels_and_clusters()
    rng = random.Random(11)
    drawn = global_shuffle(labels, clusters, rng)
    assert sorted(drawn) == sorted(labels)


def test_cluster_block_permutation_swaps_whole_same_sized_clusters() -> None:
    """Blocks are exchanged intact, so the label multiset is preserved."""
    labels, clusters = _labels_and_clusters()
    rng = random.Random(3)
    for _ in range(50):
        drawn = cluster_block_permutation(labels, clusters, rng)
        assert sorted(drawn) == sorted(labels)
        # The size-3 cluster has no same-sized partner, so it never moves.
        assert [drawn[i] for i in (0, 1, 2)] == [labels[i] for i in (0, 1, 2)]


def test_permuted_auc_is_reproducible_and_reports_preservation() -> None:
    """The same seed gives the same numbers; preservation is in ``[0, 1]``."""
    labels, clusters = _labels_and_clusters()
    scores = [0.9, 0.1, 0.8, 0.2, 0.7, 0.3, 0.4]
    first = permuted_auc(scores, labels, clusters, global_shuffle, 25, 5)
    second = permuted_auc(scores, labels, clusters, global_shuffle, 25, 5)
    assert first == second
    assert 0.0 <= first[3] <= 1.0


# --- outcome definitions ------------------------------------------------------


def test_label_for_covers_the_five_definitions() -> None:
    """Each sub-definition reads the comparison it is defined on."""
    grew = Comparison(name="a", frozen=("alice",), current=("alice", "bob"))
    swapped = Comparison(name="b", frozen=("alice",), current=("bob",))
    same = Comparison(name="c", frozen=("alice",), current=("alice",))

    assert label_for(grew, "any_change") and label_for(grew, "gained")
    assert not label_for(grew, "lost")
    assert not label_for(grew, "both_gained_and_lost")
    assert not label_for(grew, "complete_turnover")

    assert label_for(swapped, "complete_turnover")
    assert label_for(swapped, "both_gained_and_lost")

    assert not any(label_for(same, name) for name in ("any_change", "gained", "lost"))


def test_label_for_rejects_an_unknown_definition() -> None:
    """An unregistered outcome name is a bug, not a False."""
    with pytest.raises(ValueError):
        label_for(Comparison(name="a", frozen=(), current=()), "renamed")


# --- falsification line 1 -----------------------------------------------------


def _comparison(
    name: str, auc: float, delta: float, low: float, high: float
) -> BaselineComparison:
    """A minimal comparison row for the ranker."""
    return BaselineComparison(
        name=name,
        support=100,
        support_clusters=80,
        positives_on_support=20,
        positive_clusters_on_support=18,
        auc_as_recorded=auc,
        orientation="more is riskier",
        baseline_auc=auc,
        model_auc_on_support=auc + delta,
        delta=delta,
        ci95_clustered=(low, high),
        ci95_unclustered=(low, high),
        p_value_clustered=0.01,
    )


def test_line_1_is_read_against_the_strongest_baseline() -> None:
    """The margin is owed to the best baseline, not to a convenient one."""
    verdict = falsification_line_1(
        [
            _comparison("weak", 0.52, 0.20, 0.15, 0.25),
            _comparison("strong", 0.70, 0.02, 0.01, 0.03),
        ]
    )
    assert verdict["best_baseline"] == "strong"
    assert verdict["cleared"] is False


def test_line_1_needs_both_the_margin_and_an_interval_clear_of_zero() -> None:
    """A big point estimate whose interval straddles zero does not clear it."""
    straddles = falsification_line_1([_comparison("only", 0.55, 0.12, -0.02, 0.26)])
    assert straddles["interval_excludes_zero"] is False
    assert straddles["cleared"] is False

    clears = falsification_line_1([_comparison("only", 0.55, 0.12, 0.04, 0.20)])
    assert clears["cleared"] is True


def test_line_1_reports_when_no_baseline_is_defined() -> None:
    """An empty comparison table is reported, not silently treated as a pass."""
    verdict = falsification_line_1([])
    assert "verdict" in verdict
    assert "cleared" not in verdict


def test_compare_baselines_runs_each_on_its_own_support() -> None:
    """A baseline nobody measured for a row drops that row, and says so."""
    members = [_member(f"p{index}", 100 + index) for index in range(6)]
    record = _record()
    harvested_at = T + timedelta(days=740)
    baselines: List[HandoverBaselines] = [
        build_handover_baselines(
            member,
            T,
            record,
            {"p0": 10, "p1": 20, "p2": 30},
            {},
            harvested_at,
        )
        for member in members
    ]
    labels = [True, False, True, False, True, False]
    clusters = [0, 1, 2, 3, 4, 5]
    rows = {
        item.name: item
        for item in compare_baselines(
            [0.9, 0.1, 0.8, 0.2, 0.7, 0.3], baselines, labels, clusters, 20, 1
        )
    }
    assert rows["downloads_at_t"].support == 3
    assert rows["exposure_window_days"].support == 6
    assert rows["stars_today"].support == 0
    assert rows["stars_today"].baseline_auc is None
