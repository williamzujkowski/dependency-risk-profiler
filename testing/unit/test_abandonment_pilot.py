"""Tests for the abandonment pilot harness (``research/abandonment_pilot``).

Three of these are gates rather than tests, in the sense of AGENTS.md rule 6 —
they exist to fail when the harness is broken in a way that would otherwise
produce a publishable-looking number:

* :func:`test_a_leaked_label_drives_the_auc_to_one` proves the AUC computation
  can see a signal when one is there. Without it, a negative control passing at
  0.5 proves nothing: a harness that always returns 0.5 passes it too.
* :func:`test_shuffling_the_labels_collapses_the_auc` is the negative control
  itself, run on the pinned snapshot in CI.
* :func:`test_no_post_t_release_can_change_a_feature` is the leakage gate. Every
  feature is read at one release index; the test appends releases after T that
  change every field and asserts none of them moves.
"""

import ast
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Sequence, Tuple

import pytest

from abandonment_pilot import experiment, features, stats
from abandonment_pilot.cohort import (
    CohortMember,
    LifeTableRow,
    build_cohort,
    choose_abandonment_years,
    maintainer_clusters,
    resumption_life_table,
)
from abandonment_pilot.experiment import ScoredCohort
from abandonment_pilot.snapshot import PackageRecord, Snapshot, load_snapshot
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    SIGNAL_DEPRECATION,
    SIGNAL_EXPLOIT,
    SIGNAL_MAINTAINER,
    SIGNAL_STALENESS,
    SIGNAL_VERSION,
    AdvisoryLookupState,
    MeasurementState,
    UnmeasuredReason,
)

SNAPSHOT_DIR = Path(__file__).resolve().parents[2] / "research" / "data" / "npm-2026-08-06"

T = datetime(2024, 8, 1, tzinfo=timezone.utc)


def _record(
    name: str = "pkg",
    releases: Optional[Sequence[Tuple[str, datetime]]] = None,
    maintainers: Sequence[Tuple[int, Tuple[str, ...]]] = ((0, ("alice",)),),
    repository: Sequence[Tuple[int, Optional[str]]] = (
        (0, "git+https://github.com/alice/pkg.git"),
    ),
    license_steps: Sequence[Tuple[int, Optional[str]]] = ((0, "MIT"),),
    dep_count: Sequence[Tuple[int, int]] = ((0, 3),),
) -> PackageRecord:
    """Build a small authored record.

    Authored rather than captured on purpose: these are adversarial fixtures in
    the sense of AGENTS.md rule 5 — a leaking future, a degenerate label — and
    no cooperating registry will serve them.
    """
    if releases is None:
        releases = (
            ("1.0.0", T - timedelta(days=900)),
            ("1.1.0", T - timedelta(days=500)),
            ("1.2.0", T - timedelta(days=100)),
        )
    return PackageRecord(
        name=name,
        releases=tuple(releases),
        maintainers=tuple(maintainers),
        repository=tuple(repository),
        license=tuple(license_steps),
        dep_count=tuple(dep_count),
        raw_sha256="0" * 64,
    )


def _member(record: PackageRecord, abandoned: bool = True) -> CohortMember:
    index = record.release_index_at(T)
    if index is None:
        raise AssertionError("the authored record has no release before T")
    return CohortMember(
        name=record.name,
        index_at_t=index,
        last_release_before_t=record.releases[index][1],
        first_release=record.releases[0][1],
        releases_before_t=index + 1,
        abandoned=abandoned,
        maintainers=("alice",),
    )


# --- statistics ------------------------------------------------------------


def test_auc_is_one_for_a_perfect_ranking_and_zero_for_its_reverse() -> None:
    scores = [0.9, 0.8, 0.2, 0.1]
    labels = [True, True, False, False]
    assert stats.roc_auc(scores, labels) == 1.0
    assert stats.roc_auc([-value for value in scores], labels) == 0.0


def test_auc_is_one_half_when_every_score_ties() -> None:
    assert stats.roc_auc([0.5] * 6, [True, True, False, False, True, False]) == 0.5


def test_auc_is_undefined_when_one_class_is_empty() -> None:
    assert stats.roc_auc([0.1, 0.2], [False, False]) is None


def test_average_precision_matches_a_hand_computed_case() -> None:
    # Ranked 0.9(+) 0.8(-) 0.7(+): precision 1/1 at the first hit and 2/3 at the
    # second, averaged over the two positives.
    value = stats.average_precision([0.9, 0.8, 0.7], [True, False, True])
    assert value == pytest.approx((1.0 + 2.0 / 3.0) / 2.0)


def test_operating_points_flag_at_or_above_the_threshold() -> None:
    points = stats.operating_points(
        [0.8, 0.5, 0.2], [True, False, False], [0.5]
    )
    assert points[0].flagged == 2
    assert points[0].true_positives == 1
    assert points[0].precision == pytest.approx(0.5)
    assert points[0].recall == pytest.approx(1.0)


# --- the two harness gates -------------------------------------------------


def test_a_leaked_label_drives_the_auc_to_one() -> None:
    """A predictor that is the label must score 1.0.

    This is the half of the negative control that a broken harness passes
    without: if the AUC path were wired to a constant, or the labels were
    misaligned with the scores, the shuffle test would still report ~0.5 and
    look like a clean result.
    """
    labels = [index % 3 == 0 for index in range(90)]
    leaked = [1.0 if label else 0.0 for label in labels]
    assert stats.roc_auc(leaked, labels) == 1.0
    mean, _, _ = stats.shuffled_auc(leaked, labels, rounds=200, seed=1)
    assert mean == pytest.approx(0.5, abs=0.03)


def test_shuffled_labels_collapse_a_genuinely_predictive_score() -> None:
    labels = [index % 4 == 0 for index in range(200)]
    scores = [0.9 if label else 0.1 for label in labels]
    scores[0] = 0.1
    observed = stats.roc_auc(scores, labels)
    assert observed is not None and observed > 0.9
    mean, low, high = stats.shuffled_auc(scores, labels, rounds=300, seed=7)
    assert mean == pytest.approx(0.5, abs=0.02)
    assert low > 0.2
    assert high < 0.8


# --- leakage ---------------------------------------------------------------


def test_release_index_at_excludes_the_day_of_t() -> None:
    record = _record(releases=(("1.0.0", T - timedelta(days=10)), ("1.1.0", T)))
    assert record.release_index_at(T) == 0


def test_no_post_t_release_can_change_a_feature() -> None:
    """Appending a future that changes every field must move nothing.

    The whole no-leakage claim reduces to this: features are read at
    ``index_at_t`` and nowhere else.
    """
    before = _record()
    after = _record(
        releases=before.releases
        + (
            ("2.0.0", T + timedelta(days=30)),
            ("3.0.0", T + timedelta(days=400)),
        ),
        maintainers=before.maintainers + ((3, ("mallory", "trudy", "victor", "peggy")),),
        repository=before.repository + ((3, None),),
        license_steps=before.license + ((3, "AGPL-3.0"),),
        dep_count=before.dep_count + ((3, 250),),
    )
    member = _member(before)
    scorer = RiskScorer()
    first = scorer.score_dependency(features.build_metadata(before, member))
    second = scorer.score_dependency(features.build_metadata(after, member))
    assert first.total_score == second.total_score
    assert first.maintainer_score == second.maintainer_score
    assert first.license_score == second.license_score
    assert first.source_repository_score == second.source_repository_score


# --- ablation --------------------------------------------------------------


def test_cadence_and_drift_are_never_measured_in_any_arm() -> None:
    """The one constraint that makes this pilot non-circular."""
    record = _record()
    member = _member(record)
    scorer = RiskScorer()
    for enabled in (
        features.PILOT_SIGNALS,
        features.PILOT_SIGNALS - {SIGNAL_MAINTAINER},
        frozenset(),
    ):
        result = scorer.score_dependency(features.build_metadata(record, member, enabled))
        assert SIGNAL_STALENESS in result.unknown_signals
        assert SIGNAL_VERSION in result.unknown_signals


def test_the_two_signals_this_pilot_cannot_reconstruct_are_left_unmeasured() -> None:
    """Neither the advisory verdict nor the retirement marker is invented here.

    Both were scored as a confident clean answer for all 2,906 packages before
    #321 and #320: the exploit signal fell back to ``has_known_exploits``'s
    ``False`` at the largest single weight in the scale, and ``is_deprecated``
    was a ``bool`` that could only say "affirmatively not retired". Neither is
    reconstructable at a past date — this pilot asks no advisory source
    anything, and npm applies ``deprecated`` retroactively to every version
    (#312) — so a value for either would be fabricated rather than harvested.

    Asserted on the reason as well as the state: "nobody ran the lookup" and
    "the source published nothing" are different facts about a backtest, and a
    reader of the coverage table is entitled to which one applies.
    """
    record = _record()
    member = _member(record)
    for enabled in (features.PILOT_SIGNALS, frozenset()):
        metadata = features.build_metadata(record, member, enabled)
        assert metadata.advisory_lookup_state is AdvisoryLookupState.NOT_ATTEMPTED
        assert metadata.is_deprecated is None

        result = RiskScorer().score_dependency(metadata)
        exploit = result.measurements[SIGNAL_EXPLOIT]
        deprecation = result.measurements[SIGNAL_DEPRECATION]

        assert exploit.state is MeasurementState.UNMEASURED
        assert exploit.reason is UnmeasuredReason.LOOKUP_NOT_ATTEMPTED
        assert result.exploit_score is None
        assert deprecation.state is MeasurementState.UNMEASURED
        assert deprecation.reason is UnmeasuredReason.NO_DATA_FROM_SOURCE
        assert result.deprecation_score is None


def test_ablating_a_signal_makes_the_scorer_report_it_unmeasured() -> None:
    record = _record()
    member = _member(record)
    scorer = RiskScorer()
    with_signal = scorer.score_dependency(features.build_metadata(record, member))
    assert (
        with_signal.measurements[SIGNAL_MAINTAINER].state is MeasurementState.MEASURED
    )
    without = scorer.score_dependency(
        features.build_metadata(record, member, features.PILOT_SIGNALS - {SIGNAL_MAINTAINER})
    )
    assert without.measurements[SIGNAL_MAINTAINER].state is MeasurementState.UNMEASURED
    assert without.total_score != with_signal.total_score


# --- cohort ----------------------------------------------------------------


def test_a_label_window_that_has_not_closed_is_refused() -> None:
    record = _record()
    with pytest.raises(ValueError, match="label window"):
        build_cohort([record], T, 3, T + timedelta(days=200))


def test_a_chosen_t_too_close_to_the_harvest_is_refused() -> None:
    """A T passed by hand must still leave the label window closed.

    ``t_for`` picks a T that closes; ``--t`` lets a caller pick one that does
    not, and the failure is silent rather than loud: every package whose
    silence is still running gets counted as abandoned, so the base rate rises
    and the labels describe a window that has not finished. Refusing is the
    only version of this that cannot be misread, because the run would
    otherwise produce a complete, plausible, wrong results document.

    Driven against the pinned snapshot rather than a synthetic one because the
    check needs N and the harvest instant, and both are read from the snapshot
    it is guarding.
    """
    snapshot = Path(__file__).resolve().parents[2] / "research/data/npm-2026-08-06"
    if not snapshot.exists():  # pragma: no cover - data is committed
        pytest.skip("pinned snapshot not present")
    with pytest.raises(ValueError, match="label window open"):
        experiment.run(snapshot_dir=snapshot, moment=datetime.now(timezone.utc))


def test_a_package_already_dormant_at_t_is_excluded() -> None:
    dormant = _record(
        name="dormant",
        releases=(
            ("1.0.0", T - timedelta(days=2000)),
            ("1.1.0", T - timedelta(days=1800)),
            ("1.2.0", T - timedelta(days=1500)),
        ),
    )
    members, excluded = build_cohort([dormant], T, 1, T + timedelta(days=400))
    assert members == ()
    assert excluded == {"already_dormant_at_T": 1}


def test_a_release_inside_the_window_means_not_abandoned() -> None:
    resumed = _record(
        releases=(
            ("1.0.0", T - timedelta(days=900)),
            ("1.1.0", T - timedelta(days=500)),
            ("1.2.0", T - timedelta(days=100)),
            ("1.3.0", T + timedelta(days=200)),
        )
    )
    members, _ = build_cohort([resumed], T, 1, T + timedelta(days=400))
    assert len(members) == 1
    assert members[0].abandoned is False


def test_packages_sharing_a_maintainer_form_one_cluster() -> None:
    def member(name: str, maintainers: Tuple[str, ...]) -> CohortMember:
        return CohortMember(
            name=name,
            index_at_t=0,
            last_release_before_t=T,
            first_release=T,
            releases_before_t=3,
            abandoned=False,
            maintainers=maintainers,
        )

    members = [
        member("a", ("alice",)),
        member("b", ("bob",)),
        member("c", ("alice", "carol")),
        member("d", ("carol",)),
        member("e", ("dave",)),
    ]
    clusters = maintainer_clusters(members)
    assert clusters[0] == clusters[2] == clusters[3]
    assert clusters[1] != clusters[0]
    assert clusters[4] != clusters[0]
    assert len(set(clusters)) == 3


def test_the_life_table_counts_the_trailing_silence_as_censored() -> None:
    history = [
        T - timedelta(days=1400),
        T - timedelta(days=1300),
        T - timedelta(days=1200),
    ]
    table = resumption_life_table([history], T)
    assert table[0].resumed == 2
    # The 1200-day tail is a silence of 3.28 years that has not ended.
    assert table[3].censored == 1
    assert table[1].resumed == 0


def test_n_falls_back_to_the_year_the_hazard_stops_falling() -> None:
    """A hazard that never clears the cutoff must still yield an N, and say so."""
    rows = [
        LifeTableRow(years=0, at_risk=1000, resumed=900, censored=0, hazard=0.90),
        LifeTableRow(years=1, at_risk=1000, resumed=500, censored=0, hazard=0.50),
        LifeTableRow(years=2, at_risk=900, resumed=270, censored=0, hazard=0.30),
        LifeTableRow(years=3, at_risk=800, resumed=280, censored=0, hazard=0.35),
    ]
    assert choose_abandonment_years(rows) == (2, "hazard_stops_falling")


def test_n_prefers_the_cutoff_rule_when_a_year_clears_it() -> None:
    rows = [
        LifeTableRow(years=0, at_risk=1000, resumed=900, censored=0, hazard=0.90),
        LifeTableRow(years=1, at_risk=1000, resumed=500, censored=0, hazard=0.50),
        LifeTableRow(years=2, at_risk=900, resumed=45, censored=0, hazard=0.05),
    ]
    assert choose_abandonment_years(rows) == (2, "hazard_below_cutoff")


def test_a_year_with_too_few_observations_is_not_read() -> None:
    rows = [
        LifeTableRow(years=0, at_risk=1000, resumed=900, censored=0, hazard=0.90),
        LifeTableRow(years=1, at_risk=12, resumed=0, censored=12, hazard=0.0),
    ]
    assert choose_abandonment_years(rows) == (None, "no_year_carries_enough_observations")


# --- the analysis stays offline --------------------------------------------


def test_no_analysis_module_can_reach_the_network() -> None:
    """CI must never hit a live registry, and this is what enforces it.

    Import-level, not call-level: a module that cannot import ``requests`` and
    does not import the harvester has no path to a socket, and that is checkable
    without running anything.
    """
    package = Path(features.__file__).parent
    offline = sorted(
        path
        for path in package.glob("*.py")
        if path.name not in {"harvest.py"}
    )
    assert offline, "the pilot package has no analysis modules"
    banned = {"requests", "urllib", "http", "socket", "aiohttp", "httpx"}
    for path in offline:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                root = name.split(".")[0]
                assert root not in banned, f"{path.name} imports {name}"
                assert "harvest" not in name, f"{path.name} imports {name}"


# --- the pinned snapshot ---------------------------------------------------


@pytest.fixture(scope="module")
def snapshot() -> Snapshot:
    if not (SNAPSHOT_DIR / "MANIFEST.json").exists():
        pytest.skip(f"no pinned snapshot at {SNAPSHOT_DIR}")
    return load_snapshot(SNAPSHOT_DIR)


def test_a_tampered_snapshot_is_refused(tmp_path: Path, snapshot: Snapshot) -> None:
    """The checksum gate has to bite, or pinning the data means nothing."""
    copy = tmp_path / "snapshot"
    shutil.copytree(SNAPSHOT_DIR, copy)
    (copy / "stars.json.gz").write_bytes(b"not the pinned bytes")
    with pytest.raises(ValueError, match="does not match the pinned"):
        load_snapshot(copy)


@pytest.fixture(scope="module")
def scored(snapshot: Snapshot) -> ScoredCohort:
    selection = experiment.choose_n(snapshot.silences)
    years = selection["N_years"]
    if not isinstance(years, int):
        raise AssertionError("N selection did not produce a whole number of years")
    moment = experiment.t_for(years, snapshot.harvested_at)
    members, _ = build_cohort(
        snapshot.packages, moment, years, snapshot.harvested_at
    )
    return experiment.score_cohort(snapshot, members, moment)


def test_the_pinned_cohort_has_both_classes(scored: ScoredCohort) -> None:
    positives = sum(1 for label in scored.labels if label)
    assert 0 < positives < len(scored.labels)
    assert len(scored.labels) >= 1000


def test_shuffling_the_labels_collapses_the_auc(scored: ScoredCohort) -> None:
    """The negative control, on the real cohort. Runs in CI."""
    control = experiment.negative_control(scored, rounds=200, seed=11)
    mean = control["shuffled_auc_mean"]
    low = control["shuffled_auc_min"]
    high = control["shuffled_auc_max"]
    assert isinstance(mean, float) and isinstance(low, float) and isinstance(high, float)
    assert mean == pytest.approx(0.5, abs=0.02)
    assert 0.35 < low
    assert high < 0.65


def test_the_pinned_cohort_scores_reproducibly(scored: ScoredCohort) -> None:
    first = stats.roc_auc(scored.arms["model"], scored.labels)
    again = stats.roc_auc(scored.arms["model"], scored.labels)
    assert first == again
