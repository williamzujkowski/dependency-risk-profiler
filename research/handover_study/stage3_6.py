"""Stages 3 to 6: negative control, trivial baselines, model, ablations.

Protocol §10 steps 3 through 6, in that order, and the order is the point. The
negative control is computed and written before any baseline or ablation is,
because §6 line 2 makes it a stop rule: *if the negative control is not clean,
nothing from the run is reported at all*. ``--stage3-only`` exists so the gate
can be read on its own, from its own artifact, before the rest is run.

Step 7, the misclassification audit, is deliberately absent. §7 forbids any
"evidence of absence" claim until it bounds the two error rates, and stage 2
put the generalised-rename upper bound at 10.0% of positives — sitting exactly
on the ceiling above which §7 says a null is reported as uninformative. A
module that could produce an absence claim without that audit is a module that
could be run without it.

Two structural facts govern how everything below is read, and both were fixed
by stages 1-2 rather than discovered here:

**This is a solo cohort.** 58.6% of packages have exactly one maintainer at T
and the median is 1 at both ends. For a solo package ``gained``, ``lost`` and
``complete turnover`` are close to the same event, so the five sub-definitions
are far less independent than a five-way split suggests. Every table below
carries that warning.

**Nominal n is not effective n.** 662 positives span 473 maintainer clusters.
Both numbers appear wherever an n appears, because the compromise backtest
cleared a raw-count bar and died on the effective one.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import CohortMember, build_cohort
from abandonment_pilot.snapshot import PackageRecord, Snapshot, load_snapshot
from abandonment_pilot.stats import (
    Interval,
    average_precision,
    bootstrap_interval,
    paired_auc_delta,
    roc_auc,
)

from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import MeasurementState

from .analysis import (
    Permutation,
    cluster_block_permutation,
    global_shuffle,
    invariant_share,
    permuted_auc,
    within_cluster_shuffle,
)
from .features import (
    BASELINE_NAMES,
    HANDOVER_SIGNALS,
    HandoverBaselines,
    baseline_value,
    build_handover_baselines,
    build_handover_metadata,
    literal_staleness_input,
    staleness_days_at_t,
)
from .harvest import HARVEST_NAME, load_harvest
from .stage2 import Comparison, compare

logger = logging.getLogger(__name__)

#: The single T protocol §3 fixes. There is no second date, and the write-up
#: says so wherever a result appears.
DEFAULT_T = "2024-08-01"

#: When stage 1 read npm's current top-level maintainer arrays, per that
#: harvest's own manifest.
DEFAULT_HARVESTED_AT = "2026-08-11T08:27:43.781813+00:00"

#: Bootstrap resamples for every interval. The pilot's value.
DEFAULT_REPLICATES = 2000

#: Permutations per negative control. The pilot's value.
DEFAULT_CONTROL_ROUNDS = 200

#: One seed for every resampling in a run, so a rerun is bit-identical.
DEFAULT_SEED = 20260811

#: Protocol §6 line 2: outside this, nothing from the run is reported.
CONTROL_BAND: Tuple[float, float] = (0.47, 0.53)

#: Protocol §6 line 1: the margin the model must clear over the best baseline.
REQUIRED_MARGIN = 0.05

#: The primary outcome, and the four sub-definitions §3 fixes beside it.
DEFINITIONS: Tuple[str, ...] = (
    "any_change",
    "gained",
    "lost",
    "both_gained_and_lost",
    "complete_turnover",
)

#: Carried on every table that splits the outcome five ways.
SOLO_COHORT_NOTE = (
    "This is a solo cohort: 58.6% of packages have exactly one maintainer at T "
    "and the median is 1 at both ends (stage 2, check 2). For a solo package "
    "'gained', 'lost' and 'complete turnover' are nearly the same event, so "
    "these five sub-definitions are far less independent than the split "
    "implies and must not be read as five findings."
)

#: Carried on every result, per §3 and §9.
SINGLE_T_NOTE = (
    "One T only (2024-08-01). The outcome says 'changed by the harvest', not "
    "'changed within a fixed window', so no multi-date replication exists. The "
    "abandonment result earned its weight from three dates; this cannot."
)

#: Carried on every null, per §7. Stage 7 has not been run.
NO_ABSENCE_NOTE = (
    "No claim of evidence of absence is made or licensed here. Protocol section "
    "7 forbids one until the stage-7 misclassification audit bounds the rename "
    "and silent-transfer error rates, and stage 2 measured the generalised "
    "rename signature at 10.0% of positives -- exactly the ceiling above which "
    "section 7 says a null is reported as uninformative. Stage 7 was not run."
)


def label_for(comparison: Comparison, definition: str) -> bool:
    """Return one comparison's label under one outcome definition.

    Args:
        comparison: A resolved frozen-versus-current comparison.
        definition: A member of :data:`DEFINITIONS`.

    Returns:
        The label.

    Raises:
        ValueError: If ``definition`` is not one of the five.
    """
    if definition == "any_change":
        return comparison.changed
    if definition == "gained":
        return bool(comparison.gained)
    if definition == "lost":
        return bool(comparison.lost)
    if definition == "both_gained_and_lost":
        return comparison.both
    if definition == "complete_turnover":
        return comparison.complete_turnover
    raise ValueError(f"unknown outcome definition {definition}")


def _interval_dict(interval: Interval) -> Dict[str, object]:
    """Render a bootstrap interval for the results document.

    Args:
        interval: The interval.

    Returns:
        A JSON-ready mapping.
    """
    return {
        "estimate": interval.estimate,
        "ci95": [interval.low, interval.high],
        "replicates": interval.replicates,
    }


@dataclass(frozen=True)
class ArmCoverage:
    """What the scorer could measure, and how much it could vary, in one arm."""

    signals_supplied: Tuple[str, ...]
    signals_measured: Dict[str, int]
    insufficient_data: int
    #: Signal -> measured value -> how many packages took it. A signal with one
    #: entry here cannot discriminate anything, whatever its weight.
    distinct_measured_values: Dict[str, Dict[str, int]]
    distinct_total_scores: int

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-ready mapping.

        Returns:
            The coverage document for this arm.
        """
        return {
            "signals_supplied": list(self.signals_supplied),
            "signals_measured": dict(sorted(self.signals_measured.items())),
            "insufficient_data": self.insufficient_data,
            "distinct_measured_values": {
                signal: dict(sorted(table.items()))
                for signal, table in sorted(self.distinct_measured_values.items())
            },
            "distinct_total_scores": self.distinct_total_scores,
        }


def _score_arm(
    scorer: RiskScorer,
    records: Dict[str, PackageRecord],
    members: Sequence[CohortMember],
    moment: datetime,
    reference_now: datetime,
    enabled: FrozenSet[str],
) -> Tuple[Tuple[float, ...], ArmCoverage]:
    """Score every member through the shipped scorer under one signal set.

    Args:
        scorer: The shipped scorer, at its shipped weights.
        records: Snapshot records by name.
        members: The resolved cohort, in a fixed order.
        moment: T.
        reference_now: A clock reading taken before scoring started.
        enabled: Signals whose as-of-T inputs are supplied.

    Returns:
        ``(normalized scores, coverage)``.
    """
    scores: List[float] = []
    insufficient = 0
    measured: Dict[str, int] = {}
    values: Dict[str, Dict[str, int]] = {}
    for member in members:
        metadata = build_handover_metadata(
            records[member.name], member, moment, reference_now, enabled
        )
        result = scorer.score_dependency(metadata)
        scores.append(result.total_score / scorer.max_score)
        if result.insufficient_data:
            insufficient += 1
        for name, measurement in result.measurements.items():
            if measurement.state is not MeasurementState.MEASURED:
                continue
            measured[name] = measured.get(name, 0) + 1
            table = values.setdefault(name, {})
            key = "unset" if measurement.value is None else f"{measurement.value:.4f}"
            table[key] = table.get(key, 0) + 1
    return tuple(scores), ArmCoverage(
        signals_supplied=tuple(sorted(enabled)),
        signals_measured=measured,
        insufficient_data=insufficient,
        distinct_measured_values=values,
        distinct_total_scores=len(set(scores)),
    )


def score_arms(
    snapshot: Snapshot,
    members: Sequence[CohortMember],
    moment: datetime,
    reference_now: datetime,
) -> Tuple[Dict[str, Tuple[float, ...]], Dict[str, object]]:
    """Score the full model and every single-signal ablation.

    Ablation is absence, as in the pilot: a signal is removed by leaving its
    input unset, and the scorer drops it from both the numerator and the
    denominator. Nothing here reaches into a weight.

    Args:
        snapshot: The verified pinned snapshot.
        members: The resolved cohort, in a fixed order.
        moment: T.
        reference_now: A clock reading taken before scoring started.

    Returns:
        ``(arm name -> scores, arm name -> coverage document)``.
    """
    records = {record.name: record for record in snapshot.packages}
    scorer = RiskScorer()

    configurations: List[Tuple[str, FrozenSet[str]]] = [("model", HANDOVER_SIGNALS)]
    for signal in sorted(HANDOVER_SIGNALS):
        configurations.append((f"ablate:{signal}", HANDOVER_SIGNALS - {signal}))

    arms: Dict[str, Tuple[float, ...]] = {}
    coverage: Dict[str, object] = {}
    for name, enabled in configurations:
        scores, arm_coverage = _score_arm(
            scorer, records, members, moment, reference_now, enabled
        )
        arms[name] = scores
        coverage[name] = arm_coverage.as_dict()
    return arms, coverage


def _staleness_bucket(scorer: RiskScorer, days: int) -> float:
    """Return the shipped staleness bucket for a whole-day gap.

    Computed by handing the shipped scorer a ``last_updated`` exactly that many
    days old, so the thresholds are read out of the scorer rather than restated
    here. The extra second makes the floor division land on ``days`` rather
    than one below it.

    Args:
        scorer: The shipped scorer.
        days: Whole days since the release.

    Returns:
        The bucket.

    Raises:
        ValueError: If the shipped scorer declines to measure a supplied date.
    """
    value = scorer._calculate_staleness_score(
        datetime.now(timezone.utc) - timedelta(days=days, seconds=1)
    )
    if value is None:
        raise ValueError("the shipped scorer returned no staleness for a supplied date")
    return value


def signal_reconstruction(
    members: Sequence[CohortMember],
    records: Dict[str, PackageRecord],
    moment: datetime,
    harvested_at: datetime,
) -> Dict[str, object]:
    """Report what the two never-before-tested signals actually resolve to at T.

    Evidence, not commentary. The distributions here are what license the claim
    that ``version`` is degenerate at T, and that the literal reading of
    ``staleness`` is the exposure window rather than the cadence at T.

    Args:
        members: The resolved cohort.
        records: Snapshot records by name.
        moment: T.
        harvested_at: When stage 1 harvested.

    Returns:
        A document describing both reconstructions.
    """
    scorer = RiskScorer()
    at_t_days = [staleness_days_at_t(member, moment) for member in members]
    literal_days = [
        (harvested_at - literal_staleness_input(member)).days for member in members
    ]

    def buckets(days: Sequence[int]) -> Dict[str, int]:
        table: Dict[str, int] = {}
        for value in days:
            key = f"{_staleness_bucket(scorer, value):.2f}"
            table[key] = table.get(key, 0) + 1
        return dict(sorted(table.items()))

    literal_buckets = buckets(literal_days)
    version_scores: Dict[str, int] = {}
    for member in members:
        installed = records[member.name].releases[member.index_at_t][0]
        score = scorer._calculate_version_difference_score(installed, installed)
        key = "unmeasured" if score is None else f"{score:.4f}"
        version_scores[key] = version_scores.get(key, 0) + 1

    return {
        "staleness": {
            "supplied_as": (
                "reference_now minus (T - release in force at T), so the shipped "
                "now-relative scorer computes the as-of-T bucket"
            ),
            "why_not_the_publish_time": (
                "RiskScorer._calculate_staleness_score buckets "
                "datetime.now() - last_updated. Handing it the unadjusted publish "
                "time measures days from that release to today, which IS "
                "exposure_window_days -- the quantity protocol section 5 assigns "
                "to baseline 5. Feeding it to the model would put the baseline "
                "inside the model."
            ),
            "days_at_T": {
                "min": min(at_t_days),
                "p50": sorted(at_t_days)[len(at_t_days) // 2],
                "max": max(at_t_days),
            },
            "as_of_T_buckets": buckets(at_t_days),
            "literal_reading": {
                "days": {
                    "min": min(literal_days),
                    "p50": sorted(literal_days)[len(literal_days) // 2],
                    "max": max(literal_days),
                },
                "buckets": literal_buckets,
                "degenerate": len(literal_buckets) == 1,
                "why_degenerate": (
                    "cohort eligibility caps staleness at T at 365 days, so every "
                    "exposure window is at least 2.03 years and every one lands "
                    "in the scorer's 'more than a year' bucket"
                ),
            },
        },
        "version": {
            "supplied_as": (
                "latest_version set to the version of the release in force at T, "
                "because at T that release IS the latest release"
            ),
            "scores_from_the_shipped_scorer": version_scores,
            "degenerate": len(version_scores) == 1,
            "why": (
                "RiskScorer._calculate_version_difference_score returns 0.0 on its "
                "equality branch, before the calendar-versioning path that would "
                "have read the two release dates. Every package scores an "
                "identical measured 0.0: the signal is supplied, weighed at 0.15, "
                "and cannot vary. A signal that cannot vary is not a tested "
                "signal."
            ),
        },
    }


def negative_control(
    scores: Sequence[float],
    labels: Sequence[bool],
    clusters: Sequence[int],
    rounds: int,
    seed: int,
) -> Dict[str, object]:
    """Run the pre-registered control and the two diagnostics beside it.

    Args:
        scores: Model scores, one per row.
        labels: One label per row.
        clusters: Maintainer component id per row.
        rounds: Permutations per control.
        seed: Seed.

    Returns:
        The control document, carrying the §6 line 2 verdict.
    """
    variants: Tuple[Tuple[str, Permutation], ...] = (
        ("within_cluster", within_cluster_shuffle),
        ("global", global_shuffle),
        ("cluster_block", cluster_block_permutation),
    )
    rendered: Dict[str, object] = {}
    passed = False
    for name, permutation in variants:
        mean, low, high, preserved = permuted_auc(
            scores, labels, clusters, permutation, rounds, seed
        )
        inside = CONTROL_BAND[0] <= mean <= CONTROL_BAND[1]
        if name == "within_cluster":
            passed = inside
        rendered[name] = {
            "rounds": rounds,
            "mean_auc": mean,
            "min_auc": low,
            "max_auc": high,
            "mean_label_preservation": preserved,
            "inside_band": inside,
        }
    return {
        "pre_registered": "within_cluster",
        "band": list(CONTROL_BAND),
        "observed_auc": roc_auc(scores, labels),
        "variants": rendered,
        "within_cluster_invariant_share": invariant_share(labels, clusters),
        "gate_passed": passed,
        "caveat": (
            "The pre-registered within-cluster shuffle cannot move the label of a "
            "row in a singleton cluster, nor of any cluster whose members already "
            "share a label. On this cohort that is most of the vector, so the "
            "control returns the observed AUC shrunk towards 0.5 rather than "
            "collapsing it: it passes when the model is weak and fires when the "
            "model is strong, which is the opposite of what a negative control is "
            "for. The global and cluster-block permutations are reported because "
            "they are the ones that can detect a harness reading the outcome "
            "through a path other than the features. Neither substitutes for the "
            "pre-registered gate, and neither is used to override it."
        ),
    }


@dataclass(frozen=True)
class BaselineComparison:
    """The model against one trivial baseline, on that baseline's own support."""

    name: str
    support: int
    support_clusters: int
    positives_on_support: int
    positive_clusters_on_support: int
    auc_as_recorded: Optional[float]
    orientation: str
    baseline_auc: Optional[float]
    model_auc_on_support: Optional[float]
    delta: Optional[float]
    ci95_clustered: Tuple[Optional[float], Optional[float]]
    ci95_unclustered: Tuple[Optional[float], Optional[float]]
    p_value_clustered: Optional[float]

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-ready mapping.

        Returns:
            The comparison document.
        """
        return {
            "support_nominal": self.support,
            "support_clusters": self.support_clusters,
            "positives_nominal_on_support": self.positives_on_support,
            "positive_clusters_on_support": self.positive_clusters_on_support,
            "auc_as_recorded": self.auc_as_recorded,
            "orientation": self.orientation,
            "baseline_auc": self.baseline_auc,
            "model_auc_on_support": self.model_auc_on_support,
            "model_minus_baseline": self.delta,
            "ci95_clustered": list(self.ci95_clustered),
            "ci95_unclustered": list(self.ci95_unclustered),
            "p_value_clustered": self.p_value_clustered,
        }


def compare_baselines(
    model: Sequence[float],
    baselines: Sequence[HandoverBaselines],
    labels: Sequence[bool],
    clusters: Sequence[int],
    replicates: int,
    seed: int,
) -> List[BaselineComparison]:
    """Run the model head-to-head against each of the five trivial baselines.

    Each baseline is measured for a different subset — npm answers downloads
    for about half the cohort, GitHub answers stars for about two thirds — so
    each comparison runs on that baseline's own support and the model is
    re-scored on the same rows. Padding a missing baseline with zero would
    score the packages it knows least about as the safest ones it knows.

    **Orientation favours the baseline.** None of the five is a risk score, so
    the sign of "more of this means more handover" is taken from the data,
    which hands the baseline the better of its two possible AUCs. That is the
    conservative direction for the claim under test.

    Args:
        model: Model scores per row.
        baselines: Baselines per row.
        labels: Label per row.
        clusters: Maintainer component id per row.
        replicates: Bootstrap resamples.
        seed: Seed.

    Returns:
        One comparison per baseline, in :data:`BASELINE_NAMES` order.
    """
    out: List[BaselineComparison] = []
    for name in BASELINE_NAMES:
        values = [baseline_value(item, name) for item in baselines]
        support = [index for index, value in enumerate(values) if value is not None]
        subset_labels = [labels[index] for index in support]
        subset_clusters = [clusters[index] for index in support]
        scores = [float(values[index] or 0.0) for index in support]
        # ``or 0.0`` above is unreachable for a None: ``support`` selected the
        # non-None positions. It is there so the list is typed ``float`` rather
        # than ``Optional[float]``, which is what the ranker needs.
        auc_raw = roc_auc(scores, subset_labels)
        blank = BaselineComparison(
            name=name,
            support=len(support),
            support_clusters=len(set(subset_clusters)),
            positives_on_support=sum(1 for label in subset_labels if label),
            positive_clusters_on_support=len(
                {
                    cluster
                    for cluster, label in zip(subset_clusters, subset_labels)
                    if label
                }
            ),
            auc_as_recorded=auc_raw,
            orientation="undefined",
            baseline_auc=None,
            model_auc_on_support=None,
            delta=None,
            ci95_clustered=(None, None),
            ci95_unclustered=(None, None),
            p_value_clustered=None,
        )
        if auc_raw is None:
            out.append(blank)
            continue
        flipped = auc_raw < 0.5
        oriented = [-value for value in scores] if flipped else scores
        paired = paired_auc_delta(
            [model[index] for index in support],
            oriented,
            subset_labels,
            subset_clusters,
            replicates,
            seed,
        )
        out.append(
            replace(
                blank,
                orientation="less is riskier" if flipped else "more is riskier",
                baseline_auc=paired.auc_b,
                model_auc_on_support=paired.auc_a,
                delta=paired.delta,
                ci95_clustered=(paired.clustered.low, paired.clustered.high),
                ci95_unclustered=(paired.unclustered.low, paired.unclustered.high),
                p_value_clustered=paired.p_value,
            )
        )
    return out


def falsification_line_1(
    comparisons: Sequence[BaselineComparison],
) -> Dict[str, object]:
    """Read §6 line 1 against the best trivial baseline.

    The best baseline is the one with the highest oriented AUC. Supports
    differ, so the head-to-head against it is the paired comparison already
    computed on its own rows; the five AUCs are not pooled across supports and
    are not comparable as though they were.

    Args:
        comparisons: The output of :func:`compare_baselines`.

    Returns:
        The verdict, and the numbers it was read from.
    """
    ranked = [item for item in comparisons if item.baseline_auc is not None]
    if not ranked:
        return {"verdict": "no baseline produced a defined AUC"}
    best = max(ranked, key=lambda item: item.baseline_auc or 0.0)
    low, high = best.ci95_clustered
    excludes_zero = low is not None and high is not None and (low > 0.0 or high < 0.0)
    cleared = best.delta is not None and best.delta >= REQUIRED_MARGIN and excludes_zero
    return {
        "best_baseline": best.name,
        "best_baseline_auc": best.baseline_auc,
        "model_auc_on_its_support": best.model_auc_on_support,
        "model_minus_baseline": best.delta,
        "required_margin": REQUIRED_MARGIN,
        "ci95_clustered": list(best.ci95_clustered),
        "interval_excludes_zero": excludes_zero,
        "interval_lower_bound_clears_margin": (
            low is not None and low >= REQUIRED_MARGIN
        ),
        "cleared": cleared,
        "consequence": (
            "the claim in protocol section 2 is made"
            if cleared
            else "the claim in protocol section 2 is NOT made"
        ),
        "no_absence_claim": NO_ABSENCE_NOTE,
    }


def ablations(
    arms: Dict[str, Tuple[float, ...]],
    labels: Sequence[bool],
    clusters: Sequence[int],
    replicates: int,
    seed: int,
) -> Dict[str, object]:
    """Compare the full model against each single-signal ablation.

    Args:
        arms: Arm name -> scores.
        labels: Label per row.
        clusters: Maintainer component id per row.
        replicates: Bootstrap resamples.
        seed: Seed.

    Returns:
        One entry per ablated signal. ``auc_moved_by`` is the model's AUC minus
        the ablated arm's, so a positive number is a signal that contributed.
    """
    model = arms["model"]
    out: Dict[str, object] = {}
    for name in sorted(arms):
        if name == "model":
            continue
        delta = paired_auc_delta(model, arms[name], labels, clusters, replicates, seed)
        out[name] = {
            "auc_with": delta.auc_a,
            "auc_without": delta.auc_b,
            "auc_moved_by": delta.delta,
            "ci95_clustered": [delta.clustered.low, delta.clustered.high],
            "p_value_clustered": delta.p_value,
        }
    return out


def evaluate_definition(
    definition: str,
    arms: Dict[str, Tuple[float, ...]],
    baselines: Sequence[HandoverBaselines],
    labels: Sequence[bool],
    clusters: Sequence[int],
    replicates: int,
    control_rounds: int,
    seed: int,
) -> Dict[str, object]:
    """Run stages 4, 5 and 6 for one outcome definition.

    Args:
        definition: Which of the five.
        arms: Arm name -> scores.
        baselines: Baselines per row.
        labels: Label per row under this definition.
        clusters: Maintainer component id per row.
        replicates: Bootstrap resamples.
        control_rounds: Permutations for this definition's control.
        seed: Seed.

    Returns:
        The per-definition results.
    """
    model = arms["model"]
    positives = sum(1 for label in labels if label)
    positive_clusters = len(
        {cluster for cluster, label in zip(clusters, labels) if label}
    )

    def model_auc(indices: Sequence[int]) -> Optional[float]:
        return roc_auc(
            [model[index] for index in indices], [labels[index] for index in indices]
        )

    comparisons = compare_baselines(
        model, baselines, labels, clusters, replicates, seed
    )
    return {
        "definition": definition,
        "is_primary": definition == "any_change",
        "n_nominal": len(labels),
        "positives_nominal": positives,
        "positive_maintainer_clusters": positive_clusters,
        "clusters_in_cohort": len(set(clusters)),
        "base_rate": positives / len(labels) if labels else 0.0,
        "negative_control": negative_control(
            model, labels, clusters, control_rounds, seed
        ),
        "model": {
            "signals": sorted(HANDOVER_SIGNALS),
            "auc": _interval_dict(
                bootstrap_interval(model_auc, clusters, replicates, seed)
            ),
            "average_precision": average_precision(model, labels),
        },
        "baselines": {item.name: item.as_dict() for item in comparisons},
        "falsification_line_1": falsification_line_1(comparisons),
        "ablations": ablations(arms, labels, clusters, replicates, seed),
        "solo_cohort_note": SOLO_COHORT_NOTE,
    }


def resolve_cohort(
    snapshot: Snapshot, harvest_dir: Path, moment: datetime
) -> Tuple[List[CohortMember], List[Comparison], List[int], Dict[str, int], int]:
    """Rebuild the cohort at T and pair it with the stage-1 harvest.

    Args:
        snapshot: The verified pinned snapshot.
        harvest_dir: The stage-1 artifact directory.
        moment: T.

    Returns:
        ``(resolved members, comparisons, cluster ids, unresolved counts by
        category, nominal cohort size)``. The four sequences are aligned.
    """
    members, _ = build_cohort(snapshot.packages, moment, 2, snapshot.harvested_at)
    harvested: Dict[str, object] = dict(load_harvest(harvest_dir / HARVEST_NAME))
    comparisons, clusters, unresolved = compare(members, harvested)
    by_name = {member.name: member for member in members}
    resolved = [by_name[item.name] for item in comparisons]
    return resolved, comparisons, clusters, unresolved, len(members)


def run(
    snapshot_dir: Path,
    harvest_dir: Path,
    moment: datetime,
    harvested_at: datetime,
    replicates: int = DEFAULT_REPLICATES,
    control_rounds: int = DEFAULT_CONTROL_ROUNDS,
    seed: int = DEFAULT_SEED,
    stage3_only: bool = False,
) -> Dict[str, object]:
    """Run stages 3 to 6 and return the results document.

    Args:
        snapshot_dir: The pinned snapshot the cohort is rebuilt from.
        harvest_dir: The stage-1 harvest directory.
        moment: T.
        harvested_at: When stage 1 harvested.
        replicates: Bootstrap resamples per interval.
        control_rounds: Permutations per negative control.
        seed: Seed for every resampling.
        stage3_only: Stop after the negative control, so the §6 line 2 gate can
            be read from its own artifact before anything downstream exists.

    Returns:
        The results, ready to serialise.
    """
    snapshot = load_snapshot(snapshot_dir)
    resolved, comparisons, clusters, unresolved, nominal = resolve_cohort(
        snapshot, harvest_dir, moment
    )
    records = {record.name: record for record in snapshot.packages}
    logger.info("resolved %d of %d cohort members", len(resolved), nominal)

    # Captured before any scoring: the shipped staleness scorer reads its own
    # clock, and a reference taken afterwards would leave the difference a few
    # seconds short of a whole day and could round a package across a bucket
    # boundary.
    reference_now = datetime.now(timezone.utc)
    arms, coverage = score_arms(snapshot, resolved, moment, reference_now)

    downloads = snapshot.downloads.get(moment.date().isoformat(), {})
    baselines = [
        build_handover_baselines(
            member,
            moment,
            records[member.name],
            downloads,
            snapshot.stars,
            harvested_at,
        )
        for member in resolved
    ]

    primary = [label_for(item, "any_change") for item in comparisons]
    document: Dict[str, object] = {
        "study": "maintainer handover, docs/handover-outcome-protocol.md",
        "stages": "3" if stage3_only else "3-6",
        "T": moment.date().isoformat(),
        "harvested_at": harvested_at.isoformat(),
        "seed": seed,
        "replicates": replicates,
        "control_rounds": control_rounds,
        "notes": {
            "single_T": SINGLE_T_NOTE,
            "solo_cohort": SOLO_COHORT_NOTE,
            "no_absence_claim": NO_ABSENCE_NOTE,
        },
        "cohort": {
            "nominal": nominal,
            "resolved": len(resolved),
            "unresolved_by_category": dict(sorted(unresolved.items())),
            "maintainer_clusters": len(set(clusters)),
            "primary_positives_nominal": sum(1 for label in primary if label),
            "primary_positive_clusters": len(
                {cluster for cluster, label in zip(clusters, primary) if label}
            ),
        },
        "signal_reconstruction": signal_reconstruction(
            resolved, records, moment, harvested_at
        ),
        "coverage": coverage,
        "stage3_negative_control_primary": negative_control(
            arms["model"], primary, clusters, control_rounds, seed
        ),
    }
    if stage3_only:
        document["stages_4_to_6"] = (
            "not run: --stage3-only, so the section 6 line 2 gate is read from "
            "this artifact before anything downstream exists"
        )
        return document

    document["definitions"] = {
        definition: evaluate_definition(
            definition,
            arms,
            baselines,
            [label_for(item, definition) for item in comparisons],
            clusters,
            replicates,
            control_rounds,
            seed,
        )
        for definition in DEFINITIONS
    }
    return document


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run stages 3 to 6 and write the results document.

    Args:
        argv: Command line, or None for ``sys.argv``.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot", type=Path, default=Path("research/data/npm-2026-08-06")
    )
    parser.add_argument(
        "--harvest", type=Path, default=Path("research/data/handover-2026-08-11")
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--T", dest="moment", default=DEFAULT_T)
    parser.add_argument("--harvested-at", default=DEFAULT_HARVESTED_AT)
    parser.add_argument("--replicates", type=int, default=DEFAULT_REPLICATES)
    parser.add_argument("--control-rounds", type=int, default=DEFAULT_CONTROL_ROUNDS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--stage3-only", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    results = run(
        snapshot_dir=args.snapshot,
        harvest_dir=args.harvest,
        moment=datetime.fromisoformat(args.moment).replace(tzinfo=timezone.utc),
        harvested_at=datetime.fromisoformat(args.harvested_at),
        replicates=args.replicates,
        control_rounds=args.control_rounds,
        seed=args.seed,
        stage3_only=args.stage3_only,
    )
    with args.out.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
