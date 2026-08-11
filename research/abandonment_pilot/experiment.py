"""The pilot end to end: snapshot in, results document out.

Order matters here and it is the pre-registered order. N is chosen from the
release-silence life table before any cohort exists; the cohort is built and its
base rate measured before any model is scored; the trivial baselines are
compared before the ablations are run. Nothing downstream can reach back and
change something upstream, which is what stops a threshold from being picked
because it flattered a number that had already been seen.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import MeasurementState

from .cohort import (
    CANDIDATE_T,
    DAYS_PER_YEAR,
    RESUMPTION_HAZARD_CUTOFF,
    CohortMember,
    build_cohort,
    choose_abandonment_years,
    maintainer_clusters,
    resumption_life_table,
)
from .features import PILOT_SIGNALS, Baselines, build_baselines, build_metadata
from .snapshot import PackageRecord, Snapshot, load_snapshot
from .stats import (
    Interval,
    average_precision,
    bootstrap_interval,
    bucket_rates,
    operating_points,
    paired_auc_delta,
    roc_auc,
    shuffled_auc,
)

logger = logging.getLogger(__name__)

#: The tool's own verdict boundaries, as fractions of ``max_score``.
OPERATING_THRESHOLDS: Tuple[float, ...] = (0.25, 0.5, 0.75)

#: Buckets in ascending severity, for the calibration table.
BUCKET_ORDER: Tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

#: Bootstrap resamples for every interval reported.
DEFAULT_REPLICATES = 2000

#: Label permutations for the negative control.
DEFAULT_CONTROL_ROUNDS = 200

#: Seed for every resampling in a run, so a rerun is bit-identical.
DEFAULT_SEED = 20260806

#: The sentence that goes on every result table, because the protocol says it
#: must. Abandonment is observed over a closed window; a package silent for N
#: years may still publish in year N+1, so the positive class is a lower bound
#: on eventual abandonment and every rate below is a floor.
LOWER_BOUND_NOTE = (
    "Labels are lower bounds: a package counted as abandoned may yet publish "
    "again after the observation window closes."
)


@dataclass(frozen=True)
class ScoredCohort:
    """The cohort, its outcome, and one score per package per arm."""

    members: Tuple[CohortMember, ...]
    labels: Tuple[bool, ...]
    clusters: Tuple[int, ...]
    baselines: Tuple[Baselines, ...]
    #: Arm name -> normalized score per package, in ``members`` order.
    arms: Dict[str, Tuple[float, ...]]
    #: Arm name -> verdict bucket per package.
    buckets: Dict[str, Tuple[str, ...]]
    #: Arm name -> how many packages the scorer refused a verdict for.
    insufficient: Dict[str, int]
    #: Arm name -> signal name -> packages the scorer could measure it for.
    measured: Dict[str, Dict[str, int]]


def _score_arm(
    scorer: RiskScorer,
    records: Dict[str, PackageRecord],
    members: Sequence[CohortMember],
    enabled: FrozenSet[str],
) -> Tuple[List[float], List[str], int, Dict[str, int]]:
    """Score every cohort member through the production scorer.

    Args:
        scorer: The shipped scorer, at its shipped weights.
        records: Snapshot records by package name.
        members: The cohort.
        enabled: Signals whose as-of-T inputs are supplied.

    Returns:
        ``(normalized scores, verdict buckets, insufficient_data count,
        measured-count per signal)``.
    """
    scores: List[float] = []
    buckets: List[str] = []
    insufficient = 0
    measured: Dict[str, int] = {}
    for member in members:
        metadata: DependencyMetadata = build_metadata(
            records[member.name], member, enabled
        )
        result = scorer.score_dependency(metadata)
        scores.append(result.total_score / scorer.max_score)
        # The scorer's own ``risk_level`` is UNKNOWN for any package whose
        # unexplained-unknown count exceeds its measured-signal count, which a
        # registry-only arm reaches whenever the package declares a repository
        # nobody read. The verdict boundaries still have to be evaluated, so
        # the bucket is taken from the same thresholds the scorer applies and
        # the abstention is reported alongside as its own number.
        buckets.append(scorer._determine_risk_level(result.total_score).name)
        if result.insufficient_data:
            insufficient += 1
        for name, measurement in result.measurements.items():
            if measurement.state is MeasurementState.MEASURED:
                measured[name] = measured.get(name, 0) + 1
    return scores, buckets, insufficient, measured


def score_cohort(
    snapshot: Snapshot,
    members: Sequence[CohortMember],
    moment: datetime,
) -> ScoredCohort:
    """Score the cohort under the full ablated model and each single ablation.

    Args:
        snapshot: The verified snapshot.
        members: The cohort at T.
        moment: T.

    Returns:
        Every arm's scores, aligned to ``members``.
    """
    records = {record.name: record for record in snapshot.packages}
    downloads = _downloads_at(snapshot, moment)
    scorer = RiskScorer()

    arms: Dict[str, Tuple[float, ...]] = {}
    buckets: Dict[str, Tuple[str, ...]] = {}
    insufficient: Dict[str, int] = {}
    measured: Dict[str, Dict[str, int]] = {}

    configurations: List[Tuple[str, FrozenSet[str]]] = [("model", PILOT_SIGNALS)]
    for signal in sorted(PILOT_SIGNALS):
        configurations.append((f"ablate:{signal}", PILOT_SIGNALS - {signal}))

    for name, enabled in configurations:
        scores, arm_buckets, count, arm_measured = _score_arm(
            scorer, records, members, enabled
        )
        arms[name] = tuple(scores)
        buckets[name] = tuple(arm_buckets)
        insufficient[name] = count
        measured[name] = arm_measured

    return ScoredCohort(
        members=tuple(members),
        labels=tuple(member.abandoned for member in members),
        clusters=maintainer_clusters(members),
        baselines=tuple(
            build_baselines(
                member, moment, records[member.name], downloads, snapshot.stars
            )
            for member in members
        ),
        arms=arms,
        buckets=buckets,
        insufficient=insufficient,
        measured=measured,
    )


def _downloads_at(snapshot: Snapshot, moment: datetime) -> Dict[str, int]:
    """Return the download table for T, or an empty one when none was harvested."""
    key = moment.date().isoformat()
    nested = snapshot.downloads.get(key)
    if isinstance(nested, dict):
        return {str(name): int(value) for name, value in nested.items()}
    return {}


def _interval_dict(interval: Interval) -> Dict[str, object]:
    """Render an interval for the results document."""
    return {
        "estimate": interval.estimate,
        "ci95": [interval.low, interval.high],
        "replicates": interval.replicates,
    }


def _baseline_values(
    baselines: Sequence[Baselines], name: str
) -> List[Optional[float]]:
    """Return one baseline's value per package, None where unmeasured."""
    if name == "downloads_at_t":
        return [
            None if item.downloads_at_t is None else float(item.downloads_at_t)
            for item in baselines
        ]
    if name == "age_days":
        return [float(item.age_days) for item in baselines]
    if name == "dep_count":
        return [
            None if item.dep_count is None else float(item.dep_count)
            for item in baselines
        ]
    if name == "stars_today":
        return [
            None if item.stars_today is None else float(item.stars_today)
            for item in baselines
        ]
    raise ValueError(f"unknown baseline {name}")


BASELINE_NAMES: Tuple[str, ...] = (
    "downloads_at_t",
    "age_days",
    "dep_count",
    "stars_today",
)


def compare_baselines(
    scored: ScoredCohort, replicates: int, seed: int
) -> Dict[str, object]:
    """Run the model against each trivial baseline, paired on its own support.

    Each baseline is measured for a different subset of the cohort — npm answers
    for nearly every package, GitHub only for those declaring a repository — so
    each comparison is restricted to the packages where that baseline exists,
    and the model is re-scored on the same subset. Padding a missing baseline
    with zero would be scoring the packages it knows least about as the safest
    ones it knows.

    **Orientation is chosen to favour the baseline.** None of these four is a
    risk score, so the sign of "more of this means more abandonment" has to come
    from somewhere; taking it from the data gives the baseline the better of its
    two possible AUCs. That is the conservative direction for the claim under
    test.

    Args:
        scored: The scored cohort.
        replicates: Bootstrap resamples.
        seed: Seed.

    Returns:
        One entry per baseline.
    """
    model = scored.arms["model"]
    out: Dict[str, object] = {}
    for name in BASELINE_NAMES:
        values = _baseline_values(scored.baselines, name)
        support = [index for index, value in enumerate(values) if value is not None]
        labels = [scored.labels[index] for index in support]
        raw = [values[index] for index in support]
        baseline_scores = [value for value in raw if value is not None]
        auc_raw = roc_auc(baseline_scores, labels)
        if auc_raw is None:
            out[name] = {"support": len(support), "auc": None}
            continue
        flipped = auc_raw < 0.5
        oriented = [-value for value in baseline_scores] if flipped else baseline_scores
        delta = paired_auc_delta(
            [model[index] for index in support],
            oriented,
            labels,
            [scored.clusters[index] for index in support],
            replicates,
            seed,
        )
        out[name] = {
            "support": len(support),
            "positives": sum(1 for label in labels if label),
            "auc_as_recorded": auc_raw,
            "orientation": "less is riskier" if flipped else "more is riskier",
            "auc_oriented": delta.auc_b,
            "model_auc_on_support": delta.auc_a,
            "model_minus_baseline": delta.delta,
            "ci95_clustered": [delta.clustered.low, delta.clustered.high],
            "ci95_unclustered": [delta.unclustered.low, delta.unclustered.high],
            "p_value_clustered": delta.p_value,
        }
    return out


def stratify_by_downloads(
    scored: ScoredCohort, strata: int = 5
) -> Dict[str, object]:
    """Report the model's discrimination *within* download strata.

    The protocol's first confound mitigation, and after the baseline table the
    most informative thing here: if the model separates packages only across
    strata and not within them, it has rediscovered the download count. Strata
    rather than deciles because the download baseline is measured for about
    half the cohort and a tenth of a half is too thin to read.

    Args:
        scored: The scored cohort.
        strata: How many equal-sized download bands to cut.

    Returns:
        Per-stratum size, base rate and model AUC.
    """
    model = scored.arms["model"]
    support = [
        index
        for index, item in enumerate(scored.baselines)
        if item.downloads_at_t is not None
    ]
    support.sort(key=lambda index: scored.baselines[index].downloads_at_t or 0)
    rows: List[Dict[str, object]] = []
    width = max(1, len(support) // strata)
    for band in range(strata):
        start = band * width
        end = len(support) if band == strata - 1 else (band + 1) * width
        indices = support[start:end]
        if not indices:
            continue
        labels = [scored.labels[index] for index in indices]
        downloads = [scored.baselines[index].downloads_at_t or 0 for index in indices]
        rows.append(
            {
                "stratum": band + 1,
                "downloads_at_t": [min(downloads), max(downloads)],
                "count": len(indices),
                "abandoned": sum(1 for label in labels if label),
                "base_rate": sum(1 for label in labels if label) / len(indices),
                "model_auc": roc_auc([model[index] for index in indices], labels),
            }
        )
    return {"support": len(support), "strata": rows}


def negative_control(
    scored: ScoredCohort, rounds: int, seed: int
) -> Dict[str, object]:
    """Shuffle the labels and confirm the model's AUC collapses to chance.

    Args:
        scored: The scored cohort.
        rounds: Permutations to draw.
        seed: Seed.

    Returns:
        Mean, minimum and maximum shuffled AUC, and the observed AUC beside them.
    """
    mean, low, high = shuffled_auc(scored.arms["model"], scored.labels, rounds, seed)
    return {
        "rounds": rounds,
        "shuffled_auc_mean": mean,
        "shuffled_auc_min": low,
        "shuffled_auc_max": high,
        "observed_auc": roc_auc(scored.arms["model"], scored.labels),
    }


def choose_n(
    histories: Sequence[Sequence[datetime]],
    cutoff: float = RESUMPTION_HAZARD_CUTOFF,
) -> Dict[str, object]:
    """Pick N from the release-silence life table at every candidate T.

    Reporting all four candidates rather than one is the check that N is a
    property of how npm packages release and not of where the cut happened to
    fall.

    Args:
        histories: Release-time sequences for every sampled package.
        cutoff: The 12-month resumption hazard below which silence reads as
            abandonment.

    Returns:
        The per-candidate tables and the chosen N.

    Raises:
        ValueError: If no candidate yields an N the snapshot can observe.
    """
    tables: Dict[str, object] = {}
    chosen: List[int] = []
    for moment in CANDIDATE_T:
        table = resumption_life_table(histories, moment)
        years, rule = choose_abandonment_years(table, cutoff)
        tables[moment.date().isoformat()] = {
            "life_table": [asdict(row) for row in table],
            "N_years": years,
            "rule_applied": rule,
        }
        if years is not None:
            chosen.append(years)
    if not chosen:
        raise ValueError(
            "no candidate cut-off date produced a life table with a readable N"
        )
    return {
        "cutoff": cutoff,
        "per_candidate_T": tables,
        "N_years": max(chosen),
        "rule": (
            "N is read off the life table by two rules in order: the first "
            "whole year whose 12-month resumption hazard is below the cutoff, "
            "or failing that the first year after which the hazard stops "
            "falling. Where the candidate cut-off dates disagree, the largest "
            "N is taken: it is the conservative one, because it labels fewer "
            "packages abandoned."
        ),
    }


def t_for(abandonment_years: int, observed_until: datetime) -> datetime:
    """Return the latest candidate T whose label window closes by ``observed_until``.

    Args:
        abandonment_years: N.
        observed_until: When the snapshot was harvested.

    Returns:
        T.

    Raises:
        ValueError: If no candidate leaves room for an N-year window.
    """
    window = timedelta(days=abandonment_years * DAYS_PER_YEAR)
    usable = [moment for moment in CANDIDATE_T if moment + window <= observed_until]
    if not usable:
        raise ValueError(
            f"no candidate T leaves a closed {abandonment_years}-year window "
            f"before {observed_until.isoformat()}"
        )
    return max(usable)


def run(
    snapshot_dir: Path,
    replicates: int = DEFAULT_REPLICATES,
    control_rounds: int = DEFAULT_CONTROL_ROUNDS,
    seed: int = DEFAULT_SEED,
    moment: Optional[datetime] = None,
    override_years: Optional[int] = None,
) -> Dict[str, object]:
    """Run the whole pilot and return the results document.

    Args:
        snapshot_dir: A pinned snapshot directory.
        replicates: Bootstrap resamples per interval.
        control_rounds: Permutations for the negative control.
        seed: Seed for every resampling.
        moment: T. Defaults to the latest candidate whose label window closes
            by the harvest. Earlier candidates are what make the result
            checkable against time rather than against one date: a run at a
            single T cannot distinguish a finding from an artefact of the
            year it was measured in.
        override_years: N, overriding the value the life table selects. A
            sensitivity analysis: it asks whether a finding survives a
            different definition of the outcome. The pre-registered N is kept
            alongside it in the results document.

    Returns:
        The results, ready to serialize.
    """
    snapshot = load_snapshot(snapshot_dir)
    observed_until = snapshot.harvested_at

    selection = choose_n(snapshot.silences)
    years = selection["N_years"]
    if not isinstance(years, int):
        raise ValueError("N selection did not produce a whole number of years")
    if override_years is not None:
        # N is pre-registered: it comes from the release-silence life table
        # before any cohort exists, so it cannot be picked because it flattered
        # a result. Overriding it is a SENSITIVITY ANALYSIS and nothing else --
        # it asks whether a finding survives a different definition of the
        # outcome. The override is recorded in the results document beside the
        # pre-registered value so the two can never be confused for each other.
        selection = dict(selection)
        selection["N_years_preregistered"] = years
        selection["N_years"] = override_years
        selection["override_reason"] = "sensitivity analysis, not the registered N"
        years = override_years
    if moment is None:
        moment = t_for(years, observed_until)
    elif moment + timedelta(days=years * DAYS_PER_YEAR) > observed_until:
        # A T this late leaves the label window open: packages would be
        # counted as abandoned on the strength of a silence still running.
        raise ValueError(
            f"T={moment.date()} leaves the {years}-year label window open "
            f"at the harvest ({observed_until.date()}); the labels would be "
            "read off an unclosed window"
        )

    members, excluded = build_cohort(snapshot.packages, moment, years, observed_until)
    if not members:
        raise ValueError(f"no package is eligible at {moment.isoformat()}")
    logger.info("cohort %d packages at T=%s, N=%d", len(members), moment.date(), years)

    scored = score_cohort(snapshot, members, moment)
    labels = scored.labels
    positives = sum(1 for label in labels if label)

    model = scored.arms["model"]

    def model_auc(indices: Sequence[int]) -> Optional[float]:
        return roc_auc(
            [model[index] for index in indices], [labels[index] for index in indices]
        )

    auc_interval = bootstrap_interval(model_auc, scored.clusters, replicates, seed)

    ablations: Dict[str, object] = {}
    for name in sorted(scored.arms):
        if name == "model":
            continue
        delta = paired_auc_delta(
            model, scored.arms[name], labels, scored.clusters, replicates, seed
        )
        ablations[name] = {
            "auc_without": delta.auc_b,
            "auc_with": delta.auc_a,
            "auc_moved_by": delta.delta,
            "ci95_clustered": [delta.clustered.low, delta.clustered.high],
            "insufficient_data": scored.insufficient[name],
        }

    return {
        "note": LOWER_BOUND_NOTE,
        "snapshot": {
            "directory": snapshot_dir.name,
            "harvested_at": snapshot.manifest.get("harvested_at"),
            "ecosystem": snapshot.manifest.get("ecosystem"),
            "sample": snapshot.manifest.get("sample"),
            "name_universe": snapshot.manifest.get("name_universe"),
            "files": snapshot.manifest.get("files"),
            "stored_packages": len(snapshot.packages),
        },
        "n_selection": selection,
        "T": moment.date().isoformat(),
        "N_years": years,
        "cohort": {
            "size": len(members),
            "abandoned": positives,
            "base_rate": positives / len(members),
            "maintainer_clusters": len(set(scored.clusters)),
            "largest_cluster": max(
                scored.clusters.count(cluster) for cluster in set(scored.clusters)
            ),
            "excluded_from_stored": excluded,
        },
        "coverage": {
            "signals_measured": scored.measured["model"],
            "insufficient_data": scored.insufficient["model"],
            "downloads_at_t": sum(
                1 for item in scored.baselines if item.downloads_at_t is not None
            ),
            # Split because npm's download API throttles hard and only its bulk
            # form, which rejects scoped names, gets past that at any volume.
            # The support for the download baseline is therefore mostly
            # unscoped packages, and a reader has to be able to see that
            # rather than infer it from a total.
            "downloads_at_t_by_name_shape": {
                "unscoped_measured": sum(
                    1
                    for member, item in zip(scored.members, scored.baselines)
                    if not member.name.startswith("@")
                    and item.downloads_at_t is not None
                ),
                "unscoped_total": sum(
                    1 for member in scored.members if not member.name.startswith("@")
                ),
                "scoped_measured": sum(
                    1
                    for member, item in zip(scored.members, scored.baselines)
                    if member.name.startswith("@") and item.downloads_at_t is not None
                ),
                "scoped_total": sum(
                    1 for member in scored.members if member.name.startswith("@")
                ),
            },
            "stars_today": sum(
                1 for item in scored.baselines if item.stars_today is not None
            ),
        },
        "model": {
            "signals": sorted(PILOT_SIGNALS),
            "auc": _interval_dict(auc_interval),
            "average_precision": average_precision(model, labels),
            "operating_points": [
                asdict(point)
                for point in operating_points(model, labels, OPERATING_THRESHOLDS)
            ],
            "calibration": [
                asdict(row)
                for row in bucket_rates(scored.buckets["model"], labels, BUCKET_ORDER)
            ],
        },
        "baselines": compare_baselines(scored, replicates, seed),
        "within_download_strata": stratify_by_downloads(scored),
        "ablations": ablations,
        "negative_control": negative_control(scored, control_rounds, seed),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point.

    Args:
        argv: Argument vector, defaulting to ``sys.argv[1:]``.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--replicates", type=int, default=DEFAULT_REPLICATES)
    parser.add_argument("--control-rounds", type=int, default=DEFAULT_CONTROL_ROUNDS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument(
        "--t",
        type=str,
        default=None,
        metavar="YYYY-MM-DD",
        help=(
            "T, as a date. Defaults to the latest candidate whose label "
            "window closes by the harvest. Pass an earlier one to check "
            "whether a result holds across time or only in its own year."
        ),
    )
    parser.add_argument(
        "--years",
        type=int,
        default=None,
        metavar="N",
        help=(
            "N, overriding the life table's selection. A sensitivity "
            "analysis: does the finding survive a different definition of "
            "abandonment? The pre-registered N is kept in the results."
        ),
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    moment: Optional[datetime] = None
    if args.t is not None:
        moment = datetime.strptime(args.t, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    results = run(
        snapshot_dir=args.snapshot,
        replicates=args.replicates,
        control_rounds=args.control_rounds,
        seed=args.seed,
        moment=moment,
        override_years=args.years,
    )
    with args.out.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
