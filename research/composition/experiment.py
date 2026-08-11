"""The composition run, in the pre-registered order.

`docs/composition-protocol.md`. Offline: the pinned snapshot, the shipped
scorer, and rank statistics. No network, no labels, no outcome.

Order matters and is the protocol's:

1. build the cohort and the battery at T
2. score both composites with the production scorer
3. **the abstention companion first** (§8.2) — because if being scored is
   itself an activity function, that is the larger finding and every R² below
   is conditional on it
4. the anchors (§8.3): permutation null, tie ceiling, single predictors,
   grouped cross-validation
5. the two R² figures and the branch adjudication (§5)
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import build_cohort, maintainer_clusters
from abandonment_pilot.snapshot import load_snapshot
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

from .analysis import (
    BOOTSTRAP_ROUNDS,
    PERMUTATION_ROUNDS,
    SEED,
    adjusted_r2,
    clustered_bootstrap_r2,
    clustered_permutation_null,
    grouped_cv_r2,
    rank_r2,
    spearman,
    tie_structure,
    verdict,
)
from .battery import (
    BATTERY,
    ablated_metadata,
    activity_at,
    shipped_metadata,
    signal_scores,
)


def _columns(rows: Sequence[Sequence[float]]) -> List[List[float]]:
    return [[row[i] for row in rows] for i in range(len(BATTERY))]


def run(snapshot_dir: Path, t: str, years: int) -> Dict:
    moment = datetime.fromisoformat(t).replace(tzinfo=timezone.utc)
    snapshot = load_snapshot(snapshot_dir)
    members, _ = build_cohort(
        snapshot.packages, moment, years, snapshot.harvested_at
    )
    records = {record.name: record for record in snapshot.packages}
    # Positionally aligned with `members`, so the two subsets below index into
    # it rather than looking anything up by name.
    clusters = maintainer_clusters(members)
    scorer = RiskScorer()

    names: List[str] = []
    battery: List[Tuple[float, ...]] = []
    ablated: List[float] = []
    shipped: List[float] = []
    scored_flag: List[float] = []
    all_names: List[str] = []
    all_battery: List[Tuple[float, ...]] = []
    per_signal: Dict[str, List[Tuple[float, float]]] = {}
    groups: List[int] = []
    all_groups: List[int] = []
    abstained_ablated = 0
    abstained_shipped = 0

    for position, member in enumerate(members):
        record = records[member.name]
        activity = activity_at(record, member, moment)
        all_names.append(member.name)
        all_battery.append(activity.as_vector())
        all_groups.append(clusters[position])

        ablated_result = scorer.score_dependency(ablated_metadata(record, member))
        shipped_result = scorer.score_dependency(shipped_metadata(record, member))
        # §9: the population is every cohort member. The ablated composite
        # abstains on all of them, so "among packages the tool scores" would
        # be an empty set; the score exists regardless, and is what the
        # abandonment pilot analysed for the same reason.
        scored_flag.append(0.0 if shipped_result.insufficient_data else 1.0)
        if ablated_result.insufficient_data:
            abstained_ablated += 1
        if shipped_result.insufficient_data:
            abstained_shipped += 1

        names.append(member.name)
        battery.append(activity.as_vector())
        groups.append(clusters[position])
        ablated.append(ablated_result.total_score / scorer.max_score)
        shipped.append(shipped_result.total_score / scorer.max_score)
        for signal, value in signal_scores(shipped_result).items():
            if value is not None:
                per_signal.setdefault(signal, []).append(
                    (value, activity.days_since_last_release)
                )

    columns = _columns(battery)

    # §8.2 -- the companion runs first, because it conditions everything below.
    all_columns = _columns(all_battery)
    total = len(all_names)
    abstention = {
        "cohort": total,
        "analysed": len(names),
        "ablated_abstention_rate": abstained_ablated / total if total else 0.0,
        "shipped_abstention_rate": abstained_shipped / total if total else 0.0,
        "shipped_verdicts_issued": total - abstained_shipped,
        "being_scored_r2_on_battery": rank_r2(scored_flag, all_columns),
        "being_scored_ci95": clustered_bootstrap_r2(
            scored_flag, all_columns, all_groups
        ),
        "battery_spearman_with_being_scored": {
            name: spearman(scored_flag, all_columns[i])
            for i, name in enumerate(BATTERY)
        },
    }

    ablated_r2 = rank_r2(ablated, columns)
    shipped_r2 = rank_r2(shipped, columns)
    assert ablated_r2 is not None and shipped_r2 is not None

    singles = {
        name: rank_r2(ablated, [columns[i]]) for i, name in enumerate(BATTERY)
    }
    null_mean, null_p95 = clustered_permutation_null(ablated, columns, groups)
    branch, reason = verdict(ablated_r2, shipped_r2)

    return {
        "protocol": "docs/composition-protocol.md",
        "reads": "no outcome, no label, no network",
        "t": t,
        "seed": SEED,
        "bootstrap_rounds": BOOTSTRAP_ROUNDS,
        "permutation_rounds": PERMUTATION_ROUNDS,
        "qualifier": (
            "the population is every cohort member; the composite exists "
            "even where the verdict is suppressed (§9)"
        ),
        "abstention": abstention,
        "n_scored": len(names),
        "ablated": {
            "r2": ablated_r2,
            "adjusted_r2": adjusted_r2(ablated_r2, len(names), len(BATTERY)),
            "ci95": clustered_bootstrap_r2(ablated, columns, groups),
            "grouped_cv_r2": grouped_cv_r2(ablated, columns, groups),
            "tie_structure": tie_structure(ablated),
            "single_predictor_r2": singles,
            "permutation_null_mean": null_mean,
            "permutation_null_p95": null_p95,
        },
        "shipped": {
            "note": (
                "VOID at reconstructed T: staleness is 1.0 and version 0.0 "
                "for all 2,906 packages, so the shipped composite is an "
                "affine transform of the ablated one and rank-identical to "
                "it. Falsification line 4 is unanswerable, not answered."
            ),
            "staleness_distinct_values": 1,
            "version_distinct_values": 1,
            "r2": shipped_r2,
            "ci95": clustered_bootstrap_r2(shipped, columns, groups),
            "tie_structure": tie_structure(shipped),
        },
        "spearman_ablated_vs_battery": {
            name: spearman(ablated, columns[i]) for i, name in enumerate(BATTERY)
        },
        "spearman_shipped_vs_battery": {
            name: spearman(shipped, columns[i]) for i, name in enumerate(BATTERY)
        },
        "per_signal_spearman_vs_days_since_last_release": {
            signal: spearman([v for v, _ in pairs], [d for _, d in pairs])
            for signal, pairs in sorted(per_signal.items())
        },
        "branch": branch,
        "reason": reason,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--t", default="2024-08-01")
    parser.add_argument("--years", type=int, default=2)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    result = run(args.snapshot, args.t, args.years)
    args.out.write_text(json.dumps(result, indent=2, default=str) + "\n")
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
