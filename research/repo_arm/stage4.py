"""Stage 4: run the negative control on the assembled arm, before any model result.

This runner scores the arm through the shipped ``RiskScorer`` and hands the
score vector to the two controls. It never computes the AUC of that vector
against the true labels: §9 puts the control at stage 4 and the model at stage
6 precisely so the control cannot be read in the light of the result, and
computing the result early and withholding it would defeat the ordering while
appearing to honour it.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import build_cohort, maintainer_clusters
from abandonment_pilot.snapshot import PackageRecord, load_snapshot
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import MeasurementState

from .arm import build_arm_metadata
from .control import BAND, ROUNDS, download_bins, global_permutation, within_bin_permutation
from .signals_at_t import RepoSignals


def _load_signals(path: Path) -> Dict[str, RepoSignals]:
    """Read stage 3's reconstruction back into records.

    Args:
        path: ``signals.json``.

    Returns:
        Signals per slug.
    """
    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    return {
        slug: RepoSignals(
            slug=slug,
            head_at_t=value["head_at_t"],
            has_tests=value["has_tests"],
            has_ci=value["has_ci"],
            has_contribution_guidelines=value["has_contribution_guidelines"],
            has_security_policy=value["has_security_policy"],
            has_dependency_update_tools=value["has_dependency_update_tools"],
            commit_frequency=value["commit_frequency"],
            is_maintained=value["is_maintained"],
            error=value["error"],
        )
        for slug, value in raw.items()
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run stage 4.

    Args:
        argv: Command line, for tests.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--T", dest="moment", default="2024-08-01")
    args = parser.parse_args(argv)

    moment = datetime.fromisoformat(args.moment).replace(tzinfo=timezone.utc)
    snapshot = load_snapshot(args.snapshot)
    members, _ = build_cohort(snapshot.packages, moment, 2, snapshot.harvested_at)
    records: Dict[str, PackageRecord] = {r.name: r for r in snapshot.packages}
    clusters = maintainer_clusters(members)

    signals = _load_signals(args.data / "signals.json")
    with (args.data / "declarations.json").open(encoding="utf-8") as handle:
        declarations = {d["package"]: d for d in json.load(handle)}
    downloads_table = snapshot.downloads.get(moment.date().isoformat(), {})

    # The arm is the packages with a readable repository: the population every
    # figure from here is conditional on, per §6.
    scorer = RiskScorer()
    scores: List[float] = []
    labels: List[bool] = []
    arm_clusters: List[int] = []
    arm_downloads: List[Optional[int]] = []
    measured_counts: Dict[str, int] = {}
    for member, cluster in zip(members, clusters):
        slug = declarations[member.name]["slug"]
        record = signals.get(slug) if isinstance(slug, str) else None
        if record is None or record.error is not None:
            continue
        result = scorer.score_dependency(
            build_arm_metadata(records[member.name], member, record)
        )
        scores.append(result.total_score / scorer.max_score)
        labels.append(member.abandoned)
        arm_clusters.append(cluster)
        arm_downloads.append(downloads_table.get(member.name))
        for name, measurement in result.measurements.items():
            if measurement.state is MeasurementState.MEASURED:
                measured_counts[name] = measured_counts.get(name, 0) + 1

    bins = download_bins(arm_downloads)
    binned = [index for indices in bins for index in indices]
    primary = within_bin_permutation(scores, labels, bins)
    secondary = global_permutation(scores, labels)

    report: Dict[str, object] = {
        "arm": {
            "nominal_n": len(scores),
            "abandoned": sum(1 for label in labels if label),
            "base_rate": sum(1 for label in labels if label) / len(labels),
            "maintainer_clusters": len(set(arm_clusters)),
            "largest_cluster": max(
                arm_clusters.count(cluster) for cluster in set(arm_clusters)
            ),
            "signals_measured": measured_counts,
        },
        "download_support": {
            "nominal_n": len(binned),
            "abandoned": sum(1 for index in binned if labels[index]),
            "maintainer_clusters": len({arm_clusters[index] for index in binned}),
            "bins": [
                {
                    "bin": position + 1,
                    "n": len(indices),
                    "abandoned": sum(1 for index in indices if labels[index]),
                    "base_rate": sum(1 for index in indices if labels[index])
                    / len(indices),
                    "downloads_at_t": [
                        min(arm_downloads[index] or 0 for index in indices),
                        max(arm_downloads[index] or 0 for index in indices),
                    ],
                    "clusters": len({arm_clusters[index] for index in indices}),
                }
                for position, indices in enumerate(bins)
            ],
        },
        "primary_control_within_download_bin": {
            "statistic": "unweighted mean of the five within-bin AUCs",
            "rounds": primary.rounds,
            "mean": primary.mean,
            "min": primary.minimum,
            "max": primary.maximum,
            "label_preservation": primary.label_preservation,
            "band": list(BAND),
            "passed": primary.passes(),
        },
        "secondary_control_global": {
            "statistic": "pooled AUC over the arm",
            "rounds": secondary.rounds,
            "mean": secondary.mean,
            "min": secondary.minimum,
            "max": secondary.maximum,
            "band": list(BAND),
            "passed": secondary.passes(),
        },
        "note": (
            "No observed AUC is computed anywhere in this run. Stages 5-7 are "
            "not executed."
        ),
    }
    with (args.data / "stage4.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1, sort_keys=True)
    print(json.dumps(report, indent=1, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
