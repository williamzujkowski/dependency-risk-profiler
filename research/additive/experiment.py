"""Does anything the composite measures add to download count? — the run.

`docs/additive-value-protocol.md`, including the §9 amendment that made the
**component** model the primary arm. Offline: the pinned snapshot, the
production scorer, and a three-parameter logistic fit.

Four arms, all evaluated out of fold on the same rows:

- `downloads` — `-log1p(downloads at T)`, negated so that higher means more
  risk like every other predictor here. The incumbent, and a free one.
- `composite` — the frozen-weight ablated score, as shipped.
- `composite+downloads` — the aggregate combined with downloads.
- `components+downloads` — **the primary**: the three ablated signals as
  separate features beside downloads. This is the reweighting question asked
  directly, because a fixed-weight sum can cancel what its components carry.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from math import log1p
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import build_cohort, maintainer_clusters
from abandonment_pilot.features import PILOT_SIGNALS, build_metadata
from abandonment_pilot.snapshot import load_snapshot
from abandonment_pilot.stats import paired_auc_delta, roc_auc
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

from .logistic import fit

SEED = 20260812
FOLDS = 5
REPLICATES = 2000

#: §6 line 1: the operational floor an improvement must clear to matter, on
#: top of an interval that excludes zero.
MATERIAL_DELTA = 0.02


def _signal_features(result: object) -> List[float]:
    """The three ablated signals as separate features.

    Unmeasured reads as 0.0 here, which is a modelling choice rather than a
    measurement: the scorer excludes an unmeasured signal from its own average,
    but a regression needs a number in every cell. Recorded because it is the
    one place this harness departs from the scorer's treatment of missingness.
    """
    out: List[float] = []
    for name in ("maintainer_score", "license_score", "source_repository_score"):
        value = getattr(result, name, None)
        out.append(0.0 if value is None else float(value))
    return out


def _folds(clusters: Sequence[int], folds: int) -> List[int]:
    """Assign each row a fold via its maintainer component, never via its row."""
    unique = sorted(set(clusters))
    rng = random.Random(SEED)
    shuffled = unique[:]
    rng.shuffle(shuffled)
    assignment = {cluster: i % folds for i, cluster in enumerate(shuffled)}
    return [assignment[c] for c in clusters]


def _out_of_fold(
    columns: Sequence[Sequence[float]],
    labels: Sequence[bool],
    fold_of: Sequence[int],
) -> Optional[Tuple[List[float], List[List[float]]]]:
    """Predictions each produced by a model that never saw the row.

    Returns the predictions and the per-fold coefficient vectors, because §6
    line 3 reads the sign of the composite's coefficient across folds and a
    sign that flips is fitting the fold rather than the data.
    """
    predictions = [0.0] * len(labels)
    coefficients: List[List[float]] = []
    for fold in range(FOLDS):
        train = [i for i in range(len(labels)) if fold_of[i] != fold]
        test = [i for i in range(len(labels)) if fold_of[i] == fold]
        if not test or len(train) < 20:
            return None
        model = fit(
            [[column[i] for i in train] for column in columns],
            [labels[i] for i in train],
        )
        if model is None:
            return None
        coefficients.append(model.beta)
        held = model.predict([[column[i] for i in test] for column in columns])
        for position, index in enumerate(test):
            predictions[index] = held[position]
    return predictions, coefficients


def run(snapshot_dir: Path, t: str, years: int) -> Dict[str, object]:
    moment = datetime.fromisoformat(t).replace(tzinfo=timezone.utc)
    snapshot = load_snapshot(snapshot_dir)
    members, _ = build_cohort(snapshot.packages, moment, years, snapshot.harvested_at)
    records = {record.name: record for record in snapshot.packages}
    clusters_all = maintainer_clusters(members)
    downloads = snapshot.downloads.get(moment.date().isoformat()) or {}
    scorer = RiskScorer()

    composite: List[float] = []
    components: List[List[float]] = []
    logdl: List[float] = []
    labels: List[bool] = []
    clusters: List[int] = []

    for position, member in enumerate(members):
        count = downloads.get(member.name)
        if count is None:
            continue
        result = scorer.score_dependency(
            build_metadata(records[member.name], member, enabled=PILOT_SIGNALS)
        )
        composite.append(result.total_score / scorer.max_score)
        components.append(_signal_features(result))
        # NEGATED, and this is not cosmetic. Every predictor here is oriented
        # as RISK -- higher means more likely to be abandoned -- and downloads
        # run the other way. Unnegated, the baseline scored AUC 0.3040, which
        # is exactly 1 - 0.696, and the composite appeared to beat it by
        # +0.28. A sign error in the comparator is how a study manufactures a
        # spectacular positive out of the one number it was supposed to lose
        # to.
        logdl.append(-log1p(float(count)))
        labels.append(bool(member.abandoned))
        clusters.append(clusters_all[position])

    fold_of = _folds(clusters, FOLDS)
    component_columns = [[row[i] for row in components] for i in range(3)]

    arms: Dict[str, object] = {}
    scores: Dict[str, List[float]] = {
        "downloads": logdl,
        "composite": composite,
    }
    for name, columns in (
        ("composite+downloads", [composite, logdl]),
        ("components+downloads", component_columns + [logdl]),
    ):
        fitted = _out_of_fold(columns, labels, fold_of)
        if fitted is None:
            arms[name] = {"error": "fit failed"}
            continue
        predictions, coefficients = fitted
        scores[name] = predictions
        arms[name] = {
            "coefficients_per_fold": coefficients,
            "signs_stable": all(
                all((c[i] > 0) == (coefficients[0][i] > 0) for c in coefficients)
                for i in range(1, len(coefficients[0]))
            ),
        }

    aucs = {name: roc_auc(values, labels) for name, values in scores.items()}
    deltas: Dict[str, object] = {}
    for name in ("composite", "composite+downloads", "components+downloads"):
        if name not in scores:
            continue
        delta = paired_auc_delta(
            scores[name], scores["downloads"], labels, clusters, REPLICATES, SEED
        )
        low = delta.clustered.low
        high = delta.clustered.high
        if low is None or high is None:
            deltas[name] = {"error": "no clustered interval"}
            continue
        observed = delta.delta if delta.delta is not None else 0.0
        if low > 0 and observed >= MATERIAL_DELTA:
            verdict = "additive"
        elif high < MATERIAL_DELTA:
            verdict = "absent"
        else:
            verdict = "indeterminate"
        deltas[name] = {
            "delta_vs_downloads": observed,
            "ci95": [low, high],
            "verdict": verdict,
            "minimum_detectable_delta": (high - low) / 2.0,
            "p_value": delta.p_value,
        }

    return {
        "protocol": "docs/additive-value-protocol.md (amended, §9)",
        "t": t,
        "seed": SEED,
        "population": "packages npm answered a download count for",
        "n": len(labels),
        "cohort": len(members),
        "abandoned": sum(labels),
        "primary_arm": "components+downloads",
        "auc": aucs,
        "arms": arms,
        "deltas": deltas,
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
    print(json.dumps({k: v for k, v in result.items() if k != "arms"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
