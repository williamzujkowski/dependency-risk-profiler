"""Isolate what the repository block does, by scoring the same packages twice.

Offline. No network: the frozen #385 cohort holds every registry input, and the
registry-only arm simply never calls ``analyze_repository``.

**Why this exists.** The composition study reported registry-only rank-R² of
0.6076 against a pre-registered 0.90 threshold and read "does not fire" as
evidence the repository block is not decorative. A review rejected that, and
the rejection is right: the registry-only score is roughly 85% tied inside the
modal maintainer band, and rank-R² between a heavily-tied score and *any*
tie-broken refinement of it is mechanically depressed by the tie mass alone.
0.6076 is therefore consistent with the block contributing nothing. The
threshold was set without computing that null, which is the same defect this
project already recorded twice: measure the control first.

Rather than simulate a null, this measures the block directly. Each package is
scored twice — once as the harvest scored it, once with the repository block
suppressed — so the block's contribution is a difference rather than an
inference. Three questions follow, and only the last two matter to a user:

1. **Magnitude.** How far does the block move the score?
2. **Reordering.** Does it change the *order*, or shift everything together?
   A monotone shift adds no information at all.
3. **Decisions.** Does it change the verdict band the tool actually shows? A
   score that moves without changing what a user is told is invisible.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from abandonment_pilot.stats import _ranks  # noqa: E402

logger = logging.getLogger(__name__)


def kendall_tau(a: Sequence[float], b: Sequence[float]) -> float:
    """Kendall's tau-b over ranks. O(n²), which is fine at n≈1000."""
    n = len(a)
    concordant = discordant = tied_a = tied_b = 0
    for i in range(n):
        for j in range(i + 1, n):
            da, db = a[i] - a[j], b[i] - b[j]
            if da == 0 and db == 0:
                continue
            if da == 0:
                tied_a += 1
            elif db == 0:
                tied_b += 1
            elif (da > 0) == (db > 0):
                concordant += 1
            else:
                discordant += 1
    denominator = (
        (concordant + discordant + tied_a) * (concordant + discordant + tied_b)
    ) ** 0.5
    return (concordant - discordant) / denominator if denominator else 0.0


def rescore_without_block(row: dict, cohort_row: dict, t: datetime) -> Tuple[float, str]:
    """Score one package as if its repository had never been read."""
    from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

    from prospective.score_at_t import build_dependency

    dependency = build_dependency(cohort_row, t)
    scored = RiskScorer().score_dependency(dependency, as_of=t)
    return (
        float(scored.total_score),
        str(scored.risk_level).replace("RiskLevel.", ""),
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--record", type=Path, required=True)
    ap.add_argument("--cohort", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("dependency_risk_profiler").setLevel(logging.ERROR)

    record = json.loads(args.record.read_text())
    t = datetime.fromisoformat(record["scored_at"])
    cohort = {row["name"]: row for row in json.loads(args.cohort.read_text())}

    with_block = [
        r for r in record["packages"] if r["full_instrument"] and r["composite"] is not None
    ]

    rows = []
    for row in with_block:
        cohort_row = cohort.get(row["name"])
        if cohort_row is None:
            continue
        without, band_without = rescore_without_block(row, cohort_row, t)
        rows.append(
            {
                "name": row["name"],
                "with_block": row["composite"],
                "without_block": without,
                "delta": row["composite"] - without,
                "band_with": row["risk_level"].replace("RiskLevel.", ""),
                "band_without": band_without,
            }
        )

    deltas = sorted(r["delta"] for r in rows)
    moved = [r for r in rows if abs(r["delta"]) > 1e-9]
    flipped = [r for r in rows if r["band_with"] != r["band_without"]]

    tau = kendall_tau(
        _ranks([r["with_block"] for r in rows]),
        _ranks([r["without_block"] for r in rows]),
    )

    transitions: Dict[str, int] = {}
    for row in flipped:
        key = f"{row['band_without']} -> {row['band_with']}"
        transitions[key] = transitions.get(key, 0) + 1

    result = {
        "n": len(rows),
        "moved_at_all": len(moved),
        "moved_share": len(moved) / len(rows) if rows else 0.0,
        "delta_min": deltas[0] if deltas else None,
        "delta_median": deltas[len(deltas) // 2] if deltas else None,
        "delta_max": deltas[-1] if deltas else None,
        # A monotone shift would leave tau at 1.0 and carry no information.
        "kendall_tau_with_vs_without": tau,
        # The only figure a user experiences.
        "verdict_band_changed": len(flipped),
        "verdict_band_changed_share": len(flipped) / len(rows) if rows else 0.0,
        "band_transitions": dict(sorted(transitions.items(), key=lambda kv: -kv[1])),
    }
    text = json.dumps(result, indent=1, default=str)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
