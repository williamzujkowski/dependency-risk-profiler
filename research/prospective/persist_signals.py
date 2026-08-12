"""Re-score the frozen cohort from cached clones, persisting every signal.

Discharges the requirement recorded in ``docs/prospective-protocol.md`` §13.1:
*store every scored signal, then run the saturation check before anything
else.* That was deferred because it looked like it needed two thousand fresh
clones; it does not, because the clones are still on disk.

Two things happen here, and the second matters more than the first:

1. **Every per-signal score is written out**, so `saturation_check.py` can see
   the whole instrument rather than the four fields the harvest happened to
   keep. `version` was constant across the entire cohort and the record could
   not show it.
2. **The composite is checked against the frozen record, package by package.**
   A record nobody can reproduce is a record nobody can audit, and this is the
   only chance to find that out while the inputs still exist. ``as_of`` is
   pinned to the original ``scored_at`` — without it every ``staleness`` would
   drift by however long ago the harvest ran, and the comparison would fail for
   a reason that has nothing to do with reproducibility.

Nothing here re-clones, re-samples or re-weights. The cohort hash is over
package names and is unchanged; this only adds columns to what was already
measured.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

logger = logging.getLogger(__name__)

#: Every scored signal the composite reads, by the attribute the score object
#: exposes. Named explicitly rather than discovered, so a signal that stops
#: being emitted shows up as a missing key instead of silently vanishing.
SIGNAL_FIELDS = [
    "staleness_score",
    "maintainer_score",
    "deprecation_score",
    "exploit_score",
    "version_score",
    "health_indicators_score",
    "license_score",
    "community_score",
    "transitive_score",
    "source_repository_score",
    "security_policy_score",
    "dependency_update_score",
    "maintained_score",
]

#: Tolerance for the reproducibility check. The arithmetic is deterministic, so
#: anything above float noise is a real disagreement, not rounding.
TOLERANCE = 1e-9


def clone_path(root: Path, slug: Optional[str]) -> Optional[Path]:
    if not slug:
        return None
    candidate = root / slug.replace("/", "__")
    return candidate if candidate.is_dir() else None


def score_one(cohort_row: dict, root: Path, t: datetime) -> dict:
    from dependency_risk_profiler.analysis_helpers import analyze_repository
    from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

    from prospective.score_at_t import build_dependency

    dependency = build_dependency(cohort_row, t)
    cached = clone_path(root, cohort_row.get("repo_slug"))
    used_clone = False
    if cached is not None:
        try:
            dependency = analyze_repository(dependency, str(cached))
            used_clone = True
        except Exception as exc:  # pragma: no cover - a hostile tree is real
            logger.warning("analyze_repository failed for %s: %s", cohort_row["name"], exc)

    scored = RiskScorer().score_dependency(dependency, as_of=t)
    row: Dict[str, object] = {
        "name": cohort_row["name"],
        "used_clone": used_clone,
        "composite": scored.total_score,
    }
    for field in SIGNAL_FIELDS:
        row[field] = getattr(scored, field, None)
    return row


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--record", type=Path, required=True)
    ap.add_argument("--cohort", type=Path, required=True)
    ap.add_argument("--clone-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("dependency_risk_profiler").setLevel(logging.ERROR)

    from concurrent.futures import ThreadPoolExecutor

    record = json.loads(args.record.read_text())
    t = datetime.fromisoformat(record["scored_at"])
    cohort = json.loads(args.cohort.read_text())
    frozen = {r["name"]: r for r in record["packages"]}

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        rows = list(executor.map(lambda r: score_one(r, args.clone_root, t), cohort))

    mismatches = []
    for row in rows:
        original = frozen.get(row["name"])
        if original is None or original["composite"] is None:
            continue
        if row["composite"] is None or abs(row["composite"] - original["composite"]) > TOLERANCE:
            mismatches.append(
                {
                    "name": row["name"],
                    "frozen": original["composite"],
                    "reproduced": row["composite"],
                    "used_clone": row["used_clone"],
                    "frozen_full_instrument": original["full_instrument"],
                }
            )

    payload = {
        "scored_at": record["scored_at"],
        "cohort_sha256": record["cohort_sha256"],
        "n": len(rows),
        "used_clone": sum(1 for r in rows if r["used_clone"]),
        "reproduced_exactly": len(rows) - len(mismatches),
        "mismatches": mismatches[:50],
        "mismatch_count": len(mismatches),
        "packages": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1, default=str))
    logger.info(
        "%d/%d composites reproduced exactly (%d used a cached clone)",
        payload["reproduced_exactly"],
        len(rows),
        payload["used_clone"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
