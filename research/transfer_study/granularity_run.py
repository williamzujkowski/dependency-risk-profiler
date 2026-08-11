"""The granularity counterfactual, in the amended order.

`docs/granularity-protocol.md` §6. Offline replay of the existing harvest at
three maintainer resolutions. No new fetch.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from abandonment_pilot.cohort import build_cohort
from abandonment_pilot.snapshot import load_snapshot

from .band_crossing import build_movements
from .granularity import (
    ARMS,
    arm,
    difference_verdict,
    marginal_events,
    swap_fraction,
    wilson,
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--harvest", required=True, type=Path)
    parser.add_argument("--t", default="2024-08-01")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    moment = datetime.fromisoformat(args.t).replace(tzinfo=timezone.utc)
    snapshot = load_snapshot(args.snapshot)
    members, _ = build_cohort(snapshot.packages, moment, 2, snapshot.harvested_at)
    records = {r.name: r for r in snapshot.packages}
    baselines: Dict[str, Tuple[datetime, Tuple[str, ...], bool]] = {
        m.name: (
            records[m.name].releases[m.index_at_t][1],
            tuple(sorted(m.maintainers)),
            m.index_at_t < len(records[m.name].releases) - 1,
        )
        for m in members
    }
    harvested = json.loads(args.harvest.read_text())
    movements = build_movements(harvested, baselines, snapshot.harvested_at)
    quiet = [m for m in movements if not m.published_after_t]

    arms: Dict[str, Dict[str, Any]] = {
        name: arm(quiet, bucket) for name, bucket in ARMS.items()
    }
    for name, summary in arms.items():
        summary["risk_increasing_ci95"] = wilson(
            int(summary.get("risk_increasing", 0) or 0),
            int(summary.get("moved", 0) or 0),
        )

    marginal: Dict[str, Any] = {}
    shipped = arms["shipped"]
    for name in ("fine", "continuous"):
        events = marginal_events(quiet, ARMS[name])
        increasing = sum(
            1 for m in events if len(m.current_set) < len(m.baseline_set)
        )
        share = (increasing / len(events)) if events else None
        marginal[name] = {
            "events": len(events),
            "risk_increasing": increasing,
            "risk_decreasing": len(events) - increasing,
            "risk_increasing_share": share,
            "risk_increasing_ci95": wilson(increasing, len(events)),
            "vs_shipped": difference_verdict(
                shipped.get("risk_increasing_share"),
                int(shipped.get("moved", 0) or 0),
                share,
                len(events),
            ),
        }

    result = {
        "protocol": "docs/granularity-protocol.md (amended, §6)",
        "t": args.t,
        "subset": "quiet packages (no publish after T)",
        "primary_contrast": "marginal events -- what the finer arm sees and shipped does not",
        "arms": arms,
        "marginal": marginal,
        "swaps": swap_fraction(quiet),
        "note": (
            "This study can rule the granularity fix IN. It cannot rule it "
            "out: a per-package-correct signal is aggregate-balanced by "
            "nature, so a balanced split is not evidence of uninformativeness."
        ),
    }
    args.out.write_text(json.dumps(result, indent=2, default=str) + "\n")
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
