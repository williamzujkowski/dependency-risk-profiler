"""The band-crossing run, in the order the amended protocol fixes.

`docs/band-crossing-protocol.md` §6. Offline: reads the pinned snapshot and the
one harvest, joins them, and reports rates per subset with the window that
produced each.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

from abandonment_pilot.cohort import build_cohort
from abandonment_pilot.snapshot import load_snapshot

from .band_crossing import (
    RECENT_BASELINE_DAYS,
    build_movements,
    effective_accounts,
    summarise,
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

    baselines: Dict[str, Tuple[datetime, Tuple[str, ...], bool]] = {}
    for member in members:
        record = records[member.name]
        published_at = record.releases[member.index_at_t][1]
        published_after = member.index_at_t < len(record.releases) - 1
        baselines[member.name] = (
            published_at,
            tuple(sorted(member.maintainers)),
            published_after,
        )

    harvested = json.loads(args.harvest.read_text())
    movements = build_movements(harvested, baselines, snapshot.harvested_at)

    quiet = [m for m in movements if not m.published_after_t]
    active = [m for m in movements if m.published_after_t]
    recent = [
        m
        for m in quiet
        if (moment - m.baseline_published).days <= RECENT_BASELINE_DAYS
    ]

    result = {
        "protocol": "docs/band-crossing-protocol.md (amended, §6)",
        "t": args.t,
        "harvested_at": snapshot.harvested_at.isoformat(),
        "resolved": sum(1 for r in harvested if r.get("status") == 200),
        "requested": len(harvested),
        "primary_quantity": "band crossings per package-year",
        "headline_stratum": {
            "definition": (
                "quiet packages whose last pre-T publish is within "
                f"{RECENT_BASELINE_DAYS} days of T, so the baseline is close "
                "to T and the two-year framing is answerable as asked"
            ),
            **summarise(recent),
        },
        "quiet_all": summarise(quiet),
        "active_comparator": summarise(active),
        "whole_cohort": summarise(movements),
        "account_clustering_quiet": effective_accounts(quiet),
    }
    args.out.write_text(json.dumps(result, indent=2, default=str) + "\n")
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
