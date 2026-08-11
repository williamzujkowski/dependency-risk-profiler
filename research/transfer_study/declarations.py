"""Extract the pilot's input from the pinned snapshot: owner/repo at T, only.

The pilot measures a property of GitHub's API, so its input is a list of
repository slugs and nothing else. This module is the boundary that guarantees
it: it imports the cohort machinery, which knows every package's abandonment
label, and writes out a mapping of package name to `[owner, repo]`. No label,
no score, no date crosses it.

**The unit is the repository, not the package.** Monorepos publish many
packages from one repository, and counting each of them would weight the
channel estimate by publishing volume — which is an activity measure, in a
study whose entire difficulty is activity contaminating things through side
doors. One package name is kept per distinct slug, as a label for the row.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set

from abandonment_pilot.cohort import build_cohort
from abandonment_pilot.snapshot import load_snapshot
from repo_arm.resolve import GITHUB, classify


def extract(snapshot_dir: Path, t: str, years: int) -> Dict[str, List[str]]:
    """Return one `owner/repo` pair per distinct repository, by package name."""
    moment = datetime.fromisoformat(t).replace(tzinfo=timezone.utc)
    snapshot = load_snapshot(snapshot_dir)
    members, _ = build_cohort(
        snapshot.packages, moment, years, snapshot.harvested_at
    )
    records = {record.name: record for record in snapshot.packages}
    seen: Dict[str, List[str]] = {}
    slugs: Set[str] = set()
    for declaration in classify(members, records):
        if declaration.category != GITHUB or declaration.slug is None:
            continue
        if declaration.slug in slugs:
            continue
        slugs.add(declaration.slug)
        owner, repo = declaration.slug.split("/", 1)
        seen[declaration.package] = [owner, repo]
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, type=Path)
    parser.add_argument("--t", default="2024-08-01")
    parser.add_argument("--years", type=int, default=2)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    declarations = extract(args.snapshot, args.t, args.years)
    args.out.write_text(json.dumps(declarations, indent=1, sort_keys=True) + "\n")
    print(f"{len(declarations)} distinct repositories declared at {args.t}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
