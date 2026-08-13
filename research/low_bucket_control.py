"""Does download count's bottom bucket beat the tool's LOW bucket? Offline.

The control that #382's synthesis was missing. Its draft claimed *"it can tell
you a package is probably fine"* on the strength of LOW sitting below the base
rate in 7 of 7 runs — without ever asking whether the free baseline does the
same thing better. This project's standing rule is to measure the control
first; that rule is what killed the provenance signal, and the synthesis broke
it in the one sentence a reader would quote.

Same pinned snapshot, same cohort construction, same two-year window as the
abandonment pilot. "Bottom bucket" for a risk reading is the *safest* quartile:
for the tool that is LOW, for download count it is the most-downloaded quarter.

Lower is safer. The answer is that download count wins in all three runs.
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from abandonment_pilot.cohort import build_cohort  # noqa: E402
from abandonment_pilot.snapshot import load_snapshot  # noqa: E402

logger = logging.getLogger(__name__)

#: The tool's LOW-bucket lift, read from #344's published table (N=2 runs).
TOOL_LOW_LIFT = {"2022-08-01": 0.63, "2023-08-01": 0.66, "2024-08-01": 0.68}

WINDOW_YEARS = 2


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--snapshot", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    snapshot = load_snapshot(args.snapshot)
    with gzip.open(args.snapshot / "downloads.json.gz", "rt") as handle:
        downloads = json.load(handle)

    rows = []
    for t in sorted(TOOL_LOW_LIFT):
        moment = datetime.fromisoformat(t).replace(tzinfo=timezone.utc)
        members, _ = build_cohort(
            snapshot.packages, moment, WINDOW_YEARS, snapshot.harvested_at
        )
        at_t = downloads.get(t, {})
        paired = [
            (at_t[m.name], m.abandoned) for m in members if at_t.get(m.name) is not None
        ]
        if len(paired) < 100:
            logger.warning("%s: only %d packages carry downloads", t, len(paired))
            continue

        paired.sort(key=lambda pair: -pair[0])
        base = sum(1 for _, abandoned in paired if abandoned) / len(paired)
        quartile = paired[: len(paired) // 4]
        rate = sum(1 for _, abandoned in quartile if abandoned) / len(quartile)
        rows.append(
            {
                "t": t,
                "n": len(paired),
                "base_rate": base,
                "downloads_safest_quartile": rate,
                "downloads_lift": rate / base,
                "tool_low_lift": TOOL_LOW_LIFT[t],
                # Lower lift is safer, so the baseline wins when its lift is lower.
                "downloads_wins": (rate / base) < TOOL_LOW_LIFT[t],
            }
        )

    for row in rows:
        logger.info(
            "%s  n=%-5d base %.3f  downloads %.3f (%.2fx)  tool LOW %.2fx  -> %s",
            row["t"],
            row["n"],
            row["base_rate"],
            row["downloads_safest_quartile"],
            row["downloads_lift"],
            row["tool_low_lift"],
            "downloads" if row["downloads_wins"] else "tool",
        )

    verdict = {
        "runs": rows,
        "downloads_wins_all_runs": bool(rows) and all(r["downloads_wins"] for r in rows),
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(verdict, indent=1))
    logger.info(
        "\ndownload count's bottom bucket beats the tool's LOW bucket in %d of %d runs",
        sum(1 for r in rows if r["downloads_wins"]),
        len(rows),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
