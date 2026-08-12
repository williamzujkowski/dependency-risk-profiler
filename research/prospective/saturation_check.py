"""Print every scored signal's distinct-value count on a frozen record.

**Run this first, on any frozen record, before computing anything.**

Three studies were built on cohorts where a signal was constant, and each time
it was found late and by accident. The retrospective studies had `staleness` at
1.0 and `version` at 0.0 for every package; that made their composite a
three-signal object and was discovered only when the composition study went
looking. The prospective study was designed to escape exactly that — and
shipped with `version` constant anyway, arriving by a different route (a
package has no "installed version", so drift is undefined for it), found only
while tracing why 701 packages scored 2.5000.

A constant signal is indistinguishable from a working one at every level above
the raw values. It clears the sufficiency bar, it contributes weight, it
appears in the catalogue, and it moves nothing. The only thing that separates
it from a measurement is counting how many values it takes.

So: one function, run before analysis, that makes the question unavoidable.

**Its reach is limited by what the record stores, and that limit is the reason
`version` hid.** ``scored-at-T.json`` keeps the composite, the ablated
composite and the inputs needed to re-derive them — not the thirteen per-signal
scores. Run against it, this reports no constant fields, which is true of the
fields present and says nothing about `version`, `deprecation` or the six
repository signals. Those were caught only by reproducing the production scorer
over cohort rows.

A future harvest should persist every per-signal score and run this on it.
Doing that to the #385 record now would mean re-cloning two thousand
repositories, so the limitation is recorded instead — and the check is written
to fail loudly on whatever it *can* see rather than to imply coverage it does
not have.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

#: Below this, a signal cannot order a cohort and should be treated as absent
#: from the instrument rather than present in it.
DEGENERATE_AT_OR_BELOW = 1


def distinct_counts(rows: List[dict], fields: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for field in fields:
        values = {
            json.dumps(row.get(field), default=str)
            for row in rows
            if field in row
        }
        if values:
            out[field] = len(values)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--record", type=Path, required=True)
    ap.add_argument(
        "--fields",
        nargs="*",
        help="signal fields to check; defaults to every numeric field present",
    )
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    rows = json.loads(args.record.read_text())["packages"]
    if not rows:
        raise SystemExit("no packages in record")

    fields = args.fields or sorted(
        name
        for name, value in rows[0].items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    )
    counts = distinct_counts(rows, fields)

    degenerate = sorted(
        name for name, count in counts.items() if count <= DEGENERATE_AT_OR_BELOW
    )
    for name, count in sorted(counts.items(), key=lambda kv: kv[1]):
        marker = "  <-- CONSTANT" if count <= DEGENERATE_AT_OR_BELOW else ""
        logger.info("%-26s %6d distinct%s", name, count, marker)

    if degenerate:
        logger.error(
            "\n%d field(s) take a single value across %d packages: %s\n"
            "A constant cannot order anything. Treat it as absent from the "
            "instrument, and say so wherever the instrument is described.",
            len(degenerate),
            len(rows),
            ", ".join(degenerate),
        )
        return 1

    logger.info("\nno constant fields across %d packages", len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
