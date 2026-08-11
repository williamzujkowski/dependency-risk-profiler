"""Price the attacker moves the published lookup table makes available.

`docs/manipulation-protocol.md`. Reads the enumerated table and its occupancy
from `research/results/lookup-table-2024.json`; opens nothing, fetches nothing.

    PYTHONPATH=research uv run python -m composition.price_manipulation
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from composition.manipulation import price_cohort

#: The scorer's maintainer sub-score maps onto the published band labels.
BAND_OF_SUBSCORE = {0.0: "5+", 0.25: "3-4", 0.5: "2", 1.0: "0-1"}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--table", type=Path, default=Path("research/results/lookup-table-2024.json")
    )
    parser.add_argument(
        "--out", type=Path, default=Path("research/results/manipulation-2024.json")
    )
    args = parser.parse_args(argv)

    table = json.loads(args.table.read_text())
    occupancy: Counter = Counter()
    for row in table["table"]:
        band = BAND_OF_SUBSCORE[row["inputs"]["maintainer_band"]]
        occupancy[(band, row["inputs"]["repository_state"])] += row["packages"]

    result = price_cohort(dict(occupancy))
    result["source"] = "docs/lookup-table-result.md, enumerated exhaustively"
    args.out.write_text(json.dumps(result, indent=2) + "\n")

    print(f"packages {result['packages']}")
    print(f"movable at all:              {result['movable_share']:.4f}")
    print(f"movable WITHOUT a publish:   {result['movable_without_publish_share']:.4f}")
    cells: List[Dict[str, Any]] = result["cells"]  # type: ignore[assignment]
    for row in cells[:5]:
        best = row["best_move"]
        if best is None:
            print(f"  {row['cell']} score={row['score']:.4f} n={row['packages']} -- already floor")
            continue
        print(
            f"  {row['cell']} score={row['score']:.4f} n={row['packages']:4d}"
            f" -> drop {best['drop']:.4f}"
            f" ({best['accounts_needed']} accounts, publish={best['requires_publish']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
