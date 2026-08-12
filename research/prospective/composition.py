"""Measure what the shipped composite is made of, on the full instrument.

Offline. Reads the frozen #385 record; no network, no outcome.
Protocol: ``docs/full-instrument-composition-protocol.md``, committed first.

The prior composition and lookup-table results ran on a reconstruction where
three signals were constant and six were never computed. This runs on 928
packages whose repository block was actually collected, so it can distinguish
"the composite is a twelve-cell lookup" from "the composite *reconstructed at a
past date* is a twelve-cell lookup".
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from abandonment_pilot.stats import _ranks  # noqa: E402

logger = logging.getLogger(__name__)

#: §3 line 1.
MIN_DISTINCT = 30
#: §3 line 2.
MAX_REGISTRY_ONLY_R2 = 0.90
#: §3 line 3.
MAX_LARGEST_CELL = 0.30
#: §3 line 4.
MIN_SUBSET = 500


def maintainer_band(count: int) -> str:
    """The band the scorer actually uses, derived by bucketing the count.

    The prior enumeration learned this the hard way: using raw counts produced
    149 cells for 11 scores. The bands are what the score reads.
    """
    if count <= 1:
        return "<=1"
    if count == 2:
        return "2"
    if count <= 4:
        return "3-4"
    return ">=5"


def repo_state(row: dict) -> str:
    if not row["full_instrument"]:
        return "declared" if row["clone_reason"] not in ("no_repo_declared",) else "none"
    return "cloned"


def rank_r2(predictors: Sequence[Sequence[float]], target: Sequence[float]) -> float:
    """Rank-R² of ``target`` on ``predictors``, by ordinary least squares.

    Stdlib only, matching the rest of this repo's analysis code: normal
    equations solved by Gauss-Jordan on a small design matrix. Ranks rather
    than raw values because the composite's scale is arbitrary and only its
    ordering is used anywhere.
    """
    y = _ranks(target)
    columns = [_ranks(column) for column in predictors]
    design = [[1.0] + [column[i] for column in columns] for i in range(len(y))]
    width = len(design[0])

    # Normal equations: (X'X) b = X'y
    xtx = [[sum(row[a] * row[b] for row in design) for b in range(width)] for a in range(width)]
    xty = [sum(design[i][a] * y[i] for i in range(len(y))) for a in range(width)]

    augmented = [xtx[i] + [xty[i]] for i in range(width)]
    for column in range(width):
        pivot = max(range(column, width), key=lambda r: abs(augmented[r][column]))
        if abs(augmented[pivot][column]) < 1e-12:
            continue
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        divisor = augmented[column][column]
        augmented[column] = [value / divisor for value in augmented[column]]
        for other in range(width):
            if other == column:
                continue
            factor = augmented[other][column]
            augmented[other] = [
                value - factor * base
                for value, base in zip(augmented[other], augmented[column])
            ]
    beta = [row[width] for row in augmented]

    mean = sum(y) / len(y)
    predicted = [sum(beta[a] * design[i][a] for a in range(width)) for i in range(len(y))]
    ss_res = sum((y[i] - predicted[i]) ** 2 for i in range(len(y)))
    ss_tot = sum((value - mean) ** 2 for value in y)
    return 1.0 - ss_res / ss_tot if ss_tot else 0.0


def cells(rows: Sequence[dict]) -> Dict[Tuple[str, str], List[float]]:
    out: Dict[Tuple[str, str], List[float]] = {}
    for row in rows:
        key = (maintainer_band(row["maintainer_count"]), repo_state(row))
        out.setdefault(key, []).append(row["composite"])
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--record", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    record = json.loads(args.record.read_text())
    everything = [r for r in record["packages"] if r["composite"] is not None]
    full = [r for r in everything if r["full_instrument"]]

    result: Dict[str, object] = {
        "n": len(everything),
        "full_instrument": len(full),
        "distinct_values_all": len({round(r["composite"], 6) for r in everything}),
        "distinct_values_full": len({round(r["composite"], 6) for r in full}),
        # §3 line 4 gates everything else.
        "subset_gate_passes": len(full) >= MIN_SUBSET,
    }

    if len(full) >= MIN_SUBSET:
        # §3 line 2. Registry-only inputs: everything the tool knows without a
        # clone. If these recover the ordering, the clone changes the number
        # and not the order.
        registry_only = [
            [float(r["maintainer_count"]) for r in full],
            [float(r["release_count"]) for r in full],
            [float(r["staleness"] or 0.0) for r in full],
            [float(r["downloads"]) for r in full],
        ]
        registry_r2 = rank_r2(registry_only, [r["composite"] for r in full])
        result["registry_only_rank_r2"] = registry_r2

        # §3 line 3 is evaluated on the WHOLE cohort, not the full-instrument
        # subset. Inside that subset `repo_state` is "cloned" for every row by
        # construction, so one of the enumeration's two axes is constant and
        # the table collapses to four maintainer bands. Scored that way the
        # largest "cell" was 0.849, which measures nothing but the maintainer
        # distribution. Recorded because the first run made exactly that
        # mistake: a cell definition with a constant axis is not a cell.
        occupancy = cells(everything)
        largest = max(len(v) for v in occupancy.values())
        largest_share = largest / len(everything)
        result["cells_occupied"] = len(occupancy)
        result["largest_cell_share"] = largest_share
        # The distinct-score count per cell is the load-bearing column: it is
        # what separates "the composite is a lookup table" from "the composite
        # reconstructed without its repository block is a lookup table".
        result["cell_detail"] = {
            f"{band}|{state}": {
                "n": len(values),
                "distinct_scores": len({round(v, 6) for v in values}),
                "share": len(values) / len(everything),
            }
            for (band, state), values in sorted(
                occupancy.items(), key=lambda item: -len(item[1])
            )
        }

        distinct_full = int(result["distinct_values_full"])  # type: ignore[call-overload]
        result["line_1_lookup_survives"] = distinct_full < MIN_DISTINCT
        # Reported, but see the result document §3: this line's threshold was
        # set without computing its null, and registry-only score is ~85% tied
        # inside the modal band, which depresses rank-R² against ANY tie-broken
        # refinement. The line is uninformative rather than passed, and
        # `block_contribution.py` replaces it with a direct measurement.
        result["line_2_block_is_decorative"] = registry_r2 >= MAX_REGISTRY_ONLY_R2
        result["line_2_is_uninformative"] = True
        result["line_3_enumeration_stands"] = largest_share >= MAX_LARGEST_CELL

    text = json.dumps(result, indent=1, default=str)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
