"""Evaluate the prospective cohort. **Frozen before the harvest runs.**

``docs/prospective-protocol.md`` §8 requires this module to exist and be hashed
before any package is sampled. Pre-registered criteria with unwritten analysis
code is the forking-paths hole that survives twelve months: every judgement
call in here -- which stratum is primary, which arms are compared, how ties and
censored packages are handled -- is a degree of freedom that would otherwise be
resolved after seeing the outcome.

Nothing in this module touches the network. It reads the frozen T-record and an
outcome file and prints the registered comparisons in the registered order.

The four arms (§1):

- ``composite``          the shipped thirteen-signal score
- ``downloads``          the comparator that has beaten it everywhere
- ``staleness``          one of the composite's own inputs, alone
- ``composite_ablated``  composite with ``staleness`` and ``version`` removed

Both ``downloads`` and ``staleness`` must fall for the §1 claim. ``ablated``
attributes a win rather than assuming one.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from abandonment_pilot.stats import PairedDelta, paired_auc_delta, roc_auc

logger = logging.getLogger(__name__)

REPLICATES = 2000
SEED = 20260812

#: §5 line 5. The binding quantity is the minority count, not the base rate --
#: see §2.2 for the measurement that replaced the original base-rate guard.
MIN_MINORITY = 300

#: §5 lines 1 and 2.
DELTA_THRESHOLD = 0.03

#: §5 line 4.
MIN_FULL_INSTRUMENT_YIELD = 0.60

#: §2.1. The claim is made on ``multi_release`` or not at all.
PRIMARY_STRATUM = "multi_release"


@dataclass(frozen=True)
class Row:
    """One package, scored at T and resolved at T+12."""

    name: str
    #: Maintainer-component id, for the clustered bootstrap.
    cluster: int
    #: True when the package published no release in (T, T+12].
    quiet: bool
    #: False when the repository could not be cloned at T (§4.1).
    full_instrument: bool
    #: ``multi_release`` or ``one_shot``, fixed at T.
    stratum: str
    composite: float
    downloads: float
    staleness: float
    composite_ablated: float


def load_rows(path: Path) -> List[Row]:
    """Read the joined record, dropping censored packages.

    Censored packages (§4) carry ``quiet: null`` -- unpublished, transferred to
    the security holder, or no longer resolvable. They are counted and reported
    but cannot enter an AUC, because the outcome is undefined for them rather
    than negative.
    """
    raw = json.loads(path.read_text())
    rows: List[Row] = []
    for rec in raw["packages"]:
        if rec.get("quiet") is None:
            continue
        rows.append(
            Row(
                name=rec["name"],
                cluster=rec["cluster"],
                quiet=bool(rec["quiet"]),
                full_instrument=bool(rec["full_instrument"]),
                stratum=rec["stratum"],
                composite=float(rec["composite"]),
                # Higher downloads should mean *lower* risk, so the comparator
                # is negated to share the composite's orientation. The additive
                # study shipped this unnegated once and the baseline scored
                # exactly 1 - its true AUC, which made a losing arm look like a
                # +0.28 win. It is negated here, in frozen code, for that reason.
                downloads=-float(rec["downloads"]),
                staleness=float(rec["staleness"]),
                composite_ablated=float(rec["composite_ablated"]),
            )
        )
    return rows


def _arm(rows: Sequence[Row], name: str) -> List[float]:
    return [getattr(row, name) for row in rows]


def compare(rows: Sequence[Row], arm: str, against: str) -> PairedDelta:
    return paired_auc_delta(
        _arm(rows, arm),
        _arm(rows, against),
        [row.quiet for row in rows],
        [row.cluster for row in rows],
        REPLICATES,
        SEED,
    )


def stratum_report(rows: Sequence[Row], label: str) -> dict:
    """Every registered number for one stratum."""
    labels = [row.quiet for row in rows]
    positives = sum(labels)
    negatives = len(labels) - positives
    minority = min(positives, negatives)

    report: dict = {
        "stratum": label,
        "n": len(rows),
        "quiet": positives,
        "base_rate": (positives / len(rows)) if rows else None,
        "minority": minority,
        # §5 line 5 is a gate on this stratum's own counts.
        "minority_gate_passes": minority >= MIN_MINORITY,
        "auc": {
            arm: roc_auc(_arm(rows, arm), labels)
            for arm in ("composite", "downloads", "staleness", "composite_ablated")
        },
    }

    if minority < MIN_MINORITY:
        report["deltas"] = None
        report["note"] = (
            f"minority class {minority} < {MIN_MINORITY}; §5 line 5 fires and no "
            "AUC comparison is claimed for this stratum"
        )
        return report

    deltas: Dict[str, dict] = {}
    for arm, against in (
        ("composite", "downloads"),
        ("composite", "staleness"),
        ("composite", "composite_ablated"),
        ("composite_ablated", "downloads"),
    ):
        delta = compare(rows, arm, against)
        deltas[f"{arm}_vs_{against}"] = asdict(delta)
    report["deltas"] = deltas
    return report


def verdict(primary: dict) -> dict:
    """Apply §5 to the primary stratum. No branch is decided at read time."""
    if not primary["minority_gate_passes"]:
        return {"claim": "not made", "reason": "§5 line 5: minority class too small"}

    deltas = primary["deltas"]

    def beats(key: str) -> Optional[bool]:
        delta = deltas[key]
        point = delta["delta"]
        interval = delta["clustered"]
        if point is None or interval.get("low") is None:
            return None
        return point >= DELTA_THRESHOLD and interval["low"] > 0

    over_downloads = beats("composite_vs_downloads")
    over_staleness = beats("composite_vs_staleness")

    if over_staleness is False:
        # §5 line 2 is unconditional: it fires however line 1 resolved.
        return {
            "claim": "not made",
            "headline": (
                "the thirteen-signal instrument is outperformed by one of its own "
                "inputs (staleness alone)"
            ),
            "over_downloads": over_downloads,
            "over_staleness": False,
        }
    if over_downloads is False:
        return {
            "claim": "not made",
            "headline": "§5 line 1: the composite does not beat download count",
            "over_downloads": False,
            "over_staleness": over_staleness,
        }
    if over_downloads and over_staleness:
        return {
            "claim": "made",
            "headline": (
                "the shipped composite predicts twelve-month npm abandonment better "
                "than download count and better than staleness alone, on one cohort "
                "at one T"
            ),
            "scope": "not compromise, not beyond npm",
        }
    return {"claim": "indeterminate", "reason": "an interval was undefined"}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--joined", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    rows = load_rows(args.joined)

    full = [row for row in rows if row.full_instrument]
    yield_ = len(full) / len(rows) if rows else 0.0

    result: dict = {
        "n_scored": len(rows),
        "full_instrument_yield": yield_,
        # §5 line 4. The thing under test is the *full* instrument; a
        # registry-only run reproduces the degenerate variant this study exists
        # to escape, so falling short is reported, not worked around.
        "full_instrument_gate_passes": yield_ >= MIN_FULL_INSTRUMENT_YIELD,
        "strata": {},
    }

    analysed = full if yield_ >= MIN_FULL_INSTRUMENT_YIELD else rows
    if yield_ < MIN_FULL_INSTRUMENT_YIELD:
        result["note"] = (
            f"full-instrument yield {yield_:.3f} < {MIN_FULL_INSTRUMENT_YIELD}; §5 "
            "line 4 fires and this is reported as a registry-only study"
        )

    for label in (PRIMARY_STRATUM, "one_shot"):
        subset = [row for row in analysed if row.stratum == label]
        if subset:
            result["strata"][label] = stratum_report(subset, label)

    # Reported alongside, explicitly not the headline (§2.1).
    result["pooled_not_headline"] = stratum_report(list(analysed), "pooled")

    primary = result["strata"].get(PRIMARY_STRATUM)
    result["verdict"] = (
        verdict(primary)
        if primary
        else {"claim": "not made", "reason": "primary stratum empty"}
    )
    # §4.1: the uncloneable stratum gets its own base rate, never an imputation.
    uncloneable = [row for row in rows if not row.full_instrument]
    result["uncloneable_stratum"] = {
        "n": len(uncloneable),
        "base_rate": (
            sum(row.quiet for row in uncloneable) / len(uncloneable)
            if uncloneable
            else None
        ),
    }

    text = json.dumps(result, indent=1, default=str)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
