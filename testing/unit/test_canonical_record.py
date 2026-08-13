"""The record the 2027-08 readout will open must satisfy the frozen analysis.

``research/prospective/analyse.py`` was frozen before the harvest and must not
change. That makes the *record* the thing which has to meet it, and this checks
the committed file rather than a freshly-built object — because the failure
this exists to catch was not a broken producer, it was the readout being
pointed at a different record than the one the contract was written against.

There was already a contract test. It passed throughout, because it exercised
``score_at_t.score_one`` — the harvest producer — while the record designated
for the readout had moved to the enrichment producer, which carried six fewer
fields and a stale ablated arm. **A contract test that checks a producer proves
nothing about the artifact.**
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RESEARCH = REPO_ROOT / "research"
sys.path.insert(0, str(RESEARCH))

COHORT_DIR = REPO_ROOT / "research" / "data" / "prospective-cohort"

#: Named in ``docs/prospective-protocol.md``. One file, so there is never a
#: question at readout time about which record is authoritative.
CANONICAL = COHORT_DIR / "canonical-at-T.json"

#: Every field ``analyse.Row`` requires. ``quiet`` is added at T+12 by
#: ``outcome.py --final`` and is the only one legitimately absent now.
REQUIRED = (
    "name",
    "cluster",
    "stratum",
    "full_instrument",
    "composite",
    "composite_ablated",
    "downloads",
    "staleness",
)


def _packages() -> List[Dict[str, Any]]:
    if not CANONICAL.exists():
        pytest.skip(f"{CANONICAL.relative_to(REPO_ROOT)} not present")
    packages: List[Dict[str, Any]] = json.loads(CANONICAL.read_text())["packages"]
    return packages


def test_every_required_field_is_present_on_every_row() -> None:
    rows = _packages()
    assert rows, "canonical record is empty"
    missing: Dict[str, int] = {}
    for row in rows:
        for field in REQUIRED:
            if field not in row:
                missing[field] = missing.get(field, 0) + 1
    assert not missing, (
        "The canonical record does not satisfy the frozen analysis contract. "
        "analyse.py cannot change -- the record must meet it:\n  "
        + "\n  ".join(f"{field}: absent on {count} rows" for field, count in missing.items())
    )


def test_the_frozen_loader_accepts_the_record() -> None:
    """The contract, exercised through the frozen code rather than restated."""
    from prospective import analyse

    rows = _packages()
    joined = {"packages": [{**row, "quiet": False} for row in rows]}
    path = COHORT_DIR / ".contract-check.json"
    try:
        path.write_text(json.dumps(joined))
        loaded = analyse.load_rows(path)
    finally:
        path.unlink(missing_ok=True)

    assert len(loaded) == len(rows)
    assert all(isinstance(r.composite, float) for r in loaded)
    assert all(isinstance(r.composite_ablated, float) for r in loaded)


def test_the_ablated_arm_is_not_a_copy_of_the_composite() -> None:
    """A third arm identical to the first would compare nothing.

    The harvest's ablated arm was computed before four signals were measured,
    so carrying it forward would have ablated a different instrument than the
    one it is compared against.
    """
    rows = _packages()
    differing = sum(
        1
        for row in rows
        if row.get("composite") is not None
        and row.get("composite_ablated") is not None
        and abs(float(row["composite"]) - float(row["composite_ablated"])) > 1e-9
    )
    assert differing > len(rows) // 2, (
        f"only {differing} of {len(rows)} rows differ between the composite and "
        "its ablated arm; the third arm is not ablating anything"
    )


def test_no_scored_signal_is_constant_except_the_two_known_ones() -> None:
    """§13 and §14: the saturation check, pinned so it cannot regress.

    ``version`` is structurally inapplicable to a package-level cohort and
    ``transitive`` is deliberately unmeasured. Any *other* constant means a
    signal silently stopped being collected.
    """
    from prospective.saturation_check import distinct_counts
    from prospective.persist_signals import SIGNAL_FIELDS

    rows = _packages()
    counts = distinct_counts(rows, list(SIGNAL_FIELDS))
    constant = {name for name, count in counts.items() if count <= 1}
    assert constant <= {"version_score", "transitive_score"}, (
        "a scored signal became constant beyond the two known ones: "
        f"{sorted(constant - {'version_score', 'transitive_score'})}"
    )
