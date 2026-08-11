"""Enumerate the registry-only composite as the finite table it turns out to be.

`docs/leading-indicator-protocol.md` claim A. The registry-only composite reads
three inputs that survive reconstruction at a past date — maintainer count,
declared licence, declared repository — and produces eleven distinct values
across 2,906 packages. If the map from input tuple to score is a *function*,
then "what the composite measures" is settled by printing it rather than by
estimating anything.

**A caveat the review insisted on, and it is fair.** A deterministic
implementation necessarily maps a complete input tuple to one output; finding
otherwise would mean the tuple omitted an input, not that the scorer is
nondeterministic. So single-valuedness is not the interesting part — the
interesting part is how *small* the tuple is. Eleven outcomes over three
slow-moving registry fields is a lookup table whether or not the mapping
surprises anyone, and a reader can audit a lookup table.

The scorer's configuration is hashed into the output so a table produced under
different weights cannot be mistaken for this one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer


@dataclass(frozen=True)
class Cell:
    """One input tuple, reduced to what the composite can actually distinguish.

    Both reductions matter, and getting them wrong hides the table:

    `licence` is the *category* rather than the string, because the scorer maps
    a declared licence to a risk band — recording raw text would enumerate
    npm's spelling habits instead of the composite's input surface.

    `maintainer_band` is the scorer's own sub-score for the count, not the
    count. Recording the raw number produced **149 cells** for eleven possible
    scores, which says only that packages have many different maintainer counts.
    The band is derived by calling the scorer rather than by restating its
    thresholds here, so a re-banded scorer cannot leave this file describing a
    table it no longer produces.
    """

    maintainer_band: Optional[float]
    licence_category: str
    repository_state: Optional[str]

    def as_key(self) -> str:
        return json.dumps(
            {
                "maintainer_band": self.maintainer_band,
                "licence_category": self.licence_category,
                "repository_state": self.repository_state,
            },
            sort_keys=True,
        )


def cell_of(dependency: DependencyMetadata, scorer: RiskScorer) -> Cell:
    """The input tuple the registry-only composite can actually distinguish."""
    licence = getattr(dependency, "license_info", None)
    category = "none"
    if licence is not None:
        category = str(getattr(licence, "category", None) or getattr(
            licence, "risk_category", None
        ) or "declared")
    state = dependency.source_repository_state
    band = scorer._calculate_maintainer_score(  # noqa: SLF001 - the band IS the input
        dependency.maintainer_count
    )
    return Cell(
        maintainer_band=band,
        licence_category=category,
        repository_state=state.name if state is not None else None,
    )


def scorer_fingerprint(scorer: RiskScorer) -> str:
    """SHA-256 over the scorer's weights and maximum, so a table is attributable.

    A lookup table is only meaningful against the configuration that produced
    it. Re-weight the composite and the same three inputs give different
    numbers; without this the two tables would be indistinguishable artifacts.
    """
    weights = getattr(scorer, "weights", None)
    payload = json.dumps(
        {
            "weights": (
                {k: v for k, v in sorted(vars(weights).items())}
                if weights is not None and hasattr(weights, "__dict__")
                else str(weights)
            ),
            "max_score": getattr(scorer, "max_score", None),
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_table(
    observations: List[Tuple[Cell, float, bool]]
) -> Dict[str, Any]:
    """Fold observations into the table, and report any tuple that is not a function.

    `observations` is `(cell, score, insufficient_data)` per package. The
    abstention flag rides along because it is part of what the tuple determines
    — and because the two constant cadence signals deciding every abstention is
    the finding `composition-result.md` ended on.
    """
    by_cell: Dict[str, Dict[str, Any]] = {}
    conflicts: List[Dict[str, Any]] = []

    for cell, score, insufficient in observations:
        key = cell.as_key()
        entry = by_cell.setdefault(
            key,
            {
                "inputs": json.loads(key),
                "score": score,
                "insufficient_data": insufficient,
                "packages": 0,
            },
        )
        entry["packages"] += 1
        if entry["score"] != score or entry["insufficient_data"] != insufficient:
            conflicts.append(
                {
                    "inputs": json.loads(key),
                    "scores": sorted({entry["score"], score}),
                }
            )

    rows = sorted(
        by_cell.values(),
        key=lambda row: (-row["score"], -row["packages"]),
    )
    return {
        "cells": len(rows),
        "distinct_scores": len({row["score"] for row in rows}),
        "conflicts": conflicts,
        "is_a_function": not conflicts,
        "table": rows,
    }
