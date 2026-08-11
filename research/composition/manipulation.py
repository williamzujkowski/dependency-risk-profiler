"""What does it cost an attacker to move the score? Exactly, from the table.

`docs/manipulation-protocol.md`. No new data and no statistics: the
registry-only composite was enumerated in `lookup-table-result.md` as a twelve
-cell lookup on maintainer band x repository state, so the cost of moving
between cells is arithmetic over a table already published.

That publication is the reason to do this. **An enumerated scoring function is
also an instruction manual**, and the honest response to printing one is to
price the moves it makes available.

Two attacker actions, and the asymmetry between them is the finding:

- **declare a repository URL.** `record_source_repository` assigns DECLARED
  when the URL canonicalizes to an `owner/repo` root on a supported host. It
  does **not** check that the repository has anything to do with the package,
  so any parseable URL -- `facebook/react`, a fork, an empty repo -- qualifies.
  Requires a publish, because the field lives in the version document.
- **add maintainer accounts.** npm accounts are free and `npm owner add`
  mutates the top-level array, so this needs **no publish at all** -- which
  matters because a package an attacker has just taken over is one they may
  not want to touch.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

#: The published table: (maintainer band, repository state) -> score.
#: Read from `lookup-table-result.md`, which enumerated it exhaustively.
TABLE: Dict[Tuple[str, str], float] = {
    ("0-1", "UNDECLARED"): 1.0,
    ("0-1", "UNUSABLE"): 0.892857,
    ("2", "UNDECLARED"): 0.714286,
    ("2", "UNUSABLE"): 0.607143,
    ("0-1", "DECLARED"): 0.571429,
    ("3-4", "UNDECLARED"): 0.571429,
    ("3-4", "UNUSABLE"): 0.464286,
    ("5+", "UNDECLARED"): 0.428571,
    ("5+", "UNUSABLE"): 0.321429,
    ("2", "DECLARED"): 0.285714,
    ("3-4", "DECLARED"): 0.142857,
    ("5+", "DECLARED"): 0.0,
}

#: How many maintainer accounts each band needs, at minimum.
BAND_FLOOR: Dict[str, int] = {"0-1": 0, "2": 2, "3-4": 3, "5+": 5}

#: Bands in increasing order of accounts required.
BAND_ORDER: Tuple[str, ...] = ("0-1", "2", "3-4", "5+")


@dataclass(frozen=True)
class Move:
    """One attacker transition, priced in the units an attacker actually pays."""

    from_cell: Tuple[str, str]
    to_cell: Tuple[str, str]
    score_before: float
    score_after: float
    accounts_needed: int
    requires_publish: bool

    @property
    def score_drop(self) -> float:
        return self.score_before - self.score_after


def cheapest_move(
    cell: Tuple[str, str], allow_publish: bool = True
) -> Optional[Move]:
    """The largest score drop reachable from this cell, and what it costs.

    `allow_publish=False` restricts to actions that need no publish, which is
    the interesting case: a package whose ownership just changed hands can be
    re-scored downward without the attacker touching its code.
    """
    band, repo = cell
    best: Optional[Move] = None
    for (target_band, target_repo), score in TABLE.items():
        if score >= TABLE[cell]:
            continue
        publish_needed = target_repo != repo
        if publish_needed and not allow_publish:
            continue
        accounts = max(0, BAND_FLOOR[target_band] - BAND_FLOOR[band])
        move = Move(
            from_cell=cell,
            to_cell=(target_band, target_repo),
            score_before=TABLE[cell],
            score_after=score,
            accounts_needed=accounts,
            requires_publish=publish_needed,
        )
        if best is None or move.score_drop > best.score_drop:
            best = move
    return best


def price_cohort(
    occupancy: Dict[Tuple[str, str], int]
) -> Dict[str, object]:
    """Price every occupied cell, weighted by how many packages sit in it."""
    rows: List[Dict[str, object]] = []
    total = sum(occupancy.values())
    movable_any = 0
    movable_without_publish = 0
    for cell, count in sorted(occupancy.items(), key=lambda kv: -kv[1]):
        with_publish = cheapest_move(cell, allow_publish=True)
        without = cheapest_move(cell, allow_publish=False)
        if with_publish:
            movable_any += count
        if without:
            movable_without_publish += count
        rows.append(
            {
                "cell": list(cell),
                "score": TABLE[cell],
                "packages": count,
                "best_move": (
                    {
                        "to": list(with_publish.to_cell),
                        "score_after": with_publish.score_after,
                        "drop": with_publish.score_drop,
                        "accounts_needed": with_publish.accounts_needed,
                        "requires_publish": with_publish.requires_publish,
                    }
                    if with_publish
                    else None
                ),
                "best_move_without_publish": (
                    {
                        "to": list(without.to_cell),
                        "drop": without.score_drop,
                        "accounts_needed": without.accounts_needed,
                    }
                    if without
                    else None
                ),
            }
        )
    return {
        "cells": rows,
        "packages": total,
        "movable_share": movable_any / total if total else 0.0,
        "movable_without_publish_share": (
            movable_without_publish / total if total else 0.0
        ),
        "full_scale_move": {
            "from": ["0-1", "UNDECLARED"],
            "to": ["5+", "DECLARED"],
            "drop": TABLE[("0-1", "UNDECLARED")] - TABLE[("5+", "DECLARED")],
            "accounts_needed": BAND_FLOOR["5+"] - BAND_FLOOR["0-1"],
            "requires_publish": True,
        },
    }
