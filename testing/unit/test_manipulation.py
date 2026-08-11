"""Guards for the manipulation pricing.

`docs/manipulation-protocol.md`. The table these prices are computed from is
the enumerated one, so a change to the scorer that invalidates the table also
invalidates every price here -- and that has to fail loudly rather than leave a
published cost stale.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))

from composition.manipulation import (  # noqa: E402
    BAND_FLOOR,
    TABLE,
    cheapest_move,
    price_cohort,
)

RESULTS = Path(__file__).resolve().parents[2] / "research" / "results"


def test_the_priced_table_matches_the_enumerated_one() -> None:
    """The prices are arithmetic over the published table, so it must still hold.

    If the scorer is re-weighted, `lookup-table-2024.json` changes and every
    figure in `manipulation-result.md` is wrong. This is the link between them.
    """
    enumerated = json.loads((RESULTS / "lookup-table-2024.json").read_text())
    bands = {0.0: "5+", 0.25: "3-4", 0.5: "2", 1.0: "0-1"}
    for row in enumerated["table"]:
        cell = (bands[row["inputs"]["maintainer_band"]], row["inputs"]["repository_state"])
        assert cell in TABLE, f"{cell} is occupied but not priced"
        assert TABLE[cell] == pytest.approx(row["score"], abs=1e-5), (
            f"{cell} scores {row['score']} in the enumeration and "
            f"{TABLE[cell]} in the price table"
        )


def test_the_modal_cell_reaches_the_floor_without_a_publish() -> None:
    """The headline: 39% of the cohort, five accounts, no code touched."""
    move = cheapest_move(("0-1", "DECLARED"), allow_publish=False)
    assert move is not None
    assert move.to_cell == ("5+", "DECLARED")
    assert move.score_after == 0.0
    assert move.accounts_needed == BAND_FLOOR["5+"]
    assert move.requires_publish is False


def test_the_full_scale_move_costs_five_accounts_and_a_url() -> None:
    move = cheapest_move(("0-1", "UNDECLARED"), allow_publish=True)
    assert move is not None
    assert move.score_drop == pytest.approx(1.0)
    assert move.accounts_needed == 5
    assert move.requires_publish is True


def test_the_floor_cell_has_nowhere_left_to_go() -> None:
    """A package already at 0.0 cannot be improved, which the pricing must admit."""
    assert cheapest_move(("5+", "DECLARED")) is None


def test_the_recorded_shares_still_say_what_the_write_up_says() -> None:
    result = json.loads((RESULTS / "manipulation-2024.json").read_text())
    assert result["packages"] == 2906
    assert result["movable_share"] == pytest.approx(0.8837, abs=5e-4)
    assert result["movable_without_publish_share"] == pytest.approx(0.8348, abs=5e-4)
    assert result["full_scale_move"]["drop"] == pytest.approx(1.0)


def test_pricing_an_empty_cohort_does_not_divide_by_zero() -> None:
    empty = price_cohort({})
    assert empty["packages"] == 0
    assert empty["movable_share"] == 0.0
