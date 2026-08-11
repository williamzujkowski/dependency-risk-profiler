"""Guards for the granularity counterfactual.

`docs/granularity-protocol.md` §6. Two of these encode defects a review caught
before the study ran: the arms are nested, so the primary contrast has to be
the marginal events; and the direction bar is unpowered, so the verdict has to
admit a third state.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))

from transfer_study.band_crossing import Movement  # noqa: E402
from transfer_study.granularity import (  # noqa: E402
    ARMS,
    difference_verdict,
    marginal_events,
    moved_under,
    swap_fraction,
)

RESULTS = Path(__file__).resolve().parents[2] / "research" / "results"
T = datetime(2024, 8, 1, tzinfo=timezone.utc)


def move(before: int, after: int) -> Movement:
    return Movement(
        package="pkg",
        baseline_published=T,
        baseline_set=tuple(f"a{i}" for i in range(before)),
        current_set=tuple(f"b{i}" for i in range(after)),
        published_after_t=False,
        modified_after_newest_release=True,
        window_days=740.0,
    )


def test_the_arms_are_nested() -> None:
    """Every shipped crossing is seen by finer arms. The reason for §6.

    Nesting is why a pooled comparison is rigged: the finer arm's sample
    contains the coarser arm's, so the pooled statistic is dragged toward it.
    """
    for before, after in ((1, 2), (2, 5), (4, 5), (27, 28), (3, 3)):
        movement = move(before, after)
        if moved_under(movement, ARMS["shipped"]):
            assert moved_under(movement, ARMS["fine"])
            assert moved_under(movement, ARMS["continuous"])


def test_marginal_events_exclude_what_shipped_already_sees() -> None:
    """The primary contrast: what the finer arm adds, and only that."""
    movements = [move(27, 28), move(2, 5), move(3, 3)]
    marginal = marginal_events(movements, ARMS["continuous"])
    assert len(marginal) == 1
    assert len(marginal[0].baseline_set) == 27


def test_a_swap_is_invisible_at_every_resolution() -> None:
    """The ceiling review caught: the collapse was measured on sets, not counts.

    One maintainer out and one in changes the set and leaves the count alone,
    so no count-based resolution can ever see it — continuous included.
    """
    swap = move(3, 3)
    assert swap.set_changed
    for bucket in ARMS.values():
        assert not moved_under(swap, bucket)
    assert swap_fraction([swap])["swap_share_of_set_changes"] == 1.0


def test_the_verdict_admits_being_underpowered() -> None:
    """Tri-state, fixed before the numbers. Without it a wide interval reads as a null.

    The real run landed here: differences of +0.107 and +0.118 against a 0.10
    margin, with intervals straddling it. A point comparison would have
    announced "not the fix" on estimates that lean the other way.
    """
    assert difference_verdict(0.44, 86, 0.56, 50)["verdict"] == "underpowered"
    assert difference_verdict(0.20, 5000, 0.70, 5000)["verdict"] == "supported"
    assert difference_verdict(0.44, 5000, 0.45, 5000)["verdict"] == "refuted"
    assert difference_verdict(None, 0, 0.5, 10)["verdict"] == "underpowered"


def test_the_recorded_result_still_says_what_the_write_up_asserts() -> None:
    result = json.loads((RESULTS / "granularity-2024.json").read_text())
    arms = result["arms"]
    ratio = arms["continuous"]["movement_rate"] / arms["shipped"]["movement_rate"]
    assert 1.5 < ratio < 1.7, "the 1.58x rate gain in the write-up has moved"
    for name in ("fine", "continuous"):
        assert result["marginal"][name]["vs_shipped"]["verdict"] == "underpowered", (
            "a marginal contrast is no longer underpowered; the result doc "
            "leads on the tri-state having fired"
        )
        assert result["marginal"][name]["risk_increasing_share"] > 0.5, (
            "the marginal events no longer lean risk-increasing, which is the "
            "part of the result that runs against the registered prior"
        )
    assert result["swaps"]["swap_share_of_set_changes"] == pytest.approx(
        0.1758, abs=5e-4
    )
