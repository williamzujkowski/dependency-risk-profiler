"""Would finer maintainer bands recover the movement the current ones lose?

`docs/granularity-protocol.md`. Pure: replays the harvest already taken through
three maintainer resolutions and reports what each would have moved.

The arms differ only in how a maintainer count is bucketed:

- **shipped** -- the scorer's four bands, `<=1 / 2 / 3-4 / >=5`
- **fine** -- every integer to 9, then `10+`
- **continuous** -- the count itself, so any change of one moves the score

Everything else is held fixed, which is what makes the comparison between arms
sound even though each arm's rate is a floor.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from .band_crossing import Movement, band_of

#: The three resolutions, as functions from a count to a bucket label.
ARMS: Dict[str, Callable[[int], str]] = {
    "shipped": lambda n: band_of(n) or "0-1",
    "fine": lambda n: str(n) if n <= 9 else "10+",
    "continuous": lambda n: str(n),
}


def moved_under(movement: Movement, bucket: Callable[[int], str]) -> bool:
    """Whether this package's score would move at the given resolution."""
    return bucket(len(movement.baseline_set)) != bucket(len(movement.current_set))


def direction_of(movement: Movement) -> str:
    """Which way the score moves. More maintainers is lower risk in this scorer."""
    return (
        "risk_decreasing"
        if len(movement.current_set) > len(movement.baseline_set)
        else "risk_increasing"
    )


def arm(
    movements: Sequence[Movement], bucket: Callable[[int], str]
) -> Dict[str, Any]:
    """Rate and direction split for one resolution over one subset."""
    if not movements:
        return {"packages": 0}
    moved = [m for m in movements if moved_under(m, bucket)]
    increasing = sum(1 for m in moved if direction_of(m) == "risk_increasing")
    package_years = sum(m.window_days for m in movements) / 365.25
    return {
        "packages": len(movements),
        "moved": len(moved),
        "movement_rate": len(moved) / len(movements),
        "movements_per_package_year": (
            len(moved) / package_years if package_years else 0.0
        ),
        "risk_increasing": increasing,
        "risk_decreasing": len(moved) - increasing,
        "risk_increasing_share": (increasing / len(moved)) if moved else None,
    }


def wilson(successes: int, trials: int, z: float = 1.96) -> Optional[List[float]]:
    """95% Wilson interval on the risk-increasing share.

    Without an interval the arms cannot be compared: the continuous arm has
    several times the events of the shipped one, so two point shares of
    similar value are not similarly precise, and a bare 10-point comparison
    would read sampling noise as a change in the signal.
    """
    if trials == 0:
        return None
    phat = successes / trials
    denominator = 1 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denominator
    spread = (
        z * ((phat * (1 - phat) / trials + z * z / (4 * trials * trials)) ** 0.5)
    ) / denominator
    return [max(0.0, centre - spread), min(1.0, centre + spread)]


def marginal_events(
    movements: Sequence[Movement], bucket: Callable[[int], str]
) -> List[Movement]:
    """Set changes this resolution sees that the shipped bands do not.

    §6's primary contrast. The arms are nested — every band crossing is a set
    change — so comparing pooled splits compares overlapping samples and drags
    the finer arm toward the coarser one. The events that distinguish the arms
    are exactly these, and asking whether *they* carry direction is the
    question "does the movement granularity adds carry direction?" asked
    directly.
    """
    shipped = ARMS["shipped"]
    return [
        m
        for m in movements
        if moved_under(m, bucket) and not moved_under(m, shipped)
    ]


def swap_fraction(movements: Sequence[Movement]) -> Dict[str, Any]:
    """Set changes that leave the count identical, invisible at every resolution.

    The 2.12x collapse was measured on **sets**; every arm here buckets a
    **count**. One maintainer out and one in changes the set and leaves the
    count alone, so no granularity change can ever recover it. This is the
    ceiling on what the proposed fix could do, and it was missing from the
    registration until review caught it.
    """
    set_changes = [m for m in movements if m.set_changed]
    swaps = [
        m for m in set_changes if len(m.baseline_set) == len(m.current_set)
    ]
    return {
        "set_changes": len(set_changes),
        "swaps": len(swaps),
        "swap_share_of_set_changes": (
            len(swaps) / len(set_changes) if set_changes else 0.0
        ),
    }


def difference_verdict(
    shipped_share: Optional[float],
    shipped_n: int,
    other_share: Optional[float],
    other_n: int,
    margin: float = 0.10,
) -> Dict[str, Any]:
    """Tri-state on the direction difference: supported, refuted, or underpowered.

    §6 fixed the third state before any number existed, because at n = 86 the
    interval on a share is about +-10 points and a point comparison against a
    10-point bar cannot tell "no effect" from "no power". Announcing "not the
    fix" on an inconclusive interval is the mistake this prevents.
    """
    if shipped_share is None or other_share is None or min(shipped_n, other_n) == 0:
        return {"verdict": "underpowered", "reason": "an arm produced no events"}
    difference = other_share - shipped_share
    standard_error = (
        shipped_share * (1 - shipped_share) / shipped_n
        + other_share * (1 - other_share) / other_n
    ) ** 0.5
    low, high = difference - 1.96 * standard_error, difference + 1.96 * standard_error
    if low > margin:
        verdict = "supported"
    elif high < margin:
        verdict = "refuted"
    else:
        verdict = "underpowered"
    return {
        "verdict": verdict,
        "difference": difference,
        "ci95": [low, high],
        "margin": margin,
        "reason": (
            f"difference {difference:+.4f}, 95% CI [{low:+.4f}, {high:+.4f}] "
            f"against a {margin:.2f} margin"
        ),
    }
