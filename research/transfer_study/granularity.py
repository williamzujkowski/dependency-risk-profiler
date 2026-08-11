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

from typing import Callable, Dict, List, Optional, Sequence

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


def arm(movements: Sequence[Movement], bucket: Callable[[int], str]) -> Dict[str, object]:
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
