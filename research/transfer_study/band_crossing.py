"""Does the one lead-capable signal actually move? — the analysis.

`docs/band-crossing-protocol.md`, including the §6 amendment that changed the
primary quantity after a 4-3 reject. Pure: the harvest is `maintainer_now.py`,
this reads its output beside the pinned snapshot.

The quantity is **band crossings per package-year**, not a two-year rate. The
comparison baseline is the maintainer set frozen in the version document in
force at T, which was frozen at *that version's publish date* — for a quiet
package, potentially years before T. Assuming a uniform two-year window would
inflate the rate most for the quietest packages, which are the ones the claim
is about.

The headline stratum is packages whose last pre-T publish falls within six
months of T: there the baseline is close to T and the original question is
answerable as asked.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

#: The scorer's maintainer bands, as boundaries rather than as scores. Derived
#: from `_calculate_maintainer_score`: >=5, >=3, ==2, else. A crossing between
#: these is the only maintainer change that moves the composite at all.
BAND_EDGES = ((5, "5+"), (3, "3-4"), (2, "2"), (0, "0-1"))

#: Six months, in days. §6's headline stratum.
RECENT_BASELINE_DAYS = 183


def band_of(count: Optional[int]) -> Optional[str]:
    """The band a maintainer count falls in, or None when unknown."""
    if count is None:
        return None
    for threshold, label in BAND_EDGES:
        if count >= threshold:
            return label
    return "0-1"


@dataclass(frozen=True)
class Movement:
    """One package's before-and-after, with its own exposure window."""

    package: str
    baseline_published: datetime
    baseline_set: Tuple[str, ...]
    current_set: Tuple[str, ...]
    published_after_t: bool
    modified_after_newest_release: bool
    window_days: float

    @property
    def set_changed(self) -> bool:
        return set(self.baseline_set) != set(self.current_set)

    @property
    def baseline_band(self) -> Optional[str]:
        return band_of(len(self.baseline_set))

    @property
    def current_band(self) -> Optional[str]:
        return band_of(len(self.current_set))

    @property
    def band_crossed(self) -> bool:
        return self.baseline_band != self.current_band

    @property
    def added(self) -> Set[str]:
        return set(self.current_set) - set(self.baseline_set)

    @property
    def removed(self) -> Set[str]:
        return set(self.baseline_set) - set(self.current_set)

    @property
    def direction(self) -> Optional[str]:
        """Which way the *score* moved, which is the opposite of the count.

        More maintainers is lower risk in this scorer, so a package gaining
        maintainers has its score go **down**. Reporting the count direction
        would invert the thing a user cares about.
        """
        if not self.band_crossed:
            return None
        return (
            "risk_decreasing"
            if len(self.current_set) > len(self.baseline_set)
            else "risk_increasing"
        )


def _parse(stamp: Optional[str]) -> Optional[datetime]:
    if not stamp:
        return None
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_movements(
    harvested: Iterable[Dict[str, object]],
    baselines: Dict[str, Tuple[datetime, Tuple[str, ...], bool]],
    harvest_moment: datetime,
) -> List[Movement]:
    """Join the harvest to the frozen baselines. Unresolved packages are dropped.

    `baselines` maps package to `(publish date of the version in force at T,
    maintainer set frozen in it, published anything after T)`.
    """
    out: List[Movement] = []
    for record in harvested:
        if record.get("status") != 200:
            continue
        name = str(record["name"])
        baseline = baselines.get(name)
        if baseline is None:
            continue
        published_at, frozen, published_after = baseline
        modified_raw = record.get("modified")
        newest_raw = record.get("newest_release")
        modified = _parse(modified_raw if isinstance(modified_raw, str) else None)
        newest = _parse(newest_raw if isinstance(newest_raw, str) else None)
        raw = record.get("maintainers")
        current = tuple(sorted(raw)) if isinstance(raw, list) else ()
        out.append(
            Movement(
                package=name,
                baseline_published=published_at,
                baseline_set=frozen,
                current_set=current,
                published_after_t=published_after,
                modified_after_newest_release=bool(
                    modified and newest and modified > newest
                ),
                window_days=max(
                    1.0, (harvest_moment - published_at).total_seconds() / 86400.0
                ),
            )
        )
    return out


def effective_accounts(movements: Sequence[Movement]) -> Dict[str, object]:
    """Cluster the crossings by the account that moved, and report an effective n.

    One bot added across hundreds of packages, or a platform-wide admin action,
    could manufacture an entire crossing rate. This repository has been bitten
    by nominal-versus-effective counts four times; applying the lesson to this
    study rather than citing it is the point.
    """
    crossings = [m for m in movements if m.band_crossed]
    touched: Dict[str, int] = {}
    for movement in crossings:
        for account in movement.added | movement.removed:
            touched[account] = touched.get(account, 0) + 1
    top = sorted(touched.items(), key=lambda kv: -kv[1])[:10]
    return {
        "nominal_crossings": len(crossings),
        "distinct_accounts_involved": len(touched),
        "largest_account_share": (
            max(touched.values()) / len(crossings) if crossings else 0.0
        ),
        "top_accounts": [{"account": a, "packages": n} for a, n in top],
    }


def summarise(movements: Sequence[Movement]) -> Dict[str, object]:
    """Rates for one subset, always with the window that produced them."""
    if not movements:
        return {"packages": 0}
    crossings = [m for m in movements if m.band_crossed]
    set_changes = [m for m in movements if m.set_changed]
    package_years = sum(m.window_days for m in movements) / 365.25
    directions: Dict[str, int] = {}
    for movement in crossings:
        key = movement.direction or "none"
        directions[key] = directions.get(key, 0) + 1
    ages = sorted(m.window_days / 365.25 for m in movements)
    return {
        "packages": len(movements),
        "package_years": package_years,
        "set_change_rate": len(set_changes) / len(movements),
        "band_crossing_rate": len(crossings) / len(movements),
        "crossings_per_package_year": (
            len(crossings) / package_years if package_years else 0.0
        ),
        "collapse_ratio_set_over_band": (
            len(set_changes) / len(crossings) if crossings else None
        ),
        "direction": directions,
        "window_years_median": ages[len(ages) // 2],
        "window_years_p90": ages[int(0.9 * (len(ages) - 1))],
        "modified_after_newest_release_rate": sum(
            1 for m in movements if m.modified_after_newest_release
        )
        / len(movements),
    }
