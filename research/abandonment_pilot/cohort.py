"""Who is in the cohort, what "abandoned" means, and how long N is.

Three decisions live here, and each one is a place the experiment could quietly
answer a different question than it claims to.

**N is measured, not assumed.** "No release for two years" is the conventional
abandonment threshold and this module does not use it on those grounds. It
builds an actuarial life table of release silences observed *entirely before T*
and reads off the 12-month resumption hazard at each whole year of silence: of
the packages that have already been quiet for N years, what fraction publish
again in the next twelve months. :func:`choose_abandonment_years` reads N off
that table by two rules in order, and reports which one fired. The whole table
is reported too, so a reader can apply a different cutoff to the same numbers.

The population fed to the table is **every sampled package**, not the cohort.
That distinction is not pedantry: the cohort has to be live at T, so its
silences are the ones that ended, and its hazard plateaus near 40% out to seven
years. Selecting on activity and then measuring how often activity resumes is
the same circularity this pilot exists to avoid, one level down.

**Eligibility is fixed before any score is computed.** A package joins the
cohort if it had a real, live release history at T: at least
:data:`MIN_RELEASES_BEFORE_T` releases, a first release at least
:data:`MIN_AGE_DAYS` earlier, and a most recent release within
:data:`RECENT_ACTIVITY_DAYS`. The last of those is what makes the outcome mean
anything — without it, a package already silent for five years at T would be
labelled abandoned for continuing to do what it was already doing, and the
label would be a restatement of the pre-T cadence this pilot has ablated.

That eligibility rule is also the born-malicious exclusion, and it is stronger
than a blocklist. #312 resolved a sample of npm ``MAL-*`` packages against the
registry and measured a **median publish-history span of 35 days, one version
each**: a typosquat has no legitimate at-risk state at T because it has no
history before the attack. Three releases spanning a year excludes that class by
construction rather than by enumeration, which is the only version of the
exclusion that also covers the malicious packages nobody has catalogued yet.

**One T per package.** The cohort is built at a single instant, so no package
contributes two correlated rows. Clustering by shared maintainer is handled by
:func:`maintainer_clusters`, whose components the bootstrap resamples.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .snapshot import PackageRecord, maintainers_at

#: Days in the year used for every year-denominated threshold here. The Julian
#: year rather than 365: over a four-year window the difference is a day, and a
#: constant that is wrong by a day at year four is a constant that has to be
#: re-derived every time someone reads it.
DAYS_PER_YEAR = 365.25

#: Releases a package must already have published at T. Three rather than two:
#: two releases establish a single interval, which is not a cadence, and the
#: life table below needs at least one completed silence to observe.
MIN_RELEASES_BEFORE_T = 3

#: How old a package must be at T.
MIN_AGE_DAYS = 365

#: How recently a package must have released to count as live at T.
RECENT_ACTIVITY_DAYS = 365

#: The 12-month resumption hazard below which a silence is read as a state
#: rather than a pause. Applied to the life table in
#: :func:`resumption_life_table`; the table itself is always reported so a
#: reader can substitute their own.
RESUMPTION_HAZARD_CUTOFF = 0.10

#: Silences a year of the life table needs before its hazard is read as a
#: measurement rather than as noise.
MINIMUM_AT_RISK = 200

#: The instants a snapshot is harvested against. T is one of these, chosen once
#: N is known, because the label window ``(T, T + N years]`` has to be closed at
#: harvest time: ``T = harvested_at - N years``.
CANDIDATE_T: Tuple[datetime, ...] = (
    datetime(2022, 8, 1, tzinfo=timezone.utc),
    datetime(2023, 8, 1, tzinfo=timezone.utc),
    datetime(2024, 8, 1, tzinfo=timezone.utc),
    datetime(2025, 8, 1, tzinfo=timezone.utc),
)


@dataclass(frozen=True)
class LifeTableRow:
    """One whole year of the release-silence life table."""

    #: Years of silence already elapsed.
    years: int
    #: Silences that had reached this length and were still under observation.
    at_risk: int
    #: Of those, the ones that ended in a release during the next 12 months.
    resumed: int
    #: Of those, the ones whose observation window closed during the next 12
    #: months without a release — the trailing silence of a package whose
    #: history simply runs out before T.
    censored: int
    #: ``resumed`` over the actuarially corrected denominator.
    hazard: float


def resumption_life_table(
    histories: Iterable[Sequence[datetime]],
    before: datetime,
    max_years: int = 8,
) -> Tuple[LifeTableRow, ...]:
    """Build the 12-month resumption hazard by years of silence.

    Only release history strictly before ``before`` is read, so the table that
    chooses N cannot have seen any of the outcome it will be used to define.

    Each consecutive pair of releases contributes one completed silence. Each
    package additionally contributes one **censored** silence: the stretch from
    its last release before ``before`` up to ``before`` itself, which has not
    ended as far as this table can see. Ignoring those would count only
    silences that happened to end, which is exactly the population that makes
    abandonment look temporary.

    **Feed this every sampled package, not the cohort.** The cohort is required
    to be live at T, so its trailing silence is short by construction and its
    interior silences all ended in a release — a population in which no silence
    is ever permanent, and whose hazard is therefore biased upward at every
    year. Running it on the cohort gave a plateau near 40% out to seven years,
    which is a statement about the filter and not about npm.

    Args:
        histories: Release-time sequences, one per package.
        before: The cut-off; nothing at or after it is read.
        max_years: How many whole years of silence to tabulate.

    Returns:
        One row per whole year of silence, ascending.
    """
    completed: List[float] = []
    censored: List[float] = []
    for history in histories:
        published = sorted(when for when in history if when < before)
        if len(published) < 2:
            continue
        for earlier, later in zip(published, published[1:]):
            completed.append((later - earlier).days / DAYS_PER_YEAR)
        censored.append((before - published[-1]).days / DAYS_PER_YEAR)

    rows: List[LifeTableRow] = []
    for year in range(max_years):
        lower = float(year)
        upper = lower + 1.0
        at_risk = sum(1 for gap in completed if gap >= lower)
        at_risk += sum(1 for gap in censored if gap >= lower)
        resumed = sum(1 for gap in completed if lower <= gap < upper)
        lost = sum(1 for gap in censored if lower <= gap < upper)
        denominator = at_risk - lost / 2.0
        hazard = resumed / denominator if denominator > 0 else 0.0
        rows.append(
            LifeTableRow(
                years=year,
                at_risk=at_risk,
                resumed=resumed,
                censored=lost,
                hazard=hazard,
            )
        )
    return tuple(rows)


def choose_abandonment_years(
    table: Sequence[LifeTableRow],
    cutoff: float = RESUMPTION_HAZARD_CUTOFF,
    minimum_at_risk: int = MINIMUM_AT_RISK,
) -> Tuple[Optional[int], str]:
    """Read N off the life table, and say which rule produced it.

    Two rules, in order, both fixed before the table was computed:

    1. **Hazard below the cutoff.** The first whole year whose 12-month
       resumption hazard is under ``cutoff``. This is the rule with a meaning a
       reader can hold: at N years of silence, a package has less than a one in
       ten chance of publishing again within the year.
    2. **Hazard stops falling.** If no year clears the cutoff, the first whole
       year after which waiting longer stops lowering the hazard. Past that
       point another year of silence carries no further information about
       whether the package is coming back, so it is the largest N that is
       informative and the smallest that cannot be improved on.

    A year is only read if at least ``minimum_at_risk`` silences reached it.
    The far tail of this table thins to double digits, and a hazard computed
    over eleven observations is noise that the first rule would happily pick.

    Args:
        table: The life table from :func:`resumption_life_table`.
        cutoff: The hazard below which silence reads as abandonment.
        minimum_at_risk: Silences a year needs before its hazard is read.

    Returns:
        ``(N in years or None, the rule that produced it)``.
    """
    usable = [
        row for row in table if row.years >= 1 and row.at_risk >= minimum_at_risk
    ]
    for row in usable:
        if row.hazard < cutoff:
            return row.years, "hazard_below_cutoff"
    for earlier, later in zip(usable, usable[1:]):
        if later.hazard >= earlier.hazard:
            return earlier.years, "hazard_stops_falling"
    if usable:
        return usable[-1].years, "hazard_still_falling_at_the_last_usable_year"
    return None, "no_year_carries_enough_observations"


@dataclass(frozen=True)
class CohortMember:
    """One package, at one T, with its outcome."""

    name: str
    #: Index of the newest release published at or before T.
    index_at_t: int
    #: Publication time of that release.
    last_release_before_t: datetime
    #: Publication time of the package's first release.
    first_release: datetime
    #: Releases published at or before T.
    releases_before_t: int
    #: True when no release was published in ``(T, T + N years]``.
    abandoned: bool
    #: Maintainer usernames frozen into the release at ``index_at_t``.
    maintainers: Tuple[str, ...]


def eligibility(record: PackageRecord, moment: datetime) -> Optional[str]:
    """Return the reason a package is not in the cohort at ``moment``, or None.

    Args:
        record: The package record.
        moment: T.

    Returns:
        A stable reason string, or None when the package is eligible.
    """
    index = record.release_index_at(moment)
    if index is None:
        return "no_release_before_T"
    if index + 1 < MIN_RELEASES_BEFORE_T:
        return "too_few_releases_before_T"
    first = record.releases[0][1]
    if (moment - first).days < MIN_AGE_DAYS:
        return "younger_than_one_year_at_T"
    last = record.releases[index][1]
    if (moment - last).days > RECENT_ACTIVITY_DAYS:
        return "already_dormant_at_T"
    if maintainers_at(record, index) is None:
        return "no_maintainer_array_at_T"
    return None


def build_cohort(
    records: Iterable[PackageRecord],
    moment: datetime,
    abandonment_years: int,
    observed_until: datetime,
) -> Tuple[Tuple[CohortMember, ...], Dict[str, int]]:
    """Assemble the cohort at ``moment`` and label it.

    Args:
        records: Package records to consider.
        moment: T.
        abandonment_years: N.
        observed_until: The instant the snapshot was harvested. The label window
            must close at or before this, or a package would be labelled
            "no release in N years" on the strength of a window that has not
            finished running.

    Returns:
        ``(members, exclusion_counts)``.

    Raises:
        ValueError: If the label window extends past ``observed_until``.
    """
    window_end = moment + timedelta(days=abandonment_years * DAYS_PER_YEAR)
    if window_end > observed_until:
        raise ValueError(
            f"the label window closes at {window_end.isoformat()}, after the "
            f"snapshot was taken at {observed_until.isoformat()}: every package "
            "would be labelled on an unfinished window"
        )

    members: List[CohortMember] = []
    excluded: Dict[str, int] = {}
    for record in records:
        reason = eligibility(record, moment)
        if reason is not None:
            excluded[reason] = excluded.get(reason, 0) + 1
            continue
        index = record.release_index_at(moment)
        if index is None:
            raise ValueError(f"{record.name} passed eligibility with no release at T")
        maintainers = maintainers_at(record, index)
        if maintainers is None:
            raise ValueError(f"{record.name} passed eligibility with no maintainers")
        # ``moment <=``, matching ``release_index_at``'s strictly-before: at day
        # resolution the two together partition the timeline with no release
        # counted on both sides and none dropped between them.
        resumed = any(moment <= when <= window_end for _, when in record.releases)
        members.append(
            CohortMember(
                name=record.name,
                index_at_t=index,
                last_release_before_t=record.releases[index][1],
                first_release=record.releases[0][1],
                releases_before_t=index + 1,
                abandoned=not resumed,
                maintainers=maintainers,
            )
        )
    return tuple(members), excluded


def maintainer_clusters(members: Sequence[CohortMember]) -> Tuple[int, ...]:
    """Group packages that share a maintainer into connected components.

    Two packages published by the same npm account are not two independent
    observations of whether maintainer concentration predicts abandonment: the
    account is the thing being observed, and if it walks away both packages go
    quiet together. The bootstrap resamples these components rather than rows.

    Sharing is transitive by construction — a maintainer bridging two package
    sets merges them — because a component is what the resampling unit has to
    be for the resamples to be independent of each other.

    Args:
        members: The cohort, in a fixed order.

    Returns:
        A component id per member, in the same order.
    """
    parent: List[int] = list(range(len(members)))

    def find(node: int) -> int:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    first_seen: Dict[str, int] = {}
    for position, member in enumerate(members):
        for maintainer in member.maintainers:
            previous = first_seen.setdefault(maintainer, position)
            if previous != position:
                union(previous, position)
    return tuple(find(position) for position in range(len(members)))
