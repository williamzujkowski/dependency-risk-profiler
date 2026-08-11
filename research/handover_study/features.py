"""As-of-T inputs for the four signals protocol §4 admits, and five baselines.

This module extends the abandonment pilot's ``features`` rather than replacing
it: :func:`abandonment_pilot.features.build_metadata` still supplies
``maintainer`` and ``source_repository``, and
:func:`abandonment_pilot.features.build_baselines` still supplies four of the
five baselines. What is new here is the two signals no harness has ever
supplied — ``staleness`` and ``version`` — and the fifth baseline §5 added
against the exposure-window confound.

**``license`` is not supplied.** Protocol §4 excludes it and #340 removed it
from the composite entirely, so the pilot's ``PILOT_SIGNALS`` cannot be reused
as-is; :data:`HANDOVER_SIGNALS` is the admissible set for this study.

Two things the shipped scorer does with these inputs had to be read out of the
scorer rather than assumed, and both change what can honestly be claimed.

**``staleness`` is computed against wall-clock ``now``, not against T.**
``RiskScorer._calculate_staleness_score`` buckets
``datetime.now(timezone.utc) - last_updated``. Handing it the literal publish
time of the release in force at T therefore does not measure release cadence at
T; it measures *days from that release to today*, which is
``exposure_window_days`` — the quantity protocol §5 assigns to **baseline 5**,
precisely so the model can be tested against it. Feeding it to the model would
put the baseline inside the model.

It is also degenerate. Cohort eligibility caps staleness at T at 365 days, so
every exposure window is at least 2.03 years, every one lands in the scorer's
"more than a year" bucket, and the signal is the constant 1.0 for all 2,905
packages.

So :func:`staleness_input` supplies the ``last_updated`` **for which the
shipped scoring function computes the as-of-T bucket**: ``reference_now`` minus
the days elapsed from the release in force at T to T. This builds an input; it
does not compute a score, and no second scoring path exists. The pilot's rule
still holds — the risk number comes from ``RiskScorer.score_dependency``.

**``version`` is degenerate at T, and no input can fix that.** The signal reads
installed against latest. At T the release in force *is* the latest release, so
the two strings are equal, and
``RiskScorer._calculate_version_difference_score`` returns ``0.0`` on its first
branch — before the calendar-versioning path that would have read the two
release dates. Every package scores an identical, measured ``0.0``. It is
supplied anyway, because §4 admits it and because "we supplied it and it could
not vary" is the reportable fact; it is not a tested signal at this T.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, FrozenSet, Optional

from abandonment_pilot.cohort import CohortMember
from abandonment_pilot.features import Baselines, build_baselines
from abandonment_pilot.features import build_metadata as build_pilot_metadata
from abandonment_pilot.snapshot import PackageRecord

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.signals import (
    SIGNAL_MAINTAINER,
    SIGNAL_SOURCE_REPOSITORY,
    SIGNAL_STALENESS,
    SIGNAL_VERSION,
)

#: The signals protocol §4 admits. Four of the fifteen the composite scores,
#: and four of the seven reachable without cloning a repository.
HANDOVER_SIGNALS: FrozenSet[str] = frozenset(
    {SIGNAL_MAINTAINER, SIGNAL_SOURCE_REPOSITORY, SIGNAL_STALENESS, SIGNAL_VERSION}
)

#: The two signals the pilot already knew how to supply.
PILOT_REACHABLE: FrozenSet[str] = frozenset(
    {SIGNAL_MAINTAINER, SIGNAL_SOURCE_REPOSITORY}
)


@dataclass(frozen=True)
class HandoverBaselines:
    """The five trivial predictors of protocol §5.

    The first four are the pilot's, unchanged and reused. The fifth is this
    study's, and it exists because six of seven consensus reviewers said the
    frozen maintainer set is stamped at the last release *before* T, so a
    staler package is observed for longer and could show more changes under a
    constant hazard. §5's fix was to make that an opponent rather than an
    argument.
    """

    #: The pilot's four: downloads at T, age, dependency count, stars today.
    pilot: Baselines
    #: Days from the release in force at T to the stage-1 harvest. Never None:
    #: every cohort member has a release in force at T by construction.
    exposure_window_days: int


def build_handover_baselines(
    member: CohortMember,
    moment: datetime,
    record: PackageRecord,
    downloads: Dict[str, int],
    stars: Dict[str, int],
    harvested_at: datetime,
) -> HandoverBaselines:
    """Assemble all five baselines for one cohort member.

    Args:
        member: The cohort member.
        moment: T.
        record: The package's snapshot record.
        downloads: Name -> downloads in the 30 days ending at T.
        stars: Name -> current stargazers of the declared repository.
        harvested_at: When stage 1 read npm's current maintainer arrays.

    Returns:
        The five baselines.
    """
    return HandoverBaselines(
        pilot=build_baselines(member, moment, record, downloads, stars),
        exposure_window_days=(harvested_at - member.last_release_before_t).days,
    )


def staleness_days_at_t(member: CohortMember, moment: datetime) -> int:
    """Return days from the release in force at T to T itself.

    Cohort eligibility bounds this to ``[0, 365]``: a package must have
    released within ``RECENT_ACTIVITY_DAYS`` of T to be in the cohort at all.
    That bound is why the exposure-window confound is 1.4x rather than an order
    of magnitude, and it is also why the *literal* now-relative reading of this
    signal is a constant.

    Args:
        member: The cohort member.
        moment: T.

    Returns:
        Whole days elapsed, non-negative.
    """
    return (moment - member.last_release_before_t).days


def staleness_input(
    member: CohortMember, moment: datetime, reference_now: datetime
) -> datetime:
    """Return the ``last_updated`` that makes the shipped scorer measure T.

    ``RiskScorer._calculate_staleness_score`` buckets
    ``datetime.now(timezone.utc) - last_updated`` in whole days. Supplying
    ``reference_now - staleness_days_at_t`` therefore makes it compute the
    as-of-T bucket, using the shipped thresholds and the shipped arithmetic.

    ``reference_now`` must be captured **before** scoring starts. The scorer
    reads its own clock, so a reference taken afterwards would leave the
    difference a few seconds short of a whole day and could round a package
    down across a bucket boundary.

    Args:
        member: The cohort member.
        moment: T.
        reference_now: A clock reading taken before any scoring.

    Returns:
        The synthetic ``last_updated`` to hand the scorer.
    """
    return reference_now - timedelta(days=staleness_days_at_t(member, moment))


def build_handover_metadata(
    record: PackageRecord,
    member: CohortMember,
    moment: datetime,
    reference_now: datetime,
    enabled: FrozenSet[str] = HANDOVER_SIGNALS,
) -> DependencyMetadata:
    """Build the as-of-T metadata the production scorer reads.

    Ablation is absence, exactly as in the pilot: a signal is removed by
    leaving its input unset, and the scorer drops it from both the numerator
    and the denominator. Nothing here touches a weight.

    Args:
        record: The package's snapshot record.
        member: The cohort member, carrying the release index in force at T.
        moment: T.
        reference_now: A clock reading taken before any scoring.
        enabled: Signals whose inputs are supplied.

    Returns:
        Metadata carrying only as-of-T inputs.
    """
    dependency = build_pilot_metadata(record, member, enabled & PILOT_REACHABLE)

    if SIGNAL_STALENESS in enabled:
        dependency.last_updated = staleness_input(member, moment, reference_now)

    if SIGNAL_VERSION in enabled:
        # The release in force at T *is* the latest release at T. The scorer's
        # equality branch fires and returns 0.0 for every package; see the
        # module docstring. Setting it to anything else would be inventing a
        # drift that did not exist at T.
        dependency.latest_version = record.releases[member.index_at_t][0]

    return dependency


def literal_staleness_input(member: CohortMember) -> datetime:
    """Return the publish time of the release in force at T, unadjusted.

    This is the input a reader would reach for first, and handing it to the
    shipped scorer measures ``now - that release`` — the exposure window, not
    the cadence at T. It is exposed so the study can *report* what that reading
    produces rather than assert it, and it is not used by the model arm.

    Args:
        member: The cohort member.

    Returns:
        The publish time of the release in force at T.
    """
    return member.last_release_before_t


def baseline_value(baselines: HandoverBaselines, name: str) -> Optional[float]:
    """Return one baseline's value, or None where nobody measured it.

    None is never rewritten as zero. A package with no GitHub repository has no
    star count, and writing that down as zero stars hands the star baseline a
    confident value for the packages it knows least about.

    Args:
        baselines: One member's baselines.
        name: A member of :data:`BASELINE_NAMES`.

    Returns:
        The value, or None.

    Raises:
        ValueError: If ``name`` is not a known baseline.
    """
    pilot = baselines.pilot
    if name == "downloads_at_t":
        return None if pilot.downloads_at_t is None else float(pilot.downloads_at_t)
    if name == "age_days":
        return float(pilot.age_days)
    if name == "dep_count":
        return None if pilot.dep_count is None else float(pilot.dep_count)
    if name == "stars_today":
        return None if pilot.stars_today is None else float(pilot.stars_today)
    if name == "exposure_window_days":
        return float(baselines.exposure_window_days)
    raise ValueError(f"unknown baseline {name}")


#: The five, in protocol §5's order. ``exposure_window_days`` is last because
#: it is the one the review added.
BASELINE_NAMES = (
    "downloads_at_t",
    "stars_today",
    "age_days",
    "dep_count",
    "exposure_window_days",
)
