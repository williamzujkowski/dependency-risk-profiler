"""The activity battery, and the two composites, as of T.

`docs/composition-protocol.md` §3 fixes the battery and §2 the two composites.
Everything is read from the pinned snapshot at `member.index_at_t`, so nothing
here can see past T except where the protocol says a measure deliberately does.

The two composites differ by exactly two signals:

- **ablated** — `maintainer`, `license`, `source_repository`. What the
  abandonment pilot scores.
- **shipped** — the same three plus `staleness` and `version`, supplied from
  the release in force at T.

§8.1 requires that difference to be the *whole* difference, which is checked by
an invariance test rather than asserted here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from abandonment_pilot.cohort import CohortMember
from abandonment_pilot.features import PILOT_SIGNALS, build_metadata
from abandonment_pilot.snapshot import PackageRecord
from dependency_risk_profiler.models import DependencyMetadata

#: The five battery members, in the order every table reports them.
BATTERY = (
    "days_since_last_release",
    "releases_1y",
    "releases_90d",
    "releases_total",
    "release_span_days",
)


@dataclass(frozen=True)
class Activity:
    """One package's publication activity as of T. No score, no label."""

    days_since_last_release: float
    releases_1y: float
    releases_90d: float
    releases_total: float
    release_span_days: float

    def as_vector(self) -> Tuple[float, ...]:
        return tuple(getattr(self, name) for name in BATTERY)


def _timestamps(record: PackageRecord, upto_index: int) -> List[datetime]:
    """Release timestamps at or before the index in force at T."""
    return [record.releases[i][1] for i in range(upto_index + 1)]


def activity_at(
    record: PackageRecord, member: CohortMember, moment: datetime
) -> Activity:
    """Build the battery for one cohort member.

    Only releases up to `member.index_at_t` are read, which is the same index
    every as-of-T field in this repository is read at. A package whose entire
    history is one release has a span of zero, which is a real value rather
    than missing data.
    """
    stamps = _timestamps(record, member.index_at_t)
    last = max(stamps)
    first = min(stamps)
    year_ago = moment - timedelta(days=365)
    ninety = moment - timedelta(days=90)
    return Activity(
        days_since_last_release=float((moment - last).days),
        releases_1y=float(sum(1 for s in stamps if s > year_ago)),
        releases_90d=float(sum(1 for s in stamps if s > ninety)),
        releases_total=float(len(stamps)),
        release_span_days=float((last - first).days),
    )


def shipped_metadata(
    record: PackageRecord, member: CohortMember
) -> DependencyMetadata:
    """The ablated metadata plus the two cadence signals, as of T.

    `last_updated` is the timestamp of the release in force at T and
    `latest_version` is that release's version — both as-of-T facts, not
    today's. Setting `latest_version` equal to `installed_version` means the
    scorer's equality branch returns 0.0 for every package, which is the
    #312/`version`-at-single-T problem the outcome landscape records. That is
    deliberately not worked around: it is what the shipped scorer would compute
    from as-of-T inputs, and pretending otherwise would score a package against
    a version that did not exist yet.
    """
    dependency = build_metadata(record, member, enabled=PILOT_SIGNALS)
    version, published = record.releases[member.index_at_t]
    dependency.last_updated = published
    dependency.latest_version = version
    return dependency


def ablated_metadata(
    record: PackageRecord, member: CohortMember
) -> DependencyMetadata:
    """Exactly what the abandonment pilot scores: three signals, no timestamps."""
    return build_metadata(record, member, enabled=PILOT_SIGNALS)


def signal_scores(result: object) -> Dict[str, Optional[float]]:
    """Per-signal sub-scores, for §4's decomposition.

    Returns None where the scorer reported a signal unmeasured, never 0.0 — the
    distinction the whole scorer is built around, and flattening it here would
    make an abstention look like a clean bill of health.
    """
    names = (
        "staleness_score",
        "maintainer_score",
        "license_score",
        "version_score",
        "source_repository_score",
    )
    return {name: getattr(result, name, None) for name in names}
