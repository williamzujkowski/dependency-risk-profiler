"""As-of-T inputs for the production scorer, and the trivial baselines.

**This module builds inputs, not scores.** The risk number comes from
``RiskScorer.score_dependency`` exactly as the shipped tool computes it. A
second scoring path written for the experiment would validate the second path,
which is the failure this experiment exists to avoid.

**Ablation is absence, not substitution.** The scorer already distinguishes "we
measured this and it was fine" from "nobody measured this", and excludes the
second from both numerator and denominator. So a signal is ablated by leaving
its input unset, and the scorer does the rest. Nothing here reaches into the
weights.

Ablated for the pilot, per the protocol:

* ``staleness`` — ``last_updated`` is never set. Time since the last release is
  the release cadence, and the outcome is the absence of future releases.
* ``version`` — ``latest_version`` is never set. Version drift is cadence in a
  second notation.

Not available, and therefore honestly unmeasured:

* ``exploit`` — the advisory lookup is recorded as ``NOT_ATTEMPTED``, which is
  what happened: this pilot asks no advisory source anything. The scorer reads
  that state and leaves the signal out of both the numerator and the
  denominator, so no package here is averaged against a clean bill of health
  nobody issued. It carries the tool's largest single weight, 0.5 of 3.5, so
  the difference between an absent signal and a fabricated ``0.0`` is the
  largest one this experiment could make to an absolute score.
* ``deprecation`` — ``is_deprecated`` is left unset, which the scorer reads as
  unmeasured for the same reason. There is no as-of-T value to supply: #312
  established the field is *unreconstructable* at a past date, because npm
  applies ``deprecated`` retroactively to every version of a package, so a
  version document published years before T can carry a flag set after it.
  The signal is therefore excluded from the mean rather than held at a
  constant, and it is the one input this pilot could not have reconstructed
  even with an unlimited harvest budget.
* the eight repository-derived signals — no repository is cloned at T.
* ``transitive`` — npm freezes each version's **direct** dependency list, not
  its resolved closure, and the shipped scorer's transitive signal reads a
  closure. Feeding it a direct count would be scoring a different input than
  production sends, so the count is used only as a trivial baseline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, FrozenSet, Optional

from dependency_risk_profiler.license.analyzer import extract_license_info
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.release_dates import (
    record_source_repository,
    resolve_repository,
)
from dependency_risk_profiler.signals import (
    SIGNAL_LICENSE,
    SIGNAL_MAINTAINER,
    SIGNAL_SOURCE_REPOSITORY,
    AdvisoryLookupState,
)

from .cohort import CohortMember
from .snapshot import PackageRecord, dep_count_at, license_at, repository_at

#: The signals this pilot can both reconstruct at T and vary. Everything else
#: is ablated by the protocol, needs a repository nobody clones here, or has no
#: as-of-T value that any harvest could recover.
PILOT_SIGNALS: FrozenSet[str] = frozenset(
    {SIGNAL_MAINTAINER, SIGNAL_LICENSE, SIGNAL_SOURCE_REPOSITORY}
)


@dataclass(frozen=True)
class Baselines:
    """The four trivial predictors the protocol requires the model to beat.

    Each is ``None`` where nobody could measure it, never zero. A package with
    no GitHub repository has no star count; writing that down as zero stars
    would hand the star baseline a confident value for the packages it knows
    least about.
    """

    #: npm downloads over the 30 days ending at T. A genuine as-of-T series.
    downloads_at_t: Optional[int]
    #: Days from the first release to T.
    age_days: int
    #: Runtime dependencies declared by the release in force at T.
    dep_count: Optional[int]
    #: Stargazers **today**, not at T. GitHub publishes no historical series
    #: and this experiment does not reconstruct one from GH Archive. The
    #: baseline therefore sees information from after T that the model does
    #: not: it knows which projects went on to become popular. That advantage
    #: is deliberate and is left in — a model that cannot beat a baseline
    #: which is allowed to cheat has not been beaten on a technicality.
    stars_today: Optional[int]


def build_baselines(
    member: CohortMember,
    moment: datetime,
    record: PackageRecord,
    downloads: Dict[str, int],
    stars: Dict[str, int],
) -> Baselines:
    """Assemble the trivial baselines for one cohort member.

    Args:
        member: The cohort member.
        moment: T.
        record: The package's snapshot record.
        downloads: Name -> downloads in the 30 days ending at T.
        stars: Name -> current stargazers of the declared repository.

    Returns:
        The baselines, with None wherever a source did not answer.
    """
    return Baselines(
        downloads_at_t=downloads.get(member.name),
        age_days=(moment - member.first_release).days,
        dep_count=dep_count_at(record, member.index_at_t),
        stars_today=stars.get(member.name),
    )


def build_metadata(
    record: PackageRecord,
    member: CohortMember,
    enabled: FrozenSet[str] = PILOT_SIGNALS,
) -> DependencyMetadata:
    """Build the as-of-T metadata the production scorer will read.

    Only facts frozen into version documents published **strictly before T**
    reach this object. ``member.index_at_t`` is the only index any field is
    read at, which is what makes the no-leakage claim checkable rather than
    aspirational: there is one place to audit.

    Args:
        record: The package's snapshot record.
        member: The cohort member, carrying the release index in force at T.
        enabled: Signals whose inputs are supplied. Dropping one from this set
            is the ablation: the scorer then reports it unmeasured and
            renormalizes over the remaining weights.

    Returns:
        Metadata carrying only as-of-T inputs.
    """
    version = record.releases[member.index_at_t][0]
    dependency = DependencyMetadata(name=record.name, installed_version=version)
    dependency.record_advisory_lookup(
        AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=()
    )

    if SIGNAL_MAINTAINER in enabled:
        dependency.maintainer_count = len(member.maintainers)

    if SIGNAL_LICENSE in enabled:
        declared = license_at(record, member.index_at_t)
        if declared is not None:
            dependency.license_info = extract_license_info({"license": declared})

    if SIGNAL_SOURCE_REPOSITORY in enabled:
        url = repository_at(record, member.index_at_t)
        record_source_repository(dependency, resolve_repository([url]))

    return dependency
