"""Per-ecosystem measured-signal floors for the adapter regression tests.

The scorer calls a dependency UNKNOWN when it can measure fewer signals than it
cannot (``unknown > measured``), so an adapter that reads only two fields off
its registry payload scores UNKNOWN for *every* dependency while still looking
like it ran. That was #127 (rubygems, 167/167 UNKNOWN) and #132 (cargo and
composer, 0% scored on ripgrep and drupal), one root cause each time: registry
metadata never reached the fields the scorer reads.

Each floor below is what its ecosystem must be able to measure from **registry
metadata alone** — no repository clone, no GitHub token — which is the weakest
environment the tool runs in and the one a regression shows up in first. The
numbers are deliberately conservative: they pin the seven signals a registry
payload can answer (release cadence, maintainers, deprecation, version drift,
license, community, exploit), not the ~14 a full run reaches. Transitive
resolution is not among them: it only understands npm lockfiles and Python
requirement sets, so for these three ecosystems the signal is honestly
unmeasured (#141) and :func:`mark_transitive_unmeasured` reproduces that here
rather than letting an empty set score as "no transitive risk".

Seven of fourteen is exactly the edge: the scorer flips to UNKNOWN at
``unmeasured > measured``, so a registry payload is *just* enough on its own
and losing any one field takes the whole ecosystem back to the all-UNKNOWN
state of #127 / #132. That is the property worth pinning. (#146 added a
fifteenth signal, ``source_repository``, for the adapters that report the
registry's answer; the floor stays at seven because the point is the edge, not
the ceiling.)

:func:`assert_abandoned_package_is_scored` pins the same property from the
other direction, for #146: a package abandoned a decade ago must still produce
a measured release cadence and a risk verdict, because that is the population
the maintenance-cadence signal exists to flag and the one it used to fail on.

This module is the seam #73's adapter-conformance harness should grow into:
when that lands, it should consume this table rather than each adapter test
restating the reasoning.
"""

from datetime import datetime, timezone
from typing import Dict

from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.transitive.analyzer_enhanced import (
    TRANSITIVE_SOURCE_KEY,
    TRANSITIVE_SOURCE_UNMEASURED,
)

# Minimum signals an ecosystem must measure from registry metadata alone.
#
# nuget sits one above the rest because its registry publishes one more thing:
# a package's ``.nuspec`` states the package's own dependencies, so the
# transitive signal is genuinely measured rather than absent (#129). The other
# three have no per-package dependency document to read and leave it unmeasured.
MIN_MEASURED_SIGNALS: Dict[str, int] = {
    "cargo": 7,
    "composer": 7,
    "nuget": 8,
    "nodejs": 7,
    "python": 7,
    "rubygems": 7,
}

# Whether that floor is on its own enough to clear the insufficient-data bar.
# crates.io, Packagist and RubyGems each answer a maintainer count (an owners
# endpoint, or the package's declared authors); PyPI and npm publish no cheap
# equivalent, so those two land one signal short without a clone. That is a
# real difference between registries and it is recorded here rather than
# papered over with a guessed maintainer count.
SCORES_FROM_REGISTRY_ALONE: Dict[str, bool] = {
    "cargo": True,
    "composer": True,
    "nodejs": False,
    "nuget": True,
    "python": False,
    "rubygems": True,
}

# The two tables above are keyed by the same ecosystems and are edited by
# different people at different times: #129 added nuget to the floors while
# #146 was independently adding this second table, and the two only met at a
# rebase, where the missing key surfaced as a KeyError instead of a readable
# failure. Keep them in lockstep so a half-registered ecosystem fails here,
# naming itself, rather than deep inside an adapter test.
_FLOORS_ONLY = sorted(MIN_MEASURED_SIGNALS.keys() - SCORES_FROM_REGISTRY_ALONE.keys())
_VERDICT_ONLY = sorted(SCORES_FROM_REGISTRY_ALONE.keys() - MIN_MEASURED_SIGNALS.keys())
assert not _FLOORS_ONLY and not _VERDICT_ONLY, (
    "signal_floors tables have drifted; "
    f"in MIN_MEASURED_SIGNALS only: {_FLOORS_ONLY}, "
    f"in SCORES_FROM_REGISTRY_ALONE only: {_VERDICT_ONLY}"
)

# The oldest release date the tool must still describe as a measured cadence.
# Nothing here asserts a *specific* date: the property is that a decade-dead
# package produces a number at all.
ABANDONED_PACKAGE_MIN_AGE_DAYS = 3650


def mark_transitive_unmeasured(dependency: DependencyMetadata) -> DependencyMetadata:
    """Mark transitive resolution as not having run, as it does for these ecosystems.

    The real pipeline applies this marker to every manifest that is not an npm
    lockfile or a Python requirement set, so an offline adapter test that skips
    it would credit the ecosystem with a signal it never measures.

    Args:
        dependency: Dependency metadata to mark in place.

    Returns:
        The same dependency, for chaining.
    """
    dependency.additional_info[TRANSITIVE_SOURCE_KEY] = TRANSITIVE_SOURCE_UNMEASURED
    return dependency


def assert_meets_signal_floor(score: DependencyRiskScore, ecosystem: str) -> None:
    """Assert a scored dependency clears its ecosystem's measured-signal floor.

    Args:
        score: Risk score produced with no clone and no GitHub token.
        ecosystem: Registry key present in :data:`MIN_MEASURED_SIGNALS`.

    Raises:
        AssertionError: If the ecosystem measures too few signals to be scored,
            i.e. it has regressed to the all-UNKNOWN state of #127 / #132. The
            verdict half of the check applies only to the registries that can
            reach it unaided, per :data:`SCORES_FROM_REGISTRY_ALONE`.
    """
    floor = MIN_MEASURED_SIGNALS[ecosystem]

    assert score.measured_signal_count >= floor, (
        f"{ecosystem} measured only {score.measured_signal_count} of "
        f"{score.total_signal_count} signals (floor {floor}); "
        f"unmeasured: {score.unknown_signals}"
    )
    if not SCORES_FROM_REGISTRY_ALONE[ecosystem]:
        return
    assert score.insufficient_data is False, (
        f"{ecosystem} is still short of the insufficient-data bar: "
        f"{score.unknown_signal_count} unmeasured vs "
        f"{score.measured_signal_count} measured"
    )
    assert (
        score.risk_level is not RiskLevel.UNKNOWN
    ), f"{ecosystem} scored UNKNOWN from a complete registry payload"


def assert_abandoned_package_is_scored(
    score: DependencyRiskScore, now: datetime
) -> None:
    """Assert a long-dead package still gets a measured cadence and a verdict.

    This is #146's floor, and it is the inverse of the one above: not "a
    healthy package scores" but "an abandoned one does". Staleness used to be
    derived from the repository, so the packages most likely to have an
    archived, renamed, or never-declared repository — the ones the signal
    exists to catch — were exactly the ones that produced no cadence at all
    and fell through to UNKNOWN.

    Args:
        score: Risk score for a package abandoned more than a decade ago.
        now: Reference time to measure the release gap against.

    Raises:
        AssertionError: If the cadence is unmeasured, understates a decade-plus
            gap, or the dependency is still short of a risk verdict.
    """
    name = score.dependency.name
    last_updated = score.dependency.last_updated
    assert last_updated is not None, f"{name}: release cadence is still unmeasured"

    reference = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    measured = (
        last_updated
        if last_updated.tzinfo is not None
        else last_updated.replace(tzinfo=timezone.utc)
    )
    gap_days = (reference - measured).days
    assert gap_days >= ABANDONED_PACKAGE_MIN_AGE_DAYS, (
        f"{name}: release gap of {gap_days} days does not reflect an "
        f"abandoned package"
    )

    assert score.staleness_score == 1.0, (
        f"{name}: a decade-old release must score maximum staleness, "
        f"got {score.staleness_score}"
    )
    assert score.insufficient_data is False, (
        f"{name}: still short of the insufficient-data bar with "
        f"{score.unknown_signal_count} unmeasured vs "
        f"{score.measured_signal_count} measured"
    )
    assert (
        score.risk_level is not RiskLevel.UNKNOWN
    ), f"{name}: abandoned package still scored UNKNOWN"
