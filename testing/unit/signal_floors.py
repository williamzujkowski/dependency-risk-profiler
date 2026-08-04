"""Per-ecosystem measured-signal floors for the adapter regression tests.

The scorer calls a dependency UNKNOWN when it can measure fewer signals than it
cannot (``unknown > measured``), so an adapter that reads only two fields off
its registry payload scores UNKNOWN for *every* dependency while still looking
like it ran. That was #127 (rubygems, 167/167 UNKNOWN) and #132 (cargo and
composer, 0% scored on ripgrep and drupal), one root cause each time: registry
metadata never reached the fields the scorer reads.

Each floor below is what its ecosystem must be able to measure from **registry
metadata alone** — no repository clone, no GitHub token — which is the weakest
environment the tool runs in and the one a regression shows up in first.
Transitive resolution is not among those signals for most ecosystems: it only
understands npm lockfiles and Python requirement sets, and a lockfile is not
registry metadata, so :func:`mark_transitive_unmeasured` reproduces the
unmeasured marker here (#141) rather than letting an empty set score as "no
transitive risk". Three registries are the exception, because each publishes
the package's own dependency list beside it: nuget in the ``.nuspec`` (#129),
maven in the POM's ``<dependencies>``, and — since #180 — composer in the p2
entry's ``require`` block, minus the platform constraints (``php``, ``ext-*``)
that are runtimes rather than packages.

**The floor sits at the measured value, not below it.** Every number here was
read off the offline adapter test it guards, and it is the exact count that
test produces today — not a round number with headroom. Headroom is what this
table used to have and it was the bug (#136): every ecosystem was pinned at
seven, and seven of fourteen is precisely where the scorer flips to UNKNOWN
(``unmeasured > measured``). A floor of seven therefore admitted a *fully
collapsed* ecosystem — the all-UNKNOWN state of #127 / #132 — while still
reporting green. Dropping cargo's license field takes it from eight measured
to seven and straight to UNKNOWN, and the old floor passed that. So: a floor
below the measured value is not a floor, it is a permission slip.

The consequence is that this table ratchets. Improve an ecosystem's coverage
and you raise its number in the same change; that is the intended cost, and it
is how a conformance gate differs from a smoke test. The collapse arithmetic
itself is still worth documenting, so it lives in ``test_signal_floors.py`` as
its own assertion instead of masquerading as the floor.

Where the numbers come from: crates.io, PyPI, RubyGems, NuGet and Maven Central
each answer eight signals unaided and Packagist answers nine; npm answers seven,
landing one short of the insufficient-data bar because it publishes no cheap
maintainer count. :data:`SCORES_FROM_REGISTRY_ALONE` records that difference
rather than papering over it. PyPI was in npm's column until #171: it publishes
a top-level ``ownership`` object the adapter had never read, and reading it
moved python from seven to eight.

Packagist is the highest of the eight for the same reason: #180 found the p2
entry's ``require`` block unread, which is the only registry document that
answers a maintainer count *and* a dependency list, so composer measures
everything nuget does plus everything cargo does. maven's floor did not move
when #178 closed the parent-POM gap, and that is not an oversight — maven was
already floored at everything Maven Central can answer, and the artifacts the
fix rescues (guava, slf4j-api: licence and repository declared only in a parent)
were below the floor rather than at it. The re-baseline there is in
``adapter_conformance``, where both cases now assert the floor instead of
asserting their own blindness.

The Go module proxy is the outlier at six, and its floor is set where it is on
purpose. ``proxy.golang.org`` publishes a version, a release date and a
``go.mod``; it publishes no licence and no owner list, because Go has neither
concept at the module level. Six is what golang measures today and therefore
what it is floored at — the number was read off the conformance fixtures rather
than rounded up to match its neighbours, because a floor above measured
coverage is a test that fails for a reason nobody can fix, and a floor below it
is a permission slip (#158). Go modules do not clear the insufficient-data bar
from proxy metadata alone, and that is recorded rather than papered over too.

maven's floor is the newest of the eight and it did not exist before #73's
conformance capture: #141 had left the ecosystem with no entry in this table at
all. Both readings behind it were found by the same capture —
``maven-metadata.xml`` states ``<lastUpdated>`` and nothing read it, and the
adapter never recorded whether the POM declares a source repository — so the
floor is eight rather than the six it would have been.

:data:`REGISTRY_MEASURED_SIGNALS` names the signals behind each count, because
a count cannot see a swap: an ecosystem that loses one signal and gains another
holds its total steady while a real regression lands. Naming them is #145's
first item ("extend it from a count to a per-signal set").

It is not all of #145. The dead read that issue is named for — npm looked for a
top-level ``deprecated`` key that npm has never sent, so no npm package could
ever be flagged deprecated (#142) — would still pass here, because the
deprecation score is computed from a boolean that defaults to False and is
therefore always "measured", just always measured wrong. Catching that needs an
assertion on a signal's *value* against a live-captured fixture.

That half now exists, in ``adapter_conformance`` (#73). It consumes the tables
below rather than restating them, adds per-signal *value* assertions against
provenance-dated payloads captured from the live registries, and enforces the
rule the npm case generalizes to: every signal whose read collapses to a fixed
default when its key is absent needs at least one fixture where the correct
answer is the non-default value. All eight ecosystems are now converted;
``adapter_conformance.CONVERSION_STATUS`` carries the ledger, and
``unproven_branches()`` names every polarized branch no captured payload can
reach, with the reason.

:func:`assert_abandoned_package_is_scored` pins the same property from the
other direction, for #146: a package abandoned a decade ago must still produce
a measured release cadence and a risk verdict, because that is the population
the maintenance-cadence signal exists to flag and the one it used to fail on.

Refresh cadence: every floor here is now backed by payloads captured from the
live registry into ``testing/fixtures/registry/``, each carrying its source URL
and capture date, refreshed with ``scripts/capture_registry_fixtures.py`` — see
``registry_fixtures`` for the cadence and who owns it. Adapters keep their own
hand-written fixtures for the paths a captured payload cannot reach (a fallback
that depends on trimmed volume, an error branch); those are legitimate uses of a
synthetic fixture and are not floors. A floor is only as honest as the fixture
underneath it.
"""

from datetime import datetime, timezone
from typing import Dict, FrozenSet

from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.transitive.analyzer_enhanced import (
    TRANSITIVE_SOURCE_KEY,
    TRANSITIVE_SOURCE_UNMEASURED,
)

# Minimum signals an ecosystem must measure from registry metadata alone, set
# at what each one measures today. Raising these is a normal part of improving
# an adapter; lowering one is a regression that needs a reason in the commit.
#
# npm sits one below the rest because it publishes no maintainer count without
# a clone. PyPI used to sit beside it and no longer does: it publishes the
# project's role assignments in a top-level ``ownership`` object the adapter
# had never read (#171), found by capturing a live payload for the conformance
# harness. Everything above that line clears the insufficient-data bar by
# exactly one signal, which is why the identity table below matters as much as
# these counts do — except composer, which since #180 clears it by two.
MIN_MEASURED_SIGNALS: Dict[str, int] = {
    "cargo": 8,
    "composer": 9,
    "golang": 6,
    "maven": 8,
    "nuget": 9,
    "nodejs": 7,
    "python": 8,
    "rubygems": 8,
}

# Which signals make up each count. Asserted by name so that losing one signal
# and gaining another fails instead of passing under an unchanged total (#145).
#
# The membership differences are real registry differences, not oversights:
# cargo, composer, python and rubygems answer a maintainer count and report
# whether a source repository is declared; nuget serves per-package
# dependencies in its ``.nuspec`` and so measures ``transitive`` on top of
# that, which is why it is the only ecosystem floored at nine; npm publishes no
# cheap maintainer count.
#
# nuget used to be the odd one out for a second, worse reason: it resolved a
# repository off the nuspec and then recorded nothing about whether one was
# declared, so it alone measured 15 signals where the rest measured 16 and the
# absence read as though nuget.org had said nothing either way. It does say
# something — the nuspec either carries ``<repository>`` or it does not — so
# the floor moved 8 -> 9 with the signal added here in the same change (#183,
# #158).
_REGISTRY_CORE: FrozenSet[str] = frozenset(
    {
        "staleness",
        "deprecation",
        "exploit",
        "version",
        "license",
        "community",
    }
)
REGISTRY_MEASURED_SIGNALS: Dict[str, FrozenSet[str]] = {
    "cargo": _REGISTRY_CORE | {"maintainer", "source_repository"},
    "composer": _REGISTRY_CORE | {"maintainer", "source_repository", "transitive"},
    "golang": (_REGISTRY_CORE - {"license"}) | {"source_repository"},
    "maven": _REGISTRY_CORE | {"transitive", "source_repository"},
    "nuget": _REGISTRY_CORE | {"maintainer", "transitive", "source_repository"},
    "nodejs": _REGISTRY_CORE | {"source_repository"},
    "python": _REGISTRY_CORE | {"maintainer", "source_repository"},
    "rubygems": _REGISTRY_CORE | {"maintainer", "source_repository"},
}

# Whether that floor is on its own enough to clear the insufficient-data bar.
# crates.io, Packagist, PyPI and RubyGems each answer a maintainer count (an
# owners endpoint, a role list, or the package's declared authors); npm
# publishes no cheap equivalent, so it lands one signal short without a clone.
# That is a real difference between registries and it is recorded here rather
# than papered over with a guessed maintainer count.
#
# python moved to True when #171 was settled against a live payload: PyPI's
# top-level ``ownership`` object lists every account holding a role on the
# project. The honest caveat is captured rather than hidden — a project
# transferred to a PyPI organization reports ``roles: []`` and its maintainer
# count stays unmeasured, so it lands back at seven and does not reach a
# verdict. ``adapter_conformance``'s ``python/flask`` case is that package, and
# the floor here is what a project PyPI does answer for must measure.
SCORES_FROM_REGISTRY_ALONE: Dict[str, bool] = {
    "cargo": True,
    "composer": True,
    "golang": False,
    "maven": True,
    "nodejs": False,
    "nuget": True,
    "python": True,
    "rubygems": True,
}

# The tables above are keyed by the same ecosystems and are edited by different
# people at different times: #129 added nuget to the floors while #146 was
# independently adding the verdict table, and the two only met at a rebase,
# where the missing key surfaced as a KeyError instead of a readable failure.
# Keep them in lockstep so a half-registered ecosystem fails here, naming
# itself, rather than deep inside an adapter test.
_ECOSYSTEMS = frozenset(MIN_MEASURED_SIGNALS)
_TABLES = {
    "SCORES_FROM_REGISTRY_ALONE": frozenset(SCORES_FROM_REGISTRY_ALONE),
    "REGISTRY_MEASURED_SIGNALS": frozenset(REGISTRY_MEASURED_SIGNALS),
}
_DRIFT = {
    name: (sorted(_ECOSYSTEMS - keys), sorted(keys - _ECOSYSTEMS))
    for name, keys in _TABLES.items()
    if keys != _ECOSYSTEMS
}
assert not _DRIFT, (
    "signal_floors tables have drifted from MIN_MEASURED_SIGNALS; "
    f"(missing, extra) per table: {_DRIFT}"
)

# The count and the named set are two views of one measurement, so a floor that
# does not match its own signal list is a typo waiting to be argued about.
_MISCOUNTED = {
    ecosystem: (floor, sorted(REGISTRY_MEASURED_SIGNALS[ecosystem]))
    for ecosystem, floor in MIN_MEASURED_SIGNALS.items()
    if floor != len(REGISTRY_MEASURED_SIGNALS[ecosystem])
}
assert not _MISCOUNTED, (
    "MIN_MEASURED_SIGNALS disagrees with REGISTRY_MEASURED_SIGNALS; "
    f"(floor, named signals) per ecosystem: {_MISCOUNTED}"
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

    It also leaves an adapter's own record alone, and so does this: nuget reads
    its ``.nuspec`` dependencies, maven its POM's ``<dependencies>`` and
    composer the p2 entry's ``require`` block, all three of which are real
    measurements the adapter stamps with its own source. An empty
    ``<dependencies>`` block on an artifact that declares none is a measured
    zero, not an unmeasured one — as is a ``require`` block holding nothing but
    ``php`` — and overwriting the stamp here would report it as unmeasured while
    the pipeline reports it as measured (see
    ``transitive.analyzer_enhanced``, which skips dependencies that already
    carry a source).

    Args:
        dependency: Dependency metadata to mark in place.

    Returns:
        The same dependency, for chaining.
    """
    if not dependency.additional_info.get(TRANSITIVE_SOURCE_KEY):
        dependency.additional_info[TRANSITIVE_SOURCE_KEY] = TRANSITIVE_SOURCE_UNMEASURED
    return dependency


def assert_measures_registry_signals(
    score: DependencyRiskScore, ecosystem: str
) -> None:
    """Assert every signal the ecosystem's registry can answer was measured.

    The identity half of the gate. A count alone cannot tell "npm still reads
    seven signals" from "npm lost one signal and picked up another", so the
    names are checked too (#145). This is a floor, not an inventory: measuring
    *more* than the recorded set is fine, and should be followed by adding the
    new signal to :data:`REGISTRY_MEASURED_SIGNALS`.

    Args:
        score: Risk score produced with no clone and no GitHub token.
        ecosystem: Registry key present in :data:`REGISTRY_MEASURED_SIGNALS`.

    Raises:
        AssertionError: If any recorded signal came back unmeasured.
    """
    required = REGISTRY_MEASURED_SIGNALS[ecosystem]
    lost = sorted(required.intersection(score.unknown_signals))

    assert not lost, (
        f"{ecosystem} no longer measures {lost} from registry metadata; "
        f"the count can stay flat while a signal is swapped out, which is why "
        f"these are named. All unmeasured: {sorted(score.unknown_signals)}"
    )


def assert_meets_signal_floor(score: DependencyRiskScore, ecosystem: str) -> None:
    """Assert a scored dependency clears its ecosystem's measured-signal floor.

    Args:
        score: Risk score produced with no clone and no GitHub token.
        ecosystem: Registry key present in :data:`MIN_MEASURED_SIGNALS`.

    Raises:
        AssertionError: If the ecosystem measures too few signals, measures the
            wrong ones, or has regressed to the all-UNKNOWN state of #127 /
            #132. The verdict half of the check applies only to the registries
            that can reach it unaided, per :data:`SCORES_FROM_REGISTRY_ALONE`.
    """
    floor = MIN_MEASURED_SIGNALS[ecosystem]

    assert score.measured_signal_count >= floor, (
        f"{ecosystem} measured only {score.measured_signal_count} of "
        f"{score.total_signal_count} signals (floor {floor}); "
        f"unmeasured: {score.unknown_signals}"
    )
    assert_measures_registry_signals(score, ecosystem)
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
