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

Transitive resolution used to be excluded from that for most ecosystems, on the
grounds that it understood only npm lockfiles and Python requirement sets and a
lockfile is not registry metadata. That was never the whole story, and #204
retired it: eight of the nine registries publish the package's own dependency
list beside it, and now eight of the nine adapters read it. nuget from the
``.nuspec`` (#129), maven from the POM's scope-filtered ``<dependencies>``,
composer from the p2 ``require`` block minus platform constraints (#180), and —
new in #204 — nodejs from ``versions[<latest>].dependencies``, python from
``info.requires_dist``, rubygems from ``dependencies.runtime``, and cargo from
the per-version dependencies endpoint, which is the one of the four that costs
a request rather than reading a payload already in hand. gradle inherits
maven's read rather than earning its own; it reaches the same POM through the
same analyzer, and it is listed explicitly in
``TRANSITIVE_RECORDING_ECOSYSTEMS`` so that the route going quiet fails there
instead of passing as a plausible ``None``.

golang is the one abstainer, and it says so out loud rather than staying quiet:
``go.mod`` states no dependency scope, so a module's test-only requirements sit
in the same direct ``require`` block as its runtime ones and the block cannot
answer the question the signal asks. Nothing in the harness marks any of this
on an adapter's behalf — :func:`mark_transitive_unmeasured` existed to
reproduce the pipeline's marker here (#141) and was deleted with #199, which
made an unset marker read as unmeasured everywhere. So golang is scored as
unmeasured *because its adapter said so*, which is the property
``adapter_conformance.assert_transitive_is_recorded_not_assumed`` pins from
both directions.

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

Where the numbers come from: crates.io, PyPI, RubyGems, Packagist and NuGet each
answer nine signals unaided, Maven Central answers eight and npm answers eight,
which is exactly the insufficient-data bar. :data:`SCORES_FROM_REGISTRY_ALONE`
records where each lands rather than papering over it. PyPI was one short until
#171: it publishes a top-level ``ownership`` object the adapter had never read.
npm was one short until #204, which is the change that retired the last ``False``
in that table — npm still publishes no cheap maintainer count, and the
dependency list in its version manifest is the signal that replaces it. It
clears the bar by nothing at all, eight measured against eight unmeasured, so
losing any one signal puts express back to UNKNOWN. That is a true statement
about npm rather than a comfortable one.

Packagist used to be the highest of the eight on its own: #180 found the p2
entry's ``require`` block unread, which made it the only registry document that
answered a maintainer count *and* a dependency list. #204 closed that gap from
the other side, so cargo, python and rubygems now sit level with it at nine.
maven's floor did not move
when #178 closed the parent-POM gap, and that is not an oversight — maven was
already floored at everything Maven Central can answer, and the artifacts the
fix rescues (guava, slf4j-api: licence and repository declared only in a parent)
were below the floor rather than at it. The re-baseline there is in
``adapter_conformance``, where both cases now assert the floor instead of
asserting their own blindness.

gradle is the one entry here that is not a registry. Gradle publishes Maven
coordinates and resolves against Maven Central, so its floor is maven's floor
and its signal set is maven's signal set, deliberately and to the letter — a
different number would mean the route had lost something on the way through the
build-script parser, which is precisely what this entry exists to catch. #127's
collapse arrived through registry metadata never reaching the scorer; the Gradle
equivalent arrives through a parse producing a key Maven Central is not
addressed by, and it looks identical from here: every dependency UNKNOWN, every
other count green. That is why an ecosystem with no registry of its own still
gets a floor, and why its conformance case runs the real parser over a captured
build script rather than handing the analyzer a coordinate by hand (#101).

The Go module proxy is the outlier at six, and its floor is set where it is on
purpose. ``proxy.golang.org`` publishes a version, a release date and a
``go.mod``; it publishes no licence and no owner list, because Go has neither
concept at the module level, and the ``go.mod``'s ``require`` block states no
scope, so it cannot answer a runtime dependency count either (#204). Six is the
number that survived #204 unchanged for that reason, and it is a real registry
difference rather than an unfinished adapter. Six is what golang measures today
and therefore
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
answer is the non-default value. All nine ecosystems are now converted;
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

from dependency_risk_profiler.models import DependencyRiskScore, RiskLevel

# Minimum signals an ecosystem must measure from registry metadata alone, set
# at what each one measures today. Raising these is a normal part of improving
# an adapter; lowering one is a regression that needs a reason in the commit.
#
# npm still sits below the registries that publish a maintainer count, and it
# still publishes none without a clone; what moved it 7 -> 8 is #204's read of
# the version manifest's dependency list. PyPI, RubyGems and crates.io moved
# 8 -> 9 in the same change, and cargo's nine is the only one of the four that
# costs an extra request to reach.
#
# Everything at nine clears the insufficient-data bar by one signal. npm clears
# it by none — eight measured against eight unmeasured — which is recorded here
# rather than rounded away, because it means npm is the ecosystem where losing
# any single signal returns every package to UNKNOWN.
MIN_MEASURED_SIGNALS: Dict[str, int] = {
    "cargo": 9,
    "composer": 9,
    "golang": 6,
    "gradle": 8,
    "maven": 8,
    "nuget": 9,
    "nodejs": 8,
    "python": 9,
    "rubygems": 9,
}

# Which signals make up each count. Asserted by name so that losing one signal
# and gaining another fails instead of passing under an unchanged total (#145).
#
# The membership differences are real registry differences, not oversights.
# Since #204 the transitive signal is the near-universal one: every registry
# here publishes the package's own dependency list somewhere, and every adapter
# but golang's reads it. What still separates the ecosystems is the maintainer
# count — npm publishes none cheaply, and Go has no module-level owner concept
# at all — plus Go's missing licence field and its scopeless ``go.mod``, which
# is why golang is short by three rather than by one.
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
    "cargo": _REGISTRY_CORE | {"maintainer", "source_repository", "transitive"},
    "composer": _REGISTRY_CORE | {"maintainer", "source_repository", "transitive"},
    "golang": (_REGISTRY_CORE - {"license"}) | {"source_repository"},
    "gradle": _REGISTRY_CORE | {"transitive", "source_repository"},
    "maven": _REGISTRY_CORE | {"transitive", "source_repository"},
    "nuget": _REGISTRY_CORE | {"maintainer", "transitive", "source_repository"},
    "nodejs": _REGISTRY_CORE | {"source_repository", "transitive"},
    "python": _REGISTRY_CORE | {"maintainer", "source_repository", "transitive"},
    "rubygems": _REGISTRY_CORE | {"maintainer", "source_repository", "transitive"},
}

# Whether that floor is on its own enough to clear the insufficient-data bar.
#
# python moved to True when #171 was settled against a live payload: PyPI's
# top-level ``ownership`` object lists every account holding a role on the
# project. The honest caveat is captured rather than hidden — a project
# transferred to a PyPI organization reports ``roles: []`` and its maintainer
# count stays unmeasured. ``adapter_conformance``'s ``python/flask`` case is
# that package, and the floor here is what a project PyPI does answer for must
# measure.
#
# nodejs moved to True with #204 and is the last entry to have moved. npm still
# publishes no cheap maintainer count, so the signal that got it over the bar
# is the dependency list in ``versions[<latest>]``, which was in the packument
# the adapter already fetched the whole time. It clears by zero margin: eight
# measured, eight unmeasured, and ``unmeasured > measured`` is what the bar
# tests. Losing any one signal puts every npm package back to UNKNOWN, which is
# worth knowing rather than smoothing over.
#
# golang is the only False left, and it is a registry fact rather than an
# unfinished adapter: proxy.golang.org publishes no licence, no owner list, and
# a ``go.mod`` with no dependency scope in it (#204).
SCORES_FROM_REGISTRY_ALONE: Dict[str, bool] = {
    "cargo": True,
    "composer": True,
    "golang": False,
    "gradle": True,
    "maven": True,
    "nodejs": True,
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
