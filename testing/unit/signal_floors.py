"""Per-ecosystem measured-signal floors for the adapter regression tests.

The scorer calls a dependency UNKNOWN when it can measure fewer signals than it
cannot (``unknown > measured``), so an adapter that reads only two fields off
its registry payload scores UNKNOWN for *every* dependency while still looking
like it ran. That was #127 (rubygems, 167/167 UNKNOWN) and #132 (cargo and
composer, 0% scored on ripgrep and drupal), one root cause each time: registry
metadata never reached the fields the scorer reads.

Each floor below is what its ecosystem measures in the **weakest deployment
mode the tool has**: no repository clone, no GitHub token, and no advisory
lookup. That is the mode a regression shows up in first, and it is also the
mode a great many real scans run in.

What that mode can reach at all
-------------------------------
The scorer weighs sixteen signals. Eight of them are out of reach here before
any adapter is written, and naming them is what makes every floor below a
subtraction rather than an opinion:

* **Seven need the source repository.** ``health_indicators``,
  ``community_activity``, ``security_policy``, ``dependency_update``,
  ``signed_commits``, ``branch_protection`` and ``maintained`` are read from a
  clone's worktree, its git history, or an authenticated forge API. With
  cloning off and no token there is nothing to read.
* **``exploit`` needs an advisory source, and none is asked.** Vulnerability
  lookup is opt-in on the analyze path and off entirely here, so the advisory
  state stays ``NOT_ATTEMPTED`` and the signal leaves both the numerator and
  the denominator. It scored ``0.0`` for every package in this mode until
  #321: ``has_known_exploits`` defaults to ``False``, and an unrecorded lookup
  state read as measured, so the tool's largest single weight published a
  confident clean answer nobody had asked for.

``community_popularity`` is the one repository-derived signal that survives,
and it is worth stating plainly rather than leaving inside a count: it is a
star count regex-scraped off an unauthenticated github.com page, which needs
no clone and no token. The eight remaining candidates are therefore
``staleness``, ``maintainer``, ``deprecation``, ``version``, ``license``,
``community``, ``transitive`` and ``source_repository``.

Where each ecosystem lands, and why
-----------------------------------
Eight is the ceiling. Every floor below it is a registry that does not publish
one of the eight, not an adapter that has not got round to it:

===========  =====  =====================================================
Ecosystem    Floor  What the registry does not answer
===========  =====  =====================================================
cargo            8  —
composer         8  —
nuget            8  —
python           8  —
rubygems         8  —
nodejs           7  ``maintainer``: npm publishes no cheap owner count.
maven            6  ``maintainer`` (``<developers>`` is inherited free
                    text), ``deprecation`` (Maven Central publishes no
                    retirement marker of any kind — see #179).
gradle           6  the same two, by construction: Gradle publishes Maven
                    coordinates and resolves against Maven Central, so a
                    different number here would mean the route lost
                    something on the way through the build-script parser.
golang           5  ``maintainer`` (Go has no module-level owner concept),
                    ``license`` (proxy.golang.org publishes none), and
                    ``transitive`` (``go.mod``'s ``require`` block states
                    no scope, so it cannot answer a *runtime* dependency
                    count).
===========  =====  =====================================================

That right-hand column is data rather than prose.
:data:`REGISTRY_ONLY_CEILING` names the eight and
:data:`REGISTRY_UNANSWERED_SIGNALS` names what each registry withholds, and
every floor is checked to be exactly that subtraction. An attribution nothing
verifies is how a floor comes to be a number somebody tuned, with a reason
beside it that stopped being true.

**The floor sits at the measured value, not below it.** Every number here is
the exact count its offline test produces today, not a round number with
headroom. Headroom is what this table used to have and it was the bug (#136):
every ecosystem was pinned at seven, and seven of fourteen was precisely where
the scorer flipped to UNKNOWN. A floor below the measured value is not a floor,
it is a permission slip.

The consequence is that this table ratchets. Improve an ecosystem's coverage
and you raise its number in the same change; that is the intended cost, and it
is how a conformance gate differs from a smoke test. The collapse arithmetic
itself lives in ``test_signal_floors.py`` as its own assertion instead of
masquerading as the floor.

Which of them reach a verdict at all
------------------------------------
Sixteen signals and the ``unmeasured > measured`` bar mean the answer is
arithmetic, and :data:`SCORES_FROM_REGISTRY_ALONE` records it rather than
smoothing it over: eight measured against eight unmeasured clears the bar by
exactly nothing, and anything under eight does not clear it. So five
ecosystems reach a verdict from a registry document alone and four do not.

That is a true statement about what a registry-only scan can know, and it is
not a target to tune back. The four are not reporting UNKNOWN because a
threshold is set wrong; they are reporting it because the largest weight in
the scale is a question nobody asked, and three of them are missing one or two
registry fields on top. A scan that wants a verdict for them asks an advisory
source, which is the one input that moves every ecosystem in the table up by
one.

Per-signal coverage
-------------------
:data:`REGISTRY_MEASURED_SIGNALS` names the signals behind each count, because
a count cannot see a swap: an ecosystem that loses one signal and gains another
holds its total steady while a real regression lands. Naming them is #145's
first item.

It is not all of #145. A dead read of the #142 class — npm looking for a
top-level ``deprecated`` key npm has never sent — needs an assertion on a
signal's *value* against a live-captured fixture. That half lives in
``adapter_conformance`` (#73): it consumes the tables below rather than
restating them, adds per-signal value assertions against provenance-dated
payloads, and enforces the rule the npm case generalizes to — every signal
whose read collapses to a fixed default when its key is absent needs at least
one fixture where the correct answer is the non-default value.
``adapter_conformance.CONVERSION_STATUS`` carries the ledger, and
``unproven_branches()`` names every polarized branch no captured payload can
reach, with the reason.

:func:`assert_abandoned_package_is_scored` pins the same property from the
other direction, for #146: a package abandoned a decade ago must still produce
a measured release cadence and a risk verdict, because that is the population
the maintenance-cadence signal exists to flag and the one it used to fail on.

Refresh cadence: every floor here is backed by payloads captured from the live
registry into ``testing/fixtures/registry/``, each carrying its source URL and
capture date, refreshed with ``scripts/capture_registry_fixtures.py`` — see
``registry_fixtures`` for the cadence and who owns it. Adapters keep their own
hand-written fixtures for the paths a captured payload cannot reach (a fallback
that depends on trimmed volume, an error branch); those are legitimate uses of
a synthetic fixture and are not floors. A floor is only as honest as the
fixture underneath it.
"""

from datetime import datetime, timezone
from typing import Dict, FrozenSet

from dependency_risk_profiler.models import DependencyRiskScore, RiskLevel

# Minimum signals an ecosystem must measure with no clone, no token and no
# advisory lookup, set at what each one measures today. Raising these is a
# normal part of improving an adapter; lowering one is a regression that needs
# a reason in the commit.
#
# Eight is the ceiling in this mode and five ecosystems reach it. The four
# below it are missing a registry field rather than an adapter read: npm
# publishes no cheap owner count; Maven Central publishes neither an owner list
# a machine can read nor any retirement marker; proxy.golang.org publishes no
# licence, no owner list and a scopeless ``go.mod``. The module docstring
# derives each subtraction.
MIN_MEASURED_SIGNALS: Dict[str, int] = {
    "cargo": 8,
    "composer": 8,
    "golang": 5,
    "gradle": 6,
    "maven": 6,
    "nuget": 8,
    "nodejs": 7,
    "python": 8,
    "rubygems": 8,
}

# The eight signals a registry-only scan can reach at all, written out rather
# than derived from the scorer's catalog. Deriving it would make every floor
# below a restatement of whatever the code happens to measure, which is a
# tautology: the number would move with the implementation and could never
# contradict it. The module docstring's subtraction starts here.
REGISTRY_ONLY_CEILING: FrozenSet[str] = frozenset(
    {
        "staleness",
        "maintainer",
        "deprecation",
        "version",
        "license",
        "community",
        "transitive",
        "source_repository",
    }
)

# What each registry does not publish, which is the whole of why any floor sits
# below the ceiling. This is the docstring's right-hand column as data: without
# it the attribution is prose, and prose cannot fail. An ecosystem could have
# its missing signal swapped for a different one and every count below would
# still agree while the stated reason quietly became false.
#
# Each entry is a fact about a registry, not about an adapter. npm publishes no
# cheap owner count; Maven Central publishes neither a machine-readable owner
# list nor any retirement marker (``<distributionManagement><relocation>`` says
# an artifact moved, not that it was retired — #179); Gradle inherits both by
# publishing Maven coordinates and resolving against Maven Central;
# proxy.golang.org publishes no licence, no module-level owner concept, and a
# ``go.mod`` whose ``require`` block states no scope, so it cannot answer a
# *runtime* dependency count.
REGISTRY_UNANSWERED_SIGNALS: Dict[str, FrozenSet[str]] = {
    "cargo": frozenset(),
    "composer": frozenset(),
    "golang": frozenset({"maintainer", "license", "transitive"}),
    "gradle": frozenset({"maintainer", "deprecation"}),
    "maven": frozenset({"maintainer", "deprecation"}),
    "nuget": frozenset(),
    "nodejs": frozenset({"maintainer"}),
    "python": frozenset(),
    "rubygems": frozenset(),
}

# Which signals make up each count. Asserted by name so that losing one signal
# and gaining another fails instead of passing under an unchanged total (#145).
#
# ``exploit`` is in none of them, and that is the point rather than an
# omission: this mode asks no advisory source anything, so the signal is
# unmeasured everywhere here and belongs to whichever runs do ask (#321).
# ``deprecation`` is in every set but maven's and gradle's, because Maven
# Central is the one registry publishing no retirement marker at all — the
# nearest thing it has is ``<distributionManagement><relocation>``, which says
# an artifact moved rather than that it was retired (#179).
#
# ``community`` names the star count, which is scraped from an unauthenticated
# github.com page rather than from a registry document. It is in this mode
# because it needs neither a clone nor a token, not because a registry answers
# it.
_REGISTRY_CORE: FrozenSet[str] = frozenset(
    {
        "staleness",
        "version",
        "license",
        "community",
    }
)
REGISTRY_MEASURED_SIGNALS: Dict[str, FrozenSet[str]] = {
    "cargo": _REGISTRY_CORE
    | {"deprecation", "maintainer", "source_repository", "transitive"},
    "composer": _REGISTRY_CORE
    | {"deprecation", "maintainer", "source_repository", "transitive"},
    "golang": (_REGISTRY_CORE - {"license"}) | {"deprecation", "source_repository"},
    "gradle": _REGISTRY_CORE | {"transitive", "source_repository"},
    "maven": _REGISTRY_CORE | {"transitive", "source_repository"},
    "nuget": _REGISTRY_CORE
    | {"deprecation", "maintainer", "transitive", "source_repository"},
    "nodejs": _REGISTRY_CORE | {"deprecation", "source_repository", "transitive"},
    "python": _REGISTRY_CORE
    | {"deprecation", "maintainer", "source_repository", "transitive"},
    "rubygems": _REGISTRY_CORE
    | {"deprecation", "maintainer", "source_repository", "transitive"},
}

# Whether that floor is on its own enough to clear the insufficient-data bar.
#
# Pure arithmetic over sixteen signals: the bar is ``unmeasured > measured``,
# so eight measured against eight unmeasured clears it by exactly nothing and
# seven does not clear it at all. The five at eight are therefore True and the
# four below it are False, and every one of the four is one advisory lookup
# away from clearing — asking a source is the single input that moves every
# ecosystem in this table up by one.
#
# The margins are recorded rather than rounded away, because zero margin means
# losing any single signal returns every package in that ecosystem to UNKNOWN.
SCORES_FROM_REGISTRY_ALONE: Dict[str, bool] = {
    "cargo": True,
    "composer": True,
    "golang": False,
    "gradle": False,
    "maven": False,
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
    "REGISTRY_UNANSWERED_SIGNALS": frozenset(REGISTRY_UNANSWERED_SIGNALS),
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

# Every floor is the ceiling minus what its registry does not publish, so the
# attribution is checked rather than asserted in prose. A number that cannot be
# reached by that subtraction is either a registry fact nobody wrote down or a
# floor tuned to whatever the code currently produces, and the two are
# indistinguishable once the reason lives only in a docstring.
_MISATTRIBUTED = {
    ecosystem: (
        sorted(REGISTRY_MEASURED_SIGNALS[ecosystem]),
        sorted(REGISTRY_ONLY_CEILING - REGISTRY_UNANSWERED_SIGNALS[ecosystem]),
    )
    for ecosystem in MIN_MEASURED_SIGNALS
    if REGISTRY_MEASURED_SIGNALS[ecosystem]
    != REGISTRY_ONLY_CEILING - REGISTRY_UNANSWERED_SIGNALS[ecosystem]
}
assert not _MISATTRIBUTED, (
    "a floor does not equal the ceiling minus the signals its registry is "
    "recorded as not answering; (measured, ceiling minus unanswered) per "
    f"ecosystem: {_MISATTRIBUTED}"
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
