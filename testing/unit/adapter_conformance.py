"""The adapter-conformance harness: per-signal VALUE assertions (#73, #145).

What this adds that ``signal_floors`` cannot
--------------------------------------------
``signal_floors`` asserts how many signals an ecosystem measures and, since
#158, which ones by name. Both are count-shaped, and #158 recorded the case
neither can reach:

    npm read a top-level ``deprecated`` key that npm has never sent. The
    deprecation flag therefore defaulted to ``False``. ``False`` is not
    ``None``, so the signal always read as *measured* — just always measured
    **wrong**. No npm package could ever be flagged deprecated, and every count
    stayed green for the life of the adapter (#142).

The only thing that catches that is an assertion on a signal's **value**,
against a fixture whose ground truth is the branch the buggy code can never
reach. Generalized, the rule this module enforces is:

    **Every signal whose read collapses to a fixed default when the key is
    absent needs at least one captured fixture where the correct answer is the
    non-default value, asserted by value.**

Those are the *polarized* signals — booleans and two-state enums. A signal that
goes to ``None`` when its key is missing is already caught by the floors,
because ``None`` leaves the measured count. A signal that goes to ``False`` is
not, because ``False`` is a number the scorer will happily average.

The proof this bites: put #142 back — read ``npm_data.get("deprecated")`` at the
top level again — and ``test_adapter_conformance`` fails on the captured
``request`` packument, which has no top-level ``deprecated`` key and does carry
one inside ``versions["2.88.2"]``.

Converted ecosystems and the ones still pending
-----------------------------------------------
See :data:`CONVERSION_STATUS`. Four of eight are converted; the other four are
listed with what each needs, so the gap is visible rather than assumed closed.

Fixtures come from :mod:`registry_fixtures` — captured from the live registry,
provenance-dated, replayed offline. This module never touches the network.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple
from unittest import mock

from registry_fixtures import RegistryFixture, load_ecosystem, replay_fetcher
from signal_floors import (
    REGISTRY_MEASURED_SIGNALS,
    assert_meets_signal_floor,
    mark_transitive_unmeasured,
)

from dependency_risk_profiler.analyzers.crates import CratesIOAnalyzer
from dependency_risk_profiler.analyzers.nodejs import NodeJSAnalyzer
from dependency_risk_profiler.analyzers.python import PythonAnalyzer
from dependency_risk_profiler.analyzers.ruby import RubyGemsAnalyzer
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.license.analyzer import analyze_license
from dependency_risk_profiler.models import DependencyMetadata, DependencyRiskScore
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

# The community signal is scraped off a GitHub repository page, not off a
# registry document, so it is out of scope for a *registry* fixture and is
# stubbed here rather than captured. Recorded as a known limit in
# CONVERSION_STATUS rather than left implicit.
GITHUB_REPO_HTML = (
    '<a href="/owner/repo/stargazers" '
    'aria-label="1,234 users starred this repository">1.2k</a>'
)


# --- The assertion vocabulary ----------------------------------------------


@dataclass(frozen=True)
class SignalValue:
    """One per-signal value assertion against a scored dependency.

    Exactly one of ``equals``, ``unmeasured``, or a ``minimum``/``maximum``
    range is meaningful per instance. A range exists for the signals whose
    correct answer moves with the calendar — express's staleness climbs a step
    every few months — where pinning an exact number would make the harness a
    clock rather than a conformance gate.
    """

    signal: str
    because: str
    equals: Optional[float] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    unmeasured: bool = False

    def check(self, score: DependencyRiskScore, slug: str) -> None:
        """Assert the scored value matches this expectation.

        Args:
            score: The scored dependency.
            slug: Fixture id, for the failure message.

        Raises:
            AssertionError: If the signal's value does not match.
        """
        attribute = f"{self.signal}_score"
        assert hasattr(score, attribute), f"no such signal: {self.signal}"
        actual = getattr(score, attribute)
        where = f"{slug}: {self.signal} — {self.because}"

        if self.unmeasured:
            assert actual is None, f"{where}\n  expected unmeasured, got {actual}"
            return

        assert actual is not None, (
            f"{where}\n  expected a measured value, got None. An unmeasured "
            f"signal here means the adapter stopped reading the key it used to."
        )
        if self.equals is not None:
            assert (
                actual == self.equals
            ), f"{where}\n  expected {self.equals}, got {actual}"
        if self.minimum is not None:
            assert (
                actual >= self.minimum
            ), f"{where}\n  expected at least {self.minimum}, got {actual}"
        if self.maximum is not None:
            assert (
                actual <= self.maximum
            ), f"{where}\n  expected at most {self.maximum}, got {actual}"


@dataclass(frozen=True)
class Polarity:
    """A signal whose read collapses to a fixed value when its key is absent.

    ``default`` is what the scorer produces when the adapter's read finds
    nothing — for a boolean that is the ``False`` branch, and it is the value a
    dead read produces forever. ``non_default`` is the branch a dead read can
    never reach, and the one a captured fixture has to prove.

    ``proven_elsewhere`` records a branch this harness cannot prove from a
    registry fixture, with the reason. It is a visible gap, not a pass: the
    conformance report prints every waiver.
    """

    default: float
    non_default: float
    why: str
    proven_elsewhere: Optional[str] = None


@dataclass(frozen=True)
class FixtureCase:
    """One captured payload, scored offline, with its expected signal values."""

    ecosystem: str
    fixture: str
    installed_version: str
    purpose: str
    signals: Sequence[SignalValue]
    extra_fixtures: Sequence[str] = ()
    expected_latest_version: Optional[str] = None
    expected_repository_url: Optional[str] = None
    expected_license_id: Optional[str] = None
    expected_deprecated: Optional[bool] = None
    meets_signal_floor: bool = False
    ground_truth: Sequence[str] = field(default_factory=tuple)

    @property
    def slug(self) -> str:
        """Return the ``ecosystem/fixture`` id used in assertion messages."""
        return f"{self.ecosystem}/{self.fixture}"


# --- Offline drivers, one per converted ecosystem --------------------------
#
# Each driver mirrors the analyze command's order — adapter, license, community,
# scoring — with cloning off and no GitHub token, which is the weakest
# environment the tool runs in and the one a regression shows up in first. The
# only thing that differs between them is which fetch seam the ecosystem's
# adapter uses.


def _package_name(fixture: RegistryFixture) -> str:
    """Return the package name a fixture's payload declares.

    Args:
        fixture: The captured registry document.

    Returns:
        The package name.
    """
    payload = fixture.payload
    assert isinstance(payload, Mapping), f"{fixture.slug} is not a JSON object"
    name = payload.get("name")
    assert isinstance(name, str) and name, f"{fixture.slug} declares no name"
    return name


def _finish(
    dep: DependencyMetadata, metadata: Mapping[str, object]
) -> DependencyRiskScore:
    """Run the license, community, and scoring passes over an analyzed dep.

    Args:
        dep: Dependency as the adapter left it.
        metadata: The adapter's cached registry payload.

    Returns:
        The scored dependency, with transitive resolution marked unmeasured the
        way the real pipeline marks it for registry-only ecosystems (#141).
    """
    dep = analyze_license(dep, dict(metadata))
    with mock.patch.object(
        community_analyzer, "fetch_url", return_value=GITHUB_REPO_HTML
    ):
        dep = community_analyzer.analyze_community_metrics(dep, dict(metadata))
    return RiskScorer().score_dependency(mark_transitive_unmeasured(dep))


def _score_nodejs(
    case: FixtureCase, fixtures: Mapping[str, RegistryFixture]
) -> DependencyRiskScore:
    """Score one captured npm packument offline.

    Args:
        case: The conformance case.
        fixtures: Every fixture captured for the ecosystem.

    Returns:
        The scored dependency.
    """
    fixture = fixtures[case.fixture]
    name = _package_name(fixture)
    analyzer = NodeJSAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version=case.installed_version)

    fetch = replay_fetcher({case.fixture: fixture})
    with mock.patch(
        "dependency_risk_profiler.analyzers.nodejs.fetch_json", side_effect=fetch
    ):
        dep = analyzer.analyze({name: dep})[name]
    return _finish(dep, analyzer.metadata_cache[name])


def _score_rubygems(
    case: FixtureCase, fixtures: Mapping[str, RegistryFixture]
) -> DependencyRiskScore:
    """Score one captured rubygems.org payload offline.

    Args:
        case: The conformance case, whose ``extra_fixtures`` names the gem's
            owners document.
        fixtures: Every fixture captured for the ecosystem.

    Returns:
        The scored dependency.
    """
    served = {case.fixture: fixtures[case.fixture]}
    for extra in case.extra_fixtures:
        served[extra] = fixtures[extra]

    name = _package_name(served[case.fixture])
    analyzer = RubyGemsAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version=case.installed_version)

    fetch = replay_fetcher(served)

    def fetch_one(url: str) -> object:
        return fetch(url)

    with mock.patch.object(analyzer, "_get_json", side_effect=fetch_one):
        dep = analyzer.analyze({name: dep})[name]
    return _finish(dep, analyzer.metadata_cache[name])


def _nested_name(fixture: RegistryFixture, container: str) -> str:
    """Return the package name a fixture declares inside a nested object.

    PyPI puts it in ``info.name`` and crates.io in ``crate.name``, and both
    spellings matter: the adapter builds its request URL from the name, so a
    name that does not round-trip to the captured URL fails at the replay
    fetcher rather than silently reaching the network.

    Args:
        fixture: The captured registry document.
        container: The object holding the name (``info`` or ``crate``).

    Returns:
        The package name.
    """
    payload = fixture.payload
    assert isinstance(payload, Mapping), f"{fixture.slug} is not a JSON object"
    nested = payload.get(container)
    assert isinstance(nested, Mapping), f"{fixture.slug} has no {container} object"
    name = nested.get("name")
    assert isinstance(name, str) and name, f"{fixture.slug} declares no name"
    return name


def _score_python(
    case: FixtureCase, fixtures: Mapping[str, RegistryFixture]
) -> DependencyRiskScore:
    """Score one captured PyPI project document offline.

    Args:
        case: The conformance case.
        fixtures: Every fixture captured for the ecosystem.

    Returns:
        The scored dependency.
    """
    fixture = fixtures[case.fixture]
    name = _nested_name(fixture, "info")
    analyzer = PythonAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version=case.installed_version)

    fetch = replay_fetcher({case.fixture: fixture})
    with mock.patch(
        "dependency_risk_profiler.analyzers.python.fetch_json", side_effect=fetch
    ):
        dep = analyzer.analyze({name: dep})[name]
    return _finish(dep, analyzer.metadata_cache[name])


def _score_cargo(
    case: FixtureCase, fixtures: Mapping[str, RegistryFixture]
) -> DependencyRiskScore:
    """Score one captured crates.io crate document offline.

    Args:
        case: The conformance case, whose ``extra_fixtures`` names the crate's
            owners document.
        fixtures: Every fixture captured for the ecosystem.

    Returns:
        The scored dependency.
    """
    served = {case.fixture: fixtures[case.fixture]}
    for extra in case.extra_fixtures:
        served[extra] = fixtures[extra]

    name = _nested_name(served[case.fixture], "crate")
    analyzer = CratesIOAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version=case.installed_version)

    fetch = replay_fetcher(served)

    def fetch_one(url: str) -> object:
        return fetch(url)

    with mock.patch.object(analyzer, "_get_json", side_effect=fetch_one):
        dep = analyzer.analyze({name: dep})[name]
    return _finish(dep, analyzer.metadata_cache[name])


DRIVERS = {
    "cargo": _score_cargo,
    "nodejs": _score_nodejs,
    "python": _score_python,
    "rubygems": _score_rubygems,
}


def score_case(case: FixtureCase) -> DependencyRiskScore:
    """Score one conformance case from its captured fixtures.

    Args:
        case: The conformance case.

    Returns:
        The scored dependency.
    """
    fixtures = {
        name: RegistryFixture(**{**vars(f), "payload": deepcopy(f.payload)})
        for name, f in load_ecosystem(case.ecosystem).items()
    }
    return DRIVERS[case.ecosystem](case, fixtures)


# --- Polarized signals, per ecosystem --------------------------------------

POLARIZED_SIGNALS: Dict[str, Dict[str, Polarity]] = {
    "nodejs": {
        "deprecation": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "npm records deprecation inside versions[<latest>].deprecated. "
                "The adapter used to read a top-level 'deprecated' key npm has "
                "never sent, so the flag defaulted to False for every package "
                "in the registry and every count stayed green (#142)."
            ),
        ),
        "source_repository": Polarity(
            default=1.0,
            non_default=0.0,
            why=(
                "A repository read that finds nothing records UNDECLARED, "
                "which scores 1.0. A dead read is indistinguishable from a "
                "package that genuinely declares no source, so the DECLARED "
                "branch has to be proven by value."
            ),
        ),
        "exploit": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "has_known_exploits defaults to False, the same shape as the "
                "npm deprecation bug."
            ),
            proven_elsewhere=(
                "Not registry-driven: the exploit signal is set by the "
                "vulnerability aggregator from OSV, not by the adapter, so no "
                "registry payload can flip it. Its non-default branch is "
                "covered by testing/unit/test_comprehensive_vulnerability_"
                "aggregator.py and the OSV routing tests. #73's "
                "'known-CVE package -> >0 advisories per ecosystem' "
                "regression test is the piece that would bring it in here."
            ),
        ),
    },
    "python": {
        "deprecation": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "Two reads feed one flag: info.yanked, and a summary line the "
                "maintainer writes on purpose. Both default to False when the "
                "key is absent, which is #142's shape. sklearn proves the "
                "non-default value through the summary read."
            ),
        ),
        "source_repository": Polarity(
            default=1.0,
            non_default=0.0,
            why=(
                "Same as npm's: a project_urls sweep that finds nothing "
                "records UNDECLARED and scores 1.0, which a dead read also "
                "produces."
            ),
        ),
        "exploit": Polarity(
            default=0.0,
            non_default=1.0,
            why="has_known_exploits defaults to False.",
            proven_elsewhere=(
                "Not registry-driven; see the nodejs entry. Worth noting that "
                "the captured payloads do carry a top-level 'vulnerabilities' "
                "list the adapter does not read (#171). It is left unread "
                "deliberately: the aggregator already queries OSV, which is "
                "the same data with a wider ecosystem reach and a real "
                "severity model. The key is kept in the fixtures so that the "
                "decision stays visible."
            ),
        ),
    },
    "cargo": {
        "deprecation": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "The adapter flags a crate deprecated when the release entry "
                "reports yanked: true. Absent key means False forever, the "
                "same shape as npm's."
            ),
        ),
        "source_repository": Polarity(
            default=1.0,
            non_default=0.0,
            why=(
                "Same as npm's: a repository read that finds nothing records "
                "UNDECLARED and scores 1.0, which a dead read also produces."
            ),
        ),
        "exploit": Polarity(
            default=0.0,
            non_default=1.0,
            why="has_known_exploits defaults to False.",
            proven_elsewhere=(
                "Not registry-driven; see the nodejs entry. Same aggregator, "
                "same coverage, same gap."
            ),
        ),
    },
    "rubygems": {
        "deprecation": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "The adapter flags a gem deprecated when the payload reports "
                "yanked: true. Same shape as npm's: absent key means False "
                "forever."
            ),
            proven_elsewhere=(
                "UNPROVEN, and the harness is what made that visible. No live "
                "capture of /api/v1/gems/<name>.json was found reporting "
                "yanked: true — that endpoint answers with the newest "
                "*non-yanked* release, and a gem whose releases are all yanked "
                "answers 404, at which point the adapter bails out before the "
                "read. So this may be a dead read of exactly #142's class in a "
                "second adapter. Audit needed against a gem with a yanked "
                "latest version; until then this branch is recorded as "
                "unproven rather than assumed to work. Sharpened by the cargo "
                "conversion (#170): crates.io answers 200 for a fully yanked "
                "crate and reports yanked: true on the release entry, so the "
                "same idea IS capturable one ecosystem over — cargo.acid-store "
                "is that fixture. The difference is the endpoint, not the "
                "idea, which makes rubygems' choice of endpoint the thing to "
                "fix rather than the read."
            ),
        ),
        "source_repository": Polarity(
            default=1.0,
            non_default=0.0,
            why=(
                "Same as npm's: a repository read that finds nothing records "
                "UNDECLARED and scores 1.0, which a dead read also produces."
            ),
        ),
        "exploit": Polarity(
            default=0.0,
            non_default=1.0,
            why="has_known_exploits defaults to False.",
            proven_elsewhere=(
                "Not registry-driven; see the nodejs entry. Same aggregator, "
                "same coverage, same gap."
            ),
        ),
    },
}


# --- The cases -------------------------------------------------------------

NODEJS_CASES: Tuple[FixtureCase, ...] = (
    FixtureCase(
        ecosystem="nodejs",
        fixture="express",
        installed_version="4.17.1",
        purpose=(
            "A healthy, fully-populated packument: the coverage floor case, and "
            "the DECLARED branch of the repository signal."
        ),
        expected_latest_version="5.2.1",
        expected_repository_url="https://github.com/expressjs/express",
        expected_license_id="MIT",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "dist-tags.latest carries the release; the packument has no "
            "top-level 'version' key (#140).",
            "repository.url arrives git+-prefixed and .git-suffixed.",
        ),
        signals=(
            SignalValue(
                "deprecation",
                equals=0.0,
                because="express is not deprecated; this is the default branch",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="the packument declares repository.url — non-default branch",
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="license: MIT is permissive, which scores 0.0",
            ),
            SignalValue(
                "version",
                minimum=0.25,
                because="4.17.1 installed against a 5.x latest is real drift",
            ),
            SignalValue(
                "staleness",
                minimum=0.0,
                maximum=1.0,
                because=(
                    "measured off time[dist-tags.latest]; the exact step moves "
                    "with the calendar, so only measurement is pinned"
                ),
            ),
            SignalValue(
                "community",
                minimum=0.0,
                maximum=1.0,
                because="a resolvable repository lets the star scrape land",
            ),
            SignalValue(
                "maintainer",
                unmeasured=True,
                because=(
                    "npm publishes no cheap maintainer count; recorded as "
                    "SCORES_FROM_REGISTRY_ALONE['nodejs'] is False"
                ),
            ),
        ),
    ),
    FixtureCase(
        ecosystem="nodejs",
        fixture="request",
        installed_version="2.88.0",
        purpose=(
            "#142's ground truth. The most famous deprecated package in the "
            "registry, captured whole: no top-level 'deprecated' key, a real "
            "one inside versions['2.88.2']. This is the case a count-based "
            "floor cannot fail on."
        ),
        expected_latest_version="2.88.2",
        expected_repository_url="https://github.com/request/request",
        expected_license_id="APACHE-2.0",
        expected_deprecated=True,
        ground_truth=(
            "'deprecated' is absent at the top level of the live packument.",
            "versions['2.88.2'].deprecated carries the notice.",
            "time.modified moved when the deprecation landed; the publication "
            "date did not (#146).",
        ),
        signals=(
            SignalValue(
                "deprecation",
                equals=1.0,
                because=(
                    "THE assertion. A top-level read gives False here forever, "
                    "and False is measured, so only the value catches it (#142)"
                ),
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="last published February 2020; over a year is maximum",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="request still declares its repository",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="nodejs",
        fixture="indexof",
        installed_version="0.0.1",
        purpose=(
            "The UNDECLARED branch, captured rather than constructed: a real "
            "packument with no 'repository' and no 'homepage' at all."
        ),
        expected_latest_version="0.0.1",
        expected_repository_url=None,
        expected_deprecated=False,
        ground_truth=(
            "Neither 'repository' nor 'homepage' appears in the live packument.",
            "No 'license' key either, which is why the license signal is "
            "unmeasured rather than guessed at (#74).",
        ),
        signals=(
            SignalValue(
                "source_repository",
                equals=1.0,
                because="the registry answered and declares no source — default branch",
            ),
            SignalValue(
                "license",
                unmeasured=True,
                because="no license key means unmeasured, never a confident zero",
            ),
            SignalValue(
                "community",
                unmeasured=True,
                because="no repository to scrape stars from",
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="published in 2012 and never touched since",
            ),
        ),
    ),
)

RUBYGEMS_CASES: Tuple[FixtureCase, ...] = (
    FixtureCase(
        ecosystem="rubygems",
        fixture="tzinfo",
        extra_fixtures=("tzinfo.owners",),
        installed_version="1.0.0",
        purpose=(
            "#134's ground truth and the coverage floor case. RubyGems "
            "publishes the license as a *list* under 'licenses'; the adapter "
            "read a string 'license' that no gem payload has ever carried, and "
            "the signal was dead for all 167 gems measured."
        ),
        expected_latest_version="2.0.6",
        expected_repository_url="https://github.com/tzinfo/tzinfo",
        expected_license_id="MIT",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "'licenses' is a list; there is no 'license' key at all.",
            "source_code_uri is pinned to the released tag (/tree/v2.0.6) and "
            "has to be trimmed to the repository root.",
        ),
        signals=(
            SignalValue(
                "license",
                equals=0.0,
                because=(
                    "MIT read out of the licenses *list*; a string read gives "
                    "None here, which is what #134 shipped"
                ),
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="source_code_uri is declared — non-default branch",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="tzinfo is not yanked; the default branch",
            ),
            SignalValue(
                "maintainer",
                equals=1.0,
                because="the owners endpoint lists one owner, and one is a risk",
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="2.0.6 shipped in January 2023",
            ),
            SignalValue(
                "community",
                minimum=0.0,
                maximum=1.0,
                because="the trimmed repository root lets the star scrape land",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="rubygems",
        fixture="hpricot",
        extra_fixtures=("hpricot.owners",),
        installed_version="0.8.6",
        purpose=(
            "The UNDECLARED branch on a real gem: hpricot's only homepage is "
            "code.whytheluckystiff.net, which is not a supported repository "
            "host, so the canonicalizer correctly refuses it."
        ),
        expected_latest_version="0.8.6",
        expected_repository_url=None,
        expected_license_id=None,
        expected_deprecated=False,
        ground_truth=(
            "'source_code_uri' is null and homepage_uri points at a dead "
            "non-git host.",
            "'licenses' is null, so the license signal is honestly unmeasured.",
        ),
        signals=(
            SignalValue(
                "source_repository",
                equals=1.0,
                because="the registry answered and declares no usable source",
            ),
            SignalValue(
                "license",
                unmeasured=True,
                because="licenses is null; unmeasured, not a confident zero",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="not yanked — see the rubygems deprecation waiver",
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="0.8.6 shipped in January 2012",
            ),
        ),
    ),
)

PYTHON_CASES: Tuple[FixtureCase, ...] = (
    FixtureCase(
        ecosystem="python",
        fixture="requests",
        installed_version="2.31.0",
        purpose=(
            "The coverage floor case, and the one that retires "
            "SCORES_FROM_REGISTRY_ALONE['python'] = False. PyPI publishes the "
            "project's role assignments in a top-level 'ownership' object the "
            "adapter never read (#171); reading it answers the maintainer "
            "count PyPI was recorded as unable to provide, and python clears "
            "the insufficient-data bar from registry metadata alone."
        ),
        expected_latest_version="2.34.2",
        expected_repository_url="https://github.com/psf/requests",
        expected_license_id="APACHE-2.0",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "ownership.roles lists three Owner accounts; there is no "
            "'maintainers' key anywhere in the payload, which is why the count "
            "was believed unavailable.",
            "info.license is the legacy free-text spelling here ('Apache-2.0') "
            "and info.license_expression is null — the opposite of flask.",
            "project_urls.Source carries the repository; home_page is null, as "
            "it is on every modern package.",
        ),
        signals=(
            SignalValue(
                "maintainer",
                equals=0.25,
                because=(
                    "THE #171 assertion: three owners read straight off "
                    "ownership.roles. Before this the signal was unmeasured "
                    "for every PyPI package and python was floored one signal "
                    "short of a verdict"
                ),
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="Apache-2.0 is permissive; the legacy spelling still reads",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="project_urls declares Source — non-default branch",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="requests is neither yanked nor summary-deprecated",
            ),
            SignalValue(
                "version",
                minimum=0.5,
                because="2.31.0 against a 2.34.x latest is a real minor gap",
            ),
            SignalValue(
                "staleness",
                minimum=0.0,
                maximum=1.0,
                because=(
                    "read off the newest upload_time_iso_8601 in the payload; "
                    "the step moves with the calendar, so only measurement is "
                    "pinned"
                ),
            ),
            SignalValue(
                "community",
                minimum=0.0,
                maximum=1.0,
                because="a resolvable repository lets the star scrape land",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="python",
        fixture="flask",
        installed_version="2.0.0",
        purpose=(
            "Two findings in one captured payload. First: flask publishes its "
            "licence only as info.license_expression (PEP 639 / metadata 2.4), "
            "with info.license null and no 'License ::' classifier — 17 of 30 "
            "sampled popular packages do, and the licence signal read as "
            "unmeasured for all of them. Second: a project owned by a PyPI "
            "organization reports 'roles': [], and counting that as zero "
            "maintainers would score the worst possible bus factor from a "
            "measurement nobody made."
        ),
        expected_latest_version="3.1.3",
        expected_repository_url="https://github.com/pallets/flask",
        expected_license_id="BSD-3-CLAUSE",
        expected_deprecated=False,
        ground_truth=(
            "info.license is null and info.license_expression is "
            "'BSD-3-Clause'; the classifiers carry no 'License ::' entry at "
            "all, so the old fallback had nothing to reach either.",
            "ownership is {'organization': 'pallets', 'roles': []} — the "
            "permissions live on the organization, whose membership this "
            "payload does not publish.",
        ),
        signals=(
            SignalValue(
                "license",
                equals=0.0,
                because=(
                    "BSD-3-Clause read from license_expression. A 'license'-only "
                    "read gives None here, and None is unmeasured, so this one "
                    "the floors could have caught — on a package whose floor "
                    "case happened to be an org-owned project"
                ),
            ),
            SignalValue(
                "maintainer",
                unmeasured=True,
                because=(
                    "an empty roles list is not zero maintainers. Zero scores "
                    "1.0, the single-maintainer verdict, from a fact nobody "
                    "measured (#74, #141)"
                ),
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="project_urls.Source declares the repository",
            ),
            SignalValue(
                "version",
                equals=1.0,
                because="2.0.0 against a 3.x latest is a major-version gap",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="flask is current; the default branch",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="python",
        fixture="sklearn",
        installed_version="0.0",
        purpose=(
            "The deprecation non-default branch, and the UNDECLARED branch, on "
            "one real package. sklearn exists only to tell you to install "
            "scikit-learn: its summary says so in as many words, it declares no "
            "project_urls at all, and its license string is empty."
        ),
        expected_latest_version="0.0.post12",
        expected_repository_url=None,
        expected_license_id=None,
        expected_deprecated=True,
        ground_truth=(
            "info.summary is 'deprecated sklearn package, use scikit-learn "
            "instead' while info.yanked is False — the summary read is the one "
            "that fires.",
            "info.project_urls is null and info.home_page is the empty string.",
            "info.license is '' and info.license_expression is null, so the "
            "licence is honestly unmeasured rather than guessed.",
        ),
        signals=(
            SignalValue(
                "deprecation",
                equals=1.0,
                because=(
                    "THE assertion for python. A read of a key PyPI does not "
                    "send leaves this False forever, and False is measured, so "
                    "only the value catches it (#142)"
                ),
            ),
            SignalValue(
                "source_repository",
                equals=1.0,
                because="the registry answered and declares no source — default branch",
            ),
            SignalValue(
                "license",
                unmeasured=True,
                because="an empty licence string is unmeasured, never a confident zero",
            ),
            SignalValue(
                "community",
                unmeasured=True,
                because="no repository to scrape stars from",
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="last uploaded in December 2023; over a year is maximum",
            ),
            SignalValue(
                "maintainer",
                equals=0.25,
                because="ownership.roles lists three owners",
            ),
        ),
    ),
)

CARGO_CASES: Tuple[FixtureCase, ...] = (
    FixtureCase(
        ecosystem="cargo",
        fixture="serde",
        extra_fixtures=("serde.owners",),
        installed_version="1.0.100",
        purpose=(
            "#139's ground truth and the coverage floor case. The crate object "
            "was first published in December 2014 and the newest release "
            "shipped last month; reading crate.created_at as the release date "
            "made the most actively maintained crate in the registry look "
            "abandoned by a decade."
        ),
        expected_latest_version="1.0.229",
        expected_repository_url="https://github.com/serde-rs/serde",
        expected_license_id="MIT",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "crate.created_at is 2014-12-05 and the newest versions entry is "
            "dated 2026 — the two dates the #139 bug confused.",
            "the licence lives on the version entry, not on the crate object.",
            "the owners endpoint lists two entries, one of them a team "
            "(github:serde-rs:publish), which still counts as a publisher.",
        ),
        signals=(
            SignalValue(
                "staleness",
                maximum=0.5,
                because=(
                    "THE #139 assertion: measured off the release entry, not "
                    "off crate.created_at. The 2014 date scores 1.0 and this "
                    "one cannot, however the calendar moves"
                ),
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="the crate declares repository — non-default branch",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="serde is not yanked; the default branch",
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="MIT OR Apache-2.0 is permissive, read off the version entry",
            ),
            SignalValue(
                "maintainer",
                equals=0.5,
                because="the owners endpoint lists two publishers",
            ),
            SignalValue(
                "version",
                minimum=0.25,
                because="1.0.100 against a 1.0.229 latest is real patch drift",
            ),
            SignalValue(
                "community",
                minimum=0.0,
                maximum=1.0,
                because="a resolvable repository lets the star scrape land",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="cargo",
        fixture="acid-store",
        extra_fixtures=("acid-store.owners",),
        installed_version="0.10.0",
        purpose=(
            "The branch rubygems could not prove (#170), captured one "
            "ecosystem over. Every one of acid-store's 25 releases is yanked, "
            "and crates.io still answers 200 with yanked: true on the release "
            "entry — where a fully yanked gem answers 404 and the RubyGems "
            "adapter never reaches its read. It also carries a second "
            "wrong-value read of #139's shape: crates.io reports max_version "
            "as the sentinel '0.0.0' when nothing installable remains."
        ),
        expected_latest_version="0.14.2",
        expected_repository_url="https://github.com/lostatc/acid-store",
        expected_license_id="APACHE-2.0",
        expected_deprecated=True,
        ground_truth=(
            "crate.max_version is '0.0.0' and no release is numbered 0.0.0; "
            "the newest release that exists is 0.14.2, from March 2024.",
            "crate.yanked is true and every versions entry reports "
            "yanked: true with an audit_actions 'yank' record.",
        ),
        signals=(
            SignalValue(
                "deprecation",
                equals=1.0,
                because=(
                    "THE assertion for cargo, and the one #170 says rubygems "
                    "has no equivalent for. A dead read of the yanked key "
                    "gives False here forever"
                ),
            ),
            SignalValue(
                "version",
                equals=0.5,
                because=(
                    "0.10.0 against the 0.14.2 that actually exists is a minor "
                    "gap. Against the '0.0.0' sentinel it scores 0.1 — a "
                    "withdrawn crate reported as a trivial patch behind"
                ),
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="the last release, yanked or not, shipped in March 2024",
            ),
            SignalValue(
                "maintainer",
                equals=1.0,
                because="one owner, and one is a bus factor",
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="Apache-2.0 on the release entry; yanking does not unlicense",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="the crate still declares its repository",
            ),
        ),
    ),
)

CASES: Tuple[FixtureCase, ...] = (
    NODEJS_CASES + RUBYGEMS_CASES + PYTHON_CASES + CARGO_CASES
)


# --- The conversion ledger -------------------------------------------------


@dataclass(frozen=True)
class ConversionStatus:
    """Whether an ecosystem is under the harness, and what it still needs."""

    converted: bool
    note: str


CONVERSION_STATUS: Dict[str, ConversionStatus] = {
    "nodejs": ConversionStatus(
        converted=True,
        note=(
            "Three captured packuments. Proves the mechanism against #142's "
            "phantom top-level 'deprecated', which is the bug no count-based "
            "floor can see. Known limit: the community signal is scraped off a "
            "GitHub page rather than a registry document and is stubbed here."
        ),
    ),
    "rubygems": ConversionStatus(
        converted=True,
        note=(
            "Two captured gem payloads plus their owners documents. Picked as "
            "the second worked example because it carried a *different* "
            "dead-read shape (#134: registry sends a 'licenses' list, adapter "
            "read a 'license' string), because it is on the other side of "
            "SCORES_FROM_REGISTRY_ALONE from npm and so exercises the full "
            "verdict path, and because its documents are small enough to "
            "capture whole — no volume trimming at all, so the never-drop-a-key "
            "rule holds by construction. Open: the yanked/deprecation branch is "
            "recorded as unproven, see POLARIZED_SIGNALS['rubygems']."
        ),
    ),
    "python": ConversionStatus(
        converted=True,
        note=(
            "Three captured project documents. #145 named PyPI as the "
            "ecosystem never audited against a live payload, 'the ecosystem "
            "everything else was implicitly compared against', and the capture "
            "found two dead reads in it. 'ownership' answers the maintainer "
            "count SCORES_FROM_REGISTRY_ALONE recorded as unavailable (#171), "
            "which retires that flag and raises the floor to 8. "
            "'license_expression' is the PEP 639 spelling PyPI now uses for "
            "packages built to metadata 2.4: 17 of 30 sampled popular packages "
            "publish it with a null 'license' and no 'License ::' classifier, "
            "and the licence signal was unmeasured for every one of them. Known "
            "limit: an org-owned project reports 'roles': [], so its maintainer "
            "count stays unmeasured and it does not clear the "
            "insufficient-data bar — flask is captured as that case rather "
            "than rounded off."
        ),
    ),
    "cargo": ConversionStatus(
        converted=True,
        note=(
            "Two captured crate documents plus their owners documents. Picked "
            "for #139's wrong-value shape (crate-level created_at is *first* "
            "publication, not latest release) — a value that was present and "
            "wrong, the third distinct dead-read shape — and because "
            "crates.io answers 200 for a fully yanked crate, which makes it "
            "the one ecosystem where the deprecation non-default branch is "
            "capturable at all (#170). Capturing it found a second read of the "
            "same shape: crate.max_version is the sentinel '0.0.0' when every "
            "release is yanked, so a withdrawn crate reported as barely behind "
            "the latest version. The release entry's own 'num' is read "
            "instead. Note the fixture floor: 162 fully yanked crates were "
            "found across 6,000 sampled and none in the top 1,000 by "
            "downloads, so acid-store is a real but small-audience crate."
        ),
    ),
    "composer": ConversionStatus(
        converted=False,
        note=(
            "PENDING. Never closely audited (#145 lists it with nuget and "
            "python as unexamined). Packagist's p2 document is version-keyed "
            "and large; it needs a reducer like npm-packument's."
        ),
    ),
    "nuget": ConversionStatus(
        converted=False,
        note=(
            "PENDING. Multi-document (registration index plus catalog entry), "
            "so the replay map has to serve several URLs per package. Its "
            "catalog 'deprecation' block is a real enum and would exercise the "
            "polarity rule properly."
        ),
    ),
    "maven": ConversionStatus(
        converted=False,
        note=(
            "PENDING. #141 found repository_url was never set at all, leaving "
            "10 of 11 signals structurally unreachable. Has no signal_floors "
            "entry yet, so it needs a floor before it can have a value gate."
        ),
    ),
    "golang": ConversionStatus(
        converted=False,
        note=(
            "PENDING. Uses proxy.golang.org rather than a JSON registry, so "
            "the capture reducer and the replay seam both differ. Also one of "
            "the two adapters #160's narrowed-B migrates onto "
            "collect_repository_signals; converting it here first is what "
            "makes that migration verifiable rather than faith-based."
        ),
    ),
}


def converted_ecosystems() -> List[str]:
    """Return the ecosystems currently under the value harness.

    Returns:
        Sorted ecosystem keys.
    """
    return sorted(k for k, v in CONVERSION_STATUS.items() if v.converted)


def unproven_branches() -> List[str]:
    """Return every polarized branch this harness does not prove, with reasons.

    Returns:
        One human-readable line per waived branch.
    """
    return [
        f"{ecosystem}.{signal}: {polarity.proven_elsewhere}"
        for ecosystem, signals in sorted(POLARIZED_SIGNALS.items())
        for signal, polarity in sorted(signals.items())
        if polarity.proven_elsewhere
    ]


# --- The assertions --------------------------------------------------------


def assert_case_conforms(case: FixtureCase) -> DependencyRiskScore:
    """Assert one captured payload produces the values it should.

    Args:
        case: The conformance case.

    Returns:
        The scored dependency, so callers can assert further.

    Raises:
        AssertionError: On any mismatch, naming the fixture and the reason the
            expectation exists.
    """
    score = score_case(case)
    dep = score.dependency

    if case.expected_latest_version is not None:
        assert dep.latest_version == case.expected_latest_version, (
            f"{case.slug}: latest_version is {dep.latest_version!r}, expected "
            f"{case.expected_latest_version!r}"
        )
    assert dep.repository_url == case.expected_repository_url, (
        f"{case.slug}: repository_url is {dep.repository_url!r}, expected "
        f"{case.expected_repository_url!r}"
    )
    if case.expected_deprecated is not None:
        assert dep.is_deprecated is case.expected_deprecated, (
            f"{case.slug}: is_deprecated is {dep.is_deprecated}, expected "
            f"{case.expected_deprecated}"
        )
    actual_license = dep.license_info.license_id if dep.license_info else None
    assert actual_license == case.expected_license_id, (
        f"{case.slug}: license_id is {actual_license!r}, expected "
        f"{case.expected_license_id!r}"
    )

    for expectation in case.signals:
        expectation.check(score, case.slug)

    if case.meets_signal_floor:
        assert_meets_signal_floor(score, case.ecosystem)
    return score


def assert_non_default_branches_are_proven(ecosystem: str) -> None:
    """Assert every polarized signal has a fixture proving its non-default branch.

    This is the rule #145 asks for, generalized from the one bug that motivated
    it. A polarized signal with no non-default fixture is a signal that could be
    reading a key the registry has never sent, and nothing in the suite would
    notice.

    Args:
        ecosystem: A converted ecosystem key.

    Raises:
        AssertionError: If a polarized signal has neither a fixture proving its
            non-default branch nor a recorded waiver.
    """
    cases = [case for case in CASES if case.ecosystem == ecosystem]
    proven: Dict[str, List[str]] = {}
    for case in cases:
        for expectation in case.signals:
            if expectation.equals is not None:
                proven.setdefault(expectation.signal, []).append(
                    f"{case.fixture}={expectation.equals}"
                )

    unproven: List[str] = []
    for signal, polarity in sorted(POLARIZED_SIGNALS[ecosystem].items()):
        if polarity.proven_elsewhere:
            continue
        wanted = f"={polarity.non_default}"
        if not any(entry.endswith(wanted) for entry in proven.get(signal, [])):
            unproven.append(
                f"{ecosystem}.{signal}: no captured fixture asserts the "
                f"non-default value {polarity.non_default}. {polarity.why} "
                f"Asserted so far: {proven.get(signal, [])}"
            )

    assert not unproven, (
        "polarized signals with no non-default fixture — a count-based floor "
        "cannot see a signal that is always measured and always wrong:\n  "
        + "\n  ".join(unproven)
    )


def assert_polarized_signals_are_registered(ecosystem: str) -> None:
    """Assert the polarity table covers the signals the ecosystem measures.

    A signal added to :data:`REGISTRY_MEASURED_SIGNALS` without a polarity
    decision is a signal nobody has asked "does this collapse to a default?"
    about, which is how the class survives.

    Args:
        ecosystem: A converted ecosystem key.

    Raises:
        AssertionError: If a polarized entry names a signal the ecosystem does
            not measure.
    """
    measured = REGISTRY_MEASURED_SIGNALS[ecosystem]
    declared = set(POLARIZED_SIGNALS[ecosystem])
    stray = sorted(declared - set(measured))
    assert not stray, (
        f"{ecosystem} declares polarity for {stray}, which it does not measure "
        f"from registry metadata; one of the two tables is stale"
    )
