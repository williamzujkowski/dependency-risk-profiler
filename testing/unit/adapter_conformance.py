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

Converted ecosystems
--------------------
See :data:`CONVERSION_STATUS`. All eight are converted. That is not the same as
"every branch is proven": :func:`unproven_branches` names each polarized branch
no captured payload can reach, with the reason it cannot, and the conformance
report prints every one. maven's deprecation branch is the sharpest of them —
Maven Central publishes no retirement marker at all, so the signal reads as
measured and False for every artifact in the repository and no fixture can make
it read otherwise.

Fixtures come from :mod:`registry_fixtures` — captured from the live registry,
provenance-dated, replayed offline. This module never touches the network.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple
from unittest import mock

from registry_fixtures import (
    RegistryFixture,
    load_ecosystem,
    replay_fetcher,
    replay_requests_get,
)
from signal_floors import REGISTRY_MEASURED_SIGNALS, assert_meets_signal_floor

from dependency_risk_profiler.analyzers import composer as composer_module
from dependency_risk_profiler.analyzers import maven as maven_module
from dependency_risk_profiler.analyzers.composer import ComposerAnalyzer
from dependency_risk_profiler.analyzers.crates import CratesIOAnalyzer
from dependency_risk_profiler.analyzers.golang import GoAnalyzer
from dependency_risk_profiler.analyzers.maven import MavenAnalyzer
from dependency_risk_profiler.analyzers.nodejs import NodeJSAnalyzer
from dependency_risk_profiler.analyzers.nuget import NuGetAnalyzer
from dependency_risk_profiler.analyzers.python import PythonAnalyzer
from dependency_risk_profiler.analyzers.ruby import RubyGemsAnalyzer
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.go_modules import GoModuleResolver
from dependency_risk_profiler.license.analyzer import analyze_license
from dependency_risk_profiler.models import DependencyMetadata, DependencyRiskScore
from dependency_risk_profiler.parsers import maven_central as maven_central_module
from dependency_risk_profiler.parsers import nuget_registry as nuget_registry_module
from dependency_risk_profiler.parsers.maven_central import pom_url
from dependency_risk_profiler.parsers.nuget_registry import (
    FLAT_CONTAINER_BASE,
    NuGetRegistryClient,
    parse_nuspec,
)
from dependency_risk_profiler.parsers.pom_model import PomCoordinate, read_pom
from dependency_risk_profiler.parsers.xml_utils import parse_xml_bytes
from dependency_risk_profiler.scoring.risk_scorer import (
    SOURCE_REPOSITORY_UNUSABLE_SCORE,
    RiskScorer,
)

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
    absent_urls: Sequence[str] = ()
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
        The scored dependency, exactly as the adapter left it.

    Nothing marks transitive unmeasured here, and that is the point since #199.
    This used to call ``mark_transitive_unmeasured`` to reproduce what the
    pipeline does for registry-only ecosystems — which meant the harness
    asserted the marker rather than the default, and would have stayed green if
    the default flipped back to fail-open. Now the five adapters that never
    read a dependency list say nothing and are scored as unmeasured *because*
    they said nothing, which is the property under test.
    """
    dep = analyze_license(dep, dict(metadata))
    with mock.patch.object(
        community_analyzer, "fetch_url", return_value=GITHUB_REPO_HTML
    ):
        dep = community_analyzer.analyze_community_metrics(dep, dict(metadata))
    return RiskScorer().score_dependency(dep)


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


def _score_composer(
    case: FixtureCase, fixtures: Mapping[str, RegistryFixture]
) -> DependencyRiskScore:
    """Score one captured Packagist p2 document offline.

    Composer reads its registry through ``requests.get`` rather than through a
    JSON helper, so the replay happens one layer lower — which is the point:
    the p2 document's ``packages -> <name> -> [releases]`` unwrapping and the
    minified format's "only the head entry is complete" rule both stay under
    test instead of being stubbed past.

    Args:
        case: The conformance case.
        fixtures: Every fixture captured for the ecosystem.

    Returns:
        The scored dependency.
    """
    fixture = fixtures[case.fixture]
    name = _packagist_name(fixture)
    analyzer = ComposerAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version=case.installed_version)

    get = replay_requests_get({case.fixture: fixture}, absent=case.absent_urls)
    with mock.patch.object(composer_module.requests, "get", side_effect=get):
        dep = analyzer.analyze({name: dep})[name]
    return _finish(dep, analyzer.metadata_cache.get(name, {"name": name}))


def _packagist_name(fixture: RegistryFixture) -> str:
    """Return the package name a Packagist p2 document is keyed by.

    Args:
        fixture: The captured p2 document.

    Returns:
        The ``vendor/package`` name.
    """
    payload = fixture.payload
    assert isinstance(payload, Mapping), f"{fixture.slug} is not a JSON object"
    packages = payload.get("packages")
    assert isinstance(packages, Mapping) and packages, f"{fixture.slug} has no packages"
    name = sorted(packages)[0]
    assert isinstance(name, str)
    return name


def _score_golang(
    case: FixtureCase, fixtures: Mapping[str, RegistryFixture]
) -> DependencyRiskScore:
    """Score one captured Go module-proxy answer offline.

    Two documents, two seams: ``@latest`` is JSON and goes through
    ``fetch_json``; ``@v/<version>.mod`` is plain text and goes through
    ``fetch_url``. Both are replayed from recordings, and the module path is
    taken from the fixture's own source URL so a changed escaping rule fails at
    the replay map rather than reaching the proxy.

    Args:
        case: The conformance case, whose ``extra_fixtures`` names the module's
            ``go.mod``.
        fixtures: Every fixture captured for the ecosystem.

    Returns:
        The scored dependency.
    """
    served = {case.fixture: fixtures[case.fixture]}
    for extra in case.extra_fixtures:
        served[extra] = fixtures[extra]

    name = _go_module_path(served[case.fixture])
    analyzer = GoAnalyzer()
    analyzer.clone_repos = False
    # A github.com module path resolves by rule, with no lookup; passing a
    # fetcher that answers nothing makes "this test never reaches the network"
    # true of the vanity path too rather than merely unexercised.
    analyzer.resolver = GoModuleResolver(fetch=lambda url: None)
    dep = DependencyMetadata(name=name, installed_version=case.installed_version)

    json_fetch = replay_fetcher(
        {k: v for k, v in served.items() if v.fmt == "json"},
    )
    text_fetch = replay_fetcher({k: v for k, v in served.items() if v.fmt == "text"})

    with (
        mock.patch(
            "dependency_risk_profiler.analyzers.golang.fetch_json",
            side_effect=json_fetch,
        ),
        mock.patch(
            "dependency_risk_profiler.analyzers.golang.fetch_url",
            side_effect=text_fetch,
        ),
    ):
        dep = analyzer.analyze({name: dep})[name]
    return _finish(dep, analyzer.metadata_cache.get(name, {"name": name}))


def _go_module_path(fixture: RegistryFixture) -> str:
    """Return the module path a captured ``@latest`` URL was taken for.

    Args:
        fixture: The captured ``@latest`` document.

    Returns:
        The Go module path.
    """
    prefix = "https://proxy.golang.org/"
    assert fixture.source_url.startswith(prefix), fixture.source_url
    path = fixture.source_url[len(prefix) :]
    assert path.endswith("/@latest"), fixture.source_url
    return path[: -len("/@latest")]


def _score_maven(
    case: FixtureCase, fixtures: Mapping[str, RegistryFixture]
) -> DependencyRiskScore:
    """Score one captured Maven Central artifact offline.

    Maven answers with XML, not JSON, and across two documents: the artifact's
    ``maven-metadata.xml`` (latest version, last publication) and the version's
    own ``.pom`` (repository, licence, dependencies). Both are replayed as
    bytes, so the real XML parse runs.

    Args:
        case: The conformance case, naming the POM fixture, with the metadata
            document in ``extra_fixtures``.
        fixtures: Every fixture captured for the ecosystem.

    Returns:
        The scored dependency.
    """
    served = {case.fixture: fixtures[case.fixture]}
    for extra in case.extra_fixtures:
        served[extra] = fixtures[extra]

    coordinate = _maven_coordinate(served[case.fixture])
    name = coordinate.key
    analyzer = MavenAnalyzer()
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version=case.installed_version)

    # The adapter prefers the installed version's own POM and falls back to the
    # latest. Only the latest is captured, so the installed one is recorded as
    # a 404 — which is what Maven Central answers for a version that was never
    # published, and the branch the fallback exists for.
    absent = list(case.absent_urls)
    if case.installed_version != coordinate.version:
        absent.append(
            pom_url(
                PomCoordinate(
                    coordinate.group_id, coordinate.artifact_id, case.installed_version
                )
            )
        )

    get = replay_requests_get(served, absent=absent)
    with (
        mock.patch.object(maven_module.requests, "get", side_effect=get),
        mock.patch.object(maven_central_module.requests, "get", side_effect=get),
    ):
        dep = analyzer.analyze({name: dep})[name]
    return _finish(dep, analyzer.metadata_cache.get(name, {"name": name}))


def _maven_coordinate(fixture: RegistryFixture) -> PomCoordinate:
    """Return the coordinate a captured POM describes.

    The POM is parsed with the tool's own reader rather than pattern-matched,
    so an artifact that inherits its ``groupId`` from a parent — guava does —
    resolves the same way the adapter resolves it.

    Args:
        fixture: The captured ``.pom`` document.

    Returns:
        The ``groupId:artifactId:version`` triple.
    """
    root = parse_xml_bytes(fixture.body, fixture.source_url)
    assert root is not None, f"{fixture.slug} did not parse as XML"
    document = read_pom(root)
    group_id = document.effective_group_id
    artifact_id = document.artifact_id
    version = document.effective_version
    assert group_id and artifact_id and version, f"{fixture.slug} has no coordinate"
    return PomCoordinate(group_id, artifact_id, version)


def _score_nuget(
    case: FixtureCase, fixtures: Mapping[str, RegistryFixture]
) -> DependencyRiskScore:
    """Score one captured nuget.org package offline.

    The most multi-document ecosystem of the eight: a flat-container version
    index, a registration index whose newest page carries the catalog entry,
    and the package's own XML ``.nuspec``. The replay map serves all three from
    one recording set, so the client's own budget, host allowlist and page-walk
    all run for real.

    Args:
        case: The conformance case, naming the nuspec fixture, with the version
            index and registration index in ``extra_fixtures``.
        fixtures: Every fixture captured for the ecosystem.

    Returns:
        The scored dependency.
    """
    served = {case.fixture: fixtures[case.fixture]}
    for extra in case.extra_fixtures:
        served[extra] = fixtures[extra]

    package_id, version = _nuspec_identity(served[case.fixture])
    analyzer = NuGetAnalyzer(client=NuGetRegistryClient(enabled=True))
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=package_id, installed_version=case.installed_version)

    absent = list(case.absent_urls)
    if case.installed_version.lower() != version.lower():
        lowered = package_id.lower()
        absent.append(
            f"{FLAT_CONTAINER_BASE}/{lowered}/{case.installed_version.lower()}/"
            f"{lowered}.nuspec"
        )

    get = replay_requests_get(served, absent=absent)
    with mock.patch.object(nuget_registry_module.requests, "get", side_effect=get):
        dep = analyzer.analyze({package_id: dep})[package_id]
    return _finish(dep, analyzer.metadata_cache.get(package_id, {"name": package_id}))


def _nuspec_identity(fixture: RegistryFixture) -> Tuple[str, str]:
    """Return the package id and version a captured nuspec declares.

    Args:
        fixture: The captured ``.nuspec`` document.

    Returns:
        The declared id and version.
    """
    root = parse_xml_bytes(fixture.body, fixture.source_url)
    assert root is not None, f"{fixture.slug} did not parse as XML"
    document = parse_nuspec(root)
    assert document is not None, f"{fixture.slug} carries no <metadata>"
    assert document.package_id and document.version, f"{fixture.slug} has no identity"
    return document.package_id, document.version


DRIVERS = {
    "cargo": _score_cargo,
    "composer": _score_composer,
    "golang": _score_golang,
    "maven": _score_maven,
    "nodejs": _score_nodejs,
    "nuget": _score_nuget,
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
    "composer": {
        "deprecation": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "Packagist marks a replaced package with 'abandoned', either "
                "true or the name of its successor. Absent key means False "
                "forever, the same shape as npm's."
            ),
        ),
        "source_repository": Polarity(
            default=1.0,
            non_default=0.0,
            why=(
                "Same as npm's: a source.url read that finds nothing records "
                "UNDECLARED and scores 1.0, which a dead read also produces."
            ),
        ),
        "exploit": Polarity(
            default=0.0,
            non_default=1.0,
            why="has_known_exploits defaults to False.",
            proven_elsewhere=(
                "Not registry-driven; see the nodejs entry. Packagist is the "
                "second registry to publish its own advisory feed the adapter "
                "does not read — the p2 document carries a top-level "
                "'security-advisories' key, kept in the fixtures so the "
                "decision stays visible. Left unread for PyPI's reason (#171): "
                "OSV answers the same question across every ecosystem and with "
                "a real severity model."
            ),
        ),
    },
    "golang": {
        "deprecation": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "Go states a module's retirement in its own go.mod, as a "
                "'// Deprecated:' comment on the module directive, and the "
                "proxy serves that file at @v/<version>.mod. Nothing read it, "
                "so is_deprecated was False for every Go module ever scanned — "
                "measured, and measured wrong, which is #142's shape exactly. "
                "github.com/golang/protobuf is the captured ground truth."
            ),
        ),
        "source_repository": Polarity(
            default=1.0,
            non_default=0.0,
            why=(
                "A module path is an import path, not a repository URL, and "
                "the ones that do not resolve leave eight signals quiet. Until "
                "#73 the adapter recorded neither answer, so the signal was "
                "absent from the score rather than measured either way."
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
    "maven": {
        "deprecation": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "is_deprecated defaults to False, and for a Maven artifact it "
                "stays there."
            ),
            proven_elsewhere=(
                "UNPROVEN, and structurally so: Maven Central publishes no "
                "retirement marker at all. There is no POM element and no "
                "maven-metadata field for it — the closest thing Maven has is "
                "<distributionManagement><relocation>, which says an artifact "
                "MOVED, not that it was retired, and which the adapter does "
                "not read either. So the deprecation signal reads as measured "
                "and False for every artifact in Maven Central, and no "
                "captured payload can make it read otherwise. This is #142's "
                "shape with no ground truth to capture: the fix is either to "
                "read <relocation> as the nearest available fact or to stop "
                "reporting deprecation as measured for this ecosystem, and "
                "both are scoring changes rather than fixture work, and both are "
                "filed as #179. Recorded here rather than left as a silent "
                "green."
            ),
        ),
        "source_repository": Polarity(
            default=1.0,
            non_default=0.0,
            why=(
                "A POM that declares neither <scm> nor a repository-shaped "
                "<url> records UNDECLARED and scores 1.0, which is also what "
                "the adapter produced for every artifact before #73, because "
                "it never recorded the answer at all."
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
    "nuget": {
        "source_repository": Polarity(
            default=1.0,
            non_default=0.0,
            why=(
                "nuget resolved a repository off the nuspec and then recorded "
                "nothing about whether one was declared, so the signal was "
                "dropped from the score entirely and nuget alone measured 15 "
                "where the other seven measured 16 (#183). Now that it is "
                "recorded, it has npm's shape: a read that finds nothing "
                "records UNDECLARED and scores 1.0, which a dead read also "
                "produces, so the DECLARED branch has to be proven by value."
            ),
        ),
        "deprecation": Polarity(
            default=0.0,
            non_default=1.0,
            why=(
                "nuget.org publishes a real deprecation object — reasons, "
                "message, and the package that supersedes it — on the catalog "
                "entry. #129 read it from the registration5-semver1 hive, "
                "which does not carry the key: the block exists only in "
                "registration5-gz-semver2. Every .NET package therefore read "
                "as not-deprecated no matter what nuget.org said about it "
                "(#73). Microsoft.Azure.ServiceBus is the captured ground "
                "truth, and the two hives were captured side by side to prove "
                "the key's absence was the registry's shape and not a fetch "
                "failure."
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
            SignalValue(
                "transitive",
                unmeasured=True,
                because=(
                    "the adapter reads no dependency list from the packument, "
                    "so nothing measured this and nothing marks it on the "
                    "adapter's behalf. Before #199 that silence scored a "
                    "confident 0.0 (#141's shape, in the one field it survived)"
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
            SignalValue(
                "transitive",
                unmeasured=True,
                because=(
                    "rubygems' versions endpoint carries a dependencies object "
                    "the adapter does not read, so nothing measured this (#199)"
                ),
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
            SignalValue(
                "transitive",
                unmeasured=True,
                because=(
                    "PyPI publishes requires_dist and the adapter does not read "
                    "it; an unread field is not a measured empty tree (#199)"
                ),
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
            SignalValue(
                "transitive",
                unmeasured=True,
                because=(
                    "crates.io serves dependencies from a separate endpoint the "
                    "adapter never calls, so nothing measured this (#199)"
                ),
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

COMPOSER_CASES: Tuple[FixtureCase, ...] = (
    FixtureCase(
        ecosystem="composer",
        fixture="monolog",
        installed_version="2.0.0",
        purpose=(
            "The coverage floor case. Packagist's p2 document is minified "
            "(composer/2.0): the head entry is complete and every later one "
            "carries only what changed from its predecessor, which is why the "
            "adapter reads the head and nothing else. The reduced fixture "
            "keeps three entries so that property is visible in the payload "
            "rather than asserted in a comment."
        ),
        expected_latest_version="3.10.0",
        expected_repository_url="https://github.com/Seldaek/monolog",
        expected_license_id="MIT",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "'license' is a list (['MIT']), the RubyGems shape rather than the "
            "npm one; #134's fix is what makes it read at all.",
            "source.url carries a .git suffix and has to be trimmed.",
            "the entry's 'require' block is {php: >=8.1, psr/log: ...}: one "
            "package and one platform constraint, so the platform filter is "
            "load-bearing even on the floor case (#180).",
        ),
        signals=(
            SignalValue(
                "license",
                equals=0.0,
                because="MIT read out of the licenses *list*",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="source.url is declared — non-default branch",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="monolog is not abandoned; the default branch",
            ),
            SignalValue(
                "maintainer",
                equals=1.0,
                because="composer.json declares one author, and one is a risk",
            ),
            SignalValue(
                "version",
                equals=1.0,
                because="2.0.0 against a 3.x latest is a major-version gap",
            ),
            SignalValue(
                "staleness",
                minimum=0.0,
                maximum=1.0,
                because=(
                    "read off the head entry's 'time'; the step moves with the "
                    "calendar, so only measurement is pinned"
                ),
            ),
            SignalValue(
                "community",
                minimum=0.0,
                maximum=1.0,
                because="a resolvable repository lets the star scrape land",
            ),
            SignalValue(
                "transitive",
                equals=0.1,
                because=(
                    "one runtime package, psr/log. 'php' is a platform "
                    "constraint and is not counted; the nineteen entries in "
                    "'require-dev' are not what installing monolog pulls in "
                    "and are not read (#180)"
                ),
            ),
        ),
    ),
    FixtureCase(
        ecosystem="composer",
        fixture="swiftmailer",
        installed_version="6.0.0",
        purpose=(
            "The deprecation non-default branch, captured. Packagist's "
            "'abandoned' marker is a two-valued thing — true, or the name of "
            "the successor — and swiftmailer carries the second form, naming "
            "symfony/mailer."
        ),
        expected_latest_version="6.3.0",
        expected_repository_url="https://github.com/swiftmailer/swiftmailer",
        expected_license_id="MIT",
        expected_deprecated=True,
        ground_truth=(
            "'abandoned' is the string 'symfony/mailer', not the boolean true.",
            "the last release shipped in October 2021.",
            "'require' names four packages and 'php'; 'require-dev' names two "
            "more. Counting the dev block would move the transitive score from "
            "0.1 to 0.25, which is what pins the runtime-only decision (#180).",
        ),
        signals=(
            SignalValue(
                "deprecation",
                equals=1.0,
                because=(
                    "THE assertion for composer. A dead read of 'abandoned' "
                    "gives False here forever, and False is measured (#142)"
                ),
            ),
            SignalValue(
                "transitive",
                equals=0.1,
                because=(
                    "four runtime packages. Six — the dev block folded in — "
                    "would score 0.25, so this value is the require-vs-"
                    "require-dev decision asserted rather than described"
                ),
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="last released in October 2021; over a year is maximum",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="an abandoned package still declares its repository",
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="MIT; abandoning a package does not unlicense it",
            ),
            SignalValue(
                "maintainer",
                equals=0.5,
                because="composer.json declares two authors",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="composer",
        fixture="psr-log",
        installed_version="1.0.0",
        purpose=(
            "The maintainer count's honest caveat, on a real package. "
            "Packagist publishes no per-package owner endpoint, so the count "
            "comes from composer.json's declared authors — and psr/log "
            "declares exactly one, 'PHP-FIG', which is a working group rather "
            "than a person. It scores the single-maintainer verdict. This is "
            "python/flask's finding in a second ecosystem, and unlike flask's "
            "it cannot be told apart from a genuine bus factor of one from the "
            "payload alone."
        ),
        expected_latest_version="3.0.2",
        expected_repository_url="https://github.com/php-fig/log",
        expected_license_id="MIT",
        expected_deprecated=False,
        ground_truth=(
            "authors is [{'name': 'PHP-FIG', 'homepage': ...}] — one entry, an "
            "organization, with no email and no account.",
            "there is no owners endpoint on Packagist to check it against.",
            "'require' is {'php': '>=8.0.0'} and nothing else, so the whole "
            "block is platform constraints and the measured answer is zero "
            "packages — the one payload where the filter and a dead read give "
            "different numbers (0.0 against 0.1).",
        ),
        signals=(
            SignalValue(
                "maintainer",
                equals=1.0,
                because=(
                    "one declared author scores the worst bus factor, and the "
                    "author is an organization; recorded rather than rounded off"
                ),
            ),
            SignalValue(
                "transitive",
                equals=0.0,
                because=(
                    "THE #180 platform-filter assertion: psr/log requires only "
                    "'php', which is a runtime and not a package. A measured "
                    "zero, not an unmeasured one and not a phantom dependency"
                ),
            ),
            SignalValue(
                "version",
                equals=1.0,
                because="1.0.0 against a 3.x latest is a major-version gap",
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="3.0.2 shipped in September 2024",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="source.url is declared",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="composer",
        fixture="mailgun-php",
        installed_version="4.5.1",
        purpose=(
            "The platform filter's sharpest edge, and the reason it tests the "
            "vendor prefix rather than the name. mailgun/mailgun-php requires "
            "six packages, three of them under the php-http vendor: "
            "php-http/client-common, php-http/discovery and "
            "php-http/multipart-stream-builder. A filter that checked the "
            "'php-' prefix before the slash would delete all three and report "
            "three dependencies where there are six — the same class of quiet "
            "wrongness as #142, arrived at from the opposite direction (#180)."
        ),
        expected_latest_version="4.5.1",
        expected_repository_url="https://github.com/mailgun/mailgun-php",
        expected_license_id="MIT",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "require names 'php' and six vendored packages; three of the six "
            "start with 'php-', which is also a platform prefix.",
            "source.url carries a .git suffix and has to be trimmed.",
        ),
        signals=(
            SignalValue(
                "transitive",
                equals=0.25,
                because=(
                    "six runtime packages. Dropping the three php-http/* names "
                    "as platform constraints would leave three and score 0.1, "
                    "so this value is the vendor-prefix rule asserted"
                ),
            ),
            SignalValue(
                "version",
                equals=0.0,
                because="the installed version is the latest one Packagist has",
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="MIT, read out of the licenses list",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="source.url is declared",
            ),
            SignalValue(
                "staleness",
                minimum=0.0,
                maximum=1.0,
                because=(
                    "read off the head entry's 'time'; the step moves with the "
                    "calendar, so only measurement is pinned"
                ),
            ),
        ),
    ),
)

GOLANG_CASES: Tuple[FixtureCase, ...] = (
    FixtureCase(
        ecosystem="golang",
        fixture="logrus.latest",
        extra_fixtures=("logrus.mod",),
        installed_version="1.8.0",
        purpose=(
            "The coverage floor case, and the one that shows where the floor "
            "actually is. proxy.golang.org answers with a version, a date and "
            "a go.mod, and nothing else: no licence, no owners. Six measured "
            "signals is the honest number, and it leaves Go modules short of "
            "the insufficient-data bar without a clone."
        ),
        expected_latest_version="v1.9.4",
        expected_repository_url="https://github.com/sirupsen/logrus",
        expected_license_id=None,
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "@latest carries 'Time' beside 'Version', and an 'Origin' object "
            "naming the VCS and the commit — the adapter reads Version and "
            "Time; Origin.URL is the proxy's own answer to the question the "
            "module-path resolver answers by rule.",
            "the go.mod carries no '// Deprecated:' comment.",
        ),
        signals=(
            SignalValue(
                "staleness",
                minimum=0.0,
                maximum=1.0,
                because=(
                    "read off @latest's 'Time'. Before #73 nothing read that "
                    "key and a Go module had no cadence at all without a "
                    "clone; the step itself moves with the calendar"
                ),
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="the module path resolves to a repository — non-default branch",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="logrus is not retired; the default branch",
            ),
            SignalValue(
                "version",
                minimum=0.25,
                because="1.8.0 against v1.9.4 is a real minor gap",
            ),
            SignalValue(
                "license",
                unmeasured=True,
                because=(
                    "the module proxy publishes no licence field; unmeasured, "
                    "never a confident zero (#74)"
                ),
            ),
            SignalValue(
                "maintainer",
                unmeasured=True,
                because="Go has no module-level owner concept to read",
            ),
            SignalValue(
                "community",
                minimum=0.0,
                maximum=1.0,
                because="a resolvable repository lets the star scrape land",
            ),
            SignalValue(
                "transitive",
                unmeasured=True,
                because=(
                    "the proxy serves the module's go.mod and the adapter reads "
                    "it for the version, not for the require block (#199)"
                ),
            ),
        ),
    ),
    FixtureCase(
        ecosystem="golang",
        fixture="protobuf.latest",
        extra_fixtures=("protobuf.mod",),
        installed_version="1.3.0",
        purpose=(
            "The deprecation non-default branch, and the fifth adapter caught "
            "in #142's shape. github.com/golang/protobuf has been retired in "
            "favour of google.golang.org/protobuf since 2020, says so on the "
            "first line of its own go.mod, and read as not-deprecated for the "
            "life of the Go adapter because nothing fetched that file."
        ),
        expected_latest_version="v1.5.4",
        expected_repository_url="https://github.com/golang/protobuf",
        expected_license_id=None,
        expected_deprecated=True,
        ground_truth=(
            "the go.mod's first line is '// Deprecated: Use the "
            '"google.golang.org/protobuf" module instead.\', immediately '
            "above the module directive.",
            "@latest reports v1.5.4 with no deprecation field of its own — the "
            "marker exists only in the go.mod, which is why it needed a second "
            "endpoint rather than a second key.",
        ),
        signals=(
            SignalValue(
                "deprecation",
                equals=1.0,
                because=(
                    "THE assertion for golang. Without the go.mod read this is "
                    "False forever, and False is measured, so only the value "
                    "catches it (#142)"
                ),
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="v1.5.4 shipped in March 2024",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="a retired module still resolves to its repository",
            ),
            SignalValue(
                "license",
                unmeasured=True,
                because="the module proxy publishes no licence field",
            ),
        ),
    ),
)

MAVEN_CASES: Tuple[FixtureCase, ...] = (
    FixtureCase(
        ecosystem="maven",
        fixture="jackson-databind.pom",
        extra_fixtures=("jackson-databind.metadata",),
        installed_version="2.9.0",
        purpose=(
            "The coverage floor case, and maven's first floor of any kind: "
            "#141 left the ecosystem with no entry in signal_floors at all. "
            "jackson-databind declares <licenses>, <scm> and <dependencies> in "
            "its own POM, which is the shape the adapter was written for and "
            "is rarer than it looks — see the guava case."
        ),
        expected_latest_version="2.22.1",
        expected_repository_url="https://github.com/FasterXML/jackson-databind",
        expected_license_id="APACHE",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "maven-metadata.xml states <lastUpdated> as a bare yyyyMMddHHmmss "
            "in UTC; nothing read it before #73 and staleness was unmeasured "
            "for every Maven artifact without a clone.",
            "<scm><url> points at the repository root already, so the "
            "canonicalizer has nothing to trim here.",
            "the POM declares its own <dependencies>, which is a measured "
            "transitive signal rather than an assumed-empty one (#141).",
        ),
        signals=(
            SignalValue(
                "staleness",
                minimum=0.0,
                maximum=1.0,
                because=(
                    "THE #73 assertion for maven: measured at all. Read off "
                    "<lastUpdated>; the step moves with the calendar"
                ),
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="the POM declares <scm> — non-default branch",
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="Apache 2.0, read from the POM's own <licenses>",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because=(
                    "the default branch, and the only branch Maven Central can "
                    "reach — see the maven deprecation waiver"
                ),
            ),
            SignalValue(
                "version",
                minimum=0.25,
                because="2.9.0 against a 2.22.x latest is a real minor gap",
            ),
            SignalValue(
                "transitive",
                minimum=0.0,
                maximum=1.0,
                because="the POM's <dependencies> block is a real measurement",
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
                    "Maven Central publishes no owner list; <developers> is "
                    "free text in a POM the artifact's own author controls"
                ),
            ),
            SignalValue(
                "transitive",
                equals=0.1,
                because=(
                    "the POM's scope-filtered <dependencies> is a real read: "
                    "two shipped artifacts, which is the 1-4 bucket. This is "
                    "the marker PR #198 found written as a bare string literal, "
                    "one typo from reverting to a fabricated zero"
                ),
            ),
        ),
    ),
    FixtureCase(
        ecosystem="maven",
        fixture="guava.pom",
        extra_fixtures=("guava.metadata", "guava-parent.pom"),
        installed_version="20.0",
        purpose=(
            "Inheritance at one hop, which is where most of the Java ecosystem "
            "keeps its licence. Maven's convention is to declare <licenses>, "
            "<scm> and <developers> once in a parent POM, and guava does "
            "exactly that: its own POM carries none of the three. The adapter "
            "used to read the artifact POM and stop, so guava's licence was "
            "unmeasured while Maven Central served it one request away, and "
            "the same held for every Apache Commons artifact — commons-lang3's "
            "licence is two hops up, in org.apache:apache (#178). It now walks "
            "the parent chain — through the "
            "same bounded client #141 built for version resolution — and this "
            "case is the ground truth for the walk."
        ),
        expected_latest_version="33.6.0-jre",
        expected_repository_url="https://github.com/google/guava",
        expected_license_id="APACHE",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "guava's own POM has no <licenses> and no <scm>; both are in "
            "com.google.guava:guava-parent, which is captured beside it so the "
            "walk is replayed rather than stubbed.",
            "the parent's <scm><url> and the child's <url> happen to be the "
            "same GitHub page here, so the licence is what the walk actually "
            "recovers — before it, this artifact reported no licence at all.",
            "Maven would append the child's artifactId to the inherited "
            "<scm><url> and produce .../google/guava/guava; the append is "
            "skipped because canonical_repository_url trims it straight off.",
        ),
        signals=(
            SignalValue(
                "license",
                equals=0.0,
                because=(
                    "THE #178 assertion: Apache 2.0, declared only in "
                    "guava-parent. Unmeasured here before the parent walk"
                ),
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because="declared — by the parent's <scm> and the child's <url>",
            ),
            SignalValue(
                "transitive",
                equals=0.25,
                because="guava's own POM declares five shipped dependencies",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="the default branch; see the maven deprecation waiver",
            ),
            SignalValue(
                "maintainer",
                unmeasured=True,
                because=(
                    "<developers> is inherited too, and is still free text the "
                    "artifact's own author controls; not read either way"
                ),
            ),
        ),
    ),
    FixtureCase(
        ecosystem="maven",
        fixture="slf4j-api.pom",
        extra_fixtures=("slf4j-api.metadata", "slf4j-parent.pom", "slf4j-bom.pom"),
        installed_version="1.7.0",
        purpose=(
            "Inheritance at two hops, and the case that proves the walk does "
            "not stop at the first parent. slf4j-api declares no <scm>, no "
            "<licenses> and a <url> of http://www.slf4j.org that is a project "
            "homepage rather than a repository; its parent, slf4j-parent, "
            "declares none of the three either; slf4j-bom, the grandparent, "
            "declares both the MIT licence and the qos-ch/slf4j repository. "
            "This case used to assert the UNDECLARED branch — that was the "
            "adapter's blindness being read as slf4j's silence."
        ),
        expected_latest_version="2.1.0-alpha1",
        expected_repository_url="https://github.com/qos-ch/slf4j",
        expected_license_id="MIT",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "no <scm>, no <licenses> and no usable <url> anywhere in the first "
            "two POMs; both facts are in org.slf4j:slf4j-bom, two hops up.",
            "<scm> outranks <url> even when the <url> is nearer, which is why "
            "http://www.slf4j.org does not win over the grandparent's repo.",
            "<release> in maven-metadata.xml is an alpha, which is what the "
            "adapter reports as latest because that is what Maven Central "
            "names as the release.",
        ),
        signals=(
            SignalValue(
                "source_repository",
                equals=0.0,
                because=(
                    "DECLARED, two hops up — the walk does not stop at one. "
                    "This read 1.0 under #176 because the artifact's own POM "
                    "has no <scm>, which was the adapter's blindness being "
                    "recorded as slf4j's silence (#178)"
                ),
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="MIT, from slf4j-bom; unmeasured before the parent walk",
            ),
            SignalValue(
                "community",
                minimum=0.0,
                maximum=1.0,
                because="an inherited repository is still a repository to scrape",
            ),
            SignalValue(
                "transitive",
                equals=0.0,
                because=(
                    "the artifact's own <dependencies> is empty and someone "
                    "looked; <dependencies> is not inherited"
                ),
            ),
            SignalValue(
                "version",
                equals=1.0,
                because="1.7.0 against a 2.x latest is a major-version gap",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="maven",
        fixture="javax.inject.pom",
        extra_fixtures=("javax.inject.metadata",),
        installed_version="1",
        purpose=(
            "The zero-hop bound on #178's parent walk, and #176's UNUSABLE "
            "state arrived at from a second direction. javax.inject has no "
            "<parent> at all, so the walk yields exactly one document and "
            "costs no fetch beyond the artifact's own POM — the case that "
            "shows inheritance is not something every artifact pays for. Its "
            "<scm> and <url> both point at code.google.com, which was shut "
            "down in 2016: log4j declares a Subversion host that still "
            "answers, this one declares a host that no longer exists, and "
            "both are DECLARED-but-unusable rather than undeclared. It is "
            "also the only case pinning the unmeasured *version* branch, "
            "below. It was captured under #178 to hold maven's UNDECLARED "
            "branch after inheritance rescued slf4j-api; #176 landed first "
            "and gave that branch to commons-collections, which declares "
            "nothing at all, so this case holds the other two properties "
            "instead."
        ),
        expected_repository_url=None,
        expected_license_id="APACHE",
        expected_deprecated=False,
        ground_truth=(
            "maven-metadata.xml states neither <release> nor <latest>, only a "
            "<versions> list of one, so latest_version is honestly unmeasured "
            "and the version signal drops out rather than reporting parity.",
            "<lastUpdated> is 20100720032040 — the staleness signal working on "
            "the population it exists for.",
            "the licence is in the artifact's own POM, so this case also pins "
            "that the walk does not need a parent to find one.",
        ),
        signals=(
            SignalValue(
                "source_repository",
                equals=0.75,
                because=(
                    "declared, and not a git forge — the same third state "
                    "log4j lands in, from a host that was decommissioned "
                    "rather than merely obsolete. 1.0 would say javax.inject "
                    "never named a source, and it did"
                ),
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="Apache 2.0, declared in the artifact's own POM",
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="one release, July 2010; maximum staleness",
            ),
            SignalValue(
                "transitive",
                equals=0.0,
                because="no <dependencies> and no parent; a measured zero",
            ),
            SignalValue(
                "community",
                unmeasured=True,
                because="no resolvable repository to scrape stars from",
            ),
            SignalValue(
                "version",
                unmeasured=True,
                because=(
                    "maven-metadata.xml names no release, so there is nothing "
                    "to compare the installed version against. The only case "
                    "pinning this branch; a read that defaulted to the "
                    "installed version would report parity forever"
                ),
            ),
        ),
    ),
    FixtureCase(
        ecosystem="maven",
        fixture="ant.pom",
        extra_fixtures=("ant.metadata", "ant-parent.pom"),
        installed_version="1.10.13",
        purpose=(
            "Where #178 and #176 meet, and the case that keeps the meeting "
            "honest. ant 1.10.13 declares no <scm> of its own; ant-parent "
            "declares one, and it points at gitbox.apache.org, which is not a "
            "git forge the canonicalizer can resolve. So the artifact has "
            "DECLARED a source repository — in the Apache idiom, through its "
            "parent — and it is unusable. Recording the #176 'declared' "
            "argument off the artifact's own POM would report UNDECLARED at "
            "1.0 here: 'this project never said where its source lives', "
            "about a project that said so one document away. That is #182's "
            "fabricated negative arrived at from a third direction, and "
            "without this fixture the leaf-POM read passes every other test. "
            "org.apache.velocity:velocity-engine-core is the same shape at "
            "three hops."
        ),
        expected_latest_version="1.10.17",
        expected_repository_url=None,
        expected_license_id="APACHE",
        expected_deprecated=False,
        ground_truth=(
            "ant's own POM has no <scm> and no <licenses>; ant-parent has "
            "both, and its <scm> is "
            "https://gitbox.apache.org/repos/asf/ant.git.",
            "the project <url> inherited from the parent is "
            "https://ant.apache.org/, a docs site, so no fallback rescues the "
            "repository either — the artifact is genuinely unclonable.",
            "ant declares five dependencies and four of them are <scope>test"
            "</scope>, so only ant-launcher ships.",
        ),
        signals=(
            SignalValue(
                "source_repository",
                equals=0.75,
                because=(
                    "THE assertion for the #178/#176 interaction: DECLARED by "
                    "the parent and not a git forge. 1.0 is what a leaf-only "
                    "read of 'declared' produces, and it is a fabricated "
                    "negative"
                ),
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="Apache 2.0, inherited from ant-parent one hop up",
            ),
            SignalValue(
                "transitive",
                equals=0.1,
                because=(
                    "one shipped dependency. Counting the four test-scoped "
                    "ones would score 0.25, so this pins the scope filter too"
                ),
            ),
            SignalValue(
                "community",
                unmeasured=True,
                because="a gitbox URL is no more scrapeable than no URL at all",
            ),
            SignalValue(
                "staleness",
                minimum=0.0,
                maximum=1.0,
                because=(
                    "read off <lastUpdated>; the step moves with the calendar, "
                    "so only measurement is pinned"
                ),
            ),
        ),
    ),
    FixtureCase(
        ecosystem="maven",
        fixture="log4j.pom",
        extra_fixtures=("log4j.metadata",),
        installed_version="1.2.17",
        purpose=(
            "#176's acceptance case, first half: an artifact that declares a "
            "source repository nobody can clone. log4j 1.2.17's <scm> names "
            "svn.apache.org — a Subversion host, not a git forge, and long "
            "decommissioned. Before #176 this scored identically to an "
            "artifact that declares no <scm> at all, which threw away the only "
            "thing separating a project of 2012 from one that never said where "
            "its source lived. PR #175 sampled 25 artifacts across both eras: "
            "9 declared no <scm>, 12 named SVN or CVS, and the 4 that named a "
            "forge all resolved. Untouched by #178's parent walk: log4j has no "
            "<parent>, so there is nowhere for inheritance to rescue it from."
        ),
        expected_latest_version="1.2.17",
        expected_repository_url=None,
        expected_license_id="APACHE",
        expected_deprecated=False,
        ground_truth=(
            "<scm> is present and carries all three of <connection>, "
            "<developerConnection> and <url>; every one of them is Subversion.",
            "<url> at the project level is http://logging.apache.org/log4j/1.2/, "
            "a docs site, so no fallback rescues the repository either.",
            "maven-metadata.xml's <lastUpdated> is 20140318154402 — the "
            "artifact is a decade dead and still one of the most depended-on "
            "jars in the ecosystem.",
            "no <parent> element, so the #178 walk reads one document here.",
        ),
        signals=(
            SignalValue(
                "source_repository",
                equals=0.75,
                because=(
                    "THE #176 assertion. Declared, and not a git forge: the "
                    "third state. Both 1.0 (as this scored before) and 0.0 are "
                    "wrong, and the pair with commons-collections is what "
                    "proves the two states are distinguishable at all"
                ),
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="last published March 2014",
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="Apache 2.0, declared in the artifact's own <licenses>",
            ),
            SignalValue(
                "community",
                unmeasured=True,
                because="an SVN URL is no more scrapeable than no URL at all",
            ),
            SignalValue(
                "transitive",
                minimum=0.0,
                maximum=1.0,
                because="the POM declares its own <dependencies>",
            ),
        ),
    ),
    FixtureCase(
        ecosystem="maven",
        fixture="commons-collections.pom",
        extra_fixtures=("commons-collections.metadata",),
        installed_version="3.1",
        purpose=(
            "#176's acceptance case, second half, and the artifact log4j has "
            "to be told apart from. commons-collections 3.1 carries no <scm> "
            "element of any kind — the string 'scm' does not appear in the "
            "POM. It never said where its source lived; log4j said so and the "
            "answer rotted. Different facts, and until #176 they were the same "
            "recorded value. Since #178 it is also maven's only UNDECLARED "
            "case, and it holds that branch honestly: it has no <parent>, so "
            "there is no inheritance that could rescue it and none that has "
            "to be suppressed to keep the branch reachable."
        ),
        expected_latest_version="20040616",
        expected_repository_url=None,
        expected_license_id=None,
        expected_deprecated=False,
        ground_truth=(
            "the POM has no <scm> element and no <licenses> block; its only "
            "<url> is the organization's, http://www.apache.org.",
            "maven-metadata.xml names 20040616 as both <latest> and <release>, "
            "which is a date masquerading as a version and is what Maven "
            "Central actually publishes for this artifact.",
            "no <parent> element either, so 'no licence' survives the #178 "
            "walk as a fact about the artifact rather than about the reader.",
        ),
        signals=(
            SignalValue(
                "source_repository",
                equals=1.0,
                because=(
                    "the other half of THE #176 assertion: nothing declared, "
                    "so the undeclared branch, and it must not collapse into "
                    "log4j's 0.75"
                ),
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="3.1 shipped in 2004 and the line stopped in 2015",
            ),
            SignalValue(
                "license",
                unmeasured=True,
                because=(
                    "no <licenses> in the artifact POM and no <parent> to "
                    "inherit one from; unmeasured, not zero, even after #178"
                ),
            ),
            SignalValue(
                "transitive",
                equals=0.0,
                because="the POM declares no dependencies, and someone looked",
            ),
        ),
    ),
)

NUGET_CASES: Tuple[FixtureCase, ...] = (
    FixtureCase(
        ecosystem="nuget",
        fixture="newtonsoft.json.nuspec",
        extra_fixtures=("newtonsoft.json.versions", "newtonsoft.json.registration"),
        installed_version="12.0.1",
        purpose=(
            "The coverage floor case, and the most multi-document one of the "
            "eight: a flat-container version index, a registration index whose "
            "newest page carries the catalog entry, and the package's own XML "
            "nuspec — three URLs served from one recording set, with the "
            "client's host allowlist and page walk running for real."
        ),
        expected_latest_version="13.0.4",
        expected_repository_url="https://github.com/JamesNK/Newtonsoft.Json",
        expected_license_id="MIT",
        expected_deprecated=False,
        meets_signal_floor=True,
        ground_truth=(
            "the nuspec's <repository url> is the authoritative source "
            "pointer; <projectUrl> is a docs site on many packages and is only "
            "the fallback.",
            "the catalog entry carries 'published' and, on this package, no "
            "'deprecation' key — the absence is the healthy case here.",
        ),
        signals=(
            SignalValue(
                "license",
                equals=0.0,
                because="MIT, from the nuspec's SPDX <license type='expression'>",
            ),
            SignalValue(
                "deprecation",
                equals=0.0,
                because="Newtonsoft.Json is not deprecated; the default branch",
            ),
            SignalValue(
                "maintainer",
                equals=1.0,
                because="the nuspec declares one author, and one is a risk",
            ),
            SignalValue(
                "source_repository",
                equals=0.0,
                because=(
                    "THE #183 assertion: the nuspec's <repository url> is "
                    "declared and resolvable. Before this the signal was "
                    "absent from nuget's score altogether, so a package "
                    "declaring no repository counted eight separate unknowns "
                    "instead of one explained gap (#146)"
                ),
            ),
            SignalValue(
                "version",
                equals=1.0,
                because="12.0.1 against a 13.x latest is a major-version gap",
            ),
            SignalValue(
                "staleness",
                minimum=0.0,
                maximum=1.0,
                because=(
                    "read off the catalog entry's publication date; the step "
                    "moves with the calendar"
                ),
            ),
            SignalValue(
                "transitive",
                equals=0.25,
                because=(
                    "the nuspec states the package's own dependencies (#129): "
                    "six of them, which is the 5-19 bucket. Pinned to a value "
                    "rather than a 0..1 range since #199, because the range "
                    "admitted the 0.0 a fail-open default produces"
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
        ecosystem="nuget",
        fixture="servicebus.nuspec",
        extra_fixtures=("servicebus.versions", "servicebus.registration"),
        installed_version="4.0.0",
        purpose=(
            "The dead read the nuget capture found. nuget.org publishes a "
            "real deprecation object — reasons, message, and the package that "
            "supersedes it — and #129 read it from the wrong registration "
            "hive: registration5-semver1 serves the same catalog entries with "
            "the 'deprecation' key stripped out, and the block exists only in "
            "registration5-gz-semver2. Microsoft.Azure.ServiceBus has been "
            "deprecated in favour of Azure.Messaging.ServiceBus since 2021 and "
            "read as healthy the whole time."
        ),
        expected_latest_version="5.2.0",
        expected_repository_url="https://github.com/Azure/azure-sdk-for-net",
        expected_license_id="MIT",
        expected_deprecated=True,
        ground_truth=(
            "the SemVer2 catalog entry carries 'deprecation' with "
            "reasons: ['Other'] and alternatePackage.id "
            "'Azure.Messaging.ServiceBus'.",
            "the SemVer1 entry for the same package and version carries no "
            "'deprecation' key at all — the two were fetched side by side, so "
            "the absence is the registry's shape and not a failed request.",
            "'listed' is true and 'published' is 2021, so the unlisted "
            "fallback is not what fires here.",
        ),
        signals=(
            SignalValue(
                "deprecation",
                equals=1.0,
                because=(
                    "THE assertion for nuget. Point the client back at "
                    "registration5-semver1 and this is 0.0 forever, with every "
                    "count still green (#142's shape, fourth adapter)"
                ),
            ),
            SignalValue(
                "staleness",
                equals=1.0,
                because="5.2.0 was published in November 2021",
            ),
            SignalValue(
                "license",
                equals=0.0,
                because="MIT; deprecating a package does not unlicense it",
            ),
            SignalValue(
                "version",
                equals=1.0,
                because="4.0.0 against a 5.x latest is a major-version gap",
            ),
        ),
    ),
)

CASES: Tuple[FixtureCase, ...] = (
    NODEJS_CASES
    + RUBYGEMS_CASES
    + PYTHON_CASES
    + CARGO_CASES
    + COMPOSER_CASES
    + GOLANG_CASES
    + MAVEN_CASES
    + NUGET_CASES
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
        converted=True,
        note=(
            "Four captured p2 documents, reduced by volume only. #145 listed "
            "composer with nuget and python as never closely audited, and it "
            "is the one of the three whose audit found no dead read: every key "
            "the adapter reads, Packagist sends. What it found instead is two "
            "things the registry sends and the adapter does not read. The p2 "
            "entry states the package's own 'require' block — the same fact "
            "nuget reads out of its nuspec and scores as transitive (#129) — "
            "and composer marked the signal unmeasured anyway. And a Packagist "
            "lookup that fails records the source repository as UNDECLARED "
            "rather than unmeasured, so a 404 is scored as 'this package "
            "declares no source'. Both are closed now. The first by #180, "
            "which moved the floor from 8 to 9 and makes Packagist the highest "
            "of the eight: it is the only registry document answering both a "
            "maintainer count and a dependency list. Two judgements ride on it "
            "and both are asserted by value — platform constraints ('php', "
            "'ext-*') are not packages, proven by psr/log, whose entire "
            "require block is 'php' and whose measured answer is therefore "
            "zero rather than one; and 'require-dev' is not counted, proven by "
            "swiftmailer, where four runtime packages score 0.1 and the six "
            "that include the dev block would score 0.25. mailgun/mailgun-php "
            "was captured for the edge that judgement has: the filter tests "
            "the vendor prefix, not the name, because php-http/discovery and "
            "php-di/php-di are packages whose names start with a platform "
            "prefix. The second by #182, whose failure fixture the capture "
            "script is deliberately not able to take, so it lives beside the "
            "adapter in test_composer_adapter instead "
            "(#182). Known limit "
            "carried by psr/log: the maintainer count comes from "
            "composer.json's declared authors, so a working group counts as "
            "one maintainer and scores the worst bus factor."
        ),
    ),
    "nuget": ConversionStatus(
        converted=True,
        note=(
            "Six captured documents across two packages — a flat-container "
            "version index, a registration index and an XML nuspec each — "
            "which makes it the multi-document proof for the replay map. The "
            "capture found #142's shape in a fourth adapter, and this one was "
            "invisible from the payload alone: #129 read the deprecation block "
            "from registration5-semver1, and nuget.org publishes that block "
            "only in registration5-gz-semver2. The same catalog entry, same "
            "package, same version, differs between the two hives by exactly "
            "that key, so no amount of staring at one payload would have shown "
            "it — capturing both did. Fixed by pointing REGISTRATION_BASE at "
            "the SemVer2 hive, which is a base-URL change: the hive is "
            "gzip-encoded, not gzip-named, and requests decodes it. The "
            "conversion also recorded that nuget resolved a repository and "
            "still reported nothing either way about whether one was declared, "
            "which made it the only ecosystem measuring 15 signals where the "
            "rest measured 16; that is now fixed and the floor moved 8 -> 9 in "
            "the same change (#183, #158)."
        ),
    ),
    "maven": ConversionStatus(
        converted=True,
        note=(
            "Eighteen captured XML documents across seven artifacts — a "
            "maven-metadata.xml and an artifact POM each, plus the four "
            "parent POMs the inheritance walk reads — and the first "
            "signal_floors entry maven has ever had. It is floored at 8, "
            "which is two higher than the capture found it at, because the "
            "capture found two readings: maven-metadata.xml states "
            "<lastUpdated> and nothing read it, so staleness was unmeasured "
            "for every artifact without a clone; and the adapter never "
            "recorded whether the POM declares a source repository, so that "
            "signal was absent from the score rather than answered either way. "
            "The floor sits at the measured value, per #158. Capturing also "
            "found a third reading, closed in #178: Maven's convention is to "
            "declare <licenses> and <scm> once in a *parent* POM and inherit "
            "them, and the adapter read the artifact POM and stopped. guava "
            "(one hop) and slf4j-api (two, through a parent that declares "
            "neither) are the captured proof, and both moved from below the "
            "floor to at it — the floor itself did not move, because 8 was "
            "already everything Maven Central answers. The walk is #141's "
            "bounded parent chain, consumed lazily, so jackson-databind — "
            "which declares both in its own POM — still costs no parent fetch "
            "at all. "
            "log4j and commons-collections were captured for #176: they "
            "are the pair proving the source-repository signal has three "
            "states and not two. log4j 1.2.17 declares <scm> and every "
            "spelling of it is Subversion; commons-collections 3.1 carries no "
            "<scm> element at all. Both recorded UNDECLARED until the third "
            "state existed, which is a distinction thrown away rather than one "
            "never available — PR #175 had already found it across 25 sampled "
            "artifacts, 9 declaring none and 12 naming SVN or CVS. Neither has "
            "a <parent>, so #178's walk reads one document for each and the "
            "two states it separates stay reachable. slf4j-api used to be a "
            "third UNDECLARED artifact and is not one any more — it inherits "
            "a repository two hops up, and reading it as silence was the "
            "adapter's blindness rather than the artifact's. javax.inject, "
            "captured under #178 to hold that branch before #176 landed, "
            "turned out to declare a code.google.com <scm> and so lands in "
            "UNUSABLE beside log4j; it is kept for the zero-hop walk bound and "
            "for the unmeasured-version branch nothing else pins. ant 1.10.13 "
            "is where the two issues actually interact and is the case neither "
            "would have produced alone: it declares no <scm> itself and "
            "inherits a gitbox one, so recording #176's 'declared' argument "
            "off the artifact's own POM reports UNDECLARED about a project "
            "that declared one document away. Reverting to the leaf-POM read "
            "fails ant, javax.inject and log4j by value. "
            "Open: the "
            "deprecation branch is unprovable by construction; see "
            "POLARIZED_SIGNALS['maven']."
        ),
    ),
    "golang": ConversionStatus(
        converted=True,
        note=(
            "Four captured proxy documents across two modules, and the first "
            "ecosystem here whose registry is not a JSON registry: "
            "proxy.golang.org answers @latest with JSON and @v/<version>.mod "
            "with the module's own go.mod as text, so the fixture format and "
            "both replay seams differ from the other seven. The capture found "
            "#142's shape in a fifth adapter and the most complete instance of "
            "it yet: Go states a module's retirement as a '// Deprecated:' "
            "comment on the module directive in its go.mod, the proxy serves "
            "that file, nothing fetched it, and is_deprecated was therefore "
            "False for every Go module ever scanned. "
            "github.com/golang/protobuf — retired since 2020, says so on line "
            "one — is the captured ground truth. It also found @latest's "
            "'Time' unread, which left Go modules with no release cadence at "
            "all without a clone, on the ecosystem whose repositories are "
            "*least* likely to clone cleanly. Floored at 6 and "
            "SCORES_FROM_REGISTRY_ALONE False: the proxy publishes no licence "
            "and no owner list, so Go modules do not reach a verdict unaided, "
            "and that is recorded rather than rounded up. This conversion is "
            "also what makes #160's narrowed-B migration of golang and maven "
            "onto collect_repository_signals verifiable rather than "
            "faith-based — both now have value gates to migrate against. Known "
            "limit: @latest also publishes an 'Origin' object naming the VCS "
            "and URL, which the adapter does not read because the module-path "
            "resolver answers the same question by rule and without a request."
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


#: The ecosystems whose adapter positively records a measured transitive set,
#: from an audit of all eight (#199). nuget reads the ``.nuspec``
#: ``<dependencies>`` (#129), maven the POM's scope-filtered ``<dependencies>``,
#: composer the p2 entry's ``require`` block minus platform constraints (#180).
#:
#: The other five never assign ``transitive_dependencies`` at all — verified by
#: grep, not by trusting the list — so under the fail-closed default they
#: report the signal as unmeasured. That is not a gap that needs a waiver: it
#: is the honest answer, and it is asserted in both directions below so that
#: adding a read without recording it, or losing a read while keeping the
#: marker, both fail here.
#:
#: (npm packuments, PyPI ``requires_dist``, crates.io's dependencies endpoint,
#: rubygems' ``dependencies`` object and a module's ``go.mod`` all *carry* a
#: dependency list none of those five adapters reads. Reading them is an
#: enhancement with its own floor changes, not part of closing the default.)
TRANSITIVE_RECORDING_ECOSYSTEMS: FrozenSet[str] = frozenset(
    {"composer", "maven", "nuget"}
)


def assert_transitive_is_recorded_not_assumed(
    score: DependencyRiskScore, case: FixtureCase
) -> None:
    """Assert the transitive signal is measured exactly where it is read.

    The regression this pins is #199's: an adapter that reads no dependency
    list and records nothing must produce an UNMEASURED transitive signal, not
    a confident ``0.0``. Nothing in this harness marks the signal on the
    adapter's behalf any more, so a fail-open default would show up here as
    five ecosystems suddenly scoring 0.0 for a list they never looked at.

    Args:
        score: The scored dependency, straight from the adapter.
        case: The conformance case, for the failure message.

    Raises:
        AssertionError: If a non-reading ecosystem produced a value, or a
            reading one produced None.
    """
    records = case.ecosystem in TRANSITIVE_RECORDING_ECOSYSTEMS
    actual = score.transitive_score
    if records:
        assert actual is not None, (
            f"{case.slug}: transitive came back unmeasured, but {case.ecosystem} "
            f"reads a dependency list off its registry document. Either the "
            f"read broke or the recorder stopped being called."
        )
        return
    assert actual is None, (
        f"{case.slug}: transitive scored {actual}, but {case.ecosystem}'s "
        f"adapter reads no dependency list, so nothing measured it. A value "
        f"here means the fail-open default is back (#199): silence being read "
        f"as 'resolved, and it is empty'."
    )


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

    assert_transitive_is_recorded_not_assumed(score, case)

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


def assert_source_repository_states_are_pinned() -> None:
    """Assert every source-repository state is pinned by value somewhere.

    The signal has three answers and they are one line apart in the scorer, so
    a refactor that collapses two of them back together is cheap to make and
    invisible to a count. #176 is what happens when it goes unnoticed: "declared
    an unusable repository" and "declared none" recorded the same value for the
    life of the maven adapter, and the pair of artifacts that told them apart
    was in Maven Central the whole time.

    Raises:
        AssertionError: If any of the three scores has no captured fixture
            asserting it.
    """
    pinned = {
        expectation.equals
        for case in CASES
        for expectation in case.signals
        if expectation.signal == "source_repository" and expectation.equals is not None
    }
    missing = sorted(
        f"{score} ({label})"
        for score, label in (
            (0.0, "declared and resolvable"),
            (SOURCE_REPOSITORY_UNUSABLE_SCORE, "declared but not a git forge"),
            (1.0, "declares none"),
        )
        if score not in pinned
    )

    assert not missing, (
        "source_repository states with no captured fixture pinning them by "
        f"value: {missing}. Three states one line apart in the scorer collapse "
        f"back into two the moment nobody is asserting the middle one (#176). "
        f"Pinned: {sorted(pinned)}"
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
