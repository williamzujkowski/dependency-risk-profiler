"""Signal coverage for the .NET adapter (#129): nuget.org metadata -> scorer.

The adapter used to read the flat-container version index and stop, so it never
set a repository URL and the eight repository-derived signals were permanently
unmeasured for every .NET dependency — 18/18 UNKNOWN on eShopOnWeb at an average
of two measured signals out of fourteen. The payloads below are recorded from
nuget.org and trimmed to the fields the adapter reads. Refresh with:

    curl https://api.nuget.org/v3-flatcontainer/mediatr/index.json
    curl https://api.nuget.org/v3-flatcontainer/mediatr/12.0.1/mediatr.nuspec
    curl https://api.nuget.org/v3/registration5-gz-semver2/mediatr/index.json

The split matters: only the ``.nuspec`` carries ``<repository>`` (MediatR's
``projectUrl`` is a documentation site, not a repository), and only the
registration catalog carries the publication date and the deprecation marker.

The hive in that third URL matters too, and the payloads below are why it took
a live capture to notice: they are "trimmed to the fields the adapter reads",
which is exactly the sentence #145 identifies as the mechanism behind four of
its five dead reads. nuget.org publishes the ``deprecation`` block **only** in
``registration5-gz-semver2``; ``registration5-semver1``, which #129 read, serves
the same catalog entries with the key absent. The hand-written payload here had
the key because the parser looked for it, so this file passed throughout. The
captured-payload gate in ``adapter_conformance`` is what caught it. URLs are
built from ``REGISTRATION_BASE`` now so the two cannot drift apart again.
"""

import copy
import json
from pathlib import Path
from typing import Dict, Optional
from unittest import mock

import pytest
from signal_floors import assert_measures_registry_signals, assert_meets_signal_floor

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.nuget import NuGetAnalyzer
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.forges import github as github_forge
from dependency_risk_profiler.license.analyzer import analyze_license
from dependency_risk_profiler.models import DependencyMetadata, DependencyRiskScore
from dependency_risk_profiler.parsers.nuget import NuGetParser
from dependency_risk_profiler.parsers.nuget_registry import (
    REGISTRATION_BASE,
    NuGetRegistryClient,
)
from dependency_risk_profiler.parsers.version_sources import (
    VERSION_SOURCE_DECLARED,
    VERSION_SOURCE_KEY,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import SourceRepositoryState
from dependency_risk_profiler.vulnerabilities import ecosystems

PACKAGES_LOCK = {
    "version": 1,
    "dependencies": {
        "net6.0": {
            "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
            "Serilog": {"type": "Transitive", "resolved": "2.10.0"},
        }
    },
}

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog"><Version>2.10.0</Version></PackageReference>
  </ItemGroup>
</Project>
"""


def test_packages_lock_json_parser(tmp_path: Path) -> None:
    """Resolved versions are read per framework from packages.lock.json."""
    lock = tmp_path / "packages.lock.json"
    lock.write_text(json.dumps(PACKAGES_LOCK), encoding="utf-8")

    deps = NuGetParser(str(lock)).parse()

    assert set(deps) == {"Newtonsoft.Json", "Serilog"}
    assert deps["Newtonsoft.Json"].installed_version == "13.0.1"
    # A lock file states the restored version outright: nothing is inherited.
    assert deps["Newtonsoft.Json"].additional_info[VERSION_SOURCE_KEY] == (
        VERSION_SOURCE_DECLARED
    )


MULTI_TFM_PACKAGES_LOCK = {
    "version": 1,
    "dependencies": {
        "net6.0": {
            "Newtonsoft.Json": {"type": "Direct", "resolved": "1.0.0"},
        },
        "net8.0": {
            "Newtonsoft.Json": {"type": "Direct", "resolved": "2.0.0"},
        },
    },
}


def test_packages_lock_json_keeps_highest_version_across_frameworks(
    tmp_path: Path,
) -> None:
    """A package resolving to different versions per TFM records the highest."""
    lock = tmp_path / "packages.lock.json"
    lock.write_text(json.dumps(MULTI_TFM_PACKAGES_LOCK), encoding="utf-8")

    deps = NuGetParser(str(lock)).parse()

    assert set(deps) == {"Newtonsoft.Json"}
    # net8.0 resolves 2.0.0, which wins over net6.0's 1.0.0 regardless of order.
    assert deps["Newtonsoft.Json"].installed_version == "2.0.0"


def test_packages_lock_json_highest_wins_when_lower_enumerated_last(
    tmp_path: Path,
) -> None:
    """Highest resolved version wins even when it is enumerated first."""
    payload = {
        "version": 1,
        "dependencies": {
            "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "2.0.0"}},
            "net6.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "1.0.0"}},
        },
    }
    lock = tmp_path / "packages.lock.json"
    lock.write_text(json.dumps(payload), encoding="utf-8")

    deps = NuGetParser(str(lock)).parse()

    assert deps["Newtonsoft.Json"].installed_version == "2.0.0"


def test_csproj_parser_reads_package_references(tmp_path: Path) -> None:
    """<PackageReference> entries are read (Version attribute or child element)."""
    proj = tmp_path / "App.csproj"
    proj.write_text(CSPROJ, encoding="utf-8")

    deps = NuGetParser(str(proj)).parse()

    assert set(deps) == {"Newtonsoft.Json", "Serilog"}
    assert deps["Newtonsoft.Json"].installed_version == "13.0.1"
    assert deps["Serilog"].installed_version == "2.10.0"


def test_nuget_manifests_dispatch_to_nuget_analyzer() -> None:
    """Both NuGet manifest kinds route to the nuget ecosystem and analyzer."""
    from dependency_risk_profiler.cli.typer_cli import get_ecosystem_from_manifest

    assert get_ecosystem_from_manifest("a/packages.lock.json") == "nuget"
    assert get_ecosystem_from_manifest("a/App.csproj") == "nuget"
    assert isinstance(BaseAnalyzer.get_analyzer_for_ecosystem("nuget"), NuGetAnalyzer)


def test_nuget_ecosystem_routes_correctly() -> None:
    """The emitted 'nuget' string resolves to NuGet (OSV/GHA) and deps.dev."""
    eco = ecosystems.resolve("nuget")
    assert eco.osv == "NuGet"
    assert eco.github_advisory == "NUGET"
    assert eco.deps_dev == "nuget"


# --------------------------------------------------------------------------
# Recorded nuget.org payloads
# --------------------------------------------------------------------------

PACKAGE_ID = "MediatR"
FLAT_BASE = "https://api.nuget.org/v3-flatcontainer"
REGISTRATION_URL = f"{REGISTRATION_BASE}/mediatr/index.json"
FLAT_INDEX_URL = f"{FLAT_BASE}/mediatr/index.json"
NUSPEC_URL = f"{FLAT_BASE}/mediatr/12.0.1/mediatr.nuspec"

FLAT_INDEX: Dict[str, object] = {
    "versions": ["11.0.0", "12.0.0", "12.0.1", "12.1.0", "13.0.0-preview1"]
}

NUSPEC = """<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>MediatR</id>
    <version>12.0.1</version>
    <authors>Jimmy Bogard</authors>
    <license type="expression">Apache-2.0</license>
    <licenseUrl>https://licenses.nuget.org/Apache-2.0</licenseUrl>
    <description>Simple, unambitious mediator implementation in .NET</description>
    <projectUrl>https://mediatr.io/</projectUrl>
    <repository type="git" url="https://github.com/jbogard/MediatR" commit="cbb16f9" />
    <dependencies>
      <group targetFramework="net6.0">
        <dependency id="MediatR.Contracts" version="[2.0.1, 3.0.0)" />
        <dependency id="Microsoft.Extensions.DependencyInjection.Abstractions"
                    version="6.0.0" />
      </group>
      <group targetFramework=".NETStandard2.0">
        <dependency id="MediatR.Contracts" version="[2.0.1, 3.0.0)" />
        <dependency id="Microsoft.Bcl.AsyncInterfaces" version="6.0.0" />
      </group>
    </dependencies>
  </metadata>
</package>
"""

REGISTRATION_INDEX: Dict[str, object] = {
    "count": 1,
    "items": [
        {
            "@id": f"{REGISTRATION_URL}#page/0.1.0/12.1.0",
            "count": 2,
            "lower": "0.1.0",
            "upper": "12.1.0",
            "items": [
                {
                    "catalogEntry": {
                        "id": "MediatR",
                        "version": "12.0.0",
                        "authors": "Jimmy Bogard",
                        "listed": True,
                        "published": "2023-01-10T00:00:00.00+00:00",
                        "projectUrl": "https://mediatr.io/",
                    }
                },
                {
                    "catalogEntry": {
                        "id": "MediatR",
                        "version": "12.1.0",
                        "authors": "Jimmy Bogard",
                        "licenseExpression": "Apache-2.0",
                        "licenseUrl": "https://licenses.nuget.org/Apache-2.0",
                        "listed": True,
                        "published": "2026-07-02T13:53:56.29+00:00",
                        "projectUrl": "https://mediatr.io/",
                    }
                },
            ],
        }
    ],
}

# Enough of a GitHub repository page for the community analyzer's star scrape.
GITHUB_REPO_HTML = (
    '<a href="/jbogard/MediatR/stargazers" '
    'aria-label="11,234 users starred this repository">11.2k</a>'
)


def _recorded_responses(
    flat_index: Optional[Dict[str, object]] = None,
    nuspec: Optional[str] = None,
    registration: Optional[Dict[str, object]] = None,
) -> Dict[str, bytes]:
    """Build the URL -> body table the offline client serves."""
    responses: Dict[str, bytes] = {}
    index = FLAT_INDEX if flat_index is None else flat_index
    if index is not None:
        responses[FLAT_INDEX_URL] = json.dumps(index).encode("utf-8")
    body = NUSPEC if nuspec is None else nuspec
    if body is not None:
        responses[NUSPEC_URL] = body.encode("utf-8")
    catalog = REGISTRATION_INDEX if registration is None else registration
    if catalog is not None:
        responses[REGISTRATION_URL] = json.dumps(catalog).encode("utf-8")
    return responses


class _RecordedClient(NuGetRegistryClient):
    """A registry client that serves recorded bytes instead of opening sockets.

    Only the transport is replaced. URL construction, the host allowlist, the
    identifier grammar, the fetch budget, and every parser above them run
    exactly as they do against the real API.
    """

    def __init__(self, responses: Dict[str, bytes]) -> None:
        super().__init__(enabled=True)
        self.responses = responses
        self.requested: list = []

    def _fetch_bounded(self, url: str) -> Optional[bytes]:
        self.requested.append(url)
        # Preserve the real guard: nothing off api.nuget.org is ever fetched.
        if not self.enabled:
            return None
        return self.responses.get(url)


def _analyze_offline(
    responses: Dict[str, bytes],
    installed_version: str = "12.0.1",
) -> tuple:
    """Run the adapter for one package with every network call recorded.

    Args:
        responses: URL -> recorded body table.
        installed_version: Version the manifest resolved for the package.

    Returns:
        The analyzed dependency and the analyzer that produced it.
    """
    client = _RecordedClient(responses)
    analyzer = NuGetAnalyzer(client=client)
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=PACKAGE_ID, installed_version=installed_version)

    analyzed = analyzer.analyze({PACKAGE_ID: dep})
    return analyzed[PACKAGE_ID], analyzer


def _score_offline(
    responses: Optional[Dict[str, bytes]] = None,
    installed_version: str = "12.0.1",
) -> DependencyRiskScore:
    """Run adapter, license, community, and scoring with no network at all.

    Mirrors the analyze command's order with repository cloning off, so the
    result reflects only what nuget.org and a public repository page provide.
    """
    dep, analyzer = _analyze_offline(
        _recorded_responses() if responses is None else responses,
        installed_version=installed_version,
    )
    metadata = analyzer.metadata_cache[PACKAGE_ID]
    dep = analyze_license(dep, metadata)
    with (
        mock.patch.object(
            github_forge, "fetch_url", return_value=GITHUB_REPO_HTML
        ),
        mock.patch.object(
            github_forge, "github_contributor_count", return_value=None
        ),
    ):
        dep = community_analyzer.analyze_community_metrics(dep, metadata)
    return RiskScorer().score_dependency(dep)


def test_nuget_analyzer_sets_ecosystem_and_reads_latest_stable() -> None:
    """The analyzer stamps the OSV ecosystem and reads the newest stable version."""
    dep, client = _analyze_offline(_recorded_responses())

    assert dep.additional_info["ecosystem"] == "nuget"
    # Newest stable (12.1.0) wins over the pre-release 13.0.0-preview1.
    assert dep.latest_version == "12.1.0"
    # The flat-container index uses the lowercased id.
    assert FLAT_INDEX_URL in client.client.requested


def test_the_nuspec_repository_beats_a_documentation_project_url() -> None:
    """A project URL is often a docs site; <repository> is the real source.

    MediatR publishes ``https://mediatr.io/``, which is not cloneable.

    This is the whole second half of the issue: with no repository URL, the
    eight repository-derived signals can never be collected no matter how good
    the rest of the metadata is.
    """
    dep, _ = _analyze_offline(_recorded_responses())

    assert dep.repository_url == "https://github.com/jbogard/MediatR"


def test_the_catalog_supplies_the_publication_date() -> None:
    """Release cadence exists only in the registration catalog."""
    dep, _ = _analyze_offline(_recorded_responses())

    assert dep.last_updated is not None
    assert dep.last_updated.year == 2026


def test_the_nuspec_supplies_license_and_declared_authors() -> None:
    """License and the maintainer fallback both come off the package manifest."""
    score = _score_offline()

    assert score.dependency.license_info is not None
    assert score.dependency.license_info.license_id == "APACHE-2.0"
    # No repository clone and no GitHub token, so the declared author stands in.
    assert score.dependency.maintainer_count == 1


def test_the_nuspec_dependencies_are_a_measured_transitive_signal() -> None:
    """A package's own <dependencies> is a measurement, not an assumed zero."""
    score = _score_offline()

    assert "MediatR.Contracts" in score.dependency.transitive_dependencies
    assert "Microsoft.Bcl.AsyncInterfaces" in score.dependency.transitive_dependencies
    assert "transitive" not in score.unknown_signals


def test_a_file_typed_license_is_not_reported_as_a_license_id() -> None:
    """`<license type="file">` names a file in the package, not an SPDX id."""
    nuspec = NUSPEC.replace(
        '<license type="expression">Apache-2.0</license>',
        '<license type="file">LICENSE.txt</license>',
    ).replace("<licenseUrl>https://licenses.nuget.org/Apache-2.0</licenseUrl>", "")
    responses = _recorded_responses(nuspec=nuspec)
    # The catalog for this package still states the expression, so drop it too
    # to isolate the nuspec behaviour.
    registration = copy.deepcopy(REGISTRATION_INDEX)
    pages = registration["items"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    leaves = page["items"]
    assert isinstance(leaves, list)
    for leaf in leaves:
        assert isinstance(leaf, dict)
        leaf["catalogEntry"].pop("licenseExpression", None)
        leaf["catalogEntry"].pop("licenseUrl", None)
    responses[REGISTRATION_URL] = json.dumps(registration).encode("utf-8")

    dep, analyzer = _analyze_offline(responses)

    assert "license" not in analyzer.metadata_cache[dep.name]


def test_a_legacy_license_url_still_yields_an_spdx_expression() -> None:
    """Older packages publish only licenses.nuget.org/<expression>."""
    nuspec = NUSPEC.replace('<license type="expression">Apache-2.0</license>', "")

    score = _score_offline(_recorded_responses(nuspec=nuspec))

    assert score.dependency.license_info is not None
    assert score.dependency.license_info.license_id == "APACHE-2.0"


def test_an_unlisted_package_is_marked_deprecated() -> None:
    """nuget.org unlists a package by rewriting its publication date to 1900."""
    registration = copy.deepcopy(REGISTRATION_INDEX)
    pages = registration["items"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    leaves = page["items"]
    assert isinstance(leaves, list)
    newest = leaves[-1]
    assert isinstance(newest, dict)
    newest["catalogEntry"]["listed"] = False
    newest["catalogEntry"]["published"] = "1900-01-01T00:00:00+00:00"

    dep, _ = _analyze_offline(_recorded_responses(registration=registration))

    assert dep.is_deprecated is True
    # And the 1900 sentinel is never mistaken for a 125-year-old release.
    assert dep.last_updated is None


def test_an_explicit_deprecation_block_is_honoured() -> None:
    """The catalog's own deprecation marker is the strongest form of the signal."""
    registration = copy.deepcopy(REGISTRATION_INDEX)
    pages = registration["items"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    leaves = page["items"]
    assert isinstance(leaves, list)
    newest = leaves[-1]
    assert isinstance(newest, dict)
    newest["catalogEntry"]["deprecation"] = {"reasons": ["Legacy"]}

    dep, _ = _analyze_offline(_recorded_responses(registration=registration))

    assert dep.is_deprecated is True


def test_a_paged_registration_index_fetches_only_the_newest_page() -> None:
    """Large packages leave the newest page out of the index and give a URL."""
    page_url = f"{REGISTRATION_BASE}/mediatr/page/0.1.0/12.1.0.json"
    registration = copy.deepcopy(REGISTRATION_INDEX)
    pages = registration["items"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    inline = page.pop("items")
    page["@id"] = page_url

    responses = _recorded_responses(registration=registration)
    responses[page_url] = json.dumps({"items": inline}).encode("utf-8")

    dep, _ = _analyze_offline(responses)

    assert dep.last_updated is not None
    assert dep.last_updated.year == 2026


def test_an_off_host_registration_page_is_refused() -> None:
    """The one URL that arrives inside a payload is re-validated before use."""
    registration = copy.deepcopy(REGISTRATION_INDEX)
    pages = registration["items"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    page.pop("items")
    page["@id"] = "https://api.nuget.org.evil.example/steal.json"

    dep, analyzer = _analyze_offline(_recorded_responses(registration=registration))

    requested = analyzer.client.requested
    assert not any("evil.example" in url for url in requested)
    # The catalog is simply unavailable; nothing is invented in its place.
    assert dep.last_updated is None


def test_a_package_with_no_repository_stays_honestly_unmeasured() -> None:
    """No published repository means no invented one, and no invented signals."""
    nuspec = NUSPEC.replace(
        '<repository type="git" url="https://github.com/jbogard/MediatR" '
        'commit="cbb16f9" />',
        "",
    )

    score = _score_offline(_recorded_responses(nuspec=nuspec))

    # projectUrl is https://mediatr.io/, which is not a repository at all.
    assert score.dependency.repository_url is None
    assert "health_indicators" in score.unknown_signals


def test_the_nuspec_repository_declaration_is_a_measured_signal() -> None:
    """#183: nuget resolved a repository and reported nothing about it.

    Every other ecosystem records whether the registry declares a source; nuget
    did not, so ``_calculate_source_repository_score`` returned None and the
    signal was dropped from ``weighted_scores`` entirely. nuget alone scored 15
    signals where the rest scored 16, and the absence read as though nuget.org
    had said nothing either way. It says plenty: the nuspec either carries
    ``<repository>`` or it does not.
    """
    score = _score_offline()

    assert score.dependency.source_repository_state == SourceRepositoryState.DECLARED
    assert score.source_repository_score == 0.0
    assert "source_repository" not in score.unknown_signals


def test_a_nuspec_declaring_no_repository_declares_none() -> None:
    """A projectUrl is a docs site on MediatR, not a source declaration.

    A ``projectUrl`` is a resolution fallback, not a declaration of source, so
    stripping ``<repository>`` leaves the package genuinely undeclared rather
    than promoting a documentation host to a broken repository.
    """
    nuspec = NUSPEC.replace(
        '<repository type="git" url="https://github.com/jbogard/MediatR" '
        'commit="cbb16f9" />',
        "",
    )

    score = _score_offline(_recorded_responses(nuspec=nuspec))

    assert score.source_repository_score == 1.0
    assert "Declares no source repository" in score.factors


def test_a_nuspec_repository_on_a_non_forge_host_is_declared_but_unusable() -> None:
    """#176's middle state on .NET: an internal Azure DevOps or TFS remote.

    Plenty of .NET packages publish a ``<repository>`` pointing at a host this
    tool cannot read. The package said where its source lives; the answer is
    not reachable. That is not the same as saying nothing.
    """
    nuspec = NUSPEC.replace(
        'url="https://github.com/jbogard/MediatR"',
        'url="https://tfs.internal.example/tfs/DefaultCollection/_git/MediatR"',
    )

    score = _score_offline(_recorded_responses(nuspec=nuspec))

    assert score.dependency.source_repository_state == SourceRepositoryState.UNUSABLE
    assert score.source_repository_score == 0.75


def test_an_unanswered_nuget_lookup_leaves_the_source_signal_unmeasured() -> None:
    """#182's rule applied here too: no nuspec and no catalog is no answer.

    A package id nuget.org has never heard of, or a registry that is simply
    unreachable, must not be recorded as declaring no source repository.
    """
    dep, _ = _analyze_offline({})

    score = RiskScorer().score_dependency(dep)

    assert dep.source_repository_state is None
    assert score.source_repository_score is None
    assert "source_repository" not in score.unknown_signals


def test_a_package_declaring_no_author_leaves_the_maintainer_count_unknown() -> None:
    """An absent author must not become a fabricated maintainer count."""
    nuspec = NUSPEC.replace("<authors>Jimmy Bogard</authors>", "<authors></authors>")

    score = _score_offline(_recorded_responses(nuspec=nuspec))

    assert score.dependency.maintainer_count is None
    assert "maintainer" in score.unknown_signals


def test_an_unmanaged_version_leaves_drift_unmeasured_but_keeps_the_rest() -> None:
    """The bare-csproj case: no installed version, every other signal intact.

    This is why the repository fix matters independently of the version fix. A
    manifest fetched without its Directory.Packages.props still reaches the
    nuspec through the latest version, so the repository, license, authors, and
    dependencies all land; only drift is honestly missing.
    """
    responses = _recorded_responses()
    # With no installed version the adapter falls back to the latest, so record
    # that nuspec instead.
    responses[f"{FLAT_BASE}/mediatr/12.1.0/mediatr.nuspec"] = NUSPEC.encode("utf-8")

    score = _score_offline(responses, installed_version="")

    assert "version" in score.unknown_signals
    assert score.dependency.repository_url == "https://github.com/jbogard/MediatR"
    assert score.dependency.license_info is not None


def test_nuget_meets_minimum_measured_signal_coverage() -> None:
    """Registry metadata alone must measure every signal this registry answers.

    The floor is the coverage half. A verdict needs eight measured signals
    and a registry document supplies at most seven, so reaching one is not
    part of this claim — ``signal_floors.SCORES_FROM_REGISTRY_ALONE`` records
    which ecosystems can, and today none can (#340).
    """
    assert_meets_signal_floor(_score_offline(), "nuget")


def test_nuget_measures_the_signals_the_registry_provides() -> None:
    """Each signal nuget.org can answer is measured, not left unknown."""
    assert_measures_registry_signals(_score_offline(), "nuget")


@pytest.mark.parametrize(
    ("published", "expected_microsecond"),
    [
        ("2026-07-02T13:53:56.29+00:00", 290000),
        ("2026-07-02T13:53:56.123456+00:00", 123456),
        ("2026-07-02T13:53:56.1234567+00:00", 123456),
        ("2026-07-02T13:53:56+00:00", 0),
        ("2026-07-02T13:53:56.29Z", 290000),
    ],
    ids=["two-digits", "six-digits", "seven-digits", "none", "zulu"],
)
def test_publication_dates_parse_at_any_fractional_precision(
    published: str, expected_microsecond: int
) -> None:
    """nuget.org writes fractional seconds at whatever precision it needs.

    ``.29`` is a real catalog value, and before Python 3.11
    ``datetime.fromisoformat`` raised on anything but three or six digits — so
    on 3.9 and 3.10 every package silently lost its publication date, and with
    it the staleness signal, while 3.11 was fine.
    """
    registration = copy.deepcopy(REGISTRATION_INDEX)
    pages = registration["items"]
    assert isinstance(pages, list)
    page = pages[0]
    assert isinstance(page, dict)
    leaves = page["items"]
    assert isinstance(leaves, list)
    newest = leaves[-1]
    assert isinstance(newest, dict)
    newest["catalogEntry"]["published"] = published

    dep, _ = _analyze_offline(_recorded_responses(registration=registration))

    assert dep.last_updated is not None
    assert dep.last_updated.microsecond == expected_microsecond


def test_a_malformed_package_id_is_never_pasted_into_a_url() -> None:
    """Identifiers are validated against NuGet's grammar before they become paths."""
    client = _RecordedClient({})

    assert client.list_versions("../../etc/passwd") == ()
    assert client.fetch_nuspec("ok.package", "../1.0.0") is None
    assert client.requested == []


def test_remote_reads_can_be_switched_off_entirely() -> None:
    """The DEPENDENCY_RISK_NO_REMOTE_POMS opt-out degrades rather than guesses."""
    client = _RecordedClient(_recorded_responses())
    client.enabled = False
    analyzer = NuGetAnalyzer(client=client)
    analyzer.clone_repos = False

    dep = analyzer.analyze(
        {PACKAGE_ID: DependencyMetadata(name=PACKAGE_ID, installed_version="12.0.0")}
    )[PACKAGE_ID]

    assert dep.repository_url is None
    assert dep.latest_version is None
