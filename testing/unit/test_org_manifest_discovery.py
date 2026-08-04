"""An org scan must fetch every manifest the parser registry can read.

`scan-org` decided what to fetch from a tuple of exact file names kept in the
scanner, beside — and out of step with — the parser registry it was supposed to
mirror. The registry expresses NuGet's primary manifest as an *extension*
matcher, `*.csproj`, and an exact-name tuple has no way to hold one. So no org
scan ever fetched a `.csproj`.

That is not merely a missing score. After #262 gave every repository a coverage
state, a .NET repository was reported as `no_manifests` — "the tree listed and
holds no manifest this tool recognizes" — about a repository holding a manifest
`analyze` parses without complaint. `unreadable` at least says "I saw something
I could not read"; `no_manifests` says there was nothing there (#265).

Reproduced before the fix against `ghostvectoracademy/DLLHijackHunter`, a real
one-repository account whose only manifest is `src/DLLHijackHunter/
DLLHijackHunter.csproj` with five `<PackageReference>` entries:

    Found 0 supported manifests
    1. ghostvectoracademy/DLLHijackHunter · 0 risk points · worst: no manifests
    "coverage": "no_manifests"

The fix is not a second list with a test that the two agree. It is asking the
registry, which is the only thing that knows.
"""

from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

import pytest
from org_tree_fixture import CannedTreeSession, tree_client

from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.org_scan.models import (
    DependencyKey,
    DependencyProfiler,
    OrgScanReport,
    RepositoryCoverage,
    RepositoryManifestListing,
    RepositoryRef,
)
from dependency_risk_profiler.org_scan.scanner import (
    GitHubDiscoveryClient,
    OrgScanOptions,
    OrgScanRunner,
)
from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.parsers.registry import EcosystemRegistry

#: A .NET project of the shape the registry reads: `<PackageReference>` items
#: and no lock file anywhere. Modelled on the real repository named in the
#: module docstring, reduced in volume but not in key diversity.
_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="PeNet" Version="4.0.1" />
    <PackageReference Include="Spectre.Console" Version="0.49.1" />
  </ItemGroup>
</Project>
"""

#: One repository, one manifest, and that manifest is a `.csproj`. Everything
#: else in the tree is noise the classifier has to reject.
_DOTNET_TREE: Dict[str, str] = {
    "README.md": "# widget\n",
    "Widget.sln": "Microsoft Visual Studio Solution File\n",
    "src/Widget/Widget.csproj": _CSPROJ,
    "src/Widget/Program.cs": "class Program {}\n",
}


def _repo(full_name: str) -> RepositoryRef:
    """Build a repository ref for a fixture tree."""
    return RepositoryRef(
        full_name=full_name,
        name=full_name.split("/")[-1],
        default_branch="main",
        html_url=f"https://github.com/{full_name}",
        archived=False,
        fork=False,
    )


class _DotNetClient(GitHubDiscoveryClient):
    """Offline client whose listing is the production classifier.

    ``list_manifest_paths`` delegates to a real ``GitHubOrgClient`` over a
    canned git tree, so a test here cannot pass because a fixture reimplemented
    the matching the way the scanner used to do it.
    """

    def __init__(self, tree: Optional[Dict[str, str]] = None) -> None:
        """Serve one repository whose tree is ``tree``."""
        self.tree = _DOTNET_TREE if tree is None else tree
        self.fetched: List[Tuple[str, str]] = []
        self._client = tree_client({"acme/widget": list(self.tree)})

    @property
    def session(self) -> CannedTreeSession:
        """The canned session, for counting the requests discovery made."""
        assert isinstance(self._client.session, CannedTreeSession)
        return self._client.session

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return the single fixture repository."""
        return [_repo("acme/widget")]

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return the single fixture repository."""
        return self.list_org_repositories(user, include_archived, max_repos)

    def list_manifest_paths(
        self,
        repo: RepositoryRef,
    ) -> RepositoryManifestListing:
        """Classify the fixture tree through the production client."""
        return self._client.list_manifest_paths(repo)

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Return one fixture manifest body, recording the fetch."""
        self.fetched.append((repo.full_name, path))
        return self.tree[path]


class _LowProfiler(DependencyProfiler):
    """Score every dependency LOW, with no network."""

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Return a deterministic low score per dependency."""
        return {
            key: DependencyRiskScore(
                dependency=dependency,
                total_score=1.0,
                risk_level=RiskLevel.LOW,
            )
            for key, dependency in dependencies.items()
        }


def _run(client: _DotNetClient) -> OrgScanReport:
    """Run one offline org scan over the fixture account."""
    return OrgScanRunner(client, _LowProfiler()).run(OrgScanOptions(org="acme"))


def test_a_dotnet_repository_is_read_not_reported_empty() -> None:
    """HYPOTHESIS (#265 acceptance criteria 1 and 4): the .csproj is fetched.

    Value assertions on the manifest path and the dependency names, not on a
    count: "found one manifest" cannot tell the `.csproj` apart from the `.sln`
    beside it, and finding the wrong file is the failure mode this is about.
    """
    client = _DotNetClient()

    report = _run(client)

    assert report.manifests_scanned == ["acme/widget:src/Widget/Widget.csproj"]
    summary = report.riskiest_repositories[0]
    assert summary.repo_full_name == "acme/widget"
    assert summary.coverage is RepositoryCoverage.READ
    assert summary.coverage.is_complete
    names = {item.key.name for item in report.inventory}
    assert names == {"PeNet", "Spectre.Console"}
    # Not "recognized and unread" either: the tool reads this file.
    assert report.unreadable_manifests == []


def test_a_dotnet_repository_costs_one_listing_and_one_fetch() -> None:
    """INVARIANT (#265 acceptance criterion 3): pattern matching adds no listings.

    The glob is applied to the recursive tree the scan already paid for, so the
    only new request is the fetch of the manifest that was previously invisible.
    """
    client = _DotNetClient()

    _run(client)

    assert len(client.session.requested_urls) == 1
    assert "/git/trees/main" in client.session.requested_urls[0]
    assert client.fetched == [("acme/widget", "src/Widget/Widget.csproj")]


def test_a_large_solution_is_not_silently_capped() -> None:
    """DECISION (#265 acceptance criterion 5): no cap, because a cap would lie.

    A cap that stops after N projects reports a dependency count that is a
    prefix while claiming ``coverage: read`` — which is #262 rebuilt, and the
    reason `--manifest-glob` exists is to let an operator narrow this on
    purpose rather than have the tool narrow it silently.
    """
    tree = {
        f"src/Project{index:03d}/Project{index:03d}.csproj": _CSPROJ
        for index in range(40)
    }
    client = _DotNetClient(tree)

    report = _run(client)

    assert len(client.fetched) == 40
    assert len(report.manifests_scanned) == 40
    assert report.riskiest_repositories[0].coverage is RepositoryCoverage.READ


def test_a_narrowing_glob_still_narrows() -> None:
    """INVARIANT: ``--manifest-glob`` subtracts from the registry's set.

    The default is now "everything the registry recognizes" rather than a
    hand-written list, so this pins that the option did not become a no-op.
    """
    tree = {
        "src/Widget/Widget.csproj": _CSPROJ,
        "requirements.txt": "jinja2==3.1.6\n",
    }
    client = _DotNetClient(tree)

    report = OrgScanRunner(client, _LowProfiler()).run(
        OrgScanOptions(org="acme", manifest_globs=("*.csproj",))
    )

    assert report.manifests_scanned == ["acme/widget:src/Widget/Widget.csproj"]
    assert client.fetched == [("acme/widget", "src/Widget/Widget.csproj")]


def test_every_manifest_name_the_registry_publishes_is_matched_by_path() -> None:
    """INVARIANT (#265 acceptance criterion 2): one source of truth, not two.

    Derived from ``get_ecosystem_details()`` rather than restated, so a parser
    registered tomorrow is covered by this test the day it lands. The old tuple
    would fail this for ``*.csproj``, which is exactly how it stayed wrong.
    """
    BaseParser._initialize_registry()
    details = EcosystemRegistry.get_ecosystem_details()
    assert details, "the registry must be initialized for this to mean anything"

    published: List[Tuple[str, str]] = []
    for ecosystem, detail in details.items():
        for entry in detail["file_patterns"]:
            if entry.startswith("File name: "):
                published.append((ecosystem, entry[len("File name: ") :]))
    assert published, "the registry publishes at least one file name"

    unmatched = [
        (ecosystem, name)
        for ecosystem, name in published
        if EcosystemRegistry.match_ecosystem_by_path(PurePosixPath(name)) is None
    ]
    assert not unmatched, f"names the org scan would never fetch: {unmatched}"


def test_a_qualified_extension_does_not_become_a_bare_glob() -> None:
    """INVARIANT: deriving globs from the registry's *labels* would be a bug.

    ``get_ecosystem_details()`` publishes npm's second matcher as
    "File extension: .json" and Python's as "File extension: .txt", and drops
    the qualifying function that restricts them to ``package-lock`` and
    ``requirements``. A pattern list built from those labels would have an org
    scan fetch every JSON and text file in every repository in the account —
    which is why this asks the registry to *decide* rather than asking it for
    a list to copy.

    Value assertions on both directions: the qualifying name matches and the
    unqualified sibling does not.
    """
    BaseParser._initialize_registry()
    match = EcosystemRegistry.match_ecosystem_by_path

    assert match(PurePosixPath("build/npm-package-lock.json")) == "nodejs"
    assert match(PurePosixPath("requirements-dev.txt")) == "python"
    assert match(PurePosixPath("src/Widget/Widget.csproj")) == "nuget"

    assert match(PurePosixPath("settings/config.json")) is None
    assert match(PurePosixPath("docs/notes.txt")) is None
    assert match(PurePosixPath("README.md")) is None


def test_an_unrelated_json_file_is_never_fetched() -> None:
    """INVARIANT (#265 acceptance criterion 3): only real manifests are fetched.

    The same claim as the test above, made where a user would feel it: a
    repository of ordinary config files must cost its one tree listing and
    nothing else.
    """
    tree = {
        "settings/config.json": "{}\n",
        "tsconfig.json": "{}\n",
        "docs/notes.txt": "hello\n",
        "src/Widget/Widget.csproj": _CSPROJ,
    }
    client = _DotNetClient(tree)

    report = _run(client)

    assert client.fetched == [("acme/widget", "src/Widget/Widget.csproj")]
    assert report.manifests_scanned == ["acme/widget:src/Widget/Widget.csproj"]


@pytest.mark.parametrize(
    "relative_path",
    [
        "src/Widget/Widget.csproj",
        "src/Widget/packages.lock.json",
        "src/Widget/Widget.vbproj",
        "package-lock.json",
        "frontend/package.json",
        "settings/config.json",
        "requirements.txt",
        "docs/requirements/base.txt",
        "notes.txt",
        "pom.xml",
        "build.gradle.kts",
        "Cargo.toml",
        "pyproject.toml",
        "Gemfile.lock",
        "composer.lock",
        "README.md",
    ],
)
def test_the_remote_and_local_classifiers_agree(
    relative_path: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """INVARIANT: what ``analyze`` reads is what ``scan-org`` fetches.

    ``detect_ecosystem`` decides for a file on disk and
    ``match_ecosystem_by_path`` decides for a name in somebody else's git tree.
    They run the same matchers over the same table, so they must return the
    same answer for the same name — including the negatives: ``config.json``
    and ``notes.txt`` are the reason npm's and Python's extension matchers keep
    their qualifying functions instead of becoming ``*.json`` and ``*.txt``.

    Run from ``tmp_path`` with relative paths on purpose. The registry's
    extension matchers inspect the *whole* path string, so an absolute path
    whose parent directories happen to contain "requirements" would answer
    differently from the repository-relative name — a real wart, and not one
    this test should hide behind.
    """
    BaseParser._initialize_registry()
    monkeypatch.chdir(tmp_path)
    local = Path(relative_path)
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(_CSPROJ if relative_path.endswith("proj") else "{}\n")

    assert EcosystemRegistry.match_ecosystem_by_path(
        PurePosixPath(relative_path)
    ) == EcosystemRegistry.detect_ecosystem(local)
