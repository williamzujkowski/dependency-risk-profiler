"""An org scan must not report what it could not read as what it did not find.

`scan-org` filtered every repository's tree against the manifest names it can
parse *before* fetching anything, so a repository holding only `package.json`
matched nothing, was never fetched, and never reached `parse_failures`. It
still appeared in `riskiest_repositories` — with `dependency_count: 0`, zero
risk points and `worst: none`, which is byte-for-byte what a repository with no
dependencies at all looks like. Two opposite facts, one output (#262).

These tests pin the four states apart. Every one of them was observed to fail
against the pre-fix scanner.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, cast

import pytest
from org_tree_fixture import CannedTreeSession, tree_client
from typer.testing import CliRunner, Result

from dependency_risk_profiler.cli.typer_cli import app
from dependency_risk_profiler.manifest_guidance import (
    is_recognized_unreadable_name,
    is_vendored_relative_path,
    recognise_unreadable_manifest,
    recognise_unreadable_manifest_in_listing,
)
from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.org_scan.github import GitHubOrgClient
from dependency_risk_profiler.org_scan.models import (
    DependencyKey,
    DependencyProfiler,
    OrgScanReport,
    RepositoryCoverage,
    RepositoryManifestListing,
    RepositoryRef,
)
from dependency_risk_profiler.org_scan.report import (
    render_html_report,
    render_terminal_summary,
    report_to_dict,
)
from dependency_risk_profiler.org_scan.scanner import (
    GitHubDiscoveryClient,
    OrgScanOptions,
    OrgScanRunner,
)

#: Repositories covering all four outcomes at once, so no test can pass by
#: accident of a fixture that only contains its own case.
_TREES: Dict[str, Dict[str, str]] = {
    # Only manifests the tool cannot read. The #262 repository.
    "acme/frontend": {
        "package.json": '{"dependencies": {"left-pad": "^1.3.0"}}',
        "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
    },
    # A manifest the tool reads, declaring one dependency.
    "acme/api": {"requirements.txt": "jinja2==3.1.6\n"},
    # A manifest the tool reads that declares nothing. A real, measured zero.
    "acme/empty-but-read": {"requirements.txt": "# nothing here\n"},
    # No dependency manifest of any kind.
    "acme/docs": {"README.md": "# docs\n"},
    # Read one ecosystem, cannot read another. The count is a floor.
    "acme/hybrid": {
        "requirements.txt": "jinja2==3.1.6\n",
        "frontend/package.json": '{"dependencies": {"left-pad": "^1.3.0"}}',
    },
    # A supported input sits beside the unreadable one, so the ecosystem *was*
    # read and there is no coverage gap to report.
    "acme/covered": {
        "package.json": '{"dependencies": {"left-pad": "^1.3.0"}}',
        "package-lock.json": (
            '{"lockfileVersion": 3, "packages": {"node_modules/left-pad": '
            '{"version": "1.3.0"}}}'
        ),
    },
    # Installed dependencies committed to the repository.
    "acme/vendored": {
        "requirements.txt": "jinja2==3.1.6\n",
        "node_modules/left-pad/package.json": '{"name": "left-pad"}',
    },
}

#: The repository whose tree listing raises, so nothing is known about it.
_UNLISTABLE = "acme/private"


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


class _FixtureClient(GitHubDiscoveryClient):
    """Offline client whose tree listing is the *production* classifier.

    It used to reimplement the supported/unreadable split against the same
    ``manifest_guidance`` predicates, which read as faithful and was not: it
    copied the scanner's exact-name matching, so it hid the ``*.csproj`` gap
    (#265) exactly as production did and every test agreed with the bug. Now
    ``list_manifest_paths`` delegates to a real :class:`GitHubOrgClient` over a
    canned tree document — delete the classifier and these tests fail.

    It still records every fetch, which is how the "costs no extra request"
    claim is checked rather than asserted.
    """

    def __init__(self, repositories: Optional[List[str]] = None) -> None:
        """Initialize the fixture with the repositories to serve."""
        self.repositories = list(_TREES) if repositories is None else repositories
        self.fetched: List[Tuple[str, str]] = []
        self.listed: List[str] = []
        self._client = tree_client(
            {full_name: list(tree) for full_name, tree in _TREES.items()}
        )

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return the fixture repositories for an organization."""
        return [_repo(name) for name in self.repositories]

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return the fixture repositories for a user."""
        return self.list_org_repositories(user, include_archived, max_repos)

    def list_manifest_paths(
        self,
        repo: RepositoryRef,
    ) -> RepositoryManifestListing:
        """Split one fixture tree into what is read and what is not."""
        self.listed.append(repo.full_name)
        if repo.full_name == _UNLISTABLE:
            raise RuntimeError("404 Not Found")
        return self._client.list_manifest_paths(repo)

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Return one fixture manifest body, recording the fetch."""
        self.fetched.append((repo.full_name, path))
        return _TREES[repo.full_name][path]


class _FixtureProfiler(DependencyProfiler):
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


def _run(client: Optional[_FixtureClient] = None) -> OrgScanReport:
    """Run one offline org scan over the fixture account."""
    return OrgScanRunner(client or _FixtureClient(), _FixtureProfiler()).run(
        OrgScanOptions(org="acme")
    )


def _coverage(report: OrgScanReport) -> Dict[str, RepositoryCoverage]:
    """Index a report's repository coverage states by repository name."""
    return {repo.repo_full_name: repo.coverage for repo in report.riskiest_repositories}


def test_a_repository_of_unreadable_manifests_is_named_not_dropped() -> None:
    """HYPOTHESIS (#262): the repository reaches the report with its files named.

    The value assertions are on the manifest paths rather than on a count: a
    count cannot tell "found the right two files" from "found two of anything".
    """
    report = _run()

    named = {
        (entry.repo_full_name, entry.path) for entry in report.unreadable_manifests
    }
    assert ("acme/frontend", "package.json") in named
    assert ("acme/frontend", "pnpm-lock.yaml") in named
    assert ("acme/hybrid", "frontend/package.json") in named

    npm = next(
        entry
        for entry in report.unreadable_manifests
        if entry.repo_full_name == "acme/frontend" and entry.path == "package.json"
    )
    assert npm.ecosystem == "npm"
    assert "package-lock.json" in npm.guidance
    # The location names the repository, because a bare "." would point at the
    # operator's working directory rather than at anything in the account.
    assert "acme/frontend" in npm.guidance


def test_the_four_ways_of_having_no_dependencies_are_four_states() -> None:
    """INVARIANT (AGENTS.md rule 4): unmeasured is distinct from measured-zero.

    All four repositories below produce ``dependency_count: 0``. Before #262
    they produced nothing else either, so the output could not say which was
    which.
    """
    report = _run(_FixtureClient(list(_TREES) + [_UNLISTABLE]))
    coverage = _coverage(report)

    assert coverage["acme/frontend"] is RepositoryCoverage.UNREADABLE
    assert coverage["acme/empty-but-read"] is RepositoryCoverage.READ
    assert coverage["acme/docs"] is RepositoryCoverage.NO_MANIFESTS
    assert coverage[_UNLISTABLE] is RepositoryCoverage.DISCOVERY_FAILED

    counts = {
        name: repo.dependency_count
        for name, repo in (
            (summary.repo_full_name, summary)
            for summary in report.riskiest_repositories
        )
    }
    assert counts["acme/frontend"] == 0
    assert counts["acme/empty-but-read"] == 0
    assert counts["acme/docs"] == 0
    assert counts[_UNLISTABLE] == 0


def test_a_repository_read_in_part_says_its_count_is_a_floor() -> None:
    """HYPOTHESIS: reading one ecosystem and not another is its own state."""
    report = _run()

    assert _coverage(report)["acme/hybrid"] is RepositoryCoverage.PARTIALLY_READ
    assert not _coverage(report)["acme/hybrid"].is_complete
    assert _coverage(report)["acme/api"] is RepositoryCoverage.READ
    assert _coverage(report)["acme/api"].is_complete


def test_a_repository_that_could_not_be_listed_reaches_the_report() -> None:
    """REGRESSION: discovery warnings were built and then dropped on the floor.

    ``_discover_manifests`` appended to a local list it never returned, so
    ``OrgScanReport.warnings`` was empty on every scan and a repository the
    GitHub API refused left no trace at all.
    """
    report = _run(_FixtureClient(["acme/api", _UNLISTABLE]))

    assert any(_UNLISTABLE in warning for warning in report.warnings)
    assert any("manifest discovery failed" in warning for warning in report.warnings)
    assert _coverage(report)[_UNLISTABLE] is RepositoryCoverage.DISCOVERY_FAILED
    # Not folded into the unreadable list: we do not know that this repository
    # has manifests, only that we never saw its tree.
    assert all(
        entry.repo_full_name != _UNLISTABLE for entry in report.unreadable_manifests
    )


def test_recognition_fetches_nothing() -> None:
    """INVARIANT (#262 acceptance criterion 4): no extra request per repository.

    Recognition is by file name against a tree listing the scan already paid
    for, so the unreadable half of every listing must never be fetched.
    """
    client = _FixtureClient()
    report = _run(client)

    assert client.listed.count("acme/frontend") == 1
    unreadable_paths = {
        (entry.repo_full_name, entry.path) for entry in report.unreadable_manifests
    }
    assert unreadable_paths, "fixture must produce unreadable manifests"
    assert unreadable_paths.isdisjoint(set(client.fetched))
    assert ("acme/frontend", "package.json") not in client.fetched


def test_a_supported_input_beside_it_is_not_a_coverage_gap() -> None:
    """INVARIANT: no crying wolf on a healthy repository.

    ``acme/covered`` holds ``package.json`` next to ``package-lock.json``. The
    ecosystem was read, so the repository is complete and nothing is reported.
    """
    report = _run()

    assert all(
        entry.repo_full_name != "acme/covered" for entry in report.unreadable_manifests
    )
    assert _coverage(report)["acme/covered"] is RepositoryCoverage.READ


def test_sibling_lookup_never_consults_the_local_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REGRESSION: a remote path resolved against the operator's shell.

    ``recognise_unreadable_manifest`` answers "is the lock file already there?"
    by stating the directory next to the manifest. An org scan's paths name
    files on somebody else's server, so reusing it would let a stray
    ``package-lock.json`` in whatever directory the scan was launched from mark
    a remote repository as covered — dropping it from the report again, this
    time for a reason nobody could reproduce.
    """
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    # The filesystem-backed entry point does see it. That is correct for
    # `analyze`, and it is exactly why the org path must not use it.
    local = recognise_unreadable_manifest("package.json")
    assert local is not None
    assert local.supported_input_present is True

    remote = recognise_unreadable_manifest_in_listing(
        "package.json", [], location="acme/frontend"
    )
    assert remote is not None
    assert remote.supported_input_present is False

    report = _run()
    assert any(
        entry.repo_full_name == "acme/frontend" and entry.path == "package.json"
        for entry in report.unreadable_manifests
    )


def test_committed_dependencies_do_not_become_a_warning_storm() -> None:
    """INVARIANT: a repository that checked in node_modules reports once, not 500."""
    report = _run()

    assert all(
        "node_modules" not in entry.path for entry in report.unreadable_manifests
    )
    assert _coverage(report)["acme/vendored"] is RepositoryCoverage.READ


def test_the_headline_and_the_json_state_the_coverage_gap() -> None:
    """HYPOTHESIS (#262 acceptance criterion 2): a reader can tell the two apart.

    The headline carries it beside ``unscored_dependency_count``, in the same
    register, and the JSON carries a key rather than a sentence.
    """
    report = _run(_FixtureClient(list(_TREES) + [_UNLISTABLE]))
    document = report_to_dict(report)

    assert "2 repos could not be read" in report.headline
    assert document["unread_repository_count"] == 2

    entries = cast(List[Dict[str, object]], document["unreadable_manifests"])
    assert {(entry["repo"], entry["manifest_path"]) for entry in entries} >= {
        ("acme/frontend", "package.json"),
        ("acme/frontend", "pnpm-lock.yaml"),
    }
    assert all("ecosystem" in entry and "guidance" in entry for entry in entries)

    repositories = cast(List[Dict[str, object]], document["riskiest_repositories"])
    states = {repo["repo"]: repo["coverage"] for repo in repositories}
    assert states["acme/frontend"] == "unreadable"
    assert states["acme/docs"] == "no_manifests"
    assert states["acme/empty-but-read"] == "read"
    assert states[_UNLISTABLE] == "discovery_failed"


def test_the_key_is_present_and_empty_when_everything_was_read() -> None:
    """INVARIANT: a key that only appears when non-empty cannot be branched on."""
    report = _run(_FixtureClient(["acme/api", "acme/empty-but-read"]))
    document = report_to_dict(report)

    assert document["unreadable_manifests"] == []
    assert document["unread_repository_count"] == 0
    assert "could not be read" not in report.headline


def test_the_terminal_and_html_reports_say_which_zero_it_is() -> None:
    """HYPOTHESIS: "worst: none" no longer covers a repository nobody read."""
    report = _run(_FixtureClient(list(_TREES) + [_UNLISTABLE]))
    summary = render_terminal_summary(report)
    html = render_html_report(report)

    assert "Repositories with no measurement: 2" in summary
    assert "acme/frontend · dependency manifests found, none readable" in summary
    assert f"{_UNLISTABLE} · repository could not be listed" in summary
    assert "acme/docs" in summary

    assert "Unread repos" in html
    assert "produced no measurement at all" in html
    assert "acme/frontend:package.json" in html


def test_every_coverage_state_is_rendered_by_name() -> None:
    """INVARIANT: a new state cannot be added without wiring it into the output.

    Both renderers index a total mapping, so a member added to the enum and
    forgotten raises here instead of silently printing the reassuring label.
    """
    from dependency_risk_profiler.org_scan.report import (
        _coverage_label,
        _no_dependencies_reason,
    )

    for state in RepositoryCoverage:
        assert _coverage_label(state)
        assert _no_dependencies_reason(state)
    assert _no_dependencies_reason(RepositoryCoverage.READ) == "none"
    assert _no_dependencies_reason(RepositoryCoverage.UNREADABLE) != "none"


def test_manifest_globs_do_not_hide_the_coverage_gap() -> None:
    """REGRESSION: the default globs are the supported names.

    Filtering the unreadable list through ``--manifest-glob`` would empty it on
    every default run, which is the defect wearing a new hat.
    """
    report = OrgScanRunner(_FixtureClient(), _FixtureProfiler()).run(
        OrgScanOptions(org="acme", manifest_globs=("requirements.txt",))
    )

    assert any(
        entry.repo_full_name == "acme/frontend" for entry in report.unreadable_manifests
    )


def test_the_real_client_returns_the_unreadable_half_of_the_tree() -> None:
    """HYPOTHESIS (#262): the defect lived in the client's pre-fetch filter.

    Driven through ``GitHubOrgClient`` rather than a fixture, because the tree
    filter is where the repository disappeared: a scanner test that classifies
    its own fixture would pass with this filter still dropping everything it
    cannot read.
    """
    client = tree_client(
        {
            "acme/frontend": [
                "package.json",
                "pnpm-lock.yaml",
                "requirements.txt",
                "node_modules/left-pad/package.json",
                "README.md",
                "src/Widget.fsproj",
            ]
        }
    )
    session = cast(CannedTreeSession, client.session)

    listing = client.list_manifest_paths(_repo("acme/frontend"))

    assert listing.supported == ["requirements.txt"]
    assert listing.unreadable == [
        "package.json",
        "pnpm-lock.yaml",
        "src/Widget.fsproj",
    ]
    # One request for both halves: recognition is by name against a tree the
    # scan already paid for (#262 acceptance criterion 4).
    assert len(session.requested_urls) == 1
    assert "/git/trees/main" in session.requested_urls[0]


class _CliClient(_FixtureClient):
    """Fixture client with the production client's constructor signature."""

    #: Which fixture repositories the next CLI invocation serves.
    served: List[str] = list(_TREES)

    def __init__(self, token: str) -> None:
        """Accept the production constructor argument and ignore it."""
        super().__init__(list(_CliClient.served))


class _CliProfiler(_FixtureProfiler):
    """Fixture profiler with the production profiler's constructor signature."""

    def __init__(
        self,
        scoring_weights: object,
        vulnerability_options: object,
        timeout: int = 30,
        repository_signals_client: Optional[object] = None,
    ) -> None:
        """Accept the production constructor arguments and ignore them."""


def _invoke_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, served: List[str]
) -> Result:
    """Run ``scan-org`` over a chosen set of fixture repositories."""
    monkeypatch.setattr(_CliClient, "served", served)
    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.GitHubOrgClient", _CliClient
    )
    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.ExistingDependencyProfiler",
        _CliProfiler,
    )
    return CliRunner().invoke(
        app,
        [
            "scan-org",
            "acme",
            "--github-token",
            "fixture-token",
            "--output-html",
            str(tmp_path / "org.html"),
            "--output-json",
            str(tmp_path / "org.json"),
        ],
    )


def test_an_account_that_read_nothing_does_not_exit_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HYPOTHESIS (#264 parity): a scan that measured nothing is not a clean scan.

    A CI job branching on the exit code recorded an account with no findings.
    The account had findings; the tool could not read a single manifest in it.
    """
    result = _invoke_scan(tmp_path, monkeypatch, ["acme/frontend"])

    assert result.exit_code == 1, result.output
    assert "nothing was scored" in result.output
    # The reports are still written: the exit code says the scan is not usable,
    # the files say why.
    assert (tmp_path / "org.json").exists()


def test_an_account_with_no_dependencies_at_all_still_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """INVARIANT: a real zero is a successful measurement, not a refusal (#20, #68)."""
    result = _invoke_scan(tmp_path, monkeypatch, ["acme/docs", "acme/empty-but-read"])

    assert result.exit_code == 0, result.output


def test_reading_one_repository_of_several_still_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """INVARIANT: partial coverage is reported in the body, not in the exit code."""
    result = _invoke_scan(tmp_path, monkeypatch, ["acme/api", "acme/frontend"])

    assert result.exit_code == 0, result.output
    assert "1 repo could not be read" in result.output


def test_a_datetime_free_report_still_orders_repositories() -> None:
    """Guard the fixture itself: the scan ran and produced a real report."""
    report = _run()

    assert isinstance(report.generated_at, datetime)
    assert set(report.repositories_scanned) == set(_TREES)
    # jinja2 from the requirements files, left-pad from the one lock file that
    # is readable. Named rather than counted: a count cannot tell "read the
    # right manifests" from "read two of anything".
    assert {dep.key.name for dep in report.inventory} == {"jinja2", "left-pad"}
