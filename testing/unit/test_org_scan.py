"""Tests for GitHub account-wide dependency risk scans."""

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Protocol, cast

import requests
from org_tree_fixture import tree_client
from typer.testing import CliRunner

from dependency_risk_profiler.cli.typer_cli import app
from dependency_risk_profiler.contract import Remediation, RemediationAction
from dependency_risk_profiler.manifest_guidance import (
    is_recognized_unreadable_name,
    is_vendored_relative_path,
)
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
    LicenseCategory,
    LicenseInfo,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.org_scan.github import GitHubOrgClient, RepoSignals
from dependency_risk_profiler.org_scan.models import (
    DependencyKey,
    DependencyProfiler,
    RepositoryCoverage,
    RepositoryManifestListing,
    RepositoryRef,
)
from dependency_risk_profiler.org_scan.pipeline import (
    ExistingDependencyProfiler,
    RepositorySignalsClient,
    VulnerabilityOptions,
)
from dependency_risk_profiler.org_scan.report import (
    render_html_report,
    render_terminal_summary,
    report_to_dict,
    write_csv_report,
    write_json_report,
)
from dependency_risk_profiler.org_scan.scanner import (
    GitHubDiscoveryClient,
    OrgScanOptions,
    OrgScanRunner,
)


class MonkeyPatchFixture(Protocol):
    """Subset of pytest monkeypatch used by these tests."""

    def setattr(self, target: str, value: object, raising: bool = True) -> None:
        """Set an import-path target to a replacement value."""


class FixtureGitHubClient(GitHubDiscoveryClient):
    """Offline fixture GitHub client."""

    def __init__(self) -> None:
        """Initialize fixture repos and manifests."""
        self.repositories = [
            RepositoryRef(
                full_name="acme/api",
                name="api",
                default_branch="main",
                html_url="https://github.com/acme/api",
                archived=False,
                fork=False,
            ),
            RepositoryRef(
                full_name="acme/web",
                name="web",
                default_branch="main",
                html_url="https://github.com/acme/web",
                archived=False,
                fork=False,
            ),
            RepositoryRef(
                full_name="acme/old",
                name="old",
                default_branch="main",
                html_url="https://github.com/acme/old",
                archived=True,
                fork=False,
            ),
        ]
        self.manifests = {
            "acme/api": {
                "requirements.txt": "risky==1.0\nsafe==2.0\nmystery==0.1\n",
            },
            "acme/web": {
                "requirements.txt": "risky==1.0\nmedium==3.1\n",
            },
            "acme/old": {
                "requirements.txt": "legacy==0.1\n",
            },
        }

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return fixture repositories."""
        selected = [
            repo
            for repo in self.repositories
            if repo.full_name.startswith(f"{org}/")
            and (include_archived or not repo.archived)
        ]
        if max_repos is None:
            return selected
        return selected[:max_repos]

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
        include_collaborations: bool = False,
    ) -> List[RepositoryRef]:
        """Return fixture user repositories."""
        selected = [
            repo
            for repo in self.repositories
            if repo.full_name.startswith(f"{user}/")
            and (include_archived or not repo.archived)
        ]
        if max_repos is None:
            return selected
        return selected[:max_repos]

    def list_manifest_paths(
        self,
        repo: RepositoryRef,
    ) -> RepositoryManifestListing:
        """Split fixture manifest paths through the production classifier.

        Delegated to a real ``GitHubOrgClient`` over a canned git tree rather
        than reimplemented here: a fixture that classifies its own trees agrees
        with whatever the scanner does, including when the scanner is wrong
        (#265).
        """
        return tree_client(
            {name: list(tree) for name, tree in self.manifests.items()}
        ).list_manifest_paths(repo)

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Return fixture manifest content."""
        return self.manifests[repo.full_name][path]


class CanonicalPackageGitHubClient(FixtureGitHubClient):
    """Fixture with one PyPI package appearing through multiple manifest types."""

    def __init__(self) -> None:
        """Initialize canonical package grouping fixtures."""
        self.repositories: List[RepositoryRef] = [
            RepositoryRef(
                full_name="acme/api",
                name="api",
                default_branch="main",
                html_url="https://github.com/acme/api",
                archived=False,
                fork=False,
            ),
            RepositoryRef(
                full_name="acme/web",
                name="web",
                default_branch="main",
                html_url="https://github.com/acme/web",
                archived=False,
                fork=False,
            ),
        ]
        self.manifests: Dict[str, Dict[str, str]] = {
            "acme/api": {
                "requirements.txt": "jinja2==3.1.6\n",
                "pyproject.toml": ("[project]\n" 'dependencies = ["jinja2>=3.1.2"]\n'),
            },
            "acme/web": {
                "requirements.txt": "jinja2==3.1.6\n",
            },
        }


class QuietHeadlineGitHubClient(FixtureGitHubClient):
    """An account with zero high-risk dependencies and plenty of live advisories.

    This is the shape #133 is about: the leading-indicator axis is quiet — partly
    because a third of the inventory cannot be scored at all — while the advisory
    path keeps working. A headline that reports only the high-risk count reads as
    "clean" here, which is exactly wrong.
    """

    def __init__(self) -> None:
        """Initialize a single-repo account with no high-risk dependencies."""
        self.repositories: List[RepositoryRef] = [
            RepositoryRef(
                full_name="acme/api",
                name="api",
                default_branch="main",
                html_url="https://github.com/acme/api",
                archived=False,
                fork=False,
            ),
        ]
        self.manifests: Dict[str, Dict[str, str]] = {
            "acme/api": {
                "requirements.txt": (
                    "medium==3.1\njinja2==3.1.5\nmystery==0.1\nsafe==2.0\n"
                ),
            },
        }


class FixtureProfiler(DependencyProfiler):
    """Offline dependency profiler with call counting for cache assertions."""

    def __init__(self) -> None:
        """Initialize call count."""
        self.profiled_keys: List[DependencyKey] = []

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Return deterministic risk scores for fixture dependencies."""
        self.profiled_keys.extend(dependencies.keys())
        return {
            key: _score_for_key(key, dependency)
            for key, dependency in dependencies.items()
        }


class CliFixtureProfiler(FixtureProfiler):
    """CLI-compatible fixture profiler."""

    def __init__(
        self,
        scoring_weights: object,
        vulnerability_options: object,
        timeout: int = 30,
        repository_signals_client: Optional[object] = None,
    ) -> None:
        """Accept production constructor arguments."""
        super().__init__()


class CliFixtureGitHubClient(FixtureGitHubClient):
    """CLI-compatible fixture GitHub client."""

    listed_sources: List[str] = []

    def __init__(self, token: str) -> None:
        """Accept production constructor arguments."""
        super().__init__()

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Track org listing calls."""
        self.listed_sources.append(f"org:{org}")
        return super().list_org_repositories(org, include_archived, max_repos)

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
        include_collaborations: bool = False,
    ) -> List[RepositoryRef]:
        """Track user listing calls and reuse account-shaped fixtures."""
        self.listed_sources.append(f"user:{user}")
        return super().list_org_repositories(user, include_archived, max_repos)


class _FixtureResponse:
    """Small requests.Response stand-in for GitHub client endpoint tests."""

    def __init__(
        self, payload: object, headers: Optional[Dict[str, str]] = None
    ) -> None:
        """Store response payload and request-compatible attributes."""
        self._payload = payload
        self.status_code = 200
        self.headers = headers or {}
        self.text = ""

    def json(self) -> object:
        """Return fixture JSON payload."""
        return self._payload

    def raise_for_status(self) -> None:
        """Fixture responses are always successful."""


class RecordingSession:
    """Requests-compatible session that records GET calls."""

    def __init__(self, pages: List[object]) -> None:
        """Initialize paginated payloads."""
        self.pages = pages
        self.urls: List[str] = []
        self.params: List[Dict[str, str]] = []

    def get(
        self,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, str],
        timeout: int,
        stream: bool = False,
    ) -> _FixtureResponse:
        """Record request details and return the next page."""
        self.urls.append(url)
        self.params.append(params)
        index = len(self.urls) - 1
        if index < len(self.pages):
            return _FixtureResponse(self.pages[index])
        return _FixtureResponse([])


class SignalSession:
    """Requests-compatible session that returns prebuilt responses."""

    def __init__(self, responses: List[_FixtureResponse]) -> None:
        """Initialize response queue."""
        self.responses = responses
        self.urls: List[str] = []
        self.params: List[Dict[str, str]] = []

    def get(
        self,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, str],
        timeout: int,
        stream: bool = False,
    ) -> _FixtureResponse:
        """Record request details and return the next response."""
        self.urls.append(url)
        self.params.append(params)
        index = len(self.urls) - 1
        if index < len(self.responses):
            return self.responses[index]
        return _FixtureResponse([])


class FixtureRepositorySignalsClient(RepositorySignalsClient):
    """Offline authenticated repository signal fixture."""

    def __init__(self, signals: RepoSignals) -> None:
        """Initialize fixture signal payload."""
        self.signals = signals
        self.calls: List[str] = []

    def get_repository_signals(self, owner_repo: str) -> RepoSignals:
        """Return fixture signals and record the normalized repo key."""
        self.calls.append(owner_repo)
        return self.signals


def test_org_scan_aggregates_blast_radius_and_rankings() -> None:
    """HYPOTHESIS: org scan deduplicates dependencies and ranks exposure."""
    profiler = FixtureProfiler()
    report = OrgScanRunner(FixtureGitHubClient(), profiler).run(
        OrgScanOptions(org="acme")
    )

    assert len(report.repositories_scanned) == 2
    assert len(report.manifests_scanned) == 2
    assert report.unique_dependency_count == 4
    assert len(profiler.profiled_keys) == 4

    risky = report.inventory[0]
    assert risky.key.name == "risky"
    assert risky.risk_level == RiskLevel.HIGH
    assert risky.blast_radius == 2
    assert sorted(risky.repositories) == ["acme/api", "acme/web"]
    assert risky.repo_refs["acme/api"].default_branch == "main"
    assert risky.repo_refs["acme/web"].html_url == "https://github.com/acme/web"
    assert risky.manifest_paths_by_repo == {
        "acme/api": {"requirements.txt"},
        "acme/web": {"requirements.txt"},
    }

    assert report.most_exposed_risky_dependencies[0].key.name == "risky"
    assert [dep.key.name for dep in report.most_exposed_risky_dependencies] == [
        "risky",
        "medium",
        "mystery",
    ]
    assert report.riskiest_repositories[0].repo_full_name == "acme/web"
    # Both axes plus the coverage caveat, known-vulnerable first (#133).
    assert report.headline == (
        "2 known-vulnerable · 1 high-risk · 1 could not be scored · "
        "4 dependencies across 2 repos"
    )
    assert report.known_vulnerable_dependency_count == 2
    assert report.unscored_dependency_count == 1


def test_org_scan_groups_report_by_canonical_package_identity() -> None:
    """REGRESSION: PyPI packages from pyproject and requirements render once."""
    profiler = FixtureProfiler()
    report = OrgScanRunner(CanonicalPackageGitHubClient(), profiler).run(
        OrgScanOptions(org="acme")
    )

    assert len(profiler.profiled_keys) == 2
    assert sorted(
        (key.ecosystem, key.name, key.version) for key in profiler.profiled_keys
    ) == [
        ("pyproject", "jinja2", ">=3.1.2"),
        ("python", "jinja2", "3.1.6"),
    ]
    assert report.unique_dependency_count == 1

    dependency = report.inventory[0]
    assert dependency.key.ecosystem == "python"
    assert dependency.key.name == "jinja2"
    assert dependency.key.version == "3.1.6"
    assert dependency.version_specs == {">=3.1.2", "3.1.6"}
    assert dependency.version_specs_list == [">=3.1.2", "3.1.6"]
    assert dependency.risk_level == RiskLevel.HIGH
    assert dependency.risk_score.total_score == 7.3
    assert dependency.advisory_summary == "2 scored / 0 filtered"
    assert dependency.blast_radius == 2
    assert sorted(dependency.repositories) == ["acme/api", "acme/web"]
    assert sorted(dependency.manifests) == [
        "acme/api:pyproject.toml",
        "acme/api:requirements.txt",
        "acme/web:requirements.txt",
    ]
    assert dependency.manifest_paths_by_repo == {
        "acme/api": {"pyproject.toml", "requirements.txt"},
        "acme/web": {"requirements.txt"},
    }

    repo_counts = {
        summary.repo_full_name: summary.dependency_count
        for summary in report.riskiest_repositories
    }
    assert repo_counts == {"acme/api": 1, "acme/web": 1}

    model = report_to_dict(report)
    inventory = cast(List[Dict[str, object]], model["inventory"])
    assert len(inventory) == 1
    assert inventory[0]["ecosystem"] == "python"
    # Org-only concepts live under the declared extension block; the shared
    # fields keep their names on both paths (#164).
    org_scan = cast(
        Dict[str, object], cast(Dict[str, object], inventory[0])["extensions"]
    )["org_scan"]
    assert cast(Dict[str, object], org_scan)["version_specs"] == [
        ">=3.1.2",
        "3.1.6",
    ]

    html = render_html_report(report)
    assert '<span class="eco">· python</span>' in html
    assert '<span class="eco">· pyproject</span>' not in html
    assert "&gt;=3.1.2, 3.1.6" in html


def test_org_scan_html_json_and_terminal_outputs(tmp_path: Path) -> None:
    """HYPOTHESIS: reports contain required sections and aggregate model."""
    report = OrgScanRunner(FixtureGitHubClient(), FixtureProfiler()).run(
        OrgScanOptions(org="acme")
    )

    html = render_html_report(report)
    assert "Most exposed risky dependencies" in html
    assert "Riskiest repositories" in html
    assert "Full inventory" in html
    assert '<dl class="readout" aria-label="Scan totals">' in html
    assert "<dt>High-risk</dt>" in html
    # Known-vulnerable is an orthogonal axis: a readout cell + a chip on deps
    # whose installed version has scored advisories.
    assert "<dt>Known-vuln</dt>" in html
    assert 'class="vuln-tag"' in html
    assert ":root{" in html
    assert ':root[data-theme="dark"]' in html
    assert '<span class="badge high">HIGH</span>' in html
    assert '<span class="badge unknown">UNKNOWN</span>' in html
    assert '<details class="exp-row drill" data-risk="1"' in html
    assert '<summary class="exp-summary">' in html
    assert '<meter class="bar high"' in html
    assert 'max="2"' in html and 'value="2"' in html
    assert 'aria-label="2 / 2 repos exposed to risky"' in html
    assert "2 / 2 repos" in html
    assert "2 scored · 1 filtered" in html
    assert "advisories: unknown" in html
    assert "Why it&#x27;s flagged" in html
    assert "Bus factor: 1 primary maintainer" in html
    assert "Version drift: 1.0 → 2.3.0 (1 major behind)" in html
    assert (
        'href="https://github.com/acme/api/blob/main/requirements.txt" '
        'target="_blank" rel="noopener"'
    ) in html
    assert 'href="https://deps.dev/pypi/risky" target="_blank" rel="noopener"' in html
    assert (
        'href="https://pypi.org/project/risky/" target="_blank" rel="noopener"'
    ) in html
    assert (
        'href="https://securityscorecards.dev/viewer/?uri=github.com%2Facme%2Frisky" '
        'target="_blank" rel="noopener"'
    ) in html
    assert (
        'href="https://github.com/advisories/GHSA-risky" '
        'target="_blank" rel="noopener"'
    ) in html
    assert "excluded: informational" in html
    assert "<b>How to read this.</b>" in html
    assert "filtered out of the score" in html

    json_path = tmp_path / "report.json"
    write_json_report(report, json_path)
    assert json_path.exists()

    csv_path = tmp_path / "report.csv"
    write_csv_report(report, csv_path)
    with csv_path.open(encoding="utf-8", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    assert len(csv_rows) == report.unique_dependency_count
    first_csv = csv_rows[0]
    assert set(first_csv) == {
        "package",
        "ecosystem",
        "risk_level",
        "risk_score",
        "repos_exposed",
        "repos_scanned",
        "installed_version",
        "version_specs",
        "latest_version",
        "stars",
        "contributors",
        "last_updated",
        "license",
        "deprecated",
        "known_vulnerable",
        "remediation",
        "advisories_scored",
        "advisories_filtered",
        "signals",
        "repositories",
        "manifests",
        "source_repo",
        "deps_dev",
    }
    assert first_csv["risk_level"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    assert first_csv["deps_dev"].startswith("https://deps.dev/")
    assert first_csv["known_vulnerable"] in {"yes", "no"}
    assert any(r["known_vulnerable"] == "yes" for r in csv_rows)
    # A known-vulnerable dependency carries a ready-to-use remediation string.
    vuln_row = next(r for r in csv_rows if r["known_vulnerable"] == "yes")
    assert "advisories" in vuln_row["remediation"]

    model = report_to_dict(report)
    assert model["unique_dependency_count"] == 4
    known_vulnerable_count = model["known_vulnerable_dependency_count"]
    assert isinstance(known_vulnerable_count, int)
    assert known_vulnerable_count >= 1
    assert "most_exposed_risky_dependencies" in model
    first_dependencies = cast(
        List[Dict[str, object]], model["most_exposed_risky_dependencies"]
    )
    # Every serialized dependency carries a structured remediation block under
    # the org extension; the known-vulnerable one classifies an action rather
    # than describing one in prose an agent would have to regex (#164).
    org_blocks = [
        cast(Dict[str, object], cast(Dict[str, object], dep["extensions"])["org_scan"])
        for dep in first_dependencies
    ]
    assert all("remediation" in block for block in org_blocks)
    vuln_index = next(
        index for index, dep in enumerate(first_dependencies) if dep["known_vulnerable"]
    )
    vuln_remediation = cast(Dict[str, object], org_blocks[vuln_index]["remediation"])
    # This fixture's advisories publish no fix, so the honest classification is
    # "replace", not an upgrade target invented to fill the field.
    assert vuln_remediation["action"] == "replace"
    assert vuln_remediation["fix_versions"] == []
    assert org_blocks[0]["usage"] == [
        {
            "repo": "acme/api",
            "html_url": "https://github.com/acme/api",
            "default_branch": "main",
            "manifests": ["requirements.txt"],
        },
        {
            "repo": "acme/web",
            "html_url": "https://github.com/acme/web",
            "default_branch": "main",
            "manifests": ["requirements.txt"],
        },
    ]

    summary = render_terminal_summary(report)
    assert "Most exposed risky dependencies:" in summary
    assert "python:risky@1.0 · HIGH · 2 / 2 repos" in summary
    assert "Riskiest repositories:" in summary


def test_csv_remediation_prose_is_generated_from_the_structured_block(
    tmp_path: Path,
) -> None:
    """INVARIANT (#164 step 6): one classifier, two renderings, not two of each.

    The CSV column used to run its own precedence chain over the same facts.
    Two independent descriptions of one dependency can disagree, and this pair
    did worse than drift: the prose path printed raw registry version strings
    the structured path had already refused as unsafe to publish. The sentence
    is now derived from the block, so this rebuilds it from the serialized JSON
    and demands the bytes match.
    """
    report = OrgScanRunner(FixtureGitHubClient(), FixtureProfiler()).run(
        OrgScanOptions(org="acme")
    )
    csv_path = tmp_path / "org.csv"
    write_csv_report(report, csv_path)
    with csv_path.open(encoding="utf-8") as handle:
        prose_by_package = {
            row["package"]: row["remediation"] for row in csv.DictReader(handle)
        }

    inventory = cast(List[Dict[str, object]], report_to_dict(report)["inventory"])
    assert prose_by_package
    for entry in inventory:
        extensions = cast(Dict[str, object], entry["extensions"])
        org_scan = cast(Dict[str, object], extensions["org_scan"])
        block = cast(Dict[str, object], org_scan["remediation"])
        rebuilt = Remediation(
            action=RemediationAction(cast(str, block["action"])),
            fix_versions=tuple(cast(List[str], block["fix_versions"])),
            target_version=cast(Optional[str], block["target_version"]),
            detail=cast(str, block["detail"]),
        )
        assert prose_by_package[cast(str, entry["name"])] == rebuilt.sentence()


def test_zero_high_risk_headline_still_reports_advisories_and_coverage() -> None:
    """REGRESSION (#133): a quiet high-risk count must not read as reassuring.

    With no high-risk dependencies, the old headline said "0 high-risk
    dependencies exposed across 0 repositories" while two dependencies carried
    live advisories and a third could not be scored at all. Every surface —
    terminal, JSON, HTML — has to carry all three numbers.
    """
    report = OrgScanRunner(QuietHeadlineGitHubClient(), FixtureProfiler()).run(
        OrgScanOptions(org="acme")
    )

    assert report.high_risk_dependency_count == 0
    assert report.known_vulnerable_dependency_count == 2
    assert report.unscored_dependency_count == 1
    assert report.unique_dependency_count == 4

    # Known-vulnerable leads: there is a fix and a version to move to.
    assert report.headline == (
        "2 known-vulnerable · 0 high-risk · 1 could not be scored · "
        "4 dependencies across 1 repo"
    )
    assert report.headline.index("known-vulnerable") < report.headline.index(
        "high-risk"
    )

    # The terminal summary leads with the headline, so it inherits all of it.
    summary = render_terminal_summary(report)
    assert report.headline in summary

    model = report_to_dict(report)
    assert model["known_vulnerable_dependency_count"] == 2
    assert model["unscored_dependency_count"] == 1
    assert model["high_risk_dependency_count"] == 0
    assert model["headline"] == report.headline

    html = render_html_report(report)
    assert "<dt>Known-vuln</dt>" in html
    assert "<dt>Unscored</dt>" in html
    assert "<b>2 known-vulnerable</b>" in html
    assert "<b>0 high-risk</b>" in html
    # The caveat that stops the high-risk count reading as a total.
    assert "1 of 4 could not be scored" in html
    assert "the high-risk count is a floor, not a total" in html


def test_github_client_lists_user_repositories_with_filters() -> None:
    """HYPOTHESIS: user repo listing calls /users/{user}/repos and filters repos."""
    session = RecordingSession(
        [
            [
                _repo_payload("williamzujkowski/kept", archived=False, fork=False),
                _repo_payload("williamzujkowski/forked", archived=False, fork=True),
                _repo_payload("williamzujkowski/archived", archived=True, fork=False),
            ],
            [],
        ]
    )
    client = GitHubOrgClient(
        token="fixture-token",
        session=cast(requests.Session, session),
    )

    repos = client.list_user_repositories("williamzujkowski")

    assert [repo.full_name for repo in repos] == ["williamzujkowski/kept"]
    assert session.urls[0].endswith("/users/williamzujkowski/repos")
    # Default scopes to repos the user OWNS, not ones they collaborate on.
    assert session.params[0]["type"] == "owner"
    assert session.params[0]["per_page"] == "100"


def test_github_client_user_repos_include_collaborations_opt_in() -> None:
    """include_collaborations=True asks GitHub for type=all (owner + member)."""
    session = RecordingSession(
        [
            [_repo_payload("williamzujkowski/kept", archived=False, fork=False)],
            [],
        ]
    )
    client = GitHubOrgClient(
        token="fixture-token",
        session=cast(requests.Session, session),
    )

    client.list_user_repositories("williamzujkowski", include_collaborations=True)

    assert session.params[0]["type"] == "all"


def test_github_client_fetches_repository_signals_from_authenticated_api() -> None:
    """REGRESSION: repo signals use API JSON and Link header contributor counts."""
    session = SignalSession(
        [
            _FixtureResponse({"stargazers_count": 12345, "archived": False}),
            _FixtureResponse(
                [{"login": "first"}],
                {
                    "Link": (
                        "<https://api.github.com/repos/pallets/jinja/contributors"
                        '?per_page=1&anon=true&page=248>; rel="last"'
                    )
                },
            ),
            _FixtureResponse(
                [{"sha": "abc"}],
                {
                    "Link": (
                        "<https://api.github.com/repos/pallets/jinja/commits"
                        '?per_page=1&page=90>; rel="last"'
                    )
                },
            ),
        ]
    )
    client = GitHubOrgClient(
        token="fixture-token",
        session=cast(requests.Session, session),
    )

    signals = client.get_repository_signals("pallets/jinja")

    assert signals.star_count == 12345
    assert signals.contributor_count == 248
    assert signals.archived is False
    # 90 commits over the six-month window: an org scan measures cadence from
    # the API because it never clones (#166).
    assert signals.commit_frequency == 15.0
    assert session.urls == [
        "https://api.github.com/repos/pallets/jinja",
        "https://api.github.com/repos/pallets/jinja/contributors",
        "https://api.github.com/repos/pallets/jinja/commits",
    ]
    assert session.params[1] == {"per_page": "1", "anon": "true"}
    assert session.params[2]["per_page"] == "1"
    assert "since" in session.params[2]


def test_github_client_leaves_cadence_unmeasured_when_commits_fail() -> None:
    """An empty repo answers 409; cadence goes unmeasured, stars survive (#166)."""

    class _EmptyRepoCommits(_FixtureResponse):
        """A commits response that behaves like GitHub's 409 for an empty repo."""

        def raise_for_status(self) -> None:
            """Fail the way requests does for a 4xx."""
            raise requests.HTTPError("409 Conflict: Git Repository is empty.")

        def close(self) -> None:
            """Absorb the close the client does before re-raising."""

    session = SignalSession(
        [
            _FixtureResponse({"stargazers_count": 3, "archived": False}),
            _FixtureResponse([{"login": "one"}], {}),
            _EmptyRepoCommits([]),
        ]
    )
    client = GitHubOrgClient(
        token="fixture-token", session=cast(requests.Session, session)
    )

    signals = client.get_repository_signals("acme/empty")

    assert signals.commit_frequency is None
    assert signals.star_count == 3


def test_github_client_derives_pushed_at_and_health_from_tree() -> None:
    """Repo signals get last-push + tests/CI from the API tree, no clone."""
    session = SignalSession(
        [
            _FixtureResponse(
                {
                    "stargazers_count": 100,
                    "archived": False,
                    "pushed_at": "2026-01-15T10:30:00Z",
                    "default_branch": "main",
                }
            ),
            _FixtureResponse([{"login": "one"}], {}),
            _FixtureResponse([{"sha": "abc"}], {}),
            _FixtureResponse(
                {
                    # Non-recursive root tree: top-level entries only. A
                    # ".github" dir implies CI; a "tests" dir implies tests.
                    "tree": [
                        {"path": "src", "type": "tree"},
                        {"path": "tests", "type": "tree"},
                        {"path": ".github", "type": "tree"},
                    ],
                }
            ),
        ]
    )
    client = GitHubOrgClient(
        token="fixture-token", session=cast(requests.Session, session)
    )

    signals = client.get_repository_signals("acme/widget")

    assert signals.pushed_at is not None
    assert signals.pushed_at.year == 2026 and signals.pushed_at.month == 1
    assert signals.has_tests is True
    assert signals.has_ci is True
    # Non-recursive tree request (no ?recursive=1) keeps it cheap for monorepos.
    assert session.urls[3] == "https://api.github.com/repos/acme/widget/git/trees/main"
    assert session.params[3] == {}


def test_github_client_reports_false_health_when_no_markers() -> None:
    """A root tree with no test/CI markers yields has_tests/has_ci False."""
    session = SignalSession(
        [
            _FixtureResponse(
                {"stargazers_count": 5, "default_branch": "main", "archived": False}
            ),
            _FixtureResponse([{"login": "one"}], {}),
            _FixtureResponse([], {}),
            _FixtureResponse({"tree": [{"path": "src", "type": "tree"}]}),
        ]
    )
    client = GitHubOrgClient(
        token="fixture-token", session=cast(requests.Session, session)
    )

    signals = client.get_repository_signals("acme/plain")

    assert signals.has_tests is False
    assert signals.has_ci is False


def test_profiler_applies_pushed_at_and_health_signals() -> None:
    """pushed_at becomes last_updated and tests/CI flags are applied."""
    pushed = datetime(2026, 1, 15, tzinfo=timezone.utc)
    signals_client = FixtureRepositorySignalsClient(
        RepoSignals(
            star_count=100,
            contributor_count=50,
            archived=False,
            pushed_at=pushed,
            has_tests=True,
            has_ci=False,
        )
    )
    profiler = ExistingDependencyProfiler(
        scoring_weights={},
        vulnerability_options=VulnerabilityOptions(),
        repository_signals_client=signals_client,
    )
    dependency = DependencyMetadata(
        name="jinja2",
        installed_version="3.1.6",
        repository_url="https://github.com/pallets/jinja/",
    )

    enriched = profiler._apply_github_repository_signals(dependency)

    assert enriched.last_updated == pushed
    assert enriched.has_tests is True
    assert enriched.has_ci is False


def test_org_scan_profiler_disables_cloning() -> None:
    """Org-scan analyzers never clone; API signals stand in for repo inspection."""
    profiler = ExistingDependencyProfiler(
        scoring_weights={},
        vulnerability_options=VulnerabilityOptions(),
    )
    analyzer = profiler._get_analyzer("python")
    assert analyzer is not None
    assert analyzer.clone_repos is False


def test_profiler_applies_authenticated_repository_signals_and_caches() -> None:
    """REGRESSION: GitHub repo signals replace registry maintainer guesses."""
    signals_client = FixtureRepositorySignalsClient(
        RepoSignals(star_count=12345, contributor_count=248, archived=False)
    )
    profiler = ExistingDependencyProfiler(
        scoring_weights={},
        vulnerability_options=VulnerabilityOptions(),
        repository_signals_client=signals_client,
    )
    dependency = DependencyMetadata(
        name="jinja2",
        installed_version="3.1.6",
        maintainer_count=1,
        repository_url="https://github.com/pallets/jinja/",
        community_metrics=CommunityMetrics(),
    )

    enriched = profiler._apply_github_repository_signals(dependency)
    second = DependencyMetadata(
        name="jinja2",
        installed_version="3.1.6",
        repository_url="git+https://github.com/pallets/jinja.git",
    )
    profiler._apply_github_repository_signals(second)

    assert enriched.community_metrics is not None
    assert enriched.community_metrics.star_count == 12345
    assert enriched.community_metrics.contributor_count == 248
    assert enriched.maintainer_count == 248
    assert enriched.additional_info["github_repository_archived"] == "false"
    assert signals_client.calls == ["pallets/jinja"]


def test_user_scan_aggregates_blast_radius_and_report_labels() -> None:
    """HYPOTHESIS: user scans share aggregation and label the source as user."""
    profiler = FixtureProfiler()
    client = FixtureGitHubClient()
    report = OrgScanRunner(client, profiler).run(
        OrgScanOptions(
            org="acme",
            account_type="user",
            repository_lister=client.list_user_repositories,
        )
    )

    assert report.account_type == "user"
    assert report.unique_dependency_count == 4
    assert len(profiler.profiled_keys) == 4
    assert report.most_exposed_risky_dependencies[0].key.name == "risky"
    assert report.most_exposed_risky_dependencies[0].blast_radius == 2

    html = render_html_report(report)
    assert "Dependency exposure · github user" in html
    assert "Most exposed risky dependencies" in html
    assert "Riskiest repositories" in html
    assert "Full inventory" in html
    assert "2 / 2 repos" in html

    model = report_to_dict(report)
    assert model["account_type"] == "user"
    assert model["account"] == "acme"


def test_scan_org_cli_writes_html_and_json(
    tmp_path: Path,
    monkeypatch: MonkeyPatchFixture,
) -> None:
    """HYPOTHESIS: scan-org command runs end-to-end with offline fixtures."""
    html_path = tmp_path / "org.html"
    json_path = tmp_path / "org.json"
    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.GitHubOrgClient",
        CliFixtureGitHubClient,
    )
    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.ExistingDependencyProfiler",
        CliFixtureProfiler,
    )

    result = CliRunner().invoke(
        app,
        [
            "scan-org",
            "acme",
            "--github-token",
            "fixture-token",
            "--output-html",
            str(html_path),
            "--output-json",
            str(json_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert html_path.exists()
    assert json_path.exists()
    assert "Dependency Risk Org Scan · acme" in result.output
    assert "python:risky@1.0 · HIGH · 2 / 2 repos" in result.output
    assert "HTML report written" in result.output


def test_scan_org_fail_on_exit_code(
    tmp_path: Path,
    monkeypatch: MonkeyPatchFixture,
) -> None:
    """--fail-on exits non-zero when the threshold is met, zero otherwise."""
    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.GitHubOrgClient",
        CliFixtureGitHubClient,
    )
    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.ExistingDependencyProfiler",
        CliFixtureProfiler,
    )

    def _invoke(level: str) -> int:
        result = CliRunner().invoke(
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
                "--fail-on",
                level,
            ],
        )
        return result.exit_code

    # The fixture has a HIGH dependency: fail-on high triggers, critical does not.
    assert _invoke("high") == 2
    assert _invoke("critical") == 0


def test_scan_user_cli_writes_html_and_json(
    tmp_path: Path,
    monkeypatch: MonkeyPatchFixture,
) -> None:
    """HYPOTHESIS: scan-user command runs end-to-end with offline fixtures."""
    html_path = tmp_path / "user.html"
    json_path = tmp_path / "user.json"
    CliFixtureGitHubClient.listed_sources = []
    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.GitHubOrgClient",
        CliFixtureGitHubClient,
    )
    monkeypatch.setattr(
        "dependency_risk_profiler.cli.typer_cli.ExistingDependencyProfiler",
        CliFixtureProfiler,
    )

    result = CliRunner().invoke(
        app,
        [
            "scan-user",
            "acme",
            "--github-token",
            "fixture-token",
            "--output-html",
            str(html_path),
            "--output-json",
            str(json_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert html_path.exists()
    assert json_path.exists()
    assert CliFixtureGitHubClient.listed_sources == ["user:acme"]
    assert "Dependency Risk User Scan · acme" in result.output
    assert "python:risky@1.0 · HIGH · 2 / 2 repos" in result.output
    assert "Dependency exposure · github user" in html_path.read_text(encoding="utf-8")


def _repo_payload(full_name: str, archived: bool, fork: bool) -> Dict[str, object]:
    """Build a minimal GitHub repository API payload."""
    name = full_name.rsplit("/", 1)[-1]
    return {
        "full_name": full_name,
        "name": name,
        "default_branch": "main",
        "html_url": f"https://github.com/{full_name}",
        "archived": archived,
        "fork": fork,
    }


def _score_for_key(
    key: DependencyKey, dependency: DependencyMetadata
) -> DependencyRiskScore:
    """Build deterministic fixture scores."""
    if key.name == "jinja2":
        dependency.latest_version = "3.1.6"
        if key.version == "3.1.6":
            dependency.security_metrics = SecurityMetrics(
                vulnerability_count=2,
                counted_vulnerability_count=2,
                filtered_vulnerability_count=0,
                max_vulnerability_severity="HIGH",
            )
            return DependencyRiskScore(
                dependency=dependency,
                total_score=7.3,
                risk_level=RiskLevel.HIGH,
                exploit_score=1.0,
                version_score=0.0,
                factors=["scored advisories"],
            )
        dependency.security_metrics = SecurityMetrics(
            vulnerability_count=1,
            counted_vulnerability_count=1,
            filtered_vulnerability_count=0,
            max_vulnerability_severity="MEDIUM",
        )
        return DependencyRiskScore(
            dependency=dependency,
            total_score=2.6,
            risk_level=RiskLevel.MEDIUM,
            exploit_score=0.5,
            version_score=0.5,
            factors=["behind latest"],
        )
    if key.name == "risky":
        dependency.latest_version = "2.3.0"
        dependency.last_updated = datetime(2023, 5, 1)
        dependency.maintainer_count = 1
        dependency.repository_url = "https://github.com/acme/risky"
        dependency.has_tests = False
        dependency.has_ci = False
        dependency.has_contribution_guidelines = True
        dependency.license_info = LicenseInfo(
            license_id="GPL-3.0",
            category=LicenseCategory.COPYLEFT,
            is_approved=False,
        )
        dependency.security_metrics = SecurityMetrics(
            vulnerability_count=3,
            counted_vulnerability_count=2,
            filtered_vulnerability_count=1,
            max_vulnerability_severity="HIGH",
            vulnerability_details=[
                {
                    "id": "GHSA-risky",
                    "severity": "HIGH",
                    "summary": "fixture",
                    "counted_in_score": True,
                    "filtered": False,
                },
                {
                    "id": "OSV-2024-risky",
                    "severity": "MEDIUM",
                    "summary": "fixture",
                    "counted_in_score": True,
                    "filtered": False,
                },
                {
                    "id": "GHSA-info",
                    "severity": "INFORMATIONAL",
                    "summary": "fixture",
                    "counted_in_score": False,
                    "filtered": True,
                    "filter_reasons": ["informational"],
                },
            ],
        )
        return DependencyRiskScore(
            dependency=dependency,
            total_score=4.2,
            risk_level=RiskLevel.HIGH,
            maintainer_score=1.0,
            exploit_score=1.0,
            version_score=1.0,
            health_indicators_score=1.0,
            license_score=1.0,
            factors=["single maintainer", "scored advisories"],
        )
    if key.name == "medium":
        dependency.security_metrics = SecurityMetrics(
            vulnerability_count=1,
            counted_vulnerability_count=1,
            filtered_vulnerability_count=0,
            max_vulnerability_severity="MEDIUM",
        )
        return DependencyRiskScore(
            dependency=dependency,
            total_score=2.4,
            risk_level=RiskLevel.MEDIUM,
            version_score=0.5,
            factors=["behind latest"],
        )
    if key.name == "mystery":
        return DependencyRiskScore(
            dependency=dependency,
            total_score=0.0,
            risk_level=RiskLevel.UNKNOWN,
            insufficient_data=True,
            unknown_signals=["maintainer", "community"],
            factors=["Insufficient data for confident risk level"],
        )
    return DependencyRiskScore(
        dependency=dependency,
        total_score=0.8,
        risk_level=RiskLevel.LOW,
        factors=[],
    )
