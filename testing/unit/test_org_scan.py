"""Tests for GitHub account-wide dependency risk scans."""

from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Protocol, cast

import requests
from typer.testing import CliRunner

from dependency_risk_profiler.cli.typer_cli import app
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
        supported_names: Iterable[str],
    ) -> List[str]:
        """Return fixture manifest paths."""
        supported = {name.lower() for name in supported_names}
        return [
            path
            for path in self.manifests.get(repo.full_name, {})
            if path.rsplit("/", 1)[-1].lower() in supported
        ]

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
    assert report.headline == "1 high-risk dependencies exposed across 2 repositories"


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
    assert dependency.versions_display == ">=3.1.2, 3.1.6"
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
    assert inventory[0]["version_specs"] == [">=3.1.2", "3.1.6"]
    assert inventory[0]["versions_display"] == ">=3.1.2, 3.1.6"

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
    assert ":root{" in html
    assert ':root[data-theme="dark"]' in html
    assert '<span class="badge high">HIGH</span>' in html
    assert '<span class="badge unknown">UNKNOWN</span>' in html
    assert '<details class="exp-row drill" data-risk="1"' in html
    assert '<summary class="exp-summary">' in html
    assert 'class="bar-fill high" style="width:100%"></span>' in html
    assert 'role="img" aria-label="2 / 2 repos exposed to risky"' in html
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
    model = report_to_dict(report)
    assert model["unique_dependency_count"] == 4
    assert "most_exposed_risky_dependencies" in model
    first_dependencies = cast(
        List[Dict[str, object]], model["most_exposed_risky_dependencies"]
    )
    assert first_dependencies[0]["usage"] == [
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
    assert session.params[0]["type"] == "all"
    assert session.params[0]["per_page"] == "100"


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
    assert session.urls == [
        "https://api.github.com/repos/pallets/jinja",
        "https://api.github.com/repos/pallets/jinja/contributors",
    ]
    assert session.params[1] == {"per_page": "1", "anon": "true"}


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
