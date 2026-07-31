"""Tests for organization-wide dependency risk scans."""

from pathlib import Path
from typing import Dict, Iterable, List, Optional

from typer.testing import CliRunner

from dependency_risk_profiler.cli.typer_cli import app
from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.org_scan.models import (
    DependencyKey,
    DependencyProfiler,
    RepositoryRef,
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
    ) -> None:
        """Accept production constructor arguments."""
        super().__init__()


class CliFixtureGitHubClient(FixtureGitHubClient):
    """CLI-compatible fixture GitHub client."""

    def __init__(self, token: str) -> None:
        """Accept production constructor arguments."""
        super().__init__()


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

    assert report.most_exposed_risky_dependencies[0].key.name == "risky"
    assert report.riskiest_repositories[0].repo_full_name == "acme/web"
    assert report.headline == "1 high-risk dependencies exposed across 2 repositories"


def test_org_scan_html_json_and_terminal_outputs(tmp_path: Path) -> None:
    """HYPOTHESIS: reports contain required sections and aggregate model."""
    report = OrgScanRunner(FixtureGitHubClient(), FixtureProfiler()).run(
        OrgScanOptions(org="acme")
    )

    html = render_html_report(report)
    assert "Most exposed risky dependencies" in html
    assert "Riskiest repositories" in html
    assert "Full dependency inventory" in html
    assert "2 / 2 repos" in html
    assert "Filtered advisories are excluded from scoring" in html

    json_path = tmp_path / "report.json"
    write_json_report(report, json_path)
    assert json_path.exists()
    model = report_to_dict(report)
    assert model["unique_dependency_count"] == 4
    assert "most_exposed_risky_dependencies" in model

    summary = render_terminal_summary(report)
    assert "Most exposed risky dependencies:" in summary
    assert "python:risky@1.0 · HIGH · 2 / 2 repos" in summary
    assert "Riskiest repositories:" in summary


def test_scan_org_cli_writes_html_and_json(
    tmp_path: Path,
    monkeypatch,
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


def _score_for_key(
    key: DependencyKey, dependency: DependencyMetadata
) -> DependencyRiskScore:
    """Build deterministic fixture scores."""
    if key.name == "risky":
        dependency.maintainer_count = 1
        dependency.security_metrics = SecurityMetrics(
            vulnerability_count=3,
            counted_vulnerability_count=2,
            filtered_vulnerability_count=1,
            max_vulnerability_severity="HIGH",
            vulnerability_details=[
                {"id": "GHSA-risky", "severity": "HIGH", "summary": "fixture"}
            ],
        )
        return DependencyRiskScore(
            dependency=dependency,
            total_score=4.2,
            risk_level=RiskLevel.HIGH,
            maintainer_score=1.0,
            exploit_score=1.0,
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
