"""Typed models for organization-wide dependency risk scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Literal, Set, Tuple

from ..models import DependencyMetadata, DependencyRiskScore, RiskLevel

AccountType = Literal["organization", "user"]

_CANONICAL_ECOSYSTEM_ALIASES = {
    "pyproject": "python",
}


def canonical_ecosystem(raw: str) -> str:
    """Return the package-identity ecosystem for report aggregation."""
    normalized = raw.lower().strip()
    return _CANONICAL_ECOSYSTEM_ALIASES.get(normalized, normalized)


@dataclass(frozen=True)
class DependencyKey:
    """Stable identity for a dependency profile reused across repositories."""

    ecosystem: str
    name: str
    version: str

    @property
    def display_name(self) -> str:
        """Return an ecosystem-qualified dependency label."""
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass(frozen=True)
class RepositoryRef:
    """GitHub repository metadata used during org scans."""

    full_name: str
    name: str
    default_branch: str
    html_url: str
    archived: bool
    fork: bool


@dataclass(frozen=True)
class ManifestRef:
    """A discovered manifest within a repository."""

    repo_full_name: str
    path: str
    ecosystem: str
    content: str

    @property
    def display_path(self) -> str:
        """Return a repository-qualified manifest path."""
        return f"{self.repo_full_name}:{self.path}"


@dataclass(frozen=True)
class DependencyOccurrence:
    """A single repository/manifest occurrence of a dependency."""

    repo_full_name: str
    manifest_path: str
    key: DependencyKey


@dataclass
class ManifestParseFailure:
    """A manifest that could not be parsed."""

    repo_full_name: str
    path: str
    reason: str


@dataclass
class AggregatedDependency:
    """Org-wide exposure for one unique dependency."""

    key: DependencyKey
    risk_score: DependencyRiskScore
    repositories: Set[str] = field(default_factory=set)
    manifests: Set[str] = field(default_factory=set)
    repo_refs: Dict[str, RepositoryRef] = field(default_factory=dict)
    manifest_paths_by_repo: Dict[str, Set[str]] = field(default_factory=dict)
    key_signals: List[str] = field(default_factory=list)
    advisory_summary: str = "unknown"
    version_specs: Set[str] = field(default_factory=set)

    @property
    def blast_radius(self) -> int:
        """Return the number of repositories depending on this dependency."""
        return len(self.repositories)

    @property
    def risk_level(self) -> RiskLevel:
        """Return the dependency risk level."""
        return self.risk_score.risk_level

    @property
    def versions_display(self) -> str:
        """Return a deterministic compact display of all seen version specs."""
        return ", ".join(self.version_specs_list)

    @property
    def version_specs_list(self) -> List[str]:
        """Return all seen version specs in deterministic display order."""
        if not self.version_specs:
            return [self.key.version]
        return sorted(self.version_specs, key=_version_spec_sort_key)


def _version_spec_sort_key(version_spec: str) -> Tuple[int, str]:
    """Sort range-like specs before concrete pins for compact display."""
    first_character = version_spec[:1]
    range_prefixes = {"<", ">", "=", "~", "^"}
    return (0 if first_character in range_prefixes else 1, version_spec.lower())


@dataclass
class RepositoryRiskSummary:
    """Aggregate risk summary for one scanned repository."""

    repo_full_name: str
    dependency_count: int
    critical_risk_dependencies: int
    high_risk_dependencies: int
    medium_risk_dependencies: int
    unknown_risk_dependencies: int
    risk_points: int
    average_risk_score: float
    worst_dependencies: List[AggregatedDependency]


@dataclass
class OrgScanReport:
    """Complete aggregate model for an organization scan."""

    org: str
    account_type: AccountType
    generated_at: datetime
    repositories_scanned: List[str]
    manifests_scanned: List[str]
    unique_dependency_count: int
    parse_failures: List[ManifestParseFailure]
    inventory: List[AggregatedDependency]
    most_exposed_risky_dependencies: List[AggregatedDependency]
    riskiest_repositories: List[RepositoryRiskSummary]
    high_risk_dependency_count: int
    high_risk_exposed_repository_count: int
    headline: str
    warnings: List[str] = field(default_factory=list)


class DependencyProfiler:
    """Protocol-like base class for dependency profiling adapters."""

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Analyze and score unique dependencies."""
        raise NotImplementedError


def risk_rank(risk_level: RiskLevel) -> int:
    """Return sort priority for risk levels, worst first."""
    ranks = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.UNKNOWN: 4,
    }
    return ranks[risk_level]


def risk_points(risk_level: RiskLevel) -> int:
    """Return repository aggregate points for a dependency risk level."""
    points = {
        RiskLevel.CRITICAL: 20,
        RiskLevel.HIGH: 10,
        RiskLevel.MEDIUM: 4,
        RiskLevel.LOW: 1,
        RiskLevel.UNKNOWN: 0,
    }
    return points[risk_level]
