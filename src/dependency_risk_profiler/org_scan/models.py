"""Typed models for organization-wide dependency risk scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Literal, Protocol, Set, Tuple

from ..models import DependencyMetadata, DependencyRiskScore, RiskLevel

AccountType = Literal["organization", "user"]

_CANONICAL_ECOSYSTEM_ALIASES = {
    "pyproject": "python",
    # A Gradle build declares Maven coordinates, and the Maven analyzer stamps
    # every one of them "maven". Without this row the OSV prewarm would write
    # under "gradle" and the profiling read would look under "maven", so the
    # prewarm would buy nothing and every Gradle dependency would re-query OSV
    # — #116's failure, which test_prewarm_ecosystem_key exists to catch (#101).
    "gradle": "maven",
}


def canonical_ecosystem(raw: str) -> str:
    """Return the package-identity ecosystem for report aggregation."""
    normalized = raw.lower().strip()
    return _CANONICAL_ECOSYSTEM_ALIASES.get(normalized, normalized)


@dataclass(frozen=True)
class DependencyKey:
    """Stable identity for a dependency profile reused across repositories."""

    # ``display_name`` used to live here and was serialized into the org JSON.
    # It was ``f"{ecosystem}:{name}@{version}"`` over three fields already in
    # the payload, so schema v2 deleted it; the reports format their own label.
    ecosystem: str
    name: str
    version: str


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
    # ``key_signals`` used to live here: a third hand-maintained
    # English-string generator over the same scores ``risk_score.factors``
    # already describes, serialized as its own contract field. Deleted in
    # schema v2; the reports render the scorer's factors instead.
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
    def is_known_vulnerable(self) -> bool:
        """Whether the installed version has scored (counted) advisories.

        This is deliberately ORTHOGONAL to ``risk_level``: the risk level is
        maintenance/leading-indicator driven, while this flags concrete known
        exposure in the shipped version, so a well-maintained dependency pinned
        to a vulnerable version reads as "MEDIUM risk, but known-vulnerable".
        """
        metrics = self.risk_score.dependency.security_metrics
        if metrics is None:
            return False
        return bool(metrics.counted_vulnerability_count)

    @property
    def is_unscored(self) -> bool:
        """Whether the scan could not produce a confident risk level.

        Counting these matters for honest reporting: the high-risk count is
        systematically depressed when coverage is poor, because a dependency
        that cannot be scored at all cannot score HIGH. Reporting the unscored
        population alongside the risk counts is what lets a reader tell "clean"
        apart from "we measured almost nothing" (#133).
        """
        return self.risk_level == RiskLevel.UNKNOWN or self.risk_score.insufficient_data

    @property
    def version_specs_list(self) -> List[str]:
        """Return all seen version specs in deterministic display order.

        Kept when its display-string sibling was deleted: this is the set of
        raw specifiers the manifests actually declared, and no amount of
        formatting reconstructs it from one resolved version.

        Returns:
            The observed specs, range-like ones first.
        """
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
    # Reported alongside the high-risk count so neither number can be read
    # alone. See `AggregatedDependency.is_unscored` and #133.
    known_vulnerable_dependency_count: int = 0
    unscored_dependency_count: int = 0


def build_headline(
    known_vulnerable_count: int,
    high_risk_count: int,
    unscored_count: int,
    dependency_count: int,
    repository_count: int,
) -> str:
    """Compose the org-scan headline from both risk axes plus coverage.

    Ordered by what demands action: known-vulnerable first (there is a fix and
    a version to move to), then high-risk leading indicators, then the coverage
    caveat, then the totals that give all three a denominator.
    """
    parts = [
        f"{known_vulnerable_count} known-vulnerable",
        f"{high_risk_count} high-risk",
    ]
    if unscored_count:
        parts.append(f"{unscored_count} could not be scored")
    parts.append(
        f"{dependency_count} {_plural(dependency_count, 'dependency')} across "
        f"{repository_count} {_plural(repository_count, 'repo')}"
    )
    return " · ".join(parts)


def _plural(count: int, singular: str) -> str:
    """Return a count-aware noun without the count."""
    if count == 1:
        return singular
    if singular.endswith("y"):
        return f"{singular[:-1]}ies"
    return f"{singular}s"


class DependencyProfiler(Protocol):
    """Structural protocol for dependency profiling adapters.

    This was a plain nominal base class whose docstring claimed to be a
    protocol, the same defect #153 fixed in ``GitHubDiscoveryClient``. Both
    real implementations already inherit explicitly, so making the claim true
    costs nothing at runtime and lets fixtures satisfy it by shape.
    """

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
