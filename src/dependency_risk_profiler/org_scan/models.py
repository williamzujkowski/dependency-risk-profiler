"""Typed models for organization-wide dependency risk scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Literal, Optional, Protocol, Set, Tuple

from ..models import DependencyMetadata, DependencyRiskScore, RiskLevel
from ..parsers.version_sources import VERSION_SOURCE_UNMANAGED

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


@dataclass(frozen=True)
class RepositoryManifestListing:
    """What one repository's tree listing contains, split by whether we read it.

    One request produces all three fields. ``unreadable`` is not an afterthought
    to ``supported``: a repository whose tree holds only ``package.json`` used to
    return an empty list here, which the scanner could not tell apart from a
    repository holding no manifests at all (#262). No field has a default, so a
    client cannot answer only the reassuring half.
    """

    # Paths the tool fetches and parses.
    supported: List[str]
    # Paths recognized as dependency manifests this tool does not read. Never
    # fetched — recognition is by file name — so this costs no extra request.
    unreadable: List[str]
    # Whether GitHub truncated the tree, making both lists above a prefix of
    # some unknown larger set. Required and undefaulted for the same reason
    # ``unreadable`` is: a caller that answers "here is what I found" without
    # answering "did I see all of it" is asserting completeness it does not
    # have. GitHub used to say this only to the log (#266).
    truncated: bool


@dataclass
class ManifestParseFailure:
    """A manifest that could not be parsed."""

    repo_full_name: str
    path: str
    reason: str


@dataclass(frozen=True)
class UnreadableManifestRef:
    """A dependency manifest an org scan recognized and did not read.

    Field names match ``analyze``'s ``unreadable_manifests[]`` (#243/#264) so
    one consumer parses both paths; ``repo_full_name`` is the org dimension
    ``analyze`` has no equivalent for.

    This is deliberately *not* a :class:`ManifestParseFailure`. That records a
    manifest that was fetched and then refused, which is a different fact about
    a different byte stream: these were never fetched, because their names are
    enough to know the parsers cannot use them.
    """

    repo_full_name: str
    path: str
    ecosystem: str
    guidance: str

    @property
    def display_path(self) -> str:
        """Return a repository-qualified manifest path."""
        return f"{self.repo_full_name}:{self.path}"


class RepositoryCoverage(Enum):
    """How much of one repository an org scan actually managed to read.

    The failing states used to be one indistinguishable output: a repository
    that could not be listed, one whose only manifests were unreadable, and one
    that genuinely declares no dependencies all appeared as a summary with
    ``dependency_count: 0`` and no worst dependencies (#262). Only one of those
    is good news.
    """

    #: Every recognized manifest was fetched and parsed. A zero here is a real
    #: zero: the repository declares no dependencies.
    READ = "read"
    #: At least one manifest was read and at least one was not, so this
    #: repository's dependency count is a floor rather than a total.
    PARTIALLY_READ = "partially_read"
    #: GitHub truncated the git tree, so the manifest list is a prefix of an
    #: unknown larger set and everything below is a claim about that prefix
    #: only.
    #:
    #: Distinct from ``PARTIALLY_READ`` on purpose, and the difference is what
    #: a consumer can do next. ``PARTIALLY_READ`` names every manifest it did
    #: not read, in ``unreadable_manifests[]``, each with a remedy: generate
    #: the lock file and the gap closes. Here the unread manifests have no
    #: names, because they were never listed. It is also not the same shape:
    #: a truncated repository may have read every manifest it was shown, so
    #: "at least one was read and at least one was not" is not even true of it.
    #:
    #: It outranks every state below and is outranked only by
    #: ``DISCOVERY_FAILED``, so "this repository's dependency list is a prefix"
    #: is exactly one comparison for a consumer. The per-manifest facts are not
    #: lost to that: ``unreadable_manifests[]`` and ``parse_failures[]`` still
    #: carry everything the prefix contained.
    PARTIALLY_LISTED = "partially_listed"
    #: Dependency manifests were found and none of them could be read. The
    #: scan measured nothing here.
    UNREADABLE = "unreadable"
    #: The tree was listed and holds no manifest this tool recognizes at all.
    NO_MANIFESTS = "no_manifests"
    #: The tree could not be listed, so nothing is known about the contents.
    DISCOVERY_FAILED = "discovery_failed"

    @property
    def is_complete(self) -> bool:
        """Whether the scan read everything it recognized in this repository."""
        return self is RepositoryCoverage.READ


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

        A variant whose version could not be resolved contributes the empty
        string, which joined into ``", 3.1.6"`` and read as a formatting bug.
        It is rendered with the word the rest of the tool already uses for it —
        NuGet's unreachable ``Directory.Packages.props``, Maven's inherited
        versions and, since #275, a Python requirement that states a bound
        rather than a pin all arrive here the same way.

        Returns:
            The observed specs, range-like ones first.
        """
        if not self.version_specs:
            return [self.key.version or VERSION_SOURCE_UNMANAGED]
        return sorted(
            (spec or VERSION_SOURCE_UNMANAGED for spec in self.version_specs),
            key=_version_spec_sort_key,
        )


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
    # The denominator of ``average_risk_score``, required so the mean and the
    # population it covers cannot be reported apart (#276). ``dependency_count``
    # is the population; this is how much of it the scan could score.
    scored_dependency_count: int
    critical_risk_dependencies: int
    high_risk_dependencies: int
    medium_risk_dependencies: int
    unknown_risk_dependencies: int
    risk_points: int
    # ``None``, not ``0.0``, when nothing in this repository could be scored.
    # An unscorable dependency leaves both halves of the mean, exactly as an
    # unmeasured signal leaves both halves of a dependency's score (#74/#276).
    average_risk_score: Optional[float]
    worst_dependencies: List[AggregatedDependency]
    # Required, and last, so every construction has to answer it. A summary
    # that omitted it would default to the reassuring state, which is the
    # defect (#262, AGENTS.md rule 4).
    coverage: RepositoryCoverage


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
    # Recognized dependency manifests the scan did not read. Required and
    # undefaulted: empty means "everything recognized was read", and that is a
    # claim a caller has to make on purpose (#262).
    unreadable_manifests: List[UnreadableManifestRef]
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
    unread_repository_count: int,
    partially_listed_repository_count: int,
    dependency_count: int,
    repository_count: int,
) -> str:
    """Compose the org-scan headline from both risk axes plus coverage.

    Ordered by what demands action: known-vulnerable first (there is a fix and
    a version to move to), then high-risk leading indicators, then the coverage
    caveats, then the totals that give all three a denominator.

    Both coverage caveats sit next to each other on purpose. "Could not be
    scored" is about a dependency the scan found and could not profile;
    "could not be read" is about a repository whose dependencies the scan never
    saw at all. Reporting only the first leaves the second looking like a
    repository with nothing in it (#262).

    Args:
        known_vulnerable_count: Dependencies with scored advisories.
        high_risk_count: Dependencies at HIGH or CRITICAL.
        unscored_count: Dependencies found but not scorable.
        unread_repository_count: Repositories the scan could not read, whether
            because their manifests are unreadable or the tree never listed.
        partially_listed_repository_count: Repositories whose git tree GitHub
            truncated, so their dependency list is a prefix.
        dependency_count: Unique dependencies in the inventory.
        repository_count: Repositories the scan was asked to cover.

    Returns:
        The single-line headline.
    """
    parts = [
        f"{known_vulnerable_count} known-vulnerable",
        f"{high_risk_count} high-risk",
    ]
    if unscored_count:
        parts.append(f"{unscored_count} could not be scored")
    if unread_repository_count:
        parts.append(
            f"{unread_repository_count} "
            f"{_plural(unread_repository_count, 'repo')} could not be read"
        )
    # A third coverage caveat, kept apart from "could not be read" for the same
    # reason that one was kept apart from "could not be scored": this is a
    # repository the scan read part of and cannot say how much of (#266).
    if partially_listed_repository_count:
        parts.append(
            f"{partially_listed_repository_count} "
            f"{_plural(partially_listed_repository_count, 'repo')} "
            "listed only in part"
        )
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
