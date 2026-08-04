"""Data models for dependency risk profiling."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set

from .signals import Measurement, SourceRepositoryState


class RiskLevel(Enum):
    """Risk level classification for dependencies."""

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class LicenseCategory(Enum):
    """License categories for risk assessment."""

    PERMISSIVE = "PERMISSIVE"  # MIT, BSD, Apache, etc.
    COPYLEFT = "COPYLEFT"  # GPL, LGPL, etc.
    NETWORK_COPYLEFT = "NETWORK_COPYLEFT"  # AGPL, etc.
    COMMERCIAL = "COMMERCIAL"  # Proprietary licenses
    UNKNOWN = "UNKNOWN"  # Unrecognized or custom licenses


@dataclass
class LicenseInfo:
    """License information for a dependency."""

    license_id: str  # SPDX ID or license name
    category: LicenseCategory  # License category
    is_approved: Optional[bool] = None  # Whether this license is approved by org policy
    url: Optional[str] = None  # URL to license text
    risk_level: RiskLevel = RiskLevel.LOW  # Risk level for this license


@dataclass
class CommunityMetrics:
    """Community health metrics for a dependency."""

    star_count: Optional[int] = None  # GitHub stars or equivalent
    contributor_count: Optional[int] = None  # Total contributors
    # Commits per month over the trailing six months, read from a clone in the
    # analyze path and from the GitHub commits API in org scans. None means
    # nobody could look, and the scorer reports that rather than guessing (#166).
    commit_frequency: Optional[float] = None
    last_release_date: Optional[datetime] = None  # Date of last release
    # Publication date of the *installed* version. Paired with last_release_date
    # this measures elapsed-time drift for calendar-versioned packages, where
    # component distance carries no compatibility meaning (#126).
    installed_release_date: Optional[datetime] = None


@dataclass
class SecurityMetrics:
    """Security metrics for a dependency."""

    # OpenSSF Scorecard-inspired metrics
    has_security_policy: Optional[bool] = None  # Whether repo has a security policy
    has_dependency_update_tools: Optional[bool] = (
        None  # Whether repo uses dependency update tools
    )
    has_signed_commits: Optional[bool] = (
        None  # Whether repo uses signed commits/releases
    )
    has_branch_protection: Optional[bool] = None  # Whether repo uses branch protection
    is_maintained: Optional[bool] = None  # Whether repo is actively maintained

    # Vulnerability metrics
    vulnerability_count: Optional[int] = None  # Number of known vulnerabilities
    max_cvss_score: Optional[float] = None  # Maximum CVSS score of vulnerabilities
    counted_vulnerability_count: Optional[int] = None
    filtered_vulnerability_count: Optional[int] = None
    filtered_vulnerability_reasons: Dict[str, int] = field(default_factory=dict)
    # Counted advisories whose applicability to the installed version could not
    # be decided, with the reasons why. Reported rather than assumed away (#61).
    applicability_unknown_count: Optional[int] = None
    applicability_unknown_reasons: Dict[str, int] = field(default_factory=dict)
    max_vulnerability_severity: Optional[str] = None
    vulnerability_details: List[Dict[str, object]] = field(default_factory=list)


@dataclass
class DependencyMetadata:
    """Metadata for a dependency."""

    name: str
    installed_version: str
    latest_version: Optional[str] = None
    last_updated: Optional[datetime] = None
    maintainer_count: Optional[int] = None
    is_deprecated: bool = False
    has_known_exploits: bool = False
    repository_url: Optional[str] = None
    has_tests: Optional[bool] = None
    has_ci: Optional[bool] = None
    has_contribution_guidelines: Optional[bool] = None

    # Enhanced metadata fields
    license_info: Optional[LicenseInfo] = None
    community_metrics: Optional[CommunityMetrics] = None
    security_metrics: Optional[SecurityMetrics] = None
    transitive_dependencies: Set[str] = field(default_factory=set)

    # Measurement states, typed. Both used to be stringly-typed entries in
    # ``additional_info``, where nothing stopped a typo from silently reading
    # as "unmeasured" and mypy could not see them at all (#164).
    #
    # What the registry said about the source repository. None means the lookup
    # did not happen or did not answer — unmeasured, and never a negative
    # finding (#182). Written only by ``release_dates.record_source_repository``.
    source_repository_state: Optional[SourceRepositoryState] = None
    # How this dependency's transitive set was established, so the scorer can
    # tell "resolved, and it is empty" from "never resolved". Written only by
    # ``transitive.analyzer_enhanced.record_transitive_source``, and read only
    # through ``signals.transitive_is_measured``, which fails closed: None here
    # means nobody resolved this tree, not that someone resolved it and found
    # nothing (#199).
    transitive_source: Optional[str] = None

    additional_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class DependencyRiskScore:
    """Risk score for a dependency."""

    dependency: DependencyMetadata
    staleness_score: Optional[float] = None
    maintainer_score: Optional[float] = None
    deprecation_score: Optional[float] = None
    exploit_score: Optional[float] = None
    version_score: Optional[float] = None
    health_indicators_score: Optional[float] = None

    # Enhanced risk scores
    license_score: Optional[float] = None
    community_score: Optional[float] = None
    transitive_score: Optional[float] = None
    # Whether the registry declares a source repository at all. None when the
    # ecosystem's adapter reports nothing either way (#146).
    source_repository_score: Optional[float] = None

    # OpenSSF Scorecard-inspired risk scores
    security_policy_score: Optional[float] = None
    dependency_update_score: Optional[float] = None
    signed_commits_score: Optional[float] = None
    branch_protection_score: Optional[float] = None
    maintained_score: Optional[float] = None

    total_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    factors: List[str] = field(default_factory=list)
    unknown_signals: List[str] = field(default_factory=list)
    measured_signal_count: int = 0
    total_signal_count: int = 0
    insufficient_data: bool = False

    # Every signal by its stable name, as a MEASURED value or an UNMEASURED
    # reason (#198). The distinction used to stop at the scorer: both JSON
    # writers flattened it to a bare ``null``, which a consumer cannot tell
    # from "measured, and the answer happens to be null". Surfacing it is #164
    # step 5. Keyed by the names in ``signals.SIGNAL_CATALOG``.
    measurements: Dict[str, Measurement] = field(default_factory=dict)

    @property
    def unknown_signal_count(self) -> int:
        """Return how many signals came back unmeasured.

        A property rather than a stored field: it is ``len(unknown_signals)``
        and always was, so storing it only created a second thing that could
        disagree with the first. Not serialized in schema v2; the frozen v1
        writer still emits it.

        Returns:
            The number of unmeasured signals.
        """
        return len(self.unknown_signals)


@dataclass
class ProjectRiskProfile:
    """Overall risk profile for a project."""

    manifest_path: str
    ecosystem: str
    dependencies: List[DependencyRiskScore] = field(default_factory=list)
    high_risk_dependencies: int = 0
    medium_risk_dependencies: int = 0
    low_risk_dependencies: int = 0
    unknown_risk_dependencies: int = 0
    insufficient_data_dependencies: int = 0
    unknown_signal_count: int = 0
    overall_risk_score: float = 0.0
    scan_time: datetime = field(default_factory=datetime.now)
