"""Data models for dependency risk profiling."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set


class RiskLevel(Enum):
    """Risk level classification for dependencies."""

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
    fork_count: Optional[int] = None  # Fork count
    contributor_count: Optional[int] = None  # Total contributors
    open_issues_count: Optional[int] = None  # Open issues
    closed_issues_count: Optional[int] = None  # Closed issues
    issue_close_time_days: Optional[float] = None  # Average days to close issues
    commit_frequency: Optional[float] = None  # Commits per month
    last_release_date: Optional[datetime] = None  # Date of last release
    releases_count: Optional[int] = None  # Number of releases
    downloads_count: Optional[int] = None  # Number of downloads
    dependent_repos_count: Optional[int] = None  # Number of dependent repositories


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

    # Vulnerability metrics
    vulnerability_count: Optional[int] = None  # Number of known vulnerabilities
    fixed_vulnerability_count: Optional[int] = None  # Number of fixed vulnerabilities
    max_cvss_score: Optional[float] = None  # Maximum CVSS score of vulnerabilities
    average_time_to_fix_days: Optional[float] = (
        None  # Average days to fix vulnerabilities
    )
    has_recent_security_update: Optional[bool] = (
        None  # Whether there was a recent security update
    )


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

    additional_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class DependencyRiskScore:
    """Risk score for a dependency."""

    dependency: DependencyMetadata
    staleness_score: float = 0.0
    maintainer_score: float = 0.0
    deprecation_score: float = 0.0
    exploit_score: float = 0.0
    version_score: float = 0.0
    health_indicators_score: float = 0.0

    # Enhanced risk scores
    license_score: float = 0.0
    community_score: float = 0.0
    transitive_score: float = 0.0

    # OpenSSF Scorecard-inspired risk scores
    security_policy_score: float = 0.0
    dependency_update_score: float = 0.0
    signed_commits_score: float = 0.0
    branch_protection_score: float = 0.0

    total_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    factors: List[str] = field(default_factory=list)


@dataclass
class ProjectRiskProfile:
    """Overall risk profile for a project."""

    manifest_path: str
    ecosystem: str
    dependencies: List[DependencyRiskScore] = field(default_factory=list)
    high_risk_dependencies: int = 0
    medium_risk_dependencies: int = 0
    low_risk_dependencies: int = 0
    overall_risk_score: float = 0.0
    scan_time: datetime = field(default_factory=datetime.now)
