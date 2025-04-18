"""Risk scoring for dependencies."""

import logging
from datetime import datetime
from typing import Dict, List

from packaging import version

from ..models import (
    DependencyMetadata,
    DependencyRiskScore,
    ProjectRiskProfile,
    RiskLevel,
)

logger = logging.getLogger(__name__)


class RiskScorer:
    """Scores dependencies based on various risk factors."""

    def __init__(
        self,
        staleness_weight: float = 0.25,
        maintainer_weight: float = 0.2,
        deprecation_weight: float = 0.3,
        exploit_weight: float = 0.5,
        version_difference_weight: float = 0.15,
        health_indicators_weight: float = 0.1,
        # Enhanced risk factors
        license_weight: float = 0.3,
        community_weight: float = 0.2,
        transitive_weight: float = 0.15,
        # OpenSSF Scorecard-inspired risk factors
        security_policy_weight: float = 0.25,
        dependency_update_weight: float = 0.2,
        signed_commits_weight: float = 0.2,
        branch_protection_weight: float = 0.15,
        max_score: float = 5.0,
    ):
        """Initialize the risk scorer with customizable weights.

        Args:
            staleness_weight: Weight for staleness score.
            maintainer_weight: Weight for maintainer count score.
            deprecation_weight: Weight for deprecation score.
            exploit_weight: Weight for known exploits score.
            version_difference_weight: Weight for version difference score.
            health_indicators_weight: Weight for health indicators score.
            license_weight: Weight for license risk score.
            community_weight: Weight for community health risk score.
            transitive_weight: Weight for transitive dependency risk score.
            security_policy_weight: Weight for security policy risk score.
            dependency_update_weight: Weight for dependency update tools risk score.
            max_score: Maximum risk score.
        """
        self.staleness_weight = staleness_weight
        self.maintainer_weight = maintainer_weight
        self.deprecation_weight = deprecation_weight
        self.exploit_weight = exploit_weight
        self.version_difference_weight = version_difference_weight
        self.health_indicators_weight = health_indicators_weight

        # Enhanced risk factors
        self.license_weight = license_weight
        self.community_weight = community_weight
        self.transitive_weight = transitive_weight
        self.security_policy_weight = security_policy_weight
        self.dependency_update_weight = dependency_update_weight
        self.signed_commits_weight = signed_commits_weight
        self.branch_protection_weight = branch_protection_weight

        self.max_score = max_score

        # Risk level thresholds (as a percentage of max_score)
        self.risk_thresholds = {
            RiskLevel.LOW: 0.25,  # 0% - 25%
            RiskLevel.MEDIUM: 0.5,  # 25% - 50%
            RiskLevel.HIGH: 0.75,  # 50% - 75%
            RiskLevel.CRITICAL: 1.0,  # 75% - 100%
        }

    def score_dependency(self, dependency: DependencyMetadata) -> DependencyRiskScore:
        """Score a dependency based on its metadata.

        Args:
            dependency: Dependency metadata to score.

        Returns:
            Risk score for the dependency.
        """
        staleness_score = self._calculate_staleness_score(dependency.last_updated)
        maintainer_score = self._calculate_maintainer_score(dependency.maintainer_count)
        deprecation_score = self._calculate_deprecation_score(dependency.is_deprecated)
        exploit_score = self._calculate_exploit_score(dependency.has_known_exploits)
        version_score = self._calculate_version_difference_score(
            dependency.installed_version, dependency.latest_version
        )
        health_score = self._calculate_health_indicators_score(
            dependency.has_tests,
            dependency.has_ci,
            dependency.has_contribution_guidelines,
        )

        # Enhanced risk scores
        license_score = self._calculate_license_score(dependency.license_info)
        community_score = self._calculate_community_score(dependency.community_metrics)
        transitive_score = self._calculate_transitive_score(
            dependency.transitive_dependencies
        )

        # OpenSSF Scorecard-inspired risk scores
        security_policy_score = self._calculate_security_policy_score(
            dependency.security_metrics
        )
        dependency_update_score = self._calculate_dependency_update_score(
            dependency.security_metrics
        )
        signed_commits_score = self._calculate_signed_commits_score(
            dependency.security_metrics
        )
        branch_protection_score = self._calculate_branch_protection_score(
            dependency.security_metrics
        )

        # Calculate weighted score
        weighted_scores = [
            (staleness_score, self.staleness_weight),
            (maintainer_score, self.maintainer_weight),
            (deprecation_score, self.deprecation_weight),
            (exploit_score, self.exploit_weight),
            (version_score, self.version_difference_weight),
            (health_score, self.health_indicators_weight),
            # Enhanced risk factors
            (
                (license_score, self.license_weight)
                if license_score is not None
                else (None, 0)
            ),
            (
                (community_score, self.community_weight)
                if community_score is not None
                else (None, 0)
            ),
            (
                (transitive_score, self.transitive_weight)
                if transitive_score is not None
                else (None, 0)
            ),
            (
                (security_policy_score, self.security_policy_weight)
                if security_policy_score is not None
                else (None, 0)
            ),
            (
                (dependency_update_score, self.dependency_update_weight)
                if dependency_update_score is not None
                else (None, 0)
            ),
            (
                (signed_commits_score, self.signed_commits_weight)
                if signed_commits_score is not None
                else (None, 0)
            ),
            (
                (branch_protection_score, self.branch_protection_weight)
                if branch_protection_score is not None
                else (None, 0)
            ),
        ]

        total_score = 0.0
        for score, weight in weighted_scores:
            if score is not None:  # Only count available scores
                total_score += score * weight

        # Normalize to max_score
        available_weights = sum(weight for _, weight in weighted_scores)
        if available_weights > 0:
            total_score = (total_score / available_weights) * self.max_score

        # Determine risk level
        risk_level = self._determine_risk_level(total_score)

        # Determine risk factors
        risk_factors = self._determine_risk_factors(
            dependency,
            staleness_score,
            maintainer_score,
            deprecation_score,
            exploit_score,
            version_score,
            health_score,
            license_score,
            community_score,
            transitive_score,
            security_policy_score,
            dependency_update_score,
            signed_commits_score,
            branch_protection_score,
        )

        return DependencyRiskScore(
            dependency=dependency,
            staleness_score=staleness_score or 0.0,
            maintainer_score=maintainer_score or 0.0,
            deprecation_score=deprecation_score or 0.0,
            exploit_score=exploit_score or 0.0,
            version_score=version_score or 0.0,
            health_indicators_score=health_score or 0.0,
            license_score=license_score or 0.0,
            community_score=community_score or 0.0,
            transitive_score=transitive_score or 0.0,
            security_policy_score=security_policy_score or 0.0,
            dependency_update_score=dependency_update_score or 0.0,
            signed_commits_score=signed_commits_score or 0.0,
            branch_protection_score=branch_protection_score or 0.0,
            total_score=total_score,
            risk_level=risk_level,
            factors=risk_factors,
        )

    def create_project_profile(
        self,
        manifest_path: str,
        ecosystem: str,
        dependencies: Dict[str, DependencyMetadata],
    ) -> ProjectRiskProfile:
        """Create a project risk profile from scored dependencies.

        Args:
            manifest_path: Path to the dependency manifest file.
            ecosystem: Dependency ecosystem.
            dependencies: Dictionary of dependency metadata.

        Returns:
            Project risk profile.
        """
        # Score all dependencies
        scored_dependencies = [
            self.score_dependency(dep) for dep in dependencies.values()
        ]

        # Count risk levels
        high_risk = 0
        medium_risk = 0
        low_risk = 0

        for dep in scored_dependencies:
            if dep.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                high_risk += 1
            elif dep.risk_level == RiskLevel.MEDIUM:
                medium_risk += 1
            else:
                low_risk += 1

        # Calculate overall project risk score
        if scored_dependencies:
            overall_score = sum(dep.total_score for dep in scored_dependencies) / len(
                scored_dependencies
            )
        else:
            overall_score = 0.0

        return ProjectRiskProfile(
            manifest_path=manifest_path,
            ecosystem=ecosystem,
            dependencies=scored_dependencies,
            high_risk_dependencies=high_risk,
            medium_risk_dependencies=medium_risk,
            low_risk_dependencies=low_risk,
            overall_risk_score=overall_score,
        )

    def _calculate_staleness_score(self, last_updated: datetime) -> float:
        """Calculate staleness score based on last update date.

        Args:
            last_updated: Date of last update.

        Returns:
            Staleness score between 0.0 and 1.0.
        """
        if not last_updated:
            return 0.5  # Default score when data is missing

        # Ensure both datetimes are timezone-naive for comparison
        if last_updated.tzinfo:
            # Convert timezone-aware to naive by replacing tzinfo
            last_updated = last_updated.replace(tzinfo=None)

        now = datetime.now()
        days_since_update = (now - last_updated).days

        # Scoring thresholds for staleness
        if days_since_update < 30:  # Less than a month
            return 0.0
        elif days_since_update < 90:  # 1-3 months
            return 0.25
        elif days_since_update < 180:  # 3-6 months
            return 0.5
        elif days_since_update < 365:  # 6-12 months
            return 0.75
        else:  # More than a year
            return 1.0

    def _calculate_maintainer_score(self, maintainer_count: int) -> float:
        """Calculate maintainer score based on maintainer count.

        Args:
            maintainer_count: Number of maintainers.

        Returns:
            Maintainer score between 0.0 and 1.0.
        """
        if not maintainer_count:
            return 0.5  # Default score when data is missing

        # Scoring thresholds for maintainers
        if maintainer_count >= 5:
            return 0.0
        elif maintainer_count >= 3:
            return 0.25
        elif maintainer_count == 2:
            return 0.5
        else:  # Single maintainer
            return 1.0

    def _calculate_deprecation_score(self, is_deprecated: bool) -> float:
        """Calculate deprecation score.

        Args:
            is_deprecated: Whether the dependency is deprecated.

        Returns:
            Deprecation score of 0.0 or 1.0.
        """
        return 1.0 if is_deprecated else 0.0

    def _calculate_exploit_score(self, has_known_exploits: bool) -> float:
        """Calculate exploit score.

        Args:
            has_known_exploits: Whether the dependency has known exploits.

        Returns:
            Exploit score of 0.0 or 1.0.
        """
        return 1.0 if has_known_exploits else 0.0

    def _calculate_version_difference_score(
        self, installed_version: str, latest_version: str
    ) -> float:
        """Calculate version difference score.

        Args:
            installed_version: Installed version string.
            latest_version: Latest version string.

        Returns:
            Version difference score between 0.0 and 1.0.
        """
        if not latest_version or installed_version == latest_version:
            return 0.0

        try:
            # Handle version ranges and non-standard version strings
            if any(op in installed_version for op in ["<", ">", "~", "^", "-"]):
                return 0.25  # Assume minimal risk for version ranges

            # Try to parse as standard versions
            current = version.parse(installed_version)
            latest = version.parse(latest_version)

            if current == latest:
                return 0.0

            # Handle LegacyVersion objects which don't have major, minor attributes
            if not hasattr(current, "major") or not hasattr(latest, "major"):
                # If we got LegacyVersion objects, return a moderate risk score
                if current != latest:
                    return 0.5
                return 0.0

            # Major version difference
            if latest.major > current.major:
                return 1.0

            # Minor version difference
            if latest.minor > current.minor:
                return 0.5

            # Patch version difference
            if hasattr(latest, "micro") and hasattr(current, "micro"):
                if latest.micro > current.micro:
                    return 0.25

            return 0.1  # Small difference

        except (TypeError, ValueError):
            # If we can't parse the versions, assume a moderate risk
            if installed_version != latest_version:
                return 0.5
            return 0.0

    def _calculate_health_indicators_score(
        self, has_tests: bool, has_ci: bool, has_contribution_guidelines: bool
    ) -> float:
        """Calculate health indicators score.

        Args:
            has_tests: Whether the dependency has tests.
            has_ci: Whether the dependency has CI configuration.
            has_contribution_guidelines: Whether the dependency has contribution guidelines.

        Returns:
            Health indicators score between 0.0 and 1.0.
        """
        # Skip if all indicators are None
        if has_tests is None and has_ci is None and has_contribution_guidelines is None:
            return None

        # Count available indicators
        indicators = [has_tests, has_ci, has_contribution_guidelines]
        available = sum(1 for i in indicators if i is not None)

        if available == 0:
            return 0.5  # Default score when data is missing

        # Count positive indicators
        positive = sum(1 for i in indicators if i is True)

        # Calculate score (0.0 = all positive, 1.0 = all negative)
        return 1.0 - (positive / available)

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level based on score.

        Args:
            score: Risk score.

        Returns:
            Risk level.
        """
        normalized_score = score / self.max_score

        if normalized_score < self.risk_thresholds[RiskLevel.LOW]:
            return RiskLevel.LOW
        elif normalized_score < self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif normalized_score < self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _calculate_license_score(self, license_info) -> float:
        """Calculate license risk score.

        Args:
            license_info: License information.

        Returns:
            License risk score between 0.0 and 1.0.
        """
        if not license_info:
            return 0.5  # Default score when data is missing

        # Use the risk level already calculated for the license
        if license_info.risk_level == RiskLevel.CRITICAL:
            return 1.0
        elif license_info.risk_level == RiskLevel.HIGH:
            return 0.75
        elif license_info.risk_level == RiskLevel.MEDIUM:
            return 0.5
        elif license_info.risk_level == RiskLevel.LOW:
            return 0.0
        else:
            return 0.5

    def _calculate_community_score(self, community_metrics) -> float:
        """Calculate community health risk score.

        Args:
            community_metrics: Community health metrics.

        Returns:
            Community health risk score between 0.0 and 1.0.
        """
        if not community_metrics:
            return 0.5  # Default score when data is missing

        sub_scores = []

        # Star count score (more stars = lower risk)
        if community_metrics.star_count is not None:
            if community_metrics.star_count >= 5000:
                sub_scores.append(0.0)  # Very popular project
            elif community_metrics.star_count >= 1000:
                sub_scores.append(0.25)  # Popular project
            elif community_metrics.star_count >= 100:
                sub_scores.append(0.5)  # Moderately popular
            else:
                sub_scores.append(0.75)  # Not very popular

        # Issue activity score
        if (
            community_metrics.open_issues_count is not None
            and community_metrics.closed_issues_count is not None
            and (
                community_metrics.open_issues_count
                + community_metrics.closed_issues_count
            )
            > 0
        ):

            # Calculate ratio of closed issues to total issues
            total_issues = (
                community_metrics.open_issues_count
                + community_metrics.closed_issues_count
            )
            closed_ratio = community_metrics.closed_issues_count / total_issues

            if closed_ratio >= 0.8:
                sub_scores.append(0.0)  # High issue resolution rate
            elif closed_ratio >= 0.5:
                sub_scores.append(0.25)  # Moderate issue resolution rate
            elif closed_ratio >= 0.2:
                sub_scores.append(0.5)  # Low issue resolution rate
            else:
                sub_scores.append(1.0)  # Very low issue resolution rate

        # Commit frequency score
        if community_metrics.commit_frequency is not None:
            if community_metrics.commit_frequency >= 10:
                sub_scores.append(0.0)  # Very active development
            elif community_metrics.commit_frequency >= 5:
                sub_scores.append(0.25)  # Active development
            elif community_metrics.commit_frequency >= 1:
                sub_scores.append(0.5)  # Moderate development activity
            else:
                sub_scores.append(1.0)  # Low development activity

        # Calculate final score (average of sub-scores)
        if sub_scores:
            return sum(sub_scores) / len(sub_scores)
        else:
            return 0.5  # Default score when no metrics available

    def _calculate_transitive_score(self, transitive_dependencies) -> float:
        """Calculate transitive dependency risk score.

        Args:
            transitive_dependencies: Set of transitive dependencies.

        Returns:
            Transitive dependency risk score between 0.0 and 1.0.
        """
        if not transitive_dependencies:
            return 0.0  # No transitive dependencies = no risk

        # Calculate risk based on number of transitive dependencies
        num_deps = len(transitive_dependencies)

        if num_deps >= 100:
            return 1.0  # Very high transitive dependency count
        elif num_deps >= 50:
            return 0.75  # High transitive dependency count
        elif num_deps >= 20:
            return 0.5  # Moderate transitive dependency count
        elif num_deps >= 5:
            return 0.25  # Low transitive dependency count
        else:
            return 0.1  # Very low transitive dependency count

    def _calculate_security_policy_score(self, security_metrics) -> float:
        """Calculate security policy risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Security policy risk score between 0.0 and 1.0.
        """
        if not security_metrics:
            return 0.7  # Higher default risk when security data is missing

        # If the dependency has a security policy, it's a good sign
        if security_metrics.has_security_policy is not None:
            if security_metrics.has_security_policy:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - no security policy

        # If we don't have explicit security policy data
        return 0.7  # Higher default risk when security policy status is unknown

    def _calculate_dependency_update_score(self, security_metrics) -> float:
        """Calculate dependency update tools risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Dependency update tools risk score between 0.0 and 1.0.
        """
        if not security_metrics:
            return 0.7  # Higher default risk when security data is missing

        # If the dependency uses dependency update tools, it's a good sign
        if security_metrics.has_dependency_update_tools is not None:
            if security_metrics.has_dependency_update_tools:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - no dependency update tools

        # If we don't have explicit dependency update tools data
        return 0.7  # Higher default risk when dependency update tools status is unknown

    def _calculate_signed_commits_score(self, security_metrics) -> float:
        """Calculate signed commits risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Signed commits risk score between 0.0 and 1.0.
        """
        if not security_metrics:
            return 0.7  # Higher default risk when security data is missing

        # If the dependency uses signed commits/releases, it's a good sign
        if security_metrics.has_signed_commits is not None:
            if security_metrics.has_signed_commits:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - no signed commits

        # If we don't have explicit signed commits data
        return 0.7  # Higher default risk when signed commits status is unknown

    def _calculate_branch_protection_score(self, security_metrics) -> float:
        """Calculate branch protection risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Branch protection risk score between 0.0 and 1.0.
        """
        if not security_metrics:
            return 0.7  # Higher default risk when security data is missing

        # If the dependency uses branch protection, it's a good sign
        if security_metrics.has_branch_protection is not None:
            if security_metrics.has_branch_protection:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - no branch protection

        # If we don't have explicit branch protection data
        return 0.7  # Higher default risk when branch protection status is unknown

    def _determine_risk_factors(
        self,
        dependency: DependencyMetadata,
        staleness_score: float,
        maintainer_score: float,
        deprecation_score: float,
        exploit_score: float,
        version_score: float,
        health_score: float,
        license_score: float,
        community_score: float,
        transitive_score: float,
        security_policy_score: float,
        dependency_update_score: float,
        signed_commits_score: float,
        branch_protection_score: float,
    ) -> List[str]:
        """Determine risk factors that contribute to the risk score.

        Args:
            dependency: Dependency metadata.
            staleness_score: Staleness score.
            maintainer_score: Maintainer score.
            deprecation_score: Deprecation score.
            exploit_score: Exploit score.
            version_score: Version difference score.
            health_score: Health indicators score.
            license_score: License risk score.
            community_score: Community health risk score.
            transitive_score: Transitive dependency risk score.
            security_policy_score: Security policy risk score.

        Returns:
            List of risk factors.
        """
        factors = []

        if staleness_score and staleness_score > 0.5:
            if dependency.last_updated:
                # Ensure both datetimes are timezone-naive for comparison
                last_updated = dependency.last_updated
                if last_updated.tzinfo:
                    last_updated = last_updated.replace(tzinfo=None)

                days_since_update = (datetime.now() - last_updated).days
                factors.append(f"Not updated in {days_since_update} days")
            else:
                factors.append("Update date unknown")

        if maintainer_score and maintainer_score > 0.5:
            if (
                dependency.maintainer_count is not None
                and dependency.maintainer_count < 2
            ):
                factors.append("Single maintainer")
            else:
                factors.append("Maintainer count unknown")

        if deprecation_score and deprecation_score > 0:
            factors.append("Deprecated")

        if exploit_score and exploit_score > 0:
            factors.append("Known security issues")

        if version_score and version_score > 0.5:
            factors.append(
                (
                    f"Outdated (current: {dependency.installed_version}, "
                    f"latest: {dependency.latest_version})"
                )
            )

        if health_score and health_score > 0.5:
            missing = []
            if not dependency.has_tests:
                missing.append("tests")
            if not dependency.has_ci:
                missing.append("CI")
            if not dependency.has_contribution_guidelines:
                missing.append("contribution guidelines")

            if missing:
                factors.append(f"Missing {', '.join(missing)}")

        # License risk factors
        if license_score and license_score > 0.5:
            if dependency.license_info:
                if dependency.license_info.category.value == "NETWORK_COPYLEFT":
                    factors.append(
                        f"Network copyleft license ({dependency.license_info.license_id})"
                    )
                elif dependency.license_info.category.value == "COPYLEFT":
                    factors.append(
                        f"Copyleft license ({dependency.license_info.license_id})"
                    )
                elif dependency.license_info.category.value == "COMMERCIAL":
                    factors.append(
                        f"Commercial license ({dependency.license_info.license_id})"
                    )
                elif dependency.license_info.category.value == "UNKNOWN":
                    factors.append("Unknown license")
                elif not dependency.license_info.is_approved:
                    factors.append(
                        f"Non-approved license ({dependency.license_info.license_id})"
                    )

        # Community health risk factors
        if community_score and community_score > 0.5:
            if dependency.community_metrics:
                if (
                    dependency.community_metrics.star_count is not None
                    and dependency.community_metrics.star_count < 100
                ):
                    factors.append(
                        f"Low popularity ({dependency.community_metrics.star_count} stars)"
                    )

                if (
                    dependency.community_metrics.commit_frequency is not None
                    and dependency.community_metrics.commit_frequency < 1
                ):
                    factors.append("Low development activity")

        # Transitive dependency risk factors
        if transitive_score and transitive_score > 0.5:
            if dependency.transitive_dependencies:
                factors.append(
                    f"Large dependency tree ({len(dependency.transitive_dependencies)} deps)"
                )

        # Security policy risk factors
        if security_policy_score and security_policy_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.has_security_policy is not None:
                    if not dependency.security_metrics.has_security_policy:
                        factors.append("Missing security policy")
                else:
                    factors.append("Security policy status unknown")
            else:
                factors.append("No security metadata available")

        # Dependency update tools risk factors
        if dependency_update_score and dependency_update_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.has_dependency_update_tools is not None:
                    if not dependency.security_metrics.has_dependency_update_tools:
                        factors.append("No dependency update tools found")
                else:
                    factors.append("Dependency update tools status unknown")
            else:
                factors.append("No security metadata available")

        # Signed commits risk factors
        if signed_commits_score and signed_commits_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.has_signed_commits is not None:
                    if not dependency.security_metrics.has_signed_commits:
                        factors.append("Does not use signed commits")
                else:
                    factors.append("Signed commits status unknown")
            else:
                factors.append("No security metadata available")

        # Branch protection risk factors
        if branch_protection_score and branch_protection_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.has_branch_protection is not None:
                    if not dependency.security_metrics.has_branch_protection:
                        factors.append("Does not use branch protection")
                else:
                    factors.append("Branch protection status unknown")
            else:
                factors.append("No security metadata available")

        return factors
