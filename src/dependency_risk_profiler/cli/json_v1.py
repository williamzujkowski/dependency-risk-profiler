"""The frozen schema-v1 JSON writer for ``analyze``. Do not change this file.

``--schema v1`` routes here. This is the pre-unification writer, lifted out of
``cli/formatter.py`` **verbatim** so that a v1 payload is byte-identical to what
the previous release emitted, and so that nobody has to keep two writers in
sync as v2 evolves. It is deliberately self-contained: it computes what it
needs rather than importing helpers that v2 is free to change underneath it.

It is removed in ``contract.SCHEMA_V1_REMOVAL_VERSION``. Until then the only
acceptable edits are ones that keep the bytes identical.

Its known defects are the reason v2 exists and are **not** fixed here:

* licence and community facts are computed by the run and never serialized;
* the advisory list is emitted twice, under ``vulnerability_summary.advisories``
  and again under ``vulnerabilities``;
* an unmeasured signal is flattened to a bare ``null``, indistinguishable from
  a measured null.
"""

import json
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from ..models import DependencyRiskScore, ProjectRiskProfile


class JsonFormatterV1:
    """Schema-v1 JSON output formatter. Frozen."""

    def format_profile(self, profile: ProjectRiskProfile) -> str:
        """Format a project risk profile as JSON.

        Args:
            profile: Project risk profile.

        Returns:
            JSON formatted profile.
        """
        return json.dumps(
            self._profile_dict(profile), indent=2, default=self._json_serializer
        )

    def format_report(
        self,
        profiles: List[ProjectRiskProfile],
        manifest_path: str,
        warnings: List[str],
    ) -> str:
        """Format a whole analyze run as exactly one JSON document.

        Args:
            profiles: Successfully analyzed manifest profiles, possibly empty.
            manifest_path: The path the user actually pointed the tool at.
            warnings: Human-readable notes about skipped or refused inputs.

        Returns:
            A single JSON document.
        """
        report = self._report_dict(profiles, manifest_path)
        report["manifests"] = [
            {
                "manifest_path": profile.manifest_path,
                "ecosystem": profile.ecosystem,
                "dependency_count": len(profile.dependencies),
                "overall_risk_score": profile.overall_risk_score,
            }
            for profile in profiles
        ]
        report["warnings"] = list(warnings)
        return json.dumps(report, indent=2, default=self._json_serializer)

    def _report_dict(
        self, profiles: List[ProjectRiskProfile], manifest_path: str
    ) -> Dict[str, object]:
        """Build the top-level report body for zero, one, or many profiles.

        Args:
            profiles: Successfully analyzed manifest profiles.
            manifest_path: The path the user pointed the tool at.

        Returns:
            The report body.
        """
        if len(profiles) == 1:
            return self._profile_dict(profiles[0])
        if not profiles:
            return {
                "manifest_path": manifest_path,
                "ecosystem": None,
                "scan_time": datetime.now().isoformat(),
                "dependency_count": 0,
                "high_risk_dependencies": 0,
                "medium_risk_dependencies": 0,
                "low_risk_dependencies": 0,
                "unknown_risk_dependencies": 0,
                "insufficient_data_dependencies": 0,
                "unknown_signal_count": 0,
                "overall_risk_score": None,
                "dependencies": [],
            }
        return self._merged_dict(profiles, manifest_path)

    def _merged_dict(
        self, profiles: List[ProjectRiskProfile], manifest_path: str
    ) -> Dict[str, object]:
        """Merge several manifest profiles into one document.

        Args:
            profiles: Successfully analyzed manifest profiles.
            manifest_path: The path the user pointed the tool at.

        Returns:
            The merged report body.
        """
        dependencies = [dep for profile in profiles for dep in profile.dependencies]
        ecosystems = {profile.ecosystem for profile in profiles}
        total = len(dependencies)
        if total:
            weighted = sum(
                profile.overall_risk_score * len(profile.dependencies)
                for profile in profiles
            )
            overall: Optional[float] = weighted / total
        else:
            overall = None
        return {
            "manifest_path": manifest_path,
            "ecosystem": ecosystems.pop() if len(ecosystems) == 1 else None,
            "scan_time": max(profile.scan_time for profile in profiles).isoformat(),
            "dependency_count": total,
            "high_risk_dependencies": sum(
                profile.high_risk_dependencies for profile in profiles
            ),
            "medium_risk_dependencies": sum(
                profile.medium_risk_dependencies for profile in profiles
            ),
            "low_risk_dependencies": sum(
                profile.low_risk_dependencies for profile in profiles
            ),
            "unknown_risk_dependencies": sum(
                profile.unknown_risk_dependencies for profile in profiles
            ),
            "insufficient_data_dependencies": sum(
                profile.insufficient_data_dependencies for profile in profiles
            ),
            "unknown_signal_count": sum(
                profile.unknown_signal_count for profile in profiles
            ),
            "overall_risk_score": overall,
            "dependencies": [self._format_dependency(dep) for dep in dependencies],
        }

    def _profile_dict(self, profile: ProjectRiskProfile) -> Dict[str, object]:
        """Serialize one manifest profile.

        Args:
            profile: Project risk profile.

        Returns:
            The serialized profile.
        """
        return {
            "manifest_path": profile.manifest_path,
            "ecosystem": profile.ecosystem,
            "scan_time": profile.scan_time.isoformat(),
            "dependency_count": len(profile.dependencies),
            "high_risk_dependencies": profile.high_risk_dependencies,
            "medium_risk_dependencies": profile.medium_risk_dependencies,
            "low_risk_dependencies": profile.low_risk_dependencies,
            "unknown_risk_dependencies": profile.unknown_risk_dependencies,
            "insufficient_data_dependencies": profile.insufficient_data_dependencies,
            "unknown_signal_count": profile.unknown_signal_count,
            "overall_risk_score": profile.overall_risk_score,
            "dependencies": [
                self._format_dependency(dep) for dep in profile.dependencies
            ],
        }

    def _json_serializer(self, obj: object) -> object:
        """Serialize objects not serializable by default.

        Args:
            obj: Object to serialize.

        Returns:
            Serialized object.

        Raises:
            TypeError: If the object has no supported serialization.
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        raise TypeError(f"Type {type(obj)} not serializable")

    def _format_dependency(self, dep: DependencyRiskScore) -> Dict[str, object]:
        """Format dependency risk score as dict.

        Args:
            dep: Dependency risk score.

        Returns:
            Dictionary representation of the dependency risk score.
        """
        metadata = dep.dependency
        vulnerability_summary = self._format_vulnerability_details(dep)

        return {
            "name": metadata.name,
            "installed_version": metadata.installed_version,
            "latest_version": metadata.latest_version,
            "last_updated": (
                metadata.last_updated.isoformat() if metadata.last_updated else None
            ),
            "maintainer_count": metadata.maintainer_count,
            "is_deprecated": metadata.is_deprecated,
            "has_known_exploits": metadata.has_known_exploits,
            "repository_url": metadata.repository_url,
            "has_tests": metadata.has_tests,
            "has_ci": metadata.has_ci,
            "has_contribution_guidelines": metadata.has_contribution_guidelines,
            "vulnerability_summary": vulnerability_summary,
            "vulnerabilities": vulnerability_summary["advisories"],
            "scores": {
                "staleness_score": dep.staleness_score,
                "maintainer_score": dep.maintainer_score,
                "deprecation_score": dep.deprecation_score,
                "exploit_score": dep.exploit_score,
                "version_score": dep.version_score,
                "health_indicators_score": dep.health_indicators_score,
                "license_score": dep.license_score,
                "community_score": dep.community_score,
                "transitive_score": dep.transitive_score,
                "source_repository_score": dep.source_repository_score,
                "security_policy_score": dep.security_policy_score,
                "dependency_update_score": dep.dependency_update_score,
                "signed_commits_score": dep.signed_commits_score,
                "branch_protection_score": dep.branch_protection_score,
                "maintained_score": dep.maintained_score,
                "total_score": dep.total_score,
            },
            "risk_level": dep.risk_level.value,
            "unknown_signals": dep.unknown_signals,
            "unknown_signal_count": dep.unknown_signal_count,
            "measured_signal_count": dep.measured_signal_count,
            "total_signal_count": dep.total_signal_count,
            "insufficient_data": dep.insufficient_data,
            "risk_factors": dep.factors,
        }

    def _format_vulnerability_details(
        self, dep: DependencyRiskScore
    ) -> Dict[str, object]:
        """Format vulnerability accounting and advisory details for JSON output.

        Args:
            dep: Dependency risk score.

        Returns:
            Vulnerability summary dictionary.
        """
        metrics = dep.dependency.security_metrics
        if metrics is None:
            return {
                "total_found": None,
                "counted_in_score": None,
                "filtered": None,
                "filtered_reasons": {},
                "applicability_unknown": None,
                "applicability_unknown_reasons": {},
                "max_counted_cvss_score": None,
                "max_counted_severity": None,
                "advisories": [],
            }

        return {
            "total_found": metrics.vulnerability_count,
            "counted_in_score": metrics.counted_vulnerability_count,
            "filtered": metrics.filtered_vulnerability_count,
            "filtered_reasons": metrics.filtered_vulnerability_reasons,
            "applicability_unknown": metrics.applicability_unknown_count,
            "applicability_unknown_reasons": metrics.applicability_unknown_reasons,
            "max_counted_cvss_score": metrics.max_cvss_score,
            "max_counted_severity": metrics.max_vulnerability_severity,
            "advisories": metrics.vulnerability_details,
        }
