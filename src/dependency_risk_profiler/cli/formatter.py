"""Output formatters for the dependency risk profiler."""

import json
from datetime import datetime
from typing import Dict

from ..models import DependencyRiskScore, ProjectRiskProfile, RiskLevel


class BaseFormatter:
    """Base class for output formatters."""

    def format_profile(self, profile: ProjectRiskProfile) -> str:
        """Format a project risk profile.

        Args:
            profile: Project risk profile.

        Returns:
            Formatted profile.
        """
        raise NotImplementedError("Formatter must implement format_profile method")


class TerminalFormatter(BaseFormatter):
    """Terminal output formatter with color support."""

    # ANSI color codes
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"

    def __init__(self, color: bool = True):
        """Initialize the terminal formatter.

        Args:
            color: Whether to enable color output.
        """
        self.color = color

    def format_profile(self, profile: ProjectRiskProfile) -> str:
        """Format a project risk profile for terminal output.

        Args:
            profile: Project risk profile.

        Returns:
            Formatted profile.
        """
        result = []

        # Add header
        result.append(self._colored(f"{self.BOLD}Dependency Risk Profile{self.RESET}"))
        result.append("")
        result.append(f"Manifest: {profile.manifest_path}")
        result.append(f"Ecosystem: {profile.ecosystem}")
        result.append(f"Scan Time: {profile.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        result.append(f"Dependencies: {len(profile.dependencies)}")
        result.append("")

        # Add risk summary
        result.append(self._colored(f"{self.BOLD}Risk Summary{self.RESET}"))
        overall_risk = self._get_risk_color(profile.overall_risk_score / 5.0)
        result.append(
            f"Overall Risk Score: {self._colored(f'{profile.overall_risk_score:.2f}/5.0', overall_risk)}"
        )
        result.append(
            f"High Risk Dependencies: {self._colored(str(profile.high_risk_dependencies), self.RED)}"
        )
        result.append(
            f"Medium Risk Dependencies: {self._colored(str(profile.medium_risk_dependencies), self.YELLOW)}"
        )
        result.append(
            f"Low Risk Dependencies: {self._colored(str(profile.low_risk_dependencies), self.GREEN)}"
        )
        result.append("")

        # Add dependency table
        if profile.dependencies:
            result.append(self._colored(f"{self.BOLD}Dependency Details{self.RESET}"))
            result.append(self._format_table_header())

            # Sort dependencies by risk score (highest first)
            sorted_deps = sorted(
                profile.dependencies, key=lambda d: d.total_score, reverse=True
            )

            for dep in sorted_deps:
                result.append(self._format_dependency_row(dep))

        return "\n".join(result)

    def _colored(self, text: str, color: str = "") -> str:
        """Add color to text if color is enabled.

        Args:
            text: Text to color.
            color: ANSI color code.

        Returns:
            Colored text or original text.
        """
        if not self.color or not color:
            return text.replace(self.BOLD, "").replace(self.RESET, "")
        return f"{color}{text}{self.RESET}"

    def _get_risk_color(self, risk_factor: float) -> str:
        """Get color for risk level.

        Args:
            risk_factor: Risk factor between 0.0 and 1.0.

        Returns:
            ANSI color code.
        """
        if risk_factor >= 0.75:
            return self.RED
        elif risk_factor >= 0.5:
            return self.MAGENTA
        elif risk_factor >= 0.25:
            return self.YELLOW
        else:
            return self.GREEN

    def _get_risk_level_color(self, risk_level: RiskLevel) -> str:
        """Get color for risk level.

        Args:
            risk_level: Risk level.

        Returns:
            ANSI color code.
        """
        if risk_level == RiskLevel.CRITICAL:
            return self.RED
        elif risk_level == RiskLevel.HIGH:
            return self.MAGENTA
        elif risk_level == RiskLevel.MEDIUM:
            return self.YELLOW
        else:
            return self.GREEN

    def _format_table_header(self) -> str:
        """Format table header.

        Returns:
            Formatted table header.
        """
        header = f"{'Dependency':<30} {'Installed':<15} {'Latest':<15} {'Last Update':<15} {'Maintainers':<10} {'Risk Score':<10} {'Status':<20}"
        separator = "-" * 115
        return self._colored(f"{self.BOLD}{header}{self.RESET}\n{separator}")

    def _format_dependency_row(self, dep: DependencyRiskScore) -> str:
        """Format dependency row.

        Args:
            dep: Dependency risk score.

        Returns:
            Formatted dependency row.
        """
        metadata = dep.dependency

        # Format fields
        name = metadata.name[:28] + ".." if len(metadata.name) > 30 else metadata.name
        installed = (
            metadata.installed_version[:13] + ".."
            if len(metadata.installed_version) > 15
            else metadata.installed_version
        )
        latest = (
            metadata.latest_version[:13] + ".."
            if metadata.latest_version and len(metadata.latest_version) > 15
            else (metadata.latest_version or "Unknown")
        )

        # Format last update
        if metadata.last_updated:
            # Ensure both datetimes are timezone-naive for comparison
            last_updated = metadata.last_updated
            if last_updated.tzinfo:
                last_updated = last_updated.replace(tzinfo=None)

            if (datetime.now() - last_updated).days < 30:
                last_update = "< 1 month ago"
            else:
                months = (datetime.now() - last_updated).days // 30
                last_update = f"{months} months ago"
        else:
            last_update = "Unknown"

        # Format maintainers
        maintainers = (
            str(metadata.maintainer_count)
            if metadata.maintainer_count is not None
            else "Unknown"
        )

        # Format risk score
        risk_score = f"{dep.total_score:.1f}/5.0"

        # Format risk level and factors
        risk_level = dep.risk_level.value
        if dep.factors:
            risk_level += f" ({dep.factors[0]})"

        # Apply color
        risk_color = self._get_risk_level_color(dep.risk_level)
        risk_score = self._colored(risk_score, risk_color)
        risk_level = self._colored(risk_level, risk_color)

        return f"{name:<30} {installed:<15} {latest:<15} {last_update:<15} {maintainers:<10} {risk_score:<10} {risk_level:<20}"


class JsonFormatter(BaseFormatter):
    """JSON output formatter."""

    def format_profile(self, profile: ProjectRiskProfile) -> str:
        """Format a project risk profile as JSON.

        Args:
            profile: Project risk profile.

        Returns:
            JSON formatted profile.
        """
        # Convert profile to dict
        profile_dict = {
            "manifest_path": profile.manifest_path,
            "ecosystem": profile.ecosystem,
            "scan_time": profile.scan_time.isoformat(),
            "dependency_count": len(profile.dependencies),
            "high_risk_dependencies": profile.high_risk_dependencies,
            "medium_risk_dependencies": profile.medium_risk_dependencies,
            "low_risk_dependencies": profile.low_risk_dependencies,
            "overall_risk_score": profile.overall_risk_score,
            "dependencies": [
                self._format_dependency(dep) for dep in profile.dependencies
            ],
        }

        # Convert to JSON with datetime handling
        return json.dumps(profile_dict, indent=2, default=self._json_serializer)

    def _json_serializer(self, obj):
        """Custom JSON serializer for objects not serializable by default.

        Args:
            obj: Object to serialize.

        Returns:
            Serialized object.
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        raise TypeError(f"Type {type(obj)} not serializable")

    def _format_dependency(self, dep: DependencyRiskScore) -> Dict:
        """Format dependency risk score as dict.

        Args:
            dep: Dependency risk score.

        Returns:
            Dictionary representation of the dependency risk score.
        """
        metadata = dep.dependency

        # Create dependency dict
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
                "total_score": dep.total_score,
            },
            "risk_level": dep.risk_level.value,
            "risk_factors": dep.factors,
        }
