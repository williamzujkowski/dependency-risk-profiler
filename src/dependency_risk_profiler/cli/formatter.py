"""Output formatters for the dependency risk profiler."""

import json
from datetime import datetime
from enum import Enum
from io import StringIO
from pathlib import Path
from textwrap import wrap
from typing import Dict

from packaging.version import InvalidVersion, Version, parse
from rich.cells import cell_len, set_cell_size
from rich.console import Console
from rich.text import Text

from ..models import DependencyRiskScore, ProjectRiskProfile, RiskLevel
from ..popularity import should_soften_low_release_cadence


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

    RISK_WIDTH = 8
    DEPENDENCY_WIDTH = 12
    VERSION_WIDTH = 18
    SIGNALS_WIDTH = 45
    ADVISORIES_WIDTH = 26
    TABLE_SEPARATOR = "  "

    def __init__(self, color: bool = True) -> None:
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
        manifest_name = Path(profile.manifest_path).name
        dependency_label = self._pluralize(
            len(profile.dependencies), "dependency", "dependencies"
        )
        unknown_signal_label = self._pluralize(
            profile.unknown_signal_count, "signal", "signals"
        )
        result = [
            f"Dependency Risk · {manifest_name} ({profile.ecosystem})",
            (
                f"{len(profile.dependencies)} {dependency_label} · overall "
                f"{profile.overall_risk_score:.1f} / 5.0 · "
                f"{profile.unknown_signal_count} {unknown_signal_label} "
                "could not be measured"
            ),
        ]

        if profile.insufficient_data_dependencies:
            insufficient_label = self._pluralize(
                profile.insufficient_data_dependencies, "dependency", "dependencies"
            )
            result.append(
                f"{profile.insufficient_data_dependencies} {insufficient_label} "
                "had insufficient data to score"
            )

        if profile.dependencies:
            result.extend(
                [
                    "",
                    self._format_table_header(),
                    self._format_separator(),
                ]
            )
            for dep in sorted(profile.dependencies, key=self._risk_sort_key):
                result.extend(self._format_dependency_rows(dep))

        result.extend(
            [
                "",
                (
                    'Worst first. "filtered" = informational / withdrawn / '
                    "low-confidence advisories excluded from the score."
                ),
            ]
        )

        return "\n".join(result)

    def _risk_sort_key(self, dep: DependencyRiskScore) -> tuple[int, float, str]:
        """Return the display sort key for a dependency."""
        risk_order = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.LOW: 3,
            RiskLevel.UNKNOWN: 4,
        }
        return (
            risk_order[dep.risk_level],
            -dep.total_score,
            dep.dependency.name.lower(),
        )

    def _format_table_header(self) -> str:
        """Format the dependency table header."""
        return self.TABLE_SEPARATOR.join(
            [
                self._fit_cell("RISK", self.RISK_WIDTH),
                self._fit_cell("DEPENDENCY", self.DEPENDENCY_WIDTH),
                self._fit_cell("VERSION", self.VERSION_WIDTH),
                self._fit_cell("LEADING SIGNALS", self.SIGNALS_WIDTH),
                self._fit_cell("ADVISORIES", self.ADVISORIES_WIDTH),
            ]
        )

    def _format_separator(self) -> str:
        """Format the dependency table separator."""
        return "─" * self._table_width()

    def _table_width(self) -> int:
        """Return the rendered table width."""
        column_width = (
            self.RISK_WIDTH
            + self.DEPENDENCY_WIDTH
            + self.VERSION_WIDTH
            + self.SIGNALS_WIDTH
            + self.ADVISORIES_WIDTH
        )
        separator_width = len(self.TABLE_SEPARATOR) * 4
        return column_width + separator_width

    def _format_dependency_rows(self, dep: DependencyRiskScore) -> list[str]:
        """Format one dependency into one or more rendered table lines."""
        metadata = dep.dependency
        signal_lines = wrap(
            self._format_leading_signals(dep),
            width=self.SIGNALS_WIDTH,
            break_long_words=False,
            break_on_hyphens=False,
        )
        if not signal_lines:
            signal_lines = ["—"]

        risk_level = "UNKNOWN" if dep.insufficient_data else dep.risk_level.value
        lines = [
            self.TABLE_SEPARATOR.join(
                [
                    self._format_risk_cell(risk_level, dep.risk_level),
                    self._fit_cell(metadata.name, self.DEPENDENCY_WIDTH),
                    self._fit_cell(
                        self._format_version_summary(dep), self.VERSION_WIDTH
                    ),
                    self._fit_cell(signal_lines[0], self.SIGNALS_WIDTH),
                    self._fit_cell(
                        self._format_vulnerability_summary(dep),
                        self.ADVISORIES_WIDTH,
                    ),
                ]
            )
        ]

        for signal_line in signal_lines[1:]:
            lines.append(
                self.TABLE_SEPARATOR.join(
                    [
                        self._fit_cell("", self.RISK_WIDTH),
                        self._fit_cell("", self.DEPENDENCY_WIDTH),
                        self._fit_cell("", self.VERSION_WIDTH),
                        self._fit_cell(signal_line, self.SIGNALS_WIDTH),
                        self._fit_cell("", self.ADVISORIES_WIDTH),
                    ]
                )
            )

        return lines

    def _format_risk_cell(self, text: str, risk_level: RiskLevel) -> str:
        """Format the styled risk cell."""
        cell = self._fit_cell(text, self.RISK_WIDTH)
        if not self.color:
            return cell

        console = Console(
            file=StringIO(),
            force_terminal=True,
            color_system="standard",
            record=True,
        )
        console.print(Text(cell, style=self._risk_style(risk_level)), end="")
        return console.export_text(styles=True, clear=True)

    def _risk_style(self, risk_level: RiskLevel) -> str:
        """Return the Rich style for a risk level."""
        if risk_level in {RiskLevel.CRITICAL, RiskLevel.HIGH}:
            return "red"
        if risk_level == RiskLevel.MEDIUM:
            return "yellow"
        if risk_level == RiskLevel.LOW:
            return "green"
        return "dim"

    def _fit_cell(self, text: str, width: int) -> str:
        """Pad or truncate a string to a fixed terminal cell width."""
        if cell_len(text) <= width:
            return set_cell_size(text, width)
        return set_cell_size(set_cell_size(text, width - 1) + "…", width)

    def _format_version_summary(self, dep: DependencyRiskScore) -> str:
        """Format installed and latest versions in plain language."""
        metadata = dep.dependency
        if metadata.latest_version:
            return f"{metadata.installed_version} → {metadata.latest_version}"
        return f"{metadata.installed_version} → latest unknown"

    def _format_leading_signals(self, dep: DependencyRiskScore) -> str:
        """Build a plain-language signal summary from measured risk inputs."""
        metadata = dep.dependency
        if dep.insufficient_data:
            return "insufficient data to score"

        signals: list[str] = []

        if (
            dep.maintainer_score is not None
            and dep.maintainer_score > 0.5
            and metadata.maintainer_count is not None
        ):
            if metadata.maintainer_count <= 1:
                signals.append("single maintainer")
            else:
                signals.append(f"{metadata.maintainer_count} maintainers")

        if (
            dep.staleness_score is not None
            and dep.staleness_score > 0
            and metadata.last_updated is not None
        ):
            if should_soften_low_release_cadence(metadata):
                signals.append("stable, low release cadence")
            else:
                signals.append(self._format_release_signal(metadata.last_updated))

        if dep.version_score is not None and dep.version_score > 0:
            signals.append(self._format_version_signal(dep))

        if dep.deprecation_score > 0:
            signals.append("deprecated")

        if dep.license_score is not None and dep.license_score > 0.5:
            license_info = metadata.license_info
            if license_info is not None:
                signals.append(f"{license_info.license_id} license flag")

        if (
            dep.health_indicators_score is not None
            and dep.health_indicators_score > 0.5
        ):
            missing = self._missing_health_indicators(dep)
            if missing:
                signals.append(f"missing {', '.join(missing)}")

        if dep.security_policy_score is not None and dep.security_policy_score > 0.5:
            signals.append("missing security policy")

        if (
            dep.dependency_update_score is not None
            and dep.dependency_update_score > 0.5
        ):
            signals.append("no dependency update tooling")

        if dep.signed_commits_score is not None and dep.signed_commits_score > 0.5:
            signals.append("unsigned commits")

        if (
            dep.branch_protection_score is not None
            and dep.branch_protection_score > 0.5
        ):
            signals.append("no branch protection")

        if dep.maintained_score is not None and dep.maintained_score > 0.5:
            if should_soften_low_release_cadence(metadata):
                if "stable, low release cadence" not in signals:
                    signals.append("stable, low release cadence")
            else:
                signals.append("not actively maintained")

        if dep.community_score is not None and dep.community_score > 0.5:
            community_signal = self._format_community_signal(dep)
            if community_signal:
                signals.append(community_signal)

        if dep.transitive_score > 0.5:
            signals.append(f"{len(metadata.transitive_dependencies)} transitive deps")

        if signals:
            return " · ".join(signals[:2])
        return "no leading risk signals"

    def _missing_health_indicators(self, dep: DependencyRiskScore) -> list[str]:
        """Return measured health indicators that are missing."""
        metadata = dep.dependency
        missing: list[str] = []
        if metadata.has_tests is False:
            missing.append("tests")
        if metadata.has_ci is False:
            missing.append("CI")
        if metadata.has_contribution_guidelines is False:
            missing.append("contribution guidelines")
        return missing

    def _format_community_signal(self, dep: DependencyRiskScore) -> str:
        """Format the strongest measured community signal."""
        metrics = dep.dependency.community_metrics
        if metrics is None:
            return ""
        if metrics.star_count is not None and metrics.star_count < 100:
            return f"low popularity ({metrics.star_count} stars)"
        if metrics.commit_frequency is not None and metrics.commit_frequency < 1:
            return "low development activity"
        return ""

    def _format_release_signal(self, last_updated: datetime) -> str:
        """Format release recency in human terms."""
        normalized_update = (
            last_updated.replace(tzinfo=None) if last_updated.tzinfo else last_updated
        )
        days_since_update = max((datetime.now() - normalized_update).days, 0)

        if days_since_update < 30:
            return "released < 1 month ago"
        if days_since_update < 365:
            months = max(days_since_update // 30, 1)
            return (
                f"released {months} "
                f"{self._pluralize(months, 'month', 'months')} ago"
            )

        years = max(round(days_since_update / 365), 1)
        return f"unmaintained ~{years} {self._pluralize(years, 'year', 'years')}"

    def _format_version_signal(self, dep: DependencyRiskScore) -> str:
        """Format version drift in human terms."""
        metadata = dep.dependency
        if not metadata.latest_version:
            return "latest version unknown"

        try:
            installed = parse(metadata.installed_version)
            latest = parse(metadata.latest_version)
        except InvalidVersion:
            return "behind latest"

        if not isinstance(installed, Version) or not isinstance(latest, Version):
            return "behind latest"
        if latest.major > installed.major:
            major_diff = latest.major - installed.major
            return (
                f"{major_diff} "
                f"{self._pluralize(major_diff, 'major version', 'major versions')} "
                "behind"
            )
        if latest.minor > installed.minor:
            minor_diff = latest.minor - installed.minor
            return (
                f"{minor_diff} "
                f"{self._pluralize(minor_diff, 'minor version', 'minor versions')} "
                "behind"
            )
        return "behind latest"

    def _format_vulnerability_summary(self, dep: DependencyRiskScore) -> str:
        """Format advisory counts in plain language."""
        metrics = dep.dependency.security_metrics
        if metrics is None or metrics.vulnerability_count is None:
            return "unknown"

        counted = metrics.counted_vulnerability_count
        filtered = metrics.filtered_vulnerability_count
        if counted is None or filtered is None:
            if metrics.vulnerability_count == 0:
                return "none"
            return f"{metrics.vulnerability_count} found"

        if counted == 0 and filtered == 0:
            return "none"
        return f"{counted} scored · {filtered} filtered"

    def _pluralize(self, count: int, singular: str, plural: str) -> str:
        """Return singular or plural text for a count."""
        return singular if count == 1 else plural


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
            "unknown_risk_dependencies": profile.unknown_risk_dependencies,
            "insufficient_data_dependencies": profile.insufficient_data_dependencies,
            "unknown_signal_count": profile.unknown_signal_count,
            "overall_risk_score": profile.overall_risk_score,
            "dependencies": [
                self._format_dependency(dep) for dep in profile.dependencies
            ],
        }

        # Convert to JSON with datetime handling
        return json.dumps(profile_dict, indent=2, default=self._json_serializer)

    def _json_serializer(self, obj: object) -> object:
        """Serialize objects not serializable by default.

        Args:
            obj: Object to serialize.

        Returns:
            Serialized object.
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
                "max_counted_cvss_score": None,
                "max_counted_severity": None,
                "advisories": [],
            }

        return {
            "total_found": metrics.vulnerability_count,
            "counted_in_score": metrics.counted_vulnerability_count,
            "filtered": metrics.filtered_vulnerability_count,
            "filtered_reasons": metrics.filtered_vulnerability_reasons,
            "max_counted_cvss_score": metrics.max_cvss_score,
            "max_counted_severity": metrics.max_vulnerability_severity,
            "advisories": metrics.vulnerability_details,
        }
