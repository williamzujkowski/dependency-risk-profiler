"""Output formatters for the dependency risk profiler."""

import json
from datetime import datetime
from enum import Enum
from io import StringIO
from pathlib import Path
from textwrap import wrap
from typing import Dict, List, Optional

from packaging.version import InvalidVersion, Version, parse
from rich.cells import cell_len, set_cell_size
from rich.console import Console
from rich.text import Text

from ..contract import SCHEMA_VERSION, scored_dependency
from ..models import (
    DependencyRiskScore,
    ProjectRiskProfile,
    RiskLevel,
    merged_overall_risk_score,
)
from ..parsers.version_sources import DECLARED_CONSTRAINT_KEY
from ..popularity import should_soften_low_release_cadence
from ..versioning import (
    calendar_drift_days,
    calendar_drift_label,
    release_timestamps,
    uses_calendar_versioning,
)


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

    # The dependency column is sized to the names present, between these
    # bounds. 12 is the floor because shorter names need no more; 48 is the cap
    # because a longer name is rarer than the cost of a table that wide.
    #
    # There is deliberately no terminal-width arithmetic. The other four
    # columns and their separators total 117 cells, which already exceeds any
    # terminal this is likely to run in, so there is no slack to redistribute
    # between columns -- a budget computed against the terminal yields the
    # floor and truncates every namespaced name. The table is as wide as its
    # content requires.
    MIN_DEPENDENCY_WIDTH = 12
    MAX_DEPENDENCY_WIDTH = 48

    def __init__(self, color: bool = True) -> None:
        """Initialize the terminal formatter.

        Args:
            color: Whether to enable color output.
        """
        self.color = color

    def _apply_layout(self, profile: ProjectRiskProfile) -> None:
        """Size the dependency column to the names this report will render.

        Namespaced ecosystems -- golang import paths, maven ``group:artifact``,
        ``Microsoft.*``, ``androidx.*`` -- share a prefix longer than any fixed
        width worth choosing. A column narrower than the prefix renders the
        part every row has in common and cuts the part that tells them apart,
        which names nothing (#279).

        Sets instance attributes that shadow the class constants, so a caller
        rendering rows without going through ``format_profile`` gets the
        default layout rather than an exception.

        Args:
            profile: The profile about to be rendered.
        """
        longest = max(
            (cell_len(dep.dependency.name) for dep in profile.dependencies),
            default=0,
        )
        self.DEPENDENCY_WIDTH = min(
            self.MAX_DEPENDENCY_WIDTH,
            max(self.MIN_DEPENDENCY_WIDTH, longest),
        )

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
                f"{len(profile.dependencies)} {dependency_label} · "
                f"{self._overall_clause(profile)} · "
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
            self._apply_layout(profile)
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
                    'Worst first. "filtered" = advisories excluded from the '
                    "score: ones that do not affect the installed version, "
                    "plus informational / withdrawn / low-confidence ones."
                ),
            ]
        )

        return "\n".join(result)

    def _overall_clause(self, profile: ProjectRiskProfile) -> str:
        """Render the headline mean so it cannot be read without its coverage.

        Three states, three sentences. The mean over every dependency reads as
        it always did. A mean over some of them says how many, in the same
        breath, because "overall 2.5" and "overall 2.5, from one package in
        five" are different claims and the second one used to be printed as the
        first (#276). A mean over none of them is not a number at all.

        Args:
            profile: The manifest profile being rendered.

        Returns:
            The ``overall …`` clause for the summary line.
        """
        total = len(profile.dependencies)
        scored = profile.scored_dependency_count
        overall = profile.overall_risk_score
        if overall is None:
            label = self._pluralize(total, "dependency", "dependencies")
            return f"overall not scored · 0 of {total} {label} could be scored"
        if scored == total:
            return f"overall {overall:.1f} / 5.0"
        return f"overall {overall:.1f} / 5.0 across {scored} of {total} scored"

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
        # A blank installed version used to render as a bare arrow, which reads
        # like a bug. Say what actually happened: the version is declared
        # somewhere we could not reach (a parent POM, an imported BOM), so drift
        # is unmeasured rather than zero.
        # A manifest that states `requests>=2.20.0` did say something, just not
        # a version. Printing the bound and labelling it unpinned keeps that
        # fact visible without putting it where a version goes (#275).
        constraint = metadata.additional_info.get(DECLARED_CONSTRAINT_KEY)
        if not metadata.installed_version and constraint:
            installed = f"{constraint} unpinned"
        else:
            installed = metadata.installed_version or "unmanaged"
        if metadata.latest_version:
            return f"{installed} → {metadata.latest_version}"
        return f"{installed} → latest unknown"

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

        # Every other score here is guarded; this one was not, and a score
        # object built without a deprecation reading crashed the whole report.
        if dep.deprecation_score is not None and dep.deprecation_score > 0:
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

        # Gated on the metrics themselves rather than on the averaged community
        # score: a heavily-starred package with a dead commit log averages to
        # exactly 0.5 and would otherwise report neither half (#166).
        community_signal = self._format_community_signal(dep)
        if community_signal:
            signals.append(community_signal)

        if dep.transitive_score is not None and dep.transitive_score > 0.5:
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
            return f"low development activity ({metrics.commit_frequency:.1f}/month)"
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

        # CalVer drift is elapsed time, not breaking changes (#126).
        if uses_calendar_versioning(
            metadata.installed_version, metadata.latest_version
        ):
            installed_release, latest_release = release_timestamps(metadata)
            return calendar_drift_label(
                calendar_drift_days(installed_release, latest_release)
            )

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
    """Schema-v2 JSON output formatter.

    Every dependency is serialized by ``contract.scored_dependency``, the one
    shape ``scan-org`` emits too. This class owns only the envelope: which
    manifests were read, how many dependencies came out, and the run-level
    counts. See ``contract`` for what changed and why, and ``cli/json_v1.py``
    for the frozen writer ``--schema v1`` still routes to.
    """

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
        unreadable_manifests: List[Dict[str, str]],
    ) -> str:
        """Format a whole analyze run as exactly one JSON document.

        The contract this upholds (#147): a run that exits 0 in JSON mode
        writes parseable JSON to stdout. Zero manifests, one manifest, and a
        directory of manifests all produce the same top-level shape, so a
        consumer that reads ``dependency_count`` and ``dependencies`` never
        needs a special case for "nothing to report". Anything the run refused
        or skipped is stated in ``warnings`` rather than left as silence.

        ``unreadable_manifests`` is what makes "I found no dependencies"
        distinguishable from "I could not read your project" (#243). Both used
        to serialize as ``dependency_count: 0``, and a consumer had no key to
        branch on. It is a required argument, not an optional one, so the
        reassuring shape cannot be produced by forgetting to pass it
        (AGENTS.md rule 4).

        Args:
            profiles: Successfully analyzed manifest profiles, possibly empty.
            manifest_path: The path the user actually pointed the tool at.
            warnings: Human-readable notes about skipped or refused inputs.
            unreadable_manifests: Dependency manifests the scan recognized and
                could not read, each with ``manifest_path``, ``ecosystem`` and
                ``guidance``. Empty means every recognized manifest was read.

        Returns:
            A single JSON document.
        """
        report = self._report_dict(profiles, manifest_path)
        report["manifests"] = [
            {
                "manifest_path": profile.manifest_path,
                "ecosystem": profile.ecosystem,
                "dependency_count": len(profile.dependencies),
                # The per-manifest sort key of the terminal summary, so it
                # carries its denominator here too (#276).
                "scored_dependency_count": profile.scored_dependency_count,
                "overall_risk_score": profile.overall_risk_score,
            }
            for profile in profiles
        ]
        report["unreadable_manifests"] = [dict(entry) for entry in unreadable_manifests]
        report["warnings"] = list(warnings)
        return json.dumps(report, indent=2, default=self._json_serializer)

    def _report_dict(
        self, profiles: List[ProjectRiskProfile], manifest_path: str
    ) -> Dict[str, object]:
        """Build the top-level report body for zero, one, or many profiles."""
        if len(profiles) == 1:
            return self._profile_dict(profiles[0])
        if not profiles:
            return {
                "schema_version": SCHEMA_VERSION,
                "manifest_path": manifest_path,
                "ecosystem": None,
                "scan_time": datetime.now().isoformat(),
                "dependency_count": 0,
                "scored_dependency_count": 0,
                "high_risk_dependencies": 0,
                "medium_risk_dependencies": 0,
                "low_risk_dependencies": 0,
                "unknown_risk_dependencies": 0,
                "insufficient_data_dependencies": 0,
                "unknown_signal_count": 0,
                # None, not 0.0: nothing was measured, and a 0.0 here would read
                # as "perfectly safe" (#74, #147). Since #276 that is no longer
                # the only route to a null here — a manifest whose every
                # dependency was unresolvable reports the same state, because
                # it is the same state.
                "overall_risk_score": None,
                "dependencies": [],
            }
        return self._merged_dict(profiles, manifest_path)

    def _merged_dict(
        self, profiles: List[ProjectRiskProfile], manifest_path: str
    ) -> Dict[str, object]:
        """Merge several manifest profiles into one document."""
        dependencies = [dep for profile in profiles for dep in profile.dependencies]
        ecosystems = {profile.ecosystem for profile in profiles}
        total = len(dependencies)
        overall, scored = merged_overall_risk_score(profiles)
        return {
            "schema_version": SCHEMA_VERSION,
            "manifest_path": manifest_path,
            # A mixed-ecosystem run has no single ecosystem; say so rather than
            # picking one of them.
            "ecosystem": ecosystems.pop() if len(ecosystems) == 1 else None,
            "scan_time": max(profile.scan_time for profile in profiles).isoformat(),
            "dependency_count": total,
            "scored_dependency_count": scored,
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
            # Each dependency keeps the ecosystem of the manifest it came from,
            # which the v1 merged document could not express: it had one
            # ecosystem key for the whole run and set it to null for a mixed
            # directory, leaving a consumer no way to tell which is which.
            "dependencies": [
                scored_dependency(dep, ecosystem=profile.ecosystem)
                for profile in profiles
                for dep in profile.dependencies
            ],
        }

    def _profile_dict(self, profile: ProjectRiskProfile) -> Dict[str, object]:
        """Serialize one manifest profile.

        Args:
            profile: Project risk profile.

        Returns:
            The serialized profile envelope.
        """
        return {
            "schema_version": SCHEMA_VERSION,
            "manifest_path": profile.manifest_path,
            "ecosystem": profile.ecosystem,
            "scan_time": profile.scan_time.isoformat(),
            "dependency_count": len(profile.dependencies),
            # The denominator ``overall_risk_score`` was taken over. Published
            # beside it so the mean cannot be quoted without its coverage: a
            # 2.46 over one of five dependencies is not a project's score
            # (#276).
            "scored_dependency_count": profile.scored_dependency_count,
            "high_risk_dependencies": profile.high_risk_dependencies,
            "medium_risk_dependencies": profile.medium_risk_dependencies,
            "low_risk_dependencies": profile.low_risk_dependencies,
            "unknown_risk_dependencies": profile.unknown_risk_dependencies,
            "insufficient_data_dependencies": profile.insufficient_data_dependencies,
            # A run-level total, not the per-dependency count v2 deleted: this
            # one summarizes the whole manifest alongside the risk-level tallies
            # rather than restating one dependency's own list.
            "unknown_signal_count": profile.unknown_signal_count,
            "overall_risk_score": profile.overall_risk_score,
            "dependencies": [
                scored_dependency(dep, ecosystem=profile.ecosystem)
                for dep in profile.dependencies
            ],
        }

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
