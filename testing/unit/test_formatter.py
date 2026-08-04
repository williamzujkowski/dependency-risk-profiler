"""Tests for terminal report formatting."""

from datetime import datetime, timedelta

from dependency_risk_profiler.cli.formatter import TerminalFormatter
from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    ProjectRiskProfile,
    RiskLevel,
    SecurityMetrics,
)


def test_terminal_report_uses_plain_language_table() -> None:
    """Terminal report should be compact, sorted worst first, and readable."""
    flask = DependencyRiskScore(
        dependency=DependencyMetadata(
            name="flask",
            installed_version="2.0.0",
            latest_version="3.1.3",
            last_updated=datetime.now() - timedelta(days=64),
            maintainer_count=1,
            security_metrics=SecurityMetrics(
                vulnerability_count=10,
                counted_vulnerability_count=5,
                filtered_vulnerability_count=5,
            ),
        ),
        staleness_score=0.25,
        maintainer_score=1.0,
        deprecation_score=0.0,
        exploit_score=0.5,
        version_score=1.0,
        transitive_score=0.0,
        total_score=3.2,
        risk_level=RiskLevel.HIGH,
        measured_signal_count=8,
        total_signal_count=14,
    )
    requests = DependencyRiskScore(
        dependency=DependencyMetadata(
            name="requests",
            installed_version="2.31.0",
            latest_version="2.34.2",
            last_updated=datetime.now() - timedelta(days=15),
            maintainer_count=1,
            security_metrics=SecurityMetrics(
                vulnerability_count=0,
                counted_vulnerability_count=0,
                filtered_vulnerability_count=0,
            ),
        ),
        staleness_score=0.0,
        maintainer_score=1.0,
        deprecation_score=0.0,
        exploit_score=0.0,
        version_score=0.5,
        transitive_score=0.0,
        total_score=2.0,
        risk_level=RiskLevel.MEDIUM,
        measured_signal_count=8,
        total_signal_count=14,
    )
    unknown = DependencyRiskScore(
        dependency=DependencyMetadata(
            name="mostly-unknown",
            installed_version="0.1.0",
        ),
        total_score=4.9,
        risk_level=RiskLevel.UNKNOWN,
        unknown_signal_count=10,
        measured_signal_count=2,
        total_signal_count=14,
        insufficient_data=True,
    )
    profile = ProjectRiskProfile(
        manifest_path="/tmp/requirements.txt",
        ecosystem="python",
        dependencies=[unknown, requests, flask],
        high_risk_dependencies=1,
        medium_risk_dependencies=1,
        unknown_risk_dependencies=1,
        insufficient_data_dependencies=1,
        unknown_signal_count=10,
        overall_risk_score=2.4,
    )

    output = TerminalFormatter(color=False).format_profile(profile)
    lines = output.splitlines()

    assert lines[0] == "Dependency Risk · requirements.txt (python)"
    assert "3 dependencies · overall 2.4 / 5.0" in lines[1]
    assert "10 signals could not be measured" in lines[1]
    assert "1 dependency had insufficient data to score" in output
    assert "RISK" in output
    assert "DEPENDENCY" in output
    assert "VERSION" in output
    assert "LEADING SIGNALS" in output
    assert "ADVISORIES" in output

    flask_line = next(line for line in lines if "flask" in line)
    requests_line = next(line for line in lines if "requests" in line)
    unknown_line = next(line for line in lines if "mostly-unkn" in line)

    assert (
        lines.index(flask_line) < lines.index(requests_line) < lines.index(unknown_line)
    )
    assert "HIGH" in flask_line
    assert "single maintainer" in flask_line
    assert "2.0.0 → 3.1.3" in flask_line
    assert "5 scored · 5 filtered" in flask_line
    assert "MEDIUM" in requests_line
    assert "none" in requests_line
    assert "UNKNOWN" in unknown_line
    assert "insufficient data to score" in unknown_line
    assert "score 5 filt" not in output
    assert "1/14" not in output


def test_unresolved_installed_version_is_labelled_not_blank() -> None:
    """REGRESSION #128: a bare " → 2.22.1" read like a rendering bug.

    A Maven artifact whose version lives in an unreachable parent POM has no
    installed version to show. Say so, rather than printing an arrow with
    nothing on its left.
    """
    dep = DependencyRiskScore(
        dependency=DependencyMetadata(
            name="com.fasterxml.jackson.core:jackson-databind",
            installed_version="",
            latest_version="2.22.1",
        ),
        total_score=1.0,
        risk_level=RiskLevel.LOW,
        measured_signal_count=9,
        total_signal_count=14,
    )
    profile = ProjectRiskProfile(
        manifest_path="/tmp/wg/pom.xml",
        ecosystem="maven",
        dependencies=[dep],
        low_risk_dependencies=1,
    )

    output = TerminalFormatter(color=False).format_profile(profile)

    assert "unmanaged → 2.22.1" in output
