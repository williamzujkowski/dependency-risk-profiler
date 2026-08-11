"""Tests for terminal report formatting."""

from datetime import datetime, timedelta

from dependency_risk_profiler.cli.formatter import TerminalFormatter
from dependency_risk_profiler.models import (
    CommunityMetrics,
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
        # The per-dependency count is derived from this list, not stored.
        unknown_signals=[f"signal_{index}" for index in range(10)],
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
    )

    output = TerminalFormatter(color=False).format_profile(profile)
    lines = output.splitlines()

    assert lines[0] == "Dependency Risk · requirements.txt (python)"
    # (3.2 + 2.0) / 2. ``mostly-unknown`` carries a 4.9 it could not justify
    # and is excluded, so this headline moves *up* on exclusion — which is why
    # the coverage has to travel with it (#276).
    assert "3 dependencies · overall 2.6 / 5.0 across 2 of 3 scored" in lines[1]
    assert "10 signals could not be measured" in lines[1]
    assert "1 dependency had insufficient data to score" in output
    assert "RISK" in output
    assert "DEPENDENCY" in output
    assert "VERSION" in output
    assert "LEADING SIGNALS" in output
    assert "ADVISORIES" in output
    # The two axes the verdict is not a measure of, each with a column of its
    # own beside the one that lists what moved the verdict (#242, #340).
    assert "LICENSE" in output

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


def test_low_cadence_reaches_the_terminal_report() -> None:
    """REGRESSION #166: the cadence branch was unreachable, so it never printed.

    ``commit_frequency`` had no producer, so this line of the terminal report
    was dead code from the day it was written. It is also no longer gated on
    the averaged ``community_score``: a well-starred package with a dead commit
    log averages to exactly 0.5 and cleared no ``> 0.5`` threshold.
    """
    dep = DependencyRiskScore(
        dependency=DependencyMetadata(
            name="six",
            installed_version="1.16.0",
            community_metrics=CommunityMetrics(
                star_count=50_000,
                commit_frequency=0.5,
            ),
        ),
        community_score=0.5,
        total_score=1.0,
        risk_level=RiskLevel.MEDIUM,
        measured_signal_count=9,
        total_signal_count=16,
    )
    profile = ProjectRiskProfile(
        manifest_path="/tmp/wg/requirements.txt",
        ecosystem="python",
        dependencies=[dep],
        medium_risk_dependencies=1,
    )

    output = TerminalFormatter(color=False).format_profile(profile)

    assert "low development activity (0.5/month)" in output


def test_namespaced_names_render_in_full_not_as_a_shared_prefix() -> None:
    """REGRESSION #279: a 12-cell name column named nothing.

    ``DEPENDENCY_WIDTH`` was the constant 12, so every ecosystem with
    namespaced names rendered only the part they have in common. On gin's
    ``go.mod``, 26 of 35 rows read ``github.com/…`` -- the report described
    dependencies it could not name, and two rows differing only after the
    prefix were indistinguishable.

    Asserted on the two names together: a check that one long name survives
    would also pass if the column had merely been made wider by a constant,
    which is the fix that breaks again on the next longer ecosystem.
    """
    names = [
        "github.com/gin-contrib/sse",
        "github.com/goccy/go-json",
    ]
    dependencies = [
        DependencyRiskScore(
            dependency=DependencyMetadata(
                name=name,
                installed_version="v1.0.0",
                latest_version="v1.0.0",
            ),
            total_score=1.0,
            risk_level=RiskLevel.LOW,
            measured_signal_count=9,
            total_signal_count=14,
        )
        for name in names
    ]
    profile = ProjectRiskProfile(
        manifest_path="/tmp/gin/go.mod",
        ecosystem="golang",
        dependencies=dependencies,
        low_risk_dependencies=len(names),
    )

    output = TerminalFormatter(color=False).format_profile(profile)

    for name in names:
        assert name in output, f"{name!r} was truncated out of the report"
    assert "github.com/…" not in output
