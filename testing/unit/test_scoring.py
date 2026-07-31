"""Tests for the risk scoring system."""

from datetime import datetime, timedelta
from typing import Dict, List

from dependency_risk_profiler.cli.formatter import JsonFormatter, TerminalFormatter
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    LicenseCategory,
    LicenseInfo,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.vulnerabilities.aggregator import (
    _update_dependency_with_vulnerabilities,
)


def test_scoring_system() -> None:
    """Test the risk scoring system."""
    # Create a risk scorer with default weights
    scorer = RiskScorer()

    # Test a low-risk dependency
    low_risk = DependencyMetadata(
        name="low-risk",
        installed_version="1.0.0",
        latest_version="1.0.0",
        last_updated=datetime.now() - timedelta(days=15),
        maintainer_count=5,
        is_deprecated=False,
        has_known_exploits=False,
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=True,
    )

    low_risk_score = scorer.score_dependency(low_risk)
    # The risk level might vary based on the scoring implementation
    # Just ensure it's not high or critical
    assert low_risk_score.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]
    assert low_risk_score.total_score < 3.0

    # Test a medium-risk dependency
    medium_risk = DependencyMetadata(
        name="medium-risk",
        installed_version="1.0.0",
        latest_version="1.2.0",
        last_updated=datetime.now() - timedelta(days=120),
        maintainer_count=2,
        is_deprecated=False,
        has_known_exploits=False,
        has_tests=True,
        has_ci=False,
        has_contribution_guidelines=False,
    )

    medium_risk_score = scorer.score_dependency(medium_risk)
    # Missing enhanced metadata is excluded instead of scored as moderate risk.
    assert medium_risk_score.risk_level == RiskLevel.LOW
    assert medium_risk_score.unknown_signal_count == 7
    assert medium_risk_score.total_score < 3.5

    # Test a high-risk dependency
    high_risk = DependencyMetadata(
        name="high-risk",
        installed_version="1.0.0",
        latest_version="2.0.0",
        last_updated=datetime.now() - timedelta(days=370),
        maintainer_count=1,
        is_deprecated=False,
        has_known_exploits=False,
        has_tests=False,
        has_ci=False,
        has_contribution_guidelines=False,
    )

    high_risk_score = scorer.score_dependency(high_risk)
    # Missing enhanced metadata is not scored as extra risk.
    assert high_risk_score.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
    # The exact score may vary, just ensure it's higher than medium risk
    assert high_risk_score.total_score > medium_risk_score.total_score

    # Test a critical-risk dependency
    critical_risk = DependencyMetadata(
        name="critical-risk",
        installed_version="1.0.0",
        latest_version="3.0.0",
        last_updated=datetime.now() - timedelta(days=730),
        maintainer_count=1,
        is_deprecated=True,
        has_known_exploits=True,
        has_tests=False,
        has_ci=False,
        has_contribution_guidelines=False,
    )

    critical_risk_score = scorer.score_dependency(critical_risk)
    # Check that it's at CRITICAL risk level
    assert critical_risk_score.risk_level == RiskLevel.CRITICAL
    # Make sure the critical risk score is higher than the high risk score
    assert critical_risk_score.total_score > high_risk_score.total_score


def test_risk_factors() -> None:
    """Test the risk factors."""
    # Create a risk scorer with default weights
    scorer = RiskScorer()

    # Test a dependency with multiple risk factors
    dep = DependencyMetadata(
        name="risky-dep",
        installed_version="1.0.0",
        latest_version="2.0.0",
        last_updated=datetime.now() - timedelta(days=400),
        maintainer_count=1,
        is_deprecated=True,
        has_known_exploits=True,
        has_tests=False,
        has_ci=False,
        has_contribution_guidelines=False,
    )

    score = scorer.score_dependency(dep)

    # Check that risk factors are identified
    assert len(score.factors) > 0
    assert any("Outdated" in factor for factor in score.factors)
    assert any("Deprecated" in factor for factor in score.factors)
    assert any("Known security issues" in factor for factor in score.factors)
    assert any("Single maintainer" in factor for factor in score.factors)
    assert any("Not updated" in factor for factor in score.factors)
    assert any("Missing" in factor for factor in score.factors)


def test_partial_data() -> None:
    """Test scoring with partial data."""
    # Create a risk scorer with default weights
    scorer = RiskScorer()

    # Test a dependency with minimal data
    dep = DependencyMetadata(
        name="partial-data",
        installed_version="1.0.0",
    )

    score = scorer.score_dependency(dep)

    assert score.total_score == 0.0
    assert score.risk_level == RiskLevel.UNKNOWN
    assert score.insufficient_data is True
    assert score.unknown_signal_count == 11
    assert "staleness" in score.unknown_signals
    assert "maintainer" in score.unknown_signals
    assert "version" in score.unknown_signals


def test_all_missing_data_is_unknown_not_medium() -> None:
    """A mostly unmeasurable dependency must not become confident MEDIUM risk."""
    scorer = RiskScorer()
    dep = DependencyMetadata(name="no-metadata", installed_version="0.0.0")

    score = scorer.score_dependency(dep)

    assert score.risk_level == RiskLevel.UNKNOWN
    assert score.insufficient_data is True
    assert score.total_score == 0.0
    assert score.unknown_signal_count > score.measured_signal_count
    assert score.unknown_signals == [
        "staleness",
        "maintainer",
        "version",
        "health_indicators",
        "license",
        "community",
        "security_policy",
        "dependency_update",
        "signed_commits",
        "branch_protection",
        "maintained",
    ]


def test_full_data_scoring_is_unchanged() -> None:
    """Measured full-data signals keep their calibrated component scores."""
    scorer = RiskScorer()
    dep = DependencyMetadata(
        name="full-data",
        installed_version="1.0.0",
        latest_version="1.1.0",
        last_updated=datetime.now() - timedelta(days=120),
        maintainer_count=2,
        has_tests=True,
        has_ci=False,
        has_contribution_guidelines=False,
        license_info=LicenseInfo(
            license_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            is_approved=True,
            risk_level=RiskLevel.LOW,
        ),
        community_metrics=CommunityMetrics(
            star_count=1000,
            open_issues_count=20,
            closed_issues_count=80,
            commit_frequency=5.0,
        ),
        transitive_dependencies={"a", "b", "c", "d", "e"},
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=True,
            has_signed_commits=True,
            has_branch_protection=True,
            is_maintained=True,
        ),
    )

    score = scorer.score_dependency(dep)

    assert score.unknown_signals == []
    assert score.insufficient_data is False
    assert score.staleness_score == 0.5
    assert score.maintainer_score == 0.5
    assert score.version_score == 0.5
    assert round(score.health_indicators_score or 0.0, 2) == 0.67
    assert score.license_score == 0.0
    assert round(score.community_score or 0.0, 2) == 0.17
    assert score.transitive_score == 0.25
    assert score.security_policy_score == 0.0
    assert score.dependency_update_score == 0.0
    assert score.signed_commits_score == 0.0
    assert score.branch_protection_score == 0.0
    assert score.maintained_score == 0.0


def test_high_star_stale_dependency_scores_lower_than_obscure_stale_peer() -> None:
    """REGRESSION: broad adoption dampens stale release cadence, not advisories."""
    scorer = RiskScorer(
        staleness_weight=1.0,
        maintainer_weight=0.0,
        deprecation_weight=0.0,
        exploit_weight=0.0,
        version_difference_weight=0.0,
        health_indicators_weight=0.0,
        license_weight=0.0,
        community_weight=0.0,
        transitive_weight=0.0,
        security_policy_weight=0.0,
        dependency_update_weight=0.0,
        signed_commits_weight=0.0,
        branch_protection_weight=0.0,
    )
    last_updated = datetime.now() - timedelta(days=500)
    popular = DependencyMetadata(
        name="popular-stale",
        installed_version="1.0.0",
        last_updated=last_updated,
        community_metrics=CommunityMetrics(star_count=5000),
    )
    obscure = DependencyMetadata(
        name="obscure-stale",
        installed_version="1.0.0",
        last_updated=last_updated,
        community_metrics=CommunityMetrics(star_count=5),
    )

    popular_score = scorer.score_dependency(popular)
    obscure_score = scorer.score_dependency(obscure)

    assert popular_score.staleness_score == 0.5
    assert obscure_score.staleness_score == 1.0
    assert popular_score.total_score < obscure_score.total_score


def test_high_contributor_dependency_does_not_get_single_maintainer_signal() -> None:
    """REGRESSION: real contributor counts replace registry author guesses."""
    scorer = RiskScorer()
    dependency = DependencyMetadata(
        name="team-maintained",
        installed_version="1.0.0",
        latest_version="1.0.0",
        last_updated=datetime.now() - timedelta(days=15),
        maintainer_count=25,
        community_metrics=CommunityMetrics(contributor_count=25),
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=True,
        license_info=LicenseInfo(
            license_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            is_approved=True,
            risk_level=RiskLevel.LOW,
        ),
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=True,
            has_signed_commits=True,
            has_branch_protection=True,
            is_maintained=True,
        ),
    )

    score = scorer.score_dependency(dependency)

    assert score.maintainer_score == 0.0
    assert "Single maintainer" not in score.factors
    assert "single maintainer" not in TerminalFormatter()._format_leading_signals(score)


def test_popular_single_contributor_dependency_keeps_bus_factor_signal() -> None:
    """REGRESSION: popularity dampens abandonment risk, not bus-factor risk."""
    scorer = RiskScorer()
    dependency = DependencyMetadata(
        name="popular-single",
        installed_version="1.0.0",
        latest_version="1.0.0",
        last_updated=datetime.now() - timedelta(days=15),
        maintainer_count=1,
        community_metrics=CommunityMetrics(star_count=5000, contributor_count=1),
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=True,
        license_info=LicenseInfo(
            license_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            is_approved=True,
            risk_level=RiskLevel.LOW,
        ),
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=True,
            has_signed_commits=True,
            has_branch_protection=True,
            is_maintained=True,
        ),
    )

    score = scorer.score_dependency(dependency)

    assert score.maintainer_score == 1.0
    assert "Single maintainer" in score.factors
    assert "single maintainer" in TerminalFormatter()._format_leading_signals(score)


def test_missing_popularity_data_keeps_stale_and_maintenance_signals() -> None:
    """REGRESSION: unknown popularity does not silently mitigate abandonment risk."""
    scorer = RiskScorer()
    last_updated = datetime.now() - timedelta(days=500)
    base = DependencyMetadata(
        name="unknown-popularity",
        installed_version="1.0.0",
        last_updated=last_updated,
        security_metrics=SecurityMetrics(is_maintained=False),
    )
    empty_metrics = DependencyMetadata(
        name="unknown-popularity",
        installed_version="1.0.0",
        last_updated=last_updated,
        community_metrics=CommunityMetrics(),
        security_metrics=SecurityMetrics(is_maintained=False),
    )

    base_score = scorer.score_dependency(base)
    empty_metrics_score = scorer.score_dependency(empty_metrics)

    assert empty_metrics_score.staleness_score == base_score.staleness_score == 1.0
    assert empty_metrics_score.maintained_score == base_score.maintained_score == 1.0
    assert empty_metrics_score.total_score == base_score.total_score
    assert empty_metrics_score.factors == base_score.factors
    assert any("Not updated" in factor for factor in empty_metrics_score.factors)
    assert any(
        "Project does not appear to be actively maintained" in factor
        for factor in empty_metrics_score.factors
    )


def test_high_adoption_maintenance_signal_is_softened_in_terminal_formatter() -> None:
    """REGRESSION: quiet mature projects get a soft cadence label, not abandonment."""
    scorer = RiskScorer()
    dependency = DependencyMetadata(
        name="mature-stable",
        installed_version="1.0.0",
        latest_version="1.0.0",
        last_updated=datetime.now() - timedelta(days=500),
        maintainer_count=5,
        community_metrics=CommunityMetrics(star_count=5000),
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=True,
        license_info=LicenseInfo(
            license_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            is_approved=True,
            risk_level=RiskLevel.LOW,
        ),
        security_metrics=SecurityMetrics(is_maintained=False),
    )

    score = scorer.score_dependency(dependency)
    signals = TerminalFormatter()._format_leading_signals(score)

    assert score.staleness_score == 0.5
    assert score.maintained_score == 0.5
    assert "stable, low release cadence" in signals
    assert "not actively maintained" not in signals


def test_aggregate_ignores_unknown_signals() -> None:
    """Unknown signals are excluded from the weighted denominator."""
    scorer = RiskScorer(
        staleness_weight=1.0,
        maintainer_weight=1.0,
        deprecation_weight=1.0,
        exploit_weight=1.0,
        version_difference_weight=1.0,
        health_indicators_weight=1.0,
        license_weight=1.0,
        community_weight=1.0,
        transitive_weight=1.0,
        security_policy_weight=1.0,
        dependency_update_weight=1.0,
        signed_commits_weight=1.0,
        branch_protection_weight=1.0,
        max_score=5.0,
    )
    dep = DependencyMetadata(
        name="partial",
        installed_version="1.0.0",
        latest_version="2.0.0",
        last_updated=datetime.now() - timedelta(days=400),
    )

    score = scorer.score_dependency(dep)

    assert score.unknown_signal_count == 9
    assert score.measured_signal_count == 5
    assert score.insufficient_data is True
    assert score.total_score == 5.0 * (1.0 + 1.0) / 5.0


def test_info_and_withdrawn_vulnerabilities_do_not_raise_exploit_score() -> None:
    """Filtered low-value advisories should be visible but not scored."""
    dep = DependencyMetadata(name="noise-only", installed_version="1.0.0")
    vulnerabilities: List[Dict[str, object]] = [
        {
            "id": "OSV-INFO",
            "source": "OSV",
            "severity": "INFO",
            "summary": "Informational scanner result",
            "cvss_score": None,
            "fixed_versions": [],
            "references": [],
        },
        {
            "id": "OSV-WITHDRAWN",
            "source": "OSV",
            "severity": "CRITICAL",
            "withdrawn": True,
            "summary": "Withdrawn advisory",
            "cvss_score": 9.8,
            "fixed_versions": [],
            "references": [],
        },
    ]

    updated = _update_dependency_with_vulnerabilities(dep, vulnerabilities)
    score = RiskScorer().score_dependency(updated)

    assert score.exploit_score == 0.0
    assert updated.has_known_exploits is False
    assert updated.security_metrics is not None
    assert updated.security_metrics.vulnerability_count == 2
    assert updated.security_metrics.counted_vulnerability_count == 0
    assert updated.security_metrics.filtered_vulnerability_count == 2
    assert updated.security_metrics.filtered_vulnerability_reasons == {
        "informational": 1,
        "withdrawn": 1,
    }
    assert all(
        advisory["filtered"] is True
        for advisory in updated.security_metrics.vulnerability_details
    )


def test_critical_vulnerability_scores_higher_than_low() -> None:
    """Exploit scoring should be graduated by counted advisory severity."""
    scorer = RiskScorer()
    low = DependencyMetadata(
        name="low-vuln",
        installed_version="1.0.0",
        security_metrics=SecurityMetrics(
            vulnerability_count=1,
            counted_vulnerability_count=1,
            filtered_vulnerability_count=0,
            max_cvss_score=3.1,
            max_vulnerability_severity="LOW",
        ),
    )
    critical = DependencyMetadata(
        name="critical-vuln",
        installed_version="1.0.0",
        security_metrics=SecurityMetrics(
            vulnerability_count=1,
            counted_vulnerability_count=1,
            filtered_vulnerability_count=0,
            max_cvss_score=9.8,
            max_vulnerability_severity="CRITICAL",
        ),
    )

    low_score = scorer.score_dependency(low)
    critical_score = scorer.score_dependency(critical)

    assert low_score.exploit_score is not None
    assert critical_score.exploit_score is not None
    assert low_score.exploit_score < critical_score.exploit_score
    assert low_score.exploit_score == 0.2
    assert critical_score.exploit_score == 1.0


def test_vulnerability_minimum_severity_threshold_is_respected() -> None:
    """Configurable threshold should filter advisories below the selected tier."""
    dep = DependencyMetadata(name="thresholded", installed_version="1.0.0")
    vulnerabilities = [
        {
            "id": "OSV-MEDIUM",
            "source": "OSV",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
            "fixed_versions": [],
            "references": [],
        },
        {
            "id": "OSV-CRITICAL",
            "source": "OSV",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "fixed_versions": [],
            "references": [],
        },
    ]

    updated = _update_dependency_with_vulnerabilities(dep, vulnerabilities, "HIGH")

    assert updated.security_metrics is not None
    assert updated.security_metrics.vulnerability_count == 2
    assert updated.security_metrics.counted_vulnerability_count == 1
    assert updated.security_metrics.filtered_vulnerability_count == 1
    assert updated.security_metrics.filtered_vulnerability_reasons == {
        "below high threshold": 1
    }
    assert updated.security_metrics.max_vulnerability_severity == "CRITICAL"


def test_vulnerability_counts_are_reported_in_terminal_and_json() -> None:
    """Report output should include total, counted, and filtered vuln counts."""
    dep = DependencyMetadata(name="reported", installed_version="1.0.0")
    updated = _update_dependency_with_vulnerabilities(
        dep,
        [
            {
                "id": "OSV-LOW",
                "source": "OSV",
                "severity": "LOW",
                "cvss_score": 3.1,
                "fixed_versions": [],
                "references": [],
            },
            {
                "id": "OSV-INFO",
                "source": "OSV",
                "severity": "INFO",
                "cvss_score": None,
                "fixed_versions": [],
                "references": [],
            },
        ],
    )
    profile = RiskScorer().create_project_profile(
        "requirements.txt", "python", {"reported": updated}
    )

    terminal_output = TerminalFormatter(color=False).format_profile(profile)
    json_output = JsonFormatter().format_profile(profile)

    assert "1 scored · 1 filtered" in terminal_output
    assert "2/1 score 1 filt" not in terminal_output
    assert '"total_found": 2' in json_output
    assert '"counted_in_score": 1' in json_output
    assert '"filtered": 1' in json_output
    assert '"filtered": true' in json_output
