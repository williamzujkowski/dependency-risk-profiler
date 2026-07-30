"""Tests for the risk scoring system."""

from datetime import datetime, timedelta

from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    LicenseCategory,
    LicenseInfo,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer


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
