"""Tests for the risk scoring system."""
from datetime import datetime, timedelta


from dependency_risk_profiler.models import DependencyMetadata, RiskLevel
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer


def test_scoring_system():
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
    assert low_risk_score.risk_level == RiskLevel.LOW
    assert low_risk_score.total_score < 2.0
    
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
    assert medium_risk_score.risk_level == RiskLevel.MEDIUM
    assert medium_risk_score.total_score > 2.0
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
    assert high_risk_score.risk_level == RiskLevel.HIGH
    assert high_risk_score.total_score > 3.5
    
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
    assert critical_risk_score.risk_level == RiskLevel.CRITICAL
    assert critical_risk_score.total_score > 4.0


def test_risk_factors():
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


def test_partial_data():
    """Test scoring with partial data."""
    # Create a risk scorer with default weights
    scorer = RiskScorer()
    
    # Test a dependency with minimal data
    dep = DependencyMetadata(
        name="partial-data",
        installed_version="1.0.0",
    )
    
    score = scorer.score_dependency(dep)
    
    # Score should still be calculated even with minimal data
    assert score.total_score > 0
    assert score.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]