"""An unresolved transitive set is unmeasured, not zero (issue #128).

``analyze_transitive_dependencies_enhanced`` only knows npm lockfiles and Python
requirement sets. For a Maven, NuGet, Ruby, Composer, or Cargo manifest it used
to log ``Could not extract dependency map`` and leave every dependency with an
empty transitive set — which the scorer then read as a confident "no transitive
dependencies, therefore no transitive risk". That is exactly the fabricated-zero
that #74 exists to prevent.
"""

from typing import Dict

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import TRANSITIVE_SOURCE_UNMEASURED
from dependency_risk_profiler.transitive.analyzer_enhanced import (
    analyze_transitive_dependencies_enhanced,
)


def _dependencies() -> Dict[str, DependencyMetadata]:
    """Return one collected dependency and one nobody resolved."""
    measured = DependencyMetadata(
        name="com.google.guava:guava", installed_version="33.0.0-jre"
    )
    measured.transitive_dependencies = {"com.google.guava:failureaccess"}
    measured.transitive_source = "maven-pom"
    return {
        "com.google.guava:guava": measured,
        "org.jsoup:jsoup": DependencyMetadata(
            name="org.jsoup:jsoup", installed_version="1.17.2"
        ),
    }


def test_unsupported_manifest_marks_transitive_unmeasured(tmp_path: str) -> None:
    """REGRESSION #128: no dependency map means unmeasured, not empty."""
    pom = f"{tmp_path}/pom.xml"

    result = analyze_transitive_dependencies_enhanced(_dependencies(), pom)

    assert result["org.jsoup:jsoup"].transitive_source == TRANSITIVE_SOURCE_UNMEASURED
    # What the ecosystem analyzer already collected is left alone.
    assert result["com.google.guava:guava"].transitive_source == "maven-pom"
    assert result["com.google.guava:guava"].transitive_dependencies == {
        "com.google.guava:failureaccess"
    }


def test_unmeasured_transitive_is_excluded_from_the_score() -> None:
    """An unmeasured signal leaves both numerator and denominator (#74)."""
    scorer = RiskScorer()
    unmeasured = DependencyMetadata(name="a:b", installed_version="1.0.0")
    unmeasured.transitive_source = TRANSITIVE_SOURCE_UNMEASURED

    score = scorer.score_dependency(unmeasured)

    assert score.transitive_score is None
    assert "transitive" in score.unknown_signals


def test_measured_empty_transitive_still_scores_zero() -> None:
    """Looking and finding nothing is a real result, and still scores 0.0."""
    scorer = RiskScorer()
    looked = DependencyMetadata(name="a:b", installed_version="1.0.0")
    looked.transitive_source = "manifest"

    score = scorer.score_dependency(looked)

    assert score.transitive_score == 0.0
    assert "transitive" not in score.unknown_signals
