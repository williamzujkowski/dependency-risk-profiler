"""An unresolved transitive set is unmeasured, not zero (issues #128, #199).

``analyze_transitive_dependencies_enhanced`` only knows npm lockfiles and Python
requirement sets. For a Maven, NuGet, Ruby, Composer, or Cargo manifest it used
to log ``Could not extract dependency map`` and leave every dependency with an
empty transitive set — which the scorer then read as a confident "no transitive
dependencies, therefore no transitive risk". That is exactly the fabricated-zero
that #74 exists to prevent.

#128 marked those cases explicitly and left the *default* alone, so the
guarantee only held for code paths someone remembered to annotate. #199 closed
that: an unset marker now reads as unmeasured. The tests at the bottom of this
file are the ones that fail if the default is ever flipped back — including the
one that matters most, where a brand-new adapter records nothing at all and
must not thereby claim a measured zero for every package in its ecosystem.
"""

import inspect
from typing import Dict

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    TRANSITIVE_SOURCE_UNMEASURED,
    transitive_is_measured,
)
from dependency_risk_profiler.transitive.analyzer_enhanced import (
    analyze_transitive_dependencies_enhanced,
    record_transitive_source,
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


# --- #199: silence cannot fabricate a measurement --------------------------


class SilentAnalyzer(BaseAnalyzer):
    """The ninth adapter, written by someone who never heard of this field.

    It collects whatever its registry answers and says nothing about transitive
    dependencies, because its registry does not publish them — which is the
    normal case for five of the eight adapters that exist today.
    """

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Return the dependencies with a version filled in and nothing else.

        Args:
            dependencies: Dependencies to analyze.

        Returns:
            The same dependencies, with no transitive claim made.
        """
        for dependency in dependencies.values():
            dependency.latest_version = "9.9.9"
        return dependencies


def test_a_silent_adapter_cannot_fabricate_a_measured_zero() -> None:
    """REGRESSION #199: recording nothing yields UNMEASURED, never 0.0.

    This is the acceptance criterion, and it is deliberately written against an
    adapter that does not exist in the tree. The bug it guards is not "adapter X
    forgot the marker" — it is that forgetting was survivable, silently, because
    a fabricated ``0.0`` is a perfectly plausible score with no test to
    contradict it. PR #198 caught Maven one typo away from exactly that.
    """
    dependency = DependencyMetadata(name="ninth-eco/pkg", installed_version="1.0.0")

    analyzed = SilentAnalyzer().analyze({dependency.name: dependency})[dependency.name]
    score = RiskScorer().score_dependency(analyzed)

    assert analyzed.transitive_source is None, "the adapter said nothing, by design"
    assert score.transitive_score is None, (
        "a silent adapter fabricated a transitive score; the fail-open default "
        "is back and every dependency in its ecosystem now reports a confident "
        "'no transitive risk' nobody measured"
    )
    assert "transitive" in score.unknown_signals


def test_the_default_read_is_unmeasured() -> None:
    """The one-line statement of #199, at the seam the scorer reads."""
    assert transitive_is_measured(None) is False
    assert transitive_is_measured(TRANSITIVE_SOURCE_UNMEASURED) is False
    assert transitive_is_measured("maven-pom") is True


def test_the_recorder_cannot_be_called_without_saying_what_measured_it() -> None:
    """``source`` is keyword-only and defaultless, the #189 shape.

    A default here would put the fail-open back one call site at a time: a new
    adapter calls ``record_transitive_source(dep)``, gets whatever the default
    says, and no reviewer sees an argument that is not there.
    """
    parameter = inspect.signature(record_transitive_source).parameters["source"]

    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


def test_an_unvouched_set_is_not_evidence() -> None:
    """A populated set with no source marker does not score either.

    The fabricated zero is the loud half of #199; this is the quiet half. Data
    that arrived from nowhere in particular is not a measurement, and the
    scorer declines it rather than guessing which resolver to credit.
    """
    dependency = DependencyMetadata(name="a:b", installed_version="1.0.0")
    dependency.transitive_dependencies = {"x", "y", "z"}

    unvouched = RiskScorer().score_dependency(dependency)
    record_transitive_source(dependency, source="manifest")
    vouched = RiskScorer().score_dependency(dependency)

    assert unvouched.transitive_score is None
    assert vouched.transitive_score == 0.1
