"""Cross-ecosystem score-comparability guarantees (#74).

Different ecosystems supply different signal subsets (Go has no maintainer
concept, crates.io no deprecation field, deps.dev is absent for some). The
scorer already normalizes for this: an unmeasured component is excluded from
BOTH the weighted numerator and the denominator (renormalized over available
weights), so a missing signal is treated as "unavailable", never as a confident
zero that would make a sparsely-covered package look lower-risk. And when more
than half the signals are unknown, the risk LEVEL is reported UNKNOWN rather
than a falsely-confident value. These tests lock those properties so the
per-ecosystem adapter work (#72) can't regress cross-ecosystem comparability.
"""

from dependency_risk_profiler.models import DependencyMetadata, RiskLevel
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer


def test_sparse_data_reports_unknown_not_a_confident_level() -> None:
    """A dependency with almost no measurable signals is UNKNOWN, not confident."""
    scorer = RiskScorer()
    dep = DependencyMetadata(name="sparse", installed_version="1.0.0")

    score = scorer.score_dependency(dep)

    assert score.risk_level == RiskLevel.UNKNOWN
    assert any("Insufficient data" in factor for factor in score.factors)


def test_missing_signals_are_excluded_not_scored_as_zero() -> None:
    """A lone strong risk signal stays elevated; missing signals don't dilute it.

    If unmeasured components were scored 0, the exploit signal would be dragged
    toward 0 by the dozen missing signals. Renormalization over available
    weights keeps the score reflective of what was actually measured.
    """
    scorer = RiskScorer()
    exploited = DependencyMetadata(
        name="exploited", installed_version="1.0.0", has_known_exploits=True
    )
    clean = DependencyMetadata(
        name="clean", installed_version="1.0.0", has_known_exploits=False
    )

    exploited_score = scorer.score_dependency(exploited)
    clean_score = scorer.score_dependency(clean)

    # Same (sparse) signal coverage; the only difference is the exploit flag,
    # which must move the score materially rather than being averaged into
    # near-zero by the missing signals.
    assert exploited_score.total_score > clean_score.total_score + 1.0


def test_total_score_stays_in_range_regardless_of_coverage() -> None:
    """Normalization keeps the score bounded no matter how sparse the data."""
    scorer = RiskScorer()
    for dep in (
        DependencyMetadata(name="empty", installed_version="1.0.0"),
        DependencyMetadata(
            name="one-signal", installed_version="1.0.0", has_known_exploits=True
        ),
    ):
        score = scorer.score_dependency(dep)
        assert 0.0 <= score.total_score <= scorer.max_score
