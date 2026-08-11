"""Tests for the risk scoring system."""

from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple, TypedDict, cast

from dependency_risk_profiler.cli.formatter import JsonFormatter, TerminalFormatter
from dependency_risk_profiler.contract import scored_dependency
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    LicenseCategory,
    LicenseInfo,
    ProjectRiskProfile,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import AdvisoryLookupState
from dependency_risk_profiler.vulnerabilities.aggregator import (
    _update_dependency_with_vulnerabilities,
)


def _lookup_completed(dependency: DependencyMetadata) -> DependencyMetadata:
    """Record the advisory lookup a scored dependency is assumed to have had.

    A fixture that wants a measured exploit signal has to say that every
    advisory source it asked answered, because the alternative — leaving the
    state alone — means nobody asked, and the scorer then reports the signal
    unmeasured rather than handing it ``has_known_exploits``'s ``False``
    (#321).

    Args:
        dependency: The metadata under test.

    Returns:
        The same object, so it can be wrapped around a constructor call.
    """
    dependency.record_advisory_lookup(
        AdvisoryLookupState.COMPLETE, sources_unavailable=()
    )
    return dependency


def test_scoring_system() -> None:
    """Test the risk scoring system."""
    # Create a risk scorer with default weights
    scorer = RiskScorer()

    # Test a low-risk dependency. Each fixture states that its tree *was*
    # resolved and came back empty, which is what the pipeline records for a
    # supported manifest. Before #199 the fixtures got that for free by saying
    # nothing, and the free signal was load-bearing: it is what kept the
    # low-risk case one measured signal clear of the insufficient-data bar.
    low_risk = _lookup_completed(
        DependencyMetadata(
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
            transitive_source="manifest",
        )
    )

    low_risk_score = scorer.score_dependency(low_risk)
    # The risk level might vary based on the scoring implementation
    # Just ensure it's not high or critical
    assert low_risk_score.risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM]
    assert low_risk_score.total_score < 3.0

    # Test a medium-risk dependency
    medium_risk = _lookup_completed(
        DependencyMetadata(
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
            transitive_source="manifest",
        )
    )

    medium_risk_score = scorer.score_dependency(medium_risk)
    # Missing enhanced metadata is excluded instead of scored as moderate risk.
    assert medium_risk_score.risk_level == RiskLevel.LOW
    assert medium_risk_score.unknown_signal_count == 7
    assert medium_risk_score.total_score < 3.5

    # Test a high-risk dependency
    high_risk = _lookup_completed(
        DependencyMetadata(
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
            transitive_source="manifest",
        )
    )

    high_risk_score = scorer.score_dependency(high_risk)
    # Missing enhanced metadata is not scored as extra risk.
    assert high_risk_score.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH]
    # The exact score may vary, just ensure it's higher than medium risk
    assert high_risk_score.total_score > medium_risk_score.total_score

    # Test a critical-risk dependency
    critical_risk = _lookup_completed(
        DependencyMetadata(
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
            transitive_source="manifest",
        )
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
    dep = _lookup_completed(
        DependencyMetadata(
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
    # Every weighed signal, because a bare manifest entry establishes nothing:
    # nothing resolved the tree (#199), nobody asked an advisory source (#321),
    # and no registry answered the deprecation question (#320).
    assert score.unknown_signal_count == 14
    for silent in ("staleness", "transitive", "maintainer", "version"):
        assert silent in score.unknown_signals


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
        # No registry answered whether this package is retired, and a `bool`
        # field could only have said "affirmatively not" (#320).
        "deprecation",
        # Nobody asked an advisory source anything, and an unrecorded lookup
        # used to read as one that answered clean (#321).
        "exploit",
        "version",
        "health_indicators",
        # ``license`` is absent: it is measured and published on its own axis,
        # so it is in neither the weighted set nor the gaps in it (#340).
        "community_popularity",
        "community_activity",
        # Nothing resolved this dependency's tree, and since #199 saying
        # nothing no longer counts as having looked.
        "transitive",
        "security_policy",
        "dependency_update",
        "signed_commits",
        "branch_protection",
        "maintained",
    ]


def test_stars_alone_do_not_pass_as_a_measured_community_signal() -> None:
    """Popularity without cadence is half a signal, and says so (#166).

    ``community_score`` used to be the star bucket wearing a composite's name:
    ``commit_frequency`` was never produced, so the cadence half silently
    vanished and the remaining half carried the full community weight.
    """
    scorer = RiskScorer()
    dep = DependencyMetadata(
        name="popular-but-unclonable",
        installed_version="1.0.0",
        community_metrics=CommunityMetrics(star_count=50_000),
    )

    score = scorer.score_dependency(dep)

    # The measured half is still reported — an unmeasurable cadence does not
    # discard a known star count.
    assert score.community_score == 0.0
    assert "community_popularity" not in score.unknown_signals
    # But the unmeasured half is named, not quietly averaged away.
    assert "community_activity" in score.unknown_signals


def test_measured_cadence_moves_the_community_score() -> None:
    """A well-starred package with a dead commit log is not a 0.0 (#166)."""
    scorer = RiskScorer()
    popular = CommunityMetrics(star_count=50_000)
    popular_and_dead = CommunityMetrics(star_count=50_000, commit_frequency=0.1)

    assert scorer._calculate_popularity_score(popular) == 0.0
    assert scorer._calculate_development_activity_score(popular) is None
    assert scorer._calculate_development_activity_score(popular_and_dead) == 1.0

    dep = DependencyMetadata(
        name="starred-and-stalled",
        installed_version="1.0.0",
        community_metrics=popular_and_dead,
    )
    score = scorer.score_dependency(dep)

    assert score.community_score == 0.5
    assert "community_activity" not in score.unknown_signals
    # The risk factor gates on the cadence half, not on the average, which
    # lands on exactly 0.5 and would clear no `> 0.5` threshold.
    assert "Low development activity (0.1 commits/month)" in score.factors


def test_full_data_scoring_is_unchanged() -> None:
    """Measured full-data signals keep their calibrated component scores."""
    scorer = RiskScorer()
    dep = _lookup_completed(
        DependencyMetadata(
            name="full-data",
            installed_version="1.0.0",
            latest_version="1.1.0",
            last_updated=datetime.now() - timedelta(days=120),
            maintainer_count=2,
            # Full data means every signal has an answer behind it, and for
            # these two the answer is a recorded state rather than a value: a
            # registry that says the package is live, and an advisory lookup
            # every source answered.
            is_deprecated=False,
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
                commit_frequency=5.0,
            ),
            transitive_dependencies={"a", "b", "c", "d", "e"},
            # A populated set with no source marker is data of unknown origin,
            # and since #199 the scorer declines to score it rather than
            # assuming someone looked.
            transitive_source="manifest",
            security_metrics=SecurityMetrics(
                has_security_policy=True,
                has_dependency_update_tools=True,
                has_signed_commits=True,
                has_branch_protection=True,
                is_maintained=True,
            ),
        )
    )

    score = scorer.score_dependency(dep)

    assert score.unknown_signals == []
    assert score.insufficient_data is False
    assert score.staleness_score == 0.5
    assert score.maintainer_score == 0.5
    assert score.version_score == 0.5
    assert round(score.health_indicators_score or 0.0, 2) == 0.67
    assert score.license_score == 0.0
    assert round(score.community_score or 0.0, 2) == 0.25
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
    dependency = _lookup_completed(
        DependencyMetadata(
            name="mature-stable",
            installed_version="1.0.0",
            latest_version="1.0.0",
            last_updated=datetime.now() - timedelta(days=500),
            maintainer_count=5,
            community_metrics=CommunityMetrics(star_count=5000),
            is_deprecated=False,
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

    # Two measured, not five: three signals leave the denominator rather than
    # contributing a fabricated 0.0 apiece — nothing resolved this
    # dependency's tree (#199), nobody asked an advisory source (#321), and no
    # registry answered the deprecation question (#320). Dropping those zeros
    # *raises* the reported risk from 2.0 to 5.0 — the same two risky signals,
    # now over an honest denominator, which is the direction this rule always
    # moves a score and the reason it has to be argued rather than assumed.
    assert score.unknown_signal_count == 12
    assert score.measured_signal_count == 2
    assert score.insufficient_data is True
    assert score.total_score == 5.0 * (1.0 + 1.0) / 2.0


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


def _zero_weight_scorer(**overrides: float) -> RiskScorer:
    """Build a scorer with every weight zeroed except the ones passed in.

    Lets a test isolate a single signal's contribution so the renormalized
    (#74) total reflects only the weights under test.
    """
    weights: Dict[str, float] = {
        "staleness_weight": 0.0,
        "maintainer_weight": 0.0,
        "deprecation_weight": 0.0,
        "exploit_weight": 0.0,
        "version_difference_weight": 0.0,
        "health_indicators_weight": 0.0,
        "community_weight": 0.0,
        "transitive_weight": 0.0,
        "security_policy_weight": 0.0,
        "dependency_update_weight": 0.0,
        "signed_commits_weight": 0.0,
        "branch_protection_weight": 0.0,
        "maintained_weight": 0.0,
    }
    weights.update(overrides)
    return RiskScorer(**weights)


def test_maintained_weight_defaults_to_020_and_is_independent() -> None:
    """#104: the maintained signal owns a dedicated, separately tunable weight."""
    scorer = RiskScorer()

    assert scorer.maintained_weight == 0.20
    # It must not be an alias of branch_protection_weight.
    assert scorer.maintained_weight is not scorer.branch_protection_weight
    assert scorer.branch_protection_weight == 0.15


def test_each_weighted_score_maps_to_its_own_weight_attribute() -> None:
    """#116 (score drift): every signal contributes at its OWN weight attribute.

    For each signal we build a scorer whose only non-zero weight is that
    signal's dedicated attribute and a dependency that measures only that one
    signal (risk 1.0). Under #74 renormalization the total then collapses to
    ``max_score`` iff the signal is wired to the weight we set. This locks the
    shipped bug where ``maintained`` reused ``branch_protection_weight``: with
    ``branch_protection_weight=0`` the buggy wiring would zero maintained out.
    """
    # signal name -> (weight kwarg, a SecurityMetrics with exactly that signal
    # reading risky). Written as constructor calls rather than field-name
    # strings so mypy checks each field actually exists on SecurityMetrics.
    security_signals: Dict[str, Tuple[str, Callable[[], SecurityMetrics]]] = {
        "security_policy": (
            "security_policy_weight",
            lambda: SecurityMetrics(has_security_policy=False),
        ),
        "dependency_update": (
            "dependency_update_weight",
            lambda: SecurityMetrics(has_dependency_update_tools=False),
        ),
        "signed_commits": (
            "signed_commits_weight",
            lambda: SecurityMetrics(has_signed_commits=False),
        ),
        "branch_protection": (
            "branch_protection_weight",
            lambda: SecurityMetrics(has_branch_protection=False),
        ),
        "maintained": (
            "maintained_weight",
            lambda: SecurityMetrics(is_maintained=False),
        ),
    }

    for name, (weight_kwarg, risky_metrics) in security_signals.items():
        scorer = _zero_weight_scorer(**{weight_kwarg: 1.0})
        dep = DependencyMetadata(
            name=f"only-{name}",
            installed_version="1.0.0",
            # A risky reading (False) for exactly one security signal; all other
            # signals stay None (unmeasured) and drop out of the denominator.
            security_metrics=risky_metrics(),
        )

        score = scorer.score_dependency(dep)

        # The only non-zero-weight signal is the one under test, and it reads
        # 1.0, so the renormalized total collapses to max_score iff that signal
        # is wired to the weight we set (deprecation/exploit/transitive are
        # always measured but carry weight 0, so they cannot shift the ratio).
        assert name not in score.unknown_signals
        assert (
            score.total_score == scorer.max_score
        ), f"signal '{name}' is not wired to '{weight_kwarg}'"


def test_branch_protection_and_maintained_contribute_at_independent_weights() -> None:
    """#116: both OpenSSF signals present -> each adds at its own weight."""
    scorer = _zero_weight_scorer(
        branch_protection_weight=0.15,
        maintained_weight=0.20,
    )
    # Only maintained is risky; branch_protection is measured but clean.
    dep = DependencyMetadata(
        name="both-signals",
        installed_version="1.0.0",
        security_metrics=SecurityMetrics(
            has_branch_protection=True,  # clean -> 0.0
            is_maintained=False,  # risky -> 1.0
        ),
    )

    score = scorer.score_dependency(dep)

    # Renormalized over the two measured weights: 0.20 / (0.15 + 0.20) * max.
    expected = (0.20 / (0.15 + 0.20)) * scorer.max_score
    assert score.total_score == expected
    # Under the shipped bug maintained would reuse 0.15, giving 0.15/0.30*max.
    assert score.total_score != (0.15 / (0.15 + 0.15)) * scorer.max_score


class _HealthySignals(TypedDict):
    """The non-security ``DependencyMetadata`` kwargs shared by two fixtures.

    Spelled as a ``TypedDict`` rather than a bare ``dict`` so that ``**common``
    is checked against the real constructor signature; a plain dict literal
    widens to ``dict[str, object]`` and the splat stops meaning anything.
    """

    installed_version: str
    latest_version: str
    last_updated: datetime
    maintainer_count: int
    has_tests: bool
    has_ci: bool
    has_contribution_guidelines: bool
    license_info: LicenseInfo


def test_missing_maintained_signal_leaves_other_packages_unchanged() -> None:
    """#116: #74 renormalization is missing-signal invariant for maintained."""
    scorer = RiskScorer()
    common: _HealthySignals = dict(
        installed_version="1.0.0",
        latest_version="1.0.0",
        last_updated=datetime.now(timezone.utc) - timedelta(days=15),
        maintainer_count=5,
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=True,
        license_info=LicenseInfo(
            license_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            is_approved=True,
            risk_level=RiskLevel.LOW,
        ),
    )
    with_maintained = DependencyMetadata(
        name="has-maintained",
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=True,
            has_signed_commits=True,
            has_branch_protection=True,
            is_maintained=True,
        ),
        **common,
    )
    without_maintained = DependencyMetadata(
        name="no-maintained",
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=True,
            has_signed_commits=True,
            has_branch_protection=True,
            # is_maintained left None -> signal absent
        ),
        **common,
    )

    with_score = scorer.score_dependency(with_maintained)
    without_score = scorer.score_dependency(without_maintained)

    # The maintained reading here is 0.0 (clean), so dropping it changes neither
    # the numerator nor the outcome for the other, fully-measured signals.
    assert "maintained" not in with_score.unknown_signals
    assert "maintained" in without_score.unknown_signals
    assert without_score.total_score == with_score.total_score


def test_hyphenated_prerelease_scored_by_real_version_distance() -> None:
    """#106: a hyphenated prerelease is not flattened to the 0.25 range default."""
    scorer = RiskScorer()
    # 2.0.0-beta is two majors behind 4.0.0 -> should read as major-version risk.
    dep = DependencyMetadata(
        name="prerelease-behind",
        installed_version="2.0.0-beta",
        latest_version="4.0.0",
    )

    score = scorer.score_dependency(dep)

    assert score.version_score is not None
    assert score.version_score > 0.25
    assert score.version_score == 1.0

    # Go-style pseudo-versions also carry a hyphen. They are not PEP 440 so they
    # no longer short-circuit to the 0.25 range default; they now fall through to
    # the parser's moderate-distance handling (0.5) instead of being flattened.
    go_dep = DependencyMetadata(
        name="go-pseudo",
        installed_version="1.0.0-20230101000000-abcdefabcdef",
        latest_version="3.0.0",
    )
    go_score = scorer.score_dependency(go_dep)
    assert go_score.version_score is not None
    assert go_score.version_score > 0.25


def test_staleness_is_computed_in_utc_regardless_of_timestamp_tz() -> None:
    """#111: the same instant scores identically no matter its tz representation."""
    scorer = RiskScorer()
    # One fixed instant, 200 days ago, expressed in two different time zones.
    instant_utc = datetime.now(timezone.utc) - timedelta(days=200)
    instant_offset = instant_utc.astimezone(timezone(timedelta(hours=9)))

    utc_dep = DependencyMetadata(
        name="utc-stamp", installed_version="1.0.0", last_updated=instant_utc
    )
    offset_dep = DependencyMetadata(
        name="offset-stamp", installed_version="1.0.0", last_updated=instant_offset
    )

    utc_score = scorer.score_dependency(utc_dep)
    offset_score = scorer.score_dependency(offset_dep)

    assert utc_score.staleness_score == offset_score.staleness_score
    # 200 days -> the 180-365 day band.
    assert utc_score.staleness_score == 0.75

    # A naive timestamp is treated as UTC rather than crashing on the diff.
    naive_dep = DependencyMetadata(
        name="naive-stamp",
        installed_version="1.0.0",
        last_updated=instant_utc.replace(tzinfo=None),
    )
    assert scorer.score_dependency(naive_dep).staleness_score == 0.75


def test_critical_vulnerability_scores_higher_than_low() -> None:
    """Exploit scoring should be graduated by counted advisory severity."""
    scorer = RiskScorer()
    low = _lookup_completed(
        DependencyMetadata(
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
    )
    critical = _lookup_completed(
        DependencyMetadata(
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


def _dependency_with_license(license_info: Optional[LicenseInfo]) -> DependencyMetadata:
    """Return one identical dependency, differing only in its declared licence.

    Args:
        license_info: The licence to attach, or None for a package whose
            licence was never read.

    Returns:
        Metadata with every other input held fixed.
    """
    dependency = _lookup_completed(
        DependencyMetadata(
            name="license-varied",
            installed_version="1.0.0",
            latest_version="1.2.0",
            last_updated=datetime.now(timezone.utc) - timedelta(days=200),
            maintainer_count=2,
            is_deprecated=False,
            has_known_exploits=False,
            has_tests=True,
            has_ci=True,
            has_contribution_guidelines=False,
            transitive_source="manifest",
        )
    )
    dependency.license_info = license_info
    return dependency


#: Every licence the analyzer can produce, worst to best, plus the unread case.
#: Spanning the whole range matters: a weight reintroduced at any size separates
#: at least one of these pairs.
_LICENSE_VARIANTS: List[Optional[LicenseInfo]] = [
    None,
    LicenseInfo(
        license_id="MIT",
        category=LicenseCategory.PERMISSIVE,
        is_approved=True,
        risk_level=RiskLevel.LOW,
    ),
    LicenseInfo(
        license_id="GPL-3.0-only",
        category=LicenseCategory.COPYLEFT,
        is_approved=False,
        risk_level=RiskLevel.HIGH,
    ),
    LicenseInfo(
        license_id="AGPL-3.0-only",
        category=LicenseCategory.NETWORK_COPYLEFT,
        is_approved=False,
        risk_level=RiskLevel.CRITICAL,
    ),
    LicenseInfo(
        license_id="LicenseRef-Proprietary",
        category=LicenseCategory.COMMERCIAL,
        is_approved=False,
        risk_level=RiskLevel.CRITICAL,
    ),
]


def test_the_licence_contributes_nothing_to_the_composite() -> None:
    """REGRESSION #340: the licence axis is reported, never weighed.

    A licence states an obligation a consumer takes on. It is not a forecast of
    how a package will be maintained, and the one outcome it has been measured
    against it predicted backwards — removing it raised the composite's
    discrimination in all seven abandonment ablations, every clustered interval
    excluding zero.

    Only the licence varies here, across the whole range the analyzer can
    produce. Every derived number must be bit-identical: the weighted mean, the
    verdict, the measured count and the set of gaps. A weight reintroduced at
    any size separates at least one of these pairs.
    """
    scores = [
        RiskScorer().score_dependency(_dependency_with_license(variant))
        for variant in _LICENSE_VARIANTS
    ]
    baseline = scores[0]

    assert {score.license_score for score in scores} != {None}, (
        "the licence must still be measured, or this test would pass on a "
        "scorer that had simply stopped reading it"
    )
    for score in scores[1:]:
        assert score.total_score == baseline.total_score
        assert score.risk_level is baseline.risk_level
        assert score.measured_signal_count == baseline.measured_signal_count
        assert score.total_signal_count == baseline.total_signal_count
        assert score.unknown_signals == baseline.unknown_signals
        assert score.factors == baseline.factors


def test_the_licence_is_still_reported_when_it_is_not_scored() -> None:
    """Unscored is not unpublished. The finding has to survive the change.

    Its own key beside ``risk_level`` in the contract, its own measurement in
    ``signals``, and the identifier in the terminal table's LICENSE column.
    Without this the test above is satisfied by deleting the licence.
    """
    flagged = _dependency_with_license(_LICENSE_VARIANTS[3])
    score = RiskScorer().score_dependency(flagged)

    entry = scored_dependency(score, ecosystem="python")
    assert entry["license_flagged"] is True
    assert cast(Dict[str, object], entry["license"])["id"] == "AGPL-3.0-only"
    signals = cast(Dict[str, object], entry["signals"])
    assert cast(Dict[str, object], signals["license"])["state"] == "measured"

    permissive = RiskScorer().score_dependency(
        _dependency_with_license(_LICENSE_VARIANTS[1])
    )
    assert scored_dependency(permissive, ecosystem="python")["license_flagged"] is False

    profile = ProjectRiskProfile(
        manifest_path="requirements.txt",
        ecosystem="python",
        dependencies=[score],
    )
    rendered = TerminalFormatter(color=False).format_profile(profile)
    assert "LICENSE" in rendered
    assert "AGPL-3.0-only · network copyleft" in rendered
