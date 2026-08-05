"""Risk scoring for dependencies."""

import logging
from datetime import datetime, timezone
from typing import Collection, Dict, FrozenSet, List, Optional, Sequence, Tuple

from packaging import version

from ..models import (
    RISK_LEVEL_ORDER,
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
    LicenseInfo,
    ProjectRiskProfile,
    RiskLevel,
    SecurityMetrics,
    VerdictFloor,
)
from ..popularity import (
    POPULARITY_HIGH_CONTRIBUTORS_DEFAULT,
    POPULARITY_HIGH_STARS_DEFAULT,
    STALENESS_POPULARITY_DAMPENING_DEFAULT,
    should_soften_low_release_cadence,
)
from ..signals import (
    ADVISORY_LOOKUP_DEGRADED,
    SIGNAL_BRANCH_PROTECTION,
    SIGNAL_COMMUNITY_ACTIVITY,
    SIGNAL_COMMUNITY_POPULARITY,
    SIGNAL_DEPENDENCY_UPDATE,
    SIGNAL_DEPRECATION,
    SIGNAL_EXPLOIT,
    SIGNAL_HEALTH_INDICATORS,
    SIGNAL_LICENSE,
    SIGNAL_MAINTAINED,
    SIGNAL_MAINTAINER,
    SIGNAL_SECURITY_POLICY,
    SIGNAL_SIGNED_COMMITS,
    SIGNAL_SOURCE_REPOSITORY,
    SIGNAL_STALENESS,
    SIGNAL_TRANSITIVE,
    SIGNAL_VERSION,
    SOURCE_REPOSITORY_UNREADABLE,
    AdvisoryLookupState,
    Measurement,
    MeasurementState,
    SourceRepositoryState,
    UnmeasuredReason,
    advisory_lookup_is_measured,
    transitive_is_measured,
    unmeasured_reason_for,
)
from ..versioning import (
    calendar_drift_days,
    release_timestamps,
    uses_calendar_versioning,
)
from ..vulnerabilities.aggregator import (
    MALICIOUS_SEVERITY,
    exploit_score_from_cvss,
    exploit_score_from_severity,
)

logger = logging.getLogger(__name__)

# The two halves of the community signal. Split apart so a measured popularity
# cannot carry an unmeasured cadence (#166), but a package we have no community
# data for at all is still one gap rather than two — the #146 rule.
COMMUNITY_SIGNALS: FrozenSet[str] = frozenset(
    {SIGNAL_COMMUNITY_POPULARITY, SIGNAL_COMMUNITY_ACTIVITY}
)

# What "declared a source repository that is not a reachable git forge" scores.
# Deliberately near the undeclared end: the auditable consequence is the same
# (no source to read), and the discount is for the declaration itself, which is
# real evidence about the package's publishing hygiene and its era. See
# ``_calculate_source_repository_score`` for the argument (#176).
SOURCE_REPOSITORY_UNUSABLE_SCORE = 0.75

# Advisory severity tiers read as verdict rungs. The vocabularies are the same
# four words on purpose; this is the only place that says so.
SEVERITY_AS_RISK_LEVEL: Dict[str, RiskLevel] = {
    "LOW": RiskLevel.LOW,
    "MEDIUM": RiskLevel.MEDIUM,
    "HIGH": RiskLevel.HIGH,
    "CRITICAL": RiskLevel.CRITICAL,
}

#: What the exploit signal is worth for a package whose counted advisories all
#: state no severity. Derived from the ``LOW`` contribution rather than written
#: as a number, so the two cannot drift: it is a **floor** — "a live advisory
#: exists, and no publisher has said it is worse than the mildest thing on this
#: scale" — and deliberately not a claim that the advisory is LOW. The
#: alternative, 0.0, is the value a package with no advisories at all carries,
#: and this signal has the largest single weight in the mean (#272).
ADVISORY_WITHOUT_SEVERITY_EXPLOIT_FLOOR = exploit_score_from_severity("LOW")


def severity_floor(max_counted_severity: str) -> Optional[RiskLevel]:
    """Return the verdict a live advisory of this severity forbids sitting below.

    **One rung under the worst counted advisory**, clamped at the bottom of the
    scale. Derived from :data:`~..models.RISK_LEVEL_ORDER` rather than written
    out as a table, so the rule and the mapping cannot drift apart.

    The one rung of slack is the whole of the argument, so it is stated here
    rather than left to be re-derived. Advisory severity is a property of the
    vulnerability considered alone — a CVSS base tier, with no environmental
    context — while the verdict is a property of the package in *this* tree,
    and whether the vulnerable path is reachable from the caller is something
    this tool does not measure and does not claim to. One rung is what that
    unmeasured context is worth. Two rungs is not slack; it is the verdict
    ignoring the fact, which is #242.

    **``MALICIOUS`` gets no slack: it floors at ``CRITICAL``.** The rung of
    slack above is paid for by one unmeasured thing, reachability, and a
    malicious package does not depend on it — the payload runs at install time
    or on import, from a package the manifest already asked for, and there is
    no vulnerable code path for the caller to avoid. There is also nothing
    below to discount to: the advisory does not say "this is exploitable under
    conditions", it says the artifact is the attack. Handing it the same one
    rung of doubt as a CVSS base score would be applying an allowance whose
    justification is absent (#272).

    **An advisory whose severity nobody published floors nothing, and that is a
    decision rather than an omission.** Absence of a severity is not evidence of
    a high one, so the honest floor is the weakest rung the scale has, ``LOW``
    — and ``severity_floor("LOW")`` is itself ``LOW``, the bottom of
    ``RISK_LEVEL_ORDER``, so such a floor forbids nothing any real verdict was
    going to do anyway. Returning None rather than a vacuous floor keeps
    ``verdict_floor.applied`` meaning what it says. What protects the reader is
    upstream of the floor: the advisory is **counted**, so ``known_vulnerable``
    is true, the ``N scored`` column is non-zero, the exploit signal carries a
    non-zero floor, and ``severity_unknown`` says how many counted advisories
    are in this state. Before #272 it was none of those, because the advisory
    was discarded.

    Args:
        max_counted_severity: Worst severity among the advisories that counted
            toward the score.

    Returns:
        The floor, or None when the severity is not one this scale recognizes.
    """
    if max_counted_severity == MALICIOUS_SEVERITY:
        return RiskLevel.CRITICAL
    tier = SEVERITY_AS_RISK_LEVEL.get(max_counted_severity)
    if tier is None:
        return None
    return RISK_LEVEL_ORDER[max(0, RISK_LEVEL_ORDER.index(tier) - 1)]


def verdict_floor_for(
    dependency: DependencyMetadata, unfloored_level: RiskLevel
) -> Optional[VerdictFloor]:
    """Return the floor the counted advisories put under a verdict, if any.

    Keyed on exactly the fact that produces ``known_vulnerable`` in the output
    contract — ``counted_vulnerability_count`` — because #242 is that those two
    fields could contradict each other. Anything the annotator filtered (fixed
    before the installed version, withdrawn, informational, below the scoring
    threshold) never reaches ``counted_vulnerability_count`` and so cannot floor
    anything: inflating a verdict off advisories that do not affect the
    installed version would be the same defect pointing the other way.

    ``UNKNOWN`` is left alone. It is an abstention rather than a rung, it is not
    a reassuring verdict, and ``insufficient_data: true`` implies
    ``risk_level: UNKNOWN`` in the published contract — raising it here would be
    a semantic break to schema v2 rather than an additive change. See #248.

    A module-level function for the same measured reason as
    :func:`advisory_risk_factors`: ``score_dependency`` sits on a benchmark
    cliff where physical lines cost budget and helpers do not.

    Args:
        dependency: The scored dependency.
        unfloored_level: The verdict the weighted mean produced on its own.

    Returns:
        The floor and whether it moved the verdict, or None when no counted
        advisory established one.
    """
    if unfloored_level is RiskLevel.UNKNOWN:
        return None
    metrics = dependency.security_metrics
    if metrics is None or not metrics.counted_vulnerability_count:
        return None
    max_severity = metrics.max_vulnerability_severity
    if max_severity is None:
        return None
    floor_level = severity_floor(max_severity)
    if floor_level is None:
        return None
    return VerdictFloor(
        max_counted_severity=max_severity,
        advisory_id=_worst_counted_advisory_id(metrics, max_severity),
        unfloored_level=unfloored_level,
        floor_level=floor_level,
        applied=(
            RISK_LEVEL_ORDER.index(floor_level)
            > RISK_LEVEL_ORDER.index(unfloored_level)
        ),
    )


def _worst_counted_advisory_id(
    metrics: SecurityMetrics, max_counted_severity: str
) -> Optional[str]:
    """Return the counted advisory that carries the maximum severity.

    Lexicographically first among ties rather than first-seen, so the recorded
    cause does not depend on which advisory source answered first — the same
    determinism requirement the org-scan report is held to.

    Args:
        metrics: The dependency's security metrics.
        max_counted_severity: The severity to match.

    Returns:
        The advisory ID, or None when the counted advisories carry no readable
        ID — which is a gap in the record, never a reason to drop the floor.
    """
    candidates = [
        str(detail["id"])
        for detail in metrics.vulnerability_details
        if detail.get("counted_in_score") is True
        and detail.get("normalized_severity") == max_counted_severity
        and isinstance(detail.get("id"), str)
    ]
    return min(candidates) if candidates else None


def advisory_risk_factors(dependency: DependencyMetadata) -> List[str]:
    """Return the risk factors describing an advisory lookup that fell short.

    A gap the reader can act on: "we could not tell" is a different instruction
    from "we found nothing", and before #219 the two rendered as the same blank
    line. ``FAILED`` says the exposure is unknown; ``PARTIAL`` says what is
    listed is a floor rather than a total.

    A module-level function rather than four inline branches in
    ``RiskScorer.score_dependency``, and that is a measured decision rather than
    a stylistic one. That method is enforced by a 50ms-per-100-dependencies SLA
    measured **with coverage instrumentation active**, and it sits on a cliff:
    adding as few as five physical lines to it — comments included, which
    generate no bytecode at all — costs ~30% of the budget under
    instrumentation, while the same lines added at the end of the file or in a
    helper cost nothing measurable. So the branches, and the paragraphs
    explaining them, live out here.

    Args:
        dependency: The scored dependency.

    Returns:
        Zero or one factor, in report order.
    """
    advisory = dependency.advisory_lookup_state
    if advisory not in ADVISORY_LOOKUP_DEGRADED:
        return []
    unavailable = ", ".join(dependency.advisory_sources_unavailable)
    if advisory is AdvisoryLookupState.FAILED:
        return [
            f"Advisory lookup did not answer ({unavailable}); "
            "exposure is unknown, not absent"
        ]
    return [
        f"Advisory lookup was incomplete ({unavailable} did not answer); "
        "advisories listed are a floor"
    ]


class RiskScorer:
    """Scores dependencies based on various risk factors."""

    def __init__(
        self,
        staleness_weight: float = 0.25,
        maintainer_weight: float = 0.2,
        deprecation_weight: float = 0.3,
        exploit_weight: float = 0.5,
        version_difference_weight: float = 0.15,
        health_indicators_weight: float = 0.1,
        # Enhanced risk factors
        license_weight: float = 0.3,
        community_weight: float = 0.2,
        transitive_weight: float = 0.15,
        source_repository_weight: float = 0.15,
        # OpenSSF Scorecard-inspired risk factors
        security_policy_weight: float = 0.25,
        dependency_update_weight: float = 0.2,
        signed_commits_weight: float = 0.2,
        branch_protection_weight: float = 0.15,
        maintained_weight: float = 0.20,
        popularity_high_stars: float = float(POPULARITY_HIGH_STARS_DEFAULT),
        popularity_high_contributors: float = float(
            POPULARITY_HIGH_CONTRIBUTORS_DEFAULT
        ),
        staleness_popularity_dampening: float = (
            STALENESS_POPULARITY_DAMPENING_DEFAULT
        ),
        max_score: float = 5.0,
    ) -> None:
        """Initialize the risk scorer with customizable weights.

        Args:
            staleness_weight: Weight for staleness score.
            maintainer_weight: Weight for maintainer count score.
            deprecation_weight: Weight for deprecation score.
            exploit_weight: Weight for known exploits score.
            version_difference_weight: Weight for version difference score.
            health_indicators_weight: Weight for health indicators score.
            license_weight: Weight for license risk score.
            community_weight: Weight for community health risk score.
            transitive_weight: Weight for transitive dependency risk score.
            source_repository_weight: Weight for the "declares a source
                repository" risk score. Scored only for ecosystems whose
                adapter reports the registry's answer; elsewhere the signal is
                absent rather than assumed (#74). Deliberately at the low end
                of the scale: a fifteenth signal shifts the weighted average
                for every already-scored dependency, and this one is a leading
                indicator, not a finding in itself.
            security_policy_weight: Weight for security policy risk score.
            dependency_update_weight: Weight for dependency update tools risk score.
            maintained_weight: Weight for the maintained-status risk score. Kept
                independent from branch_protection_weight so the two OpenSSF
                signals contribute at their own, separately tunable weights.
            popularity_high_stars: Star threshold for treating stale release cadence
                as mature stability instead of abandonment.
            popularity_high_contributors: Contributor threshold for the same
                staleness dampening. This does not affect bus-factor scoring.
            staleness_popularity_dampening: Factor applied only to abandonment-style
                scores when high adoption is measured and no hard abandonment marker
                is present.
            max_score: Maximum risk score.
        """
        self.staleness_weight = staleness_weight
        self.maintainer_weight = maintainer_weight
        self.deprecation_weight = deprecation_weight
        self.exploit_weight = exploit_weight
        self.version_difference_weight = version_difference_weight
        self.health_indicators_weight = health_indicators_weight

        # Enhanced risk factors
        self.license_weight = license_weight
        self.community_weight = community_weight
        self.transitive_weight = transitive_weight
        self.source_repository_weight = source_repository_weight
        self.security_policy_weight = security_policy_weight
        self.dependency_update_weight = dependency_update_weight
        self.signed_commits_weight = signed_commits_weight
        self.branch_protection_weight = branch_protection_weight
        self.maintained_weight = maintained_weight
        self.popularity_high_stars = max(0, int(popularity_high_stars))
        self.popularity_high_contributors = max(
            0,
            int(popularity_high_contributors),
        )
        self.staleness_popularity_dampening = min(
            1.0,
            max(0.0, staleness_popularity_dampening),
        )

        self.max_score = max_score

        # Risk level thresholds (as a percentage of max_score)
        self.risk_thresholds = {
            RiskLevel.LOW: 0.25,  # 0% - 25%
            RiskLevel.MEDIUM: 0.5,  # 25% - 50%
            RiskLevel.HIGH: 0.75,  # 50% - 75%
            RiskLevel.CRITICAL: 1.0,  # 75% - 100%
        }

    def score_dependency(self, dependency: DependencyMetadata) -> DependencyRiskScore:
        """Score a dependency based on its metadata.

        Args:
            dependency: Dependency metadata to score.

        Returns:
            Risk score for the dependency.
        """
        # The registry's answer about the source repository is read first
        # because it is the one measured fact that explains why several other
        # signals are silent, and the reason table needs it (#146).
        source_repository_state = dependency.source_repository_state
        unreadable = source_repository_state in SOURCE_REPOSITORY_UNREADABLE
        advisory = dependency.advisory_lookup_state

        staleness_score = self._calculate_staleness_score(dependency.last_updated)
        staleness_score = self._dampen_staleness_for_popularity(
            dependency,
            staleness_score,
        )
        maintainer_score = self._calculate_maintainer_score(dependency.maintainer_count)
        deprecation_score = self._calculate_deprecation_score(dependency.is_deprecated)
        exploit_score = self._calculate_exploit_score(
            dependency.has_known_exploits, dependency.security_metrics, advisory
        )
        installed_release_date, latest_release_date = release_timestamps(dependency)
        version_score = self._calculate_version_difference_score(
            dependency.installed_version,
            dependency.latest_version,
            installed_release_date,
            latest_release_date,
        )
        health_score = self._calculate_health_indicators_score(
            dependency.has_tests,
            dependency.has_ci,
            dependency.has_contribution_guidelines,
        )

        # Enhanced risk scores
        license_score = self._calculate_license_score(dependency.license_info)
        # Popularity and development cadence are weighed apart, not averaged
        # into one confident number. `community_score` below is the reported
        # summary of whichever halves were measured (#166).
        popularity_score = self._calculate_popularity_score(
            dependency.community_metrics
        )
        development_activity_score = self._calculate_development_activity_score(
            dependency.community_metrics
        )
        community_score = self._combine_community_score(
            popularity_score, development_activity_score
        )
        transitive_score = self._calculate_transitive_score(
            dependency.transitive_dependencies,
            measured=transitive_is_measured(dependency.transitive_source),
        )

        # OpenSSF Scorecard-inspired risk scores
        security_policy_score = self._calculate_security_policy_score(
            dependency.security_metrics
        )
        dependency_update_score = self._calculate_dependency_update_score(
            dependency.security_metrics
        )
        signed_commits_score = self._calculate_signed_commits_score(
            dependency.security_metrics
        )
        branch_protection_score = self._calculate_branch_protection_score(
            dependency.security_metrics
        )
        maintained_score = self._calculate_maintained_score(dependency.security_metrics)
        maintained_score = self._dampen_maintained_for_popularity(
            dependency,
            maintained_score,
        )

        # Every signal is now a MEASURED value or an UNMEASURED reason, and the
        # type refuses anything else (#164). ``_measure`` routes each absence
        # through the one centralized reason table, so no adapter and no branch
        # of this method gets to decide independently what an absence means.
        measure = self._measure
        context = (unreadable, advisory)
        weighted_scores: List[Tuple[str, Measurement, float]] = [
            (
                SIGNAL_STALENESS,
                measure(SIGNAL_STALENESS, staleness_score, context),
                self.staleness_weight,
            ),
            (
                SIGNAL_MAINTAINER,
                measure(SIGNAL_MAINTAINER, maintainer_score, context),
                self.maintainer_weight,
            ),
            (
                SIGNAL_DEPRECATION,
                measure(SIGNAL_DEPRECATION, deprecation_score, context),
                self.deprecation_weight,
            ),
            (
                SIGNAL_EXPLOIT,
                measure(SIGNAL_EXPLOIT, exploit_score, context),
                self.exploit_weight,
            ),
            (
                SIGNAL_VERSION,
                measure(SIGNAL_VERSION, version_score, context),
                self.version_difference_weight,
            ),
            (
                SIGNAL_HEALTH_INDICATORS,
                measure(SIGNAL_HEALTH_INDICATORS, health_score, context),
                self.health_indicators_weight,
            ),
            # Enhanced risk factors
            (
                SIGNAL_LICENSE,
                measure(SIGNAL_LICENSE, license_score, context),
                self.license_weight,
            ),
            # The community budget splits evenly across its two halves. When
            # both are measured this is arithmetically identical to weighting
            # their average; when only one is, the missing half drops out of the
            # denominator instead of being silently carried by the other (#74).
            (
                SIGNAL_COMMUNITY_POPULARITY,
                measure(SIGNAL_COMMUNITY_POPULARITY, popularity_score, context),
                self.community_weight / 2,
            ),
            (
                SIGNAL_COMMUNITY_ACTIVITY,
                measure(SIGNAL_COMMUNITY_ACTIVITY, development_activity_score, context),
                self.community_weight / 2,
            ),
            (
                SIGNAL_TRANSITIVE,
                measure(SIGNAL_TRANSITIVE, transitive_score, context),
                self.transitive_weight,
            ),
            (
                SIGNAL_SECURITY_POLICY,
                measure(SIGNAL_SECURITY_POLICY, security_policy_score, context),
                self.security_policy_weight,
            ),
            (
                SIGNAL_DEPENDENCY_UPDATE,
                measure(SIGNAL_DEPENDENCY_UPDATE, dependency_update_score, context),
                self.dependency_update_weight,
            ),
            (
                SIGNAL_SIGNED_COMMITS,
                measure(SIGNAL_SIGNED_COMMITS, signed_commits_score, context),
                self.signed_commits_weight,
            ),
            (
                SIGNAL_BRANCH_PROTECTION,
                measure(SIGNAL_BRANCH_PROTECTION, branch_protection_score, context),
                self.branch_protection_weight,
            ),
            (
                SIGNAL_MAINTAINED,
                measure(SIGNAL_MAINTAINED, maintained_score, context),
                self.maintained_weight,
            ),
        ]

        # "Declares no source repository" is a leading indicator in its own
        # right — a package that no longer says where its source lives — and
        # until #146 it was only ever a silent cause of UNKNOWN. It is appended
        # rather than listed above because an adapter that does not report the
        # registry's answer has not measured it, and #74's rule is that an
        # unavailable signal leaves both the numerator and the denominator
        # rather than being assumed either way.
        source_repository_score = self._calculate_source_repository_score(dependency)
        if source_repository_score is not None:
            weighted_scores.append(
                (
                    SIGNAL_SOURCE_REPOSITORY,
                    Measurement.measured(source_repository_score),
                    self.source_repository_weight,
                )
            )

        # Cross-ecosystem score normalization (#74): an unmeasured component is
        # excluded from BOTH the numerator and the denominator (renormalized
        # over available weights), so a signal an ecosystem doesn't provide
        # (e.g. Go has no maintainer concept) is treated as unavailable, never a
        # confident zero that would make a sparsely-covered package look safer.
        total_score = 0.0
        available_weights = 0.0
        for _, measurement, weight in weighted_scores:
            if measurement.value is not None:  # Only count available scores
                total_score += measurement.value * weight
                available_weights += weight

        if available_weights > 0:
            total_score = (total_score / available_weights) * self.max_score

        unknown_signals = self._determine_unknown_signals(weighted_scores)
        measured_signal_count = len(weighted_scores) - len(unknown_signals)
        insufficient_data = (
            self._unexplained_unknown_count(weighted_scores) > measured_signal_count
        )

        risk_level = (
            RiskLevel.UNKNOWN
            if insufficient_data
            else self._determine_risk_level(total_score)
        )
        # Facts set floors; forecasts move within them (#242).
        floor = verdict_floor_for(dependency, risk_level)
        if floor is not None and floor.applied:
            risk_level = floor.floor_level

        # Determine risk factors
        risk_factors = self._determine_risk_factors(
            dependency,
            staleness_score,
            maintainer_score,
            deprecation_score,
            exploit_score,
            version_score,
            health_score,
            license_score,
            popularity_score,
            development_activity_score,
            transitive_score,
            security_policy_score,
            dependency_update_score,
            signed_commits_score,
            branch_protection_score,
            maintained_score,
        )
        risk_factors.extend(advisory_risk_factors(dependency))
        if source_repository_state is SourceRepositoryState.UNDECLARED:
            risk_factors.append("Declares no source repository")
        elif source_repository_state is SourceRepositoryState.UNUSABLE:
            risk_factors.append(
                "Declares a source repository that is not a reachable git forge"
            )
        if insufficient_data:
            risk_factors.insert(0, "Insufficient data for confident risk level")

        return DependencyRiskScore(
            dependency=dependency,
            staleness_score=staleness_score,
            maintainer_score=maintainer_score,
            deprecation_score=deprecation_score,
            exploit_score=exploit_score,
            version_score=version_score,
            health_indicators_score=health_score,
            license_score=license_score,
            community_score=community_score,
            transitive_score=transitive_score,
            security_policy_score=security_policy_score,
            dependency_update_score=dependency_update_score,
            signed_commits_score=signed_commits_score,
            branch_protection_score=branch_protection_score,
            maintained_score=maintained_score,
            source_repository_score=source_repository_score,
            total_score=total_score,
            risk_level=risk_level,
            verdict_floor=floor,
            factors=risk_factors,
            unknown_signals=unknown_signals,
            measured_signal_count=measured_signal_count,
            total_signal_count=len(weighted_scores),
            insufficient_data=insufficient_data,
            # Handed over by reference, not reshaped: ``DependencyRiskScore``
            # derives the per-signal mapping the output contract needs, on
            # demand. Building it here cost enough per dependency to breach the
            # scoring SLA once coverage instrumentation was counted.
            weighted_signals=weighted_scores,
        )

    def create_project_profile(
        self,
        manifest_path: str,
        ecosystem: str,
        dependencies: Dict[str, DependencyMetadata],
    ) -> ProjectRiskProfile:
        """Create a project risk profile from scored dependencies.

        Args:
            manifest_path: Path to the dependency manifest file.
            ecosystem: Dependency ecosystem.
            dependencies: Dictionary of dependency metadata.

        Returns:
            Project risk profile.
        """
        # Score all dependencies
        scored_dependencies = [
            self.score_dependency(dep) for dep in dependencies.values()
        ]

        # Count risk levels
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        unknown_risk = 0
        insufficient_data = 0

        for dep in scored_dependencies:
            if dep.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                high_risk += 1
            elif dep.risk_level == RiskLevel.MEDIUM:
                medium_risk += 1
            elif dep.risk_level == RiskLevel.LOW:
                low_risk += 1
            else:
                unknown_risk += 1

            if dep.insufficient_data:
                insufficient_data += 1

        # The overall project risk score is not computed here. It is
        # ``ProjectRiskProfile.overall_risk_score``, a mean over the
        # dependencies that could be scored, taken from the same list it
        # reports (#276). It used to be computed here over *every* dependency,
        # including the ones scoring produced no measurement for, which is
        # #74's defect one layer up: an unmeasured dependency contributed 0.0
        # to the numerator and 1 to the denominator, so the headline number
        # fell every time the scan failed to resolve a package.
        return ProjectRiskProfile(
            manifest_path=manifest_path,
            ecosystem=ecosystem,
            dependencies=scored_dependencies,
            high_risk_dependencies=high_risk,
            medium_risk_dependencies=medium_risk,
            low_risk_dependencies=low_risk,
            unknown_risk_dependencies=unknown_risk,
            insufficient_data_dependencies=insufficient_data,
            unknown_signal_count=sum(
                len(dep.unknown_signals) for dep in scored_dependencies
            ),
        )

    @staticmethod
    def _measure(
        signal: str,
        score: Optional[float],
        context: Tuple[bool, Optional[AdvisoryLookupState]],
    ) -> Measurement:
        """Lift one scorer result into a measurement, with its reason.

        Args:
            signal: The stable signal name.
            score: The computed score, or None when it could not be measured.
            context: The two facts the centralized reason table branches on:
                whether the registry answered and no readable source repository
                came out of it (#146), and what the advisory sources
                established, which is None when no lookup ran (#219).

                One tuple rather than two arguments because a two-argument tail
                does not fit on one line at fifteen call sites, and each one
                spread over four lines costs the SLA more than the work on it —
                see ``advisory_risk_factors`` for the measurement.

        Returns:
            A MEASURED measurement carrying the score, or an UNMEASURED one
            carrying the reason the table assigns.
        """
        # The measured branch constructs directly rather than through
        # ``Measurement.measured``: this runs sixteen times per dependency
        # across an org scan's thousands and the classmethod hop was
        # measurable. The constructor is the same gate either way. The
        # unmeasured branch goes through the classmethod because that is where
        # the shared per-reason instances live, which is cheaper still.
        if score is not None:
            return Measurement(MeasurementState.MEASURED, score, None)
        unreadable, advisory = context
        return Measurement.unmeasured(
            unmeasured_reason_for(
                signal,
                source_repository_unreadable=unreadable,
                advisory_lookup=advisory,
            )
        )

    def _determine_unknown_signals(
        self, weighted_scores: Sequence[Tuple[str, Measurement, float]]
    ) -> List[str]:
        """Return names for signals that could not be measured.

        Args:
            weighted_scores: The scored signals, in report order.

        Returns:
            The names of the unmeasured ones, in the same order.
        """
        # ``state is UNMEASURED`` rather than ``not is_measured``: identical by
        # construction, and this runs per signal per dependency in an org scan.
        return [
            name
            for name, measurement, _ in weighted_scores
            if measurement.state is MeasurementState.UNMEASURED
        ]

    @staticmethod
    def _calculate_source_repository_score(
        dependency: DependencyMetadata,
    ) -> Optional[float]:
        """Score what the registry said about the package's source repository.

        Three answers, three scores. The middle one is a judgment call and it is
        made here rather than by omission: a package that declares a Subversion
        URL on a decommissioned host has told you *something* — it published its
        provenance, in the idiom of its era — where a package that declares
        nothing has not. That is worth a discount, and only a discount. The
        operative consequence is identical either way: nobody can read the
        source, so the eight repository-derived signals stay dark and no auditor
        can check the package against what it claims to be. So
        :data:`SOURCE_REPOSITORY_UNUSABLE_SCORE` sits near the undeclared end
        rather than midway, and a package that declares a *live* forge is the
        only one that scores clean (#176).

        Args:
            dependency: Dependency metadata, carrying the adapter's record of
                what the registry answered.

        Returns:
            0.0 when a usable repository is declared, ``SOURCE_REPOSITORY_
            UNUSABLE_SCORE`` when what is declared is not a reachable git forge,
            1.0 when the registry answered and declares none, or None when this
            ecosystem's adapter reports nothing either way.
        """
        declared = dependency.source_repository_state
        if declared is SourceRepositoryState.DECLARED:
            return 0.0
        if declared is SourceRepositoryState.UNUSABLE:
            return SOURCE_REPOSITORY_UNUSABLE_SCORE
        if declared is SourceRepositoryState.UNDECLARED:
            return 1.0
        return None

    @staticmethod
    def _unexplained_unknown_count(
        weighted_scores: Sequence[Tuple[str, Measurement, float]],
    ) -> int:
        """Count unmeasured signals that are not explained by a measured fact.

        ``insufficient_data`` asks "do we know less about this package than we
        know?". A package that declares no source repository cannot answer the
        seven repository-derived signals, and that inability is not seven
        separate holes in the evidence — it is one thing we measured. Counting
        it seven times is what made an abandoned crypto library carrying two
        CRITICAL advisories report "insufficient data" (#146). The same rule
        applies to the two community halves: when *neither* was measured, that
        is one absent community record, not two independent gaps. Every other
        unmeasured signal still counts in full.

        Since #164 the collapse reads each signal's recorded *reason* rather
        than re-deriving it from the registry state and a second list of
        repository-derived signal names. Same arithmetic, one source of truth:
        ``SOURCE_REPOSITORY_UNREADABLE`` is assigned by the centralized table
        exactly when the registry answered, no repository could be read, and
        the signal needed one — which covers "declared an unusable repository"
        and "declared none" alike, as #176 requires.

        Args:
            weighted_scores: The scored signals, each carrying its measurement.

        Returns:
            The number of unmeasured signals that remain unexplained.
        """
        remaining = [
            name
            for name, measurement, _ in weighted_scores
            if measurement.state is MeasurementState.UNMEASURED
            and measurement.reason is not UnmeasuredReason.SOURCE_REPOSITORY_UNREADABLE
        ]

        community_unknown = sum(1 for name in remaining if name in COMMUNITY_SIGNALS)
        if community_unknown == len(COMMUNITY_SIGNALS):
            return len(remaining) - (len(COMMUNITY_SIGNALS) - 1)
        return len(remaining)

    def _calculate_staleness_score(
        self, last_updated: Optional[datetime]
    ) -> Optional[float]:
        """Calculate staleness score based on last update date.

        Args:
            last_updated: Date of last update.

        Returns:
            Staleness score between 0.0 and 1.0.
        """
        if last_updated is None:
            return None

        # Compare in UTC so staleness is independent of the host's local tz.
        # Naive inputs are assumed to already be UTC.
        if last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=timezone.utc)
        else:
            last_updated = last_updated.astimezone(timezone.utc)

        now = datetime.now(timezone.utc)
        days_since_update = (now - last_updated).days

        # Scoring thresholds for staleness
        if days_since_update < 30:  # Less than a month
            return 0.0
        elif days_since_update < 90:  # 1-3 months
            return 0.25
        elif days_since_update < 180:  # 3-6 months
            return 0.5
        elif days_since_update < 365:  # 6-12 months
            return 0.75
        else:  # More than a year
            return 1.0

    def _calculate_maintainer_score(
        self, maintainer_count: Optional[int]
    ) -> Optional[float]:
        """Calculate maintainer score based on maintainer count.

        Args:
            maintainer_count: Number of maintainers.

        Returns:
            Maintainer score between 0.0 and 1.0.
        """
        if maintainer_count is None:
            return None

        # Scoring thresholds for maintainers
        if maintainer_count >= 5:
            return 0.0
        elif maintainer_count >= 3:
            return 0.25
        elif maintainer_count == 2:
            return 0.5
        else:  # Single maintainer
            return 1.0

    def _dampen_staleness_for_popularity(
        self,
        dependency: DependencyMetadata,
        staleness_score: Optional[float],
    ) -> Optional[float]:
        """Reduce stale-release risk only when adoption is actually measured high."""
        if staleness_score is None:
            return None
        if not should_soften_low_release_cadence(
            dependency,
            popularity_high_stars=self.popularity_high_stars,
            popularity_high_contributors=self.popularity_high_contributors,
        ):
            return staleness_score
        return max(0.0, staleness_score * self.staleness_popularity_dampening)

    def _dampen_maintained_for_popularity(
        self,
        dependency: DependencyMetadata,
        maintained_score: Optional[float],
    ) -> Optional[float]:
        """Reduce abandonment-style maintained risk for mature high-adoption deps."""
        if maintained_score is None or maintained_score <= 0.5:
            return maintained_score
        if not should_soften_low_release_cadence(
            dependency,
            popularity_high_stars=self.popularity_high_stars,
            popularity_high_contributors=self.popularity_high_contributors,
        ):
            return maintained_score
        return max(0.0, maintained_score * self.staleness_popularity_dampening)

    def _calculate_deprecation_score(self, is_deprecated: bool) -> float:
        """Calculate deprecation score.

        Args:
            is_deprecated: Whether the dependency is deprecated.

        Returns:
            Deprecation score of 0.0 or 1.0.
        """
        return 1.0 if is_deprecated else 0.0

    def _calculate_exploit_score(
        self,
        has_known_exploits: bool,
        security_metrics: Optional[SecurityMetrics] = None,
        advisory_lookup: Optional[AdvisoryLookupState] = None,
    ) -> Optional[float]:
        """Calculate exploit score, or None when nobody could measure one.

        The ``None`` return is the point of #219. Every path through this
        method used to end at a number: a lookup that never happened, a lookup
        that failed, and a package with no advisories all scored ``0.0``, the
        most reassuring value in the range, at the tool's highest-weighted
        signal. A lookup that established nothing now measures nothing, and the
        reason travels with it through ``unmeasured_reason_for``.

        Args:
            has_known_exploits: Whether the dependency has known exploits.
            security_metrics: Optional vulnerability metrics from aggregation.
            advisory_lookup: What the advisory sources established. ``None``
                means no lookup ran, which keeps the pre-#219 behaviour — see
                ``signals.advisory_lookup_is_measured`` for why that is not the
                same as a lookup that failed.

        Returns:
            Exploit score between 0.0 and 1.0, or None when the advisory
            lookup established nothing.
        """
        if not advisory_lookup_is_measured(advisory_lookup):
            return None

        if security_metrics is not None:
            counted_count = security_metrics.counted_vulnerability_count
            if counted_count is not None:
                if counted_count == 0:
                    return 0.0

                # Severity first, CVSS second — the reverse of the old order,
                # and only ``MALICIOUS`` can tell the difference. A malicious
                # package that shares an alias group with a CVSS-scored
                # advisory would otherwise be scored off that CVSS, which is a
                # statement about the vulnerability and not about the malware.
                severity = security_metrics.max_vulnerability_severity
                if severity == MALICIOUS_SEVERITY:
                    return exploit_score_from_severity(severity)

                if security_metrics.max_cvss_score is not None:
                    return exploit_score_from_cvss(security_metrics.max_cvss_score)

                if severity is not None:
                    return exploit_score_from_severity(severity)

                # Counted advisories, none of which states a severity. Not
                # zero: zero is the value this signal carries for a package
                # with **no** live advisories, and returning it here would say
                # a package with a live advisory looks exactly like a clean one
                # at the tool's highest-weighted signal (#272). Not a guess at
                # a tier either — the floor is the weakest non-zero rung the
                # scale has, which is what "there is something here, and
                # nobody has said how bad" is worth.
                return ADVISORY_WITHOUT_SEVERITY_EXPLOIT_FLOOR

        return 1.0 if has_known_exploits else 0.0

    def _calculate_version_difference_score(
        self,
        installed_version: Optional[str],
        latest_version: Optional[str],
        installed_release_date: Optional[datetime] = None,
        latest_release_date: Optional[datetime] = None,
    ) -> Optional[float]:
        """Calculate version difference score.

        Args:
            installed_version: Installed version string.
            latest_version: Latest version string.
            installed_release_date: Publication date of the installed version,
                used only for calendar-versioned packages.
            latest_release_date: Publication date of the latest version, used
                only for calendar-versioned packages.

        Returns:
            Version difference score between 0.0 and 1.0, or None when the
            signal could not be measured.
        """
        if not installed_version or not latest_version:
            return None

        if installed_version == latest_version:
            return 0.0

        try:
            # Handle version ranges and non-standard version strings
            if any(op in installed_version for op in ["<", ">", "~", "^"]):
                return 0.25  # Assume minimal risk for version ranges

            # Calendar versioning carries no compatibility semantics, so
            # component distance is meaningless here: a four-year gap in
            # certifi is four years of stale CA data, not four breaking
            # upgrades. Score it by elapsed time instead (#126).
            if uses_calendar_versioning(installed_version, latest_version):
                return self._calculate_calendar_drift_score(
                    installed_release_date, latest_release_date
                )

            # Try to parse as standard versions
            current = version.parse(installed_version)
            latest = version.parse(latest_version)

            if current == latest:
                return 0.0

            # Handle LegacyVersion objects which don't have major, minor attributes
            if not hasattr(current, "major") or not hasattr(latest, "major"):
                # If we got LegacyVersion objects, return a moderate risk score
                if current != latest:
                    return 0.5
                return 0.0

            # Major version difference
            if latest.major > current.major:
                return 1.0

            # Minor version difference
            if latest.minor > current.minor:
                return 0.5

            # Patch version difference
            if hasattr(latest, "micro") and hasattr(current, "micro"):
                if latest.micro > current.micro:
                    return 0.25

            return 0.1  # Small difference

        except (TypeError, ValueError):
            # If we can't parse the versions, assume a moderate risk
            if installed_version != latest_version:
                return 0.5
            return 0.0

    def _calculate_calendar_drift_score(
        self,
        installed_release_date: Optional[datetime],
        latest_release_date: Optional[datetime],
    ) -> Optional[float]:
        """Score calendar-version drift by elapsed time between releases.

        Args:
            installed_release_date: Publication date of the installed version.
            latest_release_date: Publication date of the latest version.

        Returns:
            Drift score between 0.0 and 1.0, or None when the release
            timestamps are unavailable. A None result marks the signal
            unmeasured, which #74's normalization drops from both the numerator
            and the denominator rather than scoring it as a confident zero.
        """
        drift_days = calendar_drift_days(installed_release_date, latest_release_date)
        if drift_days is None:
            return None

        # Deliberately gentler than the SemVer ladder at every step. Under
        # SemVer a single major bump hits the 1.0 ceiling because a breaking
        # upgrade sits in the way; no CalVer gap has that property, so the
        # ceiling is reserved for a genuinely enormous stretch of missed
        # releases and the residual risk is carried by the staleness signal.
        if drift_days < 90:  # Less than a quarter
            return 0.0
        if drift_days < 365:  # Under a year
            return 0.25
        if drift_days < 730:  # 1-2 years
            return 0.5
        if drift_days < 1460:  # 2-4 years
            return 0.75
        return 1.0  # 4+ years of missed releases

    def _calculate_health_indicators_score(
        self,
        has_tests: Optional[bool],
        has_ci: Optional[bool],
        has_contribution_guidelines: Optional[bool],
    ) -> Optional[float]:
        """Calculate health indicators score.

        Args:
            has_tests: Whether the dependency has tests.
            has_ci: Whether the dependency has CI configuration.
            has_contribution_guidelines: Whether contribution guidelines exist.

        Returns:
            Health indicators score between 0.0 and 1.0.
        """
        # Skip if all indicators are None
        if has_tests is None and has_ci is None and has_contribution_guidelines is None:
            return None

        # Count available indicators
        indicators = [has_tests, has_ci, has_contribution_guidelines]
        available = sum(1 for i in indicators if i is not None)

        # Count positive indicators
        positive = sum(1 for i in indicators if i is True)

        # Calculate score (0.0 = all positive, 1.0 = all negative)
        return 1.0 - (positive / available)

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level based on score.

        Args:
            score: Risk score.

        Returns:
            Risk level.
        """
        normalized_score = score / self.max_score

        if normalized_score < self.risk_thresholds[RiskLevel.LOW]:
            return RiskLevel.LOW
        elif normalized_score < self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif normalized_score < self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _calculate_license_score(
        self, license_info: Optional[LicenseInfo]
    ) -> Optional[float]:
        """Calculate license risk score.

        Args:
            license_info: License information.

        Returns:
            License risk score between 0.0 and 1.0.
        """
        if license_info is None:
            return None

        # Use the risk level already calculated for the license
        if license_info.risk_level == RiskLevel.CRITICAL:
            return 1.0
        elif license_info.risk_level == RiskLevel.HIGH:
            return 0.75
        elif license_info.risk_level == RiskLevel.MEDIUM:
            return 0.5
        elif license_info.risk_level == RiskLevel.LOW:
            return 0.0
        else:
            return 0.5

    @staticmethod
    def _calculate_popularity_score(
        community_metrics: Optional[CommunityMetrics],
    ) -> Optional[float]:
        """Score how much attention the project has (more stars = lower risk).

        Args:
            community_metrics: Community health metrics.

        Returns:
            Popularity risk score between 0.0 and 1.0, or None when the star
            count could not be read.
        """
        if community_metrics is None or community_metrics.star_count is None:
            return None

        if community_metrics.star_count >= 5000:
            return 0.0  # Very popular project
        if community_metrics.star_count >= 1000:
            return 0.25  # Popular project
        if community_metrics.star_count >= 100:
            return 0.5  # Moderately popular
        return 0.75  # Not very popular

    @staticmethod
    def _calculate_development_activity_score(
        community_metrics: Optional[CommunityMetrics],
    ) -> Optional[float]:
        """Score development cadence from commits per month.

        Args:
            community_metrics: Community health metrics.

        Returns:
            Development activity risk score between 0.0 and 1.0, or None when
            nothing could measure the cadence — no clone in the analyze path,
            and no GitHub commits API answer in an org scan.
        """
        if community_metrics is None or community_metrics.commit_frequency is None:
            return None

        if community_metrics.commit_frequency >= 10:
            return 0.0  # Very active development
        if community_metrics.commit_frequency >= 5:
            return 0.25  # Active development
        if community_metrics.commit_frequency >= 1:
            return 0.5  # Moderate development activity
        return 1.0  # Low development activity

    @staticmethod
    def _combine_community_score(
        popularity_score: Optional[float],
        development_activity_score: Optional[float],
    ) -> Optional[float]:
        """Average the community components that were actually measured.

        This is a reporting convenience only. The two components are weighted
        independently in ``score_dependency`` so that an unmeasured half leaves
        both the numerator and the denominator (#74); averaging them here would
        otherwise let a half-measured composite pass as a whole one, which is
        exactly what made ``community_score`` a star count wearing a cadence
        label (#166).

        Args:
            popularity_score: Popularity component, or None if unmeasured.
            development_activity_score: Cadence component, or None if unmeasured.

        Returns:
            Mean of the measured components, or None when neither was measured.
        """
        measured = [
            score
            for score in (popularity_score, development_activity_score)
            if score is not None
        ]
        if not measured:
            return None
        return sum(measured) / len(measured)

    def _calculate_transitive_score(
        self, transitive_dependencies: Collection[str], *, measured: bool
    ) -> Optional[float]:
        """Calculate transitive dependency risk score.

        Args:
            transitive_dependencies: Set of transitive dependencies.
            measured: Whether transitive resolution actually ran. Keyword-only
                and defaultless on purpose (#199): the old ``measured=True``
                default meant a caller that said nothing got a confident score
                for a signal nobody measured. An empty set means "no transitive
                dependencies" only when someone looked; when nothing looked the
                signal is unavailable, not zero (#74).

        Returns:
            Transitive dependency risk score between 0.0 and 1.0, or None when
            the signal could not be measured.
        """
        if not measured:
            # A set nobody vouched for is not evidence, whatever is in it.
            return None
        if not transitive_dependencies:
            return 0.0  # Looked, found none = no transitive risk

        # Calculate risk based on number of transitive dependencies
        num_deps = len(transitive_dependencies)

        if num_deps >= 100:
            return 1.0  # Very high transitive dependency count
        elif num_deps >= 50:
            return 0.75  # High transitive dependency count
        elif num_deps >= 20:
            return 0.5  # Moderate transitive dependency count
        elif num_deps >= 5:
            return 0.25  # Low transitive dependency count
        else:
            return 0.1  # Very low transitive dependency count

    def _calculate_security_policy_score(
        self, security_metrics: Optional[SecurityMetrics]
    ) -> Optional[float]:
        """Calculate security policy risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Security policy risk score between 0.0 and 1.0.
        """
        if security_metrics is None:
            return None

        # If the dependency has a security policy, it's a good sign
        if security_metrics.has_security_policy is not None:
            if security_metrics.has_security_policy:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - no security policy

        # If we don't have explicit security policy data
        return None

    def _calculate_dependency_update_score(
        self, security_metrics: Optional[SecurityMetrics]
    ) -> Optional[float]:
        """Calculate dependency update tools risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Dependency update tools risk score between 0.0 and 1.0.
        """
        if security_metrics is None:
            return None

        # If the dependency uses dependency update tools, it's a good sign
        if security_metrics.has_dependency_update_tools is not None:
            if security_metrics.has_dependency_update_tools:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - no dependency update tools

        # If we don't have explicit dependency update tools data
        return None

    def _calculate_signed_commits_score(
        self, security_metrics: Optional[SecurityMetrics]
    ) -> Optional[float]:
        """Calculate signed commits risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Signed commits risk score between 0.0 and 1.0.
        """
        if security_metrics is None:
            return None

        # If the dependency uses signed commits/releases, it's a good sign
        if security_metrics.has_signed_commits is not None:
            if security_metrics.has_signed_commits:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - no signed commits

        # If we don't have explicit signed commits data
        return None

    def _calculate_branch_protection_score(
        self, security_metrics: Optional[SecurityMetrics]
    ) -> Optional[float]:
        """Calculate branch protection risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Branch protection risk score between 0.0 and 1.0.
        """
        if security_metrics is None:
            return None

        # If the dependency uses branch protection, it's a good sign
        if security_metrics.has_branch_protection is not None:
            if security_metrics.has_branch_protection:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - no branch protection

        # If we don't have explicit branch protection data
        return None

    def _calculate_maintained_score(
        self, security_metrics: Optional[SecurityMetrics]
    ) -> Optional[float]:
        """Calculate maintained status risk score.

        Args:
            security_metrics: Security metrics information.

        Returns:
            Maintained status risk score between 0.0 and 1.0.
        """
        if security_metrics is None:
            return None

        # If the dependency is maintained, it's a good sign
        if security_metrics.is_maintained is not None:
            if security_metrics.is_maintained:
                return 0.0  # No risk
            else:
                return 1.0  # High risk - not maintained

        # If we don't have explicit maintained status data
        return None

    def _determine_risk_factors(
        self,
        dependency: DependencyMetadata,
        staleness_score: Optional[float],
        maintainer_score: Optional[float],
        deprecation_score: float,
        exploit_score: Optional[float],
        version_score: Optional[float],
        health_score: Optional[float],
        license_score: Optional[float],
        popularity_score: Optional[float],
        development_activity_score: Optional[float],
        transitive_score: Optional[float],
        security_policy_score: Optional[float],
        dependency_update_score: Optional[float],
        signed_commits_score: Optional[float],
        branch_protection_score: Optional[float],
        maintained_score: Optional[float],
    ) -> List[str]:
        """Determine risk factors that contribute to the risk score.

        Args:
            dependency: Dependency metadata.
            staleness_score: Staleness score.
            maintainer_score: Maintainer score.
            deprecation_score: Deprecation score.
            exploit_score: Exploit score.
            version_score: Version difference score.
            health_score: Health indicators score.
            license_score: License risk score.
            popularity_score: Community popularity risk score.
            development_activity_score: Development cadence risk score.
            transitive_score: Transitive dependency risk score.
            security_policy_score: Security policy risk score.

        Returns:
            List of risk factors.
        """
        factors = []

        if staleness_score and staleness_score > 0.5:
            if dependency.last_updated:
                # Compare in UTC so staleness is independent of the host's tz.
                # Naive inputs are assumed to already be UTC.
                last_updated = dependency.last_updated
                if last_updated.tzinfo is None:
                    last_updated = last_updated.replace(tzinfo=timezone.utc)
                else:
                    last_updated = last_updated.astimezone(timezone.utc)

                now = datetime.now(timezone.utc)
                days_since_update = (now - last_updated).days
                factors.append(f"Not updated in {days_since_update} days")
            else:
                factors.append("Update date unknown")

        if maintainer_score and maintainer_score > 0.5:
            if (
                dependency.maintainer_count is not None
                and dependency.maintainer_count < 2
            ):
                factors.append("Single maintainer")
            else:
                factors.append("Maintainer count unknown")

        if deprecation_score and deprecation_score > 0:
            factors.append("Deprecated")

        if exploit_score and exploit_score > 0:
            if dependency.security_metrics:
                counted_count = dependency.security_metrics.counted_vulnerability_count
                max_severity = dependency.security_metrics.max_vulnerability_severity
                if counted_count is not None and max_severity is not None:
                    factors.append(
                        f"Known security issues ({counted_count} counted, "
                        f"max severity {max_severity})"
                    )
                elif counted_count is not None:
                    # Counted advisories, no severity among them. The count is
                    # the fact; saying "max severity UNKNOWN" would dress an
                    # absence up as a measurement (#272).
                    factors.append(
                        f"Known security issues ({counted_count} counted, "
                        "severity not published)"
                    )
                else:
                    factors.append("Known security issues")
            else:
                factors.append("Known security issues")

        if version_score and version_score > 0.5:
            factors.append(
                (
                    f"Outdated (current: {dependency.installed_version}, "
                    f"latest: {dependency.latest_version})"
                )
            )

        if health_score and health_score > 0.5:
            missing = []
            if not dependency.has_tests:
                missing.append("tests")
            if not dependency.has_ci:
                missing.append("CI")
            if not dependency.has_contribution_guidelines:
                missing.append("contribution guidelines")

            if missing:
                factors.append(f"Missing {', '.join(missing)}")

        # License risk factors
        if license_score and license_score > 0.5:
            if dependency.license_info:
                if dependency.license_info.category.value == "NETWORK_COPYLEFT":
                    factors.append(
                        "Network copyleft license "
                        f"({dependency.license_info.license_id})"
                    )
                elif dependency.license_info.category.value == "COPYLEFT":
                    factors.append(
                        f"Copyleft license ({dependency.license_info.license_id})"
                    )
                elif dependency.license_info.category.value == "COMMERCIAL":
                    factors.append(
                        f"Commercial license ({dependency.license_info.license_id})"
                    )
                elif dependency.license_info.category.value == "UNKNOWN":
                    factors.append("Unknown license")
                elif not dependency.license_info.is_approved:
                    factors.append(
                        f"Non-approved license ({dependency.license_info.license_id})"
                    )

        # Community health risk factors. Each half gates on its own score: an
        # averaged composite let a well-starred package with a dead commit log
        # land on exactly 0.5 and report neither problem (#166).
        if dependency.community_metrics:
            if (
                popularity_score is not None
                and popularity_score > 0.5
                and dependency.community_metrics.star_count is not None
            ):
                star_count = dependency.community_metrics.star_count
                factors.append(f"Low popularity ({star_count} stars)")

            if (
                development_activity_score is not None
                and development_activity_score > 0.5
                and dependency.community_metrics.commit_frequency is not None
            ):
                commits_per_month = dependency.community_metrics.commit_frequency
                factors.append(
                    f"Low development activity ({commits_per_month:.1f} commits/month)"
                )

        # Transitive dependency risk factors
        if transitive_score and transitive_score > 0.5:
            if dependency.transitive_dependencies:
                transitive_count = len(dependency.transitive_dependencies)
                factors.append(f"Large dependency tree ({transitive_count} deps)")

        # Security policy risk factors
        if security_policy_score and security_policy_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.has_security_policy is not None:
                    if not dependency.security_metrics.has_security_policy:
                        factors.append("Missing security policy")
                else:
                    factors.append("Security policy status unknown")
            else:
                factors.append("No security metadata available")

        # Dependency update tools risk factors
        if dependency_update_score and dependency_update_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.has_dependency_update_tools is not None:
                    if not dependency.security_metrics.has_dependency_update_tools:
                        factors.append("No dependency update tools found")
                else:
                    factors.append("Dependency update tools status unknown")
            else:
                factors.append("No security metadata available")

        # Signed commits risk factors
        if signed_commits_score and signed_commits_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.has_signed_commits is not None:
                    if not dependency.security_metrics.has_signed_commits:
                        factors.append("Does not use signed commits")
                else:
                    factors.append("Signed commits status unknown")
            else:
                factors.append("No security metadata available")

        # Branch protection risk factors
        if branch_protection_score and branch_protection_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.has_branch_protection is not None:
                    if not dependency.security_metrics.has_branch_protection:
                        factors.append("Does not use branch protection")
                else:
                    factors.append("Branch protection status unknown")
            else:
                factors.append("No security metadata available")

        # Maintained status risk factors
        if maintained_score and maintained_score > 0.5:
            if dependency.security_metrics:
                if dependency.security_metrics.is_maintained is not None:
                    if not dependency.security_metrics.is_maintained:
                        factors.append(
                            "Project does not appear to be actively maintained"
                        )
                else:
                    factors.append("Maintenance status unknown")
            else:
                factors.append("No security metadata available")

        return factors
