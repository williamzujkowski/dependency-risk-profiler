"""Data models for dependency risk profiling."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .signals import (
    SIGNAL_SOURCE_REPOSITORY,
    SOURCE_REPOSITORY_UNREADABLE,
    AdvisoryLookupState,
    FieldSource,
    Measurement,
    ProvenancedField,
    SourceRepositoryState,
    unmeasured_reason_for,
)


class RiskLevel(Enum):
    """Risk level classification for dependencies."""

    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


#: The verdict scale, weakest first. ``UNKNOWN`` is deliberately absent: it is
#: an abstention rather than a rung, and nothing may be ordered against it.
RISK_LEVEL_ORDER: Tuple[RiskLevel, ...] = (
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
)


@dataclass(frozen=True)
class VerdictFloor:
    """The lower bound a live advisory puts under a verdict (#242).

    Recorded whenever counted advisories establish a floor, whether or not the
    floor moved anything. A field that only appeared when the floor fired would
    let a test assert the *outcome* and never the *cause*, and this repository
    has a history of expectations that start passing for the wrong reason.

    ``applied`` is therefore the fact, not the existence of this object.
    """

    #: Worst severity among the advisories that counted toward the score.
    max_counted_severity: str
    #: The advisory that carries that severity. Lexicographically first among
    #: ties, so the record does not depend on which source answered first.
    advisory_id: Optional[str]
    #: The verdict the weighted mean produced on its own.
    unfloored_level: RiskLevel
    #: The verdict the floor forbids the tool to report below.
    floor_level: RiskLevel
    #: Whether the floor actually raised the verdict.
    applied: bool


class LicenseCategory(Enum):
    """License categories for risk assessment."""

    PERMISSIVE = "PERMISSIVE"  # MIT, BSD, Apache, etc.
    COPYLEFT = "COPYLEFT"  # GPL, LGPL, etc.
    NETWORK_COPYLEFT = "NETWORK_COPYLEFT"  # AGPL, etc.
    COMMERCIAL = "COMMERCIAL"  # Proprietary licenses
    UNKNOWN = "UNKNOWN"  # Unrecognized or custom licenses


@dataclass
class LicenseInfo:
    """License information for a dependency."""

    license_id: str  # SPDX ID or license name
    category: LicenseCategory  # License category
    is_approved: Optional[bool] = None  # Whether this license is approved by org policy
    url: Optional[str] = None  # URL to license text
    risk_level: RiskLevel = RiskLevel.LOW  # Risk level for this license


@dataclass
class CommunityMetrics:
    """Community health metrics for a dependency."""

    star_count: Optional[int] = None  # GitHub stars or equivalent
    contributor_count: Optional[int] = None  # Total contributors
    # Commits per month over the trailing six months, read from a clone in the
    # analyze path and from the GitHub commits API in org scans. None means
    # nobody could look, and the scorer reports that rather than guessing (#166).
    commit_frequency: Optional[float] = None
    last_release_date: Optional[datetime] = None  # Date of last release
    # Publication date of the *installed* version. Paired with last_release_date
    # this measures elapsed-time drift for calendar-versioned packages, where
    # component distance carries no compatibility meaning (#126).
    installed_release_date: Optional[datetime] = None


@dataclass
class SecurityMetrics:
    """Security metrics for a dependency."""

    # OpenSSF Scorecard-inspired metrics
    has_security_policy: Optional[bool] = None  # Whether repo has a security policy
    has_dependency_update_tools: Optional[bool] = (
        None  # Whether repo uses dependency update tools
    )
    has_signed_commits: Optional[bool] = (
        None  # Whether repo uses signed commits/releases
    )
    has_branch_protection: Optional[bool] = None  # Whether repo uses branch protection
    is_maintained: Optional[bool] = None  # Whether repo is actively maintained

    # Vulnerability metrics
    vulnerability_count: Optional[int] = None  # Number of known vulnerabilities
    max_cvss_score: Optional[float] = None  # Maximum CVSS score of vulnerabilities
    counted_vulnerability_count: Optional[int] = None
    filtered_vulnerability_count: Optional[int] = None
    filtered_vulnerability_reasons: Dict[str, int] = field(default_factory=dict)
    # Counted advisories whose applicability to the installed version could not
    # be decided, with the reasons why. Reported rather than assumed away (#61).
    applicability_unknown_count: Optional[int] = None
    applicability_unknown_reasons: Dict[str, int] = field(default_factory=dict)
    # Counted advisories whose severity nobody published, with the reasons why.
    # The same two-state shape as ``applicability_unknown`` above, and needed
    # for the same reason: these advisories were being dropped from the score
    # for carrying no severity label, which silenced the ``GO-*`` and
    # ``RUSTSEC-*`` databases entirely and every malware finding the tool made
    # (#272). ``max_vulnerability_severity`` cannot express them — it holds a
    # tier or nothing, and "nothing" means no counted advisory stated one.
    severity_unknown_count: Optional[int] = None
    severity_unknown_reasons: Dict[str, int] = field(default_factory=dict)
    max_vulnerability_severity: Optional[str] = None
    vulnerability_details: List[Dict[str, object]] = field(default_factory=list)


@dataclass
class DependencyMetadata:
    """Metadata for a dependency."""

    name: str
    installed_version: str
    latest_version: Optional[str] = None
    last_updated: Optional[datetime] = None
    maintainer_count: Optional[int] = None
    is_deprecated: bool = False
    has_known_exploits: bool = False
    repository_url: Optional[str] = None
    has_tests: Optional[bool] = None
    has_ci: Optional[bool] = None
    has_contribution_guidelines: Optional[bool] = None

    # Enhanced metadata fields
    license_info: Optional[LicenseInfo] = None
    community_metrics: Optional[CommunityMetrics] = None
    security_metrics: Optional[SecurityMetrics] = None
    transitive_dependencies: Set[str] = field(default_factory=set)

    # Measurement states, typed. Both used to be stringly-typed entries in
    # ``additional_info``, where nothing stopped a typo from silently reading
    # as "unmeasured" and mypy could not see them at all (#164).
    #
    # What the registry said about the source repository. None means the lookup
    # did not happen or did not answer — unmeasured, and never a negative
    # finding (#182). Written only by ``release_dates.record_source_repository``.
    source_repository_state: Optional[SourceRepositoryState] = None
    # How this dependency's transitive set was established, so the scorer can
    # tell "resolved, and it is empty" from "never resolved". Written only by
    # ``transitive.analyzer_enhanced.record_transitive_source``, and read only
    # through ``signals.transitive_is_measured``, which fails closed: None here
    # means nobody resolved this tree, not that someone resolved it and found
    # nothing (#199).
    transitive_source: Optional[str] = None
    # What the advisory sources established, so the scorer can tell "they
    # answered and found nothing" from "they did not answer". Written only by
    # ``record_advisory_lookup`` below, from the vulnerability aggregator, and
    # read only through ``signals.advisory_lookup_is_measured``. None means no
    # lookup ran at all; see that function for why that is not a failure (#219).
    advisory_lookup_state: Optional[AdvisoryLookupState] = None
    # Which advisory sources were asked and did not answer. Names only — the
    # source's own ``name``, never a URL or a token-bearing request — because
    # this is rendered into reports.
    advisory_sources_unavailable: Tuple[str, ...] = ()

    # Which acquisition path last wrote each of the seven fields that have more
    # than one (#164 step 7). Written only through ``record_field_source``,
    # which is what keeps the values a closed vocabulary rather than free text.
    # Empty means nobody recorded anything, which is honest: this mapping never
    # claims a source for a field it did not see written.
    field_sources: Dict[ProvenancedField, FieldSource] = field(default_factory=dict)

    additional_info: Dict[str, str] = field(default_factory=dict)

    def record_field_source(
        self, field_name: ProvenancedField, source: FieldSource
    ) -> None:
        """Record which acquisition path wrote one multiply-written field.

        The only writer of :attr:`field_sources`, for the same reason
        ``unmeasured_reason_for`` is the only classifier of unmeasured signals:
        one enforcement point beats twenty-odd call sites each remembering the
        rule. Last write wins, matching the fields themselves — the value and
        its recorded source are set together, so they cannot disagree about who
        won.

        The ``isinstance`` checks are the runtime half of the design's binding
        security condition. Types already forbid a string here, but mypy does
        not run in production and an untyped caller (a plugin, a REPL, a test
        fixture) would otherwise be one assignment away from putting an
        authenticated URL or a clone path into a field documented as a
        sanitized locator. Failing loudly is cheap; a leaked credential is not.

        Args:
            field_name: Which field was written.
            source: Which acquisition path wrote it.

        Raises:
            TypeError: If either argument is not the enum member it claims to
                be. Never coerced: a value that is not in the closed vocabulary
                has no sanitized rendering, so there is nothing to record.
        """
        if not isinstance(field_name, ProvenancedField):
            raise TypeError(
                "field_name must be a ProvenancedField member, not "
                f"{type(field_name).__name__}"
            )
        if not isinstance(source, FieldSource):
            raise TypeError(
                "source must be a FieldSource member, not "
                f"{type(source).__name__}: field provenance is a closed "
                "vocabulary of sanitized logical locators, never free text"
            )
        self.field_sources[field_name] = source

    def record_advisory_lookup(
        self,
        state: AdvisoryLookupState,
        *,
        sources_unavailable: Sequence[str],
    ) -> None:
        """Record what the advisory lookup established, and what it could not.

        The only writer of :attr:`advisory_lookup_state`, and it takes the
        evidence as a required keyword-only argument for the same reason
        ``record_source_repository`` does: a state that can be set by omission
        is a state nobody has to justify. Here that matters twice over, because
        the state being justified is the one that stops a package from reading
        as advisory-clean.

        Args:
            state: What the sources established.
            sources_unavailable: Names of the sources that were asked and did
                not answer. Required to be non-empty exactly when the state
                says something failed, and empty otherwise.

        Raises:
            TypeError: If ``state`` is not an :class:`AdvisoryLookupState`.
            ValueError: If the names disagree with the state — a failure that
                cannot say what failed is not a report, and a complete lookup
                that names a casualty is a contradiction.
        """
        if not isinstance(state, AdvisoryLookupState):
            raise TypeError(
                "state must be an AdvisoryLookupState member, not "
                f"{type(state).__name__}"
            )
        names = tuple(sources_unavailable)
        degraded = state in (AdvisoryLookupState.PARTIAL, AdvisoryLookupState.FAILED)
        if degraded and not names:
            raise ValueError(
                f"advisory lookup state {state.value!r} must name the sources "
                "that did not answer: an unexplained failure is the empty list "
                "wearing a different hat (#219)"
            )
        if not degraded and names:
            raise ValueError(
                f"advisory lookup state {state.value!r} means every source "
                f"that was asked answered, so it cannot also report {names!r} "
                "as unavailable"
            )
        self.advisory_lookup_state = state
        self.advisory_sources_unavailable = names


@dataclass
class DependencyRiskScore:
    """Risk score for a dependency."""

    dependency: DependencyMetadata
    staleness_score: Optional[float] = None
    maintainer_score: Optional[float] = None
    deprecation_score: Optional[float] = None
    exploit_score: Optional[float] = None
    version_score: Optional[float] = None
    health_indicators_score: Optional[float] = None

    # Enhanced risk scores
    license_score: Optional[float] = None
    community_score: Optional[float] = None
    transitive_score: Optional[float] = None
    # Whether the registry declares a source repository at all. None when the
    # ecosystem's adapter reports nothing either way (#146).
    source_repository_score: Optional[float] = None

    # OpenSSF Scorecard-inspired risk scores
    security_policy_score: Optional[float] = None
    dependency_update_score: Optional[float] = None
    signed_commits_score: Optional[float] = None
    branch_protection_score: Optional[float] = None
    maintained_score: Optional[float] = None

    total_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    # The lagging-evidence floor under ``risk_level``, or None when the counted
    # advisories established none (#242). Additive: ``risk_level`` still reads
    # the same way, and this says whether a fact rather than the weighted mean
    # is what put it there.
    verdict_floor: Optional[VerdictFloor] = None
    factors: List[str] = field(default_factory=list)
    unknown_signals: List[str] = field(default_factory=list)
    measured_signal_count: int = 0
    total_signal_count: int = 0
    insufficient_data: bool = False

    # Exactly the ``(signal, measurement, weight)`` list the scorer weighed,
    # stored by reference rather than copied. The scorer already builds it, so
    # keeping it costs nothing in the hot path — which matters: scoring runs
    # under a 50ms-per-100-dependencies SLA that coverage instrumentation eats
    # most of, and an eager per-dependency reshape of this list measurably ate
    # the rest. Read it through :attr:`measurements`.
    weighted_signals: Sequence[Tuple[str, Measurement, float]] = ()

    @property
    def measurements(self) -> Dict[str, Measurement]:
        """Return every signal by name, as a value or the reason there isn't one.

        The two-state measurement (#198) used to stop at the scorer: both JSON
        writers flattened it to a bare ``null``, which a consumer cannot tell
        from "measured, and the answer happens to be null". Surfacing it is
        #164 step 5, and this is the view the output contract serializes.

        Built on demand, not at scoring time. ``source_repository`` is added
        here when it never entered the weighted score, so a consumer can tell
        "unmeasured" from "this build has no such signal" — it stays out of
        ``unknown_signals`` and the counts, which describe the weighted set,
        because #74's rule is that an unavailable signal leaves both the
        numerator and the denominator.

        Returns:
            Mapping of stable signal name to its measurement.
        """
        measurements = {
            name: measurement for name, measurement, _ in self.weighted_signals
        }
        if SIGNAL_SOURCE_REPOSITORY not in measurements:
            unreadable = (
                self.dependency.source_repository_state in SOURCE_REPOSITORY_UNREADABLE
            )
            measurements[SIGNAL_SOURCE_REPOSITORY] = Measurement.unmeasured(
                unmeasured_reason_for(
                    SIGNAL_SOURCE_REPOSITORY,
                    source_repository_unreadable=unreadable,
                    advisory_lookup=self.dependency.advisory_lookup_state,
                )
            )
        return measurements

    @property
    def unknown_signal_count(self) -> int:
        """Return how many signals came back unmeasured.

        A property rather than a stored field: it is ``len(unknown_signals)``
        and always was, so storing it only created a second thing that could
        disagree with the first. Not serialized in schema v2; the frozen v1
        writer still emits it.

        Returns:
            The number of unmeasured signals.
        """
        return len(self.unknown_signals)


@dataclass
class ProjectRiskProfile:
    """Overall risk profile for a project."""

    manifest_path: str
    ecosystem: str
    dependencies: List[DependencyRiskScore] = field(default_factory=list)
    high_risk_dependencies: int = 0
    medium_risk_dependencies: int = 0
    low_risk_dependencies: int = 0
    unknown_risk_dependencies: int = 0
    insufficient_data_dependencies: int = 0
    unknown_signal_count: int = 0
    scan_time: datetime = field(default_factory=datetime.now)

    @property
    def scored_dependency_count(self) -> int:
        """Return how many dependencies :attr:`overall_risk_score` averages.

        The denominator of a published mean, published. Its sibling
        ``dependency_count`` is the population, so a consumer reading both can
        tell "2.46 across all five" from "2.46 across one of five" without
        knowing this tool's exclusion rule.

        Derivable from ``dependency_count`` minus
        ``insufficient_data_dependencies``, and published anyway, on the
        precedent of ``measured_signal_count`` one layer down: that is exactly
        ``total_signal_count - len(unknown_signals)`` and is published because
        the denominator of a mean is part of the measurement rather than a
        convenience. ``unknown_signal_count`` was deleted from schema v2 for
        being derivable; it was not anybody's denominator.

        Returns:
            The number of dependencies that could be scored.
        """
        return sum(1 for dep in self.dependencies if not dep.insufficient_data)

    @property
    def overall_risk_score(self) -> Optional[float]:
        """Return the mean risk score over the dependencies that were scored.

        #74's rule, applied one layer up (#276). A dependency the tool could
        not measure leaves both the numerator and the denominator, exactly as
        an unmeasured *signal* does inside a single dependency's score. It used
        to leave only the numerator: an ``insufficient_data`` dependency
        carries ``total_score = 0.0``, so averaging over every dependency
        pulled the headline number toward zero once per package the scan failed
        to resolve. A manifest of one HIGH-risk package scored 2.46; the same
        manifest with four unresolvable packages appended scored 0.49. The
        number improved as the scan learned less, which is the one direction a
        risk score must never move for that reason.

        ``None``, not ``0.0``, when nothing could be scored. The run-level
        envelope already reports ``overall_risk_score: null`` for a manifest
        with no dependencies at all, so "no score" is a state the contract
        admits; a manifest of five unresolvable packages simply never reached
        it. ``0.0`` keeps its one honest meaning: dependencies were scored and
        the mean of their scores was zero.

        A property rather than a stored field, so the mean cannot be set
        independently of the dependencies it is a mean *of*. The field version
        could be handed any float at construction — and was, by a test that
        computed the average itself, passed it in, and asserted it came back
        out (AGENTS.md rule 6).

        Returns:
            The mean ``total_score`` of the scored dependencies, or ``None``
            when no dependency could be scored.
        """
        scored = [
            dep.total_score for dep in self.dependencies if not dep.insufficient_data
        ]
        if not scored:
            return None
        return sum(scored) / len(scored)


def merged_overall_risk_score(
    profiles: Sequence[ProjectRiskProfile],
) -> Tuple[Optional[float], int]:
    """Return the mean across several manifests, with the count it covers.

    A directory run reports one number over every manifest under it, and it was
    a mean weighted by each manifest's *dependency* count while the per-manifest
    means are over its *scored* dependencies. Mixing the two denominators
    reimports #276 at the run level: a manifest of five packages of which one
    scored would contribute its honest 2.46 five times over.

    The weights are ``scored_dependency_count`` and the values are
    ``overall_risk_score``, so this composes the per-manifest definition rather
    than restating which dependencies count. A manifest that scored nothing
    weighs nothing, and contributes no zero.

    Args:
        profiles: The manifest profiles in the run, possibly empty.

    Returns:
        The mean over every scored dependency in the run and how many that was,
        or ``(None, 0)`` when no dependency in the run could be scored.
    """
    total = 0.0
    scored = 0
    for profile in profiles:
        overall = profile.overall_risk_score
        if overall is None:
            continue
        count = profile.scored_dependency_count
        total += overall * count
        scored += count
    if not scored:
        return None, 0
    return total / scored, scored
