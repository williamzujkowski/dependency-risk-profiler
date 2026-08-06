"""A live advisory sets a floor under the verdict; it never sets a ceiling (#242).

The scorer is a weighted mean over sixteen signals whose weights sum to 3.5.
``exploit`` carries the largest single weight, 0.5, so its maximum share of the
normalized score is ``0.5 / 3.5 = 0.143`` against a LOW/MEDIUM boundary of
0.25. The arithmetic consequence is not a tuning problem: **a package with a
maximal exploit signal and a perfect, zero-risk record on all fifteen other
signals normalizes to 0.143 and reports LOW.** No advisory load, however
severe, could cross the first boundary on its own, so the tool printed
``risk_level: LOW`` on the same record where it printed
``known_vulnerable: true``.

The rule these tests pin is stated in ``docs/signals.md``: a weighted mean is a
compensatory model, known exploitation of the installed version is not, and
facts set floors that forecasts may move above but never below.

Four properties, and the fourth is the one that keeps the fix honest:

1. a counted advisory floors the verdict at one rung under its severity;
2. the floor only ever raises — no verdict anywhere moves down;
3. a record with no counted advisories scores identically to before;
4. an advisory that does **not** affect the installed version floors nothing.
   Inflating verdicts off filtered advisories would be the same defect
   pointing the other way.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from dependency_risk_profiler.contract import (
    known_vulnerable,
    scored_dependency,
    verdict_floor_to_dict,
)
from dependency_risk_profiler.models import (
    RISK_LEVEL_ORDER,
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
    LicenseCategory,
    LicenseInfo,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.release_dates import (
    RepositoryResolution,
    record_source_repository,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer, severity_floor
from dependency_risk_profiler.signals import AdvisoryLookupState, SourceRepositoryState
from dependency_risk_profiler.vulnerabilities.aggregator import (
    _update_dependency_with_vulnerabilities,
)

#: The verdict each maximum counted severity forbids the scorer to sit below:
#: one rung under the worst live advisory. Written out here as a table so the
#: test states the rule independently of the code that derives it.
SEVERITY_FLOOR_CASES = [
    ("LOW", RiskLevel.LOW),
    ("MEDIUM", RiskLevel.LOW),
    ("HIGH", RiskLevel.MEDIUM),
    ("CRITICAL", RiskLevel.HIGH),
]

RISK_ORDER = {level: index for index, level in enumerate(RISK_LEVEL_ORDER)}

AXIOS_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "axios_1_6_5.json"

# Every component score the live pre-fix run produced for axios 1.6.5, read off
# that run. The floor must leave every one of them exactly where it was: that
# is the difference between a floor and a re-weighting, and asserting it by
# value is the only way to tell the two apart from the outside.
AXIOS_COMPONENT_SCORES = {
    "staleness_score": 0.0,
    "maintainer_score": 0.0,
    "deprecation_score": 0.0,
    "exploit_score": 0.75,
    "version_score": 0.5,
    "health_indicators_score": 0.0,
    "license_score": 0.0,
    "community_score": 0.0,
    "transitive_score": 0.0,
    "security_policy_score": 0.0,
    "dependency_update_score": 0.0,
    "signed_commits_score": 1.0,
    "branch_protection_score": 0.0,
    "maintained_score": 0.5,
    "source_repository_score": 0.0,
}

# The weighted mean the pre-fix run produced, on the 0-5 scale. Normalized that
# is 0.2273 — inside LOW's 0.25 boundary, and exactly where it stays.
AXIOS_UNFLOORED_SCORE = 1.1363636363636362


def _healthy_dependency(name: str) -> DependencyMetadata:
    """Return a dependency that is measured, and clean, on every other signal.

    This is the shape the issue's arithmetic is about. Every leading indicator
    is measured and scores zero risk, so whatever verdict comes out is the
    exploit signal's contribution and nothing else.

    Args:
        name: Package name, so a parametrized case names its own subject.

    Returns:
        Metadata with fifteen measured, zero-risk leading indicators.
    """
    dependency = DependencyMetadata(
        name=name,
        installed_version="1.0.0",
        latest_version="1.0.0",
        last_updated=datetime.now(timezone.utc) - timedelta(days=3),
        maintainer_count=12,
        is_deprecated=False,
        repository_url="https://github.com/example/example",
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=True,
        license_info=LicenseInfo(
            license_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            is_approved=True,
            risk_level=RiskLevel.LOW,
        ),
        community_metrics=CommunityMetrics(
            star_count=50000,
            contributor_count=400,
            commit_frequency=30.0,
        ),
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=True,
            has_signed_commits=True,
            has_branch_protection=True,
            is_maintained=True,
        ),
        transitive_source="manifest",
        additional_info={"ecosystem": "nodejs"},
    )
    record_source_repository(
        dependency,
        RepositoryResolution(
            url="https://github.com/example/example",
            declared="https://github.com/example/example",
        ),
    )
    return dependency


def _advisory(
    identifier: str,
    severity: str,
    *,
    fixed: Optional[str] = "2.0.0",
    introduced: str = "0.0.0",
) -> Dict[str, object]:
    """Return one normalized advisory record, in the aggregator's own shape.

    Args:
        identifier: Advisory ID.
        severity: Source severity string.
        fixed: Version the advisory was fixed in, or None for an open range.
        introduced: Version the advisory was introduced in.

    Returns:
        An advisory record ready for ``_update_dependency_with_vulnerabilities``.
    """
    constraints: List[Dict[str, object]] = [{"operator": ">=", "version": introduced}]
    if fixed is not None:
        constraints.append({"operator": "<", "version": fixed})
    return {
        "id": identifier,
        "source": "OSV",
        "severity": severity,
        "normalized_severity": severity,
        "cvss_score": None,
        "fixed_versions": [fixed] if fixed else [],
        "references": [],
        "affected_versions": {"ranges": [{"constraints": constraints}]},
    }


def _scored_with(
    severity: str, name: str = "healthy-but-exploited"
) -> DependencyRiskScore:
    """Score a healthy dependency carrying one counted advisory at ``severity``.

    Args:
        severity: Severity tier of the single counted advisory.
        name: Package name for the subject.

    Returns:
        The scored dependency.
    """
    dependency = _healthy_dependency(name)
    _update_dependency_with_vulnerabilities(
        dependency, [_advisory(f"OSV-{severity}", severity)], "LOW"
    )
    return RiskScorer().score_dependency(dependency)


# --------------------------------------------------------------------------
# 1. The property
# --------------------------------------------------------------------------


@pytest.mark.parametrize("severity,floor", SEVERITY_FLOOR_CASES)
def test_a_counted_advisory_floors_the_verdict(severity: str, floor: RiskLevel) -> None:
    """PROPERTY (#242): counted > 0 and max severity S implies verdict >= floor(S).

    Asserted on the verdict's value, not on a count of advisories: a count
    cannot tell a verdict that respects the evidence from one that ignores it.
    """
    score = _scored_with(severity)

    assert score.dependency.security_metrics is not None
    assert score.dependency.security_metrics.counted_vulnerability_count == 1
    assert score.dependency.security_metrics.max_vulnerability_severity == severity
    assert RISK_ORDER[score.risk_level] >= RISK_ORDER[floor], (
        f"max counted severity {severity} must floor the verdict at "
        f"{floor.value}; got {score.risk_level.value} on a package whose "
        f"other fifteen signals are measured and clean"
    )


@pytest.mark.parametrize("severity,floor", SEVERITY_FLOOR_CASES)
def test_the_floor_records_the_advisory_that_caused_it(
    severity: str, floor: RiskLevel
) -> None:
    """The record names its cause, so a test can assert why and not only what.

    A verdict that happens to be right is indistinguishable from one that is
    right for the wrong reason unless the reason is in the payload.
    """
    score = _scored_with(severity)

    assert score.verdict_floor is not None
    assert score.verdict_floor.max_counted_severity == severity
    assert score.verdict_floor.advisory_id == f"OSV-{severity}"
    assert score.verdict_floor.floor_level is floor
    assert score.verdict_floor.unfloored_level is RiskLevel.LOW
    assert score.verdict_floor.applied is (floor is not RiskLevel.LOW)


def test_no_record_reports_low_beside_a_high_or_critical_advisory() -> None:
    """The contradiction #242 opened with: LOW next to known_vulnerable: true.

    Stated against the serialized contract rather than the scorer, because the
    contradiction was a property of what the tool *printed*.
    """
    for severity in ("HIGH", "CRITICAL"):
        entry = scored_dependency(_scored_with(severity), ecosystem="nodejs")

        assert entry["known_vulnerable"] is True
        assert entry["risk_level"] != RiskLevel.LOW.value


def test_the_severity_floor_is_one_rung_under_the_advisory() -> None:
    """The rule, checked against the table rather than restated from the code."""
    for severity, floor in SEVERITY_FLOOR_CASES:
        assert severity_floor(severity) is floor
    assert severity_floor("UNKNOWN") is None
    assert severity_floor("INFO") is None


# --------------------------------------------------------------------------
# 2. Monotonicity
# --------------------------------------------------------------------------


def _all_verdicts_for(severity: Optional[str]) -> List[Tuple[str, RiskLevel]]:
    """Score one dependency per risk band, with and without a counted advisory.

    Args:
        severity: Severity of the single counted advisory, or None for none.

    Returns:
        ``(band, verdict)`` for each band.
    """
    verdicts = []
    for band, days, latest, deprecated in (
        ("clean", 3, "1.0.0", False),
        ("aging", 200, "1.1.0", False),
        ("stale", 900, "3.0.0", False),
        ("abandoned", 2000, "9.0.0", True),
    ):
        dependency = _healthy_dependency(f"{band}-package")
        dependency.last_updated = datetime.now(timezone.utc) - timedelta(days=days)
        dependency.latest_version = latest
        dependency.is_deprecated = deprecated
        advisories = [_advisory(f"OSV-{severity}", severity)] if severity else []
        _update_dependency_with_vulnerabilities(dependency, advisories, "LOW")
        verdicts.append((band, RiskScorer().score_dependency(dependency).risk_level))
    return verdicts


@pytest.mark.parametrize("severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_the_floor_never_lowers_a_verdict(severity: str) -> None:
    """INVARIANT (#242): the floor raises or does nothing. It never lowers.

    Any downward movement is a bug, not a re-baseline. Compared band by band
    against the same packages with no advisory at all, which is the verdict
    the weighted mean produces unaided.
    """
    unfloored = dict(_all_verdicts_for(None))

    for band, verdict in _all_verdicts_for(severity):
        assert RISK_ORDER[verdict] >= RISK_ORDER[unfloored[band]], (
            f"{band}: a {severity} advisory lowered the verdict from "
            f"{unfloored[band].value} to {verdict.value}"
        )


def test_a_verdict_already_above_the_floor_is_left_alone() -> None:
    """A CRITICAL package with a HIGH advisory stays CRITICAL, and says why.

    The floor is a lower bound, not an assignment. This is the case that would
    catch a `=` written where a `max` was meant.
    """
    dependency = _healthy_dependency("abandoned-and-exploited")
    dependency.last_updated = datetime.now(timezone.utc) - timedelta(days=2000)
    dependency.latest_version = "9.0.0"
    dependency.is_deprecated = True
    dependency.maintainer_count = 0
    dependency.has_tests = False
    dependency.has_ci = False
    dependency.has_contribution_guidelines = False
    dependency.security_metrics = SecurityMetrics(
        has_security_policy=False,
        has_dependency_update_tools=False,
        has_signed_commits=False,
        has_branch_protection=False,
        is_maintained=False,
    )
    dependency.community_metrics = CommunityMetrics(
        star_count=0, contributor_count=0, commit_frequency=0.0
    )
    _update_dependency_with_vulnerabilities(
        dependency, [_advisory("OSV-HIGH", "HIGH")], "LOW"
    )

    score = RiskScorer().score_dependency(dependency)

    assert score.risk_level is RiskLevel.CRITICAL
    assert score.verdict_floor is not None
    assert score.verdict_floor.floor_level is RiskLevel.MEDIUM
    assert score.verdict_floor.applied is False
    assert score.verdict_floor.unfloored_level is RiskLevel.CRITICAL


# --------------------------------------------------------------------------
# 3. The null invariant
# --------------------------------------------------------------------------

#: Everything a scored record carries apart from the one field the floor is
#: allowed to touch. Compared field by field rather than by count.
_SCORE_FIELDS = tuple(AXIOS_COMPONENT_SCORES) + (
    "total_score",
    "factors",
    "unknown_signals",
    "measured_signal_count",
    "total_signal_count",
    "insufficient_data",
)


@pytest.mark.parametrize(
    "advisories,label",
    [
        ([], "no advisories at all"),
        (
            [_advisory("OSV-WITHDRAWN", "CRITICAL", fixed=None)],
            "one advisory, withdrawn",
        ),
        ([_advisory("OSV-INFO", "INFO")], "one informational advisory"),
    ],
)
def test_a_record_with_no_counted_advisories_scores_as_before(
    advisories: List[Dict[str, object]], label: str
) -> None:
    """INVARIANT (#242): zero counted advisories, zero change.

    Proved rather than asserted: the same dependency is scored with the floor
    reachable and with the advisory list emptied, and every field of both
    results is compared. ``verdict_floor`` is the only field allowed to differ,
    and here it does not either — nothing established a floor.
    """
    if advisories and advisories[0]["id"] == "OSV-WITHDRAWN":
        advisories = [dict(advisories[0], withdrawn=True)]

    with_advisories = _healthy_dependency("null-invariant")
    _update_dependency_with_vulnerabilities(with_advisories, advisories, "LOW")
    without = _healthy_dependency("null-invariant")
    _update_dependency_with_vulnerabilities(without, [], "LOW")

    scored = RiskScorer().score_dependency(with_advisories)
    baseline = RiskScorer().score_dependency(without)

    assert with_advisories.security_metrics is not None
    assert with_advisories.security_metrics.counted_vulnerability_count == 0, label
    assert scored.risk_level is baseline.risk_level, label
    assert scored.verdict_floor is None, label
    for name in _SCORE_FIELDS:
        assert getattr(scored, name) == getattr(baseline, name), f"{label}: {name}"


def test_an_unmeasured_advisory_lookup_establishes_no_floor() -> None:
    """A lookup that failed is not a lookup that found nothing, and not a floor.

    #219's distinction, checked from the floor's side: an outage must not
    become a verdict in either direction.
    """
    dependency = _healthy_dependency("lookup-failed")
    dependency.record_advisory_lookup(
        AdvisoryLookupState.FAILED, sources_unavailable=["OSV"]
    )

    score = RiskScorer().score_dependency(dependency)

    assert score.verdict_floor is None
    assert score.measurements["exploit"].is_measured is False


# --------------------------------------------------------------------------
# 4. The negative case
# --------------------------------------------------------------------------


def test_an_advisory_that_misses_the_installed_version_floors_nothing() -> None:
    """NEGATIVE (#242): the floor keys on counted, not on found.

    A CRITICAL fixed two releases before the installed version is exactly the
    advisory #61 stopped counting. Letting it floor a verdict would rebuild #61
    inside the fix for #242.
    """
    dependency = _healthy_dependency("patched-already")
    dependency.installed_version = "3.0.0"
    dependency.latest_version = "3.0.0"
    _update_dependency_with_vulnerabilities(
        dependency,
        [_advisory("OSV-FIXED-EARLIER", "CRITICAL", introduced="1.0.0", fixed="2.0.0")],
        "LOW",
    )

    score = RiskScorer().score_dependency(dependency)
    metrics = dependency.security_metrics

    assert metrics is not None
    assert metrics.vulnerability_count == 1
    assert metrics.counted_vulnerability_count == 0
    assert known_vulnerable(dependency) is False
    assert score.verdict_floor is None
    assert score.risk_level is RiskLevel.LOW


def test_an_advisory_below_the_scoring_threshold_floors_nothing() -> None:
    """A HIGH advisory excluded by --vuln-min-severity must not floor either.

    The floor reads the same counted set the score does. If it read the raw
    advisory list instead, raising the threshold would stop changing the score
    and start changing nothing.
    """
    dependency = _healthy_dependency("under-threshold")
    _update_dependency_with_vulnerabilities(
        dependency, [_advisory("OSV-HIGH", "HIGH")], "CRITICAL"
    )

    score = RiskScorer().score_dependency(dependency)
    metrics = dependency.security_metrics

    assert metrics is not None
    assert metrics.filtered_vulnerability_reasons == {"below critical threshold": 1}
    assert score.verdict_floor is None
    assert score.risk_level is RiskLevel.LOW


def test_an_unknown_verdict_is_left_as_an_abstention() -> None:
    """SCOPE (#242): UNKNOWN is not a rung, and the floor does not move it.

    ``insufficient_data: true`` implies ``risk_level: UNKNOWN`` in the
    published contract, so raising it here would be a semantic break to schema
    v2 rather than the additive change the vote asked for. UNKNOWN is also not
    the defect: it is not a reassuring verdict. Tracked as #248.
    """
    dependency = DependencyMetadata(name="barely-known", installed_version="1.0.0")
    _update_dependency_with_vulnerabilities(
        dependency, [_advisory("OSV-CRITICAL", "CRITICAL")], "LOW"
    )

    score = RiskScorer().score_dependency(dependency)

    assert score.insufficient_data is True
    assert score.risk_level is RiskLevel.UNKNOWN
    assert score.verdict_floor is None


# --------------------------------------------------------------------------
# 5. The named case: axios 1.6.5
# --------------------------------------------------------------------------


def _recorded_axios() -> Tuple[DependencyMetadata, List[Dict[str, object]]]:
    """Rehydrate the captured axios 1.6.5 scoring input.

    The recording holds the metadata the pipeline handed the scorer and the
    advisory records it handed the annotator. It deliberately holds none of the
    scorer's own outputs, so the test recomputes the bug rather than replaying
    a copy of it.

    Returns:
        The metadata and the recorded advisories.
    """
    document = json.loads(AXIOS_FIXTURE.read_text(encoding="utf-8"))
    recorded = document["metadata"]
    licence = recorded["license"]
    community = recorded["community"]
    scorecard = recorded["scorecard"]
    dependency = DependencyMetadata(
        name=recorded["name"],
        installed_version=recorded["installed_version"],
        latest_version=recorded["latest_version"],
        last_updated=datetime.fromisoformat(recorded["last_updated"]),
        maintainer_count=recorded["maintainer_count"],
        is_deprecated=recorded["is_deprecated"],
        repository_url=recorded["repository_url"],
        has_tests=recorded["has_tests"],
        has_ci=recorded["has_ci"],
        has_contribution_guidelines=recorded["has_contribution_guidelines"],
        license_info=LicenseInfo(
            license_id=licence["license_id"],
            category=LicenseCategory(licence["category"]),
            is_approved=licence["is_approved"],
            url=licence["url"],
            risk_level=RiskLevel(licence["risk_level"]),
        ),
        community_metrics=CommunityMetrics(
            star_count=community["star_count"],
            contributor_count=community["contributor_count"],
            commit_frequency=community["commit_frequency"],
        ),
        security_metrics=SecurityMetrics(
            has_security_policy=scorecard["has_security_policy"],
            has_dependency_update_tools=scorecard["has_dependency_update_tools"],
            has_signed_commits=scorecard["has_signed_commits"],
            has_branch_protection=scorecard["has_branch_protection"],
            is_maintained=scorecard["is_maintained"],
        ),
        transitive_dependencies=set(recorded["transitive_dependencies"]),
        transitive_source=recorded["transitive_source"],
        additional_info=dict(recorded["additional_info"]),
    )
    dependency.source_repository_state = SourceRepositoryState(
        recorded["source_repository_state"]
    )
    dependency.record_advisory_lookup(
        AdvisoryLookupState(recorded["advisory_lookup_state"]),
        sources_unavailable=[],
    )
    return dependency, document["advisories"]


def _scored_axios() -> DependencyRiskScore:
    """Score the recorded axios 1.6.5 input through the real annotator.

    Returns:
        The scored dependency.
    """
    dependency, advisories = _recorded_axios()
    _update_dependency_with_vulnerabilities(dependency, advisories, "LOW")
    return RiskScorer().score_dependency(dependency)


def test_axios_1_6_5_is_the_case_the_issue_recorded() -> None:
    """The recording reproduces #242's numbers: 44 found, 29 counted, HIGH.

    The fourth number the issue recorded was ``max_cvss_score == 8.0``, and it
    is gone rather than changed: 8.0 was ``severity_to_score("HIGH")``, not a
    CVSS anybody computed, and no advisory in this recording publishes a base
    score (#273). The floor is keyed on the **label**, so it is unmoved — see
    the test below, which still puts axios at MEDIUM off a HIGH severity.
    """
    score = _scored_axios()
    metrics = score.dependency.security_metrics

    assert metrics is not None
    assert metrics.vulnerability_count == 44
    assert metrics.counted_vulnerability_count == 29
    assert metrics.max_vulnerability_severity == "HIGH"
    assert metrics.max_cvss_score is None
    assert metrics.cvss_unknown_count == 29
    assert known_vulnerable(score.dependency) is True


def test_axios_1_6_5_no_longer_reports_low() -> None:
    """REGRESSION (#242): axios 1.6.5 was LOW beside 29 counted advisories.

    The verdict moves from LOW to MEDIUM and the reason is in the payload: the
    max counted severity is HIGH, which floors the verdict one rung under it.
    """
    score = _scored_axios()

    assert score.risk_level is RiskLevel.MEDIUM
    assert score.verdict_floor is not None
    assert score.verdict_floor.applied is True
    assert score.verdict_floor.unfloored_level is RiskLevel.LOW
    assert score.verdict_floor.floor_level is RiskLevel.MEDIUM
    assert score.verdict_floor.max_counted_severity == "HIGH"
    assert score.verdict_floor.advisory_id == "GHSA-35jp-ww65-95wh"


def test_axios_leading_indicators_are_untouched_by_the_floor() -> None:
    """This is what proves the change is a floor and not a re-weighting.

    Every component score, and the weighted mean itself, is asserted at the
    value the pre-fix run produced. A re-weighting would move the mean; a
    re-tuned exploit weight would move ``total_score``. Only the verdict moves.
    """
    score = _scored_axios()

    for name, expected in AXIOS_COMPONENT_SCORES.items():
        assert getattr(score, name) == expected, name
    assert score.total_score == pytest.approx(AXIOS_UNFLOORED_SCORE)
    # Still 0.2273 of the maximum, still inside LOW's 0.25 boundary. The
    # verdict moved; the number the verdict used to come from did not.
    assert score.total_score / 5.0 == pytest.approx(0.2272727, abs=1e-6)
    assert score.insufficient_data is False
    assert score.unknown_signals == []
    assert score.measured_signal_count == 16
    assert score.total_signal_count == 16


# --------------------------------------------------------------------------
# 6. Serialization
# --------------------------------------------------------------------------


def test_the_floor_serializes_with_every_key_present() -> None:
    """Both states carry the same keys, so a consumer reads ``applied``."""
    fired = verdict_floor_to_dict(_scored_axios().verdict_floor)
    absent = verdict_floor_to_dict(None)

    assert fired == {
        "applied": True,
        "max_counted_severity": "HIGH",
        "advisory_id": "GHSA-35jp-ww65-95wh",
        "floor": "MEDIUM",
        "from": "LOW",
        "to": "MEDIUM",
    }
    assert absent == {
        "applied": False,
        "max_counted_severity": None,
        "advisory_id": None,
        "floor": None,
        "from": None,
        "to": None,
    }
    assert set(fired) == set(absent)


def test_a_floor_the_verdict_already_cleared_is_still_reported() -> None:
    """The evaluated-and-cleared case is a record, not a silence.

    lodash 4.17.21 was this shape when #242 was filed: three counted advisories
        topping out at HIGH, a MEDIUM floor, and a verdict its own leading
        indicators had already carried past that floor. A payload that said nothing
        here would leave a reader unable to tell such a verdict from one where the
        floor was never computed at all.
    """
    dependency = _healthy_dependency("already-clear")
    dependency.last_updated = datetime.now(timezone.utc) - timedelta(days=900)
    dependency.latest_version = "3.0.0"
    dependency.maintainer_count = 1
    dependency.has_tests = False
    dependency.has_ci = False
    dependency.has_contribution_guidelines = False
    dependency.security_metrics = SecurityMetrics(
        has_security_policy=False,
        has_dependency_update_tools=False,
        has_signed_commits=False,
        has_branch_protection=False,
        is_maintained=False,
    )
    _update_dependency_with_vulnerabilities(
        dependency, [_advisory("OSV-HIGH", "HIGH")], "LOW"
    )

    score = RiskScorer().score_dependency(dependency)
    block = verdict_floor_to_dict(score.verdict_floor)

    assert score.risk_level is RiskLevel.HIGH
    assert block["applied"] is False
    assert block["floor"] == "MEDIUM"
    assert block["from"] == "HIGH"
    assert block["to"] is None
    assert block["advisory_id"] == "OSV-HIGH"


def test_the_serialized_verdict_agrees_with_the_serialized_floor() -> None:
    """The block explains the field beside it, on the path a consumer reads."""
    entry = scored_dependency(_scored_axios(), ecosystem="nodejs")
    floor = entry["verdict_floor"]

    assert isinstance(floor, dict)
    assert entry["risk_level"] == floor["to"]
    assert entry["known_vulnerable"] is True
    assert isinstance(entry["advisories"], dict)
    assert entry["advisories"]["max_counted_severity"] == floor["max_counted_severity"]
