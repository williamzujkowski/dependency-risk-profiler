"""An advisory with no published severity is counted, and says so (#272).

The range matcher decided these advisories apply to the installed version, and
they were then discarded from the score for carrying no severity label, under
the filter reason ``unknown severity``. Whole databases publish no severity —
``GO-*`` (0 of 42 sampled), ``RUSTSEC-*`` (0 of 14), and every ``MAL-*``
malicious-package record, which will never carry a CVSS because there is
nothing about malware for CVSS to score. So two ecosystems' native advisory
sources were silent, and the tool told a user that a package with known malware
in it was clean.

Three states have to stay apart, by construction rather than by convention
(rule 4):

* **severity is low** — a measurement. ``normalized_severity`` holds a tier and
  ``SEVERITY_ORDER`` can order it.
* **severity was never published** — not a measurement, and not zero.
  ``UNKNOWN`` is deliberately absent from ``SEVERITY_ORDER``, so nothing can
  order it; ``max_vulnerability_severity`` stays None; and
  ``severity_unknown_count`` carries the fact instead.
* **applicability could not be decided** — a different unknown entirely, about
  a different question, already carried by ``applicability_unknown_count``.
  A ``GO-*`` advisory whose applicability is *decided* and whose severity is
  unpublished must land in the second bucket and not the third.

The recordings are captured OSV bodies (rule 5); tests that need a payload no
cooperating database publishes are authored and labelled as such.
"""

from typing import Dict, List

import pytest
from osv_replay import annotated_dependency, counted_ids

from dependency_risk_profiler.models import DependencyMetadata, RiskLevel
from dependency_risk_profiler.scoring.risk_scorer import (
    ADVISORY_WITHOUT_SEVERITY_EXPLOIT_FLOOR,
    RiskScorer,
    severity_floor,
    verdict_floor_for,
)
from dependency_risk_profiler.vulnerabilities.aggregator import (
    MALICIOUS_SEVERITY,
    SEVERITY_NOT_PUBLISHED_REASON,
    SEVERITY_ORDER,
    _update_dependency_with_vulnerabilities,
    annotate_vulnerabilities_for_scoring,
)

#: The two packages issue #272 recorded, with the advisory each one holds and
#: the ecosystem key the tool routes it under. Both reported
#: ``known_vulnerable: false`` while holding an advisory the tool had already
#: decided was live against the pinned version.
SEVERITYLESS_CASES = [
    (
        "go_golang_org_x_net.json",
        "golang.org/x/net",
        "golang",
        "v0.55.0",
        "GO-2026-5942",
    ),
    ("crates_io_anyhow.json", "anyhow", "cargo", "1.0.75", "RUSTSEC-2026-0190"),
]


@pytest.mark.parametrize(
    "fixture,package_name,ecosystem,version,advisory_id", SEVERITYLESS_CASES
)
def test_a_severityless_advisory_that_applies_is_counted(
    monkeypatch: pytest.MonkeyPatch,
    fixture: str,
    package_name: str,
    ecosystem: str,
    version: str,
    advisory_id: str,
) -> None:
    """REGRESSION (#272): 0 scored, `known_vulnerable: false`, one live advisory."""
    dependency = annotated_dependency(
        monkeypatch,
        fixture=fixture,
        package_name=package_name,
        ecosystem=ecosystem,
        installed_version=version,
    )
    metrics = dependency.security_metrics

    assert metrics is not None
    assert counted_ids(dependency) == [advisory_id]
    assert metrics.counted_vulnerability_count == 1
    assert dependency.has_known_exploits is True


@pytest.mark.parametrize(
    "fixture,package_name,ecosystem,version,advisory_id", SEVERITYLESS_CASES
)
def test_unknown_severity_is_no_longer_a_reason_to_filter(
    monkeypatch: pytest.MonkeyPatch,
    fixture: str,
    package_name: str,
    ecosystem: str,
    version: str,
    advisory_id: str,
) -> None:
    """The filter reason is gone, and the advisory it dropped was ``affected``."""
    dependency = annotated_dependency(
        monkeypatch,
        fixture=fixture,
        package_name=package_name,
        ecosystem=ecosystem,
        installed_version=version,
    )
    metrics = dependency.security_metrics

    assert metrics is not None
    assert "unknown severity" not in metrics.filtered_vulnerability_reasons
    (live,) = [
        detail
        for detail in metrics.vulnerability_details
        if detail.get("id") == advisory_id
    ]
    assert live["version_match"] == "affected"
    assert live["filter_reasons"] == []


@pytest.mark.parametrize(
    "fixture,package_name,ecosystem,version,advisory_id", SEVERITYLESS_CASES
)
def test_no_severity_published_is_its_own_state(
    monkeypatch: pytest.MonkeyPatch,
    fixture: str,
    package_name: str,
    ecosystem: str,
    version: str,
    advisory_id: str,
) -> None:
    """Rule 4, as three assertions that a single wrong fix cannot satisfy.

    The advisory is counted **and** the maximum severity stays unmeasured
    (nothing was promoted to a tier) **and** the count of severity-less
    advisories is separate from the count of applicability-unknown ones. A fix
    that defaulted these to LOW passes the first, fails the second. A fix that
    reused ``applicability_unknown`` passes the first two and fails the third —
    and would be claiming the tool could not tell whether the advisory applied,
    when it could, and it does.
    """
    dependency = annotated_dependency(
        monkeypatch,
        fixture=fixture,
        package_name=package_name,
        ecosystem=ecosystem,
        installed_version=version,
    )
    metrics = dependency.security_metrics

    assert metrics is not None
    assert metrics.counted_vulnerability_count == 1
    assert metrics.max_vulnerability_severity is None
    assert metrics.max_cvss_score is None
    assert metrics.severity_unknown_count == 1
    assert metrics.severity_unknown_reasons == {SEVERITY_NOT_PUBLISHED_REASON: 1}
    assert metrics.applicability_unknown_count == 0


def test_nothing_can_order_an_unpublished_severity_against_a_tier() -> None:
    """The by-construction half of rule 4: ``UNKNOWN`` is not a rung.

    ``SEVERITY_ORDER`` has no key for it, so a future comparison written
    without thinking raises ``KeyError`` instead of quietly sorting an
    unmeasured severity in below ``LOW``. This is the structural guarantee that
    "no severity published" and "severity is LOW" cannot converge.
    """
    assert "UNKNOWN" not in SEVERITY_ORDER
    assert SEVERITY_ORDER[MALICIOUS_SEVERITY] > SEVERITY_ORDER["CRITICAL"]


@pytest.mark.parametrize("threshold", ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_no_threshold_filters_the_advisory_back_out(
    monkeypatch: pytest.MonkeyPatch, threshold: str
) -> None:
    """REGRESSION (#272): `--minimum-vulnerability-severity` must not rebuild it.

    Issue #272 records that ``--minimum-vulnerability-severity INFO`` did not
    recover the dropped advisory. The mirror of that mistake is a fix that
    counts it at ``INFO`` and drops it again at ``CRITICAL``, which is the same
    silence behind a flag.
    """
    dependency = annotated_dependency(
        monkeypatch,
        fixture="go_golang_org_x_net.json",
        package_name="golang.org/x/net",
        ecosystem="golang",
        installed_version="v0.55.0",
        minimum_severity=threshold,
    )
    metrics = dependency.security_metrics

    assert metrics is not None
    assert counted_ids(dependency) == ["GO-2026-5942"]


def test_a_live_advisory_leaves_the_exploit_signal_above_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero is what a clean package scores. A vulnerable one may not share it.

    ``exploit`` carries the largest single weight in the mean, and 0.0 is the
    value it takes for a package with no live advisories at all. Counting the
    advisory but scoring it 0.0 would move the silence one field along.
    """
    dependency = annotated_dependency(
        monkeypatch,
        fixture="crates_io_anyhow.json",
        package_name="anyhow",
        ecosystem="cargo",
        installed_version="1.0.75",
    )

    score = RiskScorer().score_dependency(dependency)

    assert score.exploit_score == ADVISORY_WITHOUT_SEVERITY_EXPLOIT_FLOOR
    assert score.exploit_score > 0.0
    assert "Known security issues (1 counted, severity not published)" in score.factors


def test_an_unpublished_severity_floors_nothing_and_that_is_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The decision #272 asked for, pinned.

    An advisory nobody scored puts no floor under the verdict: the weakest rung
    the scale has is LOW, ``severity_floor("LOW")`` is LOW, and a floor at the
    bottom of the scale forbids nothing. Returning None rather than a vacuous
    floor is what keeps ``verdict_floor.applied`` meaning what it says. The
    protection is that the advisory is counted, which the other tests here pin.
    """
    dependency = annotated_dependency(
        monkeypatch,
        fixture="go_golang_org_x_net.json",
        package_name="golang.org/x/net",
        ecosystem="golang",
        installed_version="v0.55.0",
    )

    assert verdict_floor_for(dependency, RiskLevel.LOW) is None
    assert severity_floor("LOW") is RiskLevel.LOW
    assert severity_floor("UNKNOWN") is None


def test_a_malicious_package_advisory_is_not_an_unknown_severity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REGRESSION (#272): `fsevents 1.2.9` holds `MAL-2023-462`, and it counts.

    OSV's malicious-packages database publishes no severity for the same reason
    it publishes no CVSS: the artifact is the attack, and there is no
    vulnerability to score. That is a categorical absence, not a gap, so the
    record is classified ``MALICIOUS`` rather than dropped into the
    unknown-severity bucket — and ``MALICIOUS`` outranks ``CRITICAL``, so a
    malware finding can never be less alarming than a LOW one.
    """
    dependency = annotated_dependency(
        monkeypatch,
        fixture="npm_fsevents.json",
        package_name="fsevents",
        ecosystem="nodejs",
        installed_version="1.2.9",
    )
    metrics = dependency.security_metrics

    assert metrics is not None
    assert "MAL-2023-462" in counted_ids(dependency)
    assert metrics.max_vulnerability_severity == MALICIOUS_SEVERITY
    assert metrics.severity_unknown_count == 0


def test_a_malicious_package_advisory_floors_the_verdict_at_critical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No one-rung slack: `severity_floor(MALICIOUS)` is CRITICAL, not HIGH.

    The rung of slack the other tiers get is paid for by reachability, which
    this tool does not measure. Malware does not depend on it — the payload
    runs from a package the manifest already asked for — so the allowance has
    nothing to be an allowance *for*.
    """
    dependency = annotated_dependency(
        monkeypatch,
        fixture="npm_fsevents.json",
        package_name="fsevents",
        ecosystem="nodejs",
        installed_version="1.2.9",
    )

    floor = verdict_floor_for(dependency, RiskLevel.LOW)

    assert floor is not None
    assert floor.max_counted_severity == MALICIOUS_SEVERITY
    assert floor.advisory_id == "MAL-2023-462"
    assert floor.floor_level is RiskLevel.CRITICAL
    assert floor.applied is True
    assert severity_floor(MALICIOUS_SEVERITY) is RiskLevel.CRITICAL
    assert severity_floor("CRITICAL") is RiskLevel.HIGH


def test_malicious_does_not_invent_a_cvss_score() -> None:
    """ADVERSARIAL (authored, not captured): the tier must not become a number.

    No malicious-package advisory carries a CVSS, so no recording can show what
    happens when one is the *only* counted advisory — ``fsevents 1.2.9`` also
    holds a CVSS-scored CRITICAL. ``severity_to_score`` would answer 10.0 for
    ``MALICIOUS``, and ``max_counted_cvss_score`` promises a measurement or
    nothing (#217). It has to stay nothing.
    """
    dependency = _update_dependency_with_vulnerabilities(
        DependencyMetadata(name="evil", installed_version="1.0.0"),
        [{"id": "MAL-2026-9999", "source": "OSV", "confidence": "HIGH"}],
    )
    metrics = dependency.security_metrics

    assert metrics is not None
    assert metrics.counted_vulnerability_count == 1
    assert metrics.max_vulnerability_severity == MALICIOUS_SEVERITY
    assert metrics.max_cvss_score is None


def test_a_malicious_record_collapsed_into_an_earlier_id_is_still_malicious() -> None:
    """ADVERSARIAL (authored, not captured): #274 must not undo #272.

    ``MAL-2023-462`` names ``GHSA-xv2f-5jw4-v95m`` in its aliases. When OSV
    answers with both for one package, the alias closure collapses them onto
    the lexicographically first ID — a ``GHSA-`` one — and a classifier that
    only read ``id`` would lose the malware finding at exactly the moment the
    two fixes met.
    """
    records: List[Dict[str, object]] = [
        {
            "id": "GHSA-zzzz-zzzz-zzzz",
            "source": "OSV",
            "aliases": ["MAL-2026-9999"],
            "confidence": "HIGH",
        }
    ]
    (annotated,) = annotate_vulnerabilities_for_scoring(records, "LOW", None, "nodejs")

    assert annotated["normalized_severity"] == MALICIOUS_SEVERITY
    assert annotated["counted_in_score"] is True
