"""A registry payload's wrong-typed field must not become a real finding.

`bool` is a subclass of `int`, so a JSON `true` in a CVSS field satisfied a
numeric guard and scored as 1.0 — a valid-looking LOW severity finding out of a
malformed or hostile registry response (#213). #211 fixed the return path of
`normalize_cvss_score`; these are the sweep: every normalizer, and every
adjacent field whose schema promises a string.
"""

from typing import Any, Dict, List

import pytest

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.vulnerabilities.aggregator import (
    GitHubAdvisorySource,
    NVDSource,
    OSVSource,
    _update_dependency_with_vulnerabilities,
    annotate_vulnerabilities_for_scoring,
    normalize_cvss_score,
)


class _StubResponse:
    """The two attributes the sources touch on a `requests` response."""

    def __init__(self, payload: object) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self._payload


def _raise_shape_error(*args: object, **kwargs: object) -> List[Dict[str, Any]]:
    """Stand in for a normalizer meeting a field of the wrong type."""
    raise TypeError("a field arrived as something no normalizer can read")


def _filter_reasons(annotated: Dict[str, object]) -> List[str]:
    """Read the annotation's reason list back with its element type intact."""
    reasons = annotated["filter_reasons"]
    assert isinstance(reasons, list)
    return reasons


def _nvd_payload(**cvss_data: object) -> List[Dict[str, Any]]:
    return [
        {
            "cve": {
                "id": "CVE-2024-0001",
                "published": "2024-01-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "A description"}],
                "metrics": {"cvssMetricV31": [{"cvssData": dict(cvss_data)}]},
            }
        }
    ]


def _github_payload(**advisory: object) -> List[Dict[str, Any]]:
    base: Dict[str, Any] = {
        "id": "GHSA-0000-0000-0000",
        "summary": "A summary",
        "publishedAt": "2024-01-01T00:00:00Z",
    }
    base.update(advisory)
    return [{"severity": "MODERATE", "advisory": base}]


class TestBooleanCvssScore:
    """A boolean is not a score, in any source."""

    @pytest.mark.parametrize("value", [True, False])
    def test_normalize_cvss_score_rejects_a_boolean(self, value: bool) -> None:
        """The known case from #211, kept as a regression."""
        assert normalize_cvss_score(value) is None

    def test_nvd_does_not_emit_a_boolean_base_score(self) -> None:
        """NVD copied `cvssData.baseScore` out verbatim, boolean included."""
        (normalized,) = NVDSource()._normalize_results(_nvd_payload(baseScore=True))

        assert normalized["cvss_score"] is None
        assert normalized["normalized_severity"] == "UNKNOWN"

    def test_github_does_not_emit_a_boolean_cvss_score(self) -> None:
        """The `advisory.cvss.score` GitHub sends was copied out verbatim too."""
        (normalized,) = GitHubAdvisorySource(api_token="token")._normalize_results(
            _github_payload(cvss={"score": True})
        )

        assert normalized["cvss_score"] is None

    def test_osv_does_not_emit_a_boolean_cvss_score(self) -> None:
        """OSV already normalized, so this states the invariant holds there."""
        (normalized,) = OSVSource()._normalize_results(
            [{"id": "OSV-1", "severity": [{"type": "CVSS_V3", "score": True}]}]
        )

        assert normalized["cvss_score"] is None

    def test_a_boolean_score_does_not_survive_annotation(self) -> None:
        """A cached record predating the fix is still refused at scoring."""
        (annotated,) = annotate_vulnerabilities_for_scoring(
            [{"id": "CVE-2024-0001", "source": "NVD", "cvss_score": True}],
            "LOW",
            None,
            "python",
        )

        assert annotated["cvss_score"] is None
        assert annotated["counted_in_score"] is False
        assert "unknown severity" in _filter_reasons(annotated)

    def test_a_real_zero_is_kept_and_a_missing_score_is_not_invented(self) -> None:
        """0.0 is a score NVD published; it is not the absence of one.

        `"MEDIUM" if severity or cvss_score else "LOW"` read a measured 0.0 as
        missing, because 0.0 is falsy — the mirror image of the boolean bug.
        """
        (measured,) = NVDSource()._normalize_results(_nvd_payload(baseScore=0.0))
        (absent,) = NVDSource()._normalize_results(_nvd_payload())

        assert measured["cvss_score"] == 0.0
        assert measured["confidence"] == "MEDIUM"
        assert absent["cvss_score"] is None
        assert absent["confidence"] == "LOW"


class TestUnmeasuredIsNotUnsevere:
    """An unreadable CVSS score must not read as "this advisory is harmless"."""

    def test_a_stated_severity_still_scores_when_the_cvss_is_unreadable(self) -> None:
        """None from `normalize_cvss_score` means unmeasured, not zero.

        The severity string is an independent claim, so an advisory NVD rated
        CRITICAL stays CRITICAL when its `baseScore` is junk.
        """
        (normalized,) = NVDSource()._normalize_results(
            _nvd_payload(baseScore=True, baseSeverity="CRITICAL")
        )

        assert normalized["cvss_score"] is None
        assert normalized["normalized_severity"] == "CRITICAL"

    def test_an_advisory_with_no_readable_severity_at_all_is_not_counted(self) -> None:
        """With nothing to go on it is refused, not scored as INFO."""
        (normalized,) = NVDSource()._normalize_results(_nvd_payload(baseScore=True))
        (annotated,) = annotate_vulnerabilities_for_scoring(
            [normalized], "LOW", None, "python"
        )

        assert annotated["normalized_severity"] == "UNKNOWN"
        assert annotated["counted_in_score"] is False
        assert "unknown severity" in _filter_reasons(annotated)


class TestWithdrawalNeedsATimestamp:
    """`withdrawn` is a date in every source's schema, not a flag."""

    def test_osv_boolean_withdrawn_does_not_suppress_an_advisory(self) -> None:
        """A payload claiming withdrawal without naming a date is not believed.

        `bool(vuln.get("withdrawn"))` accepted any truthy JSON value, so a
        `true` dropped a real advisory out of the score.
        """
        (normalized,) = OSVSource()._normalize_results(
            [{"id": "OSV-1", "withdrawn": True}]
        )

        assert normalized["withdrawn"] is False

    def test_osv_withdrawal_timestamp_is_believed(self) -> None:
        """The documented shape still works."""
        (normalized,) = OSVSource()._normalize_results(
            [{"id": "OSV-1", "withdrawn": "2024-01-01T00:00:00Z"}]
        )

        assert normalized["withdrawn"] is True

    def test_github_boolean_withdrawn_at_does_not_suppress_an_advisory(self) -> None:
        """Same shape behind GitHub's `withdrawnAt`."""
        (normalized,) = GitHubAdvisorySource(api_token="token")._normalize_results(
            _github_payload(withdrawnAt=True)
        )

        assert normalized["withdrawn"] is False


class TestWrongTypedTextFields:
    """A string field that arrives as something else is dropped, not rendered."""

    def test_github_survives_a_non_string_severity(self) -> None:
        """`vuln.get("severity", "").upper()` raised AttributeError on a bool.

        The caller wraps the whole lookup in `except Exception`, so the crash
        surfaced as "this package has no advisories".
        """
        results = [{"severity": True, "advisory": {"id": "GHSA-1"}}]

        (normalized,) = GitHubAdvisorySource(api_token="token")._normalize_results(
            results
        )

        assert normalized["severity"] == ""
        assert normalized["normalized_severity"] == "UNKNOWN"

    def test_nvd_survives_a_non_string_vuln_status(self) -> None:
        """`status.lower()` had the same problem."""
        payload = _nvd_payload(baseScore=7.5)
        payload[0]["cve"]["vulnStatus"] = True

        (normalized,) = NVDSource()._normalize_results(payload)

        assert normalized["withdrawn"] is False

    def test_a_non_string_published_date_is_dropped(self) -> None:
        """`published` is rendered as a date; a `true` there is not one."""
        (normalized,) = OSVSource()._normalize_results(
            [{"id": "OSV-1", "published": True}]
        )

        assert normalized["published"] == ""

    def test_a_non_string_fixed_version_is_dropped(self) -> None:
        """A boolean in `fixed_versions` is a version no scheme can order."""
        (normalized,) = OSVSource()._normalize_results(
            [
                {
                    "id": "OSV-1",
                    "affected": [
                        {
                            "package": {"name": "p", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"fixed": True}, {"fixed": "1.2.3"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        )

        assert normalized["fixed_versions"] == ["1.2.3"]

    def test_a_non_string_reference_url_is_dropped(self) -> None:
        """`[ref.get("url", "") for ref in ...]` assumed both shapes."""
        (normalized,) = OSVSource()._normalize_results(
            [
                {
                    "id": "OSV-1",
                    "references": [
                        {"url": "https://example.com/a"},
                        {"url": True},
                        "not-an-object",
                    ],
                }
            ]
        )

        assert normalized["references"] == ["https://example.com/a"]

    def test_a_non_string_summary_falls_back_to_the_placeholder(self) -> None:
        """`get(key, default)` returns the value for an explicit null."""
        (normalized,) = OSVSource()._normalize_results(
            [{"id": "OSV-1", "summary": None}]
        )

        assert normalized["summary"] == "No summary available"


class TestGitHubZeroCvssSentinel:
    """GitHub's non-nullable `cvss` block answers 0.0 when it has no vector.

    Live example: lodash's GHSA-p6mc-m468-83gg is severity HIGH with
    `{"score": 0, "vectorString": null}`. Copied out verbatim that is a
    high-severity advisory claiming the bottom of the CVSS scale — a sentinel
    wearing the type of a measurement (#217).
    """

    def test_a_zero_without_a_vector_is_unmeasured(self) -> None:
        """No vector means nobody scored it, whatever the score field says."""
        (normalized,) = GitHubAdvisorySource(api_token="token")._normalize_results(
            [
                {
                    "severity": "HIGH",
                    "advisory": {
                        "id": "GHSA-p6mc-m468-83gg",
                        "cvss": {"score": 0, "vectorString": None},
                    },
                }
            ]
        )

        assert normalized["cvss_score"] is None
        # The severity string is an independent claim and still stands.
        assert normalized["normalized_severity"] == "HIGH"

    def test_a_zero_with_a_vector_is_a_measurement(self) -> None:
        """A vector means somebody scored it; 0.0 is then the answer."""
        (normalized,) = GitHubAdvisorySource(api_token="token")._normalize_results(
            _github_payload(
                cvss={
                    "score": 0.0,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                }
            )
        )

        assert normalized["cvss_score"] == 0.0

    def test_a_real_score_is_untouched(self) -> None:
        """The guard is narrow: only a bare zero is read as the sentinel."""
        (normalized,) = GitHubAdvisorySource(api_token="token")._normalize_results(
            _github_payload(
                cvss={
                    "score": 8.1,
                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            )
        )

        assert normalized["cvss_score"] == 8.1


class TestMaximumCvssDistinguishesZeroFromUnmeasured:
    """`max_cvss if max_cvss > 0 else None` was the falsy read one line down.

    #216 fixed the per-advisory guard (`if cvss_score:` -> `is not None`) and
    left the accumulator that publishes the maximum, which started at 0.0 and
    could not tell a measured bottom-of-scale answer from never having read
    one (#217).
    """

    def test_a_counted_advisory_always_publishes_a_maximum(self) -> None:
        """The lodash shape: HIGH, no CVSS, still a statement about severity."""
        dependency = _update_dependency_with_vulnerabilities(
            DependencyMetadata(name="lodash", installed_version="4.17.15"),
            [
                {
                    "id": "GHSA-p6mc-m468-83gg",
                    "source": "GitHub Advisory",
                    "severity": "HIGH",
                    "normalized_severity": "HIGH",
                    "cvss_score": None,
                }
            ],
        )

        assert dependency.security_metrics is not None
        assert dependency.security_metrics.max_cvss_score == 8.0
        assert dependency.security_metrics.max_vulnerability_severity == "HIGH"

    def test_an_unreadable_advisory_leaves_the_maximum_unmeasured(self) -> None:
        """Nothing counted means nothing to take a maximum over."""
        dependency = _update_dependency_with_vulnerabilities(
            DependencyMetadata(name="pkg", installed_version="1.0.0"),
            [{"id": "X-1", "source": "OSV", "cvss_score": True}],
        )

        assert dependency.security_metrics is not None
        assert dependency.security_metrics.counted_vulnerability_count == 0
        assert dependency.security_metrics.max_cvss_score is None


class TestAShapeErrorIsNotNoAdvisories:
    """A broad `except Exception` around a fetch must not cover the parse.

    #216's `severity.upper()` raised into exactly such a handler and the
    package came back with no advisories at all. The normalizers are hardened,
    so this pins the *structure*: normalization runs outside the handler, and a
    failure there propagates instead of being reported as a clean package.
    """

    def test_osv_does_not_report_a_parse_failure_as_a_clean_package(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A normalizer that raises is a bug to surface, not an empty result."""
        source = OSVSource()
        monkeypatch.setattr(
            source, "_normalize_results", _raise_shape_error, raising=True
        )
        monkeypatch.setattr(
            "dependency_risk_profiler.vulnerabilities.aggregator.requests.post",
            lambda *args, **kwargs: _StubResponse({"vulns": [{"id": "OSV-1"}]}),
        )

        with pytest.raises(TypeError):
            source.get_vulnerabilities("pkg", "python")

    def test_github_does_not_report_a_parse_failure_as_a_clean_package(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same structure, same seam, in the second advisory source."""
        source = GitHubAdvisorySource(api_token="token")
        monkeypatch.setattr(
            source, "_normalize_results", _raise_shape_error, raising=True
        )
        monkeypatch.setattr(
            "dependency_risk_profiler.vulnerabilities.aggregator.requests.post",
            lambda *args, **kwargs: _StubResponse(
                {"data": {"securityVulnerabilities": {"nodes": [{"severity": "HIGH"}]}}}
            ),
        )

        with pytest.raises(TypeError):
            source.get_vulnerabilities("pkg", "python")

    def test_a_payload_of_the_wrong_shape_still_yields_no_advisories(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Moving the parse out must not turn a junk body into a crash."""
        source = OSVSource()
        monkeypatch.setattr(
            "dependency_risk_profiler.vulnerabilities.aggregator.requests.post",
            lambda *args, **kwargs: _StubResponse(["not", "a", "mapping"]),
        )

        assert source.get_vulnerabilities("pkg", "python") == []
