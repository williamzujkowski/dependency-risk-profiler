"""Regression tests for OSV advisory normalization range handling."""

from dependency_risk_profiler.vulnerabilities.aggregator import OSVSource


def test_normalize_results_handles_events_without_introduced() -> None:
    """OSV range events without an 'introduced' key must not raise KeyError.

    Regression: a bare {"fixed": ...} or {"last_affected": ...} event used to
    crash _normalize_results, silently dropping the whole advisory (this hid
    every npm advisory on real scans of vulnerable targets like Juice Shop).
    """
    osv = OSVSource()
    results = [
        {
            "id": "GHSA-test-npm",
            "summary": "Prototype pollution",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/.../C:H"}],
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [
                        {
                            # npm advisories use ECOSYSTEM ranges, not SEMVER.
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.21"},
                            ],
                        },
                        {
                            "type": "GIT",
                            # last_affected has no "introduced" or "fixed".
                            "events": [{"last_affected": "abc123"}],
                        },
                    ],
                }
            ],
        }
    ]

    normalized = osv._normalize_results(results)

    assert len(normalized) == 1
    assert normalized[0]["id"] == "GHSA-test-npm"
    assert "4.17.21" in normalized[0]["fixed_versions"]


def test_normalize_results_survives_missing_ranges() -> None:
    """An affected entry with no ranges still yields a normalized advisory."""
    osv = OSVSource()
    normalized = osv._normalize_results(
        [{"id": "OSV-x", "affected": [{"package": {"name": "p"}}]}]
    )
    assert len(normalized) == 1
    assert normalized[0]["fixed_versions"] == []
