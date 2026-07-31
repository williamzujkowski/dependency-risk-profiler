"""Regression tests for timezone-safe release cadence analysis."""

from datetime import timezone
from unittest import mock

from dependency_risk_profiler.scorecard import maintained
from dependency_risk_profiler.scorecard.maintained import (
    _parse_git_iso_date,
    analyze_release_cadence,
)


def test_parse_git_iso_date_returns_aware_utc() -> None:
    """Git creatordate:iso strings parse to tz-aware UTC datetimes."""
    parsed = _parse_git_iso_date("2025-06-14 13:34:58 -0700")
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc
    assert parsed.hour == 20  # -0700 normalized to UTC


def test_parse_git_iso_date_handles_naive_and_bad_input() -> None:
    """A naive date is assumed UTC; unparseable input yields None."""
    naive = _parse_git_iso_date("2025-06-14 13:34:58")
    assert naive is not None and naive.tzinfo == timezone.utc
    assert _parse_git_iso_date("not-a-date") is None


def test_analyze_release_cadence_with_tz_aware_tags_does_not_raise() -> None:
    """REGRESSION: tz-aware tag dates minus now must not mix naive/aware."""
    tag_output = (
        "2026-07-30 10:29:33 +0000\n"
        "2026-06-01 08:00:00 -0700\n"
        "2026-01-15 12:00:00 +0000\n"
    )
    completed = mock.Mock(stdout=tag_output)
    with mock.patch.object(maintained.subprocess, "run", return_value=completed):
        result = analyze_release_cadence("/fake/repo")
    assert "days_since_last_release" in result
    assert result["days_since_last_release"] >= 0
    assert "average_days_between_releases" in result


def test_analyze_release_cadence_npm_fallback_is_tz_safe() -> None:
    """The npm `time` fallback is also tz-aware safe."""
    # No tags -> empty git output forces the package_data fallback.
    completed = mock.Mock(stdout="")
    package_data = {
        "time": {
            "created": "2020-01-01T00:00:00.000Z",
            "1.0.0": "2026-01-01T00:00:00.000Z",
            "1.1.0": "2026-06-01T00:00:00.000Z",
        }
    }
    with mock.patch.object(maintained.subprocess, "run", return_value=completed):
        result = analyze_release_cadence("/fake/repo", package_data)
    assert "days_since_last_release" in result
    assert result["days_since_last_release"] >= 0
