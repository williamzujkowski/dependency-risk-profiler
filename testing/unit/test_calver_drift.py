"""Calendar-versioned drift is measured in elapsed time, not major versions (#126).

`certifi 2022.12.7` is a CA bundle dated 7 December 2022, not release 2022 of a
SemVer line. Scoring it by component distance reported a four-year gap as "4
major versions behind", warning about breaking upgrades that do not exist while
hiding the real risk (a stale trust store).
"""

from datetime import datetime, timedelta, timezone
from typing import TypedDict

from dependency_risk_profiler.cli.formatter import TerminalFormatter
from dependency_risk_profiler.community.analyzer import analyze_pypi_community_metrics
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.org_scan.report import _version_drift_line
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.versioning import (
    calendar_drift_days,
    calendar_drift_label,
    is_calendar_version,
    match_release_date,
)

UTC = timezone.utc


def _dated_dependency(
    name: str,
    installed_version: str,
    latest_version: str,
    installed_release: datetime,
    latest_release: datetime,
) -> DependencyMetadata:
    """Build a dependency carrying the release timestamps the analyzers collect."""
    return DependencyMetadata(
        name=name,
        installed_version=installed_version,
        latest_version=latest_version,
        community_metrics=CommunityMetrics(
            installed_release_date=installed_release,
            last_release_date=latest_release,
        ),
    )


# --------------------------------------------------------------------------
# Detection: shape, not magnitude
# --------------------------------------------------------------------------


def test_calendar_shapes_are_detected() -> None:
    """YYYY.MM, YYYY.MM.DD, YYYY.N and v-prefixed Go tags all read as CalVer."""
    assert is_calendar_version("2022.12.7")  # certifi
    assert is_calendar_version("2022.12.07")  # certifi, PyPI spelling
    assert is_calendar_version("2020.1")  # pytz sequence-style
    assert is_calendar_version("2026.3.post1")  # pytz with a PEP 440 suffix
    assert is_calendar_version("v2021.10.13")  # Go vYYYY.MM.DD tag
    assert is_calendar_version("1990.1")  # lower year bound
    assert is_calendar_version("2100.12.31")  # upper year bound


def test_semver_is_never_mistaken_for_a_calendar_version() -> None:
    """A big or date-ish number without the calendar shape stays SemVer."""
    for semver in (
        "1.2.3",
        "2.28.2",  # requests
        "4.2",  # Django
        "0.52.0",
        "1.2.3-rc1",
        "20.04",  # distro-style, two-digit year
        "1999",  # bare four-digit release number, no date shape
        "20210428",  # compact date, no separators
        "1989.1",  # below the plausible year floor
        "2101.1",  # above the plausible year ceiling
        "v0.0.0-20210428235338-abcdef123456",  # Go pseudo-version
    ):
        assert not is_calendar_version(semver), semver


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


def test_certifi_scores_elapsed_time_not_major_versions() -> None:
    """Certifi 2022.12.7 -> 2026.7.22 is 3.6 years of drift, not 4 majors."""
    scorer = RiskScorer()
    certifi = _dated_dependency(
        "certifi",
        "2022.12.7",
        "2026.7.22",
        datetime(2022, 12, 7, tzinfo=UTC),
        datetime(2026, 7, 22, tzinfo=UTC),
    )

    score = scorer.score_dependency(certifi)

    # Component distance would have hit the 1.0 major-version ceiling.
    assert score.version_score == 0.75


def test_pytz_sequence_calver_scores_elapsed_time() -> None:
    """Pytz 2020.1 -> 2026.3 is 6 years of drift, not 6 majors."""
    scorer = RiskScorer()
    pytz = _dated_dependency(
        "pytz",
        "2020.1",
        "2026.3.post1",
        datetime(2020, 1, 15, tzinfo=UTC),
        datetime(2026, 7, 22, tzinfo=UTC),
    )

    score = scorer.score_dependency(pytz)

    assert score.version_score == 1.0


def test_recent_calver_release_is_not_flagged_as_a_major_jump() -> None:
    """The real win: a CalVer package weeks behind no longer reads as major drift."""
    scorer = RiskScorer()
    now = datetime.now(UTC)
    fresh = _dated_dependency(
        "certifi",
        "2025.12.1",
        "2026.1.15",
        now - timedelta(days=45),
        now,
    )

    score = scorer.score_dependency(fresh)

    assert score.version_score == 0.0


def test_calver_drift_is_unmeasured_without_release_timestamps() -> None:
    """No timestamps means no number: the signal drops out of the score (#74)."""
    scorer = RiskScorer()
    undated = DependencyMetadata(
        name="tzdata",
        installed_version="2022.1",
        latest_version="2026.1",
    )

    score = scorer.score_dependency(undated)

    assert score.version_score is None
    assert "version" in score.unknown_signals


class _CommunitySignals(TypedDict):
    """The community kwargs both fixtures below share.

    A ``TypedDict`` rather than a bare dict so ``**common`` is checked against
    the real ``DependencyMetadata`` signature instead of widening to
    ``dict[str, object]``.
    """

    maintainer_count: int
    has_tests: bool
    has_ci: bool
    has_contribution_guidelines: bool


def test_unmeasured_calver_drift_is_excluded_from_the_denominator() -> None:
    """An unmeasured drift signal must not deflate the score as a confident zero."""
    scorer = RiskScorer()
    common: _CommunitySignals = {
        "maintainer_count": 5,
        "has_tests": True,
        "has_ci": True,
        "has_contribution_guidelines": True,
    }
    undated_calver = DependencyMetadata(
        name="tzdata",
        installed_version="2022.1",
        latest_version="2026.1",
        **common,
    )
    no_version_data = DependencyMetadata(
        name="tzdata",
        installed_version="2022.1",
        **common,
    )

    undated_score = scorer.score_dependency(undated_calver)
    baseline_score = scorer.score_dependency(no_version_data)

    assert undated_score.total_score == baseline_score.total_score


def test_semver_control_is_unaffected() -> None:
    """Requests 2.28.2 -> 2.34.2 still scores as ordinary minor drift."""
    scorer = RiskScorer()
    requests = DependencyMetadata(
        name="requests",
        installed_version="2.28.2",
        latest_version="2.34.2",
    )
    major_jump = DependencyMetadata(
        name="flask",
        installed_version="2.0.0",
        latest_version="3.1.3",
    )

    assert scorer.score_dependency(requests).version_score == 0.5
    assert scorer.score_dependency(major_jump).version_score == 1.0


def test_go_pseudo_version_still_scores_as_before() -> None:
    """A real go.mod pseudo-version is not date-shaped and keeps its old score."""
    scorer = RiskScorer()
    # From Contrast-Security-OSS/go-test-bench's go.mod.
    pseudo = DependencyMetadata(
        name="github.com/gin-contrib/multitemplate",
        installed_version="v0.0.0-20210428235909-8a2f6dd269a0",
        latest_version="v0.0.0-20250101000000-000000000000",
    )

    score = scorer.score_dependency(pseudo)

    # Not PEP 440, not CalVer: the pre-existing moderate-distance fallback.
    assert score.version_score == 0.5


def test_go_calendar_tag_uses_elapsed_time() -> None:
    """A vYYYY.MM.DD Go tag is calendar-versioned and scores on elapsed time."""
    scorer = RiskScorer()
    go_calver = _dated_dependency(
        "example.com/tzdata",
        "v2021.10.13",
        "v2026.1.5",
        datetime(2021, 10, 13, tzinfo=UTC),
        datetime(2026, 1, 5, tzinfo=UTC),
    )

    score = scorer.score_dependency(go_calver)

    assert score.version_score == 1.0


def test_calver_range_pin_keeps_the_range_default() -> None:
    """A range operator still short-circuits before the calendar branch."""
    scorer = RiskScorer()
    ranged = DependencyMetadata(
        name="certifi",
        installed_version=">=2022.12.7",
        latest_version="2026.7.22",
    )

    assert scorer.score_dependency(ranged).version_score == 0.25


# --------------------------------------------------------------------------
# Labels
# --------------------------------------------------------------------------


def test_terminal_signal_names_calendar_versioning() -> None:
    """The user is told about elapsed time, not imaginary breaking changes."""
    formatter = TerminalFormatter()
    certifi = DependencyRiskScore(
        dependency=_dated_dependency(
            "certifi",
            "2022.12.7",
            "2026.7.22",
            datetime(2022, 12, 7, tzinfo=UTC),
            datetime(2026, 7, 22, tzinfo=UTC),
        ),
        version_score=0.75,
        deprecation_score=0.0,
        transitive_score=0.0,
        total_score=2.0,
        risk_level=RiskLevel.MEDIUM,
        measured_signal_count=14,
        total_signal_count=14,
    )

    signals = formatter._format_leading_signals(certifi)

    assert "3 years behind (calendar versioning)" in signals
    assert "major version" not in signals


def test_org_scan_drift_line_names_calendar_versioning() -> None:
    """The org-scan report tells the same story as the terminal table."""
    certifi = _dated_dependency(
        "certifi",
        "2022.12.7",
        "2026.7.22",
        datetime(2022, 12, 7, tzinfo=UTC),
        datetime(2026, 7, 22, tzinfo=UTC),
    )

    line = _version_drift_line(certifi)

    assert line == (
        "Version drift: 2022.12.7 → 2026.7.22 " "(3 years behind (calendar versioning))"
    )


def test_org_scan_drift_line_unchanged_for_semver() -> None:
    """Ordinary versions keep the major/minor distance wording."""
    requests = DependencyMetadata(
        name="requests",
        installed_version="2.28.2",
        latest_version="2.34.2",
    )

    assert _version_drift_line(requests) == (
        "Version drift: 2.28.2 → 2.34.2 (6 minors behind)"
    )


def test_drift_labels_read_in_plain_language() -> None:
    """Elapsed drift is phrased in months or years, never in versions."""
    assert calendar_drift_label(10) == "< 1 month behind (calendar versioning)"
    assert calendar_drift_label(60) == "2 months behind (calendar versioning)"
    assert calendar_drift_label(400) == "1 year behind (calendar versioning)"
    assert calendar_drift_label(1323) == "3 years behind (calendar versioning)"
    assert calendar_drift_label(None) == "behind latest (calendar versioning)"


# --------------------------------------------------------------------------
# Timestamp collection
# --------------------------------------------------------------------------


def test_drift_days_normalize_mixed_timezones() -> None:
    """The same instant measures the same drift however its tz is spelled."""
    installed = datetime(2022, 12, 7, tzinfo=UTC)
    latest_utc = datetime(2026, 7, 22, tzinfo=UTC)
    latest_offset = latest_utc.astimezone(timezone(timedelta(hours=9)))
    naive_installed = installed.replace(tzinfo=None)

    assert calendar_drift_days(installed, latest_utc) == calendar_drift_days(
        naive_installed, latest_offset
    )


def test_release_date_lookup_tolerates_zero_padding() -> None:
    """A requirements pin of 2022.12.7 finds PyPI's 2022.12.07 release."""
    release_dates = {
        "2022.12.07": datetime(2022, 12, 7, tzinfo=UTC),
        "2026.7.22": datetime(2026, 7, 22, tzinfo=UTC),
    }

    assert match_release_date(release_dates, "2022.12.7") == datetime(
        2022, 12, 7, tzinfo=UTC
    )
    assert match_release_date(release_dates, "2019.1.1") is None
    assert match_release_date(release_dates, None) is None


def test_pypi_metadata_yields_the_installed_release_date() -> None:
    """The installed version's timestamp comes out of the payload already fetched."""
    certifi = DependencyMetadata(name="certifi", installed_version="2022.12.7")
    pypi_data = {
        "releases": {
            "2022.12.07": [{"upload_time": "2022-12-07T18:00:00"}],
            "2026.07.22": [{"upload_time": "2026-07-22T12:00:00"}],
        }
    }

    updated = analyze_pypi_community_metrics(certifi, pypi_data)

    metrics = updated.community_metrics
    assert metrics is not None
    assert metrics.installed_release_date is not None
    assert metrics.installed_release_date.date() == datetime(2022, 12, 7).date()
    assert metrics.last_release_date is not None
    assert metrics.last_release_date.date() == datetime(2026, 7, 22).date()
