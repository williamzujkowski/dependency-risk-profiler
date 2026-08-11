"""Guards for the band-crossing study.

`docs/band-crossing-protocol.md` and its §6 amendment. The band logic is where
this study's whole claim lives: a maintainer change that stays inside a band
moves the score by nothing, and counting it would restate the 22.8% set-change
figure as capacity it does not have.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))

from transfer_study.band_crossing import (  # noqa: E402
    Movement,
    band_of,
    effective_accounts,
    summarise,
)

RESULTS = Path(__file__).resolve().parents[2] / "research" / "results"
T = datetime(2024, 8, 1, tzinfo=timezone.utc)
HARVEST = datetime(2026, 8, 6, tzinfo=timezone.utc)


def move(before: int, after: int, quiet: bool = True) -> Movement:
    return Movement(
        package="pkg",
        baseline_published=T - timedelta(days=30),
        baseline_set=tuple(f"a{i}" for i in range(before)),
        current_set=tuple(f"a{i}" for i in range(after)),
        published_after_t=not quiet,
        modified_after_newest_release=True,
        window_days=740.0,
    )


@pytest.mark.parametrize(
    "count,band", [(0, "0-1"), (1, "0-1"), (2, "2"), (3, "3-4"), (4, "3-4"), (5, "5+"), (99, "5+")]
)
def test_bands_match_the_scorer(count: int, band: str) -> None:
    """The four bands the composite actually distinguishes."""
    assert band_of(count) == band
    assert band_of(None) is None


def test_a_change_inside_a_band_is_not_a_crossing() -> None:
    """The study's central distinction, and the reason 22.8% is the wrong number.

    27 maintainers becoming 28 changes the set, changes the count, and moves
    the score by exactly nothing. Counting it as capacity is how a nominal
    figure gets cited as an effective one.
    """
    inside = move(27, 28)
    assert inside.set_changed
    assert not inside.band_crossed
    assert inside.direction is None


def test_a_change_across_a_band_is_a_crossing_and_has_a_direction() -> None:
    crossing = move(2, 5)
    assert crossing.band_crossed
    assert crossing.direction == "risk_decreasing"
    assert move(5, 1).direction == "risk_increasing"


def test_more_maintainers_lowers_risk_not_raises_it() -> None:
    """Direction is reported in score units, not count units.

    The scorer treats more maintainers as lower risk, so a package gaining
    maintainers has its score go down. Reporting the count direction would
    invert the thing a reader cares about.
    """
    assert move(1, 6).direction == "risk_decreasing"
    assert move(6, 1).direction == "risk_increasing"


def test_rates_are_per_package_year_not_per_two_years() -> None:
    """§6's amendment: the window is each package's own exposure.

    The baseline is frozen at the last pre-T publish, which for a quiet package
    can be years before T. A uniform two-year denominator inflated the rate
    most for the quietest packages -- the ones the claim is about -- so a
    per-package-year rate is the primary quantity.
    """
    movements = [move(2, 5), move(27, 28), move(3, 3), move(1, 1)]
    summary = summarise(movements)
    assert summary["band_crossing_rate"] == pytest.approx(0.25)
    assert summary["set_change_rate"] == pytest.approx(0.5)
    assert summary["collapse_ratio_set_over_band"] == pytest.approx(2.0)
    expected_years = 4 * 740.0 / 365.25
    assert summary["package_years"] == pytest.approx(expected_years)
    assert summary["crossings_per_package_year"] == pytest.approx(1 / expected_years)


def test_account_clustering_would_catch_a_bot_fleet() -> None:
    """One account across every crossing must show as a share of 1.0.

    The 2,074-cases-to-43-campaign-days lesson applied to this study. If a
    single bot manufactured the rate, `largest_account_share` says so.
    """
    fleet = [
        Movement("p%d" % i, T, ("solo",), ("solo", "bot"), True, True, 700.0)
        for i in range(20)
    ]
    clustered = effective_accounts(fleet)
    assert clustered["nominal_crossings"] == 20
    assert clustered["largest_account_share"] == pytest.approx(1.0)


def test_the_recorded_result_still_says_what_three_documents_assert() -> None:
    """The published rates, pinned to the artifact they were written from."""
    result = json.loads((RESULTS / "band-crossing-2024.json").read_text())
    assert result["resolved"] == result["requested"] == 2906

    whole = result["whole_cohort"]
    assert whole["set_change_rate"] == pytest.approx(0.2281, abs=5e-4), (
        "the whole-cohort set-change rate no longer reproduces the handover "
        "study's independently measured 22.8%"
    )
    assert whole["collapse_ratio_set_over_band"] > 2.0

    quiet = result["quiet_all"]
    active = result["active_comparator"]
    assert quiet["crossings_per_package_year"] < active["crossings_per_package_year"], (
        "quiet packages no longer cross bands less often than active ones; "
        "docs/band-crossing-result.md is written on that comparison"
    )

    headline = result["headline_stratum"]
    assert headline["band_crossing_rate"] > 0.05, "line 1 now fires"
    directions = headline["direction"]
    ratio = max(directions.values()) / sum(directions.values())
    assert ratio < 0.7, (
        "the direction split is no longer close to even, which is the result "
        "the write-up leads on"
    )


def test_the_modified_probe_is_recorded_as_saturated() -> None:
    """A dead probe, kept visible rather than dropped.

    `time.modified` later than the newest release was adopted as an
    independent lower bound on non-publish mutation. It is 1.0 everywhere, so
    it discriminates nothing -- the third saturated signal in this codebase
    after `staleness` at 1.0 and `version` at 0.0.
    """
    result = json.loads((RESULTS / "band-crossing-2024.json").read_text())
    assert result["quiet_all"]["modified_after_newest_release_rate"] == 1.0
