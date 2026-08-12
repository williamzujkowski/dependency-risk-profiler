"""The frozen prospective analysis must run, and its gates must bite.

``docs/prospective-protocol.md`` §8 freezes ``research/prospective/analyse.py``
before the harvest. A frozen script that has never been executed is the defect
this repo keeps rediscovering: a bar stated with nothing checking it. These
tests run every §5 branch on synthetic data with known answers, twelve months
before the real data exists.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

RESEARCH = Path(__file__).resolve().parents[2] / "research"
sys.path.insert(0, str(RESEARCH))

from prospective import analyse, base_rate_pilot  # noqa: E402


def _package(
    index: int,
    *,
    quiet: bool,
    composite: float,
    downloads: float,
    staleness: float,
    ablated: float | None = None,
    stratum: str = "multi_release",
    full_instrument: bool = True,
) -> dict:
    return {
        "name": f"pkg-{index}",
        # One package per cluster: the clustered and unclustered intervals then
        # agree, which keeps these fixtures about the gates rather than about
        # the bootstrap.
        "cluster": index,
        "quiet": quiet,
        "full_instrument": full_instrument,
        "stratum": stratum,
        "composite": composite,
        "downloads": downloads,
        "staleness": staleness,
        "composite_ablated": composite if ablated is None else ablated,
    }


@pytest.fixture(autouse=True)
def _fast_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the resample count; these tests exercise gates, not precision.

    The registered ``REPLICATES`` stays 2000 for the real run. Every fixture
    here is perfectly separated or perfectly tied, so the interval's sign --
    which is all the §5 branches read -- is identical at 200 draws and the
    suite finishes in seconds rather than minutes.
    """
    monkeypatch.setattr(analyse, "REPLICATES", 200)


def _write(tmp_path: Path, packages: list[dict]) -> Path:
    path = tmp_path / "joined.json"
    path.write_text(json.dumps({"packages": packages}))
    return path


def _separated(n: int = 400) -> list[dict]:
    """A cohort where the composite separates perfectly and downloads do not.

    Quiet packages get a high composite (correct: high risk) and *also* high
    downloads, so the negation in :func:`analyse.load_rows` is load-bearing --
    without it the downloads arm would score 1.0 rather than 0.0.
    """
    packages = []
    for i in range(n):
        quiet = i % 2 == 0
        packages.append(
            _package(
                i,
                quiet=quiet,
                composite=0.9 if quiet else 0.1,
                downloads=1000.0 if quiet else 10.0,
                staleness=0.5,
            )
        )
    return packages


def test_downloads_are_negated_to_share_the_composite_orientation(tmp_path: Path) -> None:
    """The polarity bug that once made a losing arm look like a +0.28 win."""
    rows = analyse.load_rows(_write(tmp_path, _separated()))
    labels = [row.quiet for row in rows]
    # Raw downloads are higher for quiet packages, so unnegated they would score
    # 1.0 against the "quiet" label. Negated, high downloads means low risk.
    assert analyse.roc_auc([row.downloads for row in rows], labels) == 0.0
    assert analyse.roc_auc([row.composite for row in rows], labels) == 1.0


def test_minority_gate_fires_below_threshold(tmp_path: Path) -> None:
    """§5 line 5 gates on the minority count, not on the base rate."""
    # 380 quiet, 20 active: base rate 0.95, minority 20.
    packages = [
        _package(
            i,
            quiet=i >= 20,
            composite=0.9 if i >= 20 else 0.1,
            downloads=10.0,
            staleness=0.5,
        )
        for i in range(400)
    ]
    report = analyse.stratum_report(analyse.load_rows(_write(tmp_path, packages)), "multi_release")
    assert report["minority"] == 20
    assert report["minority_gate_passes"] is False
    assert report["deltas"] is None
    assert analyse.verdict(report)["claim"] == "not made"


def test_a_high_base_rate_alone_does_not_fire_the_gate(tmp_path: Path) -> None:
    """The measured 0.776 must not void the study; only a thin minority does.

    This is the regression guard for §2.2 -- the original criterion would have
    voided a powered design at T+12.
    """
    n = 2000
    packages = [
        _package(
            i,
            quiet=i >= 448,
            composite=0.9 if i >= 448 else 0.1,
            downloads=10.0,
            staleness=0.5,
        )
        for i in range(n)
    ]
    report = analyse.stratum_report(analyse.load_rows(_write(tmp_path, packages)), "multi_release")
    assert report["base_rate"] == pytest.approx(0.776, abs=0.001)
    assert report["minority_gate_passes"] is True


def test_losing_to_staleness_alone_fires_line_2_even_when_downloads_lose(tmp_path: Path) -> None:
    """§5 line 2 is unconditional: it fires however line 1 resolved."""
    packages = []
    # 800 packages so the minority class clears the registered floor of 300.
    for i in range(800):
        quiet = i % 2 == 0
        packages.append(
            _package(
                i,
                quiet=quiet,
                # The composite beats downloads comfortably...
                composite=0.9 if quiet else 0.1,
                downloads=10.0,
                # ...but staleness alone is perfect and the composite is not.
                staleness=1.0 if quiet else 0.0,
            )
        )
    # Blunt the composite on a slice so staleness strictly wins.
    for rec in packages[:160]:
        rec["composite"] = 0.5
    rows = analyse.load_rows(_write(tmp_path, packages))
    report = analyse.stratum_report(rows, "multi_release")
    result = analyse.verdict(report)
    assert result["claim"] == "not made"
    assert "one of its own inputs" in result["headline"]


def test_claim_is_made_only_when_both_comparators_fall(tmp_path: Path) -> None:
    packages = []
    # 800 packages so the minority class clears the registered floor of 300.
    for i in range(800):
        quiet = i % 2 == 0
        packages.append(
            _package(
                i,
                quiet=quiet,
                composite=0.95 if quiet else 0.05,
                downloads=10.0,
                staleness=0.5,
            )
        )
    report = analyse.stratum_report(analyse.load_rows(_write(tmp_path, packages)), "multi_release")
    result = analyse.verdict(report)
    assert result["claim"] == "made"


def test_censored_packages_are_dropped_not_scored_as_negative(tmp_path: Path) -> None:
    """§4: an unpublished package has an undefined outcome, not a false one."""
    packages = _separated(20)
    packages.append(
        {
            "name": "censored",
            "cluster": 999,
            "quiet": None,
            "full_instrument": True,
            "stratum": "multi_release",
            "composite": 0.5,
            "downloads": 1.0,
            "staleness": 0.5,
            "composite_ablated": 0.5,
        }
    )
    rows = analyse.load_rows(_write(tmp_path, packages))
    assert len(rows) == 20
    assert all(row.name != "censored" for row in rows)


def test_one_shot_stratum_is_reported_but_never_the_headline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    packages = _separated(1600)
    for rec in packages[:800]:
        rec["stratum"] = "one_shot"
    joined = _write(tmp_path, packages)
    analyse.main(["--joined", str(joined)])
    result = json.loads(capsys.readouterr().out)
    assert "one_shot" in result["strata"]
    assert "multi_release" in result["strata"]
    # The pooled figure exists but the verdict is taken from the primary stratum.
    assert result["pooled_not_headline"]["stratum"] == "pooled"
    assert result["verdict"]["claim"] in {"made", "not made", "indeterminate"}


def test_full_instrument_yield_gate_fires(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """§5 line 4: below 60% cloneable this is a registry-only study."""
    packages = _separated(400)
    for rec in packages[:200]:
        rec["full_instrument"] = False
    analyse.main(["--joined", str(_write(tmp_path, packages))])
    result = json.loads(capsys.readouterr().out)
    assert result["full_instrument_yield"] == pytest.approx(0.5)
    assert result["full_instrument_gate_passes"] is False
    assert "registry-only study" in result["note"]
    # §4.1: the uncloneable packages still get their own reported base rate.
    assert result["uncloneable_stratum"]["n"] == 200
    assert result["uncloneable_stratum"]["base_rate"] is not None


class TestBaseRatePilotReduction:
    """§2.2's measurement is only as good as its packument reduction."""

    def test_unpublished_is_its_own_status_not_a_release(self) -> None:
        """``time.unpublished`` is an object; ``max()`` over raw times raises."""
        doc = {
            "time": {
                "created": "2019-01-01T00:00:00.000Z",
                "modified": "2020-01-01T00:00:00.000Z",
                "unpublished": {"time": "2020-01-01T00:00:00.000Z", "versions": []},
            }
        }
        assert base_rate_pilot.reduce_packument("gone", doc)["status"] == "unpublished"

    def test_modified_is_never_counted_as_a_release(self) -> None:
        """npm touches ``modified`` on an owner change, which is not publishing."""
        doc = {
            "time": {
                "created": "2019-01-01T00:00:00.000Z",
                # Years after the only real release.
                "modified": "2026-08-01T00:00:00.000Z",
                "1.0.0": "2019-01-01T00:00:00.000Z",
            }
        }
        record = base_rate_pilot.reduce_packument("quiet-pkg", doc)
        assert record["last_publish"] == "2019-01-01T00:00:00.000Z"
        assert record["release_count"] == 1

    def test_quiet_is_measured_against_the_window(self) -> None:
        records: list[dict] = [
            {"name": "a", "status": "ok", "last_publish": "2019-01-01T00:00:00.000Z",
             "release_count": 1, "repo_declared": True, "deprecated": False},
            {"name": "b", "status": "ok", "last_publish": "2026-08-01T00:00:00.000Z",
             "release_count": 9, "repo_declared": True, "deprecated": False},
            {"name": "c", "status": "absent"},
        ]
        summary = base_rate_pilot.summarise(
            records, datetime(2026, 8, 12, tzinfo=timezone.utc)
        )
        assert summary["resolved"] == 2
        assert summary["quiet"] == 1
        assert summary["base_rate"] == pytest.approx(0.5)
        # The unresolvable name is counted, never silently dropped.
        assert summary["status_counts"]["absent"] == 1
