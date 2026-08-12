"""The outcome reader's censoring rules, tested offline.

§4 of ``docs/prospective-protocol.md`` fixes four registry states that are
**not** "went quiet": an unpublished package, a name npm's security holder has
taken over, an unresolvable document, and an all-deprecated package (which *is*
quiet if it published nothing, because deprecation is not a release).

Folding any of them into the negative class would inflate or deflate the base
rate on a technicality, twelve months from now, when nobody is watching. So
they are pinned here, twelve months early.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

import requests

RESEARCH = Path(__file__).resolve().parents[2] / "research"
sys.path.insert(0, str(RESEARCH))

from prospective import outcome  # noqa: E402

T = datetime(2026, 8, 12, tzinfo=timezone.utc)


class _Response:
    def __init__(self, status: int, payload: object) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> object:
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _Session:
    def __init__(self, response: _Response) -> None:
        self._response = response

    def get(self, url: str, timeout: int = 0) -> _Response:
        return self._response


def _observe(status: int, payload: object) -> dict:
    # A stand-in for requests.Session with only the one method observe() calls.
    # cast rather than a real Session so these stay offline.
    session = cast(requests.Session, _Session(_Response(status, payload)))
    return outcome.observe("pkg", T, session)


def test_a_release_after_t_is_not_quiet() -> None:
    result = _observe(200, {"time": {"1.0.0": "2026-10-01T00:00:00.000Z"}})
    assert result["quiet"] is False
    assert result["censored"] is None


def test_no_release_after_t_is_quiet() -> None:
    result = _observe(200, {"time": {"1.0.0": "2025-01-01T00:00:00.000Z"}})
    assert result["quiet"] is True


def test_unpublished_is_censored_not_quiet() -> None:
    """A removed package did not go quiet; it was removed."""
    result = _observe(
        200, {"time": {"unpublished": {"time": "2026-10-01T00:00:00.000Z"}}}
    )
    assert result["quiet"] is None
    assert result["censored"] == "unpublished"


def test_security_holder_takeover_is_censored() -> None:
    """npm parking a name is a different event from a maintainer going quiet."""
    result = _observe(
        200,
        {
            "time": {"1.0.0": "2025-01-01T00:00:00.000Z"},
            "maintainers": [{"name": "npm"}],
        },
    )
    assert result["quiet"] is None
    assert result["censored"] == "security_holder"


def test_a_still_real_maintainer_alongside_npm_is_not_censored() -> None:
    """Only a *sole* npm owner is a takeover."""
    result = _observe(
        200,
        {
            "time": {"1.0.0": "2025-01-01T00:00:00.000Z"},
            "maintainers": [{"name": "npm"}, {"name": "someone"}],
        },
    )
    assert result["censored"] is None
    assert result["quiet"] is True


def test_all_deprecated_but_silent_is_quiet_not_censored() -> None:
    """Deprecation is not a release (§4)."""
    result = _observe(
        200,
        {
            "time": {"1.0.0": "2025-01-01T00:00:00.000Z"},
            "versions": {"1.0.0": {"deprecated": "use something else"}},
        },
    )
    assert result["censored"] is None
    assert result["quiet"] is True


def test_a_vanished_package_is_censored() -> None:
    result = _observe(404, None)
    assert result["quiet"] is None
    assert result["censored"] == "unresolvable"


def test_modified_is_never_read_as_a_release() -> None:
    """npm touches ``modified`` on an owner change, which is not publishing."""
    result = _observe(
        200,
        {
            "time": {
                "1.0.0": "2025-01-01T00:00:00.000Z",
                "modified": "2026-12-01T00:00:00.000Z",
            }
        },
    )
    assert result["quiet"] is True


def test_the_scorer_output_satisfies_the_frozen_analysis_contract(tmp_path: Path) -> None:
    """score_at_t -> outcome join -> analyse, end to end, twelve months early.

    The analysis script was frozen before the harvest, so nothing may change to
    fit it later. That makes the contract between the two a thing to verify
    now, while a mismatch is a five-minute fix rather than a discovery made in
    2027 with the outcome already visible and no honest way to re-run.
    """
    import json

    from prospective import analyse
    from prospective.score_at_t import score_one

    record = {
        "name": "example",
        "last_publish": "2024-01-01T00:00:00.000Z",
        "release_count": 4,
        "stratum": "multi_release",
        # No repository, so this exercises the contract without a network call.
        "repo_slug": None,
        "maintainers": ["someone"],
        "downloads_last_month": 12,
        "deprecated": False,
    }
    scored = score_one(record, tmp_path, "2025-07-12", datetime.now(timezone.utc))

    joined = tmp_path / "joined.json"
    joined.write_text(json.dumps({"packages": [{**scored, "quiet": True}]}))

    rows = analyse.load_rows(joined)
    assert len(rows) == 1
    row = rows[0]
    # Every field the frozen Row requires, present and the right type.
    assert isinstance(row.composite, float)
    assert isinstance(row.composite_ablated, float)
    assert isinstance(row.staleness, float)
    assert isinstance(row.downloads, float)
    assert row.stratum == "multi_release"
    assert row.full_instrument is False
