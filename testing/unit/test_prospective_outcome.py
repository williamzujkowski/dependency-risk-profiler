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
    return outcome.observe("pkg", T, _Session(_Response(status, payload)))


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
