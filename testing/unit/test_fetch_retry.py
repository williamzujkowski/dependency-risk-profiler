"""Tests for rate-limit-aware retry in fetch_url."""

from typing import Optional
from unittest import mock

import requests

from dependency_risk_profiler import utils


def _response(status: int, text: str = "", headers: Optional[dict] = None) -> mock.Mock:
    """Build a fake requests.Response with a working raise_for_status."""
    resp = mock.Mock()
    resp.status_code = status
    resp.text = text
    resp.headers = headers or {}

    def raise_for_status() -> None:
        if status >= 400:
            raise requests.HTTPError(f"{status} error", response=resp)

    resp.raise_for_status.side_effect = raise_for_status
    return resp


def test_fetch_url_retries_on_429_then_succeeds() -> None:
    """A 429 is retried and the subsequent success is returned."""
    responses = [_response(429), _response(200, "payload")]
    with (
        mock.patch.object(utils.requests, "get", side_effect=responses),
        mock.patch.object(utils.time, "sleep") as sleep,
    ):
        result = utils.fetch_url("https://example.test/data")
    assert result == "payload"
    assert sleep.call_count == 1


def test_fetch_url_honors_retry_after_header() -> None:
    """Retry-After seconds drive the backoff delay."""
    responses = [_response(429, headers={"Retry-After": "7"}), _response(200, "ok")]
    with (
        mock.patch.object(utils.requests, "get", side_effect=responses),
        mock.patch.object(utils.time, "sleep") as sleep,
    ):
        result = utils.fetch_url("https://example.test/data")
    assert result == "ok"
    sleep.assert_called_once_with(7.0)


def test_fetch_url_gives_up_after_persistent_429() -> None:
    """Persistent rate limiting returns None instead of raising."""
    with (
        mock.patch.object(utils.requests, "get", return_value=_response(429)),
        mock.patch.object(utils.time, "sleep"),
    ):
        assert utils.fetch_url("https://example.test/data") is None


def test_fetch_url_does_not_retry_on_404() -> None:
    """A non-transient client error is not retried."""
    get = mock.Mock(return_value=_response(404))
    with (
        mock.patch.object(utils.requests, "get", get),
        mock.patch.object(utils.time, "sleep") as sleep,
    ):
        assert utils.fetch_url("https://example.test/missing") is None
    assert get.call_count == 1
    sleep.assert_not_called()
