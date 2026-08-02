"""Tests that manifest fetching is bounded so a hostile repo cannot OOM us.

A public repo in a scanned org is untrusted input. If it serves a multi-gigabyte
lock file, reading it unbounded would exhaust memory before a parser ever runs.
``fetch_manifest_content`` streams the body and rejects anything past the cap.
"""

from typing import Iterable, Iterator, Optional

import pytest
import requests

from dependency_risk_profiler.org_scan.github import (
    _MAX_MANIFEST_BYTES,
    GitHubOrgClient,
    ManifestTooLargeError,
)
from dependency_risk_profiler.org_scan.models import RepositoryRef


class _FakeStreamResponse:
    """Minimal streaming stand-in for ``requests.Response``."""

    def __init__(
        self,
        chunks: Iterable[bytes],
        headers: Optional[dict] = None,
        status_code: int = 200,
        encoding: Optional[str] = "utf-8",
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.encoding = encoding
        self._chunks = chunks
        self.closed = False
        self.consumed_bytes = 0

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        for chunk in self._chunks:
            self.consumed_bytes += len(chunk)
            yield chunk

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")

    def close(self) -> None:
        self.closed = True


class _FakeSession:
    """Session whose ``get`` returns a canned streaming response."""

    def __init__(self, response: _FakeStreamResponse) -> None:
        self._response = response
        self.stream_used: Optional[bool] = None

    def get(
        self,
        url: str,
        headers: dict,
        params: dict,
        timeout: int,
        stream: bool,
    ) -> _FakeStreamResponse:
        self.stream_used = stream
        return self._response


def _repo() -> RepositoryRef:
    return RepositoryRef(
        full_name="org/repo",
        name="repo",
        default_branch="main",
        html_url="https://github.com/org/repo",
        archived=False,
        fork=False,
    )


def _client(response: _FakeStreamResponse) -> tuple[GitHubOrgClient, _FakeSession]:
    session = _FakeSession(response)
    client = GitHubOrgClient(token="t", session=session)  # type: ignore[arg-type]
    return client, session


def test_small_manifest_is_returned_and_response_closed() -> None:
    """A normal-sized manifest streams through, decodes, and closes the body."""
    response = _FakeStreamResponse([b'{"ok": ', b"true}"])
    client, session = _client(response)

    content = client.fetch_manifest_content(_repo(), "package-lock.json")

    assert content == '{"ok": true}'
    assert session.stream_used is True
    assert response.closed is True


def test_oversized_streamed_body_is_rejected_without_full_read() -> None:
    """An enormous body is rejected shortly after passing the cap, not fully read.

    The chunk generator would yield effectively unbounded data; the guard must
    stop consuming once the cap is exceeded so memory is never exhausted.
    """
    chunk = b"x" * (64 * 1024)

    def endless() -> Iterator[bytes]:
        while True:
            yield chunk

    response = _FakeStreamResponse(endless())
    client, _ = _client(response)

    with pytest.raises(ManifestTooLargeError):
        client.fetch_manifest_content(_repo(), "Pipfile.lock")

    # Proof of "no OOM": consumption stopped within one chunk of the cap rather
    # than draining the infinite generator.
    assert response.consumed_bytes <= _MAX_MANIFEST_BYTES + len(chunk)
    assert response.closed is True


def test_oversized_content_length_header_is_rejected_before_reading() -> None:
    """A declared oversize Content-Length is refused before any body is read."""
    response = _FakeStreamResponse(
        [b"unused"],
        headers={"Content-Length": str(_MAX_MANIFEST_BYTES + 1)},
    )
    client, _ = _client(response)

    with pytest.raises(ManifestTooLargeError):
        client.fetch_manifest_content(_repo(), "package-lock.json")

    assert response.consumed_bytes == 0
    assert response.closed is True


def test_body_exactly_at_cap_is_accepted() -> None:
    """Content right at the cap is allowed; only content past it is rejected."""
    payload = b"a" * _MAX_MANIFEST_BYTES
    response = _FakeStreamResponse([payload])
    client, _ = _client(response)

    content = client.fetch_manifest_content(_repo(), "requirements.txt")

    assert len(content.encode("utf-8")) == _MAX_MANIFEST_BYTES
    assert response.closed is True
