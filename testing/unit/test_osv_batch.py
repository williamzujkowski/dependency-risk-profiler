"""Tests for OSV querybatch cache pre-warming."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.org_scan.models import DependencyKey
from dependency_risk_profiler.org_scan.pipeline import (
    ExistingDependencyProfiler,
    VulnerabilityOptions,
)
from dependency_risk_profiler.vulnerabilities import osv_batch
from dependency_risk_profiler.vulnerabilities.aggregator import OSVSource

JsonObject = dict[str, object]
CacheStore = dict[tuple[str, str], list[JsonObject]]


@dataclass
class _MemoryCache:
    """In-memory cache adapter patched over the production cache functions."""

    store: CacheStore = field(default_factory=dict)

    def get(
        self, package_name: str, ecosystem: str
    ) -> tuple[list[JsonObject], float] | None:
        cached = self.store.get((package_name, ecosystem))
        if cached is None:
            return None
        return cached, 123.0

    def set(
        self,
        package_name: str,
        ecosystem: str,
        vulnerabilities: list[JsonObject],
    ) -> None:
        self.store[(package_name, ecosystem)] = vulnerabilities


@dataclass
class _FakeHTTPClient:
    """AsyncHTTPClient test double with queued POSTs and URL-keyed GETs."""

    post_responses: list[object]
    get_responses: dict[str, object]
    post_calls: list[tuple[str, JsonObject]] = field(default_factory=list)
    get_calls: list[str] = field(default_factory=list)
    closed: bool = False

    async def post(
        self,
        url: str,
        json_data: JsonObject,
        headers: dict[str, str] | None = None,
    ) -> JsonObject | None:
        self.post_calls.append((url, json_data))
        response = self.post_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if response is None:
            return None
        return _json_object(response)

    async def get(
        self,
        url: str,
        params: JsonObject | None = None,
        headers: dict[str, str] | None = None,
    ) -> JsonObject | None:
        self.get_calls.append(url)
        response = self.get_responses[url]
        if isinstance(response, Exception):
            raise response
        if response is None:
            return None
        return _json_object(response)

    async def close(self) -> None:
        self.closed = True


@dataclass
class _FakeHTTPClientFactory:
    """Callable patched over AsyncHTTPClient construction."""

    client: _FakeHTTPClient

    def __call__(self, concurrent_requests: int = 10) -> _FakeHTTPClient:
        return self.client


def _json_object(value: object) -> JsonObject:
    assert isinstance(value, dict)
    parsed: JsonObject = {}
    for key, item in value.items():
        assert isinstance(key, str)
        parsed[key] = item
    return parsed


def _install_memory_cache(monkeypatch: pytest.MonkeyPatch) -> _MemoryCache:
    cache = _MemoryCache()
    monkeypatch.setattr(osv_batch, "get_cached_data", cache.get)
    monkeypatch.setattr(osv_batch, "cache_data", cache.set)
    return cache


def _install_http_client(
    monkeypatch: pytest.MonkeyPatch,
    post_responses: list[object],
    get_responses: dict[str, object],
) -> _FakeHTTPClient:
    client = _FakeHTTPClient(post_responses=post_responses, get_responses=get_responses)
    monkeypatch.setattr(osv_batch, "AsyncHTTPClient", _FakeHTTPClientFactory(client))
    return client


def _raw_vuln(vuln_id: str, summary: str, fixed_version: str) -> JsonObject:
    return {
        "id": vuln_id,
        "published": "2024-01-01T00:00:00Z",
        "summary": summary,
        "details": f"{summary} details",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": fixed_version},
                        ]
                    }
                ]
            }
        ],
        "references": [{"url": f"https://osv.dev/vulnerability/{vuln_id}"}],
    }


def _batch_result(*vuln_ids: str, next_page_token: str = "") -> JsonObject:
    result: JsonObject = {
        "vulns": [
            {"id": vuln_id, "modified": "2024-01-02T00:00:00Z"} for vuln_id in vuln_ids
        ]
    }
    if next_page_token:
        result["next_page_token"] = next_page_token
    return result


def _querybatch_response(*results: JsonObject) -> JsonObject:
    return {"results": list(results)}


def _vuln_url(vuln_id: str) -> str:
    return f"https://api.osv.dev/v1/vulns/{vuln_id}"


@pytest.mark.asyncio
async def test_querybatch_cache_matches_osv_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Batched hydration writes the same normalized cache as the per-dep path."""
    cache = _install_memory_cache(monkeypatch)
    raw_vulns = [
        _raw_vuln("OSV-2024-0001", "first advisory", "1.0.1"),
        _raw_vuln("OSV-2024-0002", "second advisory", "1.0.2"),
    ]
    _install_http_client(
        monkeypatch,
        [_querybatch_response(_batch_result("OSV-2024-0001", "OSV-2024-0002"))],
        {
            _vuln_url("OSV-2024-0001"): raw_vulns[0],
            _vuln_url("OSV-2024-0002"): raw_vulns[1],
        },
    )

    await osv_batch.prewarm_osv_querybatch_cache([("demo-package", "python")])

    expected = OSVSource()._normalize_results(raw_vulns)
    assert cache.store[("demo-package", "python")] == expected


@pytest.mark.asyncio
async def test_positional_mapping_with_interleaved_cached_packages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cached packages are skipped without shifting querybatch result ownership."""
    cache = _install_memory_cache(monkeypatch)
    cached_vulns: list[dict[str, object]] = [{"id": "CACHED", "source": "OSV"}]
    cache.store[("already-cached", "python")] = cached_vulns
    cache.store[("cached-node", "nodejs")] = cached_vulns
    left_vuln = _raw_vuln("OSV-LEFT", "left advisory", "2.0.0")
    right_vuln = _raw_vuln("OSV-RIGHT", "right advisory", "3.0.0")
    client = _install_http_client(
        monkeypatch,
        [_querybatch_response(_batch_result("OSV-LEFT"), _batch_result("OSV-RIGHT"))],
        {
            _vuln_url("OSV-LEFT"): left_vuln,
            _vuln_url("OSV-RIGHT"): right_vuln,
        },
    )

    await osv_batch.prewarm_osv_querybatch_cache(
        [
            ("already-cached", "python"),
            ("left-package", "python"),
            ("cached-node", "nodejs"),
            ("right-package", "python"),
        ]
    )

    post_body = client.post_calls[0][1]
    assert post_body == {
        "queries": [
            {"package": {"name": "left-package", "ecosystem": "PyPI"}},
            {"package": {"name": "right-package", "ecosystem": "PyPI"}},
        ]
    }
    assert cache.store[("already-cached", "python")] == cached_vulns
    assert cache.store[("left-package", "python")][0]["id"] == "OSV-LEFT"
    assert cache.store[("right-package", "python")][0]["id"] == "OSV-RIGHT"


@pytest.mark.asyncio
async def test_pagination_is_followed_per_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A package result with a next page token is re-queried until exhausted."""
    cache = _install_memory_cache(monkeypatch)
    raw_vulns = {
        "OSV-FIRST": _raw_vuln("OSV-FIRST", "first advisory", "1.0.1"),
        "OSV-SECOND": _raw_vuln("OSV-SECOND", "second advisory", "1.0.2"),
        "OSV-THIRD": _raw_vuln("OSV-THIRD", "third advisory", "1.0.3"),
    }
    client = _install_http_client(
        monkeypatch,
        [
            _querybatch_response(_batch_result("OSV-FIRST", next_page_token="page-2")),
            _batch_result("OSV-SECOND", next_page_token="page-3"),
            _batch_result("OSV-THIRD"),
        ],
        {
            _vuln_url("OSV-FIRST"): raw_vulns["OSV-FIRST"],
            _vuln_url("OSV-SECOND"): raw_vulns["OSV-SECOND"],
            _vuln_url("OSV-THIRD"): raw_vulns["OSV-THIRD"],
        },
    )

    await osv_batch.prewarm_osv_querybatch_cache([("paged-package", "nodejs")])

    assert [call[0] for call in client.post_calls] == [
        "https://api.osv.dev/v1/querybatch",
        "https://api.osv.dev/v1/query",
        "https://api.osv.dev/v1/query",
    ]
    assert client.post_calls[1][1]["page_token"] == "page-2"
    assert client.post_calls[2][1]["page_token"] == "page-3"
    assert [vuln["id"] for vuln in cache.store[("paged-package", "nodejs")]] == [
        "OSV-FIRST",
        "OSV-SECOND",
        "OSV-THIRD",
    ]


@pytest.mark.asyncio
async def test_chunk_failure_bisects_and_leaves_size_one_failure_uncached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Chunk failures bisect, while isolated failing packages stay uncached."""
    cache = _install_memory_cache(monkeypatch)
    good_a = _raw_vuln("OSV-GOOD-A", "good a", "1.0.1")
    good_b = _raw_vuln("OSV-GOOD-B", "good b", "1.0.1")
    client = _install_http_client(
        monkeypatch,
        [
            None,
            _querybatch_response(_batch_result("OSV-GOOD-A")),
            None,
            None,
            _querybatch_response(_batch_result("OSV-GOOD-B")),
        ],
        {
            _vuln_url("OSV-GOOD-A"): good_a,
            _vuln_url("OSV-GOOD-B"): good_b,
        },
    )

    await osv_batch.prewarm_osv_querybatch_cache(
        [
            ("good-a", "python"),
            ("bad-package", "python"),
            ("good-b", "python"),
        ]
    )

    assert ("good-a", "python") in cache.store
    assert ("bad-package", "python") not in cache.store
    assert ("good-b", "python") in cache.store
    assert {call[0] for call in client.post_calls} == {
        "https://api.osv.dev/v1/querybatch"
    }


def test_osv_not_sole_source_skips_prewarm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The profiler does not pre-warm when any non-OSV source is enabled."""
    cache = _install_memory_cache(monkeypatch)
    called = False

    async def fake_prewarm(package_ecosystems: list[tuple[str, str]]) -> None:
        nonlocal called
        called = True
        cache.store[("unexpected", "python")] = []

    monkeypatch.setattr(osv_batch, "prewarm_osv_querybatch_cache", fake_prewarm)
    profiler = ExistingDependencyProfiler(
        scoring_weights={},
        vulnerability_options=VulnerabilityOptions(
            enable_osv=True,
            enable_nvd=True,
            enable_github_advisory=False,
        ),
    )

    profiler._prewarm_osv_batch_cache(
        [
            (
                DependencyKey("python", "demo-package", "1.0.0"),
                DependencyMetadata(name="demo-package", installed_version="1.0.0"),
            )
        ]
    )

    assert called is False
    assert cache.store == {}
