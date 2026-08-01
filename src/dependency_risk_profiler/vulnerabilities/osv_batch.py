"""Pre-warm the vulnerability cache with OSV querybatch results."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import quote

from ..async_http import AsyncHTTPClient
from .aggregator import OSVSource, cache_data, get_cached_data

logger = logging.getLogger(__name__)

MAX_QUERYBATCH_SIZE = 1000
HYDRATE_CONCURRENCY = 8
OSV_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "dependency-risk-profiler/0.2.0",
}


@dataclass(frozen=True)
class OSVBatchQuery:
    """A package query after cache filtering and OSV ecosystem normalization."""

    name: str
    ecosystem: str
    osv_ecosystem: str


class OSVBatchChunkError(Exception):
    """Raised when one querybatch chunk cannot be safely cached."""


async def prewarm_osv_querybatch_cache(
    package_ecosystems: Sequence[tuple[str, str]],
) -> None:
    """Best-effort OSV querybatch pre-warm for the shared vulnerability cache.

    The caller must only invoke this when OSV is the sole enabled vulnerability
    source. A cache hit short-circuits all sources in the per-dependency path, so
    writing OSV-only results while NVD or GitHub Advisory is enabled would shadow
    those sources.
    """
    if not package_ecosystems:
        return

    osv_source = OSVSource()
    http_client = AsyncHTTPClient(concurrent_requests=HYDRATE_CONCURRENCY)
    try:
        queries = _dedupe_and_filter_cached(package_ecosystems, osv_source)
        for chunk_start in range(0, len(queries), MAX_QUERYBATCH_SIZE):
            chunk = queries[chunk_start : chunk_start + MAX_QUERYBATCH_SIZE]
            await _prewarm_chunk_with_bisect(http_client, osv_source, chunk)
    except Exception as exc:
        logger.debug("OSV querybatch cache pre-warm skipped after failure: %s", exc)
    finally:
        await http_client.close()


def _dedupe_and_filter_cached(
    package_ecosystems: Sequence[tuple[str, str]],
    osv_source: OSVSource,
) -> list[OSVBatchQuery]:
    seen: set[tuple[str, str]] = set()
    queries: list[OSVBatchQuery] = []

    for package_name, ecosystem in package_ecosystems:
        cache_key = (package_name.lower(), ecosystem.lower())
        if cache_key in seen:
            continue
        seen.add(cache_key)
        if get_cached_data(package_name, ecosystem) is not None:
            continue
        queries.append(
            OSVBatchQuery(
                name=package_name,
                ecosystem=ecosystem,
                osv_ecosystem=osv_source._normalize_ecosystem(ecosystem),
            )
        )

    return queries


async def _prewarm_chunk_with_bisect(
    http_client: AsyncHTTPClient,
    osv_source: OSVSource,
    queries: Sequence[OSVBatchQuery],
) -> None:
    if not queries:
        return

    if await _try_prewarm_chunk(http_client, osv_source, queries):
        return

    if len(queries) == 1:
        query = queries[0]
        logger.debug(
            "Leaving OSV querybatch cache unwarmed for %s/%s",
            query.ecosystem,
            query.name,
        )
        return

    midpoint = len(queries) // 2
    await _prewarm_chunk_with_bisect(http_client, osv_source, queries[:midpoint])
    await _prewarm_chunk_with_bisect(http_client, osv_source, queries[midpoint:])


async def _try_prewarm_chunk(
    http_client: AsyncHTTPClient,
    osv_source: OSVSource,
    queries: Sequence[OSVBatchQuery],
) -> bool:
    try:
        package_vuln_ids = await _querybatch_vuln_ids(http_client, osv_source, queries)
        unique_vuln_ids = {
            vuln_id for vuln_ids in package_vuln_ids for vuln_id in vuln_ids
        }
        hydrated_vulns = await _hydrate_vulnerabilities(http_client, unique_vuln_ids)
        missing_vuln_ids = unique_vuln_ids.difference(hydrated_vulns)
        if missing_vuln_ids:
            raise OSVBatchChunkError(
                f"Missing hydrated OSV vulnerabilities: {sorted(missing_vuln_ids)}"
            )

        for query, vuln_ids in zip(queries, package_vuln_ids):
            full_vulns = [hydrated_vulns[vuln_id] for vuln_id in vuln_ids]
            normalized = osv_source._normalize_results(full_vulns)
            cache_data(query.name, query.ecosystem, normalized)
        return True
    except OSVBatchChunkError as exc:
        logger.debug("OSV querybatch chunk failed: %s", exc)
        return False
    except Exception as exc:
        logger.debug("Unexpected OSV querybatch chunk failure: %s", exc)
        return False


async def _querybatch_vuln_ids(
    http_client: AsyncHTTPClient,
    osv_source: OSVSource,
    queries: Sequence[OSVBatchQuery],
) -> list[list[str]]:
    querybatch_url = f"{osv_source.base_url}/querybatch"
    response: object = await http_client.post(
        querybatch_url,
        {"queries": [_package_query(query) for query in queries]},
        OSV_HEADERS,
    )
    response_object = _json_object_or_none(response)
    if response_object is None:
        raise OSVBatchChunkError("OSV querybatch returned no JSON object")

    raw_results = response_object.get("results")
    result_objects = _json_object_list_or_none(raw_results)
    if result_objects is None:
        raise OSVBatchChunkError("OSV querybatch response is missing results")
    if len(result_objects) != len(queries):
        raise OSVBatchChunkError(
            "OSV querybatch result count does not match query count"
        )

    package_vuln_ids: list[list[str]] = []
    for query, result_object in zip(queries, result_objects):
        vuln_ids = _extract_vuln_ids(result_object)
        next_page_token = result_object.get("next_page_token")
        if isinstance(next_page_token, str) and next_page_token:
            vuln_ids.extend(
                await _paginated_vuln_ids(
                    http_client, osv_source, query, next_page_token
                )
            )
        package_vuln_ids.append(vuln_ids)

    return package_vuln_ids


async def _paginated_vuln_ids(
    http_client: AsyncHTTPClient,
    osv_source: OSVSource,
    query: OSVBatchQuery,
    page_token: str,
) -> list[str]:
    query_url = f"{osv_source.base_url}/query"
    vuln_ids: list[str] = []
    next_page_token = page_token

    while next_page_token:
        response: object = await http_client.post(
            query_url,
            {
                "package": {
                    "name": query.name,
                    "ecosystem": query.osv_ecosystem,
                },
                "page_token": next_page_token,
            },
            OSV_HEADERS,
        )
        response_object = _json_object_or_none(response)
        if response_object is None:
            raise OSVBatchChunkError("OSV pagination returned no JSON object")
        vuln_ids.extend(_extract_vuln_ids(response_object))

        raw_token = response_object.get("next_page_token")
        next_page_token = raw_token if isinstance(raw_token, str) else ""

    return vuln_ids


async def _hydrate_vulnerabilities(
    http_client: AsyncHTTPClient,
    vuln_ids: set[str],
) -> dict[str, dict[str, object]]:
    if not vuln_ids:
        return {}

    semaphore = asyncio.Semaphore(HYDRATE_CONCURRENCY)
    pairs = await asyncio.gather(
        *[
            _hydrate_vulnerability(http_client, semaphore, vuln_id)
            for vuln_id in sorted(vuln_ids)
        ]
    )
    return {vuln_id: vuln for vuln_id, vuln in pairs if vuln is not None}


async def _hydrate_vulnerability(
    http_client: AsyncHTTPClient,
    semaphore: asyncio.Semaphore,
    vuln_id: str,
) -> tuple[str, dict[str, object] | None]:
    async with semaphore:
        response: object = await http_client.get(
            f"https://api.osv.dev/v1/vulns/{quote(vuln_id, safe='')}",
            headers=OSV_HEADERS,
        )
    response_object = _json_object_or_none(response)
    return vuln_id, response_object


def _package_query(query: OSVBatchQuery) -> dict[str, object]:
    return {
        "package": {
            "name": query.name,
            "ecosystem": query.osv_ecosystem,
        }
    }


def _extract_vuln_ids(response_object: dict[str, object]) -> list[str]:
    raw_vulns = response_object.get("vulns", [])
    vuln_objects = _json_object_list_or_none(raw_vulns)
    if vuln_objects is None:
        raise OSVBatchChunkError("OSV response contains malformed vulns")

    vuln_ids: list[str] = []
    for vuln in vuln_objects:
        raw_id = vuln.get("id")
        if isinstance(raw_id, str) and raw_id:
            vuln_ids.append(raw_id)
    return vuln_ids


def _json_object_or_none(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None

    parsed: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            return None
        parsed[key] = item
    return parsed


def _json_object_list_or_none(value: object) -> list[dict[str, object]] | None:
    if not isinstance(value, list):
        return None

    parsed: list[dict[str, object]] = []
    for item in value:
        parsed_item = _json_object_or_none(item)
        if parsed_item is None:
            return None
        parsed.append(parsed_item)
    return parsed
