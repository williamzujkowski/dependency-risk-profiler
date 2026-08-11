"""Build a pinned npm snapshot. **Network. Never run from CI.**

This is the only module in the pilot that talks to a registry, and nothing
downstream imports it — ``testing/unit/test_abandonment_pilot.py`` asserts that,
so a future edit cannot quietly put a live HTTP call inside the analysis.

The harvest is three passes:

1. **Sample names.** A seeded ``random.Random.sample`` over the full npm name
   list published by ``all-the-package-names``, whose digest is recorded in the
   manifest. Sampling from every name rather than from a top-N download list
   matters: a top-N list is *today's* popularity, and a package that was
   abandoned shortly after T is exactly the one that has since fallen off it.
   Selecting on it would condition the cohort on the outcome.
2. **Fetch and reduce.** One packument per name, reduced to the release table
   and four run-length fields. A full record is kept only if the package could
   be eligible at one of the candidate T values; every other name is written to
   the ledger with the reason, so the selection is auditable without refetching.
   Release *days* are kept for every package with two or more releases, eligible
   or not, because N is chosen from that wider population — see
   :func:`.cohort.resumption_life_table` for why the cohort is the wrong one.
3. **Downloads and stars.** Downloads for the 30 days ending at each candidate
   T, from npm's own dated series. Stars from the GitHub API, which publishes
   only current state — see :mod:`.features` for why that is recorded as a
   deliberately advantaged baseline rather than as a signal.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests

from .cohort import CANDIDATE_T, MIN_AGE_DAYS, MIN_RELEASES_BEFORE_T, RECENT_ACTIVITY_DAYS
from .snapshot import (
    DOWNLOADS_NAME,
    LEDGER_NAME,
    MANIFEST_NAME,
    PACKAGES_NAME,
    SILENCES_NAME,
    STARS_NAME,
    parse_registry_time,
    sha256_file,
)

logger = logging.getLogger(__name__)

REGISTRY = "https://registry.npmjs.org"
DOWNLOADS_API = "https://api.npmjs.org/downloads/range"
GITHUB_GRAPHQL = "https://api.github.com/graphql"

#: Window over which the download baseline is measured, ending at T.
DOWNLOAD_WINDOW_DAYS = 30

#: Header that asks npm for the full packument. The abbreviated form omits
#: ``maintainers``, which is the one field this experiment exists to read.
FULL_PACKUMENT_HEADERS = {"Accept": "application/json"}

#: Attempts per request before a source is recorded as not having answered.
MAX_ATTEMPTS = 6

#: Seconds to wait after a throttled response, held constant rather than
#: doubled. ``api.npmjs.org`` meters on a refilling bucket with a period of
#: roughly this length, so the useful wait is one refill; doubling past it buys
#: nothing and costs the run an hour. Measured: at a steady 0.35s between
#: requests, 30 of 80 are throttled, and slowing to 0.7s makes it *worse*
#: because the bucket is already empty — the pacing that works is to sprint
#: until throttled and then wait out a refill, which is what this is.
BACKOFF_SECONDS = 15.0

#: Packages per npm bulk download request. 128 is the endpoint's documented cap.
BULK_DOWNLOAD_BATCH = 128

#: Repositories per GitHub GraphQL request.
GRAPHQL_BATCH = 100

#: Seconds between requests in the serial baseline passes.
REQUEST_INTERVAL_SECONDS = 0.2

#: Seconds between GraphQL requests. GitHub's secondary limits are much
#: tighter than its point budget, and answer a breach with 403.
GRAPHQL_INTERVAL_SECONDS = 2.0

#: Seconds to wait after a throttled GraphQL request; doubled per attempt.
GRAPHQL_BACKOFF_SECONDS = 10.0


def _get_with_retry(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    attempts: int = MAX_ATTEMPTS,
) -> Optional[requests.Response]:
    """GET a URL, backing off while the server is throttling.

    ``api.npmjs.org`` throttles hard and answers a throttled request in
    milliseconds, so a harvest without this returns almost instantly having
    measured almost nothing — 683 of 6,140 packages on the first attempt at
    sixteen threads. A fast run with a low answer rate is the shape that
    failure takes here, and it is easy to mistake for a source that has no data.

    Args:
        session: A session, one per worker thread.
        url: The URL to fetch.
        headers: Request headers.
        attempts: How many times to try before giving up.

    Returns:
        The first response that is not a throttle or a server error, or None
        when every attempt was one.
    """
    delay = BACKOFF_SECONDS
    for attempt in range(attempts):
        try:
            response = session.get(url, headers=headers, timeout=60)
        except requests.RequestException:
            return None
        if response.status_code != 429 and response.status_code < 500:
            return response
        if attempt == attempts - 1:
            return response
        retry_after = response.headers.get("Retry-After")
        wait = float(retry_after) if retry_after and retry_after.isdigit() else delay
        time.sleep(wait)
    return None


def _reduce_packument(name: str, body: bytes) -> Optional[Dict[str, object]]:
    """Reduce a packument to the pilot's record shape.

    Args:
        name: Package name, as sampled.
        body: The raw response body, digested into the record so a later
            harvest can tell drift from agreement.

    Returns:
        The reduced record, or None when the document carries no dated release.
    """
    document = json.loads(body)
    if not isinstance(document, dict):
        return None
    times = document.get("time")
    version_documents = document.get("versions")
    if not isinstance(times, dict) or not isinstance(version_documents, dict):
        return None

    dated: List[Tuple[str, str, Dict[str, object]]] = []
    for version, meta in version_documents.items():
        published = times.get(version)
        if not isinstance(published, str) or not isinstance(meta, dict):
            continue
        dated.append((published, version, meta))
    if not dated:
        return None
    dated.sort(key=lambda entry: (parse_registry_time(entry[0]), entry[1]))

    versions: List[str] = []
    days: List[int] = []
    maintainers: List[List[object]] = []
    repository: List[List[object]] = []
    licenses: List[List[object]] = []
    dep_counts: List[List[object]] = []

    previous_day = 0
    for index, (published, version, meta) in enumerate(dated):
        epoch_day = int(parse_registry_time(published).timestamp()) // 86400
        versions.append(version)
        days.append(epoch_day if index == 0 else epoch_day - previous_day)
        previous_day = epoch_day
        _append_step(maintainers, index, _maintainer_names(meta))
        _append_step(repository, index, _repository_url(meta))
        _append_step(licenses, index, _license_text(meta))
        _append_step(dep_counts, index, _dependency_count(meta))

    return {
        "name": name,
        "versions": versions,
        "days": days,
        "maintainers": maintainers,
        "repository": repository,
        "license": licenses,
        "dep_count": dep_counts,
        "raw_sha256": hashlib.sha256(body).hexdigest(),
    }


def _append_step(steps: List[List[object]], index: int, value: object) -> None:
    """Record ``value`` at ``index`` only when it differs from the value in force."""
    if value is None:
        return
    if steps and steps[-1][1] == value:
        return
    steps.append([index, value])


def _maintainer_names(meta: Dict[str, object]) -> Optional[List[str]]:
    """Return the maintainer usernames frozen into one version document.

    npm writes ``[{"name": ..., "email": ...}]``. Only the name is kept: the
    email is a personal identifier this experiment has no use for.

    Args:
        meta: One version document.

    Returns:
        Sorted usernames, or None when the document carries no array. Sorted so
        a reordering by the registry does not read as an ownership change.
    """
    raw = meta.get("maintainers")
    if not isinstance(raw, list):
        return None
    names: List[str] = []
    for entry in raw:
        if isinstance(entry, dict):
            candidate = entry.get("name")
            if isinstance(candidate, str) and candidate:
                names.append(candidate)
        elif isinstance(entry, str) and entry:
            names.append(entry)
    if not names:
        return None
    return sorted(set(names))


def _repository_url(meta: Dict[str, object]) -> Optional[str]:
    """Return the repository URL a version document declares, if any."""
    raw = meta.get("repository")
    if isinstance(raw, str):
        return raw or None
    if isinstance(raw, dict):
        url = raw.get("url")
        if isinstance(url, str) and url:
            return url
    return None


def _license_text(meta: Dict[str, object]) -> Optional[str]:
    """Return the license a version document declares, in any of npm's spellings."""
    raw = meta.get("license")
    if isinstance(raw, str) and raw:
        return raw
    if isinstance(raw, dict):
        kind = raw.get("type")
        if isinstance(kind, str) and kind:
            return kind
    legacy = meta.get("licenses")
    if isinstance(legacy, list):
        for entry in legacy:
            if isinstance(entry, dict):
                kind = entry.get("type")
                if isinstance(kind, str) and kind:
                    return kind
            elif isinstance(entry, str) and entry:
                return entry
    return None


def _dependency_count(meta: Dict[str, object]) -> Optional[int]:
    """Return the runtime dependency count a version document declares.

    Runtime only. ``devDependencies`` do not ship to a consumer and are not
    what the tool's transitive signal counts.

    Args:
        meta: One version document.

    Returns:
        The count, or None when the document has no ``dependencies`` key at
        all — absent is not the same fact as declared-empty.
    """
    raw = meta.get("dependencies")
    if isinstance(raw, dict):
        return len(raw)
    return None


def _storage_verdict(record: Dict[str, object]) -> str:
    """Decide whether a fetched record is worth storing, and say why not.

    Storage is gated on eligibility at *any* candidate T, because the cohort's
    T is fixed only after N is chosen from the release-interval distribution.
    Every rejected name still reaches the ledger.

    Args:
        record: A reduced record.

    Returns:
        ``"store"``, or the reason the package can never be eligible.
    """
    raw_days = record["days"]
    if not isinstance(raw_days, list):
        return "malformed"
    published: List[datetime] = []
    epoch_day = 0
    for position, delta in enumerate(raw_days):
        epoch_day = int(delta) if position == 0 else epoch_day + int(delta)
        published.append(datetime.fromtimestamp(epoch_day * 86400, tz=timezone.utc))
    if len(published) < MIN_RELEASES_BEFORE_T:
        return "fewer_than_three_releases_ever"
    reasons: List[str] = []
    for moment in CANDIDATE_T:
        before = [when for when in published if when < moment]
        if len(before) < MIN_RELEASES_BEFORE_T:
            reasons.append("too_few_releases_before_T")
            continue
        if (moment - before[0]).days < MIN_AGE_DAYS:
            reasons.append("younger_than_one_year_at_T")
            continue
        if (moment - before[-1]).days > RECENT_ACTIVITY_DAYS:
            reasons.append("already_dormant_at_T")
            continue
        return "store"
    return reasons[0] if reasons else "no_candidate_T_matched"


def _fetch_packument(
    session: requests.Session, name: str
) -> Tuple[str, Optional[Dict[str, object]], Optional[Dict[str, object]], str]:
    """Fetch and reduce one packument.

    Args:
        session: A session, one per worker thread.
        name: Package name.

    Returns:
        ``(name, cohort_record_or_None, silence_record_or_None, disposition)``.
        The silence record is kept for every package with two or more releases
        whether or not the cohort record is, because N is chosen from that
        wider population.
    """
    url = f"{REGISTRY}/{quote(name, safe='@')}"
    response = _get_with_retry(session, url, FULL_PACKUMENT_HEADERS)
    if response is None:
        return name, None, None, "request_failed"
    if response.status_code != 200:
        return name, None, None, f"http_{response.status_code}"
    record = _reduce_packument(name, response.content)
    if record is None:
        return name, None, None, "no_dated_releases"
    days = record["days"]
    silence: Optional[Dict[str, object]] = None
    if isinstance(days, list) and len(days) >= 2:
        silence = {"name": name, "days": days}
    verdict = _storage_verdict(record)
    if verdict != "store":
        return name, None, silence, verdict
    return name, record, silence, "store"


def _download_total(days: object) -> Optional[int]:
    """Sum a downloads series, or return None when it is not one."""
    if not isinstance(days, list):
        return None
    total = 0
    for day in days:
        if isinstance(day, dict) and isinstance(day.get("downloads"), int):
            total += int(day["downloads"])
    return total


def _download_window(moment: datetime) -> str:
    """Return the ``start:end`` path segment for the 30 days ending at T."""
    end = moment.date()
    start = end - timedelta(days=DOWNLOAD_WINDOW_DAYS - 1)
    return f"{start.isoformat()}:{end.isoformat()}"


def _fetch_downloads_bulk(
    session: requests.Session, names: Sequence[str], moment: datetime
) -> Dict[str, int]:
    """Fetch downloads for up to 128 unscoped packages in one request.

    npm's bulk form rejects scoped names with a 400 — the ``/`` in ``@scope/pkg``
    is indistinguishable from the path separator that joins the list — so
    :func:`_fetch_downloads_one` handles those, and this handles the rest at a
    128th of the request count.

    Args:
        session: A session.
        names: Unscoped package names, at most 128.
        moment: T.

    Returns:
        Name -> downloads over the window, for the packages npm answered for.
    """
    url = f"{DOWNLOADS_API}/{_download_window(moment)}/{','.join(names)}"
    response = _get_with_retry(session, url, {})
    if response is None or response.status_code != 200:
        return {}
    payload = response.json()
    if not isinstance(payload, dict):
        return {}
    totals: Dict[str, int] = {}
    for name, entry in payload.items():
        if isinstance(entry, dict):
            total = _download_total(entry.get("downloads"))
            if total is not None:
                totals[str(name)] = total
    return totals


def _fetch_downloads_one(
    session: requests.Session, name: str, moment: datetime
) -> Optional[int]:
    """Fetch the download total for one package over the 30 days ending at T.

    npm publishes a dated daily series, so this is a genuine as-of-T
    measurement rather than today's number stamped onto a past date.

    Args:
        session: A session.
        name: Package name.
        moment: T.

    Returns:
        The total, or None when npm did not answer. None means unmeasured, and
        is never written down as zero downloads.
    """
    url = f"{DOWNLOADS_API}/{_download_window(moment)}/{quote(name, safe='@')}"
    response = _get_with_retry(session, url, {})
    if response is None or response.status_code != 200:
        return None
    payload = response.json()
    if not isinstance(payload, dict):
        return None
    return _download_total(payload.get("downloads"))


def fetch_all_downloads(
    session: requests.Session, names: Sequence[str], moment: datetime
) -> Dict[str, int]:
    """Fetch downloads for every name, bulk where npm allows it.

    Serial, with :data:`REQUEST_INTERVAL_SECONDS` between requests. Concurrency
    here is counterproductive rather than merely rude: ``api.npmjs.org``
    escalates its throttling under parallel load, and a sixteen-thread run
    answered for 683 of 6,140 packages while a serial one answers for
    essentially all of them in about the same wall time, because the bulk form
    collapses two thirds of the work into a thirtieth of the requests.

    Args:
        session: A session.
        names: Package names.
        moment: T.

    Returns:
        Name -> downloads over the window.
    """
    unscoped = [name for name in names if not name.startswith("@")]
    scoped = [name for name in names if name.startswith("@")]
    totals: Dict[str, int] = {}
    for start in range(0, len(unscoped), BULK_DOWNLOAD_BATCH):
        batch = unscoped[start : start + BULK_DOWNLOAD_BATCH]
        totals.update(_fetch_downloads_bulk(session, batch, moment))
        time.sleep(REQUEST_INTERVAL_SECONDS)
    logger.info("downloads: %d of %d unscoped answered", len(totals), len(unscoped))
    for done, name in enumerate(scoped, start=1):
        total = _fetch_downloads_one(session, name, moment)
        if total is not None:
            totals[name] = total
        time.sleep(REQUEST_INTERVAL_SECONDS)
        if done % 500 == 0:
            logger.info("downloads: scoped %d/%d", done, len(scoped))
    return totals


def github_slug(url: str) -> Optional[str]:
    """Return the ``owner/repo`` a declared repository URL points at on GitHub.

    Args:
        url: A repository URL as npm published it, in any of the shapes npm
            accepts: ``git+https://``, ``git://``, ``git@github.com:``, or a
            bare ``owner/repo``.

    Returns:
        The slug, or None when the URL is not a GitHub repository root.
    """
    text = url.strip()
    for prefix in ("git+", "git://", "ssh://", "https://", "http://"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    text = text.replace("git@github.com:", "github.com/")
    if text.startswith("github.com/"):
        text = text[len("github.com/") :]
    elif "/" in text and not text.startswith("www."):
        parts = text.split("/")
        if len(parts) != 2:
            return None
    else:
        return None
    text = text.split("#", 1)[0].split("?", 1)[0]
    if text.endswith(".git"):
        text = text[: -len(".git")]
    parts = [part for part in text.split("/") if part]
    if len(parts) != 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def _graphql_batch(
    session: requests.Session, headers: Dict[str, str], query: str
) -> Optional[Dict[str, object]]:
    """POST one GraphQL query, backing off through GitHub's secondary limits.

    GitHub answers a secondary rate limit with **403**, not 429, and with the
    primary quota still showing thousands of points remaining. Treating 403 as
    a permanent failure is what made a first run resolve 1,175 of 6,140
    repositories while its hourly budget was 99.6% unspent.

    Args:
        session: A session.
        headers: Authorization headers.
        query: The GraphQL document.

    Returns:
        The ``data`` object, or None when no attempt got one.
    """
    delay = GRAPHQL_BACKOFF_SECONDS
    for attempt in range(MAX_ATTEMPTS):
        try:
            response = session.post(
                GITHUB_GRAPHQL, headers=headers, json={"query": query}, timeout=120
            )
        except requests.RequestException:
            return None
        if response.status_code == 200:
            payload = response.json()
            data = payload.get("data") if isinstance(payload, dict) else None
            return data if isinstance(data, dict) else None
        if response.status_code not in (403, 429) and response.status_code < 500:
            logger.warning("graphql: HTTP %d", response.status_code)
            return None
        if attempt == MAX_ATTEMPTS - 1:
            logger.warning("graphql: HTTP %d after %d attempts", response.status_code, MAX_ATTEMPTS)
            return None
        retry_after = response.headers.get("Retry-After")
        wait = float(retry_after) if retry_after and retry_after.isdigit() else delay
        time.sleep(wait)
        delay *= 2
    return None


def fetch_all_stars(
    session: requests.Session, slugs: Sequence[str], token: Optional[str]
) -> Dict[str, int]:
    """Fetch current stargazer counts, a hundred repositories per request.

    GitHub's REST endpoint costs one of 5,000 hourly points per repository;
    its GraphQL endpoint answers a hundred aliased ``repository`` fields for
    one. That is the difference between a run that fits in an hour and one that
    does not, and it needs a token either way.

    A repository that has been deleted or renamed answers ``null`` and is
    simply absent from the result, which is the honest record: nobody could
    measure it.

    Args:
        session: A session.
        slugs: ``owner/repo`` strings.
        token: A GitHub token. Without one the endpoint refuses outright.

    Returns:
        Slug -> stargazer count, for the repositories that answered.
    """
    if not token:
        logger.warning("no GITHUB_TOKEN: the star baseline will be empty")
        return {}
    headers = {"Authorization": f"Bearer {token}"}
    stars: Dict[str, int] = {}
    for start in range(0, len(slugs), GRAPHQL_BATCH):
        batch = slugs[start : start + GRAPHQL_BATCH]
        fields = []
        for position, slug in enumerate(batch):
            owner, _, repo = slug.partition("/")
            fields.append(
                f"r{position}: repository(owner: {json.dumps(owner)}, "
                f"name: {json.dumps(repo)}) {{ stargazerCount }}"
            )
        query = "query { " + " ".join(fields) + " }"
        data = _graphql_batch(session, headers, query)
        if data is not None:
            for position, slug in enumerate(batch):
                entry = data.get(f"r{position}")
                if isinstance(entry, dict) and isinstance(
                    entry.get("stargazerCount"), int
                ):
                    stars[slug] = int(entry["stargazerCount"])
        time.sleep(GRAPHQL_INTERVAL_SECONDS)
        if start % (GRAPHQL_BATCH * 10) == 0:
            logger.info("stars %d/%d resolved=%d", start, len(slugs), len(stars))
    return stars


def _write_json_gz(path: Path, payload: object) -> None:
    """Write a gzipped JSON document with a fixed mtime, so the digest is stable."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with gzip.GzipFile(filename=str(path), mode="wb", mtime=0) as handle:
        handle.write(raw)


def _write_jsonl_gz(path: Path, records: Sequence[Dict[str, object]]) -> None:
    """Write records as gzipped JSONL, name-sorted and with a fixed mtime.

    Sorted and mtime-zeroed so the digest in the manifest is a function of the
    data alone. A pin that changes when the file is merely rewritten is not a
    pin.

    Args:
        path: Destination file.
        records: Records to write; each must carry a ``name``.
    """
    with gzip.GzipFile(filename=str(path), mode="wb", mtime=0) as archive:
        for record in sorted(records, key=lambda item: str(item["name"])):
            line = json.dumps(record, sort_keys=True, separators=(",", ":"))
            archive.write(line.encode("utf-8") + b"\n")


def _rewrite_manifest(out_dir: Path, updates: Dict[str, object]) -> None:
    """Merge ``updates`` into the manifest and re-digest every file it names."""
    manifest_path = out_dir / MANIFEST_NAME
    manifest: Dict[str, object] = {}
    if manifest_path.exists():
        with manifest_path.open(encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            manifest = loaded
    manifest.update(updates)
    files: Dict[str, object] = {}
    for filename in (
        PACKAGES_NAME,
        SILENCES_NAME,
        DOWNLOADS_NAME,
        STARS_NAME,
        LEDGER_NAME,
    ):
        path = out_dir / filename
        if path.exists():
            files[filename] = {"sha256": sha256_file(path)}
    manifest["files"] = files
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")


def harvest_packuments(
    names_path: Path,
    out_dir: Path,
    seed: int,
    sample_size: int,
    workers: int,
) -> None:
    """Sample names, fetch packuments, and write the reduced package file.

    Args:
        names_path: ``names.json`` from ``all-the-package-names``.
        out_dir: Directory to create the snapshot in.
        seed: Seed for the name sample.
        sample_size: How many names to draw.
        workers: Thread-pool width.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    with names_path.open(encoding="utf-8") as handle:
        universe = json.load(handle)
    if not isinstance(universe, list):
        raise ValueError("names.json must be a list of package names")
    names = [str(entry) for entry in universe]
    sample = random.Random(seed).sample(names, sample_size)

    ledger: Dict[str, str] = {}
    kept: List[Dict[str, object]] = []
    silences: List[Dict[str, object]] = []
    sessions = [requests.Session() for _ in range(workers)]

    def fetch_one(
        indexed: Tuple[int, str],
    ) -> Tuple[str, Optional[Dict[str, object]], Optional[Dict[str, object]], str]:
        position, name = indexed
        return _fetch_packument(sessions[position % workers], name)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for done, (name, record, silence, disposition) in enumerate(
            pool.map(fetch_one, enumerate(sample)), start=1
        ):
            ledger[name] = disposition
            if record is not None:
                kept.append(record)
            if silence is not None:
                silences.append(silence)
            if done % 5000 == 0:
                logger.info("packuments %d/%d kept=%d", done, len(sample), len(kept))

    _write_jsonl_gz(out_dir / PACKAGES_NAME, kept)
    _write_jsonl_gz(out_dir / SILENCES_NAME, silences)
    _write_json_gz(out_dir / LEDGER_NAME, ledger)

    _rewrite_manifest(
        out_dir,
        {
            "harvested_at": datetime.now(timezone.utc).isoformat(),
            "registry": REGISTRY,
            "ecosystem": "npm",
            "name_universe": {
                "package": "all-the-package-names",
                "names_json_sha256": sha256_file(names_path),
                "names": len(names),
            },
            "sample": {"seed": seed, "size": sample_size},
            "candidate_T": [moment.date().isoformat() for moment in CANDIDATE_T],
            "eligibility": {
                "min_releases_before_T": MIN_RELEASES_BEFORE_T,
                "min_age_days": MIN_AGE_DAYS,
                "recent_activity_days": RECENT_ACTIVITY_DAYS,
            },
            "counts": {
                "sampled": len(sample),
                "stored": len(kept),
                "silence_histories": len(silences),
            },
        },
    )


def harvest_baselines(
    out_dir: Path, moment: datetime, token: Optional[str]
) -> None:
    """Fetch the two baselines that live outside the packument.

    Downloads are a genuine as-of-T measurement; stars are not, and cannot be.
    Both are written, and :mod:`.features` labels the difference.

    Args:
        out_dir: Snapshot directory holding ``packages.jsonl.gz``.
        moment: T.
        token: GitHub token. Without one the star baseline comes back empty.
    """
    records: List[Dict[str, object]] = []
    with gzip.open(out_dir / PACKAGES_NAME, "rt", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    stored = sorted(str(record["name"]) for record in records)
    session = requests.Session()

    totals = fetch_all_downloads(session, stored, moment)
    logger.info(
        "downloads at %s: %d of %d answered", moment.date(), len(totals), len(stored)
    )

    slugs: Dict[str, str] = {}
    for record in records:
        steps = record["repository"]
        if not isinstance(steps, list) or not steps:
            continue
        latest = steps[-1][1]
        if isinstance(latest, str):
            slug = github_slug(latest)
            if slug:
                slugs[str(record["name"])] = slug

    star_by_slug = fetch_all_stars(session, sorted(set(slugs.values())), token)
    stars = {
        name: star_by_slug[slug]
        for name, slug in slugs.items()
        if slug in star_by_slug
    }
    logger.info("stars: %d of %d packages resolved", len(stars), len(stored))

    _write_json_gz(out_dir / DOWNLOADS_NAME, {moment.date().isoformat(): totals})
    _write_json_gz(out_dir / STARS_NAME, stars)
    _rewrite_manifest(
        out_dir,
        {
            "baselines_at": moment.date().isoformat(),
            "download_window_days": DOWNLOAD_WINDOW_DAYS,
            "star_source": "GitHub GraphQL stargazerCount, current state at harvest",
        },
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point for the harvest.

    Args:
        argv: Argument vector, defaulting to ``sys.argv[1:]``.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    packuments = sub.add_parser("packuments", help="sample names and fetch packuments")
    packuments.add_argument("--names", type=Path, required=True)
    packuments.add_argument("--out", type=Path, required=True)
    packuments.add_argument("--seed", type=int, default=20260806)
    packuments.add_argument("--sample-size", type=int, default=80000)
    packuments.add_argument("--workers", type=int, default=32)

    baselines = sub.add_parser("baselines", help="fetch downloads at T and stars")
    baselines.add_argument("--out", type=Path, required=True)
    baselines.add_argument("--at", required=True, help="T, as YYYY-MM-DD")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    if args.command == "packuments":
        harvest_packuments(
            names_path=args.names,
            out_dir=args.out,
            seed=args.seed,
            sample_size=args.sample_size,
            workers=args.workers,
        )
    else:
        harvest_baselines(
            out_dir=args.out,
            moment=datetime.fromisoformat(args.at).replace(tzinfo=timezone.utc),
            token=os.environ.get("GITHUB_TOKEN"),
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
