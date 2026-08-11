"""Stage 1: harvest npm's **current** top-level ``maintainers`` for the cohort.

Protocol §10 step 1. Four constraints come from the protocol rather than from
convenience, and each one is a place the harvest could silently measure
something else:

**``registry.npmjs.org`` only, no mirror.** npmmirror's per-version endpoint is
a semver *resolver*: it answers a request for one version with a different
version's document and a 200, so a study measured against it reports agreement
between two documents it never compared (#335).

**Scoped names are URL-encoded.** ``@scope/name`` has to reach the registry as
``@scope%2Fname``; 1,877 of the 2,906 cohort members are scoped, so an
unencoded path would fail on nearly two thirds of the harvest.

**Archived as the extracted array plus a SHA-256 of the raw body**, per
amendment 1. The merged protocol text said "raw packuments"; ``react`` alone is
6.7 MB, so the literal instruction was gigabytes in git. The digest is what made
it auditable — anyone can re-fetch and check they received the same bytes.

**Failures are recorded by category, never folded into "no change".** A 404 and
an unchanged maintainer set are opposite findings that look identical once one
is written as the other, and the §10 gate is a resolution rate, which cannot be
computed at all if failures are absorbed.

The top-level array is requested with a plain ``Accept: application/json``.
npm's abbreviated packument (``application/vnd.npm.install-v1+json``) omits
``maintainers``, which is the only field this harvest exists to read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests
from abandonment_pilot.cohort import build_cohort
from abandonment_pilot.snapshot import load_snapshot, sha256_file

logger = logging.getLogger(__name__)

#: The one registry this study reads. Pinned by protocol §10; see the module
#: docstring for why a mirror is not a substitute.
REGISTRY = "https://registry.npmjs.org"

#: Asks for the full packument. The abbreviated form omits ``maintainers``.
PACKUMENT_HEADERS = {"Accept": "application/json"}

#: Protocol §10 requires a descriptive agent carrying a contact address.
USER_AGENT = (
    "dependency-risk-profiler-research/handover-study "
    "(+https://github.com/williamzujkowski/dependency-risk-profiler; "
    "contact grenlan@gmail.com)"
)

#: Worker threads. Paced globally below, so this only has to be large enough to
#: keep the pacer saturated across a 60s tail latency.
WORKERS = 8

#: Seconds between request *starts*, enforced across all workers. 0.09 is about
#: 11 req/s, inside the 8-14 band that ran clean against this registry before.
REQUEST_INTERVAL_SECONDS = 0.09

#: Attempts per package before it is recorded as unresolved.
MAX_ATTEMPTS = 6

#: Seconds to wait after a throttle, held constant rather than doubled: the
#: meter is a refilling bucket, so the useful wait is one refill.
BACKOFF_SECONDS = 15.0

#: Filename of the harvest artifact inside the output directory.
HARVEST_NAME = "maintainers-current.jsonl"

#: Filename of the harvest manifest.
MANIFEST_NAME = "MANIFEST.json"


class Pacer:
    """A global rate limiter shared by every worker thread.

    Per-thread sleeps do not bound the aggregate rate — eight threads sleeping
    0.09s each issue eight requests per 0.09s, not one. This serialises the
    *start* of each request instead, so the ceiling is the one written down.
    """

    def __init__(self, interval: float) -> None:
        """Store the minimum gap between request starts.

        Args:
            interval: Seconds between successive request starts.
        """
        self._interval = interval
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        """Block until this caller's turn to issue a request."""
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self._interval
        delay = start - now
        if delay > 0:
            time.sleep(delay)


@dataclass(frozen=True)
class HarvestResult:
    """One package's harvest outcome.

    ``maintainers`` is populated only when ``disposition`` is ``"ok"``. Every
    other disposition is a failure category and is counted as one; none of them
    is ever read as an unchanged maintainer set.
    """

    name: str
    disposition: str
    maintainers: Optional[Tuple[str, ...]] = None
    raw_sha256: Optional[str] = None
    http_status: Optional[int] = None


def normalise_maintainers(raw: object) -> Optional[List[str]]:
    """Return sorted, deduplicated usernames from a ``maintainers`` array.

    Deliberately identical to ``abandonment_pilot.harvest._maintainer_names``,
    which produced the frozen sets this harvest will be compared against. The
    two sides of the comparison have to be normalised the same way or a
    reordering by the registry reads as an ownership change; sorting and
    deduplicating is what makes set difference mean set difference.

    npm writes ``[{"name": ..., "email": ...}]``. Only the name is kept: the
    email is a personal identifier this study has no use for.

    Args:
        raw: The decoded ``maintainers`` value, of whatever shape npm sent.

    Returns:
        Sorted unique usernames, or None when the field is absent, not an
        array, or carries no usable name.
    """
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


def registry_url(name: str) -> str:
    """Return the packument URL for a package name.

    ``safe='@'`` keeps the scope sigil literal and encodes the separating
    slash, which is what the registry wants: ``@scope/name`` becomes
    ``@scope%2Fname``. Percent-encoding is case-insensitive in the hex digits,
    so this matches the protocol's ``@scope%2fname``.

    Args:
        name: Package name as it appears in the cohort.

    Returns:
        The absolute URL.
    """
    return f"{REGISTRY}/{quote(name, safe='@')}"


def fetch_one(session: requests.Session, pacer: Pacer, name: str) -> HarvestResult:
    """Fetch one packument and extract its top-level ``maintainers``.

    Args:
        session: A session, one per worker thread.
        pacer: The shared rate limiter.
        name: Package name.

    Returns:
        The result, with a failure category in ``disposition`` when the
        maintainer array could not be read for any reason.
    """
    url = registry_url(name)
    response: Optional[requests.Response] = None
    for attempt in range(MAX_ATTEMPTS):
        pacer.wait()
        try:
            response = session.get(url, headers=PACKUMENT_HEADERS, timeout=60)
        except requests.RequestException as error:
            logger.debug("%s: request error %s", name, error)
            response = None
            if attempt == MAX_ATTEMPTS - 1:
                return HarvestResult(name, "request_failed")
            time.sleep(BACKOFF_SECONDS)
            continue
        if response.status_code != 429 and response.status_code < 500:
            break
        if attempt == MAX_ATTEMPTS - 1:
            break
        retry_after = response.headers.get("Retry-After")
        wait = (
            float(retry_after)
            if retry_after and retry_after.isdigit()
            else BACKOFF_SECONDS
        )
        time.sleep(wait)

    if response is None:
        return HarvestResult(name, "request_failed")
    if response.status_code != 200:
        return HarvestResult(
            name, f"http_{response.status_code}", http_status=response.status_code
        )

    body = response.content
    digest = hashlib.sha256(body).hexdigest()
    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return HarvestResult(
            name, "unparseable_body", raw_sha256=digest, http_status=200
        )
    if not isinstance(document, dict):
        return HarvestResult(name, "not_an_object", raw_sha256=digest, http_status=200)

    names = normalise_maintainers(document.get("maintainers"))
    if names is None:
        return HarvestResult(
            name, "no_top_level_maintainers", raw_sha256=digest, http_status=200
        )
    return HarvestResult(
        name, "ok", maintainers=tuple(names), raw_sha256=digest, http_status=200
    )


def harvest(names: Sequence[str], workers: int = WORKERS) -> List[HarvestResult]:
    """Harvest every name, paced globally across ``workers`` threads.

    Args:
        names: Cohort package names.
        workers: Thread count.

    Returns:
        Results in the same order as ``names``.
    """
    pacer = Pacer(REQUEST_INTERVAL_SECONDS)
    local = threading.local()

    def session_for_thread() -> requests.Session:
        session = getattr(local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update({"User-Agent": USER_AGENT})
            local.session = session
        return session

    def run(name: str) -> HarvestResult:
        return fetch_one(session_for_thread(), pacer, name)

    results: List[HarvestResult] = []
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for done, result in enumerate(pool.map(run, names), start=1):
            results.append(result)
            if done % 250 == 0 or done == len(names):
                rate = done / max(time.monotonic() - started, 1e-9)
                logger.info("%d/%d harvested (%.1f req/s)", done, len(names), rate)
    return results


def write_artifact(
    out_dir: Path,
    results: Sequence[HarvestResult],
    snapshot_dir: Path,
    moment: datetime,
    started_at: datetime,
) -> Path:
    """Write the harvest JSONL and its manifest.

    Args:
        out_dir: Directory to create and write into.
        results: Harvest results.
        snapshot_dir: The snapshot the cohort was built from.
        moment: T.
        started_at: When the harvest began.

    Returns:
        Path to the JSONL file.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / HARVEST_NAME
    with path.open("w", encoding="utf-8") as handle:
        for result in results:
            payload: Dict[str, object] = {
                "name": result.name,
                "disposition": result.disposition,
            }
            if result.maintainers is not None:
                payload["maintainers"] = list(result.maintainers)
            if result.raw_sha256 is not None:
                payload["raw_sha256"] = result.raw_sha256
            if result.http_status is not None:
                payload["http_status"] = result.http_status
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

    categories: Dict[str, int] = {}
    for result in results:
        categories[result.disposition] = categories.get(result.disposition, 0) + 1
    resolved = categories.get("ok", 0)

    manifest = {
        "study": "maintainer handover, docs/handover-outcome-protocol.md",
        "stage": 1,
        "registry": REGISTRY,
        "mirror_used": False,
        "user_agent": USER_AGENT,
        "request_interval_seconds": REQUEST_INTERVAL_SECONDS,
        "workers": WORKERS,
        "cohort_snapshot": str(snapshot_dir),
        "T": moment.date().isoformat(),
        "cohort_size": len(results),
        "harvest_started_at": started_at.isoformat(),
        "harvest_finished_at": datetime.now(timezone.utc).isoformat(),
        "resolved": resolved,
        "resolution_rate": resolved / len(results) if results else 0.0,
        "dispositions": dict(sorted(categories.items())),
        "archival": (
            "extracted top-level maintainers array plus SHA-256 of the raw "
            "response body, per protocol amendment 1"
        ),
        "files": {HARVEST_NAME: {"sha256": sha256_file(path)}},
    }
    with (out_dir / MANIFEST_NAME).open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def load_harvest(path: Path) -> Dict[str, HarvestResult]:
    """Read a harvest artifact back into results keyed by package name.

    Args:
        path: The ``maintainers-current.jsonl`` file.

    Returns:
        Name -> result.
    """
    out: Dict[str, HarvestResult] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            maintainers = payload.get("maintainers")
            out[str(payload["name"])] = HarvestResult(
                name=str(payload["name"]),
                disposition=str(payload["disposition"]),
                maintainers=(
                    tuple(str(item) for item in maintainers)
                    if isinstance(maintainers, list)
                    else None
                ),
                raw_sha256=payload.get("raw_sha256"),
                http_status=payload.get("http_status"),
            )
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the stage-1 harvest.

    Args:
        argv: Command line, or None for ``sys.argv``.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot", type=Path, default=Path("research/data/npm-2026-08-06")
    )
    parser.add_argument(
        "--out", type=Path, default=Path("research/data/handover-2026-08-11")
    )
    parser.add_argument("--T", dest="moment", default="2024-08-01")
    parser.add_argument("--workers", type=int, default=WORKERS)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    snapshot = load_snapshot(args.snapshot)
    moment = datetime.fromisoformat(args.moment).replace(tzinfo=timezone.utc)
    members, _ = build_cohort(snapshot.packages, moment, 2, snapshot.harvested_at)
    names = [member.name for member in members]
    logger.info("cohort at %s: %d packages", args.moment, len(names))

    started_at = datetime.now(timezone.utc)
    results = harvest(names, workers=args.workers)
    path = write_artifact(args.out, results, args.snapshot, moment, started_at)
    resolved = sum(1 for result in results if result.disposition == "ok")
    logger.info(
        "wrote %s: %d/%d resolved (%.3f)",
        path,
        resolved,
        len(results),
        resolved / len(results) if results else 0.0,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
