"""Measure the 12-month quiet rate on a uniform npm sample. **Network.**

The prospective protocol (``docs/prospective-protocol.md``) registers a guard:
if the outcome base rate lands outside 5-60%, no AUC is claimed. That guard is
checkable *today* and the protocol left it open, which the review panel called
out unanimously -- tripping a criterion you could have forecast in advance is
not falsification, it is a twelve-month wait wasted.

The estimand: sample uniformly from every published npm name, ask whether the
package published a release in the trailing twelve months. For a stationary
population that is the same quantity the prospective study will measure over
``(T, T+12]``, observable now.

Why it cannot reuse the abandonment snapshot's 0.476: that cohort required two
releases before T and a minimum age, which excludes exactly the one-shot
publishes that dominate a uniform draw. This module applies **no eligibility
filter at all** -- that is the entire point.

The seed is disjoint from every other harvest in this repo, and the sampled
names are written out so the prospective cohort can exclude them.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

REGISTRY = "https://registry.npmjs.org"

#: Disjoint from the abandonment harvest (20240801) and the handover study (7).
PILOT_SEED = 20260812

WINDOW_DAYS = 365


def sample_names(names_path: Path, n: int, seed: int) -> List[str]:
    """Uniform sample over every published name, with no eligibility filter."""
    names = json.loads(names_path.read_text())
    rng = random.Random(seed)
    return rng.sample(names, n)


def _last_publish(name: str, session: requests.Session) -> Optional[dict]:
    """Return the reduced record for ``name``, or ``None`` if unresolvable.

    Only ``time`` is needed, so this asks for the abbreviated document where
    possible; a package whose packument 404s (unpublished, or a name in the
    list that the registry no longer serves) is a real category and is recorded
    rather than dropped, because the prospective outcome has the same edge case.
    """
    url = f"{REGISTRY}/{quote(name, safe='@')}"
    try:
        resp = session.get(url, timeout=30)
    except requests.RequestException as exc:  # pragma: no cover - network
        return {"name": name, "status": "error", "detail": str(exc)}
    if resp.status_code == 404:
        return {"name": name, "status": "absent"}
    if resp.status_code != 200:
        return {"name": name, "status": "http", "detail": resp.status_code}
    try:
        doc = resp.json()
    except ValueError:
        return {"name": name, "status": "unparseable"}
    return reduce_packument(name, doc)


def reduce_packument(name: str, doc: dict) -> dict:
    """Reduce a packument to the fields the base rate needs.

    Split out from the fetch so the registry's edge cases can be tested without
    a network call. They are not hypothetical: ``time.unpublished`` is an
    *object* rather than a timestamp, and taking ``max()`` over the raw ``time``
    values raises on it.
    """
    times = doc.get("time") or {}
    # ``created``/``modified`` are registry bookkeeping, not releases: npm
    # touches ``modified`` on any write, including an owner change, so counting
    # it would score maintainer edits as publishing activity. ``unpublished`` is
    # an *object* (not a timestamp) recording a whole-package removal -- that is
    # a distinct outcome from going quiet, so it gets its own status rather than
    # being coerced into the release table.
    if "unpublished" in times:
        return {"name": name, "status": "unpublished"}
    releases = [
        v for k, v in times.items()
        if k not in ("created", "modified") and isinstance(v, str)
    ]
    if not releases:
        return {"name": name, "status": "no_releases"}

    latest = max(releases)
    repo = doc.get("repository")
    repo_url = repo.get("url") if isinstance(repo, dict) else (repo if isinstance(repo, str) else None)
    return {
        "name": name,
        "status": "ok",
        "last_publish": latest,
        "release_count": len(releases),
        "repo_declared": bool(repo_url),
        "deprecated": bool(doc.get("versions", {}) and all(
            isinstance(v, dict) and v.get("deprecated")
            for v in doc.get("versions", {}).values()
        )),
    }


def harvest(names: List[str], workers: int = 12) -> List[dict]:
    session = requests.Session()
    session.headers["user-agent"] = "drp-base-rate-pilot (research; contact via github)"
    out: List[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, rec in enumerate(pool.map(lambda n: _last_publish(n, session), names)):
            out.append(rec)
            if (i + 1) % 100 == 0:
                logger.info("resolved %d/%d", i + 1, len(names))
    return out


def summarise(records: List[dict], as_of: datetime) -> dict:
    cutoff = as_of - timedelta(days=WINDOW_DAYS)
    resolved = [r for r in records if r["status"] == "ok"]
    quiet = 0
    for r in resolved:
        stamp = datetime.fromisoformat(r["last_publish"].replace("Z", "+00:00"))
        if stamp < cutoff:
            quiet += 1

    status_counts: Dict[str, int] = {}
    for r in records:
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1

    one_shot = sum(1 for r in resolved if r["release_count"] == 1)
    with_repo = sum(1 for r in resolved if r["repo_declared"])

    return {
        "as_of": as_of.isoformat(),
        "window_days": WINDOW_DAYS,
        "sampled": len(records),
        "resolved": len(resolved),
        "status_counts": status_counts,
        "quiet": quiet,
        "base_rate": (quiet / len(resolved)) if resolved else None,
        "one_shot_share": (one_shot / len(resolved)) if resolved else None,
        "repo_declared_share": (with_repo / len(resolved)) if resolved else None,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--names", type=Path, required=True)
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--seed", type=int, default=PILOT_SEED)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    names = sample_names(args.names, args.n, args.seed)
    records = harvest(names)
    as_of = datetime.now(timezone.utc)
    summary = summarise(records, as_of)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "records.json").write_text(json.dumps(records, indent=1))
    (args.out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
