"""Draw the prospective cohort and freeze it. **Network.**

``docs/prospective-protocol.md`` §2: 2,000 npm packages sampled uniformly from
``all-the-package-names``, excluding every package this project has already
looked at, with **no activity filter** -- filtering on recent publishing would
condition the cohort on ``staleness`` and reintroduce the exact coupling the
design exists to escape.

Three exclusion sets, because a package this project has already measured is
not a fresh observation:

- the 2026-08-06 abandonment snapshot (6,140 names)
- the GHSA remediation cohort
- the base-rate pilot (500 names) -- its measurement set the study's own
  stratification, so it is upstream of the design and cannot be in the cohort

§2.1 fixes the strata before sampling: ``one_shot`` (exactly one release at T)
and ``multi_release``. The pilot measured the first at 27.4% of a uniform draw
with an 85.2% quiet rate -- near-trivially predictable by any arm carrying a
staleness term, so it is reported and never pooled into the headline.

This module writes the cohort and stops. Scoring is a separate step against a
frozen list, so the sample cannot be quietly redrawn after someone sees what
it contains.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prospective.base_rate_pilot import reduce_packument  # noqa: E402

logger = logging.getLogger(__name__)

REGISTRY = "https://registry.npmjs.org"
DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-month"

#: Disjoint from the pilot (20260812) and every prior harvest.
COHORT_SEED = 20260812_2

TARGET = 2000


def load_exclusions(root: Path) -> Set[str]:
    """Every package this project has already looked at."""
    excluded: Set[str] = set()

    snapshot = root / "data" / "npm-2026-08-06" / "packages.jsonl.gz"
    if snapshot.exists():
        with gzip.open(snapshot, "rt") as handle:
            for line in handle:
                excluded.add(json.loads(line)["name"])

    for name in ("remediation-features.json", "remediation-features-365.json"):
        path = root / "results" / name
        if path.exists():
            excluded.update(row["pkg"] for row in json.loads(path.read_text()))

    pilot = root / "data" / "base-rate-pilot" / "records.json"
    if pilot.exists():
        excluded.update(row["name"] for row in json.loads(pilot.read_text()))

    return excluded


def _repo_slug(doc: dict) -> Optional[str]:
    """Extract ``owner/repo`` from a declared GitHub repository field.

    Nothing here verifies that the repository has anything to do with the
    package -- #388 established no such check exists anywhere in this tool, and
    inventing one here would score a different instrument than the shipped one.
    """
    repo = doc.get("repository")
    url = repo.get("url") if isinstance(repo, dict) else repo
    if not isinstance(url, str) or "github.com" not in url:
        return None
    tail = url.split("github.com", 1)[1].lstrip(":/")
    parts = [p for p in tail.removesuffix(".git").split("/") if p]
    return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None


def fetch(name: str, session: requests.Session) -> dict:
    """One package's state at T, registry-only."""
    try:
        resp = session.get(f"{REGISTRY}/{quote(name, safe='@')}", timeout=30)
    except requests.RequestException as exc:  # pragma: no cover - network
        return {"name": name, "status": "error", "detail": str(exc)}
    if resp.status_code != 200:
        return {"name": name, "status": "absent" if resp.status_code == 404 else "http"}
    try:
        doc = resp.json()
    except ValueError:
        return {"name": name, "status": "unparseable"}

    reduced = reduce_packument(name, doc)
    if reduced["status"] != "ok":
        return reduced

    downloads = None
    try:
        dl = session.get(f"{DOWNLOADS_API}/{quote(name, safe='@')}", timeout=30)
        if dl.status_code == 200:
            downloads = dl.json().get("downloads")
    except (requests.RequestException, ValueError):  # pragma: no cover - network
        downloads = None

    reduced.update(
        {
            # §2.1, fixed before sampling.
            "stratum": "one_shot" if reduced["release_count"] == 1 else "multi_release",
            "repo_slug": _repo_slug(doc),
            # The *top-level* maintainer array, which is what the shipped tool
            # reads and what `npm owner add` mutates without a publish. The
            # research arm's per-version array is a different quantity.
            "maintainers": sorted(
                m.get("name", "")
                for m in (doc.get("maintainers") or [])
                if isinstance(m, dict)
            ),
            "downloads_last_month": downloads,
        }
    )
    return reduced


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--names", type=Path, required=True)
    ap.add_argument("--research-root", type=Path, default=Path("research"))
    ap.add_argument("--target", type=int, default=TARGET)
    ap.add_argument("--seed", type=int, default=COHORT_SEED)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    excluded = load_exclusions(args.research_root)
    logger.info("excluding %d already-seen packages", len(excluded))

    all_names = json.loads(args.names.read_text())
    rng = random.Random(args.seed)
    pool = [n for n in all_names if n not in excluded]
    rng.shuffle(pool)

    session = requests.Session()
    session.headers["user-agent"] = "drp-prospective-cohort (research; via github)"

    members: List[dict] = []
    ledger: List[dict] = []
    cursor = 0
    # Draw in waves: eligibility (§2) is "at least one release and a resolvable
    # document", which is only knowable after fetching, so replacements come
    # from the next slice of the same shuffled pool rather than a fresh draw.
    while len(members) < args.target and cursor < len(pool):
        wave = pool[cursor : cursor + (args.target - len(members)) * 2]
        cursor += len(wave)
        if not wave:
            break
        with ThreadPoolExecutor(max_workers=10) as executor:
            for record in executor.map(lambda n: fetch(n, session), wave):
                if len(members) >= args.target:
                    break
                if record["status"] == "ok":
                    members.append(record)
                else:
                    ledger.append({"name": record["name"], "reason": record["status"]})
        logger.info("cohort %d/%d (%d rejected)", len(members), args.target, len(ledger))

    harvested_at = datetime.now(timezone.utc)
    names_digest = hashlib.sha256(args.names.read_bytes()).hexdigest()
    cohort_digest = hashlib.sha256(
        json.dumps(sorted(m["name"] for m in members)).encode()
    ).hexdigest()

    manifest = {
        "harvested_at": harvested_at.isoformat(),
        "seed": args.seed,
        "target": args.target,
        "drawn": len(members),
        "rejected": len(ledger),
        "excluded_already_seen": len(excluded),
        "names_sha256": names_digest,
        # §8: cohort membership is frozen here, before anything is scored.
        "cohort_sha256": cohort_digest,
        "strata": {
            label: sum(1 for m in members if m["stratum"] == label)
            for label in ("one_shot", "multi_release")
        },
        "repo_declared": sum(1 for m in members if m["repo_slug"]),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "cohort.json").write_text(json.dumps(members, indent=1))
    (args.out / "ledger.json").write_text(json.dumps(ledger, indent=1))
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=1))
    print(json.dumps(manifest, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
