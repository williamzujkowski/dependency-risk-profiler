"""Fetch resolved dependencies, dependents and Scorecard from deps.dev. **Network.**

Three things this project could not previously measure, all from the free
public REST API — no BigQuery, no authentication, no billing:

- **Resolved transitive closure.** ``transitive`` is one of only two signals
  still constant in the canonical record (§14). It was left unmeasured because
  a direct-dependency list is not a resolved closure and computing the real
  thing was out of reach. deps.dev publishes the resolved graph.
- **Dependent counts.** A better operationalisation of "a package someone
  actually uses" than downloads — which this harvest recorded for 60 of 2,000
  before the comparator bug was found.
- **OpenSSF Scorecard.** ``prior-art.md`` compares this tool to Scorecard by
  reading papers. This makes it a measurement on the same packages.

Fetching is separated from analysing on purpose: the Scorecard comparison is a
claim and is registered before anything is compared. Collecting the data is not.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

API = "https://api.deps.dev/v3alpha"
WORKERS = 4
MAX_ATTEMPTS = 4


def _get(url: str, session: requests.Session) -> Optional[dict]:
    for attempt in range(MAX_ATTEMPTS):
        try:
            resp = session.get(url, timeout=30)
        except requests.RequestException:
            time.sleep(2**attempt)
            continue
        if resp.status_code == 404:
            return None
        if resp.status_code in (429, 500, 502, 503):
            time.sleep(2**attempt)
            continue
        if resp.status_code != 200:
            return None
        try:
            payload = resp.json()
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None
    return None


def probe(name: str, repo_slug: Optional[str], session: requests.Session) -> dict:
    """Everything deps.dev knows about one npm package."""
    row: Dict[str, object] = {"name": name}
    encoded = quote(name, safe="")

    package = _get(f"{API}/systems/npm/packages/{encoded}", session)
    if package is None:
        row["status"] = "absent"
        return row
    versions = package.get("versions") or []
    # The default version is what a fresh install resolves to, which is the
    # version a dependency graph should be read for.
    latest = next(
        (v for v in reversed(versions) if v.get("isDefault")),
        versions[-1] if versions else None,
    )
    if latest is None:
        row["status"] = "no_versions"
        return row
    version = latest["versionKey"]["version"]
    row["version"] = version
    row["status"] = "ok"

    graph = _get(
        f"{API}/systems/npm/packages/{encoded}/versions/{quote(version, safe='')}:dependencies",
        session,
    )
    if graph is not None:
        nodes = graph.get("nodes") or []
        # Node 0 is the package itself; everything else is its closure.
        row["transitive_names"] = [
            n["versionKey"]["name"] for n in nodes[1:] if n.get("versionKey")
        ]
        row["direct_count"] = sum(1 for n in nodes if n.get("relation") == "DIRECT")

    dependents = _get(
        f"{API}/systems/npm/packages/{encoded}/versions/{quote(version, safe='')}:dependents",
        session,
    )
    if dependents is not None:
        row["dependent_count"] = dependents.get("dependentCount")
        row["direct_dependent_count"] = dependents.get("directDependentCount")

    if repo_slug:
        project = _get(f"{API}/projects/{quote('github.com/' + repo_slug, safe='')}", session)
        if project is not None:
            row["stars"] = project.get("starsCount")
            row["forks"] = project.get("forksCount")
            scorecard = project.get("scorecard") or {}
            row["scorecard_overall"] = scorecard.get("overallScore")
            row["scorecard_checks"] = {
                c.get("name"): c.get("score") for c in scorecard.get("checks") or []
            }
    return row


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cohort", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cohort = json.loads(args.cohort.read_text())
    if args.limit:
        cohort = cohort[: args.limit]

    session = requests.Session()
    session.headers["user-agent"] = "drp-depsdev-study (research; github.com/williamzujkowski)"

    rows: List[dict] = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for i, row in enumerate(
            pool.map(lambda r: probe(r["name"], r.get("repo_slug"), session), cohort), 1
        ):
            rows.append(row)
            if i % 200 == 0:
                logger.info("fetched %d/%d", i, len(cohort))

    ok = sum(1 for r in rows if r.get("status") == "ok")
    payload = {
        "n": len(rows),
        "resolved": ok,
        "with_transitive": sum(1 for r in rows if "transitive_names" in r),
        "with_dependents": sum(1 for r in rows if r.get("dependent_count") is not None),
        "with_scorecard": sum(1 for r in rows if r.get("scorecard_overall") is not None),
        "packages": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1, default=str))
    logger.info(
        "resolved %d | transitive %d | dependents %d | scorecard %d",
        ok,
        payload["with_transitive"],
        payload["with_dependents"],
        payload["with_scorecard"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
