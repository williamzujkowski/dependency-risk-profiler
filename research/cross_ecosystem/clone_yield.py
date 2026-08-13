"""Stage two: of the packages that declare a repository, how many clone?

Protocol §8, registered before this ran. Offline except for the clones.

Stage one measured declaration and flagged it as an upper bound — npm declared
0.558 and yielded 0.464. This closes the gap per ecosystem, on a subsample:
200 declared packages each, which is ±7 points at 95% and well inside the
15-point threshold the ecosystems are compared against.

Reuses #385's hardened clone path rather than a second implementation: the URL
is constructed from a charset-validated slug so the https-only allowlist holds
by construction, submodules are never recursed, and a timeout kills the whole
process group. Clones are deleted immediately after the attempt — the yield is
the measurement, the bytes are not.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cross_ecosystem.computability import (  # noqa: E402
    ECOSYSTEMS,
    SEED,
    USER_AGENT,
)
from prospective.clone import SHALLOW_SINCE_DAYS, clone_one  # noqa: E402

logger = logging.getLogger(__name__)

SUBSAMPLE = 200


def _slug(url: Optional[str]) -> Optional[str]:
    if not isinstance(url, str) or "github.com" not in url:
        return None
    tail = url.split("github.com", 1)[1].lstrip(":/")
    parts = [p for p in tail.removesuffix(".git").split("/") if p]
    return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None


#: How to reach the declared repository URL for each ecosystem. Kept next to the
#: probes in ``computability`` rather than merged into them: stage one asks the
#: production resolver for a *state*, this needs the URL itself, and conflating
#: the two would let a URL-extraction bug masquerade as a declaration finding.
def repo_url_npm(name: str, session: requests.Session) -> Optional[str]:
    resp = session.get(f"https://registry.npmjs.org/{quote(name, safe='@')}", timeout=30)
    if resp.status_code != 200:
        return None
    repo = resp.json().get("repository")
    return repo.get("url") if isinstance(repo, dict) else repo


def repo_url_pypi(name: str, session: requests.Session) -> Optional[str]:
    resp = session.get(f"https://pypi.org/pypi/{quote(name)}/json", timeout=30)
    if resp.status_code != 200:
        return None
    info = resp.json().get("info") or {}
    urls = info.get("project_urls") or {}
    for value in list(urls.values()) + [info.get("home_page")]:
        if _slug(value):
            return str(value)
    return None


def repo_url_packagist(name: str, session: requests.Session) -> Optional[str]:
    resp = session.get(f"https://repo.packagist.org/p2/{name}.json", timeout=30)
    if resp.status_code != 200:
        return None
    releases = (resp.json().get("packages") or {}).get(name) or []
    if not releases:
        return None
    source = releases[0].get("source") or {}
    url = source.get("url") or releases[0].get("homepage")
    return str(url) if isinstance(url, str) else None


def repo_url_rubygems(name: str, session: requests.Session) -> Optional[str]:
    resp = session.get(f"https://rubygems.org/api/v1/gems/{quote(name)}.json", timeout=30)
    if resp.status_code != 200:
        return None
    doc = resp.json()
    meta = doc.get("metadata") or {}
    for value in (
        doc.get("source_code_uri"),
        meta.get("source_code_uri"),
        doc.get("homepage_uri"),
        meta.get("homepage_uri"),
    ):
        if _slug(value):
            return str(value)
    return None


URL_READERS = {
    "npm": repo_url_npm,
    "pypi": repo_url_pypi,
    "packagist": repo_url_packagist,
    "rubygems": repo_url_rubygems,
}


def attempt(name: str, ecosystem: str, root: Path, since: str, session: requests.Session) -> str:
    url = URL_READERS[ecosystem](name, session)
    slug = _slug(url)
    if slug is None:
        # Declared, but not on a host this study can clone from. A real
        # category: GitLab, Bitbucket and self-hosted forges all land here.
        return "not_github"
    result = clone_one(slug, root, since)
    if result.ok and result.path is not None:
        shutil.rmtree(result.path, ignore_errors=True)
    return result.reason


def run(ecosystem: str, cache: Path, root: Path, workers: int) -> dict:
    lister, prober = ECOSYSTEMS[ecosystem]
    session = requests.Session()
    session.headers["user-agent"] = USER_AGENT

    names = lister(session, cache)
    rng = random.Random(SEED)
    stage_one = rng.sample(names, min(1000, len(names)))

    # Only packages that stage one found DECLARED are eligible.
    with ThreadPoolExecutor(max_workers=workers) as executor:
        states = list(executor.map(lambda x: prober(x, session), stage_one))
    declared = [n for n, s in zip(stage_one, states) if s == "declared"]

    subsample = random.Random(SEED + 1).sample(declared, min(SUBSAMPLE, len(declared)))
    logger.info("%s: %d declared, cloning %d", ecosystem, len(declared), len(subsample))

    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=SHALLOW_SINCE_DAYS)).strftime("%Y-%m-%d")
    root.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        reasons = list(
            executor.map(lambda x: attempt(x, ecosystem, root, since, session), subsample)
        )

    counts: Dict[str, int] = {}
    for reason in reasons:
        counts[reason] = counts.get(reason, 0) + 1
    ok = sum(v for k, v in counts.items() if k.startswith("ok"))
    github = len(reasons) - counts.get("not_github", 0)
    return {
        "ecosystem": ecosystem,
        "declared_in_stage_one": len(declared),
        "attempted": len(subsample),
        "on_github": github,
        "cloned": ok,
        # Of the declared packages hosted somewhere this study can reach.
        "clone_success_of_github": ok / github if github else None,
        # Of all declared packages, which is what the computability bound needs.
        "clone_success_of_declared": ok / len(subsample) if subsample else None,
        "reasons": counts,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--clone-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--only", nargs="*", choices=sorted(ECOSYSTEMS))
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("dependency_risk_profiler").setLevel(logging.ERROR)

    results = [
        run(name, args.cache, args.clone_root, args.workers)
        for name in (args.only or sorted(ECOSYSTEMS))
    ]
    for row in results:
        logger.info("  %s -> %s", row["ecosystem"], row["reasons"])

    payload = {"seed": SEED, "subsample": SUBSAMPLE, "results": results}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1))
    print(json.dumps(payload, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
