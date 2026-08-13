"""Can a repository-derived score be computed at all? Four ecosystems. **Network.**

Protocol: ``docs/cross-ecosystem-protocol.md``, committed before any package
was sampled.

The load-bearing design choice is §3: the definition of *declares a repository*
comes from **each analyser's own** ``_resolve_repository``, never from a
definition written for this study. Four bespoke definitions would produce a
finding about the definitions rather than about the ecosystems, and the
per-registry asymmetries (PyPI's free-text ``project_urls``, RubyGems'
two spellings of ``source_code_uri``) are the tool's reviewed judgement
already.

No clone is attempted here. Declaration is the cheap half and an upper bound —
npm declared 57.6% and yielded 46.4% once cloning was tried.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

SEED = 20260813
USER_AGENT = "drp-cross-ecosystem-study (research; github.com/williamzujkowski)"


# --------------------------------------------------------------------------
# Name lists. Full published lists only -- a top-N would condition on the very
# thing being measured (§2).
# --------------------------------------------------------------------------

def npm_names(session: requests.Session, cache: Path) -> List[str]:
    names: List[str] = json.loads((cache / "npm-names.json").read_text())
    return names


def pypi_names(session: requests.Session, cache: Path) -> List[str]:
    import re

    path = cache / "pypi-simple.html"
    if not path.exists():
        resp = session.get("https://pypi.org/simple/", timeout=300)
        resp.raise_for_status()
        path.write_text(resp.text)
    return re.findall(r'<a href="[^"]*">([^<]+)</a>', path.read_text())


def packagist_names(session: requests.Session, cache: Path) -> List[str]:
    path = cache / "packagist-list.json"
    if not path.exists():
        resp = session.get("https://packagist.org/packages/list.json", timeout=300)
        resp.raise_for_status()
        path.write_text(resp.text)
    names: List[str] = json.loads(path.read_text())["packageNames"]
    return names


def rubygems_names(session: requests.Session, cache: Path) -> List[str]:
    path = cache / "rubygems-versions.txt"
    if not path.exists():
        resp = session.get("https://rubygems.org/versions", timeout=300)
        resp.raise_for_status()
        path.write_text(resp.text)
    names = []
    for line in path.read_text().splitlines():
        # `name versions md5` -- the header lines carry no space-delimited name.
        if not line or line.startswith("-") or line.startswith("created_at"):
            continue
        names.append(line.split(" ", 1)[0])
    return sorted(set(names))


# --------------------------------------------------------------------------
# Registry fetch + the production resolver for each ecosystem.
# --------------------------------------------------------------------------

def _state(resolution: object) -> str:
    """Collapse a RepositoryResolution to the scorer's three states."""
    from dependency_risk_profiler.signals import SourceRepositoryState
    from dependency_risk_profiler.models import DependencyMetadata
    from dependency_risk_profiler.release_dates import record_source_repository

    dependency = DependencyMetadata(name="probe", installed_version="0")
    record_source_repository(dependency, resolution)  # type: ignore[arg-type]
    state = dependency.source_repository_state
    if state is SourceRepositoryState.DECLARED:
        return "declared"
    if state is SourceRepositoryState.UNUSABLE:
        return "unusable"
    if state is SourceRepositoryState.UNDECLARED:
        return "undeclared"
    return "unmeasured"


def probe_npm(name: str, session: requests.Session) -> str:
    from dependency_risk_profiler.analyzers.nodejs import NodeJSAnalyzer

    resp = session.get(f"https://registry.npmjs.org/{quote(name, safe='@')}", timeout=30)
    if resp.status_code != 200:
        return "unresolved"
    return _state(NodeJSAnalyzer._resolve_repository(resp.json()))


def probe_pypi(name: str, session: requests.Session) -> str:
    from dependency_risk_profiler.analyzers.python import PythonAnalyzer

    resp = session.get(f"https://pypi.org/pypi/{quote(name)}/json", timeout=30)
    if resp.status_code != 200:
        return "unresolved"
    info = resp.json().get("info") or {}
    return _state(PythonAnalyzer._resolve_repository(info))


def probe_packagist(name: str, session: requests.Session) -> str:
    from dependency_risk_profiler.analyzers.composer import ComposerAnalyzer

    resp = session.get(f"https://repo.packagist.org/p2/{name}.json", timeout=30)
    if resp.status_code != 200:
        return "unresolved"
    packages = resp.json().get("packages") or {}
    releases = packages.get(name) or []
    if not releases:
        return "unresolved"
    return _state(ComposerAnalyzer._resolve_repository(releases[0], None))


def probe_rubygems(name: str, session: requests.Session) -> str:
    from dependency_risk_profiler.analyzers.ruby import RubyGemsAnalyzer

    resp = session.get(f"https://rubygems.org/api/v1/gems/{quote(name)}.json", timeout=30)
    if resp.status_code != 200:
        return "unresolved"
    return _state(RubyGemsAnalyzer._resolve_repository(resp.json()))


ECOSYSTEMS: Dict[str, Tuple[Callable, Callable]] = {
    "npm": (npm_names, probe_npm),
    "pypi": (pypi_names, probe_pypi),
    "packagist": (packagist_names, probe_packagist),
    "rubygems": (rubygems_names, probe_rubygems),
}


def run(name: str, n: int, cache: Path, exclude: set, workers: int) -> dict:
    lister, prober = ECOSYSTEMS[name]
    session = requests.Session()
    session.headers["user-agent"] = USER_AGENT

    names = [x for x in lister(session, cache) if x not in exclude]
    rng = random.Random(SEED)
    sample = rng.sample(names, min(n, len(names)))
    logger.info("%s: %d names available, sampling %d", name, len(names), len(sample))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        states = list(executor.map(lambda x: prober(x, session), sample))

    counts: Dict[str, int] = {}
    for state in states:
        counts[state] = counts.get(state, 0) + 1
    resolved = len(states) - counts.get("unresolved", 0)
    return {
        "ecosystem": name,
        "population": len(names),
        "sampled": len(sample),
        "resolved": resolved,
        # §5 line 2: a thin resolution rate means the name list and the registry
        # disagree, and the sample is not what it claims to be.
        "resolution_rate": resolved / len(sample) if sample else 0.0,
        "counts": counts,
        "declared_share": counts.get("declared", 0) / resolved if resolved else None,
        "unusable_share": counts.get("unusable", 0) / resolved if resolved else None,
        "undeclared_share": counts.get("undeclared", 0) / resolved if resolved else None,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--only", nargs="*", choices=sorted(ECOSYSTEMS))
    ap.add_argument("--exclude-npm", type=Path, nargs="*", default=[])
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("dependency_risk_profiler").setLevel(logging.ERROR)
    args.cache.mkdir(parents=True, exist_ok=True)

    exclude: set = set()
    for path in args.exclude_npm:
        if path.exists():
            rows = json.loads(path.read_text())
            rows = rows.get("packages", rows) if isinstance(rows, dict) else rows
            exclude.update(r["name"] for r in rows if isinstance(r, dict) and "name" in r)
    logger.info("excluding %d already-sampled npm names", len(exclude))

    results = []
    for name in args.only or sorted(ECOSYSTEMS):
        results.append(run(name, args.n, args.cache, exclude if name == "npm" else set(), args.workers))
        logger.info("  %s -> %s", name, results[-1]["counts"])

    shares = [r["declared_share"] for r in results if r["declared_share"] is not None]
    payload = {
        "seed": SEED,
        "results": results,
        "spread_points": (max(shares) - min(shares)) * 100 if len(shares) > 1 else None,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1))
    print(json.dumps(payload, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
