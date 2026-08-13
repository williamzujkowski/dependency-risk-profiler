"""Do unresolvable declared repository links point at freed namespaces?

Protocol: ``docs/dangling-links-protocol.md``, committed before this ran.

Stage two measured that ~1 declared link in 5 no longer resolves. This asks
what share of those point at an **owner namespace that no longer exists** —
because GitHub frees a renamed or deleted owner name for re-registration, and
#388 established that 41.51% of this tool's weight is computed from that link
with nothing binding it to the package.

**Deliberate scope limit, and it is the whole ethical design of this module.**
One read-only call per slug: does the owner exist? It does not check whether a
namespace is registerable, registers nothing, requests nothing, and emits no
package or owner names — only aggregates. A count of freed namespaces is a
defensive measurement. A list of claimable ones is a target list, and this
returns counts precisely so it cannot become the latter.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cross_ecosystem.clone_yield import URL_READERS, _slug  # noqa: E402
from cross_ecosystem.computability import ECOSYSTEMS, SEED, USER_AGENT  # noqa: E402
from prospective.clone import SHALLOW_SINCE_DAYS, clone_one  # noqa: E402

logger = logging.getLogger(__name__)

SUBSAMPLE = 200

#: §4 line 2.
MIN_SLUGS = 50
#: §4 line 3.
MAX_ERROR_SHARE = 0.20
#: §1.
MATERIAL = 0.10


def owner_state(owner: str, session: requests.Session) -> str:
    """Does this owner namespace exist? One GET, nothing else."""
    try:
        resp = session.get(f"https://api.github.com/users/{owner}", timeout=30)
    except requests.RequestException:  # pragma: no cover - network
        return "error"
    if resp.status_code == 404:
        return "owner_missing"
    if resp.status_code == 200:
        return "owner_exists"
    # 403 is the rate limit, and §4 line 3 gates on how many of these appear.
    return "error"


def collect(ecosystem: str, cache: Path, root: Path, workers: int) -> List[str]:
    """Return the owner names whose declared repository failed with ``auth``."""
    lister, prober = ECOSYSTEMS[ecosystem]
    session = requests.Session()
    session.headers["user-agent"] = USER_AGENT

    names = lister(session, cache)
    stage_one = random.Random(SEED).sample(names, min(1000, len(names)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        states = list(executor.map(lambda x: prober(x, session), stage_one))
    declared = [n for n, s in zip(stage_one, states) if s == "declared"]
    subsample = random.Random(SEED + 1).sample(declared, min(SUBSAMPLE, len(declared)))

    since = (datetime.now(timezone.utc) - timedelta(days=SHALLOW_SINCE_DAYS)).strftime(
        "%Y-%m-%d"
    )
    root.mkdir(parents=True, exist_ok=True)

    def failing_owner(name: str) -> Optional[str]:
        url = URL_READERS[ecosystem](name, session)
        slug = _slug(url)
        if slug is None:
            return None
        result = clone_one(slug, root, since)
        if result.ok:
            import shutil

            if result.path is not None:
                shutil.rmtree(result.path, ignore_errors=True)
            return None
        return slug.split("/", 1)[0] if result.reason == "auth" else None

    with ThreadPoolExecutor(max_workers=workers) as executor:
        owners = [o for o in executor.map(failing_owner, subsample) if o]
    logger.info("%s: %d auth-failing declared links", ecosystem, len(owners))
    return owners


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--clone-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("dependency_risk_profiler").setLevel(logging.ERROR)

    session = requests.Session()
    session.headers["user-agent"] = USER_AGENT
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        # Raises the rate limit so §4 line 3 is less likely to fire. Read-only
        # scope is all this needs and all it should have.
        session.headers["authorization"] = f"Bearer {token}"

    per_ecosystem: Dict[str, List[str]] = {}
    for ecosystem in sorted(ECOSYSTEMS):
        per_ecosystem[ecosystem] = collect(ecosystem, args.cache, args.clone_root, args.workers)

    # De-duplicated: one owner may back several packages, and counting it twice
    # would overstate the exposure.
    owners = sorted({o for group in per_ecosystem.values() for o in group})
    logger.info("checking %d distinct owners", len(owners))

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        states = list(executor.map(lambda o: owner_state(o, session), owners))

    counts: Dict[str, int] = {}
    for state in states:
        counts[state] = counts.get(state, 0) + 1
    errors = counts.get("error", 0)
    checked = len(owners) - errors
    missing = counts.get("owner_missing", 0)

    result = {
        "auth_failing_links_by_ecosystem": {k: len(v) for k, v in per_ecosystem.items()},
        "distinct_owners": len(owners),
        "checked": checked,
        "errors": errors,
        "error_share": errors / len(owners) if owners else 0.0,
        "owner_missing": missing,
        "owner_exists": counts.get("owner_exists", 0),
        "missing_share": missing / checked if checked else None,
        # §4, evaluated here rather than in prose.
        "line_2_too_few_slugs": len(owners) < MIN_SLUGS,
        "line_3_inconclusive": (errors / len(owners) if owners else 0.0) > MAX_ERROR_SHARE,
        "line_1_material": (missing / checked) >= MATERIAL if checked else None,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
