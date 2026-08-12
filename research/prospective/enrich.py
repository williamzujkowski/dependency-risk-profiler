"""Measure the signals the harvest omitted, and re-score. **Network.**

§14 recorded that the harvest built its ``DependencyMetadata`` from six
registry fields and called the scorer directly, bypassing the analyser that
populates repository provenance, licence, advisories and transitive
dependencies. Five of thirteen signals came out constant across all 2,000
packages as a result.

This measures the three that need no clone, through the **production** code
paths rather than reimplementations:

- ``source_repository_state`` via ``resolve_repository`` + the recorder, using
  the same ``repository``/``homepage`` fallback rule the npm analyser uses. The
  harvest passed a URL and never set the state, so the signal read None even
  for packages that plainly declared a repository.
- ``license_info`` via ``extract_license_info`` over the packument.
- ``has_known_exploits`` via the vulnerability aggregator.

Transitive dependencies are left unmeasured and stay ``measured=False``, which
is the honest state: a package's dependency *set* is readable from its
packument, but the signal is about the resolved transitive closure, and
pretending a direct-dependency list is that closure would be a fabricated
measurement of exactly the kind #74 and #199 exist to prevent.

``as_of`` is pinned to the original ``scored_at`` so ``staleness`` does not
drift; the clones come from cache. The cohort hash is over package names and is
untouched — this changes what was measured about the same 2,000 packages, and
the outcome does not exist until 2027-08, so nothing is contaminated.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prospective.persist_signals import SIGNAL_FIELDS, clone_path  # noqa: E402

logger = logging.getLogger(__name__)

REGISTRY = "https://registry.npmjs.org"


def _string_or_none(value: object) -> Optional[str]:
    return value if isinstance(value, str) and value.strip() else None


def fetch_packument(name: str, session: requests.Session) -> Optional[dict]:
    try:
        resp = session.get(f"{REGISTRY}/{quote(name, safe='@')}", timeout=30)
    except requests.RequestException:  # pragma: no cover - network
        return None
    if resp.status_code != 200:
        return None
    try:
        doc = resp.json()
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def enrich_one(
    cohort_row: dict,
    packument: Optional[dict],
    root: Path,
    t: datetime,
    aggregator: object,
) -> dict:
    """Score one package with the omitted signals measured."""
    from dependency_risk_profiler.analysis_helpers import analyze_repository
    from dependency_risk_profiler.license.analyzer import extract_license_info
    from dependency_risk_profiler.release_dates import (
        record_source_repository,
        resolve_repository,
    )
    from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

    from prospective.score_at_t import build_dependency

    dependency = build_dependency(cohort_row, t)

    if packument is not None:
        repository = packument.get("repository")
        declared = (
            _string_or_none(repository.get("url"))
            if isinstance(repository, dict)
            else _string_or_none(repository)
        )
        # The registry answered, so the state is measurable -- including
        # UNDECLARED, which is a reading and not a gap.
        record_source_repository(
            dependency,
            resolve_repository(
                declarations=[declared],
                fallbacks=[_string_or_none(packument.get("homepage"))],
            ),
        )
        try:
            dependency.license_info = extract_license_info(packument)
        except Exception as exc:  # pragma: no cover - malformed packument
            logger.warning("licence extraction failed for %s: %s", cohort_row["name"], exc)

    if aggregator is not None:
        from dependency_risk_profiler.models import SecurityMetrics
        from dependency_risk_profiler.signals import AdvisoryLookupState

        try:
            advisories = aggregator.get_vulnerabilities(  # type: ignore[attr-defined]
                cohort_row["name"], "npm"
            )
        except Exception as exc:  # pragma: no cover - network
            logger.warning("advisory lookup failed for %s: %s", cohort_row["name"], exc)
            # FAILED, not absent: a lookup that errored established nothing,
            # and #219 exists so that reads as unmeasured rather than clean.
            dependency.record_advisory_lookup(
                AdvisoryLookupState.FAILED, sources_unavailable=("OSV",)
            )
        else:
            dependency.has_known_exploits = bool(advisories)
            metrics = dependency.security_metrics or SecurityMetrics()
            metrics.counted_vulnerability_count = len(advisories)
            dependency.security_metrics = metrics
            # Recording the STATE is what makes the score reachable. Setting
            # `has_known_exploits` alone leaves the lookup at NOT_ATTEMPTED and
            # the exploit signal correctly unmeasured -- which is exactly why
            # the harvest produced `None` for all 2,000 packages. PARTIAL
            # rather than COMPLETE because only OSV was consulted; NVD and the
            # GitHub Advisory Database were not.
            dependency.record_advisory_lookup(
                AdvisoryLookupState.PARTIAL,
                sources_unavailable=("NVD", "GitHub Advisory Database"),
            )

    cached = clone_path(root, cohort_row.get("repo_slug"))
    used_clone = False
    if cached is not None:
        try:
            dependency = analyze_repository(dependency, str(cached))
            used_clone = True
        except Exception as exc:  # pragma: no cover - hostile tree
            logger.warning("analyze_repository failed for %s: %s", cohort_row["name"], exc)

    scored = RiskScorer().score_dependency(dependency, as_of=t)
    row: Dict[str, object] = {
        "name": cohort_row["name"],
        "used_clone": used_clone,
        "composite": scored.total_score,
        "risk_level": str(scored.risk_level).replace("RiskLevel.", ""),
        "insufficient_data": scored.insufficient_data,
    }
    for field in SIGNAL_FIELDS:
        row[field] = getattr(scored, field, None)
    return row


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--record", type=Path, required=True)
    ap.add_argument("--cohort", type=Path, required=True)
    ap.add_argument("--clone-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--no-advisories", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("dependency_risk_profiler").setLevel(logging.ERROR)

    record = json.loads(args.record.read_text())
    t = datetime.fromisoformat(record["scored_at"])
    cohort = json.loads(args.cohort.read_text())
    if args.limit:
        cohort = cohort[: args.limit]

    aggregator = None
    if not args.no_advisories:
        from dependency_risk_profiler.vulnerabilities.aggregator import OSVSource

        # OSV alone, deliberately: it is the source that answers for npm
        # without a token, and #400 already established that 97% of the npm OSV
        # corpus is MAL takedowns, so this is a well-understood surface. NVD
        # and GitHub Advisory would add coverage and a credential requirement
        # this study does not need.
        aggregator = OSVSource()

    session = requests.Session()
    session.headers["user-agent"] = "drp-prospective-enrich (research; via github)"

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        packuments = list(executor.map(lambda r: fetch_packument(r["name"], session), cohort))
        rows = list(
            executor.map(
                lambda pair: enrich_one(pair[0], pair[1], args.clone_root, t, aggregator),
                zip(cohort, packuments),
            )
        )

    payload = {
        "scored_at": record["scored_at"],
        "cohort_sha256": record["cohort_sha256"],
        "n": len(rows),
        "packuments_resolved": sum(1 for p in packuments if p is not None),
        "used_clone": sum(1 for r in rows if r["used_clone"]),
        "packages": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1, default=str))
    logger.info(
        "enriched %d packages (%d packuments, %d clones)",
        len(rows),
        payload["packuments_resolved"],
        payload["used_clone"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
