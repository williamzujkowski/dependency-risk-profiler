"""Predictors as of each advisory's publication date, and the three outcomes.

`docs/remediation-protocol.md` §3 and §8. Every predictor is read from the
newest version published STRICTLY BEFORE the advisory, so nothing the
maintainer did in response to the advisory can leak into the features that are
supposed to predict it.

Three outcomes, per §8:

- **A** — did a fixing version ever ship after the advisory?
- **B** — among packages that published at least one version after the
  advisory, did a fix ship? Conditions on the capability to fix.
- **B'** — B, excluding packages whose *only* post-advisory publish is the
  fixing release. Without it, a fixer always enters the denominator while a
  non-fixer enters only by publishing for unrelated reasons, and the selection
  is caused by the outcome.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dependency_risk_profiler.vulnerabilities.cvss import base_score


def _parse(stamp: Optional[str]) -> Optional[datetime]:
    if not stamp:
        return None
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def build(cohort_path: Path, versions_path: Path) -> List[Dict[str, Any]]:
    cohort = json.loads(cohort_path.read_text())
    versions = {
        rec["pkg"]: rec.get("versions") or []
        for rec in json.loads(versions_path.read_text())
        if rec.get("status") == 200
    }

    rows: List[Dict[str, Any]] = []
    for entry in cohort:
        history = versions.get(entry["pkg"])
        if not history:
            continue
        published = _parse(entry["published"])
        if published is None:
            continue

        dated = [(v, _parse(v["t"])) for v in history]
        prior = [(v, t) for v, t in dated if t is not None and t < published]
        after = [(v, t) for v, t in dated if t is not None and t >= published]
        if not prior:
            # No release predates the advisory: nothing to measure the package
            # by at the moment of disclosure.
            continue

        newest, newest_at = prior[-1]
        first_at = prior[0][1]
        year_before = published - timedelta(days=365)

        fix_at = _parse(entry.get("fix_date"))
        # A post-advisory publish that is NOT the fixing release. B' requires
        # at least one, so a package cannot enter the denominator solely by
        # virtue of having fixed.
        unrelated_after = [
            (v, t) for v, t in after if fix_at is None or t != fix_at
        ]

        rows.append(
            {
                "id": entry["id"],
                "pkg": entry["pkg"],
                "published": entry["published"],
                "maintainers": newest["m"],
                "repo_declared": 1.0 if newest["r"] else 0.0,
                "releases_prior_year": float(
                    sum(1 for _, t in prior if t >= year_before)
                ),
                "days_since_release": float((published - newest_at).days),
                "age_days": float((published - first_at).days),
                "releases_total": float(len(prior)),
                "cvss": base_score(entry.get("cvss")),
                "ranges": float(entry.get("ranges") or 0),
                "outcome_a": entry["outcome"],
                "published_after": 1 if after else 0,
                "published_after_excluding_fix": 1 if unrelated_after else 0,
            }
        )
    return rows


if __name__ == "__main__":
    import sys

    built = build(Path(sys.argv[1]), Path(sys.argv[2]))
    Path(sys.argv[3]).write_text(json.dumps(built))
    print("rows:", len(built))
    print("with maintainers:", sum(1 for r in built if r["maintainers"] is not None))
    print("with cvss:", sum(1 for r in built if r["cvss"] is not None))
    b = [r for r in built if r["published_after"]]
    bp = [r for r in built if r["published_after_excluding_fix"]]
    print("outcome A: n=%d fixed=%d (%.1f%%)" % (len(built), sum(r["outcome_a"] for r in built), 100 * sum(r["outcome_a"] for r in built) / len(built)))
    print("outcome B: n=%d fixed=%d (%.1f%%)" % (len(b), sum(r["outcome_a"] for r in b), 100 * sum(r["outcome_a"] for r in b) / max(1, len(b))))
    print("outcome B':n=%d fixed=%d (%.1f%%)" % (len(bp), sum(r["outcome_a"] for r in bp), 100 * sum(r["outcome_a"] for r in bp) / max(1, len(bp))))
