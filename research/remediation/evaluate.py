"""Do any of our predictors identify who patches? — the evaluation.

`docs/remediation-protocol.md` §5. Primary outcome is B', evaluated per
predictor with a package-clustered bootstrap, because 1,557 advisories span
fewer packages and two advisories on one package are not two observations of
independent maintainer behaviour.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from abandonment_pilot.stats import bootstrap_interval, roc_auc

PREDICTORS = (
    "maintainers",
    "repo_declared",
    "releases_prior_year",
    "days_since_release",
    "age_days",
    "releases_total",
    "cvss",
    "ranges",
)


def _clusters(rows: List[Dict[str, Any]]) -> List[int]:
    index: Dict[str, int] = {}
    out = []
    for row in rows:
        out.append(index.setdefault(row["pkg"], len(index)))
    return out


def evaluate(rows: List[Dict[str, Any]], name: str) -> Dict[str, Any]:
    labels = [bool(r["outcome_a"]) for r in rows]
    clusters = _clusters(rows)
    out: Dict[str, Any] = {
        "outcome": name,
        "n": len(rows),
        "packages": len(set(clusters)),
        "base_rate": sum(labels) / len(labels) if labels else 0.0,
        "predictors": {},
    }
    for predictor in PREDICTORS:
        usable = [
            (float(r[predictor]), bool(r["outcome_a"]), c)
            for r, c in zip(rows, clusters)
            if r.get(predictor) is not None
        ]
        if len(usable) < 50:
            out["predictors"][predictor] = {"n": len(usable), "auc": None}
            continue
        values = [u[0] for u in usable]
        marks = [u[1] for u in usable]
        cl = [u[2] for u in usable]
        auc = roc_auc(values, marks)
        # The statistic is a closure over row indices: the bootstrap resamples
        # whole packages, and the AUC is recomputed on whichever rows those
        # packages contribute.
        interval = bootstrap_interval(
            lambda idx: roc_auc([values[i] for i in idx], [marks[i] for i in idx]),
            cl,
            2000,
            20260812,
        )
        out["predictors"][predictor] = {
            "n": len(usable),
            "auc": auc,
            "ci95": [interval.low, interval.high],
            "excludes_chance": bool(
                interval.low is not None
                and interval.high is not None
                and (interval.low > 0.5 or interval.high < 0.5)
            ),
        }
    return out


if __name__ == "__main__":
    rows = json.loads(Path(sys.argv[1]).read_text())
    result: Dict[str, Any] = {
        "protocol": "docs/remediation-protocol.md (amended, §8)",
        "primary": "B_prime",
        "A": evaluate(rows, "A_all"),
        "B": evaluate([r for r in rows if r["published_after"]], "B_still_publishing"),
        "B_prime": evaluate(
            [r for r in rows if r["published_after_excluding_fix"]], "B_prime"
        ),
    }
    Path(sys.argv[2]).write_text(json.dumps(result, indent=2))
    for key in ("A", "B", "B_prime"):
        block = result[key]
        print(
            "\n%s  n=%d packages=%d base=%.3f"
            % (block["outcome"], block["n"], block["packages"], block["base_rate"])
        )
        predictors = block["predictors"]
        for name, stats in predictors.items():
            if stats.get("auc") is None:
                print("   %-22s n=%-5d --" % (name, stats["n"]))
                continue
            low, high = stats["ci95"]
            print(
                "   %-22s n=%-5d AUC=%.4f CI[%.4f,%.4f]%s"
                % (
                    name,
                    stats["n"],
                    stats["auc"],
                    low,
                    high,
                    "  *" if stats["excludes_chance"] else "",
                )
            )
