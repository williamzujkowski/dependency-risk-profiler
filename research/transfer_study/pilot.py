"""Measure the detection channel before spending the harvest on it.

`docs/transfer-outcome-protocol.md` §15, whose decision rule was fixed before
this file existed. The 20% ambiguity ceiling was chosen without data; this
estimates the real rate so the halt condition is not first evaluated after
paying for 10,000 fetches.

**It runs on the burned cohort on purpose.** Resolution rates, 404 rates and
login re-registration rates are properties of GitHub's API, not of a sample,
and §1 already excludes every package in the 2026-08-06 snapshot from the fresh
frame. The two populations are disjoint by construction, so this cannot
contaminate the confirmatory cohort — an argument from disjointness, not from
the leakage being small.

**It reads bucket counts only.** No risk score is loaded, joined or computed
anywhere in this module. What it estimates is a nuisance parameter of the
instrument, and the file has no import that would let it do otherwise.

Two GitHub calls per package at most, and the second only for the packages
whose owner login changed:

    GET /repos/{owner_at_T}/{repo_at_T}   -> current owner login, id, type
    GET /users/{owner_at_T}               -> whoever holds that login today

The second is the one under examination. It does not follow renames, so it
either 404s or answers with an account that may be a stranger.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from transfer_study.detect import (  # noqa: E402
    AMBIGUITY_CEILING,
    Account,
    Observation,
    Outcome,
    Provenance,
    ambiguity_share,
    attrition_share,
    classify,
)

API = "https://api.github.com"
USER_AGENT = "drp-transfer-pilot (research; contact via repository issues)"


def _get(path: str, token: str) -> Tuple[int, Optional[Dict]]:
    """One GitHub request. Returns (status, document) and never raises on 404.

    A 404 is data here — it is the answer for a deleted repository and for a
    freed login alike — so it is returned rather than thrown. Anything else
    that fails is retried once and then reported as a status, because a
    transport error silently recoded to 404 would inflate exactly the category
    this pilot is measuring.
    """
    request = urllib.request.Request(
        f"{API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return 404, None
            if error.code in (403, 429) and attempt == 0:
                # Secondary rate limit. The documented remedy is to wait.
                time.sleep(60)
                continue
            return error.code, None
        except (urllib.error.URLError, TimeoutError, ValueError):
            if attempt == 0:
                time.sleep(5)
                continue
            return 0, None
    return 0, None


def _account(document: Dict) -> Account:
    created = document.get("created_at")
    return Account(
        login=document["login"],
        account_id=int(document["id"]),
        created_at=(
            datetime.fromisoformat(created.replace("Z", "+00:00")).date()
            if created
            else None
        ),
        account_type=document.get("type"),
    )


def wilson(successes: int, trials: int, z: float = 1.96) -> Tuple[float, float]:
    """95% Wilson interval. Normal approximation is wrong at these counts.

    The pilot's whole job is a proportion measured on a few dozen owner
    changes, where a Wald interval can run below zero and routinely understates
    the upper bound — which is the bound the decision rule keys on.
    """
    if trials == 0:
        return (0.0, 1.0)
    phat = successes / trials
    denominator = 1 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denominator
    spread = (
        z
        * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return (max(0.0, centre - spread), min(1.0, centre + spread))


def verdict(ambiguous: int, transferred: int) -> Tuple[str, str]:
    """§15's decision rule, applied. Fixed before any number existed."""
    changes = ambiguous + transferred
    if changes == 0:
        return (
            "inconclusive",
            "no owner change observed; the pilot has nothing to weigh",
        )
    share = ambiguous / changes
    low, high = wilson(ambiguous, changes)
    if high <= AMBIGUITY_CEILING:
        return (
            "proceed",
            f"ambiguity {share:.3f}, 95% CI [{low:.3f}, {high:.3f}]; the "
            f"upper bound clears the {AMBIGUITY_CEILING:.2f} ceiling",
        )
    if share > AMBIGUITY_CEILING:
        return (
            "channel-inadequate",
            f"ambiguity {share:.3f}, 95% CI [{low:.3f}, {high:.3f}]; the "
            "point estimate exceeds the ceiling. Proceed only with ids known "
            "as of T, or report the outcome unmeasurable. Do not lower the "
            "gate.",
        )
    return (
        "enlarge",
        f"ambiguity {share:.3f}, 95% CI [{low:.3f}, {high:.3f}] straddles "
        f"{AMBIGUITY_CEILING:.2f}; enlarge within the burned cohort until it "
        "does not, or treat as channel-inadequate when its supply is spent",
    )


def run(
    declarations: Dict[str, Tuple[str, str]],
    t: date,
    token: str,
    limit: int,
) -> Dict:
    """Classify `limit` declarations and return counts. No scores, ever.

    `declarations` maps package name to (owner_at_T, repo_at_T). Only packages
    whose owner login changed cost a second call, so the budget is roughly
    `limit` plus the number of changes.
    """
    counts: Counter = Counter()
    provenance_counts: Counter = Counter()
    type_changes = 0
    transport_failures = 0
    login_resolutions: Counter = Counter()
    examples = []

    for index, (package, (owner, repo)) in enumerate(
        sorted(declarations.items())[:limit]
    ):
        status, document = _get(f"/repos/{owner}/{repo}", token)
        if status not in (200, 404):
            transport_failures += 1
            continue
        current = _account(document["owner"]) if document else None

        declared: Optional[Account] = None
        if current is not None and current.login.lower() != owner.lower():
            user_status, user_document = _get(f"/users/{owner}", token)
            login_resolutions[user_status] += 1
            if user_status == 200 and user_document:
                declared = _account(user_document)
            elif user_status not in (200, 404):
                transport_failures += 1
                continue

        result = classify(
            Observation(
                package=package,
                t=t,
                declared_owner=owner,
                declared_repo=repo,
                current=current,
                declared_account=declared,
                provenance=Provenance.RESOLVED_TODAY,
            )
        )
        counts[result.outcome] += 1
        if result.provenance is not None:
            provenance_counts[result.provenance] += 1
        if result.owner_type_changed:
            type_changes += 1
        if result.outcome in (Outcome.TRANSFERRED, Outcome.AMBIGUOUS):
            examples.append(
                {
                    "package": package,
                    "outcome": result.outcome.value,
                    "detail": result.detail,
                }
            )
        if index % 25 == 0:
            print(f"  {index}/{min(limit, len(declarations))}", flush=True)

    ambiguous = counts[Outcome.AMBIGUOUS]
    transferred = counts[Outcome.TRANSFERRED]
    decision, reason = verdict(ambiguous, transferred)
    low, high = wilson(ambiguous, ambiguous + transferred)

    return {
        "protocol": "docs/transfer-outcome-protocol.md §15",
        "cohort": "burned (2026-08-06 snapshot); disjoint from the fresh frame",
        "reads": "classification buckets only; no score joined to any row",
        "t": t.isoformat(),
        "examined": sum(counts.values()),
        "counts": {outcome.value: counts[outcome] for outcome in Outcome},
        "ambiguity_share": ambiguity_share(counts),
        "ambiguity_ci95": [low, high],
        "attrition_share": attrition_share(counts),
        "owner_type_changes": type_changes,
        "positives_by_provenance": {
            provenance.value: provenance_counts[provenance]
            for provenance in Provenance
        },
        "declared_login_resolution_status": dict(login_resolutions),
        "transport_failures": transport_failures,
        "decision": decision,
        "reason": reason,
        "examples": examples[:40],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--declarations", required=True, type=Path)
    parser.add_argument("--t", default="2024-08-01")
    parser.add_argument("--limit", type=int, default=300)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("GITHUB_TOKEN is not set; refusing to run unauthenticated")
        return 2

    declarations = {
        package: (pair[0], pair[1])
        for package, pair in json.loads(
            args.declarations.read_text()
        ).items()
    }
    result = run(
        declarations, date.fromisoformat(args.t), token, args.limit
    )
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "examples"},
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
