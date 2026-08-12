"""Prove the clone shape actually feeds the six repo-derived signals. **Network.**

Run this **before** the harvest, and treat a failure as a design defect rather
than a finding.

The hazard it exists for: a uniformly-absent signal looks identical whether the
collector is broken or the *harness* is. This repo has been fooled by that once
already -- ``has_tests`` read False for all eight repos in the #339 evidence run
and looked like a dead signal; the cause was ``--filter=blob:none``
``--no-checkout`` plus a sparse-checkout that never materialised ``tests/``. A
positive control with full clones settled it in one run.

At two thousand packages the same mistake would be invisible and expensive: the
six clone-derived signals would read absent everywhere, the composite would
collapse onto its registry-only members, and the study would score **the exact
degenerate variant it was designed to escape** -- while appearing to succeed,
because "no security policy" is a plausible reading of a repository that simply
was not on disk.

So: clone a handful of repositories whose answers are known by inspection and
assert the six signals **vary**. Variation is the test, not any particular
value. A collector returning a constant across repositories this different is
not measuring the repository.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess  # nosec B404 - git is invoked with a fixed argv
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prospective.clone import SHALLOW_SINCE_DAYS, clone_one  # noqa: E402

logger = logging.getLogger(__name__)

#: Chosen to differ on the axes the clone-derived signals read: a
#: security-forward project with a real policy, a huge language runtime, a
#: framework with heavy CI, and -- deliberately -- two small, long-dead
#: packages. The dead ones matter most: they exercise the ``--shallow-since``
#: fallback, and without them every repository in the set has CI and the
#: control cannot tell "always true" from "not measured".
CONTROL_REPOS = [
    "ossf/scorecard",
    "python/cpython",
    "axios/axios",
    "pallets/flask",
    "sigstore/cosign",
    "expressjs/express",
    "substack/minimist",
    "isaacs/inherits",
]

#: What the *clone* answers. The control asserts these vary.
CLONE_DERIVED_FIELDS = [
    "has_tests",
    "has_ci",
    "has_contributing",
    "has_security_policy",
    "has_dependency_update",
    "scorecard_commit_frequency",
]

#: What the clone deliberately does NOT answer, and why this is not a defect.
#:
#: ``calculate_commit_frequency`` refuses on any shallow clone -- a truncated
#: history would read as a confidently dead project for every repository on
#: earth -- so ``community_activity`` and ``community_popularity`` come from the
#: forge API in production. Recording them here as clone-derived was a premise
#: error: the instrument is **four** clone signals plus **two** forge signals,
#: not six clone signals.
#:
#: A prospective design is the one setting where the forge path is sound: the
#: GitHub API publishes current state only, and at T = now current state *is*
#: the state at T. That is exactly why the retrospective studies could not use
#: it.
FORGE_DERIVED_FIELDS = ["commit_frequency", "contributor_count"]


def probe(repo_dir: Path) -> Dict[str, object]:
    """Read the six clone-derived signals off one checkout.

    Deliberately routed through the production ``analyze_repository`` rather
    than the collectors directly: the thing under test is what a real run sees,
    and a control that calls a different code path than the harvest proves
    nothing about the harvest.
    """
    from dependency_risk_profiler.analysis_helpers import analyze_repository
    from dependency_risk_profiler.models import DependencyMetadata

    dependency = DependencyMetadata(name=repo_dir.name, installed_version="0.0.0")
    analyzed = analyze_repository(dependency, str(repo_dir))

    from dependency_risk_profiler.scorecard.maintained import analyze_commit_frequency

    metrics = getattr(analyzed, "security_metrics", None)
    community = getattr(analyzed, "community_metrics", None)
    # Read separately from ``calculate_commit_frequency``: the scorecard
    # collector has no shallow-clone guard and answers from the truncated
    # history, which is what ``maintained`` actually scores.
    try:
        cadence = analyze_commit_frequency(str(repo_dir))
    except Exception:  # pragma: no cover - a hostile tree is a real category
        cadence = {}
    return {
        "scorecard_commit_frequency": (cadence or {}).get("average_monthly_commits"),
        "has_tests": getattr(analyzed, "has_tests", None),
        "has_ci": getattr(analyzed, "has_ci", None),
        "has_contributing": getattr(analyzed, "has_contribution_guidelines", None),
        "has_security_policy": getattr(metrics, "has_security_policy", None)
        if metrics
        else None,
        "has_dependency_update": getattr(metrics, "has_dependency_update_tools", None)
        if metrics
        else None,
        "commit_frequency": getattr(community, "commit_frequency", None) if community else None,
        "contributor_count": getattr(community, "contributor_count", None) if community else None,
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--out", type=Path)
    ap.add_argument(
        "--reuse",
        action="store_true",
        help="probe clones already under --root instead of re-cloning",
    )
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args.root.mkdir(parents=True, exist_ok=True)

    observations: Dict[str, Dict[str, object]] = {}
    since = (
        datetime.now(timezone.utc) - timedelta(days=SHALLOW_SINCE_DAYS)
    ).strftime("%Y-%m-%d")
    for slug in CONTROL_REPOS:
        cached = args.root / slug.replace("/", "__")
        if args.reuse and cached.exists():
            # Re-probing costs minutes on a large tree and re-cloning costs
            # tens; the clone shape is what is under test and it does not
            # change between runs.
            observed = probe(cached)
            observed["shallow_fallback"] = None
            observations[slug] = observed
            logger.info("%s (reused) -> %s", slug, observed)
            continue
        result = clone_one(slug, args.root, since)
        if not result.ok or result.path is None:
            logger.warning("clone failed for %s: %s", slug, result.reason)
            observations[slug] = {"clone_failed": result.reason}
            continue
        observed = probe(result.path)
        observed["shallow_fallback"] = result.shallow_fallback
        observations[slug] = observed
        logger.info("%s -> %s", slug, observed)

    # The negative half of the control. Variation across real repositories
    # cannot distinguish "this field is genuinely true everywhere" from "this
    # collector cannot return false" -- and ``has_ci`` is true for every
    # repository healthy enough to still be on GitHub. An empty tree proves the
    # collector discriminates, deterministically and without a network.
    with tempfile.TemporaryDirectory() as empty:
        subprocess.run(  # nosec B603 B607 - fixed argv, no shell string
            ["git", "init", "--quiet", empty], check=True, capture_output=True
        )
        negative = probe(Path(empty))

    cloned = {k: v for k, v in observations.items() if "clone_failed" not in v}

    def constant_among(fields: List[str]) -> List[str]:
        out = []
        for field in fields:
            seen = {
                json.dumps(values.get(field), default=str) for values in cloned.values()
            }
            if len(seen) <= 1:
                out.append(field)
        return out

    constant = constant_among(CLONE_DERIVED_FIELDS)
    # A field that is constant across real repositories is acceptable only if
    # the empty tree reads differently -- that is the collector discriminating.
    undiscriminating = [
        field
        for field in constant
        if json.dumps(negative.get(field), default=str)
        in {json.dumps(v.get(field), default=str) for v in cloned.values()}
    ]
    verdict = {
        "negative_control": negative,
        "constant_and_undiscriminating": undiscriminating,
        "cloned": len(cloned),
        "attempted": len(CONTROL_REPOS),
        "shallow_fallbacks": sum(
            1 for values in cloned.values() if values.get("shallow_fallback")
        ),
        "constant_clone_derived": constant,
        # Checked and reported, but not a pass condition: these come from the
        # forge API by design, so the clone leaving them None is correct.
        "forge_derived_unmeasured_as_expected": constant_among(FORGE_DERIVED_FIELDS),
        # A constant clone-derived field across repositories this different
        # means the harness is not feeding the collector, not that the world is
        # uniform.
        "passes": len(cloned) >= 6 and not undiscriminating,
        "observations": observations,
    }
    text = json.dumps(verdict, indent=1, default=str)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
    print(text)
    return 0 if verdict["passes"] else 1


if __name__ == "__main__":
    sys.exit(main())
