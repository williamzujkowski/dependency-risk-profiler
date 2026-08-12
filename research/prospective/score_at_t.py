"""Score the frozen cohort at T with the full shipped instrument. **Network.**

The step the whole study exists for. Every prior outcome study scored a
degenerate variant -- at a reconstructed date ``staleness`` was 1.0 for all
2,906 packages and ``version`` 0.0 for all, and the repository-derived signals
were never attempted -- so the composite that lost to download count was a
three-signal object. Here T is now, nothing is reconstructed, and nothing
saturates.

Reads ``cohort.json``, verifies its hash against the frozen manifest, clones
what declares a repository, runs the **production** collectors and the
**production** scorer, and writes a record that the (already frozen) analysis
script will read in 2027-08.

Four arms are recorded per package, per §1:

- ``composite``          the shipped thirteen-signal score
- ``downloads``          the comparator that has beaten it everywhere
- ``staleness``          one of the composite's own inputs, alone
- ``composite_ablated``  composite with ``staleness`` and ``version`` removed

The scorer's weights and the code commit are hashed into the record. A
composite re-weighted between now and the readout would otherwise be silently
substituted for the one under test, and the configuration alone does not pin
behaviour.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import subprocess  # nosec B404 - git is invoked with a fixed argv, never a shell string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover - import cycle at runtime, type-only here
    from dependency_risk_profiler.models import DependencyMetadata

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prospective.clone import SHALLOW_SINCE_DAYS, clone_one  # noqa: E402

logger = logging.getLogger(__name__)


def scorer_fingerprint() -> Dict[str, str]:
    """Hash what actually decides a score: the weights and the code."""
    from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

    scorer = RiskScorer()
    weights = {
        name: value
        for name, value in sorted(vars(scorer).items())
        if name.endswith("_weight") and isinstance(value, (int, float))
    }
    try:
        commit = subprocess.run(  # nosec B603 B607 - fixed argv, no shell string
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).resolve().parents[2],
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):  # pragma: no cover
        commit = "unknown"
    return {
        "weights": json.dumps(weights, sort_keys=True),
        "weights_sha256": hashlib.sha256(
            json.dumps(weights, sort_keys=True).encode()
        ).hexdigest(),
        "code_commit": commit,
    }


def build_dependency(record: dict, now: datetime) -> "DependencyMetadata":
    """Turn a frozen cohort row into the metadata the production scorer reads."""
    from dependency_risk_profiler.models import DependencyMetadata

    last = datetime.fromisoformat(record["last_publish"].replace("Z", "+00:00"))
    dependency = DependencyMetadata(
        name=record["name"],
        # The cohort is scored as installed-at-latest. A manifest's pinned
        # version is a property of the consumer, not of the package, and this
        # study samples packages.
        installed_version="latest",
        latest_version="latest",
        last_updated=last,
        maintainer_count=len(record["maintainers"]) or None,
        is_deprecated=record.get("deprecated"),
        repository_url=(
            f"https://github.com/{record['repo_slug']}" if record["repo_slug"] else None
        ),
    )
    return dependency


def score_one(record: dict, root: Path, since: str, now: datetime) -> dict:
    """Score one package, cloning when it declares a repository."""
    from dependency_risk_profiler.analysis_helpers import analyze_repository
    from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

    dependency = build_dependency(record, now)

    clone_reason = "no_repo_declared"
    full_instrument = False
    shallow_fallback = None
    if record["repo_slug"]:
        result = clone_one(record["repo_slug"], root, since)
        clone_reason = result.reason
        shallow_fallback = result.shallow_fallback
        if result.ok and result.path is not None:
            full_instrument = True
            try:
                dependency = analyze_repository(dependency, str(result.path))
            except Exception as exc:  # pragma: no cover - a hostile tree is real
                logger.warning("analyze_repository failed for %s: %s", record["name"], exc)
                full_instrument = False
                clone_reason = "analysis_failed"

    scorer = RiskScorer()
    scored = scorer.score_dependency(dependency, as_of=now)

    # §1's third arm, scored here rather than derived at readout: the
    # collectors will not be reproducible in a year, so an arm computed later
    # from stored fields would be a different quantity than the one the frozen
    # analysis script expects. `staleness` and `version` are the two members
    # that are activity by construction, so zeroing them is what "ablated"
    # means -- and it isolates whether a win came from the other eleven.
    ablated_scorer = RiskScorer(staleness_weight=0.0, version_difference_weight=0.0)
    ablated = ablated_scorer.score_dependency(dependency, as_of=now)

    # §1's second comparator. Two quantities were conflated here at first: the
    # scorer's own banded `staleness_score` for some packages and a raw
    # years-since-publish fallback for others, which is not one comparator but
    # two, varying by row. Both are now recorded, consistently, because §1
    # names the signal ("its own `staleness` signal") while describing the
    # quantity ("a one-line `now - last_publish` subtraction"), and those are
    # not the same thing: the banded score takes about five distinct values, so
    # it carries heavy ties that a continuous version does not.
    #
    # `staleness` is the tool's own signal, which is what §1's claim is about.
    # `staleness_days` is the continuous quantity, reported alongside so a
    # disagreement between them is visible rather than hidden by the choice.
    staleness = getattr(scored, "staleness_score", None)
    # Always set from the frozen cohort row, but `last_updated` is Optional on
    # the model and a None here would be an anomaly worth recording rather than
    # crashing a two-thousand-package run.
    staleness_days = (
        (now - dependency.last_updated).days
        if dependency.last_updated is not None
        else None
    )

    return {
        "name": record["name"],
        "stratum": record["stratum"],
        "cluster": record["maintainers"][0] if record["maintainers"] else record["name"],
        "full_instrument": full_instrument,
        "clone_reason": clone_reason,
        "shallow_fallback": shallow_fallback,
        "composite": getattr(scored, "total_score", None),
        "composite_ablated": getattr(ablated, "total_score", None),
        "risk_level": str(getattr(scored, "risk_level", "")),
        "insufficient_data": "UNKNOWN" in str(getattr(scored, "risk_level", "")),
        "downloads": record.get("downloads_last_month") or 0,
        "staleness": staleness,
        "staleness_days": staleness_days,
        # Recorded so the ablated arm can be computed at readout without
        # re-running the collectors, which will not be reproducible in a year.
        "last_publish": record["last_publish"],
        "release_count": record["release_count"],
        "maintainer_count": len(record["maintainers"]),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cohort", type=Path, required=True)
    ap.add_argument("--clone-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    manifest = json.loads((args.cohort / "manifest.json").read_text())
    cohort = json.loads((args.cohort / "cohort.json").read_text())
    digest = hashlib.sha256(
        json.dumps(sorted(row["name"] for row in cohort)).encode()
    ).hexdigest()
    if digest != manifest["cohort_sha256"]:
        raise SystemExit(
            f"cohort hash mismatch: {digest} != {manifest['cohort_sha256']}. The "
            "frozen membership changed; re-register rather than scoring this."
        )

    if args.limit:
        cohort = cohort[: args.limit]

    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=SHALLOW_SINCE_DAYS)).strftime("%Y-%m-%d")
    args.clone_root.mkdir(parents=True, exist_ok=True)

    # The collectors log a paragraph per repository at INFO. Two thousand of
    # those buries the progress line and the failures that matter.
    logging.getLogger("dependency_risk_profiler").setLevel(logging.ERROR)

    rows: List[dict] = []
    # Clone latency dominates, so threads pay even though scoring is CPU-bound.
    # Each worker owns a distinct destination directory, and the scorer is
    # constructed per call, so nothing is shared but the root.
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(score_one, record, args.clone_root, since, now)
            for record in cohort
        ]
        for index, future in enumerate(as_completed(futures), start=1):
            try:
                rows.append(future.result())
            except Exception as exc:  # pragma: no cover - one package must not
                # end a two-thousand-package harvest
                logger.warning("scoring failed: %s", exc)
            if index % 100 == 0:
                yielded = sum(1 for r in rows if r["full_instrument"])
                logger.info(
                    "scored %d/%d (full instrument %d)", index, len(cohort), yielded
                )

    full = sum(1 for r in rows if r["full_instrument"])
    payload = {
        "scored_at": now.isoformat(),
        "cohort_sha256": manifest["cohort_sha256"],
        "scorer": scorer_fingerprint(),
        "n": len(rows),
        "full_instrument": full,
        "full_instrument_yield": full / len(rows) if rows else 0.0,
        "clone_reasons": {
            reason: sum(1 for r in rows if r["clone_reason"] == reason)
            for reason in sorted({r["clone_reason"] for r in rows})
        },
        "packages": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1, default=str))
    logger.info(
        "full-instrument yield %.3f over %d packages",
        payload["full_instrument_yield"],
        len(rows),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
