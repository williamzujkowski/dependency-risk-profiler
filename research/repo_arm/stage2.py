"""Stage 2: resolve and clone the cohort's repositories, and report the bias.

Two numbers come out of this stage and both are results rather than
bookkeeping:

**The resolution rate**, which §9 gates at 60%. Below that the studied
population is too far from the cohort to generalise, and the protocol says to
stop and say so rather than proceed.

**The abandonment rate in the resolvable and unresolvable subsets, side by
side.** §6 requires this and the reason is sharp: a repository still readable
in 2026 survived the entire label window, so the studied subset is
mechanically less likely to be abandoned. The outcome is registry-derived, so
it is computable for the packages whose repository is *gone* — which turns
"conditioning on post-outcome state" from an admission into a measurement.
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import CohortMember, build_cohort, maintainer_clusters
from abandonment_pilot.snapshot import PackageRecord, load_snapshot

from .clone import OK, CloneResult, clone_one
from .resolve import GITHUB, Declaration, classify, distinct_slugs

#: T, fixed by the protocol. One date, as the handover study used.
DEFAULT_T = "2024-08-01"

#: N, the abandonment window in years. Chosen by the pilot's life table.
ABANDONMENT_YEARS = 2

#: §9's stop rule.
RESOLUTION_GATE = 0.60

#: Statuses worth one more attempt: a transport hiccup is not a deleted
#: repository, and misreading one as the other biases the very rate §6 asks
#: this stage to measure.
RETRYABLE = ("timeout", "other")


def cluster_count(members: Sequence[CohortMember], names: Sequence[str]) -> int:
    """Return the number of maintainer components spanned by ``names``.

    Effective sample size for a clustered bootstrap is the component count,
    not the row count, so every subset this study reports carries both.

    Args:
        members: The full cohort, whose components are computed once.
        names: Package names to restrict to.

    Returns:
        How many distinct components those packages fall into.
    """
    clusters = maintainer_clusters(members)
    wanted = set(names)
    return len(
        {
            cluster
            for member, cluster in zip(members, clusters)
            if member.name in wanted
        }
    )


def _rate(numerator: int, denominator: int) -> Optional[float]:
    """Return a rate, or None when the denominator is empty."""
    return numerator / denominator if denominator else None


def clone_all(
    slugs: Sequence[str], root: Path, workers: int
) -> Dict[str, CloneResult]:
    """Clone every distinct repository, retrying only transport failures.

    Args:
        slugs: Distinct ``owner/repo`` slugs.
        root: Directory to clone into.
        workers: Concurrent clones.

    Returns:
        One result per slug.
    """
    root.mkdir(parents=True, exist_ok=True)
    results: Dict[str, CloneResult] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(lambda slug: clone_one(slug, root), slugs):
            results[result.slug] = result

    retry = [slug for slug, r in results.items() if r.status in RETRYABLE]
    if retry:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(lambda slug: clone_one(slug, root), retry):
                if result.status == OK or results[result.slug].status != OK:
                    results[result.slug] = result
    return results


def summarise(
    declarations: Sequence[Declaration],
    clones: Dict[str, CloneResult],
    members: Sequence[CohortMember],
) -> Dict[str, object]:
    """Assemble stage 2's report, including §6's side-by-side table.

    Args:
        declarations: Every cohort package's classified declaration.
        clones: Clone outcome per distinct slug.
        members: The cohort, for cluster counts.

    Returns:
        The report document.
    """
    by_category: Dict[str, int] = {}
    for declaration in declarations:
        by_category[declaration.category] = by_category.get(declaration.category, 0) + 1

    github = [d for d in declarations if d.category == GITHUB]
    resolvable = [
        d for d in github if d.slug is not None and clones[d.slug].status == OK
    ]
    unresolvable = [
        d for d in github if d.slug is not None and clones[d.slug].status != OK
    ]

    failures: Dict[str, int] = {}
    for slug, result in clones.items():
        if result.status != OK:
            failures[result.status] = failures.get(result.status, 0) + 1

    # Packages, not repositories: a monorepo failing takes several packages
    # with it, and the study's unit is the package.
    package_failures: Dict[str, int] = {}
    for declaration in unresolvable:
        if declaration.slug is None:
            continue
        status = clones[declaration.slug].status
        package_failures[status] = package_failures.get(status, 0) + 1

    # The whole cohort, split by whether this arm can read a repository for it.
    # "Not resolvable" here includes declaring none at all, which is the
    # comparison §6 actually wants: studied versus not studied.
    studied_names = [d.package for d in resolvable]
    unstudied = [d for d in declarations if d.package not in set(studied_names)]

    sizes = [r.size_bytes for r in clones.values() if r.size_bytes is not None]
    return {
        "T": DEFAULT_T,
        "cohort_size": len(declarations),
        "cohort_abandoned": sum(1 for d in declarations if d.abandoned),
        "cohort_clusters": len(set(maintainer_clusters(members))),
        "declaration_categories": by_category,
        "github_packages": len(github),
        "distinct_repositories": len(clones),
        "repositories_resolved": sum(1 for r in clones.values() if r.status == OK),
        "repository_resolution_rate": _rate(
            sum(1 for r in clones.values() if r.status == OK), len(clones)
        ),
        "package_resolution_rate_of_github": _rate(len(resolvable), len(github)),
        "package_resolution_rate_of_cohort": _rate(len(resolvable), len(declarations)),
        "repository_failures": failures,
        "package_failures": package_failures,
        "gate_resolution": {
            "threshold": RESOLUTION_GATE,
            "observed": _rate(len(resolvable), len(github)),
            "passed": (_rate(len(resolvable), len(github)) or 0.0) >= RESOLUTION_GATE,
        },
        "post_outcome_conditioning": {
            "resolvable": {
                "n": len(resolvable),
                "abandoned": sum(1 for d in resolvable if d.abandoned),
                "rate": _rate(
                    sum(1 for d in resolvable if d.abandoned), len(resolvable)
                ),
                "clusters": cluster_count(members, [d.package for d in resolvable]),
            },
            "unresolvable_declared_github": {
                "n": len(unresolvable),
                "abandoned": sum(1 for d in unresolvable if d.abandoned),
                "rate": _rate(
                    sum(1 for d in unresolvable if d.abandoned), len(unresolvable)
                ),
                "clusters": cluster_count(members, [d.package for d in unresolvable]),
            },
            "not_studied_any_reason": {
                "n": len(unstudied),
                "abandoned": sum(1 for d in unstudied if d.abandoned),
                "rate": _rate(
                    sum(1 for d in unstudied if d.abandoned), len(unstudied)
                ),
                "clusters": cluster_count(members, [d.package for d in unstudied]),
            },
        },
        "clone_storage_bytes": sum(sizes),
        "clone_size_bytes_max": max(sizes) if sizes else None,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run stage 2.

    Args:
        argv: Command line, for tests.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--clone-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--T", dest="moment", default=DEFAULT_T)
    args = parser.parse_args(argv)

    moment = datetime.fromisoformat(args.moment).replace(tzinfo=timezone.utc)
    snapshot = load_snapshot(args.snapshot)
    members, _ = build_cohort(
        snapshot.packages, moment, ABANDONMENT_YEARS, snapshot.harvested_at
    )
    records: Dict[str, PackageRecord] = {r.name: r for r in snapshot.packages}
    declarations = classify(members, records)
    slugs = distinct_slugs(declarations)
    print(f"cohort {len(members)} | github packages "
          f"{sum(1 for d in declarations if d.category == GITHUB)} | "
          f"distinct repos {len(slugs)}", flush=True)

    clones = clone_all(slugs, args.clone_root, args.workers)
    report = summarise(declarations, clones, members)

    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "stage2.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1, sort_keys=True)
    with (args.out / "declarations.json").open("w", encoding="utf-8") as handle:
        json.dump(
            [
                {
                    "package": d.package,
                    "category": d.category,
                    "slug": d.slug,
                    "abandoned": d.abandoned,
                }
                for d in declarations
            ],
            handle,
            indent=1,
        )
    with (args.out / "clones.json").open("w", encoding="utf-8") as handle:
        json.dump(
            {
                slug: {
                    "status": r.status,
                    "seconds": round(r.seconds, 3),
                    "size_bytes": r.size_bytes,
                    "detail": r.detail,
                }
                for slug, r in sorted(clones.items())
            },
            handle,
            indent=1,
        )
    print(json.dumps(report, indent=1, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
