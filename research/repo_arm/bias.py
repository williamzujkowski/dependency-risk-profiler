"""§6's measurement: how far the studied subset is from the cohort it stands for.

A repository still resolvable in 2026 survived the entire label window, so the
studied subset is **conditioned on post-outcome state** and is mechanically
less likely to be abandoned. §6 requires this be measured rather than admitted,
and the outcome makes that possible: abandonment is registry-derived, so it is
computable for the packages whose repository is gone.

The difference carries a **maintainer-clustered** interval, because two
packages published by the same account are not two independent observations of
whether a repository survived — if the account walked away, both the repository
and the releases went with it, together.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import build_cohort, maintainer_clusters
from abandonment_pilot.snapshot import load_snapshot


def clustered_difference(
    labels: Sequence[bool],
    studied: Sequence[bool],
    clusters: Sequence[int],
    replicates: int = 2000,
    seed: int = 20260811,
) -> Dict[str, object]:
    """Bootstrap the abandonment-rate difference, resampling whole clusters.

    Args:
        labels: Abandonment per package.
        studied: Whether the package is in the studied (resolvable) subset.
        clusters: Maintainer component id per package.
        replicates: Resamples.
        seed: Seed.

    Returns:
        Both rates, their difference, and a 95% percentile interval.
    """
    members: Dict[int, List[int]] = {}
    for index, cluster in enumerate(clusters):
        members.setdefault(cluster, []).append(index)
    keys = list(members)

    def rates(indices: Sequence[int]) -> Optional[Tuple[float, float]]:
        inside = [labels[i] for i in indices if studied[i]]
        outside = [labels[i] for i in indices if not studied[i]]
        if not inside or not outside:
            return None
        return sum(inside) / len(inside), sum(outside) / len(outside)

    observed = rates(list(range(len(labels))))
    if observed is None:
        raise ValueError("both subsets must be non-empty")

    rng = random.Random(seed)
    draws: List[float] = []
    for _ in range(replicates):
        drawn: List[int] = []
        for _ in range(len(keys)):
            drawn.extend(members[keys[rng.randrange(len(keys))]])
        pair = rates(drawn)
        if pair is not None:
            draws.append(pair[0] - pair[1])
    draws.sort()
    low = draws[int(0.025 * (len(draws) - 1))] if draws else None
    high = draws[int(0.975 * (len(draws) - 1))] if draws else None
    return {
        "rate_studied": observed[0],
        "rate_not_studied": observed[1],
        "difference": observed[0] - observed[1],
        "ci95_clustered": [low, high],
        "replicates": len(draws),
        "excludes_zero": (
            low is not None and high is not None and (low > 0.0 or high < 0.0)
        ),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the §6 bias measurement.

    Args:
        argv: Command line, for tests.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--T", dest="moment", default="2024-08-01")
    args = parser.parse_args(argv)

    moment = datetime.fromisoformat(args.moment).replace(tzinfo=timezone.utc)
    snapshot = load_snapshot(args.snapshot)
    members, _ = build_cohort(snapshot.packages, moment, 2, snapshot.harvested_at)
    clusters = maintainer_clusters(members)
    with (args.data / "declarations.json").open(encoding="utf-8") as handle:
        declarations = {d["package"]: d for d in json.load(handle)}
    with (args.data / "clones.json").open(encoding="utf-8") as handle:
        clones = json.load(handle)

    resolved = {slug for slug, v in clones.items() if v["status"] == "ok"}

    def is_studied(name: str) -> bool:
        slug = declarations[name]["slug"]
        return isinstance(slug, str) and slug in resolved

    labels = [m.abandoned for m in members]
    studied = [is_studied(m.name) for m in members]

    # Two comparisons, because they answer different questions: the first is
    # §6's literal request (of those declaring a GitHub repo, resolvable vs
    # not), the second is the one that matters for generalisation (studied vs
    # the rest of the cohort, whatever the reason).
    github = [
        index
        for index, m in enumerate(members)
        if declarations[m.name]["category"] == "github"
    ]
    report = {
        "within_github_declarers": clustered_difference(
            [labels[i] for i in github],
            [studied[i] for i in github],
            [clusters[i] for i in github],
        ),
        "studied_vs_rest_of_cohort": clustered_difference(labels, studied, clusters),
    }
    with (args.data / "bias.json").open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1, sort_keys=True)
    print(json.dumps(report, indent=1, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
