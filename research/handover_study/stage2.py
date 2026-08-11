"""Stage 2: the base rate, its sub-definitions, and the effective n.

Protocol §10 step 2. Two numbers are computed here and only one of them
governs anything.

The positive count is the number everyone looks at. The number that decides
whether the study can proceed is the count of **maintainer clusters** those
positives span, because packages sharing an npm account are not independent
observations of an outcome that *is* an account changing. The compromise
backtest cleared a raw-count bar and died on the effective one: 2,074 nominal
cases collapsed to 43 independent campaign-days. §5 changed the power unit for
exactly that reason and §10 gates on 150 clusters.

Clusters are the connected components of the *whole cohort's* shared-maintainer
graph at T, as :func:`abandonment_pilot.cohort.maintainer_clusters` builds them
and as the pilot's bootstrap resamples them — not components recomputed over
the positives alone. Recomputing over the subset drops the non-positive
packages that bridge two positive components, which splits components apart and
inflates the effective n in the direction that flatters the gate. Both are
reported; the full-cohort one is the one the gate is read against.

Nothing here scores a model, and nothing here computes an AUC. Stage 3 is the
negative control and it comes after the gate.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import CohortMember, build_cohort, maintainer_clusters
from abandonment_pilot.snapshot import load_snapshot

from .harvest import HARVEST_NAME, load_harvest

logger = logging.getLogger(__name__)

#: The positive rate seen from version documents in #342, quoted in protocol §9
#: as the sanity anchor. The uncensored rate should sit somewhat above it.
CENSORED_REFERENCE_RATE = 0.145

#: Protocol §9: above this, suspect npm account renames before believing the
#: number.
RENAME_SUSPICION_RATE = 0.40

#: Protocol §10 step 2 gates.
MIN_POSITIVES = 200
MIN_POSITIVE_CLUSTERS = 150


@dataclass(frozen=True)
class Comparison:
    """One resolved package's frozen-versus-current maintainer comparison."""

    name: str
    frozen: Tuple[str, ...]
    current: Tuple[str, ...]

    @property
    def gained(self) -> Tuple[str, ...]:
        """Return accounts present now and not in the frozen set."""
        return tuple(sorted(set(self.current) - set(self.frozen)))

    @property
    def lost(self) -> Tuple[str, ...]:
        """Return accounts in the frozen set and not present now."""
        return tuple(sorted(set(self.frozen) - set(self.current)))

    @property
    def changed(self) -> bool:
        """Return whether the two sets differ at all. The primary outcome."""
        return set(self.frozen) != set(self.current)

    @property
    def both(self) -> bool:
        """Return whether the package both gained and lost an account."""
        return bool(self.gained) and bool(self.lost)

    @property
    def complete_turnover(self) -> bool:
        """Return whether the two sets are disjoint.

        Underpowered by construction and not a primary outcome (§3).
        """
        return not (set(self.frozen) & set(self.current))


def compare(
    members: Sequence[CohortMember], harvested: Dict[str, object]
) -> Tuple[List[Comparison], List[int], Dict[str, int]]:
    """Pair each cohort member with its harvest result.

    Args:
        members: The cohort at T, in a fixed order.
        harvested: Name -> ``HarvestResult`` from the stage-1 artifact.

    Returns:
        ``(comparisons, cluster id per comparison, unresolved counts by
        category)``. Unresolved packages are dropped from the comparisons and
        counted by category; none is folded into "no change".
    """
    clusters = maintainer_clusters(members)
    comparisons: List[Comparison] = []
    comparison_clusters: List[int] = []
    unresolved: Dict[str, int] = {}
    for position, member in enumerate(members):
        result = harvested.get(member.name)
        disposition = getattr(result, "disposition", "absent_from_harvest")
        current = getattr(result, "maintainers", None)
        if disposition != "ok" or current is None:
            unresolved[disposition] = unresolved.get(disposition, 0) + 1
            continue
        comparisons.append(
            Comparison(
                name=member.name,
                frozen=tuple(member.maintainers),
                current=tuple(current),
            )
        )
        comparison_clusters.append(clusters[position])
    return comparisons, comparison_clusters, unresolved


def size_histogram(sets: Sequence[Sequence[str]]) -> Dict[str, object]:
    """Summarise a collection of maintainer sets by size.

    Args:
        sets: Maintainer sets.

    Returns:
        Counts by size, the share that are solo, and quantiles.
    """
    sizes = sorted(len(item) for item in sets)
    if not sizes:
        return {"n": 0}
    counts = Counter(sizes)

    def quantile(fraction: float) -> int:
        position = min(len(sizes) - 1, int(fraction * (len(sizes) - 1)))
        return sizes[position]

    return {
        "n": len(sizes),
        "solo": counts.get(1, 0),
        "solo_share": counts.get(1, 0) / len(sizes),
        "two_to_four": sum(counts.get(size, 0) for size in (2, 3, 4)),
        "five_plus": sum(count for size, count in counts.items() if size >= 5),
        "min": sizes[0],
        "p50": quantile(0.5),
        "p90": quantile(0.9),
        "max": sizes[-1],
        "mean": sum(sizes) / len(sizes),
        "by_size": {str(size): counts[size] for size in sorted(counts)},
    }


def summarise(
    comparisons: Sequence[Comparison],
    comparison_clusters: Sequence[int],
    total_cohort: int,
    unresolved: Dict[str, int],
) -> Dict[str, object]:
    """Compute every rate and count stage 2 is required to report.

    Args:
        comparisons: Resolved comparisons.
        comparison_clusters: Cluster id per comparison.
        total_cohort: Cohort size before dropping unresolved packages.
        unresolved: Unresolved counts by category.

    Returns:
        The stage-2 record, ready to serialise.
    """
    denominator = len(comparisons)
    definitions = {
        "any_change": [item for item in comparisons if item.changed],
        "gained": [item for item in comparisons if item.gained],
        "lost": [item for item in comparisons if item.lost],
        "both_gained_and_lost": [item for item in comparisons if item.both],
        "complete_turnover": [item for item in comparisons if item.complete_turnover],
    }

    cluster_of = dict(zip((item.name for item in comparisons), comparison_clusters))
    sub_definitions: Dict[str, object] = {}
    for label, hits in definitions.items():
        spanned = {cluster_of[item.name] for item in hits}
        sub_definitions[label] = {
            "count": len(hits),
            "rate": len(hits) / denominator if denominator else 0.0,
            "clusters_spanned": len(spanned),
        }

    positives = definitions["any_change"]
    positive_names = {item.name for item in positives}
    # Components recomputed over the positives alone, for contrast only. This is
    # the looser number: dropping the non-positive packages that bridge two
    # positive components splits them, so it can only rise.
    positives_only_members = tuple(
        CohortMember(
            name=item.name,
            index_at_t=0,
            last_release_before_t=datetime(1970, 1, 1, tzinfo=timezone.utc),
            first_release=datetime(1970, 1, 1, tzinfo=timezone.utc),
            releases_before_t=0,
            abandoned=False,
            maintainers=item.frozen,
        )
        for item in positives
    )
    positives_only_clusters = len(set(maintainer_clusters(positives_only_members)))

    primary_rate = sub_definitions["any_change"]["rate"]  # type: ignore[index]
    positive_clusters = sub_definitions["any_change"]["clusters_spanned"]  # type: ignore[index]

    return {
        "study": "maintainer handover, docs/handover-outcome-protocol.md",
        "stage": 2,
        "T": "2024-08-01",
        "cohort_size": total_cohort,
        "resolved": denominator,
        "resolution_rate": denominator / total_cohort if total_cohort else 0.0,
        "unresolved_by_category": dict(sorted(unresolved.items())),
        "clusters_in_cohort": len(set(comparison_clusters)),
        "sub_definitions": sub_definitions,
        "primary": {
            "definition": "any_change",
            "nominal_positives": len(positives),
            "rate": primary_rate,
            "effective_maintainer_clusters": positive_clusters,
            "positives_only_recomputed_clusters": positives_only_clusters,
        },
        "gates": {
            "resolution_over_90pct": {
                "threshold": 0.90,
                "observed": denominator / total_cohort if total_cohort else 0.0,
                "passed": (denominator / total_cohort if total_cohort else 0.0) > 0.90,
            },
            "positives_at_least_200": {
                "threshold": MIN_POSITIVES,
                "observed": len(positives),
                "passed": len(positives) >= MIN_POSITIVES,
            },
            "positive_clusters_at_least_150": {
                "threshold": MIN_POSITIVE_CLUSTERS,
                "observed": positive_clusters,
                "passed": positive_clusters >= MIN_POSITIVE_CLUSTERS,
            },
        },
        "rename_sanity_check": {
            "censored_version_document_rate": CENSORED_REFERENCE_RATE,
            "uncensored_rate": primary_rate,
            "ratio_to_censored": primary_rate / CENSORED_REFERENCE_RATE,
            "suspicion_threshold": RENAME_SUSPICION_RATE,
            "suspect_renames": primary_rate > RENAME_SUSPICION_RATE,
        },
        "maintainer_set_sizes": {
            "at_T": size_histogram([item.frozen for item in comparisons]),
            "now": size_histogram([item.current for item in comparisons]),
        },
        "positive_names_sample": sorted(positive_names)[:20],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run stage 2 and write its record.

    Args:
        argv: Command line, or None for ``sys.argv``.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot", type=Path, default=Path("research/data/npm-2026-08-06")
    )
    parser.add_argument(
        "--harvest", type=Path, default=Path("research/data/handover-2026-08-11")
    )
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--T", dest="moment", default="2024-08-01")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    snapshot = load_snapshot(args.snapshot)
    moment = datetime.fromisoformat(args.moment).replace(tzinfo=timezone.utc)
    members, _ = build_cohort(snapshot.packages, moment, 2, snapshot.harvested_at)
    harvested = load_harvest(args.harvest / HARVEST_NAME)

    comparisons, clusters, unresolved = compare(members, harvested)  # type: ignore[arg-type]
    record = summarise(comparisons, clusters, len(members), unresolved)

    out = args.out or (args.harvest / "stage2.json")
    with out.open("w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
