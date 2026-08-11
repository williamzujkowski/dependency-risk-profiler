"""Stage 5: the registry-only baseline, on the same packages as the repository arm.

**This is the stage §9 says is easy to get wrong**, so the thing it must not do
is worth stating before the thing it does. The comparator is *not* the published
registry-only figure of 0.577. That number was measured on the whole cohort;
this arm is the 1,869 packages whose declared repository both resolved and read,
which §6 establishes is a survivorship-selected subset with a different
abandonment rate. Comparing a repository arm measured here against a registry
figure measured there would attribute the difference between two populations to
the repository block. So the baseline is re-measured, paired, on exactly the
rows stage 6 will use.

Two figures come out, and §12 forbids promoting either:

* **within-download-stratum**, the primary endpoint's comparator, describing
  *download-reported packages* — 73% unscoped, against a cohort that is 65%
  scoped;
* **unstratified**, describing the whole arm and controlling for nothing.

The stage also re-derives the endpoint's support and reconciles it against the
count §12's MDE was computed on, because a power calculation published against
one denominator and read against another is the drafting error §12 exists to
correct, not one to repeat.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence

from .endpoint import (
    REPLICATES,
    SEED,
    Assembled,
    arm_estimate,
    assemble,
    full_support,
    interval_dict,
    per_bin,
    stratified_support,
)

#: The published full-cohort registry-only AUC. Recorded here **only** so the
#: report can say in one place that it is not the comparator.
PUBLISHED_FULL_COHORT_AUC: float = 0.577

#: The full-cohort within-stratum figure, §3's bar. Same caveat.
PUBLISHED_FULL_COHORT_WITHIN_STRATUM: float = 0.539

#: §12's stated support, against which this run's realised support is checked.
AMENDMENT_SUPPORT = {"packages": 981, "clusters": 850, "positives": 402}

REGISTRY_ONLY = "registry_only"


def report(assembled: Assembled) -> Dict[str, object]:
    """Assemble stage 5's document.

    Args:
        assembled: The scored arm, carrying the registry-only scores.

    Returns:
        The report.
    """
    stratified = stratified_support(assembled)
    unstratified = full_support(assembled)

    within = arm_estimate(stratified, REGISTRY_ONLY, stratified=True)
    pooled_arm = arm_estimate(unstratified, REGISTRY_ONLY, stratified=False)
    pooled_support = arm_estimate(stratified, REGISTRY_ONLY, stratified=False)

    positives = sum(1 for label in assembled.labels if label)
    realised = {
        "packages": stratified.nominal_n,
        "clusters": stratified.effective_clusters,
        "positives": stratified.positives,
    }
    return {
        "what_this_is": (
            "The paired registry-only comparator, re-measured on the "
            "repository arm's own packages. Protocol 9 stage 5."
        ),
        "not_the_comparator": {
            "published_full_cohort_auc": PUBLISHED_FULL_COHORT_AUC,
            "published_full_cohort_within_stratum": (
                PUBLISHED_FULL_COHORT_WITHIN_STRATUM
            ),
            "why": (
                "Those were measured on the full cohort. This arm is the "
                "survivorship-selected subset whose repository still resolves "
                "(protocol 6), so the difference between them is a difference "
                "between populations, not between arms."
            ),
        },
        "arm": {
            "population": (
                "cohort members whose declared GitHub repository resolved and "
                "whose signals read without error"
            ),
            "nominal_n": len(assembled.labels),
            "effective_maintainer_clusters": len(set(assembled.clusters)),
            "abandoned": positives,
            "base_rate": positives / len(assembled.labels),
            "signals_measured": assembled.measured[REGISTRY_ONLY],
        },
        "within_download_stratum": {
            "population": (
                "download-reported packages only. NOT the cohort: protocol 12 "
                "records that npm answers download counts for every unscoped "
                "package and about a fifth of scoped ones."
            ),
            "statistic": "unweighted mean of the within-download-bin AUCs",
            "nominal_n": stratified.nominal_n,
            "effective_maintainer_clusters": stratified.effective_clusters,
            "positives": stratified.positives,
            "auc": within.estimate,
            "clustered": interval_dict(within.interval, difference=False),
            "bootstrap_se": within.standard_error(),
            "bins": per_bin(assembled, REGISTRY_ONLY),
        },
        "unstratified_over_the_arm": {
            "population": (
                "the whole repository arm; covers the arm, controls for " "nothing"
            ),
            "statistic": "pooled AUC",
            "nominal_n": unstratified.nominal_n,
            "effective_maintainer_clusters": unstratified.effective_clusters,
            "positives": unstratified.positives,
            "auc": pooled_arm.estimate,
            "clustered": interval_dict(pooled_arm.interval, difference=False),
            "bootstrap_se": pooled_arm.standard_error(),
        },
        "unstratified_on_the_stratified_support": {
            "why": (
                "Diagnostic only, and reported because falsification line 4 "
                "compares stratified against unstratified: on different "
                "populations that comparison confounds stratification with "
                "selection. This row holds the population fixed."
            ),
            "statistic": "pooled AUC over the download-reported rows",
            "nominal_n": stratified.nominal_n,
            "effective_maintainer_clusters": stratified.effective_clusters,
            "auc": pooled_support.estimate,
            "clustered": interval_dict(pooled_support.interval, difference=False),
        },
        "support_reconciliation": {
            "amendment_1_stated": AMENDMENT_SUPPORT,
            "realised_here": realised,
            "agrees": realised == AMENDMENT_SUPPORT,
            "note": (
                "Stage 4 recorded 979 / 849 / 401 for the same support. "
                "Amendment 1 states 981 / 850 / 402. The realised figure "
                "governs; the MDE is read from the published SE regardless, "
                "which a two-package difference does not move."
            ),
        },
        "bootstrap": {"replicates": REPLICATES, "seed": SEED},
        "neither_is_promoted": (
            "Protocol 12: the within-stratum figure describes "
            "download-reported packages and the unstratified figure describes "
            "the arm. The pair is the answer."
        ),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run stage 5.

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
    assembled = assemble(args.snapshot, args.data, moment, [(REGISTRY_ONLY, None)])
    document = report(assembled)
    with (args.data / "stage5.json").open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1, sort_keys=True)
    print(json.dumps(document, indent=1, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
