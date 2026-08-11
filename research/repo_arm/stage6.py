"""Stage 6: the repository arm head-to-head against its paired baseline.

The primary endpoint, and the only place in the study a claim is allowed to
rest: **the block composite**, registry-only against registry-plus-repository,
paired on the same packages, within download stratum, on a maintainer-clustered
bootstrap (§4d).

Three things this runner does that a simpler one would not, each because the
protocol makes it mandatory rather than because it is tidy:

* **It reports the within-stratum and the unstratified comparison side by side
  and promotes neither** (§12). They describe different populations. The
  within-stratum figure describes download-reported packages — npm answers for
  every unscoped package and about a fifth of scoped ones, so that subset runs
  73% unscoped while the cohort runs 65% scoped, and it abandons at 0.431
  against 0.380. The unstratified figure covers the arm and controls for
  nothing. The pair is the answer.
* **It reports the realised correlation between the arms and reads the MDE at
  it** (§12). The arms are nested, so rho is high by construction and the MDE is
  correspondingly small — but the number is measured rather than assumed, from
  the same clustered resamples that produced the interval.
* **It distinguishes a null from an uninformative one, in the direction that
  costs something.** A delta below the MDE at the realised rho is reported as
  *this study cannot speak*. That is not a survival certificate for the
  composite: §12 pre-commits that the withdrawn README claim (#330) stays
  withdrawn under every branch, and the report says so in its own field rather
  than in a paragraph someone can skip.

Falsification lines 1 and 4 are evaluated here, mechanically, from the numbers
above rather than from a reading of them.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence

from .endpoint import (
    PREREGISTERED_MDE_TABLE,
    PREREGISTERED_SE,
    REPLICATES,
    REPO_SIGNALS,
    SEED,
    Paired,
    assemble,
    complement_support,
    excludes_zero,
    full_support,
    mde_at,
    mde_row_for,
    paired,
    paired_dict,
    per_bin,
    stratified_support,
)

#: §7 line 1's bar: the repository arm must exceed the registry-only arm by
#: this much, within stratum, with the clustered interval excluding zero.
LINE_1_BAR: float = 0.05

REGISTRY_ONLY = "registry_only"
REPOSITORY = "registry_plus_repository"


def clears_line_1(result: Paired) -> bool:
    """Return whether a comparison clears §7 line 1's bar.

    Both halves are required: a delta of 0.05 whose interval spans zero has not
    been shown, and an interval excluding zero at a delta of 0.01 is a
    precisely-measured irrelevance.

    Args:
        result: The paired comparison.

    Returns:
        Whether the arm exceeded the comparator by the bar with an interval off
        zero.
    """
    return (
        result.delta is not None
        and result.delta >= LINE_1_BAR
        and excludes_zero(result.clustered)
        and (result.clustered.low or 0.0) > 0.0
    )


def mde_block(result: Paired) -> Dict[str, object]:
    """Read §12's MDE table at the realised correlation.

    Args:
        result: The primary comparison, carrying the realised correlation.

    Returns:
        The published table, the realised rho, the row it selects, and the MDE
        computed at that rho on both the published and the realised SE.
    """
    rho = result.realised_correlation
    realised_se = None
    if result.se_a is not None and result.se_b is not None:
        realised_se = max(result.se_a, result.se_b)
    return {
        "published_table": [
            {"assumed_correlation": assumed, "mde": value}
            for _, assumed, value in PREREGISTERED_MDE_TABLE
        ],
        "published_se": PREREGISTERED_SE,
        "realised_correlation": rho,
        "row_selected": None if rho is None else mde_row_for(rho),
        "mde_at_realised_rho_on_published_se": (
            None if rho is None else mde_at(rho, PREREGISTERED_SE)
        ),
        "mde_at_realised_rho_on_realised_se": (
            None if rho is None or realised_se is None else mde_at(rho, realised_se)
        ),
        "realised_se_per_arm": {
            "arm": result.se_a,
            "comparator": result.se_b,
            "paired_difference": result.se_delta,
        },
        "note": (
            "The MDE is read from the SE published in amendment 1 before this "
            "stage ran. The realised SE is reported beside it; where it is "
            "larger, the larger MDE is the honest bar and the verdict below "
            "uses whichever is larger."
        ),
    }


def verdict(primary: Paired, mde: Dict[str, object]) -> Dict[str, object]:
    """Decide what the primary endpoint licenses, under §7, §4c and §12.

    Args:
        primary: The within-stratum paired comparison.
        mde: The MDE block.

    Returns:
        The verdict, with the reasoning as data rather than prose.
    """
    candidates = [
        value
        for value in (
            mde.get("mde_at_realised_rho_on_published_se"),
            mde.get("mde_at_realised_rho_on_realised_se"),
        )
        if isinstance(value, float)
    ]
    governing = max(candidates) if candidates else None
    delta = primary.delta
    cleared = clears_line_1(primary)
    below_mde = delta is not None and governing is not None and abs(delta) < governing
    if cleared:
        finding = "the repository block exceeds the registry-only arm by the bar"
    elif below_mde:
        finding = "uninformative: the observed difference is below the MDE"
    else:
        finding = "the repository signals add nothing, informatively"
    return {
        "finding": finding,
        "delta": delta,
        "bar": LINE_1_BAR,
        "clustered_ci95": [primary.clustered.low, primary.clustered.high],
        "interval_excludes_zero": excludes_zero(primary.clustered),
        "governing_mde": governing,
        "below_governing_mde": below_mde,
        "uninformative_does_not_mean_the_composite_survives": (
            "Protocol 12 pre-commits this: 'uninformative' means this study "
            "cannot speak. The withdrawn README claim (#330) stays withdrawn "
            "under every branch of this study."
        ),
        "population": ("download-reported packages, not the cohort (protocol 12)"),
    }


def falsification_lines(
    primary: Paired, unstratified_arm: Paired, unstratified_support: Paired
) -> Dict[str, object]:
    """Evaluate §7's lines 1 and 4 from the numbers, not from a reading of them.

    Args:
        primary: Within-stratum, on the download-reported support.
        unstratified_arm: Pooled AUC over the whole arm.
        unstratified_support: Pooled AUC over the download-reported rows only,
            which holds the population fixed against ``primary``.

    Returns:
        One entry per line, each carrying whether it fired and why.
    """
    stratified_clears = clears_line_1(primary)
    arm_clears = clears_line_1(unstratified_arm)
    support_clears = clears_line_1(unstratified_support)
    return {
        "line_1_repo_arm_must_exceed_by_0.05_within_stratum": {
            "fired": not stratified_clears,
            "meaning_if_fired": (
                "the repository signals are reported as adding nothing, "
                "subject to the MDE qualification in the verdict above"
            ),
            "delta": primary.delta,
            "clustered_ci95": [primary.clustered.low, primary.clustered.high],
        },
        "line_4_effect_unstratified_but_not_within_stratum": {
            "fired_against_the_whole_arm": arm_clears and not stratified_clears,
            "fired_on_the_same_population": support_clears and not stratified_clears,
            "meaning_if_fired": (
                "the effect is reported as a popularity effect. Protocol 7 "
                "names this the most likely way the study produces a "
                "misleading positive."
            ),
            "unstratified_delta_whole_arm": unstratified_arm.delta,
            "unstratified_delta_same_population": unstratified_support.delta,
            "within_stratum_delta": primary.delta,
        },
        "line_2_negative_control": {
            "fired": False,
            "where": "stage 4, before any model result",
            "primary_within_download_bin_mean": 0.5013125053974443,
            "secondary_global_mean": 0.4991811741689528,
            "band": [0.47, 0.53],
        },
        "line_3_one_signal_carries_the_effect": {
            "evaluated_in": "stage 7, per signal, descriptive secondary",
        },
    }


def report(
    primary: Paired,
    unstratified_arm: Paired,
    unstratified_support: Paired,
    complement: Paired,
) -> Dict[str, object]:
    """Assemble stage 6's document.

    Args:
        primary: The within-stratum comparison.
        unstratified_arm: The unstratified comparison over the arm.
        unstratified_support: The unstratified comparison on the primary's rows.
        complement: The unstratified comparison on the rows npm reported no
            download count for. Descriptive, not pre-registered.

    Returns:
        The report.
    """
    mde = mde_block(primary)
    return {
        "what_this_is": (
            "Protocol 9 stage 6. Primary endpoint: the block composite, "
            "paired, within download stratum, maintainer-clustered bootstrap."
        ),
        "neither_is_promoted": (
            "Protocol 12. The within-stratum figure describes "
            "download-reported packages; the unstratified figure describes the "
            "arm and controls for nothing. Both are reported; the pair is the "
            "answer and the gap between them is information."
        ),
        "primary_within_download_stratum": paired_dict(primary),
        "unstratified_over_the_arm": paired_dict(unstratified_arm),
        "unstratified_on_the_stratified_support": {
            **paired_dict(unstratified_support),
            "why": (
                "Diagnostic for falsification line 4: comparing stratified "
                "against unstratified on different populations would confound "
                "stratification with selection."
            ),
        },
        "descriptive_not_preregistered": {
            "why": (
                "The within-stratum and unstratified figures disagree. The "
                "first question protocol 12 makes one ask is whether the "
                "disagreement is stratification or population. Holding the "
                "population fixed answers it, and the complement below is the "
                "half the endpoint cannot see. Descriptive: no claim rests on "
                "either, and neither is a headline."
            ),
            "no_download_count_reported": paired_dict(complement),
        },
        "mde": mde,
        "verdict": verdict(primary, mde),
        "falsification_lines": falsification_lines(
            primary, unstratified_arm, unstratified_support
        ),
        "bootstrap": {"replicates": REPLICATES, "seed": SEED},
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run stage 6.

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
    assembled = assemble(
        args.snapshot,
        args.data,
        moment,
        [(REGISTRY_ONLY, None), (REPOSITORY, REPO_SIGNALS)],
    )
    stratified = stratified_support(assembled)
    whole = full_support(assembled)
    outside = complement_support(assembled)

    document = report(
        paired(stratified, REPOSITORY, REGISTRY_ONLY, stratified=True),
        paired(whole, REPOSITORY, REGISTRY_ONLY, stratified=False),
        paired(stratified, REPOSITORY, REGISTRY_ONLY, stratified=False),
        paired(outside, REPOSITORY, REGISTRY_ONLY, stratified=False),
    )
    document["arm"] = {
        "nominal_n": len(assembled.labels),
        "effective_maintainer_clusters": len(set(assembled.clusters)),
        "positives": sum(1 for label in assembled.labels if label),
        "largest_maintainer_cluster": whole.largest_cluster,
        "signals_measured": assembled.measured[REPOSITORY],
        "repository_block": (
            "five signals: health_indicators, security_policy, "
            "dependency_update, community_activity, maintained. "
            "community_popularity is unmeasured (stage 3) and is not in the "
            "block; signed_commits and branch_protection were unevaluable at "
            "any past date (protocol 4)."
        ),
        "registry_only_signals_the_composite_actually_scores": sorted(
            set(assembled.measured[REGISTRY_ONLY]) - {"license"}
        ),
        "registry_baseline_contains_no_release_cadence": (
            "staleness and version are ablated by the abandonment protocol "
            "(release cadence cannot predict the absence of releases without "
            "circularity), so the paired baseline scores maintainer count and "
            "the source-repository declaration and nothing else. Protocol 10's "
            "pre-registered interpretation says an improvement over this "
            "baseline is 'improvement beyond cadence' because the baseline "
            "'already contains release recency'. It does not. Recorded here "
            "because the measurement stands and the interpretation attached "
            "to it does not."
        ),
        "distinct_score_values": {
            "registry_only_on_the_arm": whole.distinct_scores(REGISTRY_ONLY),
            "repository_on_the_arm": whole.distinct_scores(REPOSITORY),
            "registry_only_on_the_support": stratified.distinct_scores(REGISTRY_ONLY),
            "repository_on_the_support": stratified.distinct_scores(REPOSITORY),
        },
        "largest_maintainer_cluster_on_the_support": stratified.largest_cluster,
        "per_bin": {
            "why": (
                "The endpoint is a mean over five numbers. Publishing the mean "
                "without them hides which bin moved it."
            ),
            REGISTRY_ONLY: per_bin(assembled, REGISTRY_ONLY),
            REPOSITORY: per_bin(assembled, REPOSITORY),
        },
    }
    with (args.data / "stage6.json").open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1, sort_keys=True)
    print(json.dumps(document, indent=1, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
