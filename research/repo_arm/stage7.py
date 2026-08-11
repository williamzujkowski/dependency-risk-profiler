"""Stage 7: per-signal ablations. Descriptive secondary, and nothing rests on them.

§4d is the whole design of this stage: six signals plus a composite is seven
chances for the strongest to masquerade as the finding, so the primary endpoint
is the composite and **these results are descriptive**. No claim in the write-up
may rest on the best of five, and this module reports every signal every time
rather than the one that came out ahead.

Two directions, because they answer different questions and disagreeing is
informative:

* **add-one-in** — registry-only plus a single repository signal, against
  registry-only. What that signal is worth on its own.
* **leave-one-out** — the whole block against the block without that signal.
  What is lost by removing it, which is smaller than add-one-in whenever two
  signals carry the same information.

Ablation is **absence**: the input is withheld and the shipped scorer reports
the signal unmeasured, renormalising over the remaining weights. Nothing here
substitutes a neutral value, which would score a signal nobody measured.

**§7 line 3's rule is fixed in :data:`CARRIES_THRESHOLD` and evaluated
mechanically.** The threshold is a reporting convention, written before the
numbers existed, not a hypothesis test — the point is that "one signal carries
it" is decided by a rule rather than by looking at the table and forming an
impression.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from .endpoint import (
    REPLICATES,
    REPO_SIGNALS,
    SEED,
    Assembled,
    Paired,
    Support,
    assemble,
    excludes_zero,
    full_support,
    paired,
    paired_dict,
    stratified_support,
)

REGISTRY_ONLY = "registry_only"
REPOSITORY = "registry_plus_repository"

#: Fraction of the composite's effect a single signal must both *supply on its
#: own* and *take away when removed* before §7 line 3 is reported as fired.
#: A convention, fixed before the ablations ran.
CARRIES_THRESHOLD: float = 0.8

#: §7 line 1's bar, reused: the composite must show an effect before "one signal
#: carries the whole effect" is a question with an answer.
LINE_1_BAR: float = 0.05


def arm_specification() -> List[Tuple[str, Optional[FrozenSet[str]]]]:
    """Return every arm stage 7 scores.

    Returns:
        ``(name, enabled)`` pairs: the two endpoints of stage 6, then one
        add-one-in and one leave-one-out arm per repository signal.
    """
    arms: List[Tuple[str, Optional[FrozenSet[str]]]] = [
        (REGISTRY_ONLY, None),
        (REPOSITORY, REPO_SIGNALS),
    ]
    for signal in sorted(REPO_SIGNALS):
        arms.append((f"only:{signal}", frozenset({signal})))
        arms.append((f"without:{signal}", REPO_SIGNALS - {signal}))
    return arms


def ablations(support: Support, stratified: bool) -> Dict[str, Tuple[Paired, Paired]]:
    """Return both ablation directions for every repository signal.

    Args:
        support: The rows to compute over.
        stratified: Whether the statistic is the within-bin mean.

    Returns:
        Per signal, ``(add-one-in, leave-one-out)``.
    """
    rows: Dict[str, Tuple[Paired, Paired]] = {}
    for signal in sorted(REPO_SIGNALS):
        rows[signal] = (
            paired(support, f"only:{signal}", REGISTRY_ONLY, stratified),
            paired(support, REPOSITORY, f"without:{signal}", stratified),
        )
    return rows


def line_3(
    composite: Paired, rows: Dict[str, Tuple[Paired, Paired]]
) -> Dict[str, object]:
    """Evaluate §7 line 3 against :data:`CARRIES_THRESHOLD`.

    **The rule presupposes an effect.** "One signal carries the whole effect"
    is undefined where the composite shows no effect to carry, and the share
    that expresses it is a ratio whose denominator is then approximately zero —
    which produces shares of six and minus five that mean nothing at all. So
    the line is evaluated only where the composite delta reaches the bar §7
    line 1 sets and its clustered interval clears zero; elsewhere the shares
    are reported for completeness and the line is marked not evaluable.

    *This guard was added after the first run produced exactly those degenerate
    ratios on the unstratified arm.* It moves the rule strictly toward claiming
    less, and the ordering is recorded rather than smoothed over.

    Args:
        composite: The block composite against registry-only, on the same rows
            and the same statistic.
        rows: The per-signal comparisons.

    Returns:
        Whether any single signal both supplies and removes most of the effect,
        and the shares that decided it.
    """
    composite_delta = composite.delta
    evaluable = (
        composite_delta is not None
        and composite_delta >= LINE_1_BAR
        and excludes_zero(composite.clustered)
        and (composite.clustered.low or 0.0) > 0.0
    )
    shares: Dict[str, object] = {}
    carriers: List[str] = []
    for signal, (add_in, leave_out) in sorted(rows.items()):
        add = add_in.delta
        out = leave_out.delta
        supplied = (
            None
            if composite_delta in (None, 0.0) or add is None
            else add / composite_delta
        )
        removed = (
            None
            if composite_delta in (None, 0.0) or out is None
            else out / composite_delta
        )
        shares[signal] = {
            "share_supplied_alone": supplied,
            "share_lost_when_removed": removed,
        }
        if (
            supplied is not None
            and removed is not None
            and supplied >= CARRIES_THRESHOLD
            and removed >= CARRIES_THRESHOLD
        ):
            carriers.append(signal)
    return {
        "evaluable": evaluable,
        "not_evaluable_because": (
            None
            if evaluable
            else (
                "the composite shows no effect on this population, so there is "
                "nothing for one signal to carry and the share ratios have an "
                "approximately-zero denominator"
            )
        ),
        "fired": bool(carriers) and evaluable,
        "rule": (
            "a signal both supplies at least "
            f"{CARRIES_THRESHOLD} of the composite delta on its own and costs "
            "at least that much when removed, evaluated only where the "
            "composite itself clears the line-1 bar with an interval off zero"
        ),
        "carriers": carriers if evaluable else [],
        "carriers_ignored_because_not_evaluable": [] if evaluable else carriers,
        "composite_delta": composite_delta,
        "shares": shares,
        "meaning_if_fired": (
            "that is the finding, reported per signal and not folded into a "
            "composite claim (protocol 7 line 3)"
        ),
    }


def section(support: Support, stratified: bool, population: str) -> Dict[str, object]:
    """Return one population's ablation table plus its line-3 verdict.

    Args:
        support: The rows.
        stratified: Whether the statistic is the within-bin mean.
        population: What the rows describe, in words, per §12.

    Returns:
        The section.
    """
    rows = ablations(support, stratified)
    composite = paired(support, REPOSITORY, REGISTRY_ONLY, stratified)
    return {
        "population": population,
        "nominal_n": support.nominal_n,
        "effective_maintainer_clusters": support.effective_clusters,
        "positives": support.positives,
        "largest_maintainer_cluster": support.largest_cluster,
        "composite": paired_dict(composite),
        "per_signal": {
            signal: {
                "add_one_in": paired_dict(add_in),
                "leave_one_out": paired_dict(leave_out),
            }
            for signal, (add_in, leave_out) in sorted(rows.items())
        },
        "line_3": line_3(composite, rows),
    }


def report(assembled: Assembled) -> Dict[str, object]:
    """Assemble stage 7's document.

    Args:
        assembled: The scored arms.

    Returns:
        The report.
    """
    stratified = stratified_support(assembled)
    whole = full_support(assembled)
    return {
        "what_this_is": (
            "Protocol 9 stage 7. Per-signal ablations, DESCRIPTIVE SECONDARY "
            "under protocol 4d. No claim rests on the best of five."
        ),
        "signals": sorted(REPO_SIGNALS),
        "why_five_not_six": (
            "community_popularity is unmeasured: stage 3 could not "
            "reconstruct it without a proxy protocol 4b forbids. "
            "signed_commits and branch_protection were unevaluable at any "
            "past date before the study began."
        ),
        "ablation_is_absence": (
            "The input is withheld and the shipped scorer reports the signal "
            "unmeasured, renormalising over the remaining weights. No neutral "
            "value is substituted."
        ),
        "within_download_stratum": section(
            stratified,
            True,
            "download-reported packages, NOT the cohort (protocol 12)",
        ),
        "unstratified_over_the_arm": section(
            whole,
            False,
            "the whole repository arm; covers the arm, controls for nothing",
        ),
        "bootstrap": {"replicates": REPLICATES, "seed": SEED},
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run stage 7.

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
    assembled = assemble(args.snapshot, args.data, moment, arm_specification())
    document = report(assembled)
    with (args.data / "stage7.json").open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1, sort_keys=True)
    print(json.dumps(document, indent=1, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
