"""Stage 4: the negative control, and why it is the within-bin one.

**The last study died here**, so `validation-protocol.md` now requires a
control to be shown non-degenerate before the protocol naming it is accepted.
The handover study pre-registered a within-cluster shuffle that preserved 96.6%
of labels, returned roughly the observed model AUC, and fired its own gate for
the wrong reason.

**The primary control is a within-download-bin permutation**, because the
primary endpoint is within-download-stratum AUC and *the null must match the
estimand*. A global permutation destroys the popularity-outcome association as
well as the signal-outcome one, so it validates the AUC machinery while being
structurally unable to detect popularity leakage — the exact confound
falsification line 4 exists for.

Two consequences follow, and both are implemented here rather than assumed:

* **The statistic is the unweighted mean of the five within-bin AUCs**, which
  is how the 0.539 bar was computed. Applying a *pooled* AUC to within-bin
  permuted labels would not collapse to 0.5 at all — the preserved
  popularity-outcome association would hold it up — and a control that cannot
  reach 0.5 is a broken control, not a finding.
* **Label preservation is reported.** It is the number that would have caught
  the handover failure: a permutation that leaves most labels where they were
  has not permuted anything. §0 measured 0.566 on this cohort, which is what
  five bins at these base rates predict.

The global permutation is retained as a secondary pipeline check, computed on
the pooled AUC exactly as the abandonment pilot computed the three figures §0
tabulates.

**Nothing in this module computes the observed AUC.** §9 orders the control
strictly before any model result, and "computed but not reported" is still
looking.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from abandonment_pilot.stats import roc_auc

#: §7 falsification line 2, as §0 restates it for the primary control.
BAND = (0.47, 0.53)

#: Permutation rounds, fixed by the protocol.
ROUNDS = 200


@dataclass(frozen=True)
class ControlResult:
    """One permutation control's distribution."""

    mean: float
    minimum: float
    maximum: float
    rounds: int
    #: Mean fraction of labels a round left where it found them. None for the
    #: global permutation, where it is not the diagnostic.
    label_preservation: Optional[float]

    def passes(self) -> bool:
        """Return whether the mean sits inside :data:`BAND`."""
        return BAND[0] <= self.mean <= BAND[1]


def download_bins(
    downloads: Sequence[Optional[int]], strata: int = 5
) -> Tuple[Tuple[int, ...], ...]:
    """Cut the packages with a download count into equal-size bins.

    Reproduces ``abandonment_pilot.experiment.stratify_by_downloads``: sort the
    support by downloads, slice into equal widths, and give the remainder to
    the last bin. Packages npm published no count for are not binned, because
    a missing count is not a low one.

    Args:
        downloads: One value per package, None where npm did not answer.
        strata: How many bins.

    Returns:
        One tuple of package indices per bin.
    """
    support = [index for index, value in enumerate(downloads) if value is not None]
    support.sort(key=lambda index: downloads[index] or 0)
    width = max(1, len(support) // strata)
    bins: List[Tuple[int, ...]] = []
    for band in range(strata):
        start = band * width
        end = len(support) if band == strata - 1 else (band + 1) * width
        indices = support[start:end]
        if indices:
            bins.append(tuple(indices))
    return tuple(bins)


def mean_within_bin_auc(
    scores: Sequence[float],
    labels: Sequence[bool],
    bins: Sequence[Sequence[int]],
) -> Optional[float]:
    """Return the unweighted mean AUC across bins.

    Args:
        scores: One score per package.
        labels: One label per package.
        bins: Package indices per bin.

    Returns:
        The mean over bins that had both classes present, or None when none
        did.
    """
    values: List[float] = []
    for indices in bins:
        value = roc_auc(
            [scores[index] for index in indices],
            [labels[index] for index in indices],
        )
        if value is not None:
            values.append(value)
    if not values:
        return None
    return sum(values) / len(values)


def within_bin_permutation(
    scores: Sequence[float],
    labels: Sequence[bool],
    bins: Sequence[Sequence[int]],
    rounds: int = ROUNDS,
    seed: int = 20260811,
) -> ControlResult:
    """Permute labels inside each download bin and re-measure the estimand.

    Args:
        scores: One score per package.
        labels: One label per package.
        bins: Package indices per bin.
        rounds: Permutations to draw.
        seed: Seed, so a rerun reproduces the distribution.

    Returns:
        The distribution, with label preservation.

    Raises:
        ValueError: If no round produced a defined statistic.
    """
    rng = random.Random(seed)
    working = list(labels)
    values: List[float] = []
    preserved: List[float] = []
    total = sum(len(indices) for indices in bins)
    for _ in range(rounds):
        kept = 0
        for indices in bins:
            drawn = [labels[index] for index in indices]
            rng.shuffle(drawn)
            for index, label in zip(indices, drawn):
                working[index] = label
                if label == labels[index]:
                    kept += 1
        value = mean_within_bin_auc(scores, working, bins)
        if value is not None:
            values.append(value)
            preserved.append(kept / total if total else 0.0)
    if not values:
        raise ValueError("the within-bin control needs both classes in some bin")
    return ControlResult(
        mean=sum(values) / len(values),
        minimum=min(values),
        maximum=max(values),
        rounds=len(values),
        label_preservation=sum(preserved) / len(preserved),
    )


def global_permutation(
    scores: Sequence[float],
    labels: Sequence[bool],
    rounds: int = ROUNDS,
    seed: int = 20260811,
) -> ControlResult:
    """Shuffle labels across the whole arm and re-measure the pooled AUC.

    The secondary pipeline check. It answers "does the harness read the outcome
    through some path other than the features", and nothing about popularity.

    Args:
        scores: One score per package.
        labels: One label per package.
        rounds: Permutations to draw.
        seed: Seed.

    Returns:
        The distribution.

    Raises:
        ValueError: If no round produced a defined AUC.
    """
    rng = random.Random(seed)
    shuffled = list(labels)
    values: List[float] = []
    for _ in range(rounds):
        rng.shuffle(shuffled)
        value = roc_auc(scores, shuffled)
        if value is not None:
            values.append(value)
    if not values:
        raise ValueError("the global control needs both classes present")
    return ControlResult(
        mean=sum(values) / len(values),
        minimum=min(values),
        maximum=max(values),
        rounds=len(values),
        label_preservation=None,
    )
