"""Discrimination, calibration, and a paired comparison that respects clusters.

**No `scikit-learn`, and the reason is not squeamishness about dependencies.**
The protocol names a paired DeLong test at alpha 0.05, and in the same section
requires clustered confidence intervals because packages sharing a maintainer
are not independent observations. Those two requirements are in tension:
DeLong's closed-form covariance is derived under independent observations, so
running it on a cohort with maintainer clusters would report an interval
narrower than the data supports — the precise error the clustering requirement
exists to prevent.

:func:`paired_auc_delta` therefore resolves the pairing the way DeLong does —
both models scored on the same packages, differences taken within package — and
estimates the variance by resampling **maintainer components** rather than by a
formula that assumes there are none. Resampling packages instead of components
reproduces DeLong's assumption, so both are reported and the gap between them
is the cost of the clustering, stated rather than hidden.

The whole file is stdlib. AUC is the Mann-Whitney U statistic, which is a rank
sum; average precision is a walk down a sorted list. Neither is a place where a
dependency buys correctness.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple


def _ranks(values: Sequence[float]) -> List[float]:
    """Return midranks: tied values share the average of the ranks they span.

    Midranks rather than ordinal ranks because ties are the common case here —
    the maintainer signal takes four distinct values, so a cohort of two
    thousand packages has enormous tie groups, and ordinal ranks would let the
    input order decide the AUC.

    Args:
        values: The values to rank.

    Returns:
        One rank per value, in the input order, 1-based.
    """
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        end = position
        while end + 1 < len(order) and values[order[end + 1]] == values[order[position]]:
            end += 1
        midrank = (position + end) / 2.0 + 1.0
        for tied in range(position, end + 1):
            ranks[order[tied]] = midrank
        position = end + 1
    return ranks


def roc_auc(scores: Sequence[float], labels: Sequence[bool]) -> Optional[float]:
    """Return the area under the ROC curve.

    Computed as the Mann-Whitney U statistic over midranks, which is the same
    number as the trapezoidal area and handles ties by giving them the 0.5
    credit the trapezoid gives them.

    Args:
        scores: One score per observation; higher means more risk.
        labels: One label per observation; True is the positive class.

    Returns:
        The AUC, or None when either class is empty and the question does not
        arise.

    Raises:
        ValueError: If the two sequences differ in length.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must be the same length")
    positives = sum(1 for label in labels if label)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return None
    ranks = _ranks(scores)
    rank_sum = sum(rank for rank, label in zip(ranks, labels) if label)
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def average_precision(
    scores: Sequence[float], labels: Sequence[bool]
) -> Optional[float]:
    """Return average precision: the area under the precision-recall curve.

    Ties are resolved as one group, so a predictor that assigns the same score
    to a thousand packages gets the precision of that whole group rather than
    the precision it would have had if the positives happened to sort first.

    Args:
        scores: One score per observation; higher means more risk.
        labels: One label per observation; True is the positive class.

    Returns:
        Average precision, or None when there are no positives.

    Raises:
        ValueError: If the two sequences differ in length.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must be the same length")
    total_positives = sum(1 for label in labels if label)
    if total_positives == 0:
        return None
    order = sorted(range(len(scores)), key=lambda index: -scores[index])
    seen = 0
    hits = 0
    area = 0.0
    previous_recall = 0.0
    position = 0
    while position < len(order):
        end = position
        while end + 1 < len(order) and scores[order[end + 1]] == scores[order[position]]:
            end += 1
        for index in range(position, end + 1):
            seen += 1
            if labels[order[index]]:
                hits += 1
        recall = hits / total_positives
        precision = hits / seen
        area += (recall - previous_recall) * precision
        previous_recall = recall
        position = end + 1
    return area


@dataclass(frozen=True)
class OperatingPoint:
    """Precision and recall at one threshold on the normalized score."""

    threshold: float
    flagged: int
    true_positives: int
    precision: Optional[float]
    recall: float


def operating_points(
    scores: Sequence[float], labels: Sequence[bool], thresholds: Sequence[float]
) -> Tuple[OperatingPoint, ...]:
    """Return precision and recall at each threshold, flagging ``score >= t``.

    Args:
        scores: One score per observation.
        labels: One label per observation.
        thresholds: Thresholds to evaluate.

    Returns:
        One point per threshold, in the given order.
    """
    total_positives = sum(1 for label in labels if label)
    points: List[OperatingPoint] = []
    for threshold in thresholds:
        flagged = [label for score, label in zip(scores, labels) if score >= threshold]
        hits = sum(1 for label in flagged if label)
        points.append(
            OperatingPoint(
                threshold=threshold,
                flagged=len(flagged),
                true_positives=hits,
                precision=(hits / len(flagged)) if flagged else None,
                recall=(hits / total_positives) if total_positives else 0.0,
            )
        )
    return tuple(points)


@dataclass(frozen=True)
class BucketRate:
    """The outcome rate inside one verdict bucket."""

    bucket: str
    count: int
    positives: int
    rate: Optional[float]


def bucket_rates(
    buckets: Sequence[str], labels: Sequence[bool], order: Sequence[str]
) -> Tuple[BucketRate, ...]:
    """Return the positive rate within each bucket.

    Args:
        buckets: One bucket name per observation.
        labels: One label per observation.
        order: Bucket names in the order to report.

    Returns:
        One row per name in ``order``, including empty buckets — an empty HIGH
        bucket is a calibration result, not a row to omit.
    """
    rows: List[BucketRate] = []
    for name in order:
        members = [label for bucket, label in zip(buckets, labels) if bucket == name]
        positives = sum(1 for label in members if label)
        rows.append(
            BucketRate(
                bucket=name,
                count=len(members),
                positives=positives,
                rate=(positives / len(members)) if members else None,
            )
        )
    return tuple(rows)


def _resample_indices(
    clusters: Sequence[int], rng: random.Random
) -> List[int]:
    """Draw one bootstrap resample by sampling whole clusters with replacement."""
    members: Dict[int, List[int]] = {}
    for index, cluster in enumerate(clusters):
        members.setdefault(cluster, []).append(index)
    keys = list(members)
    drawn: List[int] = []
    for _ in range(len(keys)):
        drawn.extend(members[keys[rng.randrange(len(keys))]])
    return drawn


@dataclass(frozen=True)
class Interval:
    """A bootstrap point estimate with a percentile interval.

    ``draws`` is kept because the p-value and the interval have to come from
    the *same* resamples. Recomputing them from an identically-seeded second
    loop is two things that must agree and nothing checking that they do.
    """

    estimate: Optional[float]
    low: Optional[float]
    high: Optional[float]
    replicates: int
    draws: Tuple[float, ...]

    def two_sided_p(self) -> Optional[float]:
        """Return the two-sided bootstrap p-value against a null of zero.

        Returns:
            The p-value, or None when no resample produced a value.
        """
        if not self.draws:
            return None
        below = sum(1 for value in self.draws if value <= 0.0) / len(self.draws)
        above = sum(1 for value in self.draws if value >= 0.0) / len(self.draws)
        return min(1.0, 2.0 * min(below, above))


def bootstrap_interval(
    statistic: Callable[[Sequence[int]], Optional[float]],
    clusters: Sequence[int],
    replicates: int,
    seed: int,
) -> Interval:
    """Return a clustered percentile bootstrap interval for a statistic.

    Args:
        statistic: Computes the statistic over a list of row indices, or None
            when a resample degenerates (one class empty).
        clusters: Cluster id per row; whole clusters are resampled.
        replicates: How many resamples to draw.
        seed: Seed, so a rerun reproduces the interval exactly.

    Returns:
        The point estimate on the observed rows and the 2.5/97.5 percentiles of
        the resamples.
    """
    point = statistic(list(range(len(clusters))))
    rng = random.Random(seed)
    drawn: List[float] = []
    for _ in range(replicates):
        value = statistic(_resample_indices(clusters, rng))
        if value is not None:
            drawn.append(value)
    if not drawn:
        return Interval(
            estimate=point, low=None, high=None, replicates=0, draws=()
        )
    ordered = sorted(drawn)
    low = ordered[int(0.025 * (len(ordered) - 1))]
    high = ordered[int(0.975 * (len(ordered) - 1))]
    return Interval(
        estimate=point,
        low=low,
        high=high,
        replicates=len(ordered),
        draws=tuple(ordered),
    )


@dataclass(frozen=True)
class PairedDelta:
    """A paired AUC difference with both variance estimates."""

    auc_a: Optional[float]
    auc_b: Optional[float]
    delta: Optional[float]
    #: Resampling maintainer components: the protocol's clustered interval.
    clustered: Interval
    #: Resampling packages: what DeLong's independence assumption would give.
    unclustered: Interval
    #: Two-sided bootstrap p-value from the clustered resamples.
    p_value: Optional[float]


def paired_auc_delta(
    scores_a: Sequence[float],
    scores_b: Sequence[float],
    labels: Sequence[bool],
    clusters: Sequence[int],
    replicates: int,
    seed: int,
) -> PairedDelta:
    """Compare two predictors scored on the same packages.

    Args:
        scores_a: Scores from the model under test.
        scores_b: Scores from the comparator.
        labels: Outcome per package.
        clusters: Maintainer component id per package.
        replicates: Bootstrap resamples.
        seed: Seed.

    Returns:
        Both AUCs, their difference, and the two intervals.

    Raises:
        ValueError: If the inputs differ in length.
    """
    if not len(scores_a) == len(scores_b) == len(labels) == len(clusters):
        raise ValueError("paired comparison needs one row per package in every input")

    def delta(indices: Sequence[int]) -> Optional[float]:
        subset_labels = [labels[index] for index in indices]
        first = roc_auc([scores_a[index] for index in indices], subset_labels)
        second = roc_auc([scores_b[index] for index in indices], subset_labels)
        if first is None or second is None:
            return None
        return first - second

    clustered = bootstrap_interval(delta, clusters, replicates, seed)
    unclustered = bootstrap_interval(delta, list(range(len(labels))), replicates, seed)

    return PairedDelta(
        auc_a=roc_auc(scores_a, labels),
        auc_b=roc_auc(scores_b, labels),
        delta=delta(list(range(len(labels)))),
        clustered=clustered,
        unclustered=unclustered,
        p_value=clustered.two_sided_p(),
    )


def shuffled_auc(
    scores: Sequence[float], labels: Sequence[bool], rounds: int, seed: int
) -> Tuple[float, float, float]:
    """Return the mean, minimum and maximum AUC over shuffled labels.

    The negative control. Permuting the labels destroys every association while
    leaving the score distribution, the class balance and the tie structure
    exactly as they are, so the AUC has to collapse to 0.5. It failing to do so
    means the harness is reading the outcome through some path other than the
    features — which is the one bug in an experiment like this that produces a
    publishable-looking number.

    Args:
        scores: One score per observation.
        labels: One label per observation.
        rounds: How many permutations to draw.
        seed: Seed.

    Returns:
        ``(mean, minimum, maximum)`` over the rounds.

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
        raise ValueError("the negative control needs both classes present")
    return sum(values) / len(values), min(values), max(values)
