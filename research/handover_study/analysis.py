"""Negative controls, and the label permutations each one is built from.

Protocol §6 line 2 fixes one control: *labels shuffled within maintainer
cluster*, mean AUC inside ``[0.47, 0.53]``. That is the gate and
:func:`within_cluster_shuffle` implements it literally.

It has to be reported next to what it can and cannot detect on this cohort,
because the answer is unusual. 2,905 packages fall into 2,176 maintainer
components: 1,910 rows sit alone in their component, and once components whose
members happen to share a label are counted too, **87.3% of the label vector is
invariant under a within-cluster permutation**. A control that leaves seven
labels in eight exactly where they were does not destroy the association it is
supposed to destroy. It returns roughly the observed AUC shrunk towards 0.5,
so it *passes* when the model is weak and *fires* when the model is strong —
which is the opposite of what a negative control is for.

So two further permutations are reported beside it, neither of them a
substitute for the pre-registered gate and neither of them able to change it:

* :func:`global_shuffle` — the abandonment pilot's control, reused. It destroys
  every association and is the one that actually answers "is the harness
  reading the outcome through some path other than the features".
* :func:`cluster_block_permutation` — whole clusters exchange their label
  vectors with other clusters of the same size. This destroys the
  feature-label association while preserving the within-cluster label
  correlation that the clustering exists to represent, which is what a
  cluster-aware control is normally taken to mean.

Nothing here reweights, refits or tunes anything. The three differ only in
which permutation is applied to the labels.
"""

from __future__ import annotations

import random
from typing import Callable, Dict, List, Sequence, Tuple

from abandonment_pilot.stats import roc_auc

#: A permutation: labels and their cluster ids in, permuted labels out.
Permutation = Callable[[Sequence[bool], Sequence[int], random.Random], List[bool]]


def _by_cluster(clusters: Sequence[int]) -> Dict[int, List[int]]:
    """Group row positions by cluster id, preserving order within a cluster."""
    grouped: Dict[int, List[int]] = {}
    for position, cluster in enumerate(clusters):
        grouped.setdefault(cluster, []).append(position)
    return grouped


def within_cluster_shuffle(
    labels: Sequence[bool], clusters: Sequence[int], rng: random.Random
) -> List[bool]:
    """Permute labels **inside** each maintainer cluster. Protocol §6 line 2.

    Args:
        labels: One label per row.
        clusters: Cluster id per row.
        rng: Source of randomness.

    Returns:
        The permuted labels, in row order.
    """
    out = list(labels)
    for positions in _by_cluster(clusters).values():
        drawn = [labels[position] for position in positions]
        rng.shuffle(drawn)
        for position, value in zip(positions, drawn):
            out[position] = value
    return out


def global_shuffle(
    labels: Sequence[bool], clusters: Sequence[int], rng: random.Random
) -> List[bool]:
    """Permute labels across the whole cohort, ignoring clusters.

    Args:
        labels: One label per row.
        clusters: Cluster id per row, unused; present for the shared signature.
        rng: Source of randomness.

    Returns:
        The permuted labels, in row order.
    """
    del clusters
    drawn = list(labels)
    rng.shuffle(drawn)
    return drawn


def cluster_block_permutation(
    labels: Sequence[bool], clusters: Sequence[int], rng: random.Random
) -> List[bool]:
    """Exchange whole clusters' label vectors between same-sized clusters.

    Same-sized only, because a size-3 label block cannot be laid onto a size-1
    cluster without splitting it, and splitting the blocks is what
    :func:`within_cluster_shuffle` already does.

    Args:
        labels: One label per row.
        clusters: Cluster id per row.
        rng: Source of randomness.

    Returns:
        The permuted labels, in row order.
    """
    grouped = _by_cluster(clusters)
    by_size: Dict[int, List[List[int]]] = {}
    for positions in grouped.values():
        by_size.setdefault(len(positions), []).append(positions)

    out = list(labels)
    for blocks in by_size.values():
        order = list(range(len(blocks)))
        rng.shuffle(order)
        for target, source in zip(blocks, order):
            donor = blocks[source]
            for position, origin in zip(target, donor):
                out[position] = labels[origin]
    return out


def permuted_auc(
    scores: Sequence[float],
    labels: Sequence[bool],
    clusters: Sequence[int],
    permutation: Permutation,
    rounds: int,
    seed: int,
) -> Tuple[float, float, float, float]:
    """Return mean, min, max AUC over permuted labels, and the preserved share.

    The fourth number is what makes the three controls comparable: the fraction
    of rows whose label the permutation left exactly where it was, averaged over
    the rounds. A control that preserves most of the vector cannot collapse the
    AUC and its verdict says more about the effect size than about the harness.

    Args:
        scores: One score per row.
        labels: One label per row.
        clusters: Cluster id per row.
        permutation: How to permute.
        rounds: Permutations to draw.
        seed: Seed, so a rerun reproduces the numbers.

    Returns:
        ``(mean, minimum, maximum, mean preserved share)``.

    Raises:
        ValueError: If no round produced a defined AUC.
    """
    rng = random.Random(seed)
    values: List[float] = []
    preserved: List[float] = []
    for _ in range(rounds):
        drawn = permutation(labels, clusters, rng)
        value = roc_auc(scores, drawn)
        if value is None:
            continue
        values.append(value)
        same = sum(1 for old, new in zip(labels, drawn) if old == new)
        preserved.append(same / len(labels))
    if not values:
        raise ValueError("the negative control needs both classes present")
    return (
        sum(values) / len(values),
        min(values),
        max(values),
        sum(preserved) / len(preserved),
    )


def invariant_share(labels: Sequence[bool], clusters: Sequence[int]) -> float:
    """Return the share of rows a within-cluster shuffle can never move.

    A row is invariant when every row in its cluster carries the same label,
    which includes every singleton cluster. This is computed exactly rather
    than sampled, and it is the number that diagnoses the §6 control on this
    cohort.

    Args:
        labels: One label per row.
        clusters: Cluster id per row.

    Returns:
        The share, in ``[0, 1]``.
    """
    if not labels:
        return 0.0
    frozen = 0
    for positions in _by_cluster(clusters).values():
        if len({labels[position] for position in positions}) == 1:
            frozen += len(positions)
    return frozen / len(labels)
