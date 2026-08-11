"""Rank statistics for the composition study, with the anchors the review made binding.

`docs/composition-protocol.md` §4 and §8.3. Everything is rank-based because
the composite is bounded, lumpy and tie-heavy: a Pearson correlation on it
would largely be reporting the shape of its bucketing.

Three anchors accompany every R², because the number is uninterpretable alone:

- a **maintainer-clustered permutation null**, so the 0.15 floor is measured
  against what collinear noise achieves rather than against zero;
- the **tie structure** of the target. §8.3 asked for a tie-aware *ceiling*;
  that anchor is retired as wrong and `tie_structure` says why in full;
- **maintainer-grouped cross-validated R²**, so in-sample optimism from five
  collinear predictors is visible instead of absorbed into the headline.

No third-party numerics. Ranks, least squares by normal equations with a
Gaussian solve, and a seeded resample — the abandonment pilot established that
AUC is a rank sum and stdlib suffices, and the same holds here.
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional, Sequence, Tuple

#: Fixed so a branch adjudication can be re-run. §8.4.
SEED = 20260811

#: §4 and §8.3.
BOOTSTRAP_ROUNDS = 2000
PERMUTATION_ROUNDS = 2000
CV_FOLDS = 5


def ranks(values: Sequence[float]) -> List[float]:
    """Average ranks, ties shared. The tie handling is the whole point here."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    index = 0
    while index < len(order):
        stop = index
        while stop + 1 < len(order) and values[order[stop + 1]] == values[order[index]]:
            stop += 1
        shared = (index + stop) / 2.0 + 1.0
        for position in range(index, stop + 1):
            out[order[position]] = shared
        index = stop + 1
    return out


def spearman(left: Sequence[float], right: Sequence[float]) -> Optional[float]:
    """Spearman rho, or None when either side is constant."""
    if len(left) < 3:
        return None
    a, b = ranks(left), ranks(right)
    mean_a = sum(a) / len(a)
    mean_b = sum(b) / len(b)
    num = sum((x - mean_a) * (y - mean_b) for x, y in zip(a, b))
    den_a = sum((x - mean_a) ** 2 for x in a)
    den_b = sum((y - mean_b) ** 2 for y in b)
    if den_a <= 0 or den_b <= 0:
        return None
    return float(num / (den_a * den_b) ** 0.5)


def _solve(matrix: List[List[float]], rhs: List[float]) -> Optional[List[float]]:
    """Gaussian elimination with partial pivoting. None when singular."""
    size = len(rhs)
    augmented = [row[:] + [rhs[i]] for i, row in enumerate(matrix)]
    for column in range(size):
        pivot = max(range(column, size), key=lambda r: abs(augmented[r][column]))
        if abs(augmented[pivot][column]) < 1e-10:
            return None
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        for row in range(column + 1, size):
            factor = augmented[row][column] / augmented[column][column]
            for k in range(column, size + 1):
                augmented[row][k] -= factor * augmented[column][k]
    out = [0.0] * size
    for row in range(size - 1, -1, -1):
        total = augmented[row][size] - sum(
            augmented[row][k] * out[k] for k in range(row + 1, size)
        )
        out[row] = total / augmented[row][row]
    return out


def _fit(design: List[List[float]], target: List[float]) -> Optional[List[float]]:
    """Least squares via normal equations, intercept prepended by the caller."""
    width = len(design[0])
    xtx = [[0.0] * width for _ in range(width)]
    xty = [0.0] * width
    for row, value in zip(design, target):
        for i in range(width):
            xty[i] += row[i] * value
            for j in range(width):
                xtx[i][j] += row[i] * row[j]
    return _solve(xtx, xty)


def _design(columns: Sequence[Sequence[float]]) -> List[List[float]]:
    """Rank each predictor, prepend an intercept."""
    ranked = [ranks(column) for column in columns]
    return [
        [1.0] + [ranked[c][i] for c in range(len(ranked))]
        for i in range(len(ranked[0]))
    ]


def _r2(target: Sequence[float], predicted: Sequence[float]) -> float:
    mean = sum(target) / len(target)
    ss_tot = sum((value - mean) ** 2 for value in target)
    if ss_tot <= 0:
        return 0.0
    ss_res = sum((t - p) ** 2 for t, p in zip(target, predicted))
    return max(0.0, 1.0 - ss_res / ss_tot)


def rank_r2(
    target: Sequence[float], columns: Sequence[Sequence[float]]
) -> Optional[float]:
    """In-sample R² of ranked target on ranked predictors."""
    if len(target) <= len(columns) + 2:
        return None
    y = ranks(target)
    design = _design(columns)
    beta = _fit(design, y)
    if beta is None:
        return None
    predicted = [sum(b * x for b, x in zip(beta, row)) for row in design]
    return _r2(y, predicted)


def adjusted_r2(r2: float, n: int, predictors: int) -> float:
    """Standard adjustment, reported beside the raw figure."""
    if n - predictors - 1 <= 0:
        return r2
    return 1.0 - (1.0 - r2) * (n - 1) / (n - predictors - 1)


def grouped_cv_r2(
    target: Sequence[float],
    columns: Sequence[Sequence[float]],
    groups: Sequence[int],
    folds: int = CV_FOLDS,
) -> Optional[float]:
    """Out-of-sample R², folds split on maintainer cluster rather than on rows.

    Splitting on rows would put two packages from one maintainer either side of
    a fold boundary and score the model on something it has effectively seen.
    The ranks are computed once on the full sample, so a fold's predictions are
    on the same scale as its targets.
    """
    y = ranks(target)
    design = _design(columns)
    unique = sorted(set(groups))
    if len(unique) < folds:
        return None
    rng = random.Random(SEED)
    shuffled = unique[:]
    rng.shuffle(shuffled)
    assignment = {group: i % folds for i, group in enumerate(shuffled)}

    predictions: List[float] = [0.0] * len(y)
    for fold in range(folds):
        train = [i for i in range(len(y)) if assignment[groups[i]] != fold]
        test = [i for i in range(len(y)) if assignment[groups[i]] == fold]
        if not test or len(train) <= len(columns) + 2:
            return None
        beta = _fit([design[i] for i in train], [y[i] for i in train])
        if beta is None:
            return None
        for i in test:
            predictions[i] = sum(b * x for b, x in zip(beta, design[i]))
    return _r2(y, predictions)


def tie_structure(target: Sequence[float]) -> Dict[str, float]:
    """How lumpy the target is, which is what the tie question really asks.

    §8.3 asked for a "tie-aware ceiling" on rank-R², on the reasoning that a
    tie-heavy target cannot be perfectly ordered. **That reasoning is wrong and
    the anchor is retired**, which is recorded rather than quietly dropped:
    average ranks are *constant within* a tied block, so predicting each rank
    by its block mean reproduces it exactly and the "ceiling" comes out 1.0 by
    construction, for any target, always. It measured nothing.

    What the tie density actually bears on is interpretation, not the maximum.
    The composite takes eleven distinct values across 2,906 packages, so an R²
    is reporting how well five activity measures order **eleven levels** — and
    a reader deserves that number rather than a ceiling that is 1.0 by
    algebra. So the levels are reported, and the largest level's share, which
    is what bounds how much any predictor can be rewarded for getting one
    bucket right.
    """
    counts: Dict[float, int] = {}
    for value in target:
        counts[value] = counts.get(value, 0) + 1
    total = len(target)
    return {
        "distinct_values": float(len(counts)),
        "largest_level_share": max(counts.values()) / total if total else 0.0,
    }


def clustered_bootstrap_r2(
    target: Sequence[float],
    columns: Sequence[Sequence[float]],
    groups: Sequence[int],
    rounds: int = BOOTSTRAP_ROUNDS,
) -> Tuple[float, float]:
    """95% interval for rank-R², resampling maintainer clusters with replacement."""
    by_group: Dict[int, List[int]] = {}
    for index, group in enumerate(groups):
        by_group.setdefault(group, []).append(index)
    keys = sorted(by_group)
    rng = random.Random(SEED)
    estimates: List[float] = []
    for _ in range(rounds):
        picked: List[int] = []
        for _ in range(len(keys)):
            picked.extend(by_group[keys[rng.randrange(len(keys))]])
        if len(picked) <= len(columns) + 2:
            continue
        sample_target = [target[i] for i in picked]
        sample_columns = [[column[i] for i in picked] for column in columns]
        value = rank_r2(sample_target, sample_columns)
        if value is not None:
            estimates.append(value)
    if not estimates:
        return (0.0, 1.0)
    estimates.sort()
    low = estimates[int(0.025 * len(estimates))]
    high = estimates[min(len(estimates) - 1, int(0.975 * len(estimates)))]
    return (low, high)


def clustered_permutation_null(
    target: Sequence[float],
    columns: Sequence[Sequence[float]],
    groups: Sequence[int],
    rounds: int = PERMUTATION_ROUNDS,
) -> Tuple[float, float]:
    """Mean and 95th percentile of rank-R² under a cluster-permuted linkage.

    Clusters are permuted whole rather than rows shuffled: shuffling rows would
    break the within-maintainer correlation as well as the battery-composite
    link, and would understate the null for exactly the reason the bootstrap is
    clustered in the first place.
    """
    by_group: Dict[int, List[int]] = {}
    for index, group in enumerate(groups):
        by_group.setdefault(group, []).append(index)
    keys = sorted(by_group)
    rng = random.Random(SEED + 1)
    estimates: List[float] = []
    for _ in range(rounds):
        order = keys[:]
        rng.shuffle(order)
        permuted: List[float] = [0.0] * len(target)
        source_rows = [row for key in order for row in by_group[key]]
        destination_rows = [row for key in keys for row in by_group[key]]
        for destination, source in zip(destination_rows, source_rows):
            permuted[destination] = target[source]
        value = rank_r2(permuted, columns)
        if value is not None:
            estimates.append(value)
    if not estimates:
        return (0.0, 0.0)
    estimates.sort()
    mean = sum(estimates) / len(estimates)
    p95 = estimates[min(len(estimates) - 1, int(0.95 * len(estimates)))]
    return (mean, p95)


def verdict(ablated_r2: float, shipped_r2: float) -> Tuple[str, str]:
    """§5's four branches, applied. Machine-checked rather than narrated.

    Line 4 is tested first because it overrides: when the two composites
    disagree by more than 0.20, the level of either is the wrong headline.
    """
    gap = shipped_r2 - ablated_r2
    if abs(gap) > 0.20:
        return (
            "difference-is-the-headline",
            f"shipped {shipped_r2:.4f} and ablated {ablated_r2:.4f} differ by "
            f"{gap:+.4f}; whether the score is activity depends entirely on "
            "counting the two signals that are activity by definition",
        )
    if ablated_r2 >= 0.50:
        return (
            "claim-made",
            f"ablated R² {ablated_r2:.4f} with the definitional signals "
            "removed; activity explains most of what the score varies on",
        )
    if ablated_r2 < 0.15:
        return (
            "claim-withdrawn",
            f"ablated R² {ablated_r2:.4f}; the composite is not substantially "
            "a function of publication activity, and the project's headline "
            "conclusion is corrected in the same change",
        )
    return (
        "magnitude-only",
        f"ablated R² {ablated_r2:.4f} sits between the lines; reported as a "
        "magnitude and the headline conclusion is softened to match",
    )
