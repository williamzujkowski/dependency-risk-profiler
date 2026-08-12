"""A two-predictor logistic regression, in the standard library.

`docs/additive-value-protocol.md` §2. Three parameters over ~1,400 rows, fitted
by iteratively reweighted least squares. No third-party numerics, for the same
reason the abandonment pilot has none: AUC is a rank sum and this is a 3x3
solve, so a dependency would buy nothing and cost reproducibility.

Predictors are standardised before fitting and the coefficients are reported on
the standardised scale. That matters for §6 line 3, which reads the *sign* of
the composite's coefficient across folds: on the raw scale a coefficient's
magnitude would track the predictor's units and tell you nothing about
stability.
"""

from __future__ import annotations

import math
from typing import List, Optional, Sequence, Tuple


def _standardise(column: Sequence[float]) -> Tuple[List[float], float, float]:
    """Centre and scale, returning the constants so a fold can reuse them.

    A fold must standardise its held-out rows with the *training* mean and
    deviation, never their own — otherwise the test rows inform the transform
    that is applied to them, which is leakage wearing a preprocessing costume.
    """
    n = len(column)
    mean = sum(column) / n
    variance = sum((value - mean) ** 2 for value in column) / n
    deviation = math.sqrt(variance) if variance > 0 else 1.0
    return [(value - mean) / deviation for value in column], mean, deviation


def _apply(column: Sequence[float], mean: float, deviation: float) -> List[float]:
    return [(value - mean) / deviation for value in column]


def _solve(matrix: List[List[float]], rhs: List[float]) -> Optional[List[float]]:
    """Gaussian elimination with partial pivoting. None when singular."""
    size = len(rhs)
    augmented = [row[:] + [rhs[i]] for i, row in enumerate(matrix)]
    for column in range(size):
        pivot = max(range(column, size), key=lambda r: abs(augmented[r][column]))
        if abs(augmented[pivot][column]) < 1e-12:
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


class Logistic:
    """Fitted coefficients plus the standardisation the fit was done under."""

    def __init__(
        self,
        beta: List[float],
        means: List[float],
        deviations: List[float],
    ) -> None:
        self.beta = beta
        self.means = means
        self.deviations = deviations

    def predict(self, columns: Sequence[Sequence[float]]) -> List[float]:
        """Linear predictor for held-out rows, on the training transform.

        The log-odds is returned rather than the probability: AUC is
        rank-based, the two orderings are identical, and skipping the logistic
        transform avoids saturating to 0.0 or 1.0 on extreme rows.
        """
        scaled = [
            _apply(column, self.means[i], self.deviations[i])
            for i, column in enumerate(columns)
        ]
        rows = len(scaled[0])
        return [
            self.beta[0]
            + sum(self.beta[i + 1] * scaled[i][r] for i in range(len(scaled)))
            for r in range(rows)
        ]


def fit(
    columns: Sequence[Sequence[float]],
    labels: Sequence[bool],
    iterations: int = 50,
) -> Optional[Logistic]:
    """Fit by IRLS. Returns None if the design goes singular.

    Separation would send coefficients to infinity; the ridge below is the
    smallest thing that keeps the solve well-posed without materially moving a
    fit that is not separated. It is fixed rather than tuned, because tuning it
    against the outcome is the flexibility §2 refuses.
    """
    standardised: List[List[float]] = []
    means: List[float] = []
    deviations: List[float] = []
    for column in columns:
        scaled, mean, deviation = _standardise(column)
        standardised.append(scaled)
        means.append(mean)
        deviations.append(deviation)

    width = len(standardised) + 1
    rows = len(labels)
    beta = [0.0] * width
    ridge = 1e-6

    for _ in range(iterations):
        gradient = [0.0] * width
        hessian = [[0.0] * width for _ in range(width)]
        for r in range(rows):
            design = [1.0] + [standardised[i][r] for i in range(len(standardised))]
            eta = sum(beta[i] * design[i] for i in range(width))
            eta = max(-30.0, min(30.0, eta))
            probability = 1.0 / (1.0 + math.exp(-eta))
            weight = max(probability * (1.0 - probability), 1e-9)
            residual = (1.0 if labels[r] else 0.0) - probability
            for i in range(width):
                gradient[i] += design[i] * residual
                for j in range(width):
                    hessian[i][j] += design[i] * design[j] * weight
        for i in range(width):
            hessian[i][i] += ridge
        step = _solve(hessian, gradient)
        if step is None:
            return None
        beta = [beta[i] + step[i] for i in range(width)]
        if max(abs(value) for value in step) < 1e-8:
            break

    return Logistic(beta, means, deviations)
