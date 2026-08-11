"""The primary endpoint's machinery, shared by stages 5, 6 and 7.

Everything downstream of stage 4 answers one question — *does the repository
block discriminate abandonment beyond what the download count already
explains* — so the pieces that decide the answer live in one module rather than
three copies that have to be kept in step.

Four decisions are fixed here rather than in the runners, because a knob a
runner can turn is a knob that can be turned until a threshold clears:

* **The estimand is the unweighted mean of the five within-bin AUCs.** That is
  how the 0.539 bar was computed (§3), how stage 4's control was measured, and
  the only statistic the two are comparable across. A pooled AUC over the same
  rows is a different number answering a different question, and §12 requires
  it reported *beside* rather than instead — so both are computed, and neither
  runner gets to choose which one it publishes.
* **Bins are cut once, on the observed data, and never recut inside a
  bootstrap.** The strata are the estimand's definition. Recutting them per
  resample would let the bin edges wander and quietly widen the interval.
* **The resampling unit is the maintainer component**, restricted to the rows
  the statistic is computed over. For the within-stratum endpoint that is the
  download-reported support, not the arm.
* **Ablation is absence.** A signal is removed by withholding its input, so the
  shipped scorer reports it unmeasured and renormalises over the remaining
  weights (#74). Nothing here touches a weight, and nothing substitutes a
  neutral value for a signal it wants to silence.

``community_popularity`` is not in :data:`REPO_SIGNALS`. Stage 3 could not
reconstruct it without a proxy §4b forbids, so the block is **five signals**,
and the count is asserted in the tests so it cannot drift back to six.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import CohortMember, build_cohort, maintainer_clusters
from abandonment_pilot.snapshot import PackageRecord, load_snapshot
from abandonment_pilot.stats import Interval, bootstrap_interval, roc_auc
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import MeasurementState

from .arm import REPO_SIGNALS, build_arm_metadata
from .control import download_bins
from .signals_at_t import RepoSignals

__all__ = [
    "REPO_SIGNALS",
    "Assembled",
    "Paired",
    "Support",
    "arm_estimate",
    "assemble",
    "full_support",
    "interval_dict",
    "mde_at",
    "mde_row_for",
    "paired",
    "paired_dict",
    "per_bin",
    "stratified_support",
]

#: Bootstrap resamples for every interval in stages 5-7, and the seed. Fixed
#: here, once, before any of the three runners executes: an interval whose
#: replicate count or seed is chosen after seeing the estimate is not an
#: interval.
REPLICATES: int = 2000
SEED: int = 20260811

#: §12's published SE of the mean within-bin AUC, computed on the endpoint's
#: support *before* stage 5 ran. The MDE rows are read off this, not off
#: whatever this run's resamples produce — substituting a smaller realised SE
#: after the fact would shrink the bar the result has to clear.
PREREGISTERED_SE: float = 0.0157

#: The SE §12's *table* was evidently computed on, before being rounded to three
#: significant figures for publication: 0.0623 / ((z + z) * sqrt(2)) inverts to
#: 0.015724. Recorded because reconstructing the table from the rounded 0.0157
#: lands one unit low in the last digit on three of the four rows, and an
#: unexplained mismatch against a pre-registered number is worth more suspicion
#: than it deserves here. The published rows remain authoritative:
#: :data:`PREREGISTERED_MDE_TABLE` carries them verbatim.
PUBLISHED_TABLE_IMPLIED_SE: float = 0.015724

#: alpha = 0.05 two-sided, power 0.80 — the constants §12's table was built on.
_Z_ALPHA: float = 1.959963985
_Z_POWER: float = 0.841621234


def mde_at(correlation: float, standard_error: float = PREREGISTERED_SE) -> float:
    """Return the minimum detectable paired difference at a given correlation.

    Reproduces §12's table: the paired difference has standard error
    ``se * sqrt(2 * (1 - rho))``, and the MDE is ``(z_alpha + z_power)`` of it.
    On the published SE of 0.0157 this lands within 0.0001 of every published
    row; on :data:`PUBLISHED_TABLE_IMPLIED_SE` it reproduces all four exactly.

    Args:
        correlation: Correlation between the two arms' estimates. Clamped below
            1.0, where the paired MDE would be zero.
        standard_error: SE of one arm's mean within-bin AUC.

    Returns:
        The smallest paired difference detectable at alpha 0.05, power 0.80.
    """
    rho = min(correlation, 0.999999)
    return (_Z_ALPHA + _Z_POWER) * standard_error * math.sqrt(2.0 * (1.0 - rho))


#: §12's table, as published, so a runner reports the row rather than a number
#: it recomputed and might have recomputed differently.
PREREGISTERED_MDE_TABLE: Tuple[Tuple[str, Optional[float], float], ...] = (
    ("independent (worst case)", 0.0, 0.0623),
    ("rho = 0.5", 0.5, 0.0441),
    ("rho = 0.8", 0.8, 0.0279),
    ("rho = 0.9", 0.9, 0.0197),
)


def mde_row_for(correlation: float) -> str:
    """Return which published MDE row a realised correlation selects.

    The rows are a ladder, so "selects" means the nearest row at or below the
    realised value — reading a *higher* row than the data supports would quote
    a smaller MDE than the study earned.

    Args:
        correlation: The realised correlation between arms.

    Returns:
        The label of the selected row.
    """
    selected = PREREGISTERED_MDE_TABLE[0][0]
    for label, assumed, _ in PREREGISTERED_MDE_TABLE:
        if assumed is not None and correlation >= assumed:
            selected = label
    return selected


@dataclass(frozen=True)
class Assembled:
    """The arm, its outcome, its strata, and one score per package per arm."""

    #: Package names, in row order.
    names: Tuple[str, ...]
    labels: Tuple[bool, ...]
    #: Maintainer component id per row.
    clusters: Tuple[int, ...]
    #: npm downloads over the 30 days ending at T, None where npm did not answer.
    downloads: Tuple[Optional[int], ...]
    #: Download-bin id per row, None for rows npm reported no count for.
    bin_of: Tuple[Optional[int], ...]
    #: Arm name -> normalized score per row.
    arms: Dict[str, Tuple[float, ...]]
    #: Arm name -> signal name -> rows the scorer could measure it for.
    measured: Dict[str, Dict[str, int]]

    @property
    def support(self) -> Tuple[int, ...]:
        """Return the rows the within-stratum endpoint is computed over."""
        return tuple(
            index for index, band in enumerate(self.bin_of) if band is not None
        )


def per_bin(assembled: Assembled, arm: str) -> List[Dict[str, object]]:
    """Return one row per download bin: size, clusters, base rate, AUC.

    The endpoint is a mean over these five numbers, so publishing the mean
    without them hides which bin moved it.

    Args:
        assembled: The scored arm.
        arm: Which arm's scores to read.

    Returns:
        One row per bin, in ascending download order.
    """
    bands: Dict[int, List[int]] = {}
    for index, band in enumerate(assembled.bin_of):
        if band is not None:
            bands.setdefault(band, []).append(index)
    rows: List[Dict[str, object]] = []
    for band in sorted(bands):
        indices = bands[band]
        labels = [assembled.labels[index] for index in indices]
        downloads = [assembled.downloads[index] or 0 for index in indices]
        rows.append(
            {
                "bin": band + 1,
                "downloads_at_t": [min(downloads), max(downloads)],
                "nominal_n": len(indices),
                "effective_maintainer_clusters": len(
                    {assembled.clusters[index] for index in indices}
                ),
                "abandoned": sum(1 for label in labels if label),
                "base_rate": sum(1 for label in labels if label) / len(indices),
                "auc": roc_auc(
                    [assembled.arms[arm][index] for index in indices], labels
                ),
            }
        )
    return rows


def _load_signals(path: Path) -> Dict[str, RepoSignals]:
    """Read stage 3's reconstruction back into records.

    Args:
        path: ``signals.json``.

    Returns:
        Signals per slug.
    """
    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    return {
        slug: RepoSignals(
            slug=slug,
            head_at_t=value["head_at_t"],
            has_tests=value["has_tests"],
            has_ci=value["has_ci"],
            has_contribution_guidelines=value["has_contribution_guidelines"],
            has_security_policy=value["has_security_policy"],
            has_dependency_update_tools=value["has_dependency_update_tools"],
            commit_frequency=value["commit_frequency"],
            is_maintained=value["is_maintained"],
            error=value["error"],
        )
        for slug, value in raw.items()
    }


def assemble(
    snapshot_dir: Path,
    data_dir: Path,
    moment: datetime,
    arms: Sequence[Tuple[str, Optional[FrozenSet[str]]]],
) -> Assembled:
    """Score the repository arm's packages under each requested configuration.

    The population is stage 4's exactly: the cohort members whose declared
    repository resolved and whose signals read without error. Every figure in
    stages 5-7 is conditional on it, per §6.

    Args:
        snapshot_dir: The verified npm snapshot.
        data_dir: The stage 2-4 artifact directory.
        moment: T.
        arms: ``(name, enabled)`` pairs. ``enabled`` is the subset of
            :data:`REPO_SIGNALS` whose inputs are supplied; ``None`` means the
            registry-only arm, which attaches no repository block at all.
            ``None`` and ``frozenset()`` score identically — an attached block
            with nothing enabled supplies no input — and both are permitted so
            a caller can say which one it means.

    Returns:
        The assembled arm.
    """
    snapshot = load_snapshot(snapshot_dir)
    members, _ = build_cohort(snapshot.packages, moment, 2, snapshot.harvested_at)
    records: Dict[str, PackageRecord] = {r.name: r for r in snapshot.packages}
    clusters = maintainer_clusters(members)

    signals = _load_signals(data_dir / "signals.json")
    with (data_dir / "declarations.json").open(encoding="utf-8") as handle:
        declarations = {d["package"]: d for d in json.load(handle)}
    downloads_table = snapshot.downloads.get(moment.date().isoformat(), {})

    rows: List[Tuple[CohortMember, int, RepoSignals]] = []
    for member, cluster in zip(members, clusters):
        slug = declarations[member.name]["slug"]
        record = signals.get(slug) if isinstance(slug, str) else None
        if record is None or record.error is not None:
            continue
        rows.append((member, cluster, record))

    scorer = RiskScorer()
    scored: Dict[str, Tuple[float, ...]] = {}
    measured: Dict[str, Dict[str, int]] = {}
    for name, enabled in arms:
        values: List[float] = []
        counts: Dict[str, int] = {}
        for member, _cluster, record in rows:
            metadata = build_arm_metadata(
                records[member.name],
                member,
                None if enabled is None else record,
                enabled=REPO_SIGNALS if enabled is None else enabled,
            )
            result = scorer.score_dependency(metadata)
            values.append(result.total_score / scorer.max_score)
            for signal, measurement in result.measurements.items():
                if measurement.state is MeasurementState.MEASURED:
                    counts[signal] = counts.get(signal, 0) + 1
        scored[name] = tuple(values)
        measured[name] = counts

    download_values = tuple(downloads_table.get(m.name) for m, _, _ in rows)
    bins = download_bins(download_values)
    bin_of: List[Optional[int]] = [None] * len(rows)
    for position, indices in enumerate(bins):
        for index in indices:
            bin_of[index] = position

    return Assembled(
        names=tuple(m.name for m, _, _ in rows),
        labels=tuple(m.abandoned for m, _, _ in rows),
        clusters=tuple(cluster for _, cluster, _ in rows),
        downloads=download_values,
        bin_of=tuple(bin_of),
        arms=scored,
        measured=measured,
    )


@dataclass(frozen=True)
class Support:
    """One statistic's rows, flattened so a bootstrap can index them directly."""

    scores: Dict[str, Tuple[float, ...]]
    labels: Tuple[bool, ...]
    clusters: Tuple[int, ...]
    #: Bin id per row, or None throughout for the unstratified statistic.
    bands: Tuple[Optional[int], ...]

    @property
    def nominal_n(self) -> int:
        """Return the number of packages."""
        return len(self.labels)

    @property
    def effective_clusters(self) -> int:
        """Return the number of maintainer components the rows fall into."""
        return len(set(self.clusters))

    @property
    def positives(self) -> int:
        """Return the number of abandoned packages."""
        return sum(1 for label in self.labels if label)

    @property
    def largest_cluster(self) -> int:
        """Return the size of the largest maintainer component in these rows.

        A clustered bootstrap resamples whole components, so one large
        component widens every interval it appears in. Reporting it makes an
        interval's width attributable rather than mysterious.
        """
        counts: Dict[int, int] = {}
        for cluster in self.clusters:
            counts[cluster] = counts.get(cluster, 0) + 1
        return max(counts.values()) if counts else 0

    def distinct_scores(self, arm: str) -> int:
        """Return how many distinct values an arm's score takes on these rows.

        The tie structure is not a footnote here: a composite built from two
        scored signals takes a handful of values, and an AUC over a handful of
        values is mostly the midrank convention. Worth stating beside any
        comparison between a coarse arm and a fine one.
        """
        return len(set(self.scores[arm]))


def stratified_support(assembled: Assembled) -> Support:
    """Return the download-reported rows, carrying their bin ids.

    §12: this population is **not the cohort**. npm answers download counts for
    every unscoped package and about a fifth of scoped ones, so these rows are
    predominantly unscoped and abandon at a materially different rate.

    Args:
        assembled: The scored arm.

    Returns:
        The support for the within-stratum endpoint.
    """
    rows = assembled.support
    return Support(
        scores={
            name: tuple(values[index] for index in rows)
            for name, values in assembled.arms.items()
        },
        labels=tuple(assembled.labels[index] for index in rows),
        clusters=tuple(assembled.clusters[index] for index in rows),
        bands=tuple(assembled.bin_of[index] for index in rows),
    )


def complement_support(assembled: Assembled) -> Support:
    """Return the rows npm reported no download count for.

    **Descriptive, and not pre-registered.** §12 establishes that the excluded
    half is not a random half — it is almost entirely scoped and abandons at a
    lower rate — and requires the two populations to be named wherever a figure
    appears. When the stratified and unstratified results disagree, the first
    question is whether the disagreement is stratification or population, and
    that question is answerable only by looking at the population the
    stratified endpoint cannot see. No claim rests on this.

    Args:
        assembled: The scored arm.

    Returns:
        The rows outside the endpoint's support, unstratified.
    """
    rows = [index for index, band in enumerate(assembled.bin_of) if band is None]
    return Support(
        scores={
            name: tuple(values[index] for index in rows)
            for name, values in assembled.arms.items()
        },
        labels=tuple(assembled.labels[index] for index in rows),
        clusters=tuple(assembled.clusters[index] for index in rows),
        bands=tuple(None for _ in rows),
    )


def full_support(assembled: Assembled) -> Support:
    """Return every row in the arm, unstratified.

    Args:
        assembled: The scored arm.

    Returns:
        The support for the unstratified comparison, which covers the arm but
        controls for nothing.
    """
    return Support(
        scores=dict(assembled.arms),
        labels=assembled.labels,
        clusters=assembled.clusters,
        bands=tuple(None for _ in assembled.labels),
    )


def _statistic(support: Support, arm: str, stratified: bool) -> Optional[float]:
    """Return the observed statistic for one arm over every row."""
    return _statistic_over(support, arm, stratified, range(support.nominal_n))


def _statistic_over(
    support: Support, arm: str, stratified: bool, indices: Sequence[int]
) -> Optional[float]:
    """Return the statistic for one arm over the given rows.

    Args:
        support: The rows.
        arm: Which arm's scores to read.
        stratified: True for the unweighted mean of within-bin AUCs, False for
            the pooled AUC.
        indices: Rows, possibly with repeats from a bootstrap resample.

    Returns:
        The statistic, or None when no bin had both classes present.
    """
    scores = support.scores[arm]
    if not stratified:
        return roc_auc(
            [scores[index] for index in indices],
            [support.labels[index] for index in indices],
        )
    grouped: Dict[int, List[int]] = {}
    for index in indices:
        band = support.bands[index]
        if band is None:
            continue
        grouped.setdefault(band, []).append(index)
    values: List[float] = []
    for band in sorted(grouped):
        value = roc_auc(
            [scores[index] for index in grouped[band]],
            [support.labels[index] for index in grouped[band]],
        )
        if value is not None:
            values.append(value)
    if not values:
        return None
    return sum(values) / len(values)


@dataclass(frozen=True)
class ArmEstimate:
    """One arm's point estimate and clustered interval."""

    estimate: Optional[float]
    interval: Interval

    def standard_error(self) -> Optional[float]:
        """Return the bootstrap SE: the standard deviation of the replicates."""
        draws = self.interval.draws
        if len(draws) < 2:
            return None
        mean = sum(draws) / len(draws)
        variance = sum((value - mean) ** 2 for value in draws) / (len(draws) - 1)
        return math.sqrt(variance)


def arm_estimate(support: Support, arm: str, stratified: bool) -> ArmEstimate:
    """Return one arm's discrimination with a maintainer-clustered interval.

    Args:
        support: The rows.
        arm: Which arm.
        stratified: Whether to use the within-bin mean.

    Returns:
        The estimate and its interval.
    """
    interval = bootstrap_interval(
        lambda indices: _statistic_over(support, arm, stratified, indices),
        support.clusters,
        REPLICATES,
        SEED,
    )
    return ArmEstimate(estimate=_statistic(support, arm, stratified), interval=interval)


@dataclass(frozen=True)
class Paired:
    """A paired head-to-head between two arms on the same packages."""

    arm_a: str
    arm_b: str
    stratified: bool
    auc_a: Optional[float]
    auc_b: Optional[float]
    delta: Optional[float]
    clustered: Interval
    unclustered: Interval
    p_value: Optional[float]
    #: Correlation between the two arms' estimates across the *same* clustered
    #: resamples. This is the rho §12's MDE table is indexed on: the paired SE
    #: is ``sqrt(se_a^2 + se_b^2 - 2 rho se_a se_b)``.
    realised_correlation: Optional[float]
    se_a: Optional[float]
    se_b: Optional[float]
    se_delta: Optional[float]
    nominal_n: int
    effective_clusters: int
    positives: int


def paired(support: Support, arm_a: str, arm_b: str, stratified: bool) -> Paired:
    """Compare two arms scored on the same packages.

    The difference is taken *within* resample, so the pairing survives the
    bootstrap: both arms see the same drawn clusters, which is what makes the
    interval a paired one rather than the difference of two marginal intervals.

    Args:
        support: The rows.
        arm_a: The arm under test.
        arm_b: The comparator.
        stratified: Whether the statistic is the within-bin mean.

    Returns:
        Both estimates, their difference, both intervals, and the realised
        correlation between the arms.
    """
    collected: List[Tuple[float, float]] = []
    recording = [False]

    def difference(indices: Sequence[int]) -> Optional[float]:
        first = _statistic_over(support, arm_a, stratified, indices)
        second = _statistic_over(support, arm_b, stratified, indices)
        if first is None or second is None:
            return None
        if recording[0]:
            collected.append((first, second))
        return first - second

    # ``bootstrap_interval`` evaluates the observed rows once before it
    # resamples. That call is the point estimate, not a draw, so recording is
    # switched on after it rather than by dropping the first element — a
    # positional trick that would break silently if the helper ever reordered.
    recording[0] = False
    observed = difference(list(range(support.nominal_n)))
    recording[0] = True
    clustered = bootstrap_interval(difference, support.clusters, REPLICATES, SEED)
    # The point-estimate call inside the helper landed in ``collected``; the
    # resample draws are everything after it.
    paired_draws = collected[1:]
    recording[0] = False
    unclustered = bootstrap_interval(
        difference, list(range(support.nominal_n)), REPLICATES, SEED
    )

    correlation = _pearson([a for a, _ in paired_draws], [b for _, b in paired_draws])
    se_a = _sample_sd([a for a, _ in paired_draws])
    se_b = _sample_sd([b for _, b in paired_draws])
    se_delta = _sample_sd([a - b for a, b in paired_draws])

    return Paired(
        arm_a=arm_a,
        arm_b=arm_b,
        stratified=stratified,
        auc_a=_statistic(support, arm_a, stratified),
        auc_b=_statistic(support, arm_b, stratified),
        delta=observed,
        clustered=clustered,
        unclustered=unclustered,
        p_value=clustered.two_sided_p(),
        realised_correlation=correlation,
        se_a=se_a,
        se_b=se_b,
        se_delta=se_delta,
        nominal_n=support.nominal_n,
        effective_clusters=support.effective_clusters,
        positives=support.positives,
    )


def _sample_sd(values: Sequence[float]) -> Optional[float]:
    """Return the sample standard deviation, or None below two values."""
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    return math.sqrt(sum((v - mean) ** 2 for v in values) / (len(values) - 1))


def _pearson(left: Sequence[float], right: Sequence[float]) -> Optional[float]:
    """Return Pearson's r, or None when either side does not vary."""
    if len(left) < 2 or len(left) != len(right):
        return None
    mean_left = sum(left) / len(left)
    mean_right = sum(right) / len(right)
    covariance = sum((a - mean_left) * (b - mean_right) for a, b in zip(left, right))
    spread_left = math.sqrt(sum((a - mean_left) ** 2 for a in left))
    spread_right = math.sqrt(sum((b - mean_right) ** 2 for b in right))
    if spread_left == 0.0 or spread_right == 0.0:
        return None
    return covariance / (spread_left * spread_right)


def excludes_zero(interval: Interval) -> bool:
    """Return whether a difference's interval lies entirely off zero."""
    return (
        interval.low is not None
        and interval.high is not None
        and (interval.low > 0.0 or interval.high < 0.0)
    )


def interval_dict(interval: Interval, *, difference: bool = True) -> Dict[str, object]:
    """Render an interval for the JSON report.

    Args:
        interval: The bootstrap interval.
        difference: Whether the quantity is a difference. Only then is
            "excludes zero" a meaningful thing to say — an AUC's interval
            excludes zero always and it means nothing, and a field that is
            always true beside a falsification line that reads a field of that
            name is a trap.

    Returns:
        Its bounds, replicate count, and — for a difference — whether it
        excludes zero.
    """
    rendered: Dict[str, object] = {
        "ci95": [interval.low, interval.high],
        "replicates": interval.replicates,
    }
    if difference:
        rendered["excludes_zero"] = excludes_zero(interval)
    return rendered


def paired_dict(result: Paired) -> Dict[str, object]:
    """Render a paired comparison for the JSON report.

    Args:
        result: The comparison.

    Returns:
        A JSON-safe document, carrying nominal n *and* effective clusters
        because a count without its clustering overstates what it supports.
    """
    draws = result.clustered.draws
    return {
        "arm": result.arm_a,
        "comparator": result.arm_b,
        # How close the interval is to zero, stated as a count rather than left
        # to be inferred from a percentile. A lower bound sitting at +0.001 and
        # one sitting at +0.05 read identically as "excludes zero"; these two
        # numbers are the difference.
        "clustered_resamples_at_or_below_zero": sum(
            1 for value in draws if value <= 0.0
        ),
        "clustered_resamples": len(draws),
        "statistic": (
            "unweighted mean of the within-download-bin AUCs"
            if result.stratified
            else "pooled AUC"
        ),
        "population": (
            "download-reported packages (NOT the cohort; see protocol 12)"
            if result.stratified
            else "the repository arm, unstratified (no popularity control)"
        ),
        "nominal_n": result.nominal_n,
        "effective_maintainer_clusters": result.effective_clusters,
        "positives": result.positives,
        "auc_arm": result.auc_a,
        "auc_comparator": result.auc_b,
        "delta": result.delta,
        "clustered": interval_dict(result.clustered),
        "unclustered_for_reference": interval_dict(result.unclustered),
        "p_value_clustered": result.p_value,
        "realised_correlation_between_arms": result.realised_correlation,
        "se_arm": result.se_a,
        "se_comparator": result.se_b,
        "se_delta": result.se_delta,
    }
