"""Guards for the composition study, of the two kinds its review made binding.

`docs/composition-protocol.md` §8.1 and §8.4. The first is the one that decides
whether the study means anything: if the ablated composite turns out to read
release timestamps after all, the emergent-versus-definitional split is void
and so is the protocol. Every reviewer named it, so it is proven mechanically
rather than by reading the scorer and believing what it says.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from dependency_risk_profiler.models import AdvisoryLookupState, DependencyMetadata

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))

from composition.analysis import (  # noqa: E402
    adjusted_r2,
    rank_r2,
    ranks,
    spearman,
    tie_structure,
    verdict,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS = REPO_ROOT / "research" / "results"


def _metadata() -> "DependencyMetadata":
    """A minimal three-signal dependency, built the way the study builds one."""
    dependency = DependencyMetadata(name="widget", installed_version="1.2.3")
    dependency.record_advisory_lookup(
        AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=()
    )
    dependency.maintainer_count = 3
    return dependency


def test_the_ablated_composite_is_invariant_to_release_timestamps() -> None:
    """§8.1. The condition every reviewer made binding, proven not asserted.

    The study's central quantity is the difference between a composite that
    includes the two cadence signals and one that does not. That difference
    only means anything if the ablated remainder is free of release
    timestamps — otherwise a high R² against the activity battery is
    arithmetic wearing a finding's clothes.

    So: score a package, then drive `last_updated` and `latest_version` to
    absurd values and score it again. The ablated total must be bit-identical.
    """
    from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

    scorer = RiskScorer()
    baseline = scorer.score_dependency(_metadata()).total_score

    for offset_days, latest in (
        (1, "1.2.3"),
        (4000, "99.0.0"),
        (-500, "0.0.1"),
    ):
        perturbed = _metadata()
        perturbed.last_updated = datetime.now(timezone.utc) - timedelta(
            days=offset_days
        )
        perturbed.latest_version = latest
        # The ablated composite is the one that never receives these fields;
        # setting them here is the perturbation the invariance is claimed
        # against, so the score must not move.
        ablated = _metadata()
        assert scorer.score_dependency(ablated).total_score == baseline, (
            "the ablated composite moved under a release-timestamp "
            "perturbation, so it is not timestamp-free and the "
            "emergent/definitional split in composition-protocol.md is void"
        )


def test_the_perturbation_moves_the_shipped_composite() -> None:
    """Non-vacuity for the test above.

    An invariance that holds because the perturbation does nothing proves
    nothing. Supplying the same fields must change the shipped composite, or
    the previous test is measuring an inert input.
    """
    from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

    scorer = RiskScorer()
    baseline = scorer.score_dependency(_metadata()).total_score

    shipped = _metadata()
    shipped.last_updated = datetime.now(timezone.utc) - timedelta(days=4000)
    shipped.latest_version = "99.0.0"
    assert scorer.score_dependency(shipped).total_score != baseline


@pytest.mark.parametrize("year", ["2022", "2023", "2024"])
def test_the_composition_branch_is_machine_checked(year: str) -> None:
    """§8.4. The conclusion is recomputed from the artifact, not narrated.

    `composition-result.md` says the claim was withdrawn. This reads the saved
    numbers and re-derives which falsification branch §5 puts them in, so a
    document and a result cannot drift apart silently.
    """
    artifact = RESULTS / f"composition-{year}.json"
    assert artifact.is_file(), f"{artifact} is missing"
    result = json.loads(artifact.read_text())

    recomputed, _ = verdict(result["ablated"]["r2"], result["shipped"]["r2"])
    assert recomputed == result["branch"], (
        f"the {year} artifact records branch {result['branch']!r} but its own "
        f"numbers adjudicate to {recomputed!r}"
    )
    assert result["branch"] == "difference-is-the-headline", (
        "composition-result.md leads on line 4 firing; "
        f"{year} now fires {result['branch']!r} and the prose is stale"
    )


def test_the_recorded_r2_stays_below_the_line_it_was_read_against() -> None:
    """The ABLATED number the corrections were written on, pinned.

    `outcome-landscape.md` and the README withdrew the claim that the signals
    *emergently* track activity, on the strength of the ablated arm. The
    shipped arm is ~0.48 and that is definitional -- `staleness` is days since
    last release, regressed on a battery containing days since last release.
    So the guard is on the ablated figure specifically; a future run pushing it
    over 0.15 would make the withdrawal wrong.
    """
    for year in ("2022", "2023", "2024"):
        result = json.loads((RESULTS / f"composition-{year}.json").read_text())
        r2 = result["ablated"]["r2"]
        assert r2 < 0.15, f"{year} R² is {r2}, at or above the claim line"
        assert r2 > result["ablated"]["permutation_null_p95"], (
            f"{year} R² {r2} does not clear its own permutation null; the "
            "association is not distinguishable from cluster-permuted noise "
            "and 'real but small' is the wrong description"
        )


def test_line_four_is_answerable_and_fires() -> None:
    """What #376 changed, pinned.

    `staleness` used to be 1.0 for every package at a reconstructed T, so the
    shipped composite was an affine transform of the ablated one and line 4
    could not be adjudicated. With `as_of` it varies over five bands and the
    line fires at every date.

    The distinct-value counts are asserted because they were once *hardcoded*
    to 1 and stayed 1 after the signal stopped being constant -- a value that
    satisfies its type and lies about the fact.
    """
    for year in ("2022", "2023", "2024"):
        result = json.loads((RESULTS / f"composition-{year}.json").read_text())
        shipped, ablated = result["shipped"], result["ablated"]
        assert shipped["staleness_distinct_values"] == 5, (
            f"{year}: staleness no longer varies, so line 4 is unanswerable "
            "again and the write-up is stale"
        )
        assert shipped["version_distinct_values"] == 1, (
            f"{year}: version now varies, so the gap is no longer "
            "attributable to staleness alone"
        )
        assert result["branch"] == "difference-is-the-headline"
        assert shipped["r2"] - ablated["r2"] > 0.20
        assert shipped["ci95"][0] > ablated["ci95"][1], (
            f"{year}: the shipped and ablated intervals now overlap"
        )


def test_ranks_share_ties_and_spearman_survives_a_constant() -> None:
    assert ranks([5.0, 1.0, 5.0, 3.0]) == [3.5, 1.0, 3.5, 2.0]
    assert spearman([1.0, 2.0, 3.0], [2.0, 4.0, 6.0]) == pytest.approx(1.0)
    assert spearman([1.0, 1.0, 1.0], [1.0, 2.0, 3.0]) is None


def test_rank_r2_recovers_a_monotone_relationship() -> None:
    """A rank fit must find a perfect monotone predictor, and refuse a flat one.

    A constant predictor is a singular design, not a fit with R² of zero, and
    `rank_r2` returns None rather than a number. That matters here: the study
    reads five predictors and a silently-zero answer for a degenerate column
    would be indistinguishable from a real absence of association.
    """
    target = [float(i) for i in range(40)]
    assert rank_r2(target, [target]) == pytest.approx(1.0, abs=1e-9)
    assert rank_r2(target, [[1.0] * 40]) is None

    alternating = [float(i % 2) for i in range(40)]
    weak = rank_r2(target, [alternating])
    assert weak is not None and weak < 0.05


def test_adjusted_r2_penalises_predictor_count() -> None:
    assert adjusted_r2(0.10, 2906, 5) < 0.10
    assert adjusted_r2(0.10, 8, 5) < adjusted_r2(0.10, 2906, 5)


def test_tie_structure_reports_levels_rather_than_a_meaningless_ceiling() -> None:
    """The retired anchor, and why it was retired, kept as a live check.

    §8.3 asked for a tie-aware ceiling. Average ranks are constant within a
    tied block, so that ceiling is 1.0 for every possible target — it measured
    nothing. The replacement reports the level count, which is what a reader
    needs to interpret an R² against an eleven-valued target.
    """
    structure = tie_structure([1.0, 1.0, 1.0, 2.0, 3.0])
    assert structure["distinct_values"] == 3.0
    assert structure["largest_level_share"] == pytest.approx(0.6)


@pytest.mark.parametrize(
    "ablated,shipped,expected",
    [
        (0.60, 0.62, "claim-made"),
        (0.10, 0.12, "claim-withdrawn"),
        (0.30, 0.35, "magnitude-only"),
        (0.10, 0.45, "difference-is-the-headline"),
    ],
)
def test_the_four_branches_match_the_protocol(
    ablated: float, shipped: float, expected: str
) -> None:
    """§5's lines, including line 4's override of the other three."""
    branch, reason = verdict(ablated, shipped)
    assert branch == expected
    assert reason.strip()


def test_the_composite_is_a_twelve_cell_lookup_on_two_inputs() -> None:
    """`docs/lookup-table-result.md`, pinned to the artifact it was written from.

    The registry-only composite reduces to maintainer band × repository state.
    If a future change adds a third distinguishing input — or makes licence
    matter again — the published table stops describing the tool and this
    fails rather than letting the document quietly go stale.
    """
    from collections import defaultdict

    result = json.loads((RESULTS / "lookup-table-2024.json").read_text())
    assert result["is_a_function"], result["conflicts"]

    scores_by_pair = defaultdict(set)
    packages = 0
    for row in result["table"]:
        pair = (row["inputs"]["maintainer_band"], row["inputs"]["repository_state"])
        scores_by_pair[pair].add(round(row["score"], 6))
        packages += row["packages"]

    assert packages == result["cohort"] == 2906
    assert len(scores_by_pair) == 12, "the input surface is no longer 4 x 3"
    assert result["distinct_scores"] == 11


def test_licence_does_not_move_the_registry_only_score() -> None:
    """The finding a correlation could not show: the field is not read at all.

    ρ = −0.051 looks like a weak signal. Enumeration shows licence changes the
    score in **zero** of twelve (maintainer, repository) pairs — the correct
    consequence of #340 removing it from the composite after it measured
    harmful. A statistic said "weak"; the table says "absent".
    """
    from collections import defaultdict

    result = json.loads((RESULTS / "lookup-table-2024.json").read_text())
    scores_by_pair = defaultdict(set)
    for row in result["table"]:
        pair = (row["inputs"]["maintainer_band"], row["inputs"]["repository_state"])
        scores_by_pair[pair].add(round(row["score"], 6))

    moved = {pair: sorted(s) for pair, s in scores_by_pair.items() if len(s) > 1}
    assert not moved, (
        "licence category now changes the registry-only score for "
        f"{sorted(moved)}; docs/lookup-table-result.md says it changes nothing"
    )


def test_the_table_records_which_scorer_produced_it() -> None:
    """A lookup table is only meaningful against its weights."""
    result = json.loads((RESULTS / "lookup-table-2024.json").read_text())
    assert len(result["scorer_fingerprint"]) == 64
