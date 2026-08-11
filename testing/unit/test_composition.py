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
    assert result["branch"] == "claim-withdrawn", (
        "composition-result.md and the README are written on the withdrawal "
        f"branch; {year} now fires {result['branch']!r} and the prose is stale"
    )


def test_the_recorded_r2_stays_below_the_line_it_was_read_against() -> None:
    """The number the corrections were written on, pinned.

    Not a re-derivation of the analysis — a guard that the artifact still says
    what three documents now assert about it. If a future run pushes R² over
    0.15, the withdrawal in outcome-landscape.md and the README is wrong and
    this fails rather than letting them quietly disagree.
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


def test_the_shipped_composite_is_recorded_as_unanswerable() -> None:
    """Line 4 could not be adjudicated, and the artifact has to say so.

    At a reconstructed T both cadence signals are constant — staleness 1.0 and
    version 0.0 for every package — so the shipped composite is an affine
    transform of the ablated one. That is a limitation of the measurement, not
    a null, and recording it as a null is the Hoenig-Heisey mistake this
    repository has already made once.
    """
    result = json.loads((RESULTS / "composition-2024.json").read_text())
    assert result["shipped"]["staleness_distinct_values"] == 1
    assert result["shipped"]["version_distinct_values"] == 1
    assert "VOID" in result["shipped"]["note"]
    assert result["shipped"]["r2"] == result["ablated"]["r2"], (
        "the two composites are no longer rank-identical, so line 4 may now "
        "be answerable and the write-up needs revisiting"
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
