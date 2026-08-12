"""Guards for the additive-value test.

`docs/additive-value-result.md`. Two of these exist because of mistakes made
while building it: a polarity error that made the baseline score 1 - its true
AUC, and the §9 amendment that moved the primary arm from the frozen aggregate
to its components.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))

from additive.logistic import fit  # noqa: E402

RESULTS = Path(__file__).resolve().parents[2] / "research" / "results"


def _result() -> Dict[str, Any]:
    loaded: Dict[str, Any] = json.loads((RESULTS / "additive-2024.json").read_text())
    return loaded


def test_the_baseline_reproduces_the_published_auc() -> None:
    """0.696, independently published in abandonment-pilot.md.

    This is the harness's own check that it is measuring what it claims. It is
    also what caught the polarity bug: the baseline first scored 0.3040, which
    is exactly 1 - 0.696, because downloads were fed in unnegated while every
    other predictor is oriented as risk.
    """
    result = _result()
    assert result["auc"]["downloads"] == pytest.approx(0.696, abs=5e-3), (
        "the download baseline no longer reproduces the published 0.696; if it "
        "is near 0.304 the predictor's sign has flipped again"
    )


def test_freeing_the_weights_adds_nothing() -> None:
    """The primary arm, and the answer to the reweighting question.

    §9 moved the primary here from the frozen aggregate, because a fixed-weight
    sum can cancel information its components carry -- so a null on the
    aggregate alone would not have licensed a conclusion about reweighting.
    """
    primary = _result()["deltas"]["components+downloads"]
    assert primary["verdict"] == "absent"
    assert primary["delta_vs_downloads"] < 0
    assert primary["ci95"][1] < 0.02, (
        "the interval's upper bound now reaches the material threshold, so the "
        "verdict is indeterminate rather than absent and the write-up is stale"
    )


def test_the_study_was_powered_to_see_the_effect_it_looked_for() -> None:
    """Absent, not indeterminate -- and the difference is the whole claim.

    A null is only evidence of absence when the study could have seen the
    effect. The minimum detectable delta must sit below the 0.02 threshold, or
    "reweighting is not worth doing" is an underpowered null wearing a
    decision's clothes.
    """
    primary = _result()["deltas"]["components+downloads"]
    assert primary["minimum_detectable_delta"] < 0.02


def test_the_component_coefficients_are_recorded_as_unstable() -> None:
    """Sign instability across folds is itself the finding (§6 line 3)."""
    assert _result()["arms"]["components+downloads"]["signs_stable"] is False


def test_the_fit_recovers_a_known_relationship() -> None:
    """A positive control on the regression itself.

    A harness that always returns "no additive value" would pass every test
    above. This one feeds a predictor that genuinely separates the classes and
    requires the fit to find it, with the sign pointing the right way.
    """
    labels = [i % 2 == 0 for i in range(200)]
    informative = [1.0 if label else 0.0 for label in labels]
    noise = [float((i * 37) % 11) for i in range(200)]

    model = fit([informative, noise], labels)
    assert model is not None
    assert model.beta[1] > 0, "the fit missed a perfectly separating predictor"
    assert abs(model.beta[1]) > abs(model.beta[2]), (
        "the noise column carries more weight than the informative one"
    )


def test_the_fit_is_deterministic() -> None:
    """Two runs, identical coefficients -- a branch adjudication must re-run."""
    labels = [i % 3 == 0 for i in range(120)]
    column = [float(i % 7) for i in range(120)]
    first = fit([column], labels)
    second = fit([column], labels)
    assert first is not None and second is not None
    assert first.beta == second.beta
