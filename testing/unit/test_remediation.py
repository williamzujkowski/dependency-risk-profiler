"""Guards for the CVE remediation study.

`docs/remediation-result.md`. Several of these exist because of corrections a
4-3 interpretation review forced: a unit error in the headline, a collapse
presented as a discovery when it was mechanically guaranteed, an overreached
CVSS null, and an untested time-at-risk confound.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

RESULTS = Path(__file__).resolve().parents[2] / "research" / "results"


def _features() -> List[Dict[str, Any]]:
    loaded: List[Dict[str, Any]] = json.loads(
        (RESULTS / "remediation-features.json").read_text()
    )
    return loaded


def _eval(name: str) -> Dict[str, Any]:
    loaded: Dict[str, Any] = json.loads((RESULTS / name).read_text())
    return loaded


def test_the_headline_carries_both_units() -> None:
    """The unit error the review caught.

    An earlier draft said "72% of packages", which is the ADVISORY-level
    figure. They differ by five points and the document now states both.
    """
    rows = _features()
    advisories_never = 1 - sum(r["published_after"] for r in rows) / len(rows)
    packages = {r["pkg"]: False for r in rows}
    for row in rows:
        if row["published_after"]:
            packages[row["pkg"]] = True
    packages_never = 1 - sum(packages.values()) / len(packages)

    assert advisories_never == pytest.approx(0.720, abs=5e-3)
    assert packages_never == pytest.approx(0.772, abs=5e-3)
    assert packages_never > advisories_never, (
        "the two units no longer differ, so the correction's premise is stale"
    )


def test_the_decomposition_identity_holds() -> None:
    """P(fixed) = P(publishes again) x P(fixes | publishes).

    This is how the write-up states the two stages' contributions, because it
    needs no comparison of AUCs across populations -- which is the move the
    review rejected.
    """
    rows = _features()
    p_publish = sum(r["published_after"] for r in rows) / len(rows)
    after = [r for r in rows if r["published_after"]]
    p_fix_given = sum(r["outcome_a"] for r in after) / len(after)
    p_fixed = sum(r["outcome_a"] for r in rows) / len(rows)
    assert p_publish * p_fix_given == pytest.approx(p_fixed, abs=1e-9)


def test_no_predictor_beats_067_on_the_actionable_question() -> None:
    """The operational claim, which is what survives the collapse debate.

    Against "this maintainer is still shipping, will they ship the patch?",
    nothing we measure exceeds 0.67 -- and that holds whether or not the
    collapse from outcome A is read as informative.
    """
    for artifact in ("remediation-eval.json", "remediation-eval-365.json"):
        block = _eval(artifact)
        block = block.get("B_prime", block)
        best = max(
            s["auc"] for s in block["predictors"].values() if s.get("auc") is not None
        )
        assert best < 0.70, f"{artifact}: a predictor now reaches {best}"


def test_repo_declared_is_the_predictor_that_does_not_collapse() -> None:
    """The differential that makes the liveness reading non-circular.

    The cadence predictors were always going to fall -- B' conditions on
    close to what they measure. `repo_declared` has no activity content and
    barely moves, and that contrast is the actual evidence.
    """
    both = _eval("remediation-eval.json")
    a = both["A"]["predictors"]["repo_declared"]["auc"]
    b = both["B_prime"]["predictors"]["repo_declared"]["auc"]
    assert abs(a - b) < 0.02, "repo_declared now collapses like the cadence signals"

    cadence = both["A"]["predictors"]["releases_prior_year"]["auc"]
    cadence_b = both["B_prime"]["predictors"]["releases_prior_year"]["auc"]
    assert cadence - cadence_b > 0.15, "the cadence collapse has gone"


def test_the_cvss_null_is_bounded_and_stays_bounded_under_the_window() -> None:
    """A complete-case null, not "CVSS does not predict patching".

    The interval includes chance, so nothing positive is detectable; its
    upper bound excludes a useful positive effect among vectored advisories.
    Both readings must survive the fixed-window rerun.
    """
    for artifact in ("remediation-eval.json", "remediation-eval-365.json"):
        block = _eval(artifact)
        block = block.get("B_prime", block)
        cvss = block["predictors"]["cvss"]
        low, high = cvss["ci95"]
        assert low < 0.5 < high, f"{artifact}: the CVSS interval no longer spans chance"
        assert high < 0.55, f"{artifact}: the upper bound no longer excludes a useful effect"


def test_age_survives_the_time_at_risk_confound() -> None:
    """The confound that would have explained age away, tested rather than argued.

    A floor of 12 months is not a window: older advisories have more time to
    accumulate a fix. Capping the outcome at a fixed 12 months must leave the
    association intact, or it was differential follow-up.
    """
    unwindowed = _eval("remediation-eval.json")["B_prime"]["predictors"]["age_days"]["auc"]
    windowed = _eval("remediation-eval-365.json")["predictors"]["age_days"]["auc"]
    assert abs(unwindowed - windowed) < 0.03, (
        "age_days moves under a fixed window, so the write-up's claim that the "
        "time-at-risk confound is ruled out no longer holds"
    )
    assert windowed > 0.60


def _downloads(name: str) -> Dict[str, int]:
    rows = json.loads((RESULTS / name).read_text())
    return {
        f"{r['pkg']}@{r['day']}": r["downloads"]
        for r in rows
        if r.get("downloads") is not None
    }


def test_the_downloads_windows_never_span_their_advisory() -> None:
    """The design property the whole follow-up rests on.

    A window that reached past the advisory would let the outcome inform its
    own predictor. Both harvests are keyed by the advisory date, and the near
    window ends the day BEFORE it while the far window ends 90 days before --
    so this asserts both files are keyed to real advisory dates in the cohort
    rather than to something else.
    """
    features = _features()
    keys = {f"{r['pkg']}@{r['published'][:10]}" for r in features}
    for name in (
        "remediation-downloads-near.json",
        "remediation-downloads-far.json",
    ):
        harvested = set(_downloads(name))
        assert harvested, f"{name} carries no resolved downloads"
        assert harvested <= keys, (
            f"{name} contains (package, date) pairs that are not advisories in "
            "the cohort, so the window anchor is wrong"
        )


def test_the_attrition_is_reported_because_it_is_outcome_correlated() -> None:
    """54 rows fail the join and they fix at a HIGHER rate than the joined ones.

    That is missing-not-at-random on the predictor being tested, so the
    write-up quotes a range rather than the complete-case point estimate. If
    the two rates ever converge the range is over-cautious and the doc should
    say so -- but silence would be worse than either.
    """
    rows = [r for r in _features() if r["published_after_excluding_fix"]]
    near = _downloads("remediation-downloads-near.json")
    joined = [r for r in rows if f"{r['pkg']}@{r['published'][:10]}" in near]
    unjoined = [r for r in rows if f"{r['pkg']}@{r['published'][:10]}" not in near]

    assert unjoined, "nothing fails the join any more; the range in the doc is stale"
    joined_rate = sum(r["outcome_a"] for r in joined) / len(joined)
    unjoined_rate = sum(r["outcome_a"] for r in unjoined) / len(unjoined)
    assert unjoined_rate > joined_rate, (
        "the unjoined rows no longer fix at a higher rate, so the "
        "worst-case floor-imputation bound is no longer the conservative end"
    )
