# Does the composite add anything to download count? — result

**Protocol:** `additive-value-protocol.md`, amended at §9 after a 4-3 review.
**Registers:** #382.
**Verdict: absent.** Reweighting is not worth doing.

---

## The numbers

Out of fold, maintainer-clustered 5-fold CV, 1,414 npm packages with a
published download count, 609 abandoned, T = 2024-08-01.

| arm | AUC | delta vs downloads | 95% CI | verdict |
|---|---:|---:|---|---|
| **downloads alone** | **0.6960** | — | — | the incumbent |
| composite alone | 0.5887 | −0.1072 | [−0.1419, −0.0722] | absent |
| composite + downloads | 0.6866 | −0.0094 | [−0.0199, +0.0004] | **absent** |
| **components + downloads** *(primary)* | 0.6846 | **−0.0114** | [−0.0246, +0.0010] | **absent** |

**The baseline reproduces the published 0.696 exactly**, which is the best
evidence available that the harness is doing what it says.

## What the verdict rests on

The primary arm's **minimum detectable delta is 0.0128** — below the 0.02
material threshold. So this study was powered to see a 0.02 improvement, and
the interval's upper bound sits at **+0.0010**, far under it. That is the
difference between *absent* and *indeterminate*, and it is why the strong
reading is licensed here.

Both combined models are very slightly **worse** than downloads alone out of
fold, which is what adding uninformative features to a model does.

**And the component coefficients are not sign-stable across folds** (§6 line
3). Freeing the weights entirely — the reweighting question asked directly —
produces coefficients that change sign depending on which maintainers are held
out. That is fitting the fold, not the data.

## What this answers

The question was whether backtesting could refine the weighting. It can, and
the answer is that **there is nothing to refine**:

- the frozen composite adds nothing to download count (−0.0094)
- **freeing all three weights adds nothing either** (−0.0114)

The second is the load-bearing one. §9 exists because a frozen sum can *cancel*
information its components carry, so a null on the aggregate alone would not
have licensed this. Fitting the components separately removes that escape: even
with the weights unconstrained and chosen by the data, the signals add no
discrimination over a number that costs one API call.

## What it does not license

Per §9, this is **measurement plus argument**, and the two are kept apart:

1. **Measured:** these three signals, reweighted freely, add nothing over
   download count among packages with a published download count.
2. **Argued:** the other signals cannot be evaluated against this outcome
   anyway — `staleness` and release cadence are tautological with respect to
   *"published nothing for two years"*, and `version` is 0.0 for every package
   at a single past T.

So the licensed claim is *"no reweighting that is evaluable against this
outcome is worth doing"* — **not** *"the shipped fifteen-signal composite has
no additive value"*. That remains untested and is what #385 exists for.

## A discrepancy worth stating

The composite alone scores **0.5887** here against the **0.577** published in
`abandonment-pilot.md`, on what should be the same 1,414 packages.

The likely cause is that `license` was removed from the composite in #340,
*after* that figure was published — so the composite being scored today is not
the composite that produced 0.577. The direction of the difference matches
(#340 removed a signal measured to be harmful, so the score should improve).
It is not chased further here because it does not touch the verdict: both
figures lose to 0.696 by a wide margin.

## The bug this nearly shipped

The first run reported the composite beating downloads by **+0.28**.

It was a polarity error in my own harness: every predictor here is oriented as
*risk*, higher meaning more likely abandoned, and **downloads run the other
way**. Unnegated, the baseline scored **0.3040 — exactly 1 − 0.696** — and
every arm appeared to beat it spectacularly.

The tell was arithmetic: a composite known to score 0.577 cannot beat a
baseline known to score 0.696 by any margin, let alone a quarter of an AUC. A
sign error in the comparator is how a study manufactures a triumphant positive
out of the one number it was supposed to lose to, and the only reason it was
caught is that the expected answer was already known.
