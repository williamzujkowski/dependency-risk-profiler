# Does the composite add anything to download count? — pre-registration

**Status:** pre-registered. Committed before any combination was fitted; the
order is checkable from git.
**Registers:** #382.
**Date fixed:** 2026-08-12, against `main` at 97de226.

---

## 0. The question this gates

Reweighting the composite was proposed. Before spending effort on weights,
there is a cheaper question that decides whether weights are worth touching at
all.

The composite loses to download count against abandonment — **0.577 against
0.696**, replicated at three dates. But the two are nearly **orthogonal**:
ρ(composite, log downloads) = **−0.295**, about 9% shared variance. A predictor
can be worse alone and still carry information the better one lacks.

**If the combination beats download count alone, the composite has additive
value and tuning its weights is worth doing. If it does not, no weighting
scheme will save it**, because the information is not there to reweight.

## 1. The claim under test

> Combining the composite with download count discriminates abandonment better
> than download count alone.

## 2. The combination, fixed now

**Logistic regression on two predictors**: the composite's normalised score,
and `log1p(downloads at T)`. Two parameters plus an intercept — chosen because
it is the smallest model that can express "these carry different information",
and because with three parameters over ~1,400 rows the overfitting room is
small enough to be checkable rather than argued about.

**No feature engineering, no interaction term, no third predictor.** Anything
that improves the fit by adding flexibility is exactly what a held-out
evaluation exists to catch, and adding it here would make the result about my
search rather than about the composite.

## 3. The composite stays ablated, and this is the whole game

The composite used is the **abandonment pilot's ablated arm** — `maintainer`,
`license`, `source_repository` — with `staleness` and `version` left unmeasured.

That is not a limitation, it is the point. `staleness` is *time since last
release* and the outcome is *published nothing for two years*. Including it
would improve the fit and the improvement would be a tautology. #376 made
`staleness` computable at a past date, which makes this temptation newly
available, and it is declined here on the record.

## 4. Population, and its known defect

The evaluation runs on the packages npm answered a download count for — **1,414
of 2,906**, which is where the 0.696 baseline lives.

That subset is **not random**: npm answers downloads for nearly every unscoped
package and about a fifth of scoped ones, so it is roughly 73% unscoped where
the cohort is 65% scoped. The repository arm measured an effect that **reversed
sign** on the excluded half. So every figure here describes packages with a
published download count, and the write-up says so in the same sentence as the
number.

## 5. Method

- **Maintainer-clustered 5-fold cross-validation.** Folds split on maintainer
  component, never on rows: two packages from one maintainer either side of a
  fold boundary would let the model score something it has effectively seen.
- **Out-of-fold predictions only.** The AUC is computed on predictions the
  model did not train on.
- **Maintainer-clustered paired bootstrap**, 2,000 resamples, for the delta
  against download count alone.
- **Repeated at T = 2022-08-01, 2023-08-01, 2024-08-01**, which are the same
  packages at three moments rather than three cohorts, and are reported as
  such.
- Seeded; two runs produce identical numbers.

## 6. Falsification lines — fixed now

1. **If the combined model does not exceed download count alone by ≥0.02 AUC**,
   with the clustered paired interval excluding zero, the claim is not made and
   **the reweighting work is not worth doing** — that conclusion is recorded as
   the answer to the question that prompted this.
2. **If the combined model does not exceed the composite alone**, something is
   wrong with the fit rather than with the composite, and nothing is reported
   until it is found.
3. **If the fitted coefficient on the composite is not stable in sign across
   all five folds and all three dates**, the additive value is reported as
   unstable regardless of the AUC, because a coefficient that changes sign is
   fitting the fold rather than the data.
4. **If out-of-fold AUC exceeds in-sample AUC**, the harness is wrong and the
   run is discarded.

## 7. What a confirmation licenses

*Among npm packages with a published download count, adding the composite to
download count improves discrimination of two-year abandonment by this much,
out of fold.*

It does **not** license "the tool works" — the combination beating downloads
means the composite carries *some* information downloads lacks, not that the
shipped verdict is useful. And it says nothing about compromise, which remains
untested.

## 8. Named hazards

- **One ecosystem, one snapshot, one outcome.** Same limits as every study
  here.
- **Three dates are not three cohorts.** Same packages, three moments.
- **A positive result would still be measured against a baseline that is
  free.** Download count costs one API call; the composite costs a clone and a
  dozen lookups. Beating it by 0.02 is a different proposition from being worth
  the cost, and the write-up will not conflate them.

---

## 9. Amendment: the frozen aggregate cannot answer the reweighting question

Reviewed **4-3, below supermajority — rejected**. Four defects, all adopted.
The first is the one that would have made the whole study answer a different
question than the one asked.

### The aggregate hides exactly what reweighting would recover

Falsification line 1 concluded, from a null on the **frozen-weight composite**,
that *"no weighting scheme saves it"*. **That inference is invalid.** A
fixed-weight sum can *cancel* information its components carry — two signals
with opposite-signed relationships to the outcome subtract inside the sum and
vanish from the aggregate. **Reweighting is precisely the operation that
recovers cancelled information**, so a null on the aggregate cannot rule it
out.

And the direct test costs almost nothing. The ablated arm has **three**
signals, so a model on `{maintainer, license, source_repository,
log1p(downloads)}` is five parameters against the three proposed — no new
flexibility, the same cross-validation, and it **is** the reweighting question
rather than a proxy for it.

This is sharpened by a result from this repository's own enumeration:
`license` moves the composite in **zero of twelve cells**. So the frozen
aggregate is effectively a two-signal score, and testing *it* specifically
cannot detect information the frozen weights already discard.

**The primary arm is now the component model.** The frozen aggregate is kept as
a secondary, because the gap between them is itself the measurement — it is how
much the current weighting throws away.

### A null must not launder an underpowered result into a decision

Line 1 collapsed "failed to show ≥0.02" into "the reweighting work is not worth
doing" — absence of evidence read as evidence of absence. **The verdict is now
three-way**, decided by the clustered paired interval:

- **additive** — interval excludes zero and the point estimate is ≥0.02
- **absent** — the interval's **upper bound** falls below 0.02
- **indeterminate** — the interval spans both, which licenses only *"not shown
  here"* and explicitly does **not** license stopping the reweighting work

The minimum detectable delta implied by the bootstrap is reported beside every
result, so a reader can see which of the three the study was ever able to
return.

### What a null binds, stated as measurement plus argument

A null on the three reconstructable signals does not *measure* anything about
the fifteen-signal shipped composite. What licenses the wider reading is a
two-part structure, and it is written as two parts rather than one fact:

1. **Measured:** these three signals, reweighted freely, add nothing over
   download count.
2. **Argued:** the excluded signals cannot be evaluated against this outcome
   anyway — `staleness` and release cadence are tautological with respect to
   "published nothing for two years", and `version` is 0.0 for every package at
   a single past T.

So a null licenses *"no reweighting that is evaluable against this outcome is
worth doing"* — not *"the shipped composite has no additive value"*.

### Line 4 was not a valid check and is replaced

"Out-of-fold AUC exceeds in-sample AUC → the harness is wrong" is false as
stated: logistic regression optimises log loss rather than AUC, and sampling
variation alone can produce it on a small model. It is replaced by assertions
that actually catch a broken harness — **no maintainer component spans two
folds, every row is predicted exactly once and only out of fold, and two runs
under the same seed are identical.**

### Refused, on the record

A stratified secondary. The conditional-information worry is real, but the
downstream action being gated is **reweighting, a linear operation** — so
information that exists only inside a download stratum is information no
reweighting scheme could capture. Running a free-form stratification after
seeing a null is the flexibility this protocol exists to refuse.
