# What does the composite measure? — pre-registration

**Status:** pre-registered, reviewed 5-2 under supermajority, and revised
against the review's binding conditions in §8. Fixed before any number was
computed.
**Registers:** #375.
**Date fixed:** 2026-08-11, against `main` at 3748993.

---

## 0. Why this is not a sixth outcome

`outcome-landscape.md` is closed. Five outcomes were attempted; four were
coupled to the signals and the one that was not is unmeasurable. No sixth is
proposed, and this is not one.

**This study has no outcome at all.** It asks what the composite score *is*,
not what it predicts. Nothing here needs a label, a window, a base rate or a
fresh cohort, so the four requirements that killed the outcome programme do not
apply — there is nothing for the signals to be coupled *to*.

That is the point. The project's standing conclusion is:

> the signals may detect project **activity** rather than risk, and the
> outcomes they appeared to predict were activity in disguise

and every document that states it also admits it is an **inference from a
pattern across studies rather than a measured quantity**. It rests on: release
cadence alone scoring 0.7340 against abandonment, above every figure the tool
produced; and the composite landing at 0.4955 against the one outcome measured
independent of activity.

That is suggestive and it is not a measurement. The composite's association
with activity can be measured **directly**, on data already pinned, offline,
today. If the conclusion is going to be published it should be published as a
number.

## 1. The claim under test

> The composite risk score is substantially a function of how recently and how
> often a package published.

Falsifiable in both directions, and the directions are not symmetric in what
they cost the project:

- **Confirmed** — the tool's description has to change. "Risk score" becomes a
  claim it cannot support, and the honest label is closer to "publication
  activity index".
- **Refuted** — the project's own headline conclusion is wrong, and the real
  finding is the harder one #349 gestured at: the composite measures something
  largely orthogonal to the obvious proxies and *still* barely predicts
  anything. That is worse news, not better.

## 2. Two composites, because one of them is definitional

The shipped scorer includes `staleness` (time since last release) and `version`
(drift from latest). **Those are cadence in another notation**, so a shipped
composite loading on activity is partly true by construction and partly not.
The abandonment pilot ablated both, precisely because predicting "published
nothing for two years" from "time since last publication" is circular.

Both are measured and reported side by side:

| composite | what it is |
|---|---|
| **shipped** | every signal the registry-only run measures, `staleness` and `version` included. What a user actually gets |
| **ablated** | `staleness` and `version` left unmeasured, exactly as the abandonment pilot ablates them |

**The difference between the two is the quantity of interest.** It is how much
of the shipped score's activity loading is definitional rather than emergent,
and nobody has ever measured it. Reporting only one number would let a reader
take a tautology for a finding, or dismiss a real association as one.

## 3. The activity battery, fixed now

Registry-observable, as of T, from the pinned snapshot. No repository is
cloned; no network is opened.

| measure | definition at T |
|---|---|
| `days_since_last_release` | T minus the timestamp of the release in force at T |
| `releases_1y` | releases published in `(T − 1y, T]` |
| `releases_90d` | releases published in `(T − 90d, T]` |
| `releases_total` | releases published at any time up to T |
| `release_span_days` | first release to last release before T |

**`downloads_at_t` is not in the battery.** Popularity is not activity, ρ(model,
log downloads) is −0.295 (#349), and mixing them would let a popularity
association masquerade as an activity one. It is reported separately as a
contrast, never pooled.

## 4. Statistics, fixed now

- **Spearman ρ** for every pairwise association. The composite is bounded,
  lumpy and tie-heavy; a Pearson correlation on it would be reporting the
  shape of the bucketing.
- **R² of the composite on the battery**, computed on ranks, as the headline
  decomposition. Reported with the single strongest predictor's R² beside it,
  because a battery of five collinear activity measures will beat any one of
  them and the gap is the only interesting part.
- **Maintainer-clustered bootstrap** for every interval, 2,000 resamples.
  Packages from one maintainer are not independent, and this repository has had
  a DeLong interval come out 3.7× too narrow for exactly that reason.
- **Per-signal decomposition.** Each member signal's ρ against the battery,
  reported individually, so "the composite is activity" cannot hide one
  strongly-loading signal behind six neutral ones.

## 5. Falsification lines — fixed now

1. **Ablated composite R² ≥ 0.50 on the battery** → the claim in §1 is made:
   activity explains most of what the score varies on, and it is not
   definitional because the definitional signals are ablated.
2. **Ablated composite R² < 0.15** → the claim is **withdrawn**, and the
   project's headline conclusion is corrected in `outcome-landscape.md`,
   `validation-protocol.md` and the README in the same change.
3. **Between 0.15 and 0.50** → neither. Reported as a magnitude, with the
   interval, and the headline conclusion is softened to what the number
   supports rather than restated.
4. **If the shipped and ablated R² differ by more than 0.20**, the difference
   is reported as the headline rather than either level, because then the
   answer to "is the score activity" depends entirely on whether you count the
   two signals that are activity by definition.

## 6. What a confirmation would and would not license

It would license: *the composite is substantially a function of publication
activity*. Measured, on 2,906 packages, at one T.

It would **not** license *"the signals detect activity rather than risk"* — the
sentence the project has been circling. That sentence has two halves and this
study measures one. Whether the score fails to detect *risk* is an outcome
question, and the outcome programme is closed because those questions turned
out not to be answerable here. A composition study cannot reopen it and will
not be written up as though it had.

## 7. Named hazards

- **One T.** Composition could differ at another date. The abandonment
  replication at three dates found the model's own AUC drifting 0.605 → 0.567,
  so this is not hypothetical. Mitigated by repeating at T = 2022-08-01 and
  2023-08-01, which the pinned snapshot supports offline, and reporting all
  three.
- **`insufficient_data` is 79% of the cohort.** The scorer abstains on most
  registry-only packages, so the composite exists for a minority and that
  minority is not random. The analysed subset's size is reported beside every
  figure, and the battery is compared between the scored and abstained subsets
  so the selection is described rather than assumed away.
- **R² on ranks is not variance explained in the usual sense.** It is reported
  as what it is, and the Spearman matrix is published whole so a reader can
  disagree with the summary without re-running anything.

---

## 8. What the review changed, before anything ran

Approved 5-2 under supermajority. Both dissents and all five approvals named
the **same** blocking condition, so it is treated as binding rather than
advisory: *the estimand is undefined until the ablated remainder is proven
free of release timestamps.* All conditions below are adopted.

### 8.1 The provenance question, discharged mechanically

The registration asserted that ablating `staleness` and `version` removes the
definitional coupling. Asserting it is exactly the defect this repository keeps
finding, so it is now proven two ways.

**By audit.** `last_updated` and `latest_version` are read in exactly two
places that affect a score — `_calculate_staleness_score` and the version-drift
branch. The third read is in the human-readable risk-factor text and touches no
number. The ablated composite's three signals take their inputs from
`maintainers`, `license` and `repository`: fields of a version document, none
derived from `time`.

**By invariance test, which is the part that will still be true next year.**
`test_the_ablated_composite_is_invariant_to_release_timestamps` scores a
package, then rescores it with `last_updated` and `latest_version` driven to
absurd values, and requires the ablated score to be **bit-identical**. The
shipped composite must move under the same perturbation, so the test cannot
pass by measuring nothing.

If that invariance ever fails, the emergent/definitional split is void and this
protocol is void with it.

### 8.2 The abstention companion is mandatory, not an alternative

Three reviewers independently made the same point and it is sharper than the
original hazard note: **field completeness may itself be activity.** If active
packages answer more registry fields, then the composite's *existence* is an
activity function — and that is a larger finding than any R² on the minority
that gets scored.

So the abstention analysis runs as a required companion:

- the battery's distribution in the scored and abstained subsets, side by side
- rank-R² of *being scored* on the battery, with the same clustered bootstrap
- coverage reported per T

**Every reported figure carries its n and the qualifier "among packages the
tool scores".** No number in this study describes npm, or the cohort, or the
tool's users' dependency trees. It describes the ~21% where a score exists.

### 8.3 Thresholds get anchors instead of round numbers

0.50 and 0.15 stay — they were fixed in advance and moving them now is exactly
the laundering this project has refused twice. But they are uninterpretable
alone, so three anchors are reported beside them:

- **A maintainer-clustered permutation null.** Shuffle the battery-to-composite
  linkage across clusters, 2,000 rounds. Chance rank-R² with five predictors at
  n ≈ 600 is on the order of 0.01, which is what makes 0.15 a floor rather than
  a decoration — but it is measured rather than asserted.
- **The tie-aware ceiling.** A bounded, lumpy, tie-heavy composite mechanically
  depresses rank-R², so the achievable maximum is not 1.0. Estimated by
  regressing the composite on *itself* discretised to its observed tie
  structure. **0.50 against a ceiling of 0.6 means something very different
  from 0.50 against 1.0**, and without this the thresholds cannot be read.
- **Single-predictor baselines and out-of-sample R².** Each battery member
  alone, and the full battery under maintainer-grouped 5-fold cross-validation,
  so in-sample optimism from five collinear predictors is visible rather than
  absorbed into the headline.

### 8.4 Reproducibility, because a branch adjudication has to be re-runnable

The bootstrap and permutation seeds are fixed in the analysis module. Two runs
of the same code on the same snapshot produce byte-identical results, and
`test_the_composition_branch_is_machine_checked` reads the results artifact and
asserts which falsification branch fired — so the conclusion is computed from
the numbers rather than narrated beside them.

### 8.5 What did not change

The two-composite design, the scope limit, the exclusion of downloads from the
battery, and the three thresholds. On the 79% abstention the panel's position
was that conditioning on scored is the **correct** estimand — the composite
does not exist elsewhere, and users only ever see emitted scores — provided the
selection direction is measured rather than assumed. §8.2 is that measurement.

---

## 9. A correction to the analysis population, made before any R² was computed

Running the scorer over the cohort to build the two composites — before any
association was measured — turned up something the registration assumed wrongly.

**The ablated composite abstains on 100% of the cohort.** All 2,906 packages
come back `insufficient_data`. Three measured signals against thirteen
unexplained unknowns never clears the scorer's sufficiency bar, so a
registry-only run restricted to signals reconstructable at a past date issues
**no verdict at all, ever**.

**The shipped composite abstains on 73.9%** — 759 of 2,906 scored. That is the
~21%-scored figure the project has been carrying, and it belongs to the shipped
variant.

So the difference between the two composites is not only a difference in what
the score *is*. It is the difference between a tool that answers and a tool
that refuses. **The two signals that are activity by definition are the only
reason a verdict is ever issued.**

### What changes

§8.2's "among packages the tool scores" cannot be the primary population,
because for the ablated composite that set is empty. The primary population is
**every cohort member**, using the composite value the scorer computes — which
exists whether or not the verdict is suppressed, and is exactly what the
abandonment pilot analysed for the same reason.

The abstention analysis stays mandatory and gets sharper: it now reports the
abstention rate for *both* composites and the rank-R² of being-scored on the
battery for the shipped one, where the question is answerable.

**No threshold moves and no falsification line changes.** This is a correction
to which rows are analysed, forced by a fact about the scorer, recorded before
any association was looked at. The order matters and is checkable from git: the
composites were built in one commit and the R² computed in the next.

### One more fact worth fixing in advance

The composite takes **11 distinct values across 2,906 packages**. That is
extreme tie density, and it is precisely why §8.3's tie-aware ceiling is not a
formality: with eleven levels the achievable rank-R² is capped well below 1.0,
and reading 0.50 against 1.0 would be a category error.
