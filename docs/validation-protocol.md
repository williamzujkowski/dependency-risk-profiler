# Validation protocol

**Status: pre-registered. Written before any data was collected.**

This document fixes, in advance, what would count as evidence for and against this
tool's central claim. It exists because a falsification line chosen after seeing
results is not a falsification line.

Nothing in this repository has ever tested whether the risk score predicts
anything. Sixteen signals, weights summing to 3.5, thresholds at 0.25/0.5/0.75 —
none derived from evidence. #242 found the weights had an emergent property
nobody chose: `exploit` was structurally incapable of crossing the first
threshold alone. That was discovered by arithmetic, which means nobody had ever
checked what the weights do.

## The claim under test

> Leading indicators — release cadence, maintainer concentration, provenance,
> version drift — predict dependency risk **better than** lagging ones such as
> CVE counts.

Note "better than". This is a **comparative** claim, and testing it requires the
lagging signal to be able to win.

## Design

### What this protocol corrects

An earlier draft proposed sampling only packages with **zero** advisories at time
T, arguing that any discrimination must therefore come from leading indicators.
That is invalid, and the flaw is worth recording because it is seductive:
selecting on zero advisories removes all *variance* in the lagging signal, so
lagging cannot lose. It was excluded, not defeated. Such a design licenses only
"leading indicators carry some signal" — a weaker claim than the product makes.

### Primary experiment — head-to-head, on a cohort with lagging variance

Sample packages at time T **without** conditioning on advisory history, so prior
advisory count and recency vary across the cohort. Fit three predictors of the
same future outcome:

| model | features |
|---|---|
| **L** | leading indicators only |
| **G** | lagging only — prior advisory count, recency of most recent advisory |
| **C** | combined |

The claim is supported only if **L beats G** on held-out discrimination. If C
beats both and L does not beat G, the honest product claim is "leading
indicators add to CVE history", not "leading beats lagging".

### Outcome

Primary: **an advisory published after T that affects a version available at T.**

Window: 12 months. Labels are defined against a **frozen OSV snapshot**, pinned
by checksum.

### Secondary outcomes

- **`MAL-*` advisory arrival** — malicious-package findings. These arrive from
  compromise rather than audit attention, so they carry much less scrutiny
  confound than ordinary vulnerability disclosure. Lower frequency; reported
  separately, never pooled.
- **Maintainer handover**, where reliably dateable. This is the actual mechanism
  in `event-stream` and `ua-parser-js`. Recorded where recoverable; not primary,
  because reconstructability is unproven.

### Abandonment is not a primary outcome, and the reason is circularity

Abandonment — no release for N years after prior activity — is attractive: it is
frequent, consumer-relevant, computable from immutable timestamps, and free of
scrutiny confound. It is also **nearly tautological** for this scorer: release
cadence is one of the sixteen signals, so "low cadence predicts future absence of
releases" is close to predicting a variable from itself.

It is therefore run as a **labelled appendix with cadence and drift ablated from
the model**. The question that remains genuinely open is whether *maintainer
concentration and provenance* predict abandonment — that is not circular, and it
is worth knowing.

## Confounding: does this measure risk, or attention?

Advisory arrival is a product of latent weakness **and** scrutiny. Popular
packages are audited more, and popularity is itself one of the sixteen signals.
Unmitigated, the headline result could be "popular packages get CVEs filed
against them", which download count alone would also predict.

Mitigations, all required:

1. **Stratify by download decile** and report discrimination *within* strata. If
   the score separates only across strata, it has rediscovered download counts.
2. **Report the model with popularity-derived signals excluded**, alongside the
   full model.
3. Treat **downloads-alone as the null hypothesis to beat**, not a footnote.

One asymmetry is worth stating because it cuts in our favour and should not be
used to excuse a null result: several leading indicators — abandonment, low
cadence, single maintainer — correlate with *low* popularity and therefore *low*
scrutiny. The confound biases **against** the thesis. A positive result survives
the objection; a null result stays ambiguous.

## Comparisons that must be run

1. **Base rate.** What fraction of the cohort acquires an advisory in 12 months.
   Everything is measured as lift over this.
2. **Trivial baselines**, each alone: download count, package age, dependency
   count, star count.
3. **Per-signal ablation.** Drop each of the sixteen, re-measure. This is the
   only honest route to justifying weights.
4. **Negative control.** Shuffle labels; AUC must collapse to ~0.5. This is a
   self-test of the harness, and it runs in CI.

Report **discrimination** (AUC, precision-recall at the operating thresholds) and
**calibration** (does the HIGH bucket actually contain more future-advisory
packages than MEDIUM).

## Statistical hazards, named in advance

- **Label censoring.** Advisories are published late. A package that looks clean
  at T+12mo in today's snapshot may acquire an advisory in 2027 covering versions
  available at T. Labels are therefore **lower bounds**, and the protocol says so
  in every result table.
- **Non-independence.** Multiple (package, T) pairs from one package, and
  packages sharing a maintainer or monorepo, inflate significance. Use **one T
  per package**, and clustered bootstrap confidence intervals.
- **Leakage.** Only information available at T may enter a feature. Advisory
  *publication* dates define the label; affected-range backfill must never be
  used to establish "clean at T", or the future leaks into the past.
- **Born-malicious packages** are excluded: a typosquat that was never legitimate
  has no at-risk state at T.

Two more, added after they were hit rather than anticipated. Both are recorded
here because both were invisible in the statistics anyone would check first.

- **Counting rows is not a power analysis.** Report the **effective** number of
  independent events beside the nominal one, always, and gate on the effective
  count. This has now bitten three times. The compromise backtest had 2,074
  dated cases arriving on **43 campaign-days** — it cleared a raw-count bar and
  died on the effective one, and the estimate it was designed against was wrong
  by 5.7× because it extrapolated per-package from a 65-package sample that
  could not see concentration. A provenance measurement had 30 packages that
  decomposed to **3 victims**, 28 of them one owner in a four-minute burst. A
  study quoting the nominal count is not merely imprecise; it overstates
  confidence by whatever the clustering ratio happens to be.

- **Check what makes the outcome *observable*, not only how often it occurs.**
  Maintainer handover looked ideal — exactly reconstructable, base rate 14.5%,
  stable across three dates, ~180 events. It is **perfectly censored**: a
  maintainer change is only visible through a new release, so packages that
  published nothing after T showed **0 of 1,176**, and the censored set was
  *exactly* the abandonment positive class. Any cadence-correlated signal would
  have predicted it by construction. Nothing in the base rate, the stability
  across dates, or the event count showed this — it appears only when you
  condition on the mechanism that makes a positive recordable. Conditioning the
  cohort on that mechanism does not rescue it either; that selects on a
  variable downstream of the exposure.

## Stage 0 — validate the negative control before accepting the protocol

**A negative control must be shown to be non-degenerate on the actual cohort
before the protocol naming it is accepted.** Measure what fraction of the label
vector the permutation actually moves, and record it in the protocol.

This exists because a protocol was written without it and a study died on it.
The handover study pre-registered a control that shuffled labels *within
maintainer cluster*. On its cohort — 2,905 packages across 2,176 components,
1.33 members each — a within-cluster shuffle cannot move a label in a singleton
or in a component whose members already share one. **96.6% of labels survived
the shuffle.** The permutation was close to the identity, so the control
returned roughly the observed model AUC and fired the gate at 0.2449.

The failure mode is worse than a wasted study. Such a control **passes when the
model is weak and fires when the model is strong**, which is backwards, and
nothing about its output announces that.

The check costs one line and is available at design time. Not running it is the
same defect this repository keeps finding in its code — a bar written down with
nothing checking it — relocated into a protocol.

Two notes on doing it honestly:

- **A preservation rate computed on real labels is not outcome-free.** Cluster
  *structure* is knowable before any outcome contact; preservation is not. Run
  the check at design time on the cohort's structure, and treat any later
  diagnosis as data-contaminated for the purpose of amending a clause.
- **Report the control's null, not an assumption about it.** A permutation that
  preserves a covariate associated with the outcome does not have a null of
  0.5, and reading it against a [0.47, 0.53] band would be wrong.

## Falsification lines — fixed now

These are chosen before data collection. If any is met, the stated change happens.

1. **If full-model AUC does not exceed the best single trivial baseline by
   ≥ 0.05, by a paired DeLong test at alpha 0.05**, the "predicts risk" claim is
   removed from the README and the tool describes itself as a heuristic hygiene
   checklist. This is the primary line.

   The first version of this document said "with non-overlapping 95% CIs". That
   is the wrong test. Both models are scored on the **same** packages, so the
   comparison is paired and DeLong applies; treating the two AUCs as independent
   discards the pairing and is far more conservative than the question warrants.
   The cost of the error was not theoretical — see the power table below, where
   it nearly doubles the sample required.
2. **If model L does not beat model G**, the comparative claim — "leading beats
   lagging" — is withdrawn regardless of how L performs against the baselines.
3. **If the HIGH bucket's 12-month advisory rate is < 2× the base rate**, the
   0.25/0.5/0.75 thresholds lose their severity labels.
4. **Any signal whose ablation moves AUC by < 0.005** loses its bespoke weight
   and is either dropped or folded in at parity.

A result meeting any of these is a **successful** outcome for this protocol.
Finding it ourselves is much cheaper than a reader finding it.

## Power, against the measured base rate

Feasibility (#312) measured the advisory-arrival base rate at **1.56%** and
abandonment at **15.05%**. Those numbers decide whether the falsification lines
above are reachable at all, so the arithmetic is here rather than assumed.

Positives needed to detect the 0.05 AUC delta, assuming a model AUC of 0.70
(Hanley–McNeil standard error):

| outcome | test | positives | packages to sample |
|---|---|---:|---:|
| advisory arrival (1.56%) | non-overlapping independent CIs | ~549 | **~35,200** |
| advisory arrival (1.56%) | **paired DeLong** | ~286 | **~18,300** |
| abandonment (15.05%) | paired DeLong | ~301 | **~2,000** |

Three things follow.

**The paired test is not a nicety.** It halves the harvest. Requiring independent
CIs not to overlap would have cost ~17,000 extra packages to answer the same
question no more reliably.

**The primary outcome is expensive but reachable.** ~18,300 packages is well
within what npm and PyPI hold; the binding constraint is API rate limits and
clone time, not availability. That is a scheduling problem, not a feasibility
one, and it must be budgeted before the harvest starts rather than discovered
partway through.

**The best-powered outcome is the partly-circular one**, which is an awkward but
useful fact. Abandonment needs ~2,000 packages — a ninth of the advisory
harvest — because its base rate is ten times higher. So the abandonment
appendix, with cadence and drift ablated, is now the **pilot**: it is cheap,
well-powered, and it exercises every stage of the harness end to end before the
expensive harvest is attempted. It cannot settle the primary claim, and it is
not permitted to be reported as if it could.

Revised staging, replacing the order given below:

1. Feasibility. **Done — #312.**
2. **Abandonment pilot**, ~2,000 packages, cadence and drift ablated. Proves the
   harness and answers whether maintainer concentration and provenance predict
   anything at all.
3. Trivial baselines on that pilot. **Stop and report if they cannot be beaten.**
4. Advisory-arrival harvest, ~18,300 packages, only if stage 3 justifies the cost.
5. Head-to-head L vs G vs C, ablations, negative control throughout.

## Scope honesty

Roughly half the sixteen signals derive from the source repository. If a signal
cannot be reconstructed as of T, it cannot be ablated, and **the experiment then
validates a different scorer than the one shipped.**

Therefore: whatever subset proves reconstructable, the resulting claim is
labelled with that subset. A validation of eight registry-derived signals is not
a validation of sixteen, and will not be described as one. Feasibility is
measured before the experiment runs, not asserted.

## Prior art to read before building

- Zahan et al. (2023) on correlating OpenSSF Scorecard checks with vulnerability
  outcomes — closest existing work; read before designing features.
- OSV.dev bulk dumps — dated advisory labels.
- deps.dev, ecosyste.ms — cross-ecosystem release and advisory joins.
- GH Archive — event-level repository history, which makes more repo-derived
  signals reconstructable than first assumed.

Use them. A bespoke scraper where a public dataset exists is the wrong rung.

## Staging, with a stop rule

Each stage produces a checkable artifact, and the run **halts** if a stage fails
its own gate:

1. Feasibility: per-signal reconstructability, achievable sample size, base rate.
2. Cohort construction against a pinned snapshot.
3. Trivial baselines. **Stop and report if the baselines cannot be beaten** —
   that is a complete result.
4. Full model, head-to-head L vs G vs C.
5. Ablations.
6. Negative control, run throughout as a harness self-test.
