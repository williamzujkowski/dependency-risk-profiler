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

## Falsification lines — fixed now

These are chosen before data collection. If any is met, the stated change happens.

1. **If full-model AUC does not exceed the best single trivial baseline by
   ≥ 0.05 with non-overlapping 95% CIs**, the "predicts risk" claim is removed
   from the README and the tool describes itself as a heuristic hygiene
   checklist. This is the primary line.
2. **If model L does not beat model G**, the comparative claim — "leading beats
   lagging" — is withdrawn regardless of how L performs against the baselines.
3. **If the HIGH bucket's 12-month advisory rate is < 2× the base rate**, the
   0.25/0.5/0.75 thresholds lose their severity labels.
4. **Any signal whose ablation moves AUC by < 0.005** loses its bespoke weight
   and is either dropped or folded in at parity.

A result meeting any of these is a **successful** outcome for this protocol.
Finding it ourselves is much cheaper than a reader finding it.

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
