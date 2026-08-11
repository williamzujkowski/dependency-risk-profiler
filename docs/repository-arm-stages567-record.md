# Repository arm — stages 5, 6 and 7

**Registers against:** `repository-arm-protocol.md`, including §12 (amendment 1).
**Run:** 2026-08-11, seed 20260811, 2,000 maintainer-clustered bootstrap
resamples throughout. Stage 4 was re-run first and reproduced bit-identically,
so nothing below rests on a changed pipeline.

**The pair is the answer, and neither half is promoted.** §12 fixed that before
any score existed, and it turned out to matter more than it looked:

| population | n | clusters | positives | registry-only | + repository | delta | clustered 95% |
|---|---:|---:|---:|---:|---:|---:|---|
| **download-reported, within stratum** (primary) | 979 | 849 | 401 | 0.5617 | 0.6211 | **+0.0594** | **[+0.0014, +0.1138]** |
| **the whole arm, unstratified** | 1,869 | 1,348 | 742 | 0.6134 | 0.6217 | **+0.0082** | [−0.1207, +0.1150] |

The within-stratum figure describes **download-reported packages, not the
cohort**. The unstratified figure covers the arm and controls for nothing.

---

## Falsification lines

| line | fired? | on what |
|---|---|---|
| 1 — repo arm exceeds registry-only by ≥0.05 within stratum, interval off zero | **no** | +0.0594, [+0.0014, +0.1138], p = 0.045 |
| 2 — negative control not clean | no | stage 4: within-bin 0.5013, global 0.4992 |
| 3 — one signal carries the whole effect | **no**, by the rule; **but see below** | `community_activity` alone supplies 111% of the composite |
| 4 — effect unstratified but not within stratum | **no** | the pattern is the *reverse*, and it is a population effect |

Line 1 not firing is the study's nominal positive. Four things below are why
that sentence needs every qualifier it has.

---

## Stage 5 — the paired baseline

The comparator is **not** the published 0.577. That figure is the full cohort;
this arm is the 1,869 packages whose repository still resolves, which §6
establishes is survivorship-selected. Re-measured on the arm's own packages:

| statistic | population | n / clusters | AUC | bootstrap SE |
|---|---|---:|---:|---:|
| mean within-bin AUC | download-reported | 979 / 849 | **0.5617** | 0.0166 |
| pooled AUC | the whole arm | 1,869 / 1,348 | **0.6134** | 0.0174 |
| pooled AUC | download-reported | 979 / 849 | 0.5905 | — |

Both baselines run **above** their full-cohort counterparts (0.539 and 0.577),
which is what conditioning on a surviving repository predicts and the reason
§9 forbids the cross-population comparison.

**The registry-only arm scores two signals: `maintainer` and
`source_repository`.** `license` is measured but never enters `weighted_scores`,
and `staleness`/`version` are ablated by the abandonment protocol. It takes
**five distinct values** across all 1,869 packages, against 99 for the
repository arm. A comparison between a five-valued predictor and a
ninety-nine-valued one is not only a comparison of information content.

---

## Stage 6 — head-to-head

### The realised correlation, and the MDE it selects

| | |
|---|---|
| realised ρ between arms (clustered resamples) | **0.186** |
| published MDE row it selects | **independent (worst case), 0.0623** |
| MDE at the realised ρ on §12's published SE 0.0157 | 0.0561 |
| realised SE, repository arm / registry arm | **0.0273** / 0.0166 |
| MDE at the realised ρ on the realised SE | **0.0976** |

**§12 expected ρ to be high and it is not.** "The arms are nested… so
independence is not merely unlikely, it is impossible, and ρ will be high" —
0.186 selects the worst-case row. Nesting constrains the *scores*, not the
resample-to-resample correlation of the two AUCs, and the repository arm's
finer score resolution moves it around under resampling far more than the
five-valued baseline moves. The study is therefore powered as if the arms were
independent, and its realised precision is worse still: the repository arm's SE
came in at 1.7× the pre-registered figure.

**The observed +0.0594 is below the MDE at the realised ρ and realised SE
(0.0976).** That does not retract line 1 — line 1 is a delta with an interval,
and both halves cleared. It does mean the study detected an effect smaller than
its own realised precision was powered to detect reliably, which is the
condition under which a just-significant estimate is most likely to be
overstated. **45 of 2,000 clustered resamples fell at or below zero.**

### Both readings, side by side

| comparison | population | n / clusters | delta | clustered 95% | p |
|---|---|---:|---:|---|---:|
| within stratum (**primary**) | download-reported | 979 / 849 | +0.0594 | [+0.0014, +0.1138] | 0.045 |
| pooled, same rows | download-reported | 979 / 849 | +0.0638 | [+0.0137, +0.1104] | 0.017 |
| pooled | the whole arm | 1,869 / 1,348 | +0.0082 | [−0.1207, +0.1150] | 0.746 |

Stratifying on downloads costs **0.004** of the delta. Changing population —
from the download-reported half to the whole arm — costs **0.056**, which is
the entire effect.

**So falsification line 4 does not fire, and the reason is worth more than the
verdict.** Line 4 exists because popularity was expected to be the confound
that manufactured a positive. It is not: within-stratum and unstratified agree
almost exactly *on the same rows*. What separates a result from a null here is
**which packages are in the analysis**, exactly as §12 predicted when it found
that the endpoint's support is 73% unscoped against a 65%-scoped cohort.

### The complement — descriptive, not pre-registered

Added after the two pre-registered figures disagreed, because §12 makes "is this
stratification or population?" the first question, and the population the
endpoint cannot see is where the answer is.

| rows | n | clusters | positives | registry-only | + repository | delta | clustered 95% |
|---|---:|---:|---:|---:|---:|---:|---|
| npm reports no download count | 890 | 578 | 341 | 0.6344 | 0.5710 | **−0.0634** | [−0.2523, +0.1510] |

On the half of the arm npm answers no download count for — almost entirely
scoped packages — **the repository block makes discrimination worse**. The
clustered interval spans zero on 578 clusters and the point estimate is not
resolvable at this size; the unclustered interval, which assumes an independence
the data does not have, is [−0.114, −0.012]. Taken with the +0.059 above, the
block's effect **changes sign with the population**, and the arm-wide +0.008 is
the average of two opposite things rather than a small effect.

No claim rests on this row. It is here because reporting +0.059 and +0.008
without it would leave a reader to guess at a difference that is measurable.

### Per bin

Every bin moves in the same direction, which is the one thing the primary has
unambiguously going for it.

| bin | downloads at T | n | clusters | base rate | registry-only | + repository | delta |
|---:|---|---:|---:|---:|---:|---:|---:|
| 1 | 2 – 83 | 195 | 187 | 0.687 | 0.5595 | 0.6246 | +0.0651 |
| 2 | 83 – 237 | 195 | 182 | 0.421 | 0.5776 | 0.5887 | +0.0110 |
| 3 | 239 – 1,354 | 195 | 190 | 0.374 | 0.5281 | 0.5565 | +0.0284 |
| 4 | 1,388 – 13,643 | 195 | 184 | 0.323 | 0.5749 | 0.6826 | +0.1077 |
| 5 | 14,934 – 199,959,655 | 199 | 156 | 0.246 | 0.5683 | 0.6533 | +0.0850 |

---

## Stage 7 — ablations, per signal, **descriptive secondary**

§4d: no claim rests on the best of five. Both directions are reported because
they disagree, and the disagreement is the information. Ablation is absence —
the input is withheld, the shipped scorer reports the signal unmeasured and
renormalises. **Five signals, not six**: `community_popularity` is unmeasured
(stage 3), and `signed_commits` and `branch_protection` were unevaluable at any
past date before the study began.

### Within download stratum — 979 packages, 849 clusters, 401 positives

| signal | add-one-in | clustered 95% | leave-one-out | clustered 95% |
|---|---:|---|---:|---|
| `community_activity` | **+0.0658** | [+0.0345, +0.0937] | +0.0263 | [+0.0146, +0.0385] |
| `maintained` | +0.0376 | [+0.0003, +0.0695] | +0.0153 | [+0.0064, +0.0261] |
| `health_indicators` | +0.0243 | [+0.0007, +0.0469] | +0.0045 | [−0.0074, +0.0155] |
| `dependency_update` | −0.0069 | [−0.0455, +0.0281] | −0.0102 | [−0.0235, +0.0027] |
| `security_policy` | −0.0132 | [−0.0547, +0.0212] | −0.0059 | [−0.0169, +0.0055] |

*(composite for reference: +0.0594)*

**`community_activity` alone supplies 111% of what the five-signal block
supplies.** Its leave-one-out is only +0.026 because `maintained` is a partial
substitute — both are commit activity at T under different thresholds. The two
document-presence signals, `security_policy` and `dependency_update`, have
negative point estimates in both directions: the block is better without them.

Line 3's rule — a signal supplies ≥0.8 of the composite *and* costs ≥0.8 when
removed — does not fire, because no single signal is irreplaceable. That is a
rule outcome, not an acquittal. **The block's entire measured effect is
commit-activity-derived**, and the composite framing spreads it across five
signals of which two subtract.

### Unstratified over the arm — 1,869 packages, 1,348 clusters, 742 positives

Line 3 is reported **not evaluable** here: the composite delta is +0.008, so
the share-of-effect ratios have a denominator near zero and produce values like
6.55 and −5.71 that mean nothing. That guard was added after the first run
produced exactly those ratios; it moves the rule strictly toward claiming less,
and the ordering is recorded rather than smoothed over.

| signal | add-one-in | clustered 95% | leave-one-out | clustered 95% |
|---|---:|---|---:|---|
| `community_activity` | +0.0539 | [+0.0070, +0.0970] | +0.0214 | [+0.0128, +0.0312] |
| `health_indicators` | +0.0316 | [+0.0185, +0.0451] | +0.0023 | [−0.0046, +0.0080] |
| `maintained` | +0.0089 | [−0.0704, +0.0771] | +0.0102 | [+0.0024, +0.0200] |
| `dependency_update` | −0.0376 | [−0.1190, +0.0318] | −0.0115 | [−0.0202, −0.0019] |
| `security_policy` | −0.0470 | [−0.1454, +0.0301] | −0.0135 | [−0.0404, +0.0097] |

The same ordering survives the population change even though the composite does:
commit activity up, documents down. The composite is near zero here because the
positive and negative components roughly cancel across 1,869 packages.

---

## Two problems in the protocol, found by running it

### 1. §10's pre-registered interpretation rests on a premise that is false

§10 anticipates the autocorrelation hazard exactly — "commit activity at T
predicting no-releases-by-T+2y is the same latent construct measured twice" —
and then disarms it:

> the paired registry baseline already contains release recency, so an
> improvement over it is improvement beyond cadence

**It does not contain release recency.** `staleness` and `version` are ablated
by the abandonment protocol, for the good reason that release cadence cannot
predict the absence of releases without circularity. The paired baseline scores
`maintainer` and `source_repository`. So the mitigation §10 relies on is not
present, and the signal that carries the whole effect — `community_activity`,
with `maintained` as its partial substitute — is commit cadence.

**The measurement stands; the interpretation attached to it does not.** What
this run supports is: *commit activity in the six months before T predicts the
absence of npm releases in the two years after T, on download-reported packages,
beyond what maintainer count and a repository declaration predict.* It does not
support "improvement beyond cadence", and it must not be written up that way.
This needs an amendment or a correction before anything is claimed from it.

### 2. §12's stated support is 981/850/402; the realised support is 979/849/401

Stage 4 recorded 979/849/401 for the same rows, and this run reproduces that
exactly. Amendment 1 states 981/850/402. Two packages and one cluster, which
moves no conclusion — the MDE is read off the published SE regardless — but a
pre-registered count that does not match the artifact should be reconciled
rather than left as a discrepancy someone finds later.

Separately, reconstructing §12's MDE table from the SE as published (0.0157,
three significant figures) lands one unit low in the last digit on three of the
four rows. The table was computed on the unrounded SE, ≈0.015724. The published
rows are treated as authoritative and carried verbatim.

---

## What this licenses, and what it does not

- **On download-reported packages** — 73% unscoped, 979 of them across 849
  maintainer clusters — the repository block adds 0.059 to within-stratum AUC
  over a registry baseline that scores maintainer count and a repository
  declaration. The interval excludes zero by 0.0014.
- **On the arm as a whole** — 1,869 packages, 1,348 clusters — it adds 0.008 and
  the interval spans zero. On the 890 packages npm reports no downloads for, it
  subtracts 0.063.
- **The effect is commit activity.** Not five repository signals; two
  cadence-derived ones, of which one is nearly sufficient, plus two that
  subtract.
- **The withdrawn README claim (#330) stays withdrawn.** §12 pre-committed that
  under every branch of this study, and nothing here is a rehabilitation of the
  composite: the arm that won is the registry composite plus a repository block,
  measured on a survivorship-selected subset of one ecosystem at one T, against
  one outcome.
- **Every figure is conditional on survival.** §6's measurement bounds the bias
  rather than showing it absent: resolvable 39.68% against unresolvable 43.98%,
  clustered interval [−0.185, +0.096] on 191 packages.

## Sizes, everywhere

| population | nominal n | maintainer clusters | positives | largest cluster |
|---|---:|---:|---:|---:|
| the arm | 1,869 | 1,348 | 742 | 127 |
| download-reported (the endpoint's support) | 979 | 849 | 401 | 25 |
| npm reports no download count | 890 | 578 | 341 | — |

The 127-package cluster is why the whole-arm intervals are so much wider than
the support's: a clustered bootstrap resamples whole components, and one
component that size dominates the variance of anything it appears in.

## Verification

Suite **2,706 passed, 7 skipped**, coverage 85.68% against an 82.5% floor.
`mypy src research` clean over 118 files. `bandit` **1.8.6** via the system
binary — version printed, because a missing tool prints nothing and reads
exactly like a pass — reporting 14 low and 2 medium, identical to the count on
`main` before this branch; the four new modules contribute none.

Stage 4 re-ran bit-identically before stages 5-7 executed, and stage 6 produced
byte-identical output across two runs.

## Storage

No clone was fetched: `signals.json` carries every per-repository read, and the
6.3 GB of bare blobless clones from stage 2 remain deleted. The worktree is
`/tmp/drp-ra57` on branch `research/repo-arm-stages567`; a scratch copy of the
artifact directory used to rehearse the runs lives under the session scratchpad
and is not part of the record.
