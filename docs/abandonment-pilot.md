# Abandonment pilot — results

**Stage 2 of `docs/validation-protocol.md`. Epic #287, feasibility #312.**

**The result: the score does not beat the trivial baselines, and one baseline
beats it decisively.** Download count at T alone separates abandoned from
surviving packages at AUC 0.696. The tool's own score, with release cadence and
version drift ablated as the protocol requires, reaches 0.577 on the same
packages — **0.119 lower**, with a clustered 95% interval of [−0.155, −0.085]
that does not come near zero.
The protocol's stage 3 says to stop and report when the baselines cannot be
beaten. This is that report.

> **Labels are lower bounds.** Abandonment is observed over a closed two-year
> window. A package counted as abandoned here may publish again in 2027, so
> every rate below is a floor, and every comparison is between predictors
> measured against the same floor.

---

## What was run

| | |
|---|---|
| Ecosystem | npm |
| Snapshot | `research/data/npm-2026-08-06`, harvested 2026-08-06, five files pinned by SHA-256 |
| Name universe | 4,314,619 npm names (`all-the-package-names` 2.0.2524) |
| Sample | 60,000 names, `random.Random(20260806).sample` |
| T | 2024-08-01 |
| N | **2 years**, measured (below) |
| Cohort | **2,906 packages**, one T each |
| Base rate | **40.5%** abandoned (1,176 / 2,906) |
| Model | The shipped `RiskScorer` at shipped weights, driven with as-of-T inputs |
| Ablated | `staleness`, `version` — cadence and drift, per the protocol |

The cohort is packages that were *alive* at T: at least three releases, at
least a year old, and a release within the twelve months before T. Without that
last condition the outcome would be a restatement of pre-T cadence, which is
the variable the protocol ablates.

That eligibility rule is also the born-malicious exclusion, and it is stronger
than a blocklist would be. #312 measured a **median publish-history span of 35
days and one version** for npm `MAL-*` packages: a typosquat has no legitimate
at-risk state at T because it has no history before the attack. Three releases
spanning a year removes that class by construction, including the malicious
packages nobody has catalogued yet.

### Three deviations from the protocol, argued rather than taken

**1. npm, where the protocol's feasibility study recommended PyPI.** #312 §10
recommends PyPI for its cleaner timestamps. But the question this pilot exists
to answer is whether *maintainer concentration* predicts abandonment, and #312
§3 is unambiguous that maintainer history at a past date is **irrecoverable on
PyPI**: `ownership.roles` is current state stamped onto historical documents,
so `flask` 0.12 from 2017 returns the 2026 answer. Reading it at T would be
leakage, not measurement. npm freezes a `maintainers` array inside every version
document — 98.7% coverage over #312's sample — and is the only registry that
does. Running this on PyPI would have meant running it without the signal it is
about.

**2. A clustered paired bootstrap in place of DeLong.** The protocol names a
paired DeLong test and, four paragraphs earlier, requires clustered confidence
intervals because packages sharing a maintainer are not independent. Those two
requirements are in tension: DeLong's closed-form covariance is derived under
independent observations, so running it here would report an interval narrower
than the data supports — the exact error the clustering requirement exists to
prevent. The comparison is therefore resolved the way DeLong resolves it (both
models scored on the same packages, differences taken within package) with the
variance estimated by resampling **maintainer components**. The unclustered
resample, which reproduces DeLong's assumption, is reported beside it so the
cost of the clustering is visible rather than asserted. Clusters come from
connected components over shared maintainer accounts: 2,177 components over
2,906 packages, the largest holding 127.

This also removes the need for `scikit-learn`. AUC is the Mann-Whitney statistic
over midranks and average precision is a walk down a sorted list; neither is a
place a dependency buys correctness, and the resampling had to be hand-written
either way because no library implements a maintainer-clustered paired AUC
delta. `research/abandonment_pilot/stats.py` is stdlib.

**3. `transitive` is a baseline, not a model input.** npm freezes each version's
**direct** dependency list; the shipped scorer's transitive signal reads a
resolved closure. Feeding it a direct count would be scoring a different input
than production sends, so the count appears only as one of the four trivial
baselines. This narrows the model to three varying signals, and the scope-honesty
section of the protocol is what that narrowing is reported under.

---

## N = 2 years, and where the 2 comes from

N was not taken from convention. It is read off an actuarial life table of
release silences: of the packages that have already been quiet for N years, what
fraction publish again in the next twelve months. **N is the first whole year
where that resumption hazard falls below 10%** — the point at which silence has
stopped being a pause between releases and become a state.

The table is built from **36,420 sampled packages with two or more releases**,
not from the cohort, and that distinction turned out to matter more than
anything else in this section. Built on the cohort — which has to be alive at T,
so its silences are the ones that ended — the hazard plateaus near **40% out to
seven years**, and no whole year clears any sensible cutoff. That is a
measurement of the filter, not of npm. Selecting on activity and then measuring
how often activity resumes is the same circularity this pilot exists to avoid,
one level down, and the first version of this harness walked into it.

At T = 2024-08-01, over the unselected population:

| years of silence | silences at risk | resumed within 12 months | censored | hazard |
|---:|---:|---:|---:|---:|
| 0 | 575,728 | 546,034 | 6,401 | 0.954 |
| **1** | 23,293 | 2,587 | 3,641 | **0.121** |
| **2** | 17,065 | 700 | 2,970 | **0.045** |
| 3 | 13,395 | 263 | 2,722 | 0.022 |
| 4 | 10,410 | 89 | 2,515 | 0.010 |
| 5 | 7,806 | 32 | 2,209 | 0.005 |

Each package contributes one completed silence per consecutive release pair and
one **censored** silence — the stretch from its last release up to the cut-off,
which has not ended as far as the table can see. Omitting the censored ones
counts only silences that happened to end, which is the population that makes
abandonment look temporary.

One year of silence still leaves a 12% chance of a release in the next twelve
months. Two years leaves 4.5%. **N = 2**, and the same answer comes out at all
four candidate cut-off dates (2022, 2023, 2024, 2025), so it is a property of
how npm packages release rather than of where the cut fell. The conventional
two-year threshold turns out to be right; it is now also measured.

T follows from N: the label window has to be closed at harvest, so
T = 2024-08-01 and the window ends 2026-08-01, five days before the snapshot.

---

## What the model actually is

Of sixteen signals, **three vary across this cohort**:

| signal | measured for | note |
|---|---:|---|
| `maintainer` | 2,906 / 2,906 | Maintainer count frozen into the version document in force at T |
| `source_repository` | 2,906 / 2,906 | Declared / unusable / undeclared, from the same document |
| `license` | 2,695 / 2,906 | 211 packages declare no license at T |
| `deprecation` | 0 / 2,906 | Unmeasured. See below |

Everything else is unmeasured and drops out of both numerator and denominator,
which is the scorer's own rule.

**`deprecation` is unmeasured here, and saying so was once impossible.**
#312 found the underlying npm field is *unreconstructable* at a past date —
`deprecated` is applied retroactively to every version — so unmeasured is the
only honest answer. Until #320 the type could not express it:
`DependencyMetadata.is_deprecated` was a `bool` defaulting to `False`, so every
package here was scored with a confident "not deprecated". It is now
`Optional[bool]` defaulting to `None`, and this pilot records nothing, which is
how the fixed model spells "nobody looked".

What that cost, on this cohort: being constant, the fabricated value could not
change a ranking or an AUC — and did not, 0.5658 → 0.5665. It entered the
denominator, which pulled every absolute score toward zero and moved the
calibration buckets: LOW 2,144 → 882, MEDIUM 588 → 1,349, HIGH 174 → 496,
CRITICAL 0 → 179.

**Read those buckets with the abstention rate.** `insufficient_data` goes
2,303 → **2,906** — every package. With npm answering neither the advisory
question nor the deprecation one, a registry-only scan of this cohort declines
to score all of it. The four numbers above are where the thresholds land, not
verdicts the tool will publish.

**Recording `advisory_lookup_state` is load-bearing, and this pilot is how the
default was found pointing the wrong way.** It used to be optional, and leaving
it unset meant "the aggregator never ran" — in which state the scorer fell back
to `has_known_exploits`, whose default is `False`, so every package in a
registry-only run got a confident clean `0.0` at the tool's **largest single
weight**. It was defended as backward compatibility for offline conformance
runs; on a backtest it is plainly a fabricated measurement, and #321 removed
the option. The state is now required and validated at construction, so the
unset case this paragraph describes is unreachable.

Recording `NOT_ATTEMPTED` — what actually happened here — moved 174 packages
out of the LOW and MEDIUM buckets into HIGH. The first version of these results
had an empty HIGH bucket entirely, for that reason and no other.

**All 2,906 packages score `insufficient_data`.** A package that declares a
repository nobody read leaves eight repository-derived signals unmeasured with
no measured fact explaining the silence, and the scorer's own rule is that this
means it knows less about the package than it knows. That took 2,303 of 2,906 —
79% — over the bar on its own; #320 took the rest of the way, because once
`deprecation` stops answering a question npm cannot answer at a past date, the
four remaining registry signals no longer outnumber the unmeasured ones.
**The shipped tool abstains from a verdict on this entire cohort**, and it is
right to.
The discrimination below is computed from `total_score`, which is always
produced; the verdict buckets come from the same thresholds the scorer applies,
with the abstention reported rather than papered over.

---

## Discrimination

| | AUC | 95% CI (clustered) | average precision |
|---|---:|---|---:|
| Model, cadence and drift ablated | **0.566** | [0.536, 0.594] | 0.446 |

2,000 clustered bootstrap resamples over 2,177 maintainer components.

Base rate 40.5%, so average precision starts from 0.405 by chance.

At the tool's own operating thresholds, on the normalized score:

| threshold | flagged | precision | recall |
|---:|---:|---:|---:|
| 0.25 (MEDIUM) | 762 | 0.417 | 0.270 |
| 0.50 (HIGH) | 174 | 0.448 | 0.066 |
| 0.75 (CRITICAL) | 0 | — | 0.000 |

Precision at the HIGH threshold is 0.448 against a 0.405 base rate. Flagging
174 packages buys 7 percentage points of precision over flagging at random.

---

## Calibration

| bucket | packages | abandoned | rate | lift over base |
|---|---:|---:|---:|---:|
| LOW | 2,144 | 858 | 0.400 | 0.99× |
| MEDIUM | 588 | 240 | 0.408 | 1.01× |
| **HIGH** | 174 | 78 | **0.448** | **1.11×** |
| CRITICAL | 0 | — | — | — |

HIGH does contain more abandoned packages than MEDIUM, so the ordering is
right. The size of the gap is not: **the protocol's falsification line 3 requires
the HIGH bucket to carry at least 2× the base rate, and it carries 1.11×.** Under
that line, the 0.25/0.5/0.75 thresholds lose their severity labels.

No package in a 2,906-package cohort reaches CRITICAL. With cadence, drift and
every repository-derived signal unmeasured, the weighted mean cannot get there:
the three surviving signals do not carry enough weight between them.

---

## The trivial baselines, and the stop rule

Each baseline is compared on the packages where it exists, with the model
re-scored on the same subset — padding a missing baseline with zero would score
the packages it knows least about as the safest ones it knows. **Orientation is
taken from the data, which gives each baseline the better of its two possible
AUCs**; none of the four is a risk score, and the direction has to come from
somewhere, so it comes from the direction that makes the model's job harder.

| baseline | support | baseline AUC | model AUC on support | model − baseline | 95% CI (clustered) | p |
|---|---:|---:|---:|---:|---|---:|
| **downloads at T** | 1,414 | **0.696** | 0.577 | **−0.119** | [−0.155, −0.085] | 0.00 |
| stars today | 1,871 | 0.569 | 0.568 | −0.001 | [−0.130, +0.128] | 0.89 |
| package age at T | 2,906 | 0.551 | 0.566 | +0.015 | [−0.033, +0.058] | 0.55 |
| dependency count at T | 2,451 | 0.552 | 0.577 | +0.024 | [−0.033, +0.082] | 0.41 |

Every baseline runs in the same direction: **less is riskier** — fewer downloads,
fewer stars, younger, fewer dependencies. That is the opposite of the popularity
gradient for advisory arrival (#312 §8), and it is why abandonment was the
well-powered outcome to pilot on.

Read the table plainly:

- **Downloads at T beats the model by 0.119 AUC**, and the interval does not
  approach zero. The protocol's falsification line 1 asks whether the model
  exceeds the best trivial baseline by ≥ 0.05. It is 0.119 *behind*.
- **Against stars, it is a dead tie** — and the star baseline is *cheating*.
  GitHub publishes no historical stargazer series, so that column is stars
  **today**: it knows which of these projects went on to become popular, which
  is information from after T that the model does not have. The advantage was
  left in deliberately. Tying with a baseline that can see the future is not a
  result to round up.
- Against age and dependency count the model is nominally ahead by 0.015 and
  0.024, and both intervals span zero. Neither clears the protocol's 0.05 line
  and neither is distinguishable from no difference.

Clustering costs precision exactly where a few large maintainer components
dominate, and nowhere else. For downloads the two intervals are practically the
same ([−0.155, −0.085] clustered against [−0.152, −0.086] unclustered); for
stars the clustered interval is **3.7 times wider** ([−0.130, +0.128] against
[−0.035, +0.034]). Reported under DeLong's independence assumption, the star
comparison would look like a tight, confident tie. It is a tie held by very few
independent observations. That is the cost of taking non-independence
seriously, and it is why the protocol asked for it.

**The download baseline's support is not a random half of the cohort.**
`api.npmjs.org` throttles hard, and only its bulk form gets past that at volume
— and the bulk form rejects scoped names. So downloads are measured for **1,029
of 1,029 unscoped** cohort members and **385 of 1,877 scoped** ones. The
comparison above is therefore mostly a comparison on unscoped packages. Nothing
connects a name's shape to whether it is abandoned by any mechanism identified
here, but the support is structured rather than random and the result should be
read with that in mind.

### Within download strata

The protocol's first confound mitigation. If the model separates packages only
*across* popularity bands, it has rediscovered the download count.

| stratum | downloads at T | packages | base rate | model AUC |
|---:|---|---:|---:|---:|
| 1 | 2 – 74 | 282 | 0.709 | 0.560 |
| 2 | 75 – 208 | 282 | 0.496 | 0.544 |
| 3 | 208 – 693 | 282 | 0.429 | 0.534 |
| 4 | 693 – 6,411 | 282 | 0.262 | 0.489 |
| 5 | 6,438 – 199,959,655 | 286 | 0.259 | 0.572 |

The base rate falls from 71% to 26% across the strata, which is the download
baseline's whole result. Within strata the model holds a little discrimination
at both ends and none in the fourth band, which sits below chance. So it has not
*only* rediscovered download counts — but what it has beyond them is small, and
it is not stable across the range.

---

## Per-signal ablation

Each signal dropped in turn from the same production scorer; the ablated signal
becomes unmeasured and the weights renormalize over what remains.

| dropped | AUC without | AUC moved by | 95% CI (clustered) |
|---|---:|---:|---|
| `maintainer` | 0.488 | **+0.078** | [+0.055, +0.100] |
| `license` | 0.600 | **−0.034** | [−0.062, −0.013] |
| `source_repository` | 0.574 | −0.008 | [−0.026, +0.009] |

Three things, and the middle one is the surprising one.

**`maintainer` is the only signal carrying anything.** Remove it and the model
falls to 0.488 — below chance. Whatever discrimination there is, maintainer
concentration is where it comes from, and that is the protocol's open question:
does maintainer concentration predict abandonment when cadence cannot? Yes,
weakly — it is worth 0.078 of AUC. For scale, download count alone sits 0.196
above chance on its own support.

The concentration is real and lopsided: **1,701 of 2,906 packages have a single
maintainer at T**, which the scorer scores 1.0 — its maximum — so the signal is
close to a binary "is this one person's package".

**`license` is actively harmful.** Dropping it *raises* AUC from 0.566 to
0.600, and the interval excludes zero. The tool scores a missing or unrecognized
license as high risk; on this cohort, packages with unusual license strings are
if anything less likely to go quiet. The signal is not neutral noise, it is
pointed the wrong way for this outcome.

**`source_repository` moves 0.008, with an interval spanning zero.** The
protocol's falsification line 4 retires any signal whose ablation moves AUC by
less than 0.005; this is just above that, and indistinguishable from nothing.

Even the best of these — the model with `license` dropped, AUC 0.600 against
the download baseline's 0.696 — does not close the gap. And dropping a signal
because it happened to hurt on this cohort is a decision that would need its own
pre-registration before it counted as a result rather than as a fit.

---

## Negative control

Labels shuffled 200 times against the same scores, so the class balance, the
score distribution and the tie structure are all preserved and only the
association is destroyed.

| | |
|---|---|
| Observed AUC | 0.566 |
| Shuffled mean | **0.4993** |
| Shuffled range | 0.467 – 0.528 |

The observed AUC sits outside the shuffled range. The control runs in CI on the
pinned snapshot (`testing/unit/test_abandonment_pilot.py`), together with the
half of it that is easy to forget: a test that feeds the label in as a feature
and asserts the AUC goes to 1.0. Without that, a harness wired to a constant
0.5 would pass the shuffle test and look clean.

---

## What this pilot cannot show

- **Nothing about the primary claim.** The protocol says the abandonment
  appendix "cannot settle the primary claim, and it is not permitted to be
  reported as if it could". The primary outcome is advisory arrival, whose base
  rate is 1.56% and which needs ~18,300 packages. This is a 2,906-package
  cohort with a different outcome and an opposite popularity gradient.
- **Nothing about the thirteen ablated or unmeasurable signals.** Three signals
  varied. A result about three registry-derived signals is not a result about
  sixteen and is not described as one.
- **Nothing about compromise.** Abandonment is not a security event. A package
  that goes quiet is a maintenance risk; the tool's headline claim is about
  risk, and the two are related by argument rather than by this measurement.
- **Nothing about the repository arm.** No repository was cloned at T, so the
  eight repository-derived signals are absent — and their absence is most of
  why the whole cohort scores `insufficient_data`. A repository arm might do
  better. It would also cost a clone per package per T.
- **Nothing that survives the ecosystem.** npm is the only registry that
  publishes dated maintainer history. This result does not transfer to PyPI,
  crates.io, RubyGems, Packagist or Maven, where the signal at the centre of it
  cannot be reconstructed at all.
- **The cohort is the npm long tail.** Sampled uniformly from all 4.3M names, so
  the median cohort member has a few hundred downloads a month. A cohort of
  top-1000 packages would have a much lower base rate and might behave
  differently.
- **Labels are lower bounds**, and censoring is not symmetric: a package can be
  wrongly labelled abandoned and cannot be wrongly labelled surviving.

## Which falsification lines this meets

| line | verdict |
|---|---|
| **1** — full model must exceed the best trivial baseline by ≥ 0.05 | **Met (failed).** It is 0.119 behind download count at T, clustered CI [−0.155, −0.085]. |
| 2 — L must beat G | Not applicable. This pilot has no lagging arm. |
| **3** — HIGH bucket must carry ≥ 2× the base rate | **Met (failed).** HIGH carries 1.11×. |
| **4** — any signal whose ablation moves AUC < 0.005 loses its bespoke weight | **Met for `source_repository`** (0.008, CI spanning zero). `license` moves 0.034 in the wrong direction, which line 4 does not have a category for. |

Line 1 is the primary line, and the protocol states its consequence: the
"predicts risk" claim comes out of the README and the tool describes itself as a
heuristic hygiene checklist. That is a change to shipped documentation and is
**not** made in this change — the pilot is one outcome on one ecosystem, and the
protocol's line 1 is written against the advisory-arrival experiment. What this
result does establish is that the harness works, that stage 4's expensive
harvest now has a reason to be prioritized differently, and that at least one of
the sixteen signals is pointed the wrong way.

## Reproducing

Offline, from the pinned snapshot; see `research/README.md`.

```bash
PYTHONPATH=research uv run python -m abandonment_pilot.experiment \
    --snapshot research/data/npm-2026-08-06 \
    --out research/results/npm-2026-08-06.json
```

The loader verifies every file against its SHA-256 and refuses to run on a
snapshot that has drifted. Full numbers, including every bootstrap interval and
the complete life tables at all four candidate dates, are in
`research/results/npm-2026-08-06.json`.
