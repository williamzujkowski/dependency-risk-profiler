# Repository arm — pre-registration

**Status:** pre-registered and **revised once before any clone**, against a 7-0
consensus review that carried substantive conditions. The largest: the primary
control was mismatched to the primary endpoint. Revisions listed in §11.
**Registers:** #339. Fourth protocol, after abandonment (ran),
compromise (halted stage 1) and handover (halted stage 3).
**Date fixed:** 2026-08-11, against `main` at 08678db.

---

## 0. Control validity — checked first, because the last study died here

`validation-protocol.md` now requires a negative control to be shown
non-degenerate on the actual cohort **before the protocol naming it is
accepted**. The handover study pre-registered a within-cluster shuffle that
preserved 96.6% of labels, so it returned roughly the observed model AUC and
fired its own gate for the wrong reason.

Two controls are specified, and which is primary matters more than it looks.

### The secondary check: a global permutation

The abandonment pilot has already exercised one **on this cohort and this
outcome**, at every date:

| T | shuffled mean | min | max | rounds |
|---|---:|---:|---:|---:|
| 2022-08-01 | 0.4984 | 0.4692 | 0.5230 | 200 |
| 2023-08-01 | 0.5001 | 0.4639 | 0.5258 | 200 |
| 2024-08-01 | **0.4992** | 0.4669 | 0.5284 | 200 |

All three straddle 0.5 symmetrically and sit inside [0.47, 0.53].

*A first draft of this section cited 0.5007 — that figure is the handover
agent's global permutation on the* handover *outcome, not this one. Corrected
before acceptance. Both support the same conclusion, but a pre-registration
citing a control run against a different outcome is the kind of imprecision
that makes the rest of it worth less.*

**It is not a within-cluster shuffle**, deliberately: this cohort's maintainer
components average 1.33 members, which is what made the handover control
degenerate.

### Why that is not the primary control

Consensus review caught this and it is the most useful thing the review
produced. **The primary endpoint is within-download-stratum AUC, and a global
permutation destroys the popularity–outcome association too** — so it validates
the AUC machinery while being structurally unable to detect popularity leakage,
the exact confound falsification line 4 exists for. The null must match the
estimand.

### The primary control: a within-download-bin permutation

Validated here before acceptance, on this cohort and outcome:

| | |
|---|---|
| rounds | 200 |
| **mean** | **0.4988** |
| min / max | 0.4595 / 0.5433 |
| label preservation | **0.566** |
| band | inside [0.47, 0.53] — **passes** |

It genuinely permutes (0.566, against the handover control's degenerate 0.966)
and it preserves the popularity structure, so it tests whether the repository
signals discriminate *beyond bin membership*.

The global permutation is retained as a **secondary sanity check** on the
pipeline, not as the gate.

Clustered *intervals* still use maintainer clusters. Permuting and clustering
the bootstrap are different things; the handover protocol conflated them.

---

## 1. What this tests

**Eight of sixteen signals have never been in any arm.** All eight are
repository-derived: `health_indicators`, `security_policy`,
`dependency_update`, `community_activity`, `maintained`,
`community_popularity`, `signed_commits`, `branch_protection`.

Everything measured so far tested three, of which one carried information, one
was actively harmful and has since been removed, and one did nothing. **This is
the last untested block, and it is half the model.**

The outcome is **abandonment** — unchanged, and deliberately so. It is the only
outcome that has cleared all three requirements in `outcome-landscape.md`, and
inventing a fourth would repeat the last two failures.

## 2. The claim under test

> Adding the repository-derived signals to the registry-only composite improves
> its discrimination of two-year abandonment, **beyond what popularity already
> explains**.

## 3. The bar is 0.539, not 0.577

The headline registry-only figure is AUC 0.577 at T=2024. That is the wrong
target.

**About half the composite's discrimination is popularity.** Stratified into
five equal-size download bins, mean within-bin AUC is **0.539** — in
excess-over-chance terms 0.039 against 0.077 (#349). Any scanner already knows
download count, and gets that half for free.

**So the primary comparison is within-stratum**, and the headline unstratified
figure is reported alongside rather than instead.

**Expect these signals to be more popularity-entangled than the registry ones,
not less.** `community_popularity` *is* a star count. `community_activity`,
`maintained` and `health_indicators` all plausibly track project size. The
registry arm at least had the excuse that most of its signals were not
popularity-shaped.

## 4. Two signals cannot be tested, and that is a result

- **`signed_commits`** reads signature *validity*, which depends on keys that
  expire, rotate and get revoked. Measured: `git log --pretty=%G?` returns `E`
  — cannot check — for **80% of `requests` and 97% of `flask`** at 2022-01-01.
  Signature *presence* is recoverable; the signal is a boolean on validity, so
  as scored it is gone.
- **`branch_protection`** is current-state only. No historical API, no GH
  Archive event type. No proxy is proposed, because an unlabelled proxy is
  worse than an absence.

**They are reported as unevaluable at any past date, not as null.** Two of
sixteen signals being permanently untestable by this method belongs in
`docs/`, not only here.

Six remain: `health_indicators`, `security_policy`, `dependency_update`,
`community_activity`, `maintained`, `community_popularity`.

## 4b. Every signal must be reconstructable from git history alone

**A clone is a time machine for git history and for nothing else.** Any signal
sourced from a live API read — stars now, issue counts now, current contributor
lists, the archived flag — observes the post-outcome world and leaks.
`signed_commits` and `branch_protection` were binned as untestable on exactly
this ground; the same test applies to the remaining six, per signal, in
writing:

| signal | source at T | leaks? |
|---|---|---|
| `health_indicators` | `git ls-tree` at the last commit before T | no |
| `security_policy` | same | no |
| `dependency_update` | same | no |
| `community_activity` | `git log --since --before` | no |
| `maintained` | commit activity from `git log` | **the archived flag is current-state and is excluded**; that component is unmeasured and says so |
| `community_popularity` | GH Archive `WatchEvent` cumulative to T | no — but a **monotone upper bound**, see §5 |

**Any signal that cannot be computed from the clone plus GH Archive at T is
dropped, not proxied.** An unlabelled proxy is worse than an absence, which is
the same rule that excluded the other two.

## 4c. Power, stated before the run

The first draft proposed a 300–500 subsample on clone-cost grounds. **Review
was right that this hides an underpowered design**: split across five download
bins that is roughly 10–30 positives per bin, and a within-bin AUC at that
event count cannot distinguish 0.539 from a real improvement. A null would then
mean "underpowered", not "no effect" — which turns an honest halt culture into
a machine for producing unfalsifiable nulls.

**Partial clones remove the constraint.** `git clone --filter=blob:none --bare`
fetches commit and tree objects without file contents; `git ls-tree` and
`git log` — every method §5 relies on — work against it. That makes the **full
resolvable cohort (~1,874 packages)** affordable, which fixes the power problem
and eliminates subsample-selection risk in the same move.

**Minimum detectable effect, fixed now:** with the full cohort the primary
comparison is paired on the same packages, and the study is powered for the
0.05 within-stratum delta falsification line 1 names. **If the support of the
analysis producing the primary endpoint falls below 1,000, the MDE is computed
and published before that analysis runs**, and a null below that MDE is
reported as uninformative rather than as absence — the same rule §7 of the
handover protocol used.

*Amendment 1 rebound this clause from "the achieved cohort" to the primary
endpoint's support, and moved the MDE from "reported with the result" to
"published before the analysis". See §12.*

## 4d. One primary endpoint

Six signals plus a composite is seven chances for the strongest to masquerade
as the finding.

**The primary endpoint is the block composite**: registry-only against
registry-plus-repository, paired, within-stratum. Per-signal results are
**descriptive secondary** and are reported as such, with no claim resting on
the best of six.

## 5. Reconstruction

At the last commit before T, per #312's verified method:

- `health_indicators`, `security_policy`, `dependency_update` — `git ls-tree`.
  Verified exact on 4 repos × 11 dates.
- `community_activity` — `git log --since --before`.
- `maintained` — commit activity reconstructs; **the archived flag does not**,
  so that component is unmeasured and says so.
- `community_popularity` — no registry or API exposes historical stars. GH
  Archive `WatchEvent` from 2015. **It is a monotone upper bound**: GitHub
  emits an event for starring but not for un-starring, so a cumulative count
  can only overstate. Reported as approximate wherever it appears.

## 6. Coverage is a result, not a filter

A repo arm that silently studies only packages with readable repositories is
studying a different population.

Measured at T=2024 on this cohort: **73.3% declare a GitHub repository, 24.1%
declare none, 2.5% another host.** Separately, resolving those repositories
today, **192 of 2,066 were unresolvable** — mostly deleted or private.

**Report coverage as a headline number.** And note the direction of the bias:
a deleted repository plausibly correlates with abandonment, so the studied
subset is **not missing at random**, and every result is conditional on
having a repository somebody can still read.

**It is worse than not-missing-at-random: it is conditioning on post-outcome
state.** A repository still resolvable in 2026 survived the entire label
window, so the studied subset is mechanically less likely to be abandoned by
T+2y and its outcome variance is compressed.

**This is measurable, not merely admissible.** The outcome is registry-derived,
so it is computable for packages whose repository is *gone* as well.
**Report the abandonment rate in the resolvable and unresolvable subsets side
by side.** If they differ materially, every figure in the study is conditional
on survival and the write-up says so in the same table.

## 7. Falsification lines — fixed now

1. **If the repo arm does not exceed the registry-only arm by ≥0.05
   within-stratum**, on a maintainer-clustered paired bootstrap with the
   interval excluding zero, the repository signals are reported as adding
   nothing. Primary line.
2. **If the negative control is not clean** — global permutation, mean outside
   [0.47, 0.53] — nothing from the run is reported at all.
3. **If one signal carries the whole effect**, that is the finding, reported
   per-signal and not folded into a composite claim.
4. **If the effect exists unstratified but not within-stratum**, it is reported
   as a popularity effect. Explicitly, because that is the most likely way this
   produces a misleading positive.

## 8. What a null means — fixed now

A null means: **these six signals add nothing to abandonment prediction beyond
popularity, on npm, at this cohort size.**

It does *not* license "repository signals are worthless" — five ecosystems and
every other outcome are out of scope, and two of the eight were never testable.

The study is adequately powered for its primary line: ~2,900 packages, ~40%
base rate, and the registry-only comparison is a paired one on the same
packages. **A null here is informative** rather than an absence of evidence,
which is the property the compromise backtest lacked.

## 9. Staging, with stop rules

1. **Control validity** — §0. Done: within-bin permutation 0.4988, preservation
   0.566, on this cohort and outcome.
2. **Clone the full resolvable cohort**, `--filter=blob:none --bare`, hardened
   per §10. Gate: **stop if resolution is under 60%** — below that the studied
   population is too far from the cohort to generalise, and say so rather than
   proceeding. Report the abandonment rate in the resolvable and unresolvable
   subsets side by side (§6).
3. **Reconstruct the six signals** at the last commit before T. Gate: report
   per-signal measurement rates; a signal measured for under half the subsample
   is reported unmeasured rather than imputed.
4. **Negative control** on the assembled arm, before any model result.
5. **Registry-only baseline on the same subsample** — the paired comparator.
   Not the 0.577 headline, which is a different sample.
6. **Repo arm**, head-to-head, within-stratum primary.
7. **Ablations**, per signal.

Stage 5 matters and is easy to get wrong: the comparison must be **paired on
the same packages**, not against the published figure from the full cohort.

## 10. Named hazards

- **Popularity, again.** Half of what the registry arm had was popularity, and
  these signals are more entangled with it. Line 4 exists for this.
- **History rewriting.** `git log` at a past date assumes history was not
  rewritten. One confirmed case in #312, rate unmeasured.
- **Survivor bias in repositories**, per §6, and it is not missing at random.
- **`community_popularity` is an upper bound**, not an estimate.
- **Autocorrelation is not coupling, but it changes the claim.** Commit
  activity at T predicting no-releases-by-T+2y is the same latent construct
  measured twice. It is not mechanical coupling in the handover sense — the
  outcome is registry-derived and these signals are git-derived, which are
  independent sources — but a win may mean "current activity predicts future
  activity" rather than "risk beyond popularity." **Pre-registered
  interpretation:** the paired registry baseline already contains release
  recency, so an improvement over it is improvement beyond cadence; anything
  reported must say that rather than the broader thing.

- **The clones are hostile input.** This cohort is drawn from packages some of
  which are abandoned or compromised, and repository URLs come from
  package metadata an attacker controls. Fixed now: URLs are passed after a
  `--` separator (a URL beginning `--upload-pack=` is remote code execution
  otherwise), submodules are never initialised, clones are `--bare` so no
  working tree is written and symlink traversal is not reachable, and each
  clone is size- and time-capped against git bombs.

- **Clone cost.** `--filter=blob:none --bare` fetches no file contents, which
  is what makes the full cohort affordable (§4c). Caching exists
  (576s → 163s previously).

---

## 11. What the review changed

Circulated before any clone and approved 7-0 **with conditions**. All were
adopted. Recording them because a pre-registration that hides its revision
history is not one.

1. **The control was mismatched to the endpoint.** The draft used a global
   permutation. The primary endpoint is within-stratum, and a global
   permutation destroys the popularity–outcome association too, so it could
   never detect the confound falsification line 4 exists for. Replaced with a
   within-download-bin permutation, validated at 0.4988 with 0.566 preservation
   before acceptance. Global retained as a secondary pipeline check.
2. **Power was unstated and the subsample hid it.** 300–500 across five bins is
   10–30 positives per bin, where a null means "underpowered" rather than "no
   effect." Partial clones (`--filter=blob:none --bare`) make the full ~1,874
   resolvable cohort affordable, which fixes power and removes
   subsample-selection risk together. An MDE rule is now fixed for the case
   where the achieved cohort comes in small.
3. **Temporal leakage needed a per-signal assertion**, not a per-study one. §4b
   states the source for each of the six and drops `maintained`'s archived-flag
   component as current-state.
4. **Coverage bias is post-outcome conditioning**, not merely non-random — a
   repository resolvable in 2026 survived the label window. And it is
   measurable, because the outcome is registry-derived: §6 now requires
   reporting the abandonment rate in the resolvable and unresolvable subsets
   side by side.
5. **Multiplicity.** Six signals plus a composite is seven chances for the best
   to masquerade as the finding. One primary endpoint fixed: the block
   composite. Per-signal is descriptive secondary.
6. **Autocorrelation changes the claim even though it is not coupling.** The
   interpretation is pre-registered in §10.
7. **The clones are hostile input.** URL argument injection, submodules,
   symlink traversal and git bombs are all closed in §10.

**A first draft also cited the wrong control figure** — 0.5007, which is the
handover agent's global permutation on the *handover* outcome. Corrected before
acceptance to this cohort's own numbers.

**What did not change:** the outcome stays abandonment, and the two untestable
signals stay untestable and unproxied.

---

## 12. Amendment 1 — the MDE clause, and a selection problem it does not fix

**Made 2026-08-11, after stages 2–4 and before any model result exists.**
Stages 5–7 have not run: no AUC, no baseline, no ablations. 7-0 consensus.

### What was wrong with §4c

It bound the MDE rule to "the achieved cohort", which came in at **1,869** and
clears 1,000. But the primary endpoint is *within-download-stratum*, and npm
answers download counts for only about half the cohort, so **the endpoint's
support is 981** — below the line. The letter cleared; the thing the rule
exists to protect did not.

I wrote that clause loosely. Reading the letter to skip the MDE rule would have
been exploiting my own drafting.

**Why amending here is not the amendment that was rejected for the handover
study.** That one was proposed *after* the model AUC was observed and would have
**loosened** the interpretation. This one is made before any score exists and
can only make a future claim **weaker** — it downgrades a possible null from
"absence" to "uninformative" and leaves a positive result untouched. Direction
of hand-binding is the test, not timing alone, and the ordering is auditable in
git rather than asserted.

### The MDE, published before stage 5 runs

Computed on the endpoint's actual support by maintainer-clustered bootstrap,
600 resamples, seed 20260811:

| | |
|---|---|
| support | **981 packages, 850 clusters, 402 positives** |
| SE of the mean within-bin AUC | **0.0157** |

Minimum detectable paired difference, α = 0.05 two-sided, power 0.80:

| assumed correlation between arms | MDE |
|---|---:|
| independent (worst case) | 0.0623 |
| ρ = 0.5 | 0.0441 |
| ρ = 0.8 | 0.0279 |
| ρ = 0.9 | 0.0197 |

**The arms are nested** — the repository arm is the registry arm plus five
signals — so independence is not merely unlikely, it is impossible, and ρ will
be high. The study is powered for the 0.05 line at any ρ above roughly 0.36.

**Fixed now, before the number exists:** a null is reported as uninformative
only if the observed delta falls below the MDE computed at the *realised*
correlation, which is reported alongside it.

**And a pre-commitment that costs something:** "uninformative" means *this study
cannot speak*. It does **not** mean the composite survives. The withdrawn README
claim (#330) stays withdrawn under every branch of this study.

### The problem the MDE does not fix

Framing 981-of-1,869 as a power question was wrong. It is also, and more
seriously, **a selection question**:

| | n | abandonment rate | scoped |
|---|---:|---:|---:|
| has a download count at T | 1,414 | **0.431** [0.405, 0.457] | **27.2%** |
| npm reports none | 1,492 | **0.380** [0.356, 0.405] | **100%** |

npm answers download counts for **every unscoped package and only about a fifth
of scoped ones**. The excluded half is not a random half — it is *entirely
scoped*, and its abandonment rate is lower, with intervals that barely touch.

So the within-stratum endpoint describes a population that is **73% unscoped,
while the cohort is 65% scoped**. That is a different population, and no
increase in power addresses it.

**Fixed now:** the within-stratum result is reported as applying to
download-reported packages, not to the cohort, wherever it appears. The
unstratified comparison over the full arm is reported beside it as the figure
that covers the cohort but does not control for popularity. **Neither is
promoted to "the" answer**; the pair is the answer, and the gap between them is
information rather than an inconvenience.

This was found by consensus review asking what else moves when the support
shrinks. It is the third time in this project that a question about *counts*
turned out to be a question about *which population the counts describe*.
