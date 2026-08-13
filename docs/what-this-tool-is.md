# What this tool is, on the evidence

**Status:** the synthesis #382 asked for. Not a study — every number here is
measured elsewhere and cited. Written after ten studies, several of which
corrected earlier ones, including three that corrected each other within a
single day.

Read this first. The individual result documents are each defensible and
together they are an account that was not readable in one place.

---

## 1. The one-paragraph version

This tool inventories what is publicly knowable about a dependency and refuses
to guess when it cannot see something. That refusal is enforced by tests and is
its most defensible property. What it has **never** been shown to do is rank
dependencies by risk better than a popularity baseline: against every outcome
tried, download count beat it — including, as of this document, at the one end
of the scale that had looked like an exception. The one prospective test of the
shipped instrument is registered and its outcome is not readable until
**2027-08**.

---

## 2. What is established

| finding | where | strength |
|---|---|---|
| The composite loses to download count against 2-year abandonment, **0.577 vs 0.696** | `abandonment-pilot.md` | replicated at 3 dates |
| **77.2%** of npm packages carrying an unfixed advisory never publish again | `remediation-result.md` | 1,340 packages |
| Against *"given a live advisory, will this get patched?"*, **nothing computed exceeds AUC 0.67**; CVSS is indistinguishable from chance | `remediation-result.md` | 1,557 advisories |
| The verdict scale does not order above LOW; **CRITICAL is never the highest-risk bucket** | #344 | 7 runs |
| Six outcomes attempted; four mechanically coupled, one unobservable, one measured | `outcome-landscape.md` | closed |
| The composite is **not** an activity proxy (rank-R² 0.099) nor a popularity proxy (ρ −0.295) | `composition-result.md` | 3 dates, permutation-anchored |
| **88.4%** of packages can be scored downward; **83.5%** with no publish at all | `manipulation-result.md` | exact arithmetic |
| **41.51%** of declared weight is computed from a self-declared, unverified repository URL | `full-instrument-manipulation-result.md` | read from the scorer |
| The one lead-capable signal moves for 7.2% of quiet packages, at **half** the active rate, in a **directionless** split | `band-crossing-result.md` | 2,906 packuments |
| Finer maintainer bands recover only **1.58×** the movement; **17.6%** of changes are swaps invisible at every resolution | `granularity-result.md` | pre-registered tri-state |

### Measured on a uniform npm draw (the #385 cohort, n=2,000)

| | |
|---|---:|
| declares no repository at all | **42.45%** |
| declares one that does not resolve | 9.90% (17.2% of declarations) |
| **full-instrument yield** | **0.4640** |
| abstention, all registered signals measured | **0.0000** |
| distinct composite values | 235 |
| packages sharing the modal score | 25.6% |
| verdicts changed by the repository block | 685 of 932 (**73.5%**) |
| — of which raise risk | **667 : 18** |

---

## 3. The account these add up to

**The tool is much coarser than a five-point scale implies, and coarsest where
it can see least.** Over registry-only signals it enumerates to a twelve-cell
lookup on maintainer band × repository state. With a repository read it reaches
235 distinct values across 2,000 packages — real resolution, though a quarter of
any uniform draw still shares one number.

**It is not a proxy for the obvious things, and that is the problem.** It is
not activity (R² 0.099) and not popularity (ρ −0.295). It measures something
largely orthogonal to both, and *that something is what fails to predict*.
Adding more signals of the same family is not obviously the fix.

**Most of its weight rests on an input the scored party chooses.** 41.51% of
declared weight comes from a repository URL that nothing verifies — no owner
comparison, no reciprocal reference, no provenance check. This is how
repository-health scoring works generally; what is specific here is the
concentration.

**And that block penalises transparency.** Declaring a readable repository
changes the verdict for 73.5% of the packages it can read, and raises risk in
667 of 685. A package that shows its source is scored worse. Whether that is
*deserved* is precisely what the prospective study will answer.

**What works is the refusal to guess.** Unmeasured stays unmeasured; a live
advisory floors the verdict and leading signals can raise it but never lower it
below a known fact; advisories that do not affect the installed version are
filtered. Those are correctness properties, enforced by tests, and none of them
is a prediction.

**LOW is a real statement — and download count's bottom bucket is a better
one.** This is the control the account was missing, and it was run because a
review demanded it rather than because the result was expected.

In 7 of 7 runs the LOW bucket's abandonment rate sat below the cohort base rate
with the interval excluding it (#344). That is genuine, and a well-behaved
bottom bucket does not require good global ranking — AUC scores the whole
ordering, this is a local claim about one end of it, so the two results were
never in tension.

But nobody had asked whether the free baseline does the same thing better.
Same snapshot, same cohort construction, two-year window, most-downloaded
quartile against the tool's LOW bucket:

| T | base rate | tool's LOW | **downloads' safest quartile** |
|---|---:|---:|---:|
| 2022-08-01 | 0.459 | 0.63× | **0.53×** |
| 2023-08-01 | 0.445 | 0.66× | **0.46×** |
| 2024-08-01 | 0.431 | 0.68× | **0.64×** |

Lower is safer. **Download count's bottom bucket beats the tool's LOW bucket in
all three runs**, using one number that costs nothing to fetch.

Two further caveats on LOW, both of which point the same way. Those 7 runs used
the **same reconstructed instrument** as every other outcome result — three
signals constant, the repository block never computed — so LOW's record is
evidence about the registry-only object. And the repository block raises risk
for 667 of the 685 verdicts it changes, which means LOW is issued
preferentially to packages the tool could see *least*.

> **There is no bucket, at either end of the scale, where this tool has been
> shown to beat download count.** What it has that a download count does not is
> a refusal to guess: unmeasured stays unmeasured, a live advisory floors the
> verdict, and inapplicable advisories are filtered. Those are correctness
> properties, enforced by tests, and none of them is a prediction.

---

## 4. The five decisions #382 raised

| # | decision | status |
|---|---|---|
| 1 | keep calling itself a risk profiler? | **decided** — *risk profiler, scoped to maintenance risk*, with the reason it is a security question stated (77.2%) and the limits stated with it. In the README. |
| 2 | remove `license` from the codebase? | **decided — keep and surface it.** It is measured, it varies (76 of 2,000 non-permissive), and it is published on its own axis and never enters the composite (#340). The epic called it dead weight; it is a compliance fact deliberately reported beside a forecast. |
| 3 | finer maintainer bands? | **tested, answered no** — continuous recovers 1.58×, so the collapse is not primarily a banding artifact. 17.6% are swaps invisible at every resolution; swap detection is the only thing worth building. `granularity-result.md` |
| 4 | `staleness` as-of parameter? | **done** (#376) — `score_dependency(dep, as_of=…)`. It unblocked the composition study's line 4. |
| 5 | test or remove the repository-derived signals? | **partly done** — #339 discharged the tested half; #394 retired `signed_commits` (a merge-tooling detector) and `branch_protection` (could not observe the property it was named for). Eight became six. The remaining six are measured but still unvalidated against any outcome. |

---

## 5. What has changed since #382 was written

The epic's evidence table has entries this section supersedes, and they matter
because each was a claim about a *different instrument* than the one users run.

- **"The registry-only composite is a twelve-cell lookup table."** Still true,
  and correctly scoped by its own document. But it travelled without the
  qualifier, and the shipped instrument with a repository read has 235 distinct
  values. `full-instrument-composition-result.md` §2.
- **"Licence moves the score in zero of twelve cells."** True and by design —
  but measured when licence was never fetched at all. On the canonical record it
  varies; it moves nothing because #340 removed it from the composite, not
  because it is inert.
- **"Five outcomes attempted."** Six now. The sixth — CVE remediation — is the
  one that tested the substitution the whole programme stood in for, and it
  holds: unmaintained does mean unpatched.
- **"The validation surface is close to exhausted."** It was not. A prospective
  design was available and is now registered, and a composition study needs no
  outcome at all.

---

## 5b. How this compares to everyone else

`prior-art.md` reviews what the other tools measure and what has been
validated. Three things from it belong here:

- **OWASP's tools are a different category.** Dependency-Check matches CPEs to
  CVEs; Dependency-Track sums advisory severities. Both are lagging indicators
  and neither attempts a maintenance forecast.
- **Snyk Advisor scores popularity as one of its four pillars.** Given that
  download count beat this composite on every outcome tried, that looks like
  the better modelling choice and this tool's exclusion of it looks like the
  error.
- **When published health scores have been tested, they have not held up.**
  Scorecard against vulnerability counts came out at R² 0.09–0.12 *with the
  sign backwards*; SourceRank failed to separate malicious PyPI packages from
  legitimate ones. This project's negative results are not an outlier — they
  are the pattern.

What appears genuinely absent from the literature is a **prospective,
pre-registered validation of a shipped health score against a future outcome,
with a popularity baseline**. That is what `prospective-protocol.md` is.

---

## 6. What is not known, stated as plainly as the rest

- **Whether the composite predicts anything on the instrument users run.** Every
  outcome result above scored a degenerate variant — at a reconstructed date
  three signals were constant and the repository block was never computed. The
  prospective study (`prospective-protocol.md`) is the first test of the real
  thing and reads out **2027-08**.
- **Whether the repository block's penalty is deserved.** Same readout.
- **Whether `transitive` carries anything.** Never measured; a direct-dependency
  list is not a resolved closure.
- **Whether LOW's record survives on the real instrument.** It was measured on
  the same reconstructed object as everything else, and download count's bottom
  bucket already beats it on that object (§3).
- **Whether any of this generalises past npm.** One ecosystem, one T.

---

## 7. How this account has been wrong before

Worth recording, because the corrections were not marginal and the pattern is
consistent.

- The README once argued leading indicators beat lagging ones. **Tested against
  a pre-registered protocol, and it lost.** Withdrawn.
- *"The signals may detect activity rather than risk"* was carried for five
  studies as an inference. **Measured at R² 0.099 and withdrawn.**
- The prospective harvest was registered to measure thirteen signals and
  measured **eight**, leaving five constant. Found by a saturation check, fixed,
  and it **refuted a finding published the same day** — abstention went 53.6% to
  zero, and *"the repository block is the reason there is a verdict"* was an
  artifact of the omission.
- Three separate times a claim corrected in one place survived in another. That
  is now a mechanism (`withdrawn-claims.md`) rather than a resolution.
- **This document's own first draft claimed LOW works, without running the
  control.** The project's standing rule is to measure the baseline first — the
  rule that killed the provenance signal — and the draft broke it in the one
  sentence a reader would quote. A review caught it; the control was run; the
  claim inverted.

The through-line: **a measurement that agrees with the design is the one to
check hardest.** Every correction above began with a number that looked right.
