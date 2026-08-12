# CVE remediation — population sizing

**Protocol:** `remediation-protocol.md`, amended at §8 after a 4-3 review.
**Stage:** population only. **No predictor has been joined to any outcome.**
**Gates: both pass.** The study is viable.

---

## Two findings before any model

### 61% of advisories were already fixed when they were published

| stage | rows |
|---|---:|
| npm OSV corpus | 226,616 |
| — MAL takedowns, excluded by rule | −219,149 |
| GHSA advisory-package rows | 9,640 |
| — published within 12 months of harvest | −4,385 |
| windowed | **5,255** |
| — **fix already shipped before the advisory** | **−3,214 (61%)** |
| — package unresolvable / fix version undated | −441 |
| **corrected population** | **1,600** |

**That 61% is coordinated disclosure, measured.** The review rejected the
original design because a fix that predates its advisory makes the outcome
already-closed at the prediction date — and here is the size of it. Under the
original design those 3,214 rows would all have scored "fixed" mechanically,
putting the base rate near 66% instead of 15% and producing a model that
predicted the disclosure process rather than anything about the package.

### Of advisories not already fixed at disclosure, 85% were never fixed

Within the corrected population of 1,600 advisories across 1,378 packages:

- **240 (15.0%)** were fixed after the advisory
- **1,360 (85.0%)** have no fixing version at all

That is the security fact this study set out to reach. When a vulnerability is
disclosed and the maintainer has *not* already patched it, **it usually stays
unpatched.** No predictor is needed to say that, and it is worth stating on its
own.

## Gates

| gate | threshold | value | |
|---|---|---:|---|
| line 1 — power | n ≥ 300 | **1,600** | pass |
| line 3 — base rate | 5% < p < 95% | **15.0%** | pass |

1,378 distinct packages support the package-level clustering the analysis
requires.

## What has *not* happened

No predictor has been computed, joined, or looked at. The next stage
reconstructs maintainer count, repository presence, release cadence and
severity **as of each advisory's publication date**, then evaluates outcomes B
and B′ under package-clustered cross-validation.

Stopping here is deliberate: population sizing was the question the amendment
raised, and answering it before touching predictors is what keeps the
pre-registration meaningful.

## Caveats carried forward

- **`fixed` is OSV's claim.** A package may have patched without OSV recording
  it, which would inflate the 85%.
- **The population is popularity-biased** — these are packages somebody audited.
  Nothing here generalises to packages nobody has looked at.
- **257 packages did not resolve** and 184 fix versions carried no date. Both
  are reported rather than dropped silently.
