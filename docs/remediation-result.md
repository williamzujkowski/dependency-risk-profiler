# Does anything predict whether a CVE gets fixed? — result

**Protocol:** `remediation-protocol.md`, amended at §8.
**Primary outcome:** B′. **Line 2 does not fire** — something predicts, weakly.
**Interpretation reviewed 4-3 and corrected**; see §"What the review changed".

---

## The fact that needs no model

Among npm GHSA advisories where **no fix existed at disclosure**:

- **72.0% of advisories** (1,121 of 1,557) saw no further release from the package
- **77.2% of packages** (1,034 of 1,340) never published again

Both units are given because they differ and an earlier draft of this document
mixed them. The observation window is at least 12 months, so "never" means
*"not within the window"*.

**And the population matters:** these are advisories whose maintainer had *not*
already patched by disclosure day, which selects for maintainers who were
already unresponsive. It is a fact about disclosure-without-fix, not about
disclosed CVEs in general.

## The decomposition, stated as arithmetic

| outcome | n | packages | base rate |
|---|---:|---:|---:|
| **A** — was it ever fixed? | 1,557 | 1,340 | 15.1% |
| **B** — among packages still publishing | 436 | 306 | 53.9% |
| **B′** — B, minus fix-only publishers *(primary)* | 419 | 290 | 52.0% |

**P(fixed) = P(publishes again) × P(fixes | publishes) ≈ 0.28 × 0.52 ≈ 0.146**,
against an observed 15.1%. The identity is the honest way to say what the two
stages contribute, and it does not depend on comparing AUCs across populations.

## The predictors

Package-clustered bootstrap, 2,000 replicates. `*` = interval excludes chance.
The third column re-runs B′ with the outcome capped at **a fixed 12 months**
after each advisory, so every row has equal time at risk.

| predictor | A | B′ | B′ (12-month window) |
|---|---:|---:|---:|
| releases_total | 0.8674 | 0.6113 * | 0.5984 * |
| releases_prior_year | 0.8162 | 0.5983 * | 0.5881 * |
| **age_days** | 0.7446 | **0.6714** * | **0.6730** * |
| maintainers | 0.7353 | 0.6082 * | 0.5906 * |
| affected ranges | 0.7148 | 0.5896 * | 0.5811 * |
| repository declared | 0.5584 | 0.5599 * | 0.5538 * |
| days_since_release | 0.1730 | 0.3832 * | 0.3987 * |
| **CVSS severity** | 0.2983 | **0.4433** | **0.4442** |

## Reading the collapse honestly

Against "was it ever fixed", these look strong — up to 0.87. Against the
actionable question they sit near 0.6.

**Most of the collapse is expected rather than discovered.** B′ conditions on
publishing, and `releases_prior_year` and `days_since_release` essentially
*measure* publishing, so range restriction guarantees they fall. Citing their
drop as evidence would be circular.

What is not circular is the **differential**: `repository declared` — the one
predictor with no activity content — **does not collapse at all** (0.558 →
0.560), while the activity predictors fall hardest. That pattern is what
supports the reading, not the drop by itself.

**The operational statement stands regardless of mechanism: against the
question a user actually faces — this maintainer is still shipping, will they
ship the patch? — nothing we measure exceeds 0.67.**

## CVSS severity: a bounded null, and it confirms prior art

**0.4442, interval [0.3656, 0.5276].** The interval includes chance, so no
positive discrimination is detectable — and the upper bound near 0.53 *excludes
any useful positive effect* among advisories carrying a vector. That is a
bounded result, stronger than a bare failure to detect, and it is **stated as a
complete-case finding** because 31% of rows carry no vector.

Missingness was checked rather than assumed, and **my assumed mechanism was
backwards**: I expected older advisories to lack vectors. The rows *without* a
vector are **newer** (median advisory year 2024 vs 2022) and fix at a slightly
lower rate (0.485 vs 0.536). So missingness is era-correlated and mildly
outcome-correlated; the null holds among vectored advisories and is not
extended past them.

**This is not surprising, and an earlier draft called it "the most surprising
line in the table", which was wrong.** The EPSS literature exists precisely
because CVSS predicts downstream behaviour poorly. This result **corroborates
established prior art** rather than contradicting expectation — which makes it
more credible, not less interesting.

## Package age survives the confound that would have explained it

`age_days` is the strongest B′ predictor at **0.6714**, and the obvious
objection is differential follow-up: a 2019 advisory has years to accumulate a
fix, a 2024 one has months, and if package age tracks advisory age the AUC is
an artifact.

**Capping the outcome at a fixed 12 months moves it to 0.6730** — unchanged.
The confound is ruled out.

**That test has since been run, and age does not survive it.** See the section
below.

## What the review changed

The interpretation went to review and was **rejected 4-3**. Four corrections:

1. **A unit error in the headline.** "72% of packages" was the *advisory*-level
   figure. Both are now given, correctly labelled.
2. **The collapse was presented as a discovery** when it is mechanically
   guaranteed for the cadence predictors. Restated around the arithmetic
   identity and the differential pattern.
3. **"CVSS does not predict patching" overreached** a complete-case interval,
   and "the point estimate leans the wrong way" was reading noise inside an
   interval containing 0.5. Both removed.
4. **`age_days` needed the time-at-risk test before it could be reported.** It
   was run, and it survived.

## Limits

- **Package-clustered throughout** — 1,557 advisories over 1,340 packages.
- **B′ conditions on a collider.** It describes remediation among packages
  still shipping and nothing about the rest, and no causal reading is licensed.
- **`fixed` is OSV's claim**, not an observation.
- **Popularity-biased population** — these are packages somebody audited.
- **One ecosystem, one advisory source.**

---

# Follow-up: age is subsumed by popularity, and popularity beats everything

The result above left one test undone — *does `age_days` survive conditioning
on downloads?* It does not, and running it turned up something larger.

Downloads were measured over the **30 days ending the day before** each
advisory, so the window never spans the advisory and the outcome cannot inform
its own predictor.

## Age carries nothing beyond downloads

Out of fold, maintainer-clustered 5-fold, n = 365:

| model | AUC |
|---|---:|
| downloads only | **0.8228** |
| age only | 0.6678 |
| downloads + age | 0.8227 |

**Adding age to downloads: Δ = −0.0001, CI [−0.0077, +0.0073], p = 0.978.**
Downloads over age alone: Δ = +0.1550, CI [+0.0984, +0.2176], p < 0.001.

ρ(age, log downloads) = **+0.578**.

**What this licenses is conditional independence, and nothing more:** age
carries no predictive information *given* downloads. It does **not** establish
that age "was a popularity proxy" — with ρ = 0.578 both could be downstream of
something neither measures. The mystery has moved, not closed.

## Downloads predict remediation far above anything the tool computes

Re-scored on the **same 365 rows**, so the comparison is like-for-like:

| predictor | AUC |
|---|---:|
| **log downloads** | **0.8293** |
| age_days | 0.6735 |
| maintainers | 0.5956 |
| releases_total | 0.5906 |
| releases_prior_year | 0.5779 |
| repository declared | 0.5621 |

The earlier statement *"nothing we measure exceeds 0.67"* was true **of the
tool's own signals**, and that scoping was missing. Downloads are not one of
them.

## Two checks the review demanded, both run

**Leakage — ruled out.** GHSA publication trails the underlying disclosure, so
a window ending the day before publication could sit inside the disclosure
window and pick up attention rather than popularity. Re-running with a window
ending **90 days before** the advisory gives **AUC 0.8233** against 0.8293.
Unchanged. The signal is slow-moving popularity, not a disclosure spike.

**Attrition — real, and it bounds the number.** 54 of 419 rows failed the
downloads join, and **they are not missing at random: they fix at 0.704 against
the joined rows' 0.493.** Floor-imputing all 54 as zero downloads — the
worst case, since it forces high-fixing rows to the bottom of the predictor —
drops the AUC to **0.7029**.

**So the honest range is 0.70 to 0.83**, and both ends sit above every signal
the tool computes on the same rows.

## What this does and does not add to the programme's record

Downloads have now beaten the tool's signals on two different outcomes, and a
model with the composite's weights freed added nothing over downloads
(−0.0114, MDE 0.0128).

**The abandonment comparison is deliberately not cited as a third instance.**
That study's 0.577 was measured on an instrument with three signals constant at
reconstructed T, which this programme itself established makes the figure an
artifact. Re-importing it here as a clean head-to-head would be laundering a
number the record has already discredited.

## Limits

- **Mechanism unidentified.** Popular packages may get fixed because
  maintainers attend to them, *or* because outsiders chase and submit the fix.
  For a user triaging an advisory the distinction may not matter; for any
  causal reading it is decisive, and none is offered.
- **Cohort-scoped.** Advisory-receiving, still-publishing npm packages. The
  population is already popularity-selected, which if anything restricts the
  predictor's range and works against the observed discrimination.
- **Missingness is outcome-correlated**, which is why the range is quoted
  rather than the point estimate alone.
