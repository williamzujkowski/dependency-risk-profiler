# The repository block decides whether the tool answers at all

**Result for `docs/full-instrument-composition-protocol.md`**, committed before
any figure here was computed. Reviewed 6-1; the dissent was right about the
central defect and the correction is §3 below.

Data: the frozen #385 record — 2,000 npm packages drawn uniformly, scored at a
live T with the production collectors. 928 have the repository block. No
outcome is involved, so this describes what the instrument *is*, never what it
predicts.

## 1. The finding — WITHDRAWN, see §7

> Everything in this section is an artifact of a harvest that performed only
> eight of the thirteen registered signals. The numbers below are real
> measurements of the wrong thing. §7 explains, §8 replaces them. Kept in
> place rather than deleted so the correction is legible.

Each of the 928 packages was scored twice: once as the harvest scored it, and
once with the repository block suppressed. The block's contribution is then a
difference, not an inference.

*(Every figure in this table is withdrawn — see the banner above and §7.)*

| | |
|---|---:|
| packages whose score moved | **928 / 928** |
| median move | **+1.035** (range −2.34 to +2.71) |
| Kendall tau, with vs without | **0.617** |
| **packages whose verdict band changed** | **928 / 928 (100%)** |

Every transition is the same one:

| transition | n |
|---|---:|
| `UNKNOWN` → HIGH | 744 |
| `UNKNOWN` → MEDIUM | 121 |
| `UNKNOWN` → LOW | 43 |
| `UNKNOWN` → CRITICAL | 20 |

> **Without the repository block, every one of these 928 packages scores
> `insufficient_data`. The block is not adding precision to a verdict — it is
> the reason there is a verdict.**

The sufficiency bar is therefore decided, in this cohort, entirely by whether a
repository could be cloned. That is #408's concern measured rather than argued:
the bar counts signals that produced a number, and six numbers arrive together
or not at all.

Kendall tau of 0.617 says the block also genuinely **reorders** — a monotone
shift would leave tau at 1.0 and carry no information about relative risk.

**And the direction is not what the manipulation work would predict.** 80% of
the flips land on HIGH. Declaring a repository does not, on average, buy a
better score; it buys a *verdict*, usually an unfavourable one. `docs/full-
instrument-manipulation-result.md` reported that declaring an unrelated
repository flips the tool from abstaining to answering, then corrected itself
to "only with enough of the suite to clear the bar". With the full production
suite actually run, the flip is **universal** — and the corrected version
understated it.

## 2. The lookup table was the tool without its repository block

`docs/lookup-table-result.md` enumerated the composite as a twelve-cell lookup
table with eleven distinct scores across 2,906 packages. That measurement was
**correct, and correctly scoped by its own document** — titled "The registry-only
composite", opening with "over the signals reconstructable at a past date", and
repeating the limit in its final section. This does not overturn it.

What went wrong was transmission. The headline travelled into the README, into
summaries and into my own notes as *"the composite is a twelve-cell lookup
table"*, shedding the qualifier that made it true. **A condition stated only in
the document that earned it will be dropped by everything that cites it.**

The same enumeration on the shipped instrument:

| cell (maintainer band \| repository state) | n | share | distinct scores |
|---|---:|---:|---:|
| ≤1 \| **cloned** | 788 | 0.394 | **132** |
| ≤1 \| none declared | 762 | 0.381 | **11** |
| ≤1 \| declared, uncloneable | 189 | 0.095 | 8 |
| 2 \| cloned | 61 | 0.030 | 38 |
| 3–4 \| cloned | 48 | 0.024 | 27 |
| ≥5 \| cloned | 31 | 0.015 | 19 |
| six further uncloned cells | 121 | 0.061 | 3–6 each |

Within one maintainer band: **11 distinct scores with no repository, 132 with a
cloned one.** The uncloned cells reproduce the eleven-value backbone almost
exactly, which is the strongest possible confirmation that the earlier
enumeration measured its instrument correctly.

Spread, not jitter — measured, because distinct-value counts cannot tell the
difference:

| cell | n | p25 | median | p75 | IQR |
|---|---:|---:|---:|---:|---:|
| ≤1 \| cloned | 788 | 3.179 | 3.535 | 3.636 | **0.458** |
| ≤1 \| none declared | 762 | 2.500 | 2.500 | 2.500 | **0.000** |

**The middle half of the uncloned cell is a single number.** And **701 of 2,000
packages — 35.0% of the cohort — receive exactly the score 2.5000**; among
packages with no cloned repository, 65.4% do.

Stated the other way, honestly: concentration does not vanish when the block
runs. **289 of the 928 cloned packages (31.1%) still share one score** (3.6364).

## 3. A pre-registered line whose null was never computed

§3 line 2 declared the block "decorative" if registry-only inputs recovered the
composite's ordering at rank-R² ≥ 0.90. Measured 0.6076, and the first draft
read "does not fire" as evidence the block does real work.

**That reading was rejected on review and the rejection is correct.** The
registry-only score is roughly 85% tied inside the modal band, and rank-R²
between a heavily-tied score and *any* tie-broken refinement is mechanically
depressed by the tie mass alone. 0.6076 is consistent with the block
contributing nothing. **The threshold was set without computing its null**,
which is this project's own recorded lesson — measure the control first — for
the third time.

The line is therefore reported as **uninformative rather than passed**, and §1
replaces it with a direct measurement that needs no null: score the same
packages twice and difference them.

## 4. Two further corrections from review

**The modal-cell reproduction is not external validation.** The cell axes are
registry-side facts — maintainer count, repository declared — so two uniform
draws of npm a year apart agreeing at 0.394 vs 0.39 reproduces a property of
*npm's composition*, not of the instrument. The first draft claimed it as
validation; that reading is withdrawn. At most the cohorts are compositionally
comparable.

**Line 3 fired and the headline does not contradict it.** Line 3 tests cell
*mass*, and it fires: one cell still holds 39.4% of the cohort. But the
dominant cell is `≤1 | cloned`, which is precisely the cell holding 132
distinct scores — so the line's firing does not protect the enumeration claim
it was written to guard. That is a defect in the line, not a result, and it is
recorded rather than quietly reinterpreted.

## 5. What this does not say

**Resolution is not accuracy.** A score with 188 distinct values orders
packages no better than one with 11 unless something measures the ordering.
The abandonment result found this composite orders them badly, and this study
has no outcome.

**The added structure comes from an unverified input.** #388 established that
the repository URL is self-declared and nothing binds it to the package. So the
block that decides whether the tool answers is computed from data the scored
party chooses. Whether that is worth its cost is not answerable here, and waits
on the 2027-08 outcome read.

**The 928 are not a random half.** Clone failure correlates with abandonment,
so they are enriched for still-alive packages.

## 6. A mis-specification, recorded rather than repaired quietly

Line 3 was first evaluated on the full-instrument subset, where `repo_state` is
`cloned` for every row **by construction**. One enumeration axis was constant,
the table collapsed to four maintainer bands, and the largest "cell" read
**0.849** — a number measuring the maintainer distribution and nothing else.

**A cell definition with a constant axis is not a cell.** This is the third
time in this project that a constant has been mistaken for a measurement, after
the saturated signals that made every prior outcome study degenerate and the
tie-mass null in §3. Future protocols should pin the denominator per line, and
require a null for any threshold whose scale is not obvious.

---

## 7. §1 IS WITHDRAWN — it measured my harvest, not the tool

**2026-08-12, later the same day.** §1 reported that all 928 packages with a
cloned repository change verdict band when the block is suppressed, every
transition `UNKNOWN` → a verdict, and concluded that the block "is the reason
there is a verdict".

**That is an artifact of the harvest and the conclusion is withdrawn.**

Protocol §14 established that the harvest bypassed the production analyser and
never performed the advisory lookup, never fetched the licence, and never
recorded the repository provenance state — leaving five of thirteen signals
constant. Those omissions are what pushed packages under the sufficiency bar.
With them measured, through the production code paths and at the shipped
default configuration:

| | harvest | measured as registered |
|---|---:|---:|
| constant signals | 5 of 13 | 2 of 13 |
| **abstention** | **0.5360** | **0.0000** |
| CRITICAL verdicts | 20 | 0 |

**Not one package in the 2,000 abstains.** So the repository block cannot be
"the reason there is a verdict" — there is a verdict either way. §1's
measurement was real; what it measured was the gap my own harvest had left.

### What survives §7

The parts of this document that do not depend on abstention still stand:

- The enumeration (§2): the eleven-value backbone reproduces in the uncloned
  cells, 132 distinct scores appear in the cloned one, and the spread is real
  rather than jitter.
- §3's correction: line 2's rank-R² threshold was set without computing its
  null and remains uninformative.
- §4's withdrawal of the modal-cell reproduction as external validation.

### The lesson, and it is not a new one

§6 said *a cell definition with a constant axis is not a cell*, and called that
the third time a constant had been mistaken for a measurement. §1 was the
fourth, in the same document, one section earlier — and it took the form of
comparing an instrument against **itself minus a block**, when four of its
other signals were already missing from both arms. **A difference measured
between two degraded arms describes the degradation.**

## 8. What the repository block actually does, measured properly

Same two-arm design as §1 — score each package with the block and without it —
but with the omitted signals measured in **both** arms, so the difference is
the block rather than the gap.

The no-block arm is produced by pointing the same enrichment at an empty clone
root: identical code path, identical inputs, no repository read.

| | with block | without block |
|---|---:|---:|
| abstaining | **0** | **0** |
| packages where the block ran | 932 | — |
| **verdict band changed** | **685 of 932 (73.5%)** | |
| raised risk / lowered risk | **667 / 18** (97.4% raise) | |
| median score change | **+1.085** (p25 +0.885, p75 +1.157) | |
| ran but changed nothing | 0 | |

Sanity check that the arms are otherwise identical: of the 1,068 packages where
no repository was read, **zero** changed verdict.

### The corrected reading

**The block does not decide whether the tool answers.** It answers either way.
What the block does is move roughly three-quarters of the packages it can read
into a *different* band, and it moves them **up**: 667 raised against 18
lowered, a median of +1.085 on a five-point scale.

That has a sharper consequence than §1's withdrawn version, and it points the
opposite way from the manipulation reading:

> A package that declares a readable repository is scored **worse**, almost
> without exception. The repository block is not a reward for transparency —
> in this cohort it is a penalty for it.

Whether the penalty is *deserved* is the open question, and it is exactly what
the 2027-08 outcome read is for. If packages with readable repositories are
genuinely more likely to go quiet, the block is doing its job. If they are not,
the tool is systematically punishing the packages that gave it something to
look at, which would be the worst possible property for a signal computed from
a **self-declared, unverified URL** (#388) that a package can simply omit.

### Why §1 got this wrong

§1 compared the instrument against itself-minus-a-block while four other
signals were missing from *both* arms. The missing signals put every cloned
package under the sufficiency bar in the no-block arm, so every difference
presented as `UNKNOWN` → verdict. **A difference measured between two degraded
arms describes the degradation**, and the degradation was mine.
