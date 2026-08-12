# The repository block decides whether the tool answers at all

**Result for `docs/full-instrument-composition-protocol.md`**, committed before
any figure here was computed. Reviewed 6-1; the dissent was right about the
central defect and the correction is §3 below.

Data: the frozen #385 record — 2,000 npm packages drawn uniformly, scored at a
live T with the production collectors. 928 have the repository block. No
outcome is involved, so this describes what the instrument *is*, never what it
predicts.

## 1. The finding

Each of the 928 packages was scored twice: once as the harvest scored it, and
once with the repository block suppressed. The block's contribution is then a
difference, not an inference.

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
