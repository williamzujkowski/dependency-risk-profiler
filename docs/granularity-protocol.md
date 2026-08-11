# Would finer bands help? — pre-registration

**Status:** pre-registered. Fixed and committed before any counterfactual was
computed; the order is checkable from git.
**Registers:** #382, the synthesis epic. (An earlier draft cited #383, which
turned out to be this study's own pull request rather than an issue — the
number was predicted rather than read, and predicting an issue number is how a
document ends up citing itself.)
**Date fixed:** 2026-08-11, against `main` at 7aa9d53.

---

## 0. Testing a proposed fix, not the status quo

Six studies have measured what the tool does. This is the first to measure what
a **change** to it would do, and it exists because the obvious fix is plausible
enough to be shipped without being tested.

`band-crossing-result.md` found that maintainer-set changes collapse **2.12×**
into score movements: 22.8% of packages change their maintainer set, 10.8% cross
a scoring band. The mechanism is the bands — four of them, `≤1 / 2 / 3–4 / ≥5` —
and 27 maintainers becoming 28 moves nothing.

**The obvious conclusion is "make the bands finer."** It is obvious, it is
cheap, and nobody has checked whether it helps. This checks.

## 1. The two questions, and why the second is the real one

**Q1 — does finer granularity recover movement?** Under a finer banding, or
none at all, what fraction of quiet packages would see their score move?

**Q2 — does the movement acquire a direction?** The band-crossing study's
finding was not that the signal is still; it is that its movements split **48
risk-decreasing to 38 risk-increasing** among quiet packages. Directionless
movement is not a warning at any resolution.

**If Q1 improves and Q2 does not, granularity is not the problem and the fix is
a distraction that ships more movement of no informational value.** That is the
outcome this protocol exists to make visible before someone implements it.

## 2. The counterfactual arms, fixed now

Applied to the movements already harvested (2,906 packuments, 100% resolved,
`research/results/band-crossing-harvest.json`), with no new fetch:

| arm | maintainer resolution |
|---|---|
| **shipped** | `≤1 / 2 / 3–4 / ≥5` — the current four bands |
| **fine** | every integer count from 0 to 9, then `10+` |
| **continuous** | the count itself; any change of ±1 moves the score |

The comparison is between arms on the same packages, so nothing here depends on
a cohort choice.

## 3. Falsification lines — fixed now

1. **If the continuous arm's direction split among quiet packages is not
   materially more one-sided than the shipped arm's**, granularity is reported
   as **not the fix**, whatever it does to the movement rate. "Materially" is
   fixed as the risk-increasing share moving by at least 10 percentage points.
2. **If the continuous arm's movement rate among quiet packages is below
   twice the shipped arm's**, the collapse is reported as *not primarily a
   banding artifact* — most maintainer sets would simply not be changing.
3. **If the fine arm sits closer to continuous than to shipped on both
   measures**, that is reported as the practical recommendation, because a
   ten-level band is implementable and a continuous score is a larger change to
   the twelve-cell table than it looks.
4. **If any arm produces a direction split more one-sided than 70/30**, that
   arm is reported as carrying a directional signal the shipped one loses, and
   it becomes a product recommendation rather than a measurement.

## 4. What a confirmation licenses

*Under resolution X, the maintainer signal would move for N% of quiet packages,
in this direction split.* A statement about the **instrument**, on the same
cohort, at one T.

It does **not** license "finer bands would make the tool predictive." Whether
any movement is *correct* is an outcome question, the outcome programme is
closed, and no resolution change reopens it. A finer band that moves more often
in a more consistent direction is still unvalidated against anything.

## 5. Named hazards

- **The same lower bound.** A two-snapshot design cannot see a change that
  reverted; every rate here is a floor, in every arm equally, so the
  *comparison* is sound even though the levels are floors.
- **Direction is measured in score units.** More maintainers is lower risk in
  this scorer, so a package gaining maintainers moves risk *down*. Reporting
  count direction would invert what a reader cares about.
- **A continuous maintainer score is not a free change.** It would dissolve the
  twelve-cell table that makes the composite auditable — the property
  `lookup-table-result.md` was able to exhibit. That trade is named here so a
  favourable result does not get read as costless.
- **Cause remains unidentified.** An owner add, a transfer, a bot account and an
  npm support action are indistinguishable in this data, in every arm.

---

## 6. Amendment: nested arms, an unpowered bar, and a criterion that overreached

Reviewed **4-3, below supermajority — rejected**. Four defects, all adopted, and
the first two change what gets measured.

### The arms are nested, and the pooled comparison is rigged toward my prior

Every band crossing **is** a set change, so shipped ⊂ fine ⊂ continuous.
Comparing the continuous arm's pooled direction split against the shipped arm's
compares two overlapping samples, and the pooled statistic is dragged toward the
shipped one by construction — biased toward "granularity is not the fix", which
is the answer I said in advance that I expected.

**The primary Q2 contrast is now the marginal events**: set changes visible at a
finer resolution and invisible at the shipped one. That asks the question
directly — *does the movement granularity adds carry direction?* — without each
arm contaminating the other.

### The 10-point bar cannot distinguish "no effect" from "no power"

At n = 86 shipped crossings the risk-increasing share carries a 95% interval of
roughly ±10 points. The bar sits inside the noise of the reference arm alone,
and power to detect a true 10-point shift is around 45%: the criterion would
announce "not the fix" about half the time when granularity *is* the fix by its
own definition.

**The outcome is now tri-state** — supported, refuted, or **underpowered at this
harvest** — decided by whether the interval on the difference excludes the
margin. Pre-registering the third state is the point: without it an inconclusive
result gets narrated as a negative one.

### Criterion 2 was nearly pre-answered, and criterion 4 back-doored a closed question

The 2× movement-rate bar sits just under the **2.12× collapse already published
from the same harvest**. It is downgraded from live falsification to a
conditional check on the quiet subgroup, where the ratio genuinely is unknown.

Criterion 4 promoted a one-sided split to a *product recommendation*. That
converts aggregate one-sidedness into a claim about signal quality, which is
exactly the inference §4 forbids — aggregate drift (maintainers drifting off
quiet packages) would produce one-sidedness with no per-package information.
**Downgraded to: motivates a correctness question this study cannot answer.**

### Swaps bound what any count-based fix can recover

Unflagged by me and caught in review: the 2.12× collapse was measured on
**sets**, and every arm here buckets a **count**. A swap — one maintainer out,
one in — changes the set and leaves the count identical, so it is invisible at
*every* resolution including continuous.

The swap fraction is now reported, because it is the ceiling on what any
granularity change could ever recover.

### And criterion 1's conclusion was the same category error, twice

The wording "movement of no informational value" asserts precisely what §4's
scope forbids and what `band-crossing-result.md` has now been corrected for: a
per-package-correct signal is aggregate-balanced by nature. The conclusion is
narrowed to **"finer resolution does not change the aggregate direction
profile"**, which is what an instrument study can say.

**This study can rule the fix in. It cannot rule it out.** Recorded before the
numbers exist.
