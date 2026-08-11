# Would finer bands help? — pre-registration

**Status:** pre-registered. Fixed and committed before any counterfactual was
computed; the order is checkable from git.
**Registers:** #383.
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
