# Does the one lead-capable signal actually move? — result

**Protocol:** `band-crossing-protocol.md`, amended at §6 after a 4-3 reject.
**Registers:** #378.
**Harvest:** 2,906 of 2,906 packuments resolved. Line 4 does not fire.

---

## The numbers

Each rate is over that subset's own exposure window, not an assumed two years —
the amendment's whole point.

| subset | n | set change | **band crossing** | per package-year | collapse | median window |
|---|---:|---:|---:|---:|---:|---:|
| **quiet, baseline within 6mo of T** | 486 | 15.2% | **7.20%** | 0.0316 | 2.11× | 2.29 y |
| quiet, all | 1,174 | 14.1% | 7.33% | 0.0285 | 1.92× | 2.60 y |
| **active comparator** | 1,732 | 28.8% | **13.11%** | **0.0582** | 2.19× | 2.14 y |
| whole cohort | 2,906 | **22.81%** | 10.77% | 0.0452 | 2.12× | 2.30 y |

**The whole-cohort set-change rate is 22.81%.** The handover study measured
22.8% by a different route on the same cohort. That the two agree to three
figures is the best evidence available that this measurement is doing what it
says.

## What the falsification lines did

**Line 1 does not fire.** 7.20% of quiet packages in the headline stratum cross
a band, against a 5% floor. The signal is not motionless.

**Line 2 does not fire, but the number underneath it is the finding.** Among
quiet packages the crossings split **48 risk-decreasing to 38 risk-increasing**
— and in the headline stratum, **19 to 16**. Not "overwhelmingly" either way,
which is what line 2 asked about, and that is worse than if it had been:

> **For a package that has gone quiet, a maintainer change is about as likely to
> lower its risk score as raise it.**

Line 2 was written to catch a systematic wrong direction; what it found is no
direction.

**Correction, 2026-08-11.** This section originally continued: *"A signal whose
movements are directionally a coin flip is not a warning at all, however often
it moves."* **That is wrong, and it is wrong in a way that changes how the
result should be read.**

A balanced split is entirely consistent with a *perfectly informative* signal.
Some quiet packages genuinely get rescued — a maintainer joins, and the risk
really is lower. Others genuinely decay. A signal that is correct package by
package produces an aggregate split near even *by construction*, so aggregate
balance is not evidence of uninformativeness.

What the split licenses is narrower: **the signal carries no aggregate
directional drift.** Whether each movement is *correct* is an outcome question,
and the outcome programme is closed, so this study cannot answer it either way.
The finding stands; the inference drawn from it did not.

**Line 3 does not fire, and the ratio is reported anyway.** Set changes exceed
band crossings by **2.12×** — under the 3× line, but the collapse is real:
**22.8% nominal becomes 10.8% effective.** More than half of all maintainer-set
changes move the score by exactly nothing, because they happen inside a band.
This is the fifth time this repository has found a nominal-to-effective gap and
the first time it went looking for one in advance.

## The comparator is the part that hurts

**Quiet packages cross bands at half the rate of active ones** — 0.0285 against
0.0582 crossings per package-year, and 7.3% against 13.1% over comparable
windows.

The tool's one lead-capable signal moves *least* for exactly the packages it
would most need to speak about. Not never, which is what the study went looking
for and did not find. Half as often, in a direction that is a coin flip.

## The `time.modified` probe is saturated and useless

The amendment kept `time.modified` later than the newest release as an
independent lower bound on non-publish mutation. **It is 1.0 for every subset**
— every packument in the cohort, without exception.

npm touches `modified` on essentially any packument write, so it cannot
discriminate a maintainer change from anything else. Recorded as a dead probe
rather than dropped: a reviewer proposed it, it was adopted in good faith, and
the honest outcome is that it measures nothing here. It joins `staleness` at
1.0 and `version` at 0.0 on the list of this codebase's saturated signals, and
the pattern is worth noticing — three of them now.

## Account clustering: no bot artifact

86 crossings among quiet packages involve **434 distinct accounts**, and the
largest single account touches **8.1%** of them (7 packages). No platform-wide
admin action or bot fleet is manufacturing the rate. The concern was right to
raise and the data does not support it.

## What this licenses

*Among npm packages that have gone quiet, the maintainer signal crosses a
scoring band for about 7% of them over roughly two years, at half the rate it
does for active packages, in a direction that is close to even.*

It does **not** license "the tool gives early warning" — movement is necessary
and nowhere near sufficient — and it says nothing about whether any individual
movement was *correct*. That is an outcome question and the outcome programme
is closed.

## Limits

- **The window is per package and the rate is per package-year** for exactly the
  reason §6 records: the baseline is the maintainer set frozen at the last
  pre-T publish, not at T. The headline stratum exists so one row of this table
  answers the original question as it was asked.
- **A two-snapshot design lower-bounds the numerator.** A crossing that reverted
  before the harvest is invisible, so every rate here is a floor.
- **Cause is not identified.** An owner add, a transfer, a bot account and an
  npm support action are indistinguishable in this data, and the direction split
  above carries that ambiguity with it.
- **No lead time.** npm publishes no history of top-level maintainer changes, so
  this sees *changed by the harvest* and cannot date it. Knowing 7% of quiet
  packages saw a maintainer change at some point in two years does not tell you
  whether it came before or after anything mattered — which is what a user
  actually wants, and this cannot supply it.
