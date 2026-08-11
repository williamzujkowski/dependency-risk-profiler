# What this score can be validated against — the whole landscape

**Status:** the map after three attempts. One outcome ran; two halted at their
own gates.

Written because the next person to ask "can we test this against X?" should be
able to read the answer instead of re-deriving it, and because two of the three
failures were invisible until measured.

---

## The three requirements

An outcome has to clear all three at once. Every failure so far is one of them
missing.

1. **Reconstructable at a past date.** The label must be knowable as of T from
   data that existed at T, and the signals must be too.
2. **Enough independent events.** Not rows — *events*. Clustering has killed
   more of these than sample size has.
3. **Not mechanically coupled to the signals.** If the outcome's probability
   moves with a quantity the score already measures, the study measures its own
   arithmetic.

---

## Attempt 1 — abandonment. Ran.

**Cleared all three.** Base rate ~40%, labels exact and un-backfillable,
observable for every package by construction, no mechanical coupling to the
signals (cadence and drift were ablated *because* they would have had one).

Result: **the composite lost to download count at every date.** AUC 0.577
against 0.696, replicated across three dates and two definitions of the outcome
— six measurements, all significant, no interval touching zero. `license` was
actively harmful in 7 of 7, `maintainer` load-bearing in 7 of 7,
`source_repository` null in 7 of 7.

`abandonment-pilot.md`.

## Attempt 2 — compromise. Halted at stage 1.

**Failed requirement 2.** The cases exist and are datable — 2,074 npm packages
with a reconstructable clean→compromised boundary, once you know that no
dataset dates the compromise and the packument `time` map has to supply it.

But they arrive in campaigns: **43 distinct compromise days**, three of them
holding 61% of the cohort. The pre-registered stop rule was 75. The design's
own estimate was 244, wrong by 5.7× because it extrapolated per-package from a
65-package sample that could not see concentration.

`compromise-backtest-stage1.md`.

## Attempt 3 — maintainer handover. Halted at stage 3.

**Failed requirement 3, twice over.**

The obvious form failed first: comparing two version documents is perfectly
censored, because a maintainer change is only visible through a new release.
Packages that published nothing after T showed **0 of 1,176**, and the censored
set was *exactly* the abandonment positive class.

The redesign — compare against npm's current top-level array — fixed the
censoring and hit a second coupling. The outcome is "the set differs," so a set
of five has five ways to lose someone where a set of one has one. Rate runs
**0.047 → 0.731** across set sizes, and **the `maintainer` signal *is* set
cardinality**.

`handover-outcome-halted.md`.

---

## What is left, honestly

### Advisory arrival — the original primary, never run

`validation-protocol.md` registered it first and it was deprioritised for
abandonment. The reasons still hold:

- **1.56%/12mo base rate**, needing ~18,300 packages against the 2,906 in hand.
- **OSV `published` is backfilled** ≥1 year in 22–43% of records. #327 found
  the worst case: `flatmap-stream`, the November 2018 event-stream attack,
  carries `published: 2025-08-14`.
- **A 4.7× popularity confound** running in the direction that would make the
  tool's own popularity signal score as *anti*-predictive.

It clears requirement 1 with corrections and requirement 3. It needs a harvest
roughly six times the current one to clear requirement 2. **That harvest is the
open decision it has always been**, and everything measured since has made it
look worse rather than better.

### Repository-derived signals — eight untested, #339

Not a new outcome; the abandonment outcome with more signals. Reconstructable
via `git ls-tree` and `git log` at the last commit before T for six of the
eight. Two are not reconstructable at any past date and may never be testable:

- **`signed_commits`** reads signature *validity*, which depends on keys that
  expire and rotate. `git log --pretty=%G?` returns `E` for 80% of `requests`
  and 97% of `flask` at 2022-01-01.
- **`branch_protection`** is current-state only with no historical source.

The bar is **0.539, not 0.577** — about half the composite's discrimination is
popularity, and any scanner gets that for free (#349).

### Outcomes that do not work, and why — so they are not re-proposed

| outcome | fails on | why |
|---|---|---|
| maintainer handover (version docs) | 3 | censored by publishing activity; 0 of 1,176 |
| maintainer handover (current state) | 3 | cardinality confound, 0.047 → 0.731 |
| complete maintainer turnover | 2 | 10–13 events per date |
| compromise | 2 | 43 campaign-days |
| `version` signal, any single-T design | 1 | at T the release in force *is* the latest; the scorer's equality branch returns 0.0 for every package |
| PyPI anything, as-of-date | 1 | `ownership.roles` is current state even on historical documents |
| PyPI compromise | 1 | 1 of 60 MAL packages still resolvable; PyPI hard-deletes |

---

## The pattern worth carrying

Two of three failures were **invisible in every summary statistic** anyone
would check first. Handover showed a 14.5% base rate stable across three dates
with ~180 events — and was perfectly censored. Compromise showed 2,074 cases —
and 43 independent ones.

Neither was caught by looking at counts. Both were caught by asking a
mechanism question:

- **What makes a positive recordable?** (censoring)
- **What makes two positives independent?** (clustering)
- **What else moves when the signal moves?** (coupling)

Those three questions cost minutes and have now saved two studies' worth of
wasted effort. They are in `validation-protocol.md` as named hazards, along
with the stage-0 requirement that a negative control be shown non-degenerate
before its protocol is accepted.

## And the thing the map is really saying

The abandonment result is not one weak result among several pending. **It is
the only outcome that cleared all three requirements**, and the composite lost
on it, replicated six ways. The two studies that might have overturned it could
not be run at usable power — not because of effort, but because the events do
not arrive independently and the outcomes are coupled to the signals.

That is a statement about what is knowable here, and it should temper how much
weight any future single study is expected to carry.
