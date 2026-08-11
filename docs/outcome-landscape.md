# What this score can be validated against — the whole landscape

**Status:** the map after four attempts. One outcome ran, two halted at their
own gates, and one arm ran to completion without licensing a claim.

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

**Cleared all three — requirement 3 less cleanly than this document first
claimed.** Base rate ~40%, labels exact and un-backfillable, observable for
every package by construction. Cadence and drift were ablated *because* they
would have been coupled, and that ablation was assumed to settle it.

**It does not settle it, and the repository arm measured how much it leaves.**
Release cadence at T — the ablated construct — scores **AUC 0.7340** against
this outcome. The best predictor of "published no releases in two years" is
"how often did you release last year," which is circular by construction and
is exactly why it was excluded. But ablating a signal removes it from *the
model*; it does not remove the construct from *the outcome*. Every figure
this project has produced sits below that tautology, and any signal correlated
with project activity inherits some of it: commit cadence loses **43% of its
excess-over-chance** once conditioned on release cadence (0.6479 → 0.5842).

So abandonment remains the only outcome that clears all three, and requirement
3 is a matter of degree here rather than a clean pass. **An outcome defined as
the absence of an event cannot be fully decoupled from the rate of that
event.** Read every result against it with that in mind.

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

## Attempt 4 — the repository arm. Ran; no claim licensed.

Not a new outcome; the abandonment outcome with more signals. Pre-registered,
reviewed 7-0 twice, amended once before results and corrected by erratum after
(`repository-arm-protocol.md` §12–13).

**Result: +0.0594 [+0.0014, +0.1138] within a download-reported popularity
stratum, and +0.0082 [−0.1207, +0.1150] over the whole arm.** Both reported,
neither promoted, because they describe different populations.

Four things bound it, and together they are the finding:

- **The interval grazes zero** — 45 of 2,000 clustered resamples at or below.
  Realised ρ 0.186 and SE 0.0273 against a published 0.0157 put the MDE at
  0.0976, above the observed effect, so **Type-M inflation is likely**. It is
  *not* a null; saying so would be the post-hoc power fallacy.
- **One signal carries it.** `community_activity` supplies 111% of the block.
- **It reverses sign by population** — −0.063 on the 890 packages npm reports
  no downloads for, almost entirely scoped. Population, not popularity, is the
  confound, and the pre-registered guard was written for popularity.
- **The winning signal is substantially the ablated construct**, per attempt 1
  above.

**No claim is advanced.** The pre-registered interpretation — improvement
*beyond cadence* — rested on a false premise (the registry baseline does not
contain release recency, because it was ablated) and is void.

Two signals remain untestable at any past date and may never be testable:

- **`signed_commits`** reads signature *validity*, which depends on keys that
  expire and rotate. `git log --pretty=%G?` returns `E` for 80% of `requests`
  and 97% of `flask` at 2022-01-01.
- **`branch_protection`** is current-state only with no historical source.

The bar is **0.539, not 0.577** — about half the composite's discrimination is
popularity, and any scanner gets that for free (#349).

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

### GitHub ownership transfer — the only candidate that clears requirement 3

Tested for coupling first, as the closing section of this document demands.
**It is the first outcome in four attempts to pass that test cleanly** (#368).

| | |
|---|---|
| **release cadence at T scores against it** | **0.5104** — chance. Against abandonment the same predictor scores 0.7346. |
| positives / effective events | **105 / ~99** — collapse ratio **1.05**, the best of any outcome tried |
| base rate | 5.6% of the repository-declaring cohort |

It escapes what killed the others structurally, not by luck: it is a **positive
event** rather than the absence of one, so there is no "absence of X predicted
by the rate of X"; and it is a **binary transfer** rather than a set
difference, so no cardinality confound and no censoring by publishing activity.

**Requirement 1 is the weak one.** The owner at T comes from the repository URL
frozen in the version document, the current owner from the GitHub API resolving
transfers — so it says *changed by the harvest*, not *changed within a window*,
and runs at one T only.

**Power, computed rather than estimated:** clustered bootstrap SE 0.0299, so
the MDE against chance is 0.0839 and a paired arm difference at ρ = 0.8 is
0.053 — marginal against the 0.05 line rather than out of reach.

#### What was seen, and why it is not a result

Exploratory, **not pre-registered, and it cannot now be**: the data was
collected for another study's stage 7 and the answer was looked at before any
protocol existed. Recorded so the next person starts from it, not so anyone
cites it.

| predictor | AUC vs ownership transfer |
|---|---:|
| the registry composite | 0.4955 |
| `commit_frequency` at T | 0.5455 |

Both sit inside the 0.0839 MDE, so **neither is distinguishable from chance**
and neither can be claimed either way. What the numbers do support is a bound:
if the composite discriminates this outcome at all, it does so **below 0.584**.

The reason to write it down is the shape rather than the values. Every outcome
these signals scored above chance on was substantially an activity proxy —
abandonment at 0.7346 for release cadence alone. Given an outcome measured to
be independent of activity, the composite lands on 0.4955. **If that survives
power, the reading is that the signals detect activity rather than risk, and
the outcomes they appeared to predict were activity in disguise.**

That is the claim most worth testing and least safe to assert from here. A
replication needs a fresh cohort — not this one, whose answer is known — with
the protocol fixed before the data is touched.

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

Both halts were **invisible in every summary statistic** anyone would check
first. Handover showed a 14.5% base rate stable across three dates
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
on it, replicated six ways. Two studies that might have overturned it could not
be run at usable power — not for want of effort, but because the events do not
arrive independently and the outcomes are coupled to the signals. A third ran
and produced an estimate too imprecise, too population-dependent and too
entangled with the ablated construct to claim anything from.

**The sharpest version, after four attempts:** the difficulty is not that the
signals are weak. It is that *the outcomes available to measure them against
are all close relatives of the signals themselves.* Abandonment is the absence
of releases and the signals measure project activity. Handover is a set
difference and the signal is set cardinality. Compromise would have escaped
both and could not be powered.

Anyone proposing a fifth outcome should be asked what makes it independent of
project activity before being asked whether it is reconstructable.

**One candidate has now been put through that test and passed**: GitHub
ownership transfer, coupling AUC 0.5104 against release cadence, with
essentially independent events. Its weakness is requirement 1 and its size, not
its structure — which makes it the first outcome here whose binding constraint
is fixable.

It is pre-registered in `transfer-outcome-protocol.md`, reviewed 7-0 with
conditions, and frozen. It is also the **capstone**: either branch of it
completes this table, and a null there does not license a sixth attempt. The
honest reading of five attempts is not "keep looking for an outcome that
works" — it is that the search itself is the result.

That is a statement about what is knowable here, and it should temper how much
weight any future single study is expected to carry.
