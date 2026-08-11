# Compromise backtest — stage 1, and the gate that stopped it

**Status:** halted at stage 1 by its own pre-registered stop rule.
**Registers against:** `compromise-backtest-protocol.md`, merged before any cohort existed.
**Decision:** 7-0 consensus to halt. Date: 2026-08-11.

The study did not run. This records why, because a study that stops is only
worth something if the stopping is written down as carefully as a result would
have been.

---

## What stage 1 measured

Joined all 2,074 version-pinned entries in the DataDog `malicious-software-packages-dataset`
npm manifest to their packuments, and derived each package's compromise instant
as `min(time[v] for v in affected_versions)` — protocol §3.

| | |
|---|---:|
| manifest entries, version-pinned | 2,074 |
| **resolved** | **1,931 (93.1%)** |
| version-doc HTTP 404 | 97 |
| packument HTTP 404 | 44 |
| no clean history | 1 |
| affected versions unresolvable | 1 |

93.1% against a design assumption of ~92%. Failures are itemised rather than
folded into a denominator, per §3.

The era assumption held exactly: **1,254 cases in 2026, 673 in 2025**, three in
2024 and one in 2020. 99.8% falls in the window §2 predicted, so the
abandonment rig genuinely could not have been reused.

---

## The gate

> §11 stage 1: *"Stop if the campaign count is below 75 — the study is then
> unpowered for even a 0.10 gap and running it would produce an
> uninterpretable null."*

**Distinct compromise days: 43.**

| | |
|---|---:|
| nominal cohort | 1,931 |
| distinct campaign-days | **43** |
| mean packages per campaign-day | 44.9 |
| top three days | 441 + 418 + 323 = **61.2% of the cohort** |

The three are 2026-08-04, 2025-11-24 and 2026-05-19.

**43 < 75. The rule fires. The study halts here** — no controls built, nothing
scored.

---

## The estimate was wrong by 5.7×

The protocol carried effective n ≈ 244, extrapolated from a 65-package sample,
and labelled it an extrapolation. The measured value is 43.

The extrapolation failed for a specific and reusable reason: **a 65-package
sample cannot see concentration.** It observed 16 days across 65 packages and
divided, which assumes campaigns are roughly the same size. They are not — the
distribution is six mass events and a thin tail:

```
441, 418, 323, 160, 143, 112, 54, 50, 45, 31, 24, 20, 19, 16, 13, 10, 8,
5, 5, 4, 4, 3, 2, 2, and nineteen days holding exactly one package
```

**Per-package extrapolation of cluster counts is not a valid method under
campaign concentration, and should not be used again for a power estimate in
this project.** Count the clusters or do not claim a power figure.

---

## Why not simply re-cluster

Three clusterings are defensible and they disagree about whether the study can
run:

| clustering | clusters | clears the gate? |
|---|---:|---|
| **campaign-day** (pre-registered) | **43** | no |
| scope only | 122 | yes |
| (day, scope) pairs | 152 | yes |

The protocol says campaign-day, because it says to use whichever unit is
*coarser*. Switching to (day, scope) after learning it is the only unit that
passes is the textbook form of what pre-registration exists to prevent.

**It also fails on the merits, which matters more than the procedure.** The
three dominant days are mass-campaign days — worm propagation and credential
sweeps. Same-day compromises across different scopes in those waves share an
actor, a payload and a detection date; they are not independent, and splitting
them into separate cells would manufacture independence the attack pattern
contradicts. Only **25 of the 152** cells hold ≥1% of the cohort, so 152 is a
nominal count and the effective figure is far below it. Re-clustering would buy
a number that clears the gate rather than power that exists.

If (day, scope) is genuinely the right unit, it was the right unit before the
count was known. The honest form of that argument is to pre-register it for
**future** compromise data; this cohort is now contaminated by a known outcome.

**And 43 may itself be generous.** The clustering assumes the dataset's dating
is accurate to the day. Date noise that splits one campaign across two adjacent
days would inflate the count, so the true number of independent events is 43
*or fewer*.

---

## "Study the less-clustered subset" does not work either

26 days hold five packages or fewer, and they cover **44 packages in total**;
19 days hold exactly one. Dropping the mass campaigns to recover independence
leaves a cohort further below the gate than the one we started with.

There is no slice of this data containing 75 independent events. That is a
property of how npm compromises arrive, not of the sampling.

---

## What the sensitivity ladder actually contains

The protocol's per-package estimates were also extrapolations, and were wrong
in both directions:

| filter | estimated | **measured** |
|---|---:|---:|
| ≥1 prior clean release | ~2,870 | **1,931** |
| ≥3 | "between" | **1,677** |
| ≥5 | ~991 | **1,542** |

Median prior clean releases per case: 23 (p25 6, p75 120).

**This sharpens the problem rather than softening it.** There are plenty of
packages and almost no independent events. Every rung of the ladder reports a
healthy-looking n while the number governing the intervals stays at 43. A
write-up quoting "1,542 compromised packages" would be true and would badly
overstate what the data supports — the same shape as reporting a bucket
distribution without its abstention rate.

---

## What this does and does not mean

**It is a feasibility failure, not a null result.** No AUC was computed and no
hypothesis was tested. Nothing here bears on whether leading indicators predict
compromise; the study that would have answered that could not be run at a
usable power.

Per protocol §7, an underpowered null would not have licensed reinstating the
withdrawn claim anyway. That is why the gate was set before the number was
known, and it is the reason this halt costs the project nothing it had.

The gate working is the outcome. A pre-registered stop rule fired on honest
measurement and prevented an uninterpretable study — which is what it was for.
