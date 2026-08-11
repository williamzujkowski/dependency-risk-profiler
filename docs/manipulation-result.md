# What it costs to game the score — result

**Protocol:** `manipulation-protocol.md`. Exact, offline, no sampling.
**Registers:** #382, the synthesis epic. (No number was predicted this time:
the last protocol guessed one and cited its own pull request.)

---

## The price

| | share of the 2,906-package cohort |
|---|---:|
| score can be lowered at all | **88.4%** |
| score can be lowered **with no publish** | **83.5%** |

The whole scale, 1.0 → 0.0, costs **five npm accounts and one URL string**.

## The single most consequential row

**1,262 packages — 39% of the cohort — sit at 0.5714** (one maintainer, a
repository declared). Every one of them can be driven to **0.0**, the floor of
the scale, by **adding five maintainer accounts and publishing nothing**.

That is the modal package in this dataset going from the middle of the scale to
"no risk detected" without a single line of code changing hands.

| cell | score | packages | best reduction | cost |
|---|---:|---:|---:|---|
| ≤1 maintainer, declared | 0.5714 | 1,262 | **−0.5714** | 5 accounts, **no publish** |
| ≤1, undeclared | 1.0000 | 409 | **−1.0000** | 5 accounts + a URL, publish |
| ≥5, declared | 0.0000 | 338 | — | already at the floor |
| 3–4, declared | 0.1429 | 281 | −0.1429 | 2 accounts, no publish |
| 2, declared | 0.2857 | 266 | −0.2857 | 3 accounts, no publish |

## Both falsification lines that could have saved it did not fire

**Line 1 — is the repository field verified?** It is not.
`record_source_repository` assigns `DECLARED` when the URL canonicalizes to an
`owner/repo` root on a supported host. Nothing checks that the repository has
any relationship to the package. A fork, an empty repository, or
`facebook/react` all qualify.

**Line 2 — is the no-publish path marginal?** 83.5% against a 25% bar. It is
the main path, not a curiosity. And it is the one that matters: `npm owner add`
mutates the packument's top-level array, so an attacker who has just acquired a
package can re-score it downward **without touching the code**, which is
precisely the situation where a risk score is supposed to speak up.

**Line 3 — is the scale resistant to cheap manipulation?** The largest single
reduction available for under ten accounts is **1.0**, the entire range.

## What this does and does not say

It says what the **price** is: five free accounts and an unverified URL move a
package from the top of the scale to the bottom.

It does **not** say anyone has done this. No evidence of exploitation is
offered and none was sought. Nor is the scorer unusual — most repo-health
scores read self-declared metadata, and none of them verify it either. What is
unusual here is that the score was enumerated first, so the price can be stated
exactly instead of guessed at.

**And the enumeration is why this was owed.** Publishing an auditable scoring
function was right. Having published it, pricing the moves it exposes is the
other half of the same obligation, and leaving that arithmetic to someone else
would have been the worse choice.

## Limits

- **Registry-only arm.** The eight repository-derived signals (#339) are
  untested and might raise or lower the price; nothing here speaks to them.
- **Cost is counted in accounts and publishes**, not in effort or in risk of
  detection. Creating npm accounts at scale may trip anti-abuse controls this
  analysis cannot see.
- **"More maintainers is lower risk" is a modelling choice**, not a fact — and
  it is exactly the choice a Sybil attack exploits. A scorer that treated an
  abrupt jump from one maintainer to five as *suspicious* rather than
  reassuring would price this attack very differently.

## The product consequence

This does not belong in the same category as the other seven studies. Those
measured whether the score tracks anything. This one says that whatever it
tracks, **a motivated publisher can set it to whatever they like**, and 39% of
the cohort can be set to the floor for free.

Filed against epic #382, where the "does it stop calling itself a risk
profiler" decision now has one more input.
