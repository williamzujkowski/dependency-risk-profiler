# The registry-only composite, printed in full

**Protocol:** `leading-indicator-protocol.md` claim A — the only half the 5-2
review approved. Claim B's story is in §6 of that document.
**Registers:** #379.

---

## The whole thing

Over the signals reconstructable at a past date, the composite is a **twelve-cell
lookup table on two inputs**: how many maintainers the package declares, and
whether it declares a usable repository URL.

| maintainers | repository | score | packages |
|---|---|---:|---:|
| ≤ 1 | declared | **0.5714** | **1,262** |
| ≤ 1 | undeclared | **1.0000** | 409 |
| ≥ 5 | declared | 0.0000 | 338 |
| 3–4 | declared | 0.1429 | 281 |
| 2 | declared | 0.2857 | 266 |
| ≥ 5 | undeclared | 0.4286 | 136 |
| 3–4 | undeclared | 0.5714 | 90 |
| 2 | undeclared | 0.7143 | 66 |
| ≤ 1 | unusable | 0.8929 | 30 |
| 2 | unusable | 0.6071 | 14 |
| 3–4 | unusable | 0.4643 | 8 |
| ≥ 5 | unusable | 0.3214 | 6 |

Twelve cells, eleven distinct scores, 2,906 packages, no exceptions —
`is_a_function` is true and the conflict list is empty. Scorer configuration
fingerprint is recorded in `research/results/lookup-table-2024.json` so a table
produced under different weights cannot be mistaken for this one.

## Three things this makes visible that a statistic did not

**Licence does not move the score. At all.** Zero of the twelve
(maintainer, repository) pairs produce a different score for a different
licence category — permissive, copyleft, unknown and absent are
indistinguishable. That is the correct consequence of #340 removing `license`
from the composite after it measured *harmful*, and it means the registry-only
composite reads **two** fields, not three. Nothing said so before, because a
correlation of −0.051 looks like a weak signal rather than an absent one.

**One cell is 39% of the cohort.** 1,262 packages — one maintainer, repository
declared — all carry 0.5714. Nearly two-fifths of everything the tool scores
gets a single number, and the number sits mid-scale where it is least
actionable.

**Two very different packages collide.** "One maintainer with a repository" and
"3–4 maintainers with no repository" both score 0.5714. Whatever the composite
means, it does not distinguish those, and no amount of reading the score can
recover which one you have.

## What this does not say

- **Only the reconstructable signals.** A live run also has `staleness`,
  `version`, `deprecation`, `transitive`, `community` and eight
  repository-derived signals. This table is what remains when you keep only
  what can be computed at a past date — which is exactly the arm every
  validation study in this repository used, so it is the table those results
  were produced from.
- **Not a claim that the mapping is surprising.** A deterministic scorer maps a
  complete input tuple to one output; the review made that point and it is
  right. The finding is the *size* of the tuple, not its single-valuedness.
- **Nothing about whether the score is correct.** Twelve cells could be a
  perfectly good risk model. `outcome-landscape.md` is where that question went
  and it is closed.

## A methodological note worth keeping

The first enumeration recorded the raw maintainer *count* and produced **149
cells for eleven scores** — a table that says packages have many different
maintainer counts, which nobody needed telling. The effective input is the
scorer's own band, and deriving it by *calling* `_calculate_maintainer_score`
rather than restating its thresholds means a re-banded scorer cannot leave this
document describing a table it no longer produces.

Enumerating at the wrong granularity is how an exact method still produces
noise.
