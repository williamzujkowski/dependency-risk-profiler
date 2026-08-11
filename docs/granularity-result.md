# Would finer bands help? — result

**Protocol:** `granularity-protocol.md`, amended at §6 after a 4-3 reject.
**Registers:** #382, the synthesis epic. (An earlier draft cited #383, which
turned out to be this study's own pull request rather than an issue — the
number was predicted rather than read, and predicting an issue number is how a
document ends up citing itself.)
**Subset:** 1,174 quiet packages (no publish after T), from the existing
harvest. No new fetch.

---

## The arms

| resolution | moved | rate | per package-year | risk-increasing share | 95% CI |
|---|---:|---:|---:|---:|---|
| **shipped** (4 bands) | 86 | 7.33% | 0.0285 | 0.442 | [0.342, 0.547] |
| **fine** (0–9, then 10+) | 117 | 9.97% | 0.0387 | 0.470 | [0.382, 0.560] |
| **continuous** (the count) | 136 | 11.58% | 0.0450 | 0.485 | [0.403, 0.569] |

## Q1 — finer resolution recovers movement, but less than expected

Going from four bands to a continuous count raises the movement rate by
**1.58×**, not the 2× the conditional check asked about. So **the collapse is
not primarily a banding artifact**: most maintainer sets that change simply do
not change by enough, or in a way, that any count resolution would see.

## Q2 — underpowered, and the point estimates lean *against* my prior

The primary contrast is the **marginal events** — set changes a finer arm sees
that the shipped bands do not — because the arms are nested and comparing
pooled splits would drag the finer arm toward the coarser one by construction.

| marginal events | n | risk-increasing share | difference vs shipped | 95% CI | verdict |
|---|---:|---:|---:|---|---|
| fine | 31 | 0.548 | **+0.107** | [−0.098, +0.311] | **underpowered** |
| continuous | 50 | 0.560 | **+0.118** | [−0.055, +0.291] | **underpowered** |

**This is why the tri-state was pre-registered.** I said in advance that I
expected "granularity is not the fix". A point comparison against the 10-point
bar would have delivered exactly that — and it would have been wrong twice
over: the point estimates are **+0.107 and +0.118, on the helping side of the
margin**, and their intervals straddle it. The honest answer is that this
harvest cannot tell.

The lean is worth stating precisely because it is the opposite of what I
expected: the movements that finer resolution *adds* run about **55–56%
risk-increasing**, against the shipped arm's 44.2%. If that difference is real,
finer bands would surface proportionally more risk-*increasing* movement — the
kind a warning would be made of. At 31 and 50 events it is not established.

## The ceiling nobody registered until review caught it

**29 of 165 maintainer-set changes among quiet packages — 17.6% — are swaps**:
one maintainer out, one in, count unchanged.

A swap changes the set and leaves the count identical, so it is invisible at
*every* resolution, continuous included. That is a hard ceiling on what any
granularity change could ever recover, and it was missing from the registration
until a reviewer pointed out that the 2.12× collapse was measured on **sets**
while every arm here buckets a **count**.

A maintainer being replaced is arguably the most interesting event in this
dataset. No count-based signal can see it.

## What this licenses

*Under a continuous maintainer count the signal would move for 11.6% of quiet
packages rather than 7.3%, and whether the added movements carry more
directional signal is undetermined at this sample size.*

**It rules the granularity fix neither in nor out**, and that asymmetry was
fixed in advance: a per-package-correct signal is aggregate-balanced by nature,
so a balanced split is never evidence of uninformativeness. What would settle it
is an outcome, and the outcome programme is closed.

## Recommendation, such as it is

- **Do not ship finer bands on the strength of this.** The rate gain is real
  and modest (1.58×); the directional gain is unestablished.
- **Do not ship them as a "no-op" either.** The point estimates lean toward
  helping, and dismissing them would repeat the error this protocol's tri-state
  exists to prevent.
- **If anything is worth building, it is swap detection**, which no resolution
  change reaches and which 17.6% of the churn consists of.
- A continuous score would also dissolve the twelve-cell table that makes the
  composite auditable — named in §5 before the numbers, and still true.
