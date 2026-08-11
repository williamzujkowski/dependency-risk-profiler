# What the composite measures — result

**Protocol:** `composition-protocol.md`, pre-registered and reviewed 5-2 before
anything ran.
**Branch fired:** **claim-withdrawn** (§5 line 2), at all three dates.
**Registers:** #375.

---

## The headline

**The composite is not substantially a function of publication activity.**
Five activity measures explain about **a tenth** of its rank variance.

| T | n | rank-R² | 95% CI | grouped-CV R² | permutation null p95 |
|---|---:|---:|---|---:|---:|
| 2022-08-01 | 2,398 | **0.0745** | [0.042, 0.120] | 0.0602 | 0.0052 |
| 2023-08-01 | 2,536 | **0.0937** | [0.071, 0.127] | 0.0868 | 0.0047 |
| 2024-08-01 | 2,906 | **0.0990** | [0.077, 0.130] | 0.0873 | 0.0051 |

The association is **real** — roughly forty times the clustered permutation
null, and it survives maintainer-grouped cross-validation almost intact, so it
is not in-sample optimism from five collinear predictors. It is also **small**,
and stable in being small across three dates two years apart.

§5 line 2 fires at 0.15 and the largest estimate is 0.099, with the upper
confidence bound at 0.130. The claim is withdrawn.

## What this corrects

The project has been carrying this sentence, always with an admission attached
that it was an inference rather than a measurement:

> the signals may detect project **activity** rather than risk

**The first half is now measured, and it is not supported.** Whatever the
composite is tracking, five direct measures of how recently and how often a
package published account for about a tenth of it.

What survives, unchanged, is the outcome-side finding: release cadence alone
scores **0.7340** against abandonment, above every figure this tool produced.
Both things are true at once, and together they say something sharper than
either alone:

**The composite is not an activity proxy. It is something else that also fails
to predict.** That is #349's harder reading, and it is now the supported one —
"adding signals of the same family is not obviously the fix" was right for a
reason nobody had measured.

## Falsification line 4 is unanswerable, not answered

The design compared a **shipped** composite against an **ablated** one, the
difference being `staleness` and `version` — cadence in another notation. At
reconstructed T both are **constant**:

- `staleness_score` = **1.0 for all 2,906 packages**
- `version_score` = **0.0 for all 2,906 packages**

So the shipped composite is an affine transform of the ablated one and
**rank-identical** to it. The definitional-versus-emergent split cannot be
measured at a past date, and the line that would have adjudicated it is
reported as unanswerable rather than as a null.

Two separate causes, both worth naming:

- **`version` is 0.0 by construction at a single past T.** At T the release in
  force *is* the latest, so the scorer's equality branch returns zero for
  everything. The outcome landscape already records this; it now has a second
  consequence.
- **`staleness` is measured against `datetime.now()`, not against any as-of
  date** — see #376. Every release in a two-year-old snapshot is far enough in
  the past to saturate the signal, so it pins to 1.0 for the entire cohort.

## The two constant signals still decide whether the tool answers at all

| composite | abstention rate |
|---|---:|
| ablated (3 signals) | **100.0%** |
| shipped (5 signals) | 73.9% |

The ablated composite is `insufficient_data` for **every package in the
cohort** — three measured signals against thirteen unexplained unknowns never
clears the sufficiency bar. Adding `staleness` and `version` issues 759
verdicts.

**Those two signals contribute no variance and decide every abstention.** A
signal that is constant across the entire cohort cannot distinguish one package
from another, and it is nonetheless the difference between a tool that answers
and a tool that refuses.

## Is being scored itself an activity function?

The review's sharpest worry: if active packages answer more registry fields,
the composite's *existence* would be an activity function, which would be a
larger finding than any R² on the subset that gets scored.

**Measured, and no.** Rank-R² of being-scored on the battery is **0.062**
(2024), 0.057 and 0.040 at the earlier dates. The strongest single association
is `release_span_days` at ρ = −0.215; every other battery member sits under
0.05. Selection into the scored subset is weakly related to activity at most.

## Where the tenth of variance comes from

Single-predictor R², 2024:

| predictor | R² alone |
|---|---:|
| release_span_days | 0.0626 |
| releases_total | 0.0477 |
| days_since_last_release | 0.0456 |
| releases_90d | 0.0297 |
| releases_1y | 0.0245 |

Five collinear measures together reach 0.099, so the battery is buying about
0.04 over its best single member — the gap is real and modest.

Per-signal, the association is carried by one signal:

| signal | ρ with days_since_last_release |
|---|---:|
| **maintainer_score** | **+0.268** |
| license_score | −0.051 |
| source_repository_score | −0.006 |

`maintainer` is the only load-bearing member of the composite against
abandonment (ablating it drops AUC to 0.487, below chance) and it is also the
only member with a meaningful activity association. Both facts are about the
same signal, and neither is large.

## Limits, stated rather than implied

- **The composite has eleven distinct values** across 2,906 packages. An R² of
  0.099 is describing how well five measures order eleven levels, not a
  continuous quantity. §8.3 originally asked for a "tie-aware ceiling" to
  contextualise this; that anchor was **retired as wrong** — average ranks are
  constant within a tied block, so the ceiling is 1.0 by algebra for any target
  and measured nothing. The level count is reported instead.
- **One registry, one ecosystem, three dates from one snapshot.** The three
  dates are not independent cohorts; they are the same packages observed at
  three moments.
- **This says nothing about whether the score detects risk.** That is an
  outcome question and `outcome-landscape.md` is closed. A composition study
  cannot reopen it and this one does not try.

## Reproducing

```bash
PYTHONPATH=research uv run python -m composition.experiment \
    --snapshot research/data/npm-2026-08-06 \
    --t 2024-08-01 --out research/results/composition-2024.json
```

Offline, seeded, no network. Two runs produce identical files, and
`test_the_composition_branch_is_machine_checked` reads the artifact and asserts
which falsification branch fired rather than trusting this document.
