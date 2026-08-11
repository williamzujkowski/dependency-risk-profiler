# Maintainer handover — stage 3, and the stop it produced

**Status:** executed and **halted at the §6 line 2 gate.** Protocol:
`docs/handover-outcome-protocol.md`, §10 step 3. Stages 4, 5 and 6 were **not
run**. No baseline comparison, no model head-to-head, no ablation, and no
number from any of them exists in this repository.
**Date run:** 2026-08-11. **T = 2024-08-01**, the single T the protocol fixes.

Artifacts: `research/results/handover-stage3.json`.
Code: `research/handover_study/{features,analysis,stage3_6}.py`.
Tests: `testing/unit/test_handover_study.py`.

---

## The gate, first, because it is the result

§6 line 2: *labels shuffled within maintainer cluster, mean AUC outside
[0.47, 0.53] — nothing from the run is reported at all.*

| | value |
|---|---:|
| mean AUC over 200 within-cluster permutations | **0.2449** |
| min / max | 0.2360 / 0.2529 |
| band | [0.47, 0.53] |
| **verdict** | **FIRED** |

Stages 4-6 were therefore not executed. The harness can run them; it was not
asked to. Looking at a result the stop rule forbids reporting is the failure
mode a stop rule exists to prevent, so the numbers were never computed rather
than computed and withheld.

## Why it fired, measured rather than argued

Two facts, and the second only matters because of the first.

**The pre-registered control cannot move most of the label vector.** A
within-cluster shuffle leaves the label of every row in a singleton cluster
exactly where it was, and leaves every cluster whose members already share a
label untouched as well. On this cohort — 2,905 packages in 2,176 maintainer
components, 1.33 packages per component — that is **87.3% of rows invariant by
construction**, and 96.6% preserved on average once chance agreement in the
remainder is counted. A permutation that preserves 24 rows in 25 does not
destroy the association it is meant to destroy: it returns the observed AUC
shrunk slightly towards 0.5.

**The observed AUC is 0.235.** The composite, scored at T over the four signals
§4 admits, orders this cohort *against* the outcome, and strongly. So the
control returned 0.2449 — the observed value, barely moved — and 0.2449 is
outside the band.

Put together: on this cohort the §6 control passes when the model is weak and
fires when the model is strong. That is the opposite of what a negative control
is for, and it means the gate's verdict here is a statement about the effect
size, not about whether the harness is wired correctly.

## The harness is not the thing that is wrong

Reported because §6's premise is "the harness is wrong before the result is
interesting", and that premise is checkable independently of the gate.

| permutation | mean AUC | min | max | mean label preservation |
|---|---:|---:|---:|---:|
| **within cluster** (§6, the gate) | **0.2449** | 0.2360 | 0.2529 | 0.966 |
| global (the abandonment pilot's control) | **0.5007** | 0.4676 | 0.5308 | 0.647 |
| cluster block, size-stratified | 0.4357 | 0.3962 | 0.4784 | 0.696 |

The global permutation — the one that destroys every association — lands on
0.5007 with a range that straddles 0.5 symmetrically. Nothing in the harness is
reading the outcome through a path other than the features.

The size-stratified block permutation is reported for completeness and **its
null is not 0.5**: it exchanges label blocks only between clusters of equal
size, so it preserves the cluster-size-to-label association, and cluster size
is itself correlated with maintainer count and therefore with the score. It
cannot be read against the §6 band and is not offered as a substitute for
anything.

Neither of these two overrides the gate. The gate is what the protocol
pre-registered; these say what kind of failure it was.

## What the two never-tested signals turned out to be

This is the part that survives the stop, because it is a property of the
scorer and the snapshot rather than a result about the outcome.

### `version` is degenerate at T

The signal reads installed version against latest version. At T the release in
force **is** the latest release, so the two strings are equal, and
`RiskScorer._calculate_version_difference_score` returns `0.0` on its equality
branch — before the calendar-versioning path that would have read the two
release dates. All 2,905 packages score an identical, *measured* `0.0`.

It is supplied to the model anyway, because §4 admits it, and it carries its
full 0.15 weight in the denominator while contributing nothing to the
numerator. Its only effect on any score is a renormalisation, and its only
effect on any ranking is the second-order one caused by that renormalisation
interacting with the packages whose `source_repository` is unmeasured — 37
distinct total scores with it, 36 without.

**A signal that cannot vary is not a tested signal.** This study admits
`version`; it does not test it. No design at a single past T can, because
"latest at T" and "installed at T" are the same release by definition.

### `staleness` reads wall-clock now, not T

`RiskScorer._calculate_staleness_score` buckets
`datetime.now(timezone.utc) - last_updated`. Handing it the unadjusted publish
time of the release in force at T therefore does not measure release cadence at
T. It measures days from that release **to today**, which is exactly
`exposure_window_days` — the quantity §5 adds as **baseline 5**, specifically so
the model can be tested against it. Supplying it that way would put the
baseline inside the model.

It is also constant. Cohort eligibility caps staleness at T at 365 days, so
every exposure window is at least 2.03 years, every one lands in the "more than
a year" bucket, and the signal is `1.0` for all 2,905 packages.

| reading | days (min / p50 / max) | buckets |
|---|---|---|
| literal publish time (now-relative) | 741 / 845 / 1105 | `1.00`: 2,905 |
| as of T | 1 / 105 / 365 | `0.00`: 796, `0.25`: 519, `0.50`: 575, `0.75`: 1,000, `1.00`: 15 |

So `handover_study.features.staleness_input` supplies the `last_updated` **for
which the shipped scoring function computes the as-of-T bucket**:
`reference_now` minus the days elapsed from the release in force at T to T.
This builds an input. It does not compute a score, there is no second scoring
path, and `testing/unit/test_handover_study.py` pins the reconstruction at every
one of the scorer's threshold boundaries.

## Signal coverage in the full model arm

All four admissible signals were measured for all 2,905 packages.

| signal | measured values |
|---|---|
| `maintainer` | `0.00`: 480, `0.25`: 378, `0.50`: 346, `1.00`: 1,701 |
| `source_repository` | `0.00`: 2,146, `0.75`: 58, `1.00`: 701 |
| `staleness` (as of T) | `0.00`: 796, `0.25`: 519, `0.50`: 575, `0.75`: 1,000, `1.00`: 15 |
| `version` | `0.00`: 2,905 |

`insufficient_data` fires for 2,146 of 2,905: with eleven of the fifteen scored
signals unmeasurable from a registry alone, the scorer's own abstention rule is
tripped for every package that declares a readable repository nobody read. The
total score is still evaluated, exactly as the abandonment pilot does it.

## One diagnostic, offered so the direction is not mysterious

Not a stage-4/5/6 result and not reported as one. It is a cross-tabulation of
the cohort against its own outcome, and it exists because "the model's AUC is
0.235" invites the question of whether something is wired backwards.

| maintainers at T | n | changed | rate |
|---|---:|---:|---:|
| 1 | 1,701 | 80 | **0.047** |
| 2 | 346 | 103 | 0.298 |
| 3-4 | 378 | 128 | 0.339 |
| 5+ | 480 | 351 | **0.731** |

Nothing is wired backwards. The maintainer count at T is strongly and
monotonically **positively** associated with the maintainer set changing, and
the composite scores a solo maintainer as its highest risk. The composite is
inverted with respect to this outcome, and the inversion is the data's, not the
harness's.

**This raises a coupling the protocol does not name.** §9 names popularity as
the confound the download baseline controls. This is sharper than popularity: the
outcome is "the set differs", and a set of five accounts has five ways to lose
one where a set of one has a single way. The outcome's probability rises with
set cardinality close to mechanically, and the `maintainer` signal *is* set
cardinality. Whatever is done next, that coupling needs an answer, and the
answer is not in the pre-registration.

## Nominal n and effective n, as required everywhere

| | n |
|---|---:|
| cohort, nominal | 2,906 |
| resolved | 2,905 |
| maintainer clusters in the resolved cohort | 2,176 |
| primary positives (`any change`), nominal | 662 |
| **primary positives, effective maintainer clusters** | **473** |

## What is not claimed

**No claim of evidence of absence is made or licensed.** §7 forbids one until
the stage-7 misclassification audit bounds the rename and silent-transfer error
rates, and stage 2 measured the generalised rename signature at 10.0% of
positives — exactly the ceiling above which §7 says a null is reported as
uninformative. Stage 7 was not run and is not implemented here.

Nothing here is a claim about handover prediction in either direction. Stages 4
through 6 did not run.

## Deviations from the protocol as written

**One judgement call the protocol does not cover, and one thing it cannot
settle.**

1. **How `staleness` is supplied.** §4 admits the signal and does not say how
   to reconstruct it. The literal input measures the exposure window, which §5
   assigns to a baseline; the reconstruction described above measures the
   cadence at T, which §2 is about. The choice was made and written down
   before any AUC was computed, both readings are reported, and the literal
   one is shown to be a constant.
2. **The §6 control is degenerate on this cohort.** It is implemented exactly
   as written and its verdict is read exactly as written. It is *not* amended,
   substituted or overridden: an amendment now, after data contact, is the
   thing pre-registration exists to prevent. What can be done is to report
   that the specified control preserves 87.3% of the label vector by
   construction, that its verdict therefore tracks effect size rather than
   harness correctness, and to leave the decision about what follows to a
   process that is not this run.

`ruff` and `mypy src research` are clean. The full suite passes (2,668 passed,
7 skipped). `bandit` was run from `/home/william/.local/bin/bandit` — a missing
tool prints nothing, which reads exactly like a pass — and reports one low
`B311` on `analysis.py`'s use of `random.Random` for permutations, matching the
three the abandonment pilot already carries for the same reason. CI scans `src`
only.
