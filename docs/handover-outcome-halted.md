# Maintainer handover — halted at stage 3

**Status:** halted. 7-0 consensus, 2026-08-11.
**Registers against:** `handover-outcome-protocol.md`.
**Second study to stop at its own gate**, after `compromise-backtest-stage1.md`.

Stages 4, 5 and 6 were never run, and never computed. The negative control
fired first, which is the order the protocol puts it in precisely so that no
model number exists to be tempted by.

---

## 1. What fired

| §6 line 2 | |
|---|---|
| control | labels shuffled within maintainer cluster, 200 rounds |
| mean AUC | **0.2449** |
| band | [0.47, 0.53] |
| verdict | **FIRED** |

## 2. Why — and it was not the harness

The within-cluster shuffle is close to an identity permutation on this cohort.
2,905 packages fall into 2,176 maintainer components, 1.33 members each; a
shuffle cannot move a label in a singleton, nor in a component whose members
already share one. Measured label preservation across rounds: **96.6%**.

Meanwhile the observed model AUC is **0.235**. A near-identity permutation
therefore returns roughly the observed value.

So on this cohort the control **passes when the model is weak and fires when
the model is strong** — backwards for a negative control. A global permutation
returns mean **0.5007**, straddling 0.5 symmetrically, which establishes the
harness reads the outcome through no path other than the features.

## 3. Why the control was not simply amended

Amending it was argued and rejected 7-0, on two grounds.

**It would not have rescued the study.** A sound control unblocks stages 4-6 to
measure a model whose dominant signal is mechanically anti-correlated with the
outcome (§4 below), with one target signal untestable by construction and the
other resting on an unregistered reconstruction. Three deviations stacked on
one pre-registration is not a study.

**And the degeneracy argument is weaker than it looks.** It is tempting to say
the defect was structural and therefore knowable before any data — but only
partly. The 1.33-members-per-component figure is outcome-free and *was*
knowable at design time. **The 96.6% preservation figure is not: it requires
the labels.** So the diagnosis that justified amending is itself partly
data-contaminated, which is exactly the distinction that separates a legitimate
correction from a forking path.

The same argument shape — "the pre-registered choice is wrong on the merits" —
was rejected for the compromise backtest's clustering. Consistency is worth
more than this study's salvage value.

## 4. The finding worth keeping: the outcome is cardinality-confounded

| maintainers at T | n | changed | rate |
|---|---:|---:|---:|
| 1 | 1,701 | 80 | **0.047** |
| 2 | 346 | 103 | 0.298 |
| 3–4 | 378 | 128 | 0.339 |
| 5+ | 480 | 351 | **0.731** |

The outcome is "the set differs." A set of five has five ways to lose someone
where a set of one has one, so outcome probability rises with cardinality close
to mechanically — **and the `maintainer` signal *is* set cardinality.**

**This, not the AUC, is the reportable result.** A set-difference outcome
confounds risk with set size, and any cardinality-derived signal evaluates
backwards against it. That generalises past this study.

**AUC 0.235 is not reported as a finding about the composite.** It is
mechanically explained by the confound, and reporting it as "the composite
anti-predicts handover" would be uninterpretable. It appears here as a
diagnostic and nowhere else.

It is also not evidence the signal is wired wrong. Against *abandonment* the
same strata run the other way — solo 0.493, 5+ 0.263 — so the composite's
"solo maintainer is risky" encoding is correct for the outcome it was built
around and inverted for this one. No single weight is right for both (#353).

## 5. Both target signals were compromised anyway

The study existed to admit `staleness` and `version`, neither previously
tested. Neither survived contact.

**`version` is degenerate at T.** At T the release in force *is* the latest, so
the scorer returns `0.0` on its equality branch for all 2,905 packages —
carrying full weight in the denominator with nothing in the numerator. **No
single-past-T design can test it.** That is a fact about the signal, not this
cohort, and it should be recorded wherever the untested signals are counted.

**`staleness` is computed against wall-clock `now`.** Supplying the literal
publish time measures days from that release to today, which *is*
`exposure_window_days` — the quantity §5 assigns to baseline 5. The baseline
would have been inside the model. The harness instead supplies the value for
which the shipped scorer computes the as-of-T bucket; that is a judgement §4
does not cover, and it was fixed and documented before any AUC was computed.

## 6. The process defect, which is the durable part

**The negative control was never validated before being pre-registered.**

A check was available at design time and costs nothing: shuffle the labels and
measure what fraction actually moved. On this cohort it returns 96.6%
preservation, and the protocol would have been written differently.

That is this repository's recurring failure mode — a bar stated and nothing
checking it — applied to a protocol rather than to code. So the fix is not to
this study but to the template: **§0 of any future protocol asserts its own
negative control is non-degenerate on the actual cohort, before the protocol is
accepted.** Added to `validation-protocol.md`.

## 7. What is NOT being committed to

Redesigning the outcome to remove the cardinality confound — per-maintainer
hazard, or "lost a specific maintainer" — is a **new study needing its own
justification and its own pre-registration**, not a continuation of this one.
It is not adopted here. The abandonment pilot already established that the
composite loses to download count, so a redesigned handover study needs a
fresh reason to exist rather than the momentum of this one.

If it is ever built, use existing survival tooling rather than another bespoke
harness.
