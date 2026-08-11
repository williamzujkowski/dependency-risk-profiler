# Compromise backtest — pre-registration

**Status:** pre-registered. Fixed before any cohort was assembled or any package scored.
**Registers:** #327. Extends `validation-protocol.md`, which registered the abandonment pilot.
**Date fixed:** 2026-08-11, against `main` at 9d49a0a.

This document exists so that the answer cannot be chosen after the fact. The
abandonment pilot's value came almost entirely from having been pre-registered:
its result was negative, and the pre-registration is the only reason that
negative is worth anything. This one is written under harder conditions,
because the claim it tests has **already been withdrawn** on other evidence.
That makes the temptation asymmetric — a positive result here would restore
something, and a null would restore nothing — so the null case is written down
first, in §7.

---

## 1. The claim under test

> Leading indicators — release cadence, maintainer concentration, provenance,
> version drift — identify packages that will later be **compromised**, better
> than lagging or trivial baselines do.

This is narrower than the claim withdrawn in #330. That one was about "risky
dependencies" in general and lost on the abandonment outcome at three separate
dates. This tests the outcome that was never measured.

**It is a different question, not a rematch.** Nothing here can un-falsify the
abandonment result, and a positive result would license a claim about
compromise specifically, not the general one.

---

## 2. Why the abandonment rig cannot be reused

Three properties of the compromise outcome break it:

| | abandonment pilot | this |
|---|---|---|
| T | one global date | **per package**, its own compromise instant |
| era | 2022–2024 | **2025–2026 only** — no takeover case was found with a true compromise date before 2024 |
| cohort | random sample, 40.5% base rate | **matched case-control** — the population base rate is 0.023% |
| analysis unit | package, clustered on maintainer | **campaign-day** |

A random cohort is not affordable: at 1 compromise in 4,317 packages, 100
positives would require harvesting ~432,000 packages.

---

## 3. The outcome, and how its date is established

**Positive** = a package that was legitimate and later published a version
carrying malicious code, per the DataDog `malicious-software-packages-dataset`
npm manifest (Apache-2.0), restricted to **version-pinned** entries.

Born-malicious typosquats — entries whose value is `null`, meaning every
version is bad — are **excluded**. They have no clean history, so there is
nothing to predict from. That is 45,232 of 47,306 entries; the cohort comes
from the remaining **2,074**.

**No dataset dates the compromise.** Every public source dates *detection* or
*disclosure*. OSV `MAL-` records carry `published`, which is when someone filed
the report:

| package | attack | OSV `published` |
|---|---|---|
| `flatmap-stream` | event-stream, Nov 2018 | 2025-08-14 |
| `electron-native-notify` | 2019 | 2025-08-14 |

Labelling on `published` would misdate those by seven years. The date is
reconstructed instead from the registry's own record:

```
GET https://registry.npmjs.org/<pkg>          # the packument, NOT the version doc
compromise_ts = min(time[v] for v in affected_versions)
```

Everything published strictly before `compromise_ts` is clean history and is
the only data any signal may read.

Fixed in advance:

- **The packument, never the version doc.** npm pulls malicious version docs
  (they 404) but the `time` entry survives.
- Expected version-resolution rate ~92% (459/500 in a probe). **The achieved
  rate is reported as a result**, not assumed. Unresolvable versions are
  dropped and counted.
- **PyPI is out of scope.** 1 of 60 PyPI MAL packages remained resolvable —
  PyPI hard-deletes. Any PyPI arm would be a study of what survived deletion.

---

## 4. Controls

Matched case-control, **10 controls per case**, drawn from packages appearing
nowhere in the OSV `MAL-` corpus (not merely absent from the case list).

Each control is matched to its case **at the case's own T** on:

1. **download decile** — mandatory, not a nicety. Download count is the
   baseline that beat the composite on abandonment at all three dates. Leaving
   it unmatched hands the baseline the win by construction and the study would
   measure popularity.
2. package age
3. release count
4. scoped (`@org/name`) vs unscoped
5. calendar window — registry norms and attacker behaviour move fast

Matching on download decile means the study can no longer ask "does the score
beat download count." It asks the narrower question that remains: **within a
popularity stratum, does the score separate compromised from clean.** That
narrowing is deliberate and is stated wherever the result is reported.

---

## 5. Analysis unit: campaign-day, not package

Compromises are not independent events. In a 65-package sample there were
**16 distinct compromise days**, three of which held 49 of the 65
(2026-08-04: 21, 2026-05-19: 16, 2025-11-24: 12). Scope concentration runs in
parallel (`@antv` 15, `@servicetitan` 8).

**Every interval is clustered on campaign-day, or on scope where scope is
coarser.** Effective n is therefore ~244, not ~2,074, and **both numbers are
reported side by side** wherever an n appears. Reporting the nominal count
alone would overstate precision by roughly a factor of four.

*The 244 figure is extrapolated from the 65-package sample. The achieved
campaign count is reported as a result.*

---

## 6. Power, fixed against the effective n

At 10 controls per case, clustered:

| detectable AUC gap | positives needed |
|---:|---:|
| 0.10 | ~75 |
| 0.08 | ~120 |
| 0.05 | ~295 |

The abandonment gap was ~0.12–0.15. So ~244 comfortably detects an effect of
that size and is **underpowered below 0.05**.

**This is the number that makes the null ambiguous, and it is why §7 exists.**

---

## 7. What a null result means — fixed now, before it happens

**A null leaves the withdrawn claim withdrawn.**

The study is underpowered below a 0.05 gap. A null therefore does not
distinguish "no effect" from "an effect too small for this cohort," and
**neither reading supports reinstating anything.** "We could not detect it" is
not evidence of presence.

Specifically, on a null:

- `README.md` is unchanged. The claim stays withdrawn.
- The result is written up as a null with its power stated, in the same place
  and the same detail as a positive would have been.
- No further compromise backtest is run without a materially larger cohort or
  a different outcome. Re-running the same study hoping for a different draw
  is the failure mode this section exists to prevent.

---

## 8. What would reinstate a claim — also fixed now

A claim about compromise may be restored **only if all four hold**:

1. Full-model AUC exceeds the best trivial baseline by **≥ 0.05**, by a
   campaign-clustered paired bootstrap, 95% interval excluding zero.
2. The **negative control is clean** — labels shuffled within campaign-day,
   mean AUC within [0.47, 0.53]. The abandonment harness cleared this at all
   three dates; this one must too before any positive is believed.
3. The effect **survives the popularity matching**, i.e. it is not reproduced
   by download decile alone within the matched set.
4. The restored wording says **compromise**, cites this protocol and the
   achieved n and campaign count, and does not generalise to "risky
   dependencies."

Falling short of any one of these is a null under §7.

---

## 9. Named hazards

- **GHSA is an input to OSV.** Agreement between them is not replication and
  must not be reported as corroboration.
- **Detection bias.** A compromise is in the dataset because somebody found
  it. If popular packages are audited harder, the cohort over-represents
  popular packages — which is why §4 matches on downloads, and why an effect
  that vanishes under matching is a popularity effect.
- **Signals that leak.** npm `deprecated` is undated and applied retroactively
  to all versions; it must not be read at any past date. Same for PyPI
  `yanked` and GitHub `archived_at`. `validation-protocol.md` §2 has the full
  list of irrecoverable signals; this study inherits it.
- **Survivor bias in the famous cases.** `event-stream` and its peers are
  known partly because they were spectacular. They get no special weight.
- **Provenance is not in the scorer.** The one signal with a plausible causal
  path to a phishing-driven takeover (#328) is not currently measured. A null
  here is therefore a null about *the shipped sixteen signals*, not about the
  hypothesis that provenance predicts compromise.

---

## 10. Prior art, read before building

Zahan, Shohan, Harris & Williams, *Do Software Security Practices Yield Fewer
Vulnerabilities?*, ICSE-SEIP 2023 — https://arxiv.org/abs/2210.14884.
2,422 packages; OpenSSF Scorecard practice scores against reported
vulnerability counts. R² 0.09–0.12, **and the sign was positive**: more
good-practice indicators correlated with *more* reported vulnerabilities,
~+0.5 per unit of score, which the authors attribute to popularity
confounding.

It is cross-sectional rather than predictive, so it does not settle this
question. It is recorded here because it is the nearest published analogue,
it came out weak and backwards, and a protocol that omitted it would be
choosing not to know.

---

## 11. Staging, with a stop rule

Each stage produces a checkable artifact and the run **halts** if a stage
fails its own gate:

1. **Cohort.** Join the 2,074 version-pinned entries to packuments. Gate:
   report the achieved resolution rate and campaign count. **Stop if the
   campaign count is below 75** — the study is then unpowered for even a 0.10
   gap and running it would produce an uninterpretable null.
2. **Controls.** Build the matched set. Gate: matching balance reported per
   covariate. Stop if download deciles cannot be balanced.
3. **Negative control.** Shuffle labels within campaign-day. Gate: mean AUC in
   [0.47, 0.53]. **Stop if the harness cannot fail** — a harness that scores
   noise above chance invalidates everything after it.
4. **Trivial baselines**, within the matched set.
5. **Full model**, head-to-head against the best baseline.
6. **Ablations**, per signal.

Stages 3 and 4 run before stage 5 deliberately: if the baselines cannot be
beaten, that is a complete result and stage 5 does not change it.
