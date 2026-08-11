# Maintainer handover — pre-registration

**Status:** pre-registered and **revised once, before any harvest**, against a
5-2 consensus review. Six of seven reviewers independently identified an
exposure-window confound the first draft missed and asserted was absent; §3
now measures it and §5 adds a baseline that settles it. The revisions are
listed in §11. Nothing here was written after seeing an outcome.
**Registers:** the corrected design from #342. Third protocol, after
`validation-protocol.md` (abandonment) and `compromise-backtest-protocol.md`
(halted at its gate).
**Date fixed:** 2026-08-11, against `main` at ec6609e.

---

## 1. Why a third outcome at all

Two outcomes have been tried. Abandonment ran and the composite lost to
download count at every date. Compromise was pre-registered and halted — 43
independent campaign-days against a threshold of 75.

This one exists for a reason neither of those can satisfy: **it is the first
outcome that admits `staleness` and `version`.** Those two signals have never
been tested against anything. They were excluded from the abandonment study by
design, because low release cadence predicting the future absence of releases
predicts a variable from itself. Against a handover, there is no such
tautology — a package going quiet and a package changing hands are different
events, and whether the first predicts the second is a real question.

Three of sixteen signals have ever been tested. This would make it five.

## 2. The claim under test

> Leading indicators measured at T — release cadence, version drift, maintainer
> concentration, declared provenance — identify packages whose **maintainer set
> changes** by T + 2 years, better than trivial baselines do.

This is narrower than either withdrawn claim and it is not a compromise claim.
A handover is not an attack. #312's reading is the one being tested: the tool
may measure the *precondition* for a handover rather than a compromise.

## 3. The outcome, and the trap it was designed around

**Positive** = the maintainer set frozen into the release in force at T differs
from npm's **current top-level `maintainers`** array at the harvest.

The obvious version of this outcome does not work, and #342 measured why.
Comparing two *version documents* — at T and at T + 2y — is **perfectly
censored by publishing activity**:

| releases published after T | n | changed | rate |
|---|---:|---:|---:|
| **0** | **1,176** | **0** | **0.000** |
| 1–2 | 444 | 55 | 0.124 |
| 11+ | 783 | 283 | 0.361 |

A maintainer change is only visible through a new release, so 40% of the
cohort cannot exhibit the outcome, and the censored set is **exactly** the
abandonment positive class — 0 of 2,906 packages are both abandoned and
recorded as changed. A package that goes quiet and then quietly changes hands,
which is the event this outcome most wants to see, records as *abandoned,
maintainers unchanged*.

The top-level array is **current state**, so it is readable whether or not
anything was published. That is the whole reason for the design.

**Calibration, run before this was written**, in two parts because one is not
enough:

1. *Semantics.* For 15 packages that published since 2026-06-01, the maintainer
   set frozen into the latest release equals the current top-level set in 15 of
   15. Deliberately run on fresh releases: recency is what isolates a schema
   mismatch from a real change, since an old release that disagrees is
   ambiguous between the two.
2. *Format stability across eras.* The first check only proves the schemas
   agree **today**. npm's version-document shape could have differed a decade
   ago, which would make old frozen sets incomparable. Across 15,105 parsed
   identifiers spanning 2008–2024 buckets, all but two are username-shaped, and
   both exceptions (`'pooh!'`, `'Marc Görtz'`) are genuine odd account names
   rather than schema drift.

Without both, the study could report a spurious change rate and look like a
strong result.

### The exposure-window confound, measured rather than argued

Consensus review raised this and it is the sharpest objection to the design:
the frozen set comes from **the release in force at T**, not from T itself. For
a stale package that release predates T, so the comparison window is
`[last pre-T release, harvest]` — length `2y + staleness at T`. Under a
constant handover hazard independent of staleness, staler packages would still
show more changes, purely because they were exposed for longer. That would let
`staleness` re-derive its own exposure time, which is the tautology family this
outcome exists to escape.

**Measured on the actual cohort at T = 2024-08-01, n = 2,906:**

| | years |
|---|---:|
| min | 2.02 |
| p10 | 2.02 |
| median | 2.30 |
| p90 | 2.86 |
| max | **3.01** |

**p90/p10 = 1.4×**, not the order of magnitude the objection assumed, and
nothing exceeds 3.01 years. The reason is cohort eligibility: a package must
have released within 365 days of T to be eligible at all, so staleness at T is
capped by construction and cannot reach the multi-year values that would make
this severe.

The confound is therefore real but bounded. It is **not** waved away on that
basis — §5 adds exposure-window length as a trivial baseline the model must
beat, which converts the argument into a measurement.

### What the outcome cannot do, fixed now

- It says **"changed by the harvest"**, not "changed within a fixed window".
  So it runs at **one T only**, chosen as `harvest − 2y` = **2024-08-01**.
  There is no multi-date replication available, and that is a real weakness
  next to the abandonment result's three dates.
- It **cannot see a change that reverted** within the window.
- It **conflates benign growth with handover**. A project adding a second
  maintainer and a project changing hands are both positives. Sub-definitions
  are reported alongside the primary and fixed here:
  `any change` / `gained` / `lost` / `both gained and lost` / `complete
  turnover`.
- **`complete turnover` is underpowered and is not a primary outcome.** From
  version documents it ran at 10–13 events per date. It is reported for
  completeness and no claim rests on it.

## 4. Signals

Admissible: `maintainer`, `source_repository`, **`staleness`**, **`version`**.

Excluded and why:

- `license` — leaving the scored composite entirely (#340); it is harmful on
  abandonment in 7 of 7 runs.
- `deprecation` — npm applies it retroactively to all versions, so it leaks.
- `exploit` — no advisory source is asked.
- `transitive` — npm freezes direct dependencies, not the closure the scorer
  reads.
- the eight repository-derived signals — no clone (#339).

## 5. Baselines and analysis unit

The abandonment pilot's four trivial baselines — downloads at T, stars, package
age, dependency count — **plus a fifth added for this outcome**:

5. **`exposure_window_days`** — days from the frozen release to the harvest.

The fifth exists because of the confound above. If `staleness` predicts
handover only through the length of its own observation window, it will fail to
beat this baseline, and under falsification line 3 **that is the finding**. It
is the cheapest possible way to settle the objection: one column, and the model
either clears it or does not.

Download count remains the baseline that matters most — it beat the composite
at every date on abandonment.

**Clustered on maintainer**, as the abandonment pilot is. That matters more
here than there: the outcome *is* about maintainers, so packages sharing one
are emphatically not independent.

**Effective cluster count, not raw positives, governs power.** The compromise
backtest died precisely on this distinction — 2,074 nominal cases collapsed to
43 independent campaign-days — and a raw positive count would have hidden it
there too. Both numbers are reported wherever an n appears, and the stop rule
in §10 is written against the effective count.

## 6. Falsification lines — fixed now

1. **If the full model does not exceed the best trivial baseline by ≥ 0.05**,
   by a maintainer-clustered paired bootstrap with the 95% interval excluding
   zero, the claim in §2 is not made. Primary line.
2. **If the negative control is not clean** — labels shuffled within
   maintainer cluster, mean AUC outside [0.47, 0.53] — nothing from the run is
   reported at all. The harness is wrong before the result is interesting.
3. **If `staleness` or `version` individually carry the whole effect**, that is
   reported as the finding rather than folded into a composite claim. The
   point of this study is to test those two, not to launder them.

## 7. What a null means — fixed now, before it happens

**A null leaves both withdrawn claims withdrawn**, and adds one fact: cadence
and drift do not predict handover either.

This can be a *useful* null, unlike the compromise study's, but only under
conditions that are fixed here rather than decided afterwards.

**The claim is scoped to the operationalisation, not the construct.** A null
means "a change in npm's top-level maintainer list, at this T, is not predicted
by these signals above the minimum detectable effect." It does **not** mean
"handover is unpredictable." Those are different statements and only the first
is licensed.

**The minimum detectable effect is stated with the result, not implied.** An
effect smaller than the MDE is not an absence; it is an effect this study could
not see.

**Two unmeasured error rates can turn a null into an artefact**, and both must
be bounded before the phrase "evidence of absence" is used at all:

- **npm account renames** read as changes — false positives.
- **GitHub-side ownership transfer with no npm owner change** reads as no
  change — false negatives.

Non-differential misclassification attenuates towards the null, so an
unbounded error rate makes a null uninterpretable. Before any absence claim:
hand-audit a sample of ~50 positives for renames and estimate the false-negative
rate. **If the estimated misclassification exceeds 10%, the null is reported as
uninformative rather than as absence.**

No result from this study licenses any claim about compromise.

## 8. What would license a claim

All four:

1. ≥ 0.05 over the best trivial baseline, clustered, interval excluding zero.
2. Clean negative control.
3. The effect survives reporting the sub-definitions — if it exists only for
   `gained a maintainer`, the claim is about team growth, not handover, and
   must say so.
4. Wording names **handover**, cites this protocol and the single T, and does
   not generalise to "risk".

## 9. Named hazards

- **Popularity confounds the outcome directly.** Popular packages have more
  maintainers and more churn. The download baseline is the control for this and
  an effect that vanishes against it is a popularity effect.
- **One T, no replication.** The abandonment result earned its weight from
  three dates. This one cannot have that, and the write-up says so wherever the
  result appears.
- **Ownership transfer without an npm change.** A project can change hands on
  GitHub while the npm owner list stays put. Those are false negatives and
  their rate is unmeasured.
- **npm account renames** would read as a change. Rate unmeasured; if the
  positive rate comes in far above the ~14.5% seen from version documents,
  suspect this before believing the result.
- **`staleness` carries a star dampener**, so it is partly a popularity signal
  already. Report it ablated both ways.

## 10. Staging, with a stop rule

1. **Harvest** the current top-level `maintainers` for the cohort, from
   `registry.npmjs.org` only. **No mirror** — npmmirror's per-version endpoint
   is a semver *resolver* that silently returns a different version's data, and
   measuring from it fabricates results (#335). Scoped names are URL-encoded;
   each record is archived as the extracted `maintainers` array plus a
   **SHA-256 of the raw response body**, following the `raw_sha256` convention
   the abandonment snapshot already uses (§11 amendment 1).
   Gate: report the resolution rate. **Stop if under 90%** — below that the
   study is about packages that still exist, which is a different question.
2. **Base rate and effective n.** Gate: **stop if the positive count is under
   200, or if positives span fewer than 150 maintainer clusters.** The second
   half is the one that matters; the compromise study cleared a raw-count bar
   and died on the effective one.
3. **Negative control**, before any model result is looked at.
4. **Trivial baselines**, including `exposure_window_days`. **Stop and report
   if they cannot be beaten** — that is a complete result.
5. **Full model**, head-to-head.
6. **Ablations**, per signal, with `staleness` and `version` reported
   individually because they are the reason this study exists.
7. **Misclassification audit** before any absence claim, per §7.

**Sensitivity, not replication:** the same harvest supports frozen sets at
T = harvest − 18 months and − 30 months. Those share the current-state
comparator so they are not independent replications, and they are reported as
sensitivity only. It remains true that this design cannot deliver what three
dates delivered for abandonment.

---

## 11. What the review changed, and what it did not

The first draft went to consensus before any harvest and came back 5-2. Both
rejections, and four of the five approvals, named the same defect. Recording it
because a pre-registration that hides its own revision history is not one.

**The defect.** The draft asserted "against handover there is no such
tautology" and stopped there. Six reviewers pointed out that the frozen set is
stamped at the last release *before* T, so the observation window is
`2y + staleness`, and `staleness` could predict the outcome through its own
exposure time. The contrarian put it plainly: as specified, the study could not
deliver its stated primary purpose.

**What changed:**

1. §3 measures the confound instead of asserting it away. It is bounded —
   2.02 to 3.01 years, p90/p10 = 1.4× — because cohort eligibility caps
   staleness at T. The reviewers assumed multi-year spreads; the eligibility
   rule prevents them. That is a correction *to* the objection, not a dismissal
   of it.
2. §5 adds `exposure_window_days` as a fifth trivial baseline the model must
   beat. This is the fix: it converts the argument into a number.
3. §5 changes the power unit from raw positives to **effective maintainer
   clusters**, and §10 gates on 150 of them. This is the trap that killed the
   compromise study, which cleared a raw-count bar and died on the effective
   one.
4. §7 scopes "evidence of absence" to the operationalisation, requires the MDE
   to be stated, and **bounds the two unmeasured error rates** — with a
   pre-registered 10% ceiling above which a null is reported as uninformative.
5. §3 adds a second calibration for identifier format across eras, because the
   first one used only fresh releases and so could only prove the schemas agree
   today.
6. §10 pins the registry, forbids mirrors, and archives raw packuments.

**What did not change.** The single-T limitation stands. Reviewers were split
on whether it is disqualifying; it is not being argued away, and the write-up
will carry it wherever the result appears. The offered sensitivity runs at
other frozen T share one comparator and are not replication.

**The review is the reason this is worth anything.** The confound was
identified before a single packument was fetched, which is the entire purpose
of circulating a protocol rather than a result.

### Amendment 1 — archival format, 2026-08-11, before any harvest

The merged text said "raw packuments are archived so the analysis is
re-runnable and auditable." That is not committable. A single packument
carries every version's metadata: `react` is **6.7 MB**, `express` 786 KB. The
cohort is 2,906 packages, so the literal instruction is gigabytes in git.

Amended to the convention this repository already uses for exactly this
problem: store the extracted field plus a **SHA-256 of the raw response body**,
as `PackageRecord.raw_sha256` does in the abandonment snapshot. Anyone can
re-fetch and verify they received the same bytes, which is what auditability
required; the multi-gigabyte copy was never what made it auditable.

**This is a mechanical amendment, not an analytical one.** It changes where
bytes are kept. It does not touch the outcome definition, the baselines, the
falsification lines, the stop rules or what a null means — and it is recorded
here, before the harvest, rather than discovered later as a discrepancy
between the protocol and what was done.
