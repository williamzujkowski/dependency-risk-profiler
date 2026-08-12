# The shipped instrument, scored prospectively — pre-registration

**Status:** pre-registered. Committed before any package was sampled.
**Registers:** #385.
**Date fixed:** 2026-08-12, against `main` at d9e0931.

---

## 0. Why this exists

**Every outcome study in this repository scored a degenerate variant of the
tool, not the tool.** At a reconstructed T, `staleness` was 1.0 for all 2,906
packages, `version` was 0.0 for all, and the six repository-derived signals
were never reconstructed at all. So the composite that scored **AUC 0.577
against abandonment** was a three-signal object. The shipped fifteen — now
thirteen after #339 — has never been scored against any outcome, and every
conclusion this project has drawn about it rests on that gap.

The prospective design closes it by construction. **T is now.** Nothing is
reconstructed, so the signals that saturated retrospectively are live — but see §13, where `version` turns out to be constant by construction — and the instrument under test is the one
users actually run.

It also clears the fourth landscape requirement — *observable at the date
claimed* — trivially: the outcome is observed after the claim, not recovered
before it.

## 1. The claim under test

> The shipped composite, scored on the full instrument, identifies packages
> that go quiet over the next twelve months better than download count **and
> better than its own `staleness` signal alone**.

**Download count is the first comparator, not chance.** It has beaten this
tool's signals on every outcome where both were scored, and a model with the
composite's weights freed added nothing to it. Beating chance would settle
nothing.

**`staleness` alone is the second comparator, and it is the one that decides
whether the instrument earned anything.** At a live T, `staleness` is time
since last release, and the outcome is *no release in the next twelve months*.
That is renewal-process autocorrelation: quiet packages tend to stay quiet.
Retrospectively `staleness` was saturated at 1.0 and contributed nothing to the
0.577; this design un-saturates precisely the most self-coupled signal in the
instrument. So the composite could beat download count while being **strictly
worse than a one-line `now - last_publish` query**, and the headline would read
as vindication of thirteen signals that a single subtraction outperforms.

**Both comparators must fall for the §1 claim to be made.** If the composite
beats downloads but not `staleness`-alone, the registered headline is: *the
thirteen-signal instrument is outperformed by one of its own inputs.*

A third arm, **composite-minus-activity** (`staleness` and `version` removed),
is recorded so that a win can be attributed rather than assumed.

## 2. Cohort, fixed now

**2,000 npm packages**, sampled uniformly from `all-the-package-names`,
**excluding every package in the 2026-08-06 snapshot** and every package in the
GHSA remediation cohort, so no package this project has already looked at can
enter.

Eligibility: at least one release before T, and a resolvable registry document.
Packages failing either are replaced by the next draw, and the replacement
count is reported. **No activity filter is applied** — filtering on recent
publishing would condition the cohort on `staleness` and reintroduce the exact
coupling this design exists to escape.

### 2.1 Stratification, fixed by measurement before sampling

The base-rate pilot (§2.2) found that **27.4% of a uniform npm draw has exactly
one release ever, and 85.2% of those are quiet.** That stratum is near-trivially
predictable: any arm carrying a staleness term scores it, and pooling it in
inflates every arm at once while telling a user nothing they did not know.

Analysis is therefore **stratified, with strata fixed now**:

| stratum | share (pilot) | 12-mo quiet rate | role |
|---|---:|---:|---|
| multi-release (≥2 releases at T) | 72.6% | **0.748** | **primary — the §1 claim is made here or not at all** |
| one-shot (exactly 1 release at T) | 27.4% | 0.852 | reported, never pooled into the headline |

Each stratum reports its own AUC, its own base rate, and its own paired deltas.
A pooled figure is reported alongside and is explicitly **not** the headline.

### 2.2 The base rate, measured before registration rather than assumed

`research/prospective/base_rate_pilot.py`, seed 20260812, disjoint from every
other harvest in this repo and excluded from the cohort. 500 uniform names,
registry-only, no clone. Result: 492 resolved, **12-month quiet rate 0.776**,
one-shot share 0.274, repository declared 0.628.

**This measurement voided the original §5 line 4 before a single package was
sampled.** That line guarded on the base rate falling in 5–60%; the true
uniform rate is 0.776, so the study would have declared itself too lopsided at
T+12 — after a year of waiting, on a design that is in fact adequately
powered. The guard tested the wrong quantity: AUC precision binds on the
**minority-class count**, not on which side of 50% the base rate sits. At
n=2,000 the minority class is ~447 packages overall and ~366 in the primary
stratum. Line 4 is respecified accordingly in §5.

The general lesson, and the reason this section exists: **a guard you could
have evaluated before registering and did not is not a falsification
criterion, it is a deferred mistake.**

## 3. What is recorded at T, and it must be the whole instrument

For every package: **all thirteen scored signals**, including the six that
require a cloned repository, plus the advisory lookup. A run that skips the
clone reproduces exactly the degenerate variant this study exists to escape,
so **a package whose repository cannot be cloned is recorded as such and
analysed separately** rather than scored on the registry alone.

Also recorded at T: **download count**, the comparator, and the maintainer set,
for clustering.

The scorer's configuration is hashed into the frozen record. A composite
re-weighted between registration and evaluation would otherwise be silently
substituted for the one under test.

## 4. The outcome

**Published no release in (T, T + 12 months].** Registry-only, so it needs no
clone at evaluation and cannot fail for want of a repository that has since
disappeared.

Twelve months rather than the retrospective studies' two years. Note the pilot
correction: the 12-month rate (0.776 uniform) is **higher** than the two-year
snapshot rate (0.405), not lower as §4 originally assumed — a shorter silence
is easier to achieve, and the two figures are also measured on different
populations.

**Edge cases, fixed now** — each is a distinct registry state, and none is
silently folded into "quiet":

| state at T+12 | disposition |
|---|---|
| whole package unpublished (`time.unpublished`) | **censored**, own category, excluded from AUC (0.4% in pilot) |
| all versions deprecated but package present | **quiet if no release in window** — deprecation is not a release |
| name transferred to npm security-holder | **censored**, own category |
| registry document no longer resolves | **censored**, own category |

`time.modified` is never read as a release: npm touches it on any write,
including an owner change, so it would score maintainer edits as publishing.

### 4.1 The uncloneable stratum

Clone failure correlates with the outcome, so the full-instrument subset is
conditioned on repo-alive and its AUC applies to a healthier-than-uniform
population. Registered now: the uncloneable packages are a **reported stratum
with their own base rate**, never imputed to a score and never dropped
silently. The pilot puts declared-repository share at 0.628, which bounds the
full-instrument yield before any clone is attempted — §5 line 3's 60% floor is
therefore live, not hypothetical.

## 5. Falsification lines — fixed now

All lines are evaluated **on the primary (multi-release) stratum**, on a
maintainer-clustered paired bootstrap with intervals excluding zero.

1. **If the composite does not beat download count by ≥0.03 AUC**, the claim in
   §1 is not made. Given the record, this is the expected result.
2. **If the composite does not beat `staleness`-alone by ≥0.03 AUC**, the
   registered headline is *the instrument is outperformed by one of its own
   inputs* — regardless of how line 1 resolves. This line was added at review;
   all seven voters named its absence, and it is the one that makes a positive
   result interpretable.
3. **If the composite does not beat chance by more than the MDE**, that is
   reported as the headline: the shipped instrument, scored on its own terms
   with nothing saturated, does not discriminate.
4. **If fewer than 60% of packages yield a full-instrument score**, the study
   is reported as a registry-only study and §1's claim is not made, because the
   thing under test was not measured.
5. **If the minority class in the primary stratum falls below 300**, no AUC is
   claimed. *(Respecified from "base rate outside 5–60%", which §2.2 measured
   as wrong before sampling: the uniform rate is 0.776 and the study is
   nonetheless powered. The binding quantity is the minority count.)*

## 6. What either result licenses

**A positive** licenses: *the shipped composite predicts twelve-month npm
abandonment better than download count, on one cohort, at one T.* Not that it
predicts compromise, and not that it generalises past npm.

**A null** is the more consequential outcome and is worth stating in advance:
it would mean the tool's central claim has been tested on the instrument users
actually run, prospectively, against the baseline that keeps beating it — and
failed. **That is the result this project has been unable to obtain for its
entire history, in either direction.**

## 7. Named hazards

- **Twelve months is a long time to be wrong in public.** The registration is
  committed now precisely so the analysis cannot be quietly redesigned when the
  data arrives.
- **The instrument may change under the study.** #408 would move the
  abstention bar; any change to the scored set invalidates the frozen
  configuration hash, and the study is re-registered rather than adjusted.
- **Clone failures are not random.** A package whose repository is gone is
  plausibly closer to abandonment already, so the full-instrument subset is not
  a random half of the cohort. Line 3 exists for this and the two subsets are
  compared on the registry-only signals they share.
- **The harvest clones ~2,000 self-declared repository URLs.** #388 established
  that no package↔repository binding check exists anywhere in this tool, so
  these URLs are attacker-controllable input and the clone step is bulk
  execution of `git` against them. Registered constraints: **https-only
  transport allowlist** (no `ext::`, `file://`, `ssh://`),
  `--no-recurse-submodules`, partial clone with hard size and wall-clock caps,
  and the working tree treated as hostile input by the six repo-derived
  collectors (symlink traversal, oversized packs, resource exhaustion).
- **One ecosystem, one T, one horizon.**

## 8. What is frozen, and when

Ordering is git-checkable, which is the only reason any of this is worth
writing down.

| artifact | frozen before | why |
|---|---|---|
| this protocol | any package sampled | the registration |
| base-rate pilot + result (§2.2) | this amendment | a guard evaluated after registration is not a guard |
| cohort name list | the T-snapshot harvest | membership cannot drift |
| scorer configuration hash | scoring | a re-weighted composite cannot be substituted |
| scorer code commit SHA | scoring | the configuration alone does not pin behaviour |
| **the analysis script** | **the T-snapshot harvest** | pre-registered criteria with unwritten analysis code is the forking-paths hole that survives twelve months |
| evaluation script hash | scoring | the last unfrozen degree of freedom |

### 8.1 Interim reads, outcome-blind

A twelve-month dead window with no checkpoints means a doomed run surfaces at
month twelve. Registered now: at **3, 6 and 9 months**, cumulative quiet-rate
and cohort-integrity reads only. **No AUC is computed and no arm is compared**
at any interim point. These exist so a base-rate surprise surfaces at month
three, and they license no claim.

## 9. Review record

Reviewed by seven-role `consensus_vote`: **approved 6-1 (85.7%)**. Every voter,
including all six approvals, named the same binding condition — the missing
`staleness`-alone comparator — and five named the base-rate pilot. The single
reject asked for re-registration with both fixes rather than approval with
conditions.

Both are now in the document, along with the clone-failure estimand, the
outcome edge cases, the frozen analysis script, the transport allowlist and the
outcome-blind interim reads. **The base-rate pilot ran before this amendment
and changed a falsification line**, which is the outcome the panel was asking
for: a criterion voided by measurement costs one afternoon, and voided by a
twelve-month wait costs a year.

## 10. Cohort drawn — an observation recorded before anything was scored

**2026-08-12.** 2,000 packages drawn, 50 rejected as ineligible, 7,978
already-seen packages excluded. `cohort_sha256`
`64c07197d078753e140fbd8a7b2bb3d85174205a2da3daf467d67c15fec36746`.

| stratum | n | declares a repository |
|---|---:|---:|
| **multi_release** (primary) | 1,345 | **0.602** |
| one_shot | 655 | 0.521 |
| all | 2,000 | **0.576** |

**§5 line 4 is on course to fire, and this is recorded now rather than after
the scoring run**, so the ordering is checkable from git.

The floor is 60% of packages yielding a full-instrument score. 57.6% of the
cohort declares a repository at all, and that is an **upper bound** — a
declared repository still has to clone. The primary stratum sits at 0.602,
which the clone step can only reduce.

**This is not a study failure. It is a measurement about the product**, and it
arrives before any AUC:

> The shipped instrument cannot be fully computed for a random npm package.
> Roughly **42% of npm packages declare no repository at all**, so the six
> repository-derived signals — the larger block of the composite's declared
> weight — are structurally absent, not merely missing.

Prior studies could not see this. They sampled from cohorts already filtered to
packages with reconstructable history, and they never attempted the repository
signals at all.

**No falsification line is being respecified here.** §2.2's base-rate guard was
rewritten *before* sampling, which is why that was legitimate; this one has
seen the cohort, and moving it now would be the forking-paths hole §8 exists to
close. Line 4 fires if the scored yield lands under 60%, and the consequence
registered in §5 stands.

## 11. Registered before scoring, after a 7-0 review of §10

The panel ruled unanimously on the §10 observation. Two amendments, both
committed **before the scoring run**, which is the only thing that makes the
second one legitimate.

### 11.1 The denominator ambiguity breaks against the author

§5 line 4 says "fewer than 60% of **packages**"; §5's scope sentence says all
lines are evaluated on the primary stratum. I wrote both and they do not agree.

Registered rule: **both denominators are reported, and line 4 counts as fired
if either reading fires.** When a registered line turns out ambiguous and the
author has already seen the cohort, the ambiguity has to break adverse to the
author, or pre-registration buys nothing. Reporting both preserves the
collision as evidence about the protocol instead of laundering it.

**A correction to §10, from the review.** Line 4 gates packages that *yield a
full-instrument score*, and **a declared repository is not a yielded score.**
§10's 0.602 is a declaration rate. The yield is lower by however many declared
repositories fail to clone, and that must be **measured, not extrapolated** —
the positive control's 1-of-8 is far too wide to stand in for it. §10 read the
gate on the wrong quantity, which is recorded rather than edited away.

### 11.2 A secondary analysis on the cloneable stratum

§4.1 registered the uncloneable packages as a reported stratum before sampling.
That licenses *reporting* them; it does not license promoting the cloneable
stratum to the population. So, registered here in advance:

**Secondary, conditional:** the full instrument scored on packages where it is
computable, reported with its own yield and base rate, answering *"conditional
on being computable, does the instrument discriminate?"*

Four constraints, fixed now:

1. **It can never rescue §1**, under any result. §1 is a claim about a uniform
   draw; this is a claim about a subpopulation.
2. **The selection is stated wherever the number appears.** Clone failure
   correlates with the outcome, so the surviving stratum is enriched for
   still-alive packages and the discrimination task is *easier*. Every sentence
   carrying this AUC carries that clause.
3. **Both comparators still apply.** Downloads and `staleness`-alone are scored
   on the same stratum. A conditional win over neither is still a loss.
4. **This design is data-inspired and it is dishonest not to say so.** The
   §10 yield numbers are what prompted it. It is outcome-blind — no outcome
   exists until 2027-08 — and it is registered before scoring, which is the
   most that can be claimed for it.

### 11.3 Why not halt

Halting was on the table and was rejected 7-0. The registry-computable signals
are measurable on the whole cohort, the cohort is frozen, and the outcome
accrues passively — the twelve-month wait is calendar time, not effort. And the
registry-only question is itself unanswered: *do the computable signals beat
downloads and `staleness`-alone on a uniform draw?* Nothing has measured that.

## 12. Scored at T — the measured yield, and line 4

**2026-08-12.** All 2,000 packages scored with the production collectors and
the production scorer. Scorer weights and code commit hashed into the record.

### Line 4 fires, under both registered readings

§11.1 registered *report both denominators, fired if either*. Both fire, so the
ambiguity I created never had to be resolved in anyone's favour.

| denominator | full-instrument yield | floor | |
|---|---:|---:|---|
| cohort (all 2,000) | **0.4640** | 0.60 | **fires** |
| primary stratum (multi_release, n=1,345) | **0.5056** | 0.60 | **fires** |
| one_shot (n=655) | 0.3786 | — | reported |

**Consequence, as registered in §5:** this is reported as a registry-only
study, and **the §1 claim is not made.** The conditional secondary registered
in §11.2 covers the 928 packages where the full instrument is computable, with
its selection stated.

§10 read the gate on a declaration rate and the review corrected it. Measured,
the declaration rate (0.576) overstated the yield by 11 points.

### Why the instrument could not be computed

| reason | n | share of cohort |
|---|---:|---:|
| **no repository declared** | 849 | **0.4245** |
| cloned, shallow-since fallback | 573 | 0.2865 |
| cloned normally | 355 | 0.1775 |
| **`auth`** — private, renamed or deleted, indistinguishable (#411) | 198 | 0.0990 |
| `git_error` | 15 | 0.0075 |
| `bad_slug` — rejected before reaching `git` | 7 | 0.0035 |
| `timeout` | 3 | 0.0015 |

Two readings worth stating plainly:

**Of the 1,151 packages that declare a repository, 198 (17.2%) do not resolve
to one.** A declared repository is a claim, not an artifact — and per #388
nothing in this tool checks the claim.

**Of the 928 repositories that did clone, 573 (61.7%) had no commit in thirteen
months.** They reached the working tree only through the `--shallow-since`
fallback. That is a reading about the population, not a defect: the fallback
case is the informative one.

### Abstention

**1,072 of 2,000 (53.6%) scored `insufficient_data` — and that figure is
WITHDRAWN (§14).** It measured the harvest's own omissions, not the tool: with
the four unmeasured signals actually collected, **not one package in the cohort
abstains**. The abstention machinery is not what this cohort exercised.

The count that stands from this section is the full-instrument *yield* (0.4640),
which is a clone-success question and is unaffected by which registry signals
were read. Line 4 fires on that, unchanged.

Incidentally corroborating #344: 744 HIGH against 20 CRITICAL.

### A registered constraint that was not enforced

§7 registered a "hard wall-clock cap" on clones. It did not hold. Python's
`subprocess.run(timeout=…)` kills `git` but not the `index-pack` grandchild,
and `capture_output` then blocks on a pipe the survivor still holds open — a
repository of vendored font binaries sailed past the 180-second cap and was
still running at 409 seconds. Fixed afterwards with `start_new_session` and a
process-group kill.

Recorded rather than quietly repaired, because the record was produced under
the unfixed version. The effect on the data is that three packages are marked
`timeout` and an unknown few large repositories took longer than the cap
allowed and then succeeded — which yields *more* data, not wrong data. But a
cap that does not cap is a stated bar with nothing enforcing it, which is this
repository's own dominant defect, in a paragraph I wrote about enforcement.

## 13. A saturated signal, found after scoring — §0's "nothing saturates" is wrong

**2026-08-12**, found while tracing why 701 packages score exactly 2.5000.

§0 says the prospective design means "nothing saturates". **That is false, and it
is corrected here rather than edited away.**

`version_score` is **0.0 for every package in the cohort.** Verified by
reproducing the production scorer over cohort rows: 300 of 300 sampled.

### Why, and why it is not fixable

The harvest scores each package as installed-at-latest. `version` measures
**drift between the installed version and the current release** — and for a
*package*, "installed version" does not exist. Version drift is a property of a
**consumer's pin**, not of the package being scored.

So this is not a measurement that was skipped. **It is a signal that is
structurally inapplicable to a package-level cohort**, and no sampling or
collection change would recover it. Any package-level study of this instrument
scores twelve informative signals and one constant.

### What it does and does not damage

**It does not invalidate the study.** `version` was 0.0 across the retrospective
cohorts too, the composite under test is the one users get, and the falsification
lines were never conditioned on it. The frozen record and configuration hash
stand.

**It does damage a sentence.** "Nothing saturates" was the design's headline
advantage over the reconstructions, and it is now one-thirteenth false. The
accurate claim is narrower and still worth making: **`staleness` and the six
repository-derived signals — the ones that made every prior study degenerate —
are live here.** `version` is not, and never can be, in a study of packages
rather than of manifests.

### The lesson, which is the same one again

The retrospective studies were degenerate because signals were constant at a
reconstructed date. This study was built to escape that, and shipped with a
constant signal anyway — arriving by a different route, from a modelling choice
about what "installed version" means for a package.

**Checking that the design escapes a known failure is not the same as checking
that the data did.** The check that would have caught it is mechanical: after
any harvest, print the distinct-value count of every scored signal before
computing anything. That is now the first thing this project should do to a
frozen record, and it is what found this — three studies too late.

### 13.1 Why it hid: the frozen record stores no per-signal scores

`scored-at-T.json` keeps the composite, the ablated composite, and the inputs
needed to re-derive them. It does **not** keep the thirteen per-signal scores.

So `research/prospective/saturation_check.py` — written in response to this,
and the mechanical check that should run first on any frozen record — reports
no constant fields when pointed at it. That is true of the fields present and
silent about `version`, which is exactly how the signal stayed invisible until
someone reproduced the production scorer by hand over cohort rows.

Recorded, not fixed: persisting per-signal scores now would mean re-cloning two
thousand repositories. The requirement for the next harvest is one line —
**store every scored signal, then run the saturation check before anything
else** — and the tool to do it now exists.

## 14. The harvest did not measure the full instrument. §3 said it would.

**2026-08-12**, found by running the §13.1 saturation check against a re-scored
record that persists every per-signal score. This is a deviation from the
registered protocol, committed by me, and it is recorded before any outcome
exists.

§3 registered: *"For every package: **all thirteen scored signals**, including
the six that require a cloned repository, plus the advisory lookup."*

Measured, across all 2,000 packages:

| signal | distinct values | why |
|---|---:|---|
| `exploit_score` | **1** (`None`) | **the advisory lookup was never performed** |
| `license_score` | **1** (`None`) | licence never fetched |
| `transitive_score` | **1** (`None`) | dependencies never resolved |
| `source_repository_score` | **1** (`None`) | `source_repository_state` never set — the harvest passed `repository_url` and bypassed the analyser that records provenance |
| `version_score` | **1** (`0.0`) | structural: a package has no installed version (§13) |
| `deprecation_score` | 2 | |
| `security_policy_score`, `dependency_update_score`, `maintained_score` | 3 each | |
| `staleness_score`, `maintainer_score`, `health_indicators_score`, `community_score` | 5 each | |

**Five of thirteen signals carry no information.** The harvest built its
`DependencyMetadata` from six registry fields and called the scorer directly,
rather than driving the production analyser that populates licence, advisories,
transitive dependencies and repository provenance.

### This is the exact failure the study exists to escape

The retrospective studies were degenerate because three signals were constant
at a reconstructed date. This study was registered to fix that, and its harvest
produced **five** constant signals — by a different route, from bypassing the
analyser rather than from reconstructing the past.

§13 recorded one constant signal and called it structural. That reading was
incomplete: **only `version` is structural.** The other four are omissions, and
three of them are fixable without re-cloning anything.

### What follows

The outcome is not readable until 2027-08, **so nothing is contaminated and the
fix is legitimate now** — the same reasoning that made §2.2's pre-sampling
rewrite legitimate and §11's post-cohort respecification not. No outcome
exists; there is nothing to fork paths toward.

- **Fixable now, no clone needed:** advisory lookup (OSV), licence (from the
  packument already fetched), `source_repository_state` (from the declared URL
  through the production recorder).
- **Fixable but expensive:** `transitive` needs dependency resolution.
- **Not fixable:** `version`, per §13.

Until that re-harvest lands, **the frozen record must not be described as the
full instrument.** It is an eight-signal object of which four vary well, and
any claim resting on "the shipped instrument was finally scored" is premature.
