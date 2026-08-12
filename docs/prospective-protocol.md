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
reconstructed, so nothing saturates, and the instrument under test is the one
users actually run.

It also clears the fourth landscape requirement — *observable at the date
claimed* — trivially: the outcome is observed after the claim, not recovered
before it.

## 1. The claim under test

> The shipped composite, scored on the full instrument, identifies packages
> that go quiet over the next twelve months better than download count does.

**Download count is the comparator, not chance.** It has beaten this tool's
signals on every outcome where both were scored, and a model with the
composite's weights freed added nothing to it. Beating chance would settle
nothing.

## 2. Cohort, fixed now

**2,000 npm packages**, sampled uniformly from `all-the-package-names`,
**excluding every package in the 2026-08-06 snapshot** and every package in the
GHSA remediation cohort, so no package this project has already looked at can
enter.

Eligibility: at least one release before T, and a resolvable registry document.
Packages failing either are replaced by the next draw, and the replacement
count is reported.

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

Twelve months rather than the retrospective studies' two years: the base rate
will be lower and the study less powerful, and that is the price of an answer
in a year instead of never.

## 5. Falsification lines — fixed now

1. **If the composite does not beat download count by ≥0.03 AUC**, on a
   maintainer-clustered paired bootstrap with the interval excluding zero, the
   claim in §1 is not made. Given the record, this is the expected result.
2. **If the composite does not beat chance by more than the MDE**, that is
   reported as the headline: the shipped instrument, scored on its own terms
   with nothing saturated, does not discriminate.
3. **If fewer than 60% of packages yield a full-instrument score**, the study
   is reported as a registry-only study and §1's claim is not made, because the
   thing under test was not measured.
4. **If the base rate falls outside 5–60%**, the outcome is reported as
   too lopsided at this horizon and no AUC is claimed.

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
- **One ecosystem, one T, one horizon.**
