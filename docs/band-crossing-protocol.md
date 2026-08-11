# Does the one lead-capable signal actually move? — pre-registration

**Status:** pre-registered. Fixed and committed **before any packument was
fetched**; the order is checkable from git.
**Registers:** #378.
**Date fixed:** 2026-08-11, against `main` at d32ad1f.

---

## 0. What is already settled, and what is left

`lookup-table-result.md` printed the registry-only composite in full: a
**twelve-cell table** on maintainer band × repository state. `composition-result.md`
established it is not an activity proxy. `outcome-landscape.md` is closed.

§6 of `leading-indicator-protocol.md` then settled, analytically, that exactly
one input can move for a package that has gone quiet: the live tool reads the
packument's **top-level** `maintainers`, which `npm owner add/rm` mutates with
no publish. So `maintainer_count` — the only member carrying discrimination
against abandonment — is the tool's only **lead-capable** signal.

That is a statement about what *can* happen. **This measures what does.**

## 1. The claim under test, and the sharp version of it

> For packages that have gone quiet, the maintainer signal moves often enough
> to carry information.

The handover study measured that npm's maintainer *set* changes for **22.8%**
of packages in two years. That number has never been read as leading-indicator
capacity, and reading it that way is a mistake this protocol exists to avoid:

**The score only moves when the maintainer count crosses a band boundary.** The
bands are ≤1, 2, 3–4, ≥5. A package going from 27 maintainers to 28 changes its
set, changes its count, and **changes the score by exactly nothing**.

So the quantity that matters is not the set-change rate. It is the
**band-crossing rate**, and the gap between them is the point. This repository
has found that gap four times under other names — 2,074 compromise cases
collapsing to 43 campaign days, 30 provenance victims to 3, nominal rows to
effective clusters. **Nominal 22.8% is the number to be suspicious of.**

## 2. Method

**Harvest**, once, for the 2,906 cohort packages: the current packument's
top-level `maintainers`, `time.modified`, and the timestamp of the newest
release. Unauthenticated registry GETs, no credentials, no repository access.

**Compare** the current top-level maintainer set against the set frozen in the
version document in force at T = 2024-08-01, and record for each package:

- whether the **set** changed at all (the 22.8%-style number, for comparison)
- whether the **band** changed — the only change that moves a score
- whether the package **published anything after T** (if not, any band change
  is a score movement with no publish: the lead-capable event, observed)
- `time.modified` later than the newest release timestamp, a snapshot-visible
  lower bound on non-publish mutation that is independent of the comparison

**Report** the score delta implied by each band crossing, using the table in
`lookup-table-result.md`, so a "movement" is expressed in the units a user sees
rather than as a count of changed usernames.

## 3. Falsification lines — fixed now

1. **If the band-crossing rate among quiet packages is below 5%**, the signal
   does not move often enough to carry information about them, and the claim in
   §1 is not made. The tool's one lead-capable signal is lead-capable in
   principle and inert in practice.
2. **If band crossings among quiet packages are overwhelmingly in the
   risk-*decreasing* direction**, that is reported as the headline: a maintainer
   joining an abandoned package lowers its risk score, which is the opposite of
   a warning.
3. **If the set-change rate exceeds the band-crossing rate by more than 3×**,
   that ratio is reported beside every figure, because it is the collapse this
   repository keeps rediscovering and the 22.8% figure would otherwise be cited
   as capacity it does not have.
4. **If fewer than 60% of packages resolve**, the harvest is reported as
   unrepresentative and no rate is claimed from it.

## 4. What a confirmation licenses

*The maintainer signal changes the score for N% of quiet packages over two
years, in this direction.* One ecosystem, one T, one two-year window, and
nothing about whether those movements are **correct** — that is an outcome
question and the outcome programme is closed.

**It does not license "the tool gives early warning".** A signal that moves is
necessary for early warning and nowhere near sufficient. This measures the
necessary half only, and the write-up says so.

## 5. Named hazards

- **`npm owner` changes are not the only cause.** A maintainer set can change
  because a package was transferred, because a bot account was added, or
  because npm removed an account. This cannot distinguish them and does not
  try; the direction of the band crossing is reported instead.
- **Current state, not a series.** npm publishes no history of top-level
  maintainer changes, so this sees *changed by the harvest* and cannot date it.
  Same limit as the transfer study, and it is why line 1 is about a rate rather
  than a lead time.
- **A lead time is what a user actually wants and this cannot supply it.**
  Stated plainly rather than buried: knowing 12% of quiet packages had a
  maintainer change *at some point in two years* does not tell you whether the
  change came before or after anything mattered.

---

## 6. Amendment: the baseline was not T, and the bias ran the wrong way

Reviewed **4-3, below supermajority — rejected.** Three reviewers independently
found the same defect and it is decisive.

### The defect

The comparison baseline is the `maintainers` array in the version document in
force at T. **That array was frozen at that version's publish date, not at T.**
For a quiet package the two are by definition different, and can be years
apart: a package that last published in 2017 gets a 2017 baseline, and a
maintainer change in 2019 would have been counted as movement and reported
under "N% of quiet packages over two years".

The sharp part is what that does to the direction of the error. **The inflation
is maximal exactly in the subset the claim is about.** The quieter the package,
the older its baseline, the more pre-T drift leaks into the numerator — so
falsification line 1 was biased *toward* passing its own 5% bar. A
pre-registration may be biased in many ways; that is the one direction it must
never be biased in, and committing it to git first would only have laundered it.

This is the repository's fourth requirement — *observable at the date claimed,
not merely reconstructable* — applied to a study that thought it had escaped by
not having an outcome. That is now twice in a row.

### The primary quantity changes

**Band crossings per package-year**, with each package's window running from the
publish date of the version in force at T to the harvest — its actual exposure,
not an assumed two years. The baseline-age distribution is published beside
every rate, because a rate over an unstated window is the thing this amendment
exists to prevent.

**The headline stratum is packages whose last pre-T publish falls within six
months of T.** For those the baseline is close to T, the window is close to two
years, and the original claim is answerable as stated. Everything else is
reported as a per-package-year rate and is explicitly not the headline.

### Five more conditions, all adopted

- **The comparator is the active complement, not a bare 5%.** "Moves often
  enough to carry information" only means something against the rate at which
  the same signal moves for packages that are still publishing. An absolute
  threshold with no anchor is a number I chose.
- **"Inert in practice" is struck from line 1.** A two-snapshot design
  *lower-bounds* the numerator: a crossing that reverts before the harvest is
  invisible. Reading a lower bound as a substantive conclusion is precisely the
  observability-limit-into-finding move this repository keeps catching.
- **Maintainer accounts are clustered, and an effective n reported.** One bot
  added across hundreds of packages, or an npm mass-admin action, could
  manufacture the entire crossing rate. The 2,074-cases-to-43-campaign-days
  lesson, applied to this study rather than cited by it.
- **A datable validation subsample.** Packages that published both before *and*
  after T have maintainer changes datable from successive version documents.
  That subsample calibrates the undated top-level comparison and estimates the
  noise floor from bots and support actions, which is a floor with an argument
  attached rather than a round number.
- **Sets are compared by npm username only, never email**, and unresolved
  packages are reported as signal-correlated censoring rather than noise. The
  harvest resolved 2,906 of 2,906, so line 4 is moot — recorded because a
  future re-run may not be so lucky.

### What survived review

Two of the three attacks came back clean, and both matter.

**The undateable-change limit is not the transfer study's mistake.** That study
halted because event *identity* was contaminated — 41.3% of owner changes were
indistinguishable from renames. A band crossing is a **cardinality** change, and
cardinality is invariant to identity confusion: a rename, an email change or a
bot re-listing the same human cannot change the count. What dates would buy is
lead *time*, which the scope already disclaims.

**The quiet subset is not circular this time.** The previous study's subset was
defined by not-publishing and then tested for a property entailed by
not-publishing. Here the conditioning variable and the measured event travel
through **different mutation channels** — `npm owner add/rm` writes without a
publish — so no-publish neither guarantees nor forbids a band change. If
anything the selection biases *against* the claim, since quiet packages
plausibly see less owner churn than active ones.
