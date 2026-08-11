# What does it cost to game the score? — pre-registration

**Status:** pre-registered. Exact and offline; there is no sampling and no
estimate, so the "result" is arithmetic over a table already published.
**Registers:** #382, the synthesis epic. (No number was predicted this time:
the last protocol guessed one and cited its own pull request.)
**Date fixed:** 2026-08-11, against `main` at 712bf0b.

---

## 0. Why this exists, and why it is owed

`lookup-table-result.md` printed the registry-only composite in full: twelve
cells on maintainer band × repository state. That was the right thing to
publish — an auditable scorer is better than an opaque one.

**An enumerated scoring function is also an instruction manual.** Having
printed it, the honest next step is to price the moves it makes available,
rather than leave that arithmetic to whoever does it next.

A review panel named this as a surface the seven prior studies had not touched:
every one of them asked whether the score *tracks* something. **None asked
whether it can be *moved*.**

## 1. The two actions, and the asymmetry that matters

**Declare a repository URL.** `record_source_repository` assigns `DECLARED`
when the URL canonicalizes to an `owner/repo` root on a supported host. It does
**not** verify that the repository has any relationship to the package — a
fork, an empty repo, or `facebook/react` all qualify. Requires a publish,
because the field lives in the version document.

**Add maintainer accounts.** npm accounts are free, and `npm owner add` mutates
the packument's top-level array. **No publish required** — which is the
interesting half, because a package whose ownership has just changed hands is
one an attacker may prefer not to touch.

## 2. What is computed

For every occupied cell: the largest score reduction reachable, the number of
accounts it costs, and whether it needs a publish — reported twice, once with
publishing allowed and once without. Weighted by cohort occupancy, so the
answer is "what share of real packages can be moved", not "what does the table
permit in principle".

## 3. Falsification lines — fixed now

1. **If the repository field turns out to be verified against the package**,
   the headline claim is withdrawn: the cheaper of the two actions is not
   available and only the maintainer axis is manipulable.
2. **If fewer than 25% of packages can be moved without a publish**, the
   no-publish asymmetry is reported as a curiosity rather than a finding.
3. **If the largest single reduction available for under ten accounts is below
   0.25**, the scale is reported as resistant to cheap manipulation.

## 4. What this licenses, and what it does not

It licenses a statement about **cost**: *this many accounts and this action
move a package this far down the scale.*

It does **not** license "the tool is being gamed" — no evidence is offered that
anyone has done this, and none is sought. Nor does it say the scorer is unusual:
most repo-health scores read self-declared metadata. What it says is what the
price is, which is a thing the project can now state precisely and previously
could not.

## 5. Hazards

- **Only the registry-only arm.** The eight repository-derived signals (#339)
  are untested here and might make manipulation harder or easier; nothing in
  this study speaks to them.
- **Cost is counted in accounts and publishes**, not in effort or risk of
  detection. Creating npm accounts at scale may trip anti-abuse controls this
  analysis cannot see.
- **The direction of "worse" is the scorer's.** More maintainers reads as lower
  risk, which is a modelling choice, not a fact — and it is exactly the choice
  a Sybil attack exploits.
