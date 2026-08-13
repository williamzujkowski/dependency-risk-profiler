# Dangling repository links — pre-registration

**Status:** committed before any package was sampled.

## 0. Why

Stage two of the cross-ecosystem study measured that **roughly one declared
repository link in five no longer resolves** — 20% of npm attempts, 20% of
RubyGems, 16% of PyPI (`cross-ecosystem-result.md`).

#388 established that **41.51% of this tool's declared weight** is computed
from that link, and that nothing anywhere binds the link to the package.
Scorecard, Snyk Advisor and deps.dev read the same field.

A link that does not resolve is not merely unmeasurable. GitHub frees a
**renamed or deleted owner namespace** for re-registration, so a declared
`github.com/owner/repo` whose owner no longer exists is a name someone else can
take — and every tool in this class would then read the new occupant's
repository as the package's source.

This measures how much of that exposure exists. It does not test the attack.

## 1. The claim under test

> A material share of unresolvable declared repository links point at an owner
> namespace that no longer exists on the forge.

"Material" is fixed at **≥10%** of unresolvable links.

## 2. What is measured, and what is deliberately not

For each declared repository slug that failed to clone with `auth` — GitHub's
indistinguishable private / renamed / deleted response (#411) — a single
read-only call to `https://api.github.com/users/<owner>`:

- **404** — the owner namespace does not exist
- **200** — the owner exists, so the failure was privacy or repository-level
  deletion rather than a freed namespace

**Not measured, and not to be measured:** whether any namespace is actually
registerable, and nothing is registered, reserved, or requested. The study
stops at *"the owner does not exist"*, which is a public fact about a public
API and is where the responsible line sits. A count of freed namespaces is a
defensive measurement; a list of *claimable* ones is a target list.

**Not published:** individual package or owner names. Only aggregates, for the
same reason.

## 3. Cohort

The `auth`-failing slugs from the four ecosystems already sampled in
`cross-ecosystem-result.md` stage two — the same draw, so this describes the
population that study described. Roughly 120 slugs across four ecosystems.

## 4. Falsification lines — fixed now

1. **If under 10% of unresolvable links have a missing owner**, §1's claim is
   not made and the finding is *"unresolvable links are overwhelmingly private
   or deleted repositories under live owners"* — which is still worth
   publishing, and is the reassuring result.
2. **If fewer than 50 slugs are available to check**, no rate is claimed; the
   sample is reported as a count only.
3. **If the GitHub API rate-limits or errors on more than 20%** of checks, the
   run is reported as inconclusive rather than scaled up from the remainder.

## 5. What either result licenses

**Supported** licenses exactly one sentence: *"X% of unresolvable declared
repository links point at an owner namespace that no longer exists, so the
input carrying 41.51% of this tool's weight is, for that share, pointed at a
name nobody currently holds."* It does not license any claim about how often
this is exploited, which is not measured here.

**Refuted** is the better outcome for everyone and gets equal billing.

## 6. Hazards

- **`auth` conflates three states** (#411). A missing owner is a clean signal;
  a present owner is ambiguous between private and deleted-repo, and is
  reported as ambiguous rather than as "safe".
- **Owner-exists is not repo-exists.** A live owner with a deleted repository
  may also be re-creatable by that owner. Out of scope and stated.
- **This is a snapshot.** Namespaces are freed and taken continuously.
