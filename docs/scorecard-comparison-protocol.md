# This tool against OpenSSF Scorecard, on the same packages — pre-registration

**Status:** committed before any comparison was computed. The data was fetched
first; nothing below was calculated from it.

## 0. Why

`prior-art.md` compares this tool to Scorecard by **reading papers**. deps.dev
publishes Scorecard results per project, so the comparison can be a measurement
on the same packages instead.

This matters because the two instruments overlap heavily: Scorecard's checks
and this tool's repository-derived block cover close to the same ground —
branch protection, signed releases, CI, dependency-update tooling, maintenance.
This repository retired two of those signals after measuring them (#394), and
those findings were about *this* implementation of checks that are Scorecard's
checks.

## 1. The claims under test

Both are about **agreement**, not accuracy. Neither instrument has a validated
outcome on this cohort, so nothing here can say which is *right*.

1. **The two scores agree.** Spearman ρ between this tool's composite and
   Scorecard's overall score, on packages where both are computable.
2. **The overlapping checks agree.** For each Scorecard check with a
   counterpart here — `Maintained`, `Security-Policy`, `CI-Tests`,
   `Dependency-Update-Tool` — agreement between Scorecard's per-check score and
   this tool's corresponding signal.

## 2. Falsification lines — fixed now

1. **If |ρ| < 0.2**, the instruments are measuring different things despite
   overlapping inputs, and that is the finding. It is the result I expect.
2. **If ρ > 0.7**, they are near-substitutes, and the interesting question
   becomes which is cheaper rather than which is better.
3. **If fewer than 300 packages carry both scores**, no ρ is claimed. Scorecard
   only runs on repositories it can reach, so coverage is bounded by the same
   declaration ceiling measured in `cross-ecosystem-result.md` — and a thin
   overlap is itself worth reporting.
4. **Sign convention must be stated before reading.** This tool scores *risk*
   (higher is worse); Scorecard scores *health* (higher is better). A negative
   ρ is agreement. Getting this backwards would invert the headline, and the
   additive study already shipped one polarity error of exactly this shape.

## 3. What neither result licenses

**Agreement is not correctness.** Two instruments reading the same unverified
repository link can agree perfectly and both be wrong — and Zahan et al. found
Scorecard correlating *backwards* with vulnerability counts, so its own
validation record is no better than this tool's.

**Scorecard coverage is not random.** It runs where a repository is reachable,
which is the same 41.5–57.8% ceiling this project measured. Any ρ is
conditional on that subset.
