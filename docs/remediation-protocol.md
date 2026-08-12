# Does anything predict whether a CVE gets fixed? — pre-registration

**Status:** pre-registered. Committed before any predictor was joined to any
outcome; the order is checkable from git.
**Registers:** #382.
**Date fixed:** 2026-08-12, against `main` at 81b9d90.

---

## 0. Why this outcome, after abandonment

Abandonment was studied because it stands in for something: **if nobody
maintains a package, nobody patches it when a CVE lands.** That substitution
was never tested. This tests the thing itself.

It also escapes the trap that closed `outcome-landscape.md`. The five failed
outcomes failed on reconstructability, independence, power, or observability.
This one is **recorded by a third party at the time it happened** — OSV
publishes both the advisory and the version that fixed it — so the outcome does
not have to be reconstructed from state that has since moved.

## 1. Scoping, done before the design and it changed the design

The npm OSV corpus is **226,616 advisories**, and reading it naively would have
produced a spectacular and false headline.

| id prefix | advisories | packages | carry a `fixed` version |
|---|---:|---:|---:|
| **MAL** | 219,149 | 219,148 | **0.0%** |
| **GHSA** | 6,816 | 3,632 | **77.9%** |

**97% of the corpus is malicious-package takedowns.** A malicious package is
unpublished, not patched, so "was it fixed" is meaningless for it — and
including them yields "npm fixes 2.4% of its vulnerabilities", which is a
statement about malware reporting volume dressed as a statement about
remediation.

**The population is GHSA advisories only**, and MAL is excluded by rule rather
than by filtering after seeing a number.

## 2. The censoring problem, and the outcome that escapes it

A package that never publishes again **cannot** ship a fix. So "did a fix ship"
is censored by publishing activity, exactly as the maintainer-handover study
was — and that study died of it.

The difference is that here the coupling is **substantive rather than
spurious**: "abandoned packages never get patched" is the security consequence
we care about, not a measurement artifact. But it means the naive outcome would
largely re-derive the abandonment result rather than adding to it.

So there are two outcomes and the second is the point:

- **Outcome A — was the advisory ever fixed?** Expected to track liveness.
  Reported as the comparison, not the finding.
- **Outcome B — among packages that published at least one version *after* the
  advisory, did any version fix it?** This conditions on the *capability* to
  fix and asks about the *behaviour*. It is the genuinely new question:
  **given that a maintainer was still shipping, did they ship the patch?**

**B is the primary.** The gap between A and B is how much of "gets fixed" is
just "still alive".

## 3. Predictors, all as of the advisory's publication

Reconstructed from each package's packument at the advisory date: maintainer
count, whether a repository is declared, releases in the prior year, days since
the previous release, package age.

**Downloads are excluded from the primary.** They are the incumbent baseline
for abandonment and will be reported as a comparator, but npm's download API is
a rolling window and reconstructing it at an arbitrary past advisory date is
not something this harness can do honestly.

## 4. What conditioning on B costs, stated now

Outcome B conditions on post-advisory publishing, which is **a variable
downstream of the exposure** — a collider. Conditioning on it can induce
association between otherwise independent predictors.

This is accepted rather than solved, and it bounds the claim: B describes
**remediation behaviour among packages that were still shipping**, and nothing
about packages that were not. Both subsets are reported with their sizes.

## 5. Falsification lines — fixed now

1. **If fewer than 300 advisories survive to outcome B**, the study is reported
   as underpowered and no predictor claim is made.
2. **If no predictor beats chance on B by more than the clustered MDE**, the
   finding is that *nothing we measure predicts whether a still-active
   maintainer patches* — which is a result, and the one I expect.
3. **If B's base rate is above 95% or below 5%**, the outcome is too lopsided
   to discriminate and is reported as such rather than modelled.
4. **If A and B produce the same predictor ranking with the same magnitudes**,
   B added nothing and the study reports the abandonment result again rather
   than pretending to a new one.

## 6. What a positive would license

*Among npm packages that received a GHSA advisory and were still publishing
afterwards, this predictor identifies which ones shipped the fix.*

Not "the tool predicts security outcomes". One ecosystem, one advisory source,
and a population conditioned on having been noticed by a security researcher —
which is itself popularity-biased, and stated beside every figure.

## 7. Named hazards

- **The 4.7× popularity confound.** Packages get advisories partly because
  people look at them. The population is therefore not a random sample of npm,
  and no figure here generalises to packages nobody has audited.
- **`fixed` is OSV's claim, not an observation.** A version marked fixing may
  not fix; a package may fix without OSV recording it.
- **Advisory dates are unreliable for timing** — backfilled by a year or more
  in 22–43% of entries — which is why the primary outcome is **binary** and
  time-to-fix is not attempted.
- **Multiple advisories per package.** 6,816 advisories over 3,632 packages, so
  rows are not independent; everything clusters on package, not on advisory.
