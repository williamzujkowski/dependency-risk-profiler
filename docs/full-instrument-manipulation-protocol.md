# How much of the composite is attacker-controlled? — pre-registration

**Status:** pre-registered. Exact and offline; the answer is arithmetic over
the scorer's own weights plus a scoring run on constructed metadata.
**Registers:** #386.
**Date fixed:** 2026-08-11, against `main` at 3338bc9.

---

## 0. The sequel the last result implies

`manipulation-result.md` priced the **registry-only** arm: 88.4% of packages
can be scored downward, 83.5% with no publish, and the full scale costs five
npm accounts and one unverified URL.

That arm is three signals. The shipped tool has fourteen, and **eight of them
are read from a repository the package merely declares** — `record_source_repository`
assigns `DECLARED` to any URL that canonicalizes to `owner/repo` on a supported
host, with no check that the repository relates to the package.

So the registry-only price is an **upper bound on the cost**, and the real
question is how much cheaper the full instrument makes it.

## 1. The claim under test

> A single unverified URL field controls a large share of the composite's
> weight, because the eight repository-derived signals are computed from
> whatever repository that field names.

**Point `repository` at a healthy unrelated project and the tool clones *that*
project**, reads its tests, its CI, its security policy, its commit cadence,
its contributors — and scores the attacker's package on them.

## 2. What is computed

**The weight share**, from the scorer's own constructor rather than from a
table retyped here: the sum of weights for signals derived from the declared
repository, over the total.

**The realised drop**, by scoring constructed metadata through the production
scorer: a package with one maintainer and no repository, against the same
package declaring a repository whose eight derived signals all come back
healthy. The difference is what one URL buys.

Both are exact. There is no cohort, no sampling and no estimate.

## 3. Falsification lines — fixed now

1. **If the repository-derived weight share is below 25%**, the claim is not
   made: the declared-URL surface is a minority of the composite and the
   registry-only price stands as the headline.
2. **If declaring a healthy repository does not reduce the score by at least
   0.3 normalised**, the signals are reported as not materially manipulable
   through this channel, whatever their weight.
3. **If any of the eight signals turns out to verify the repository against
   the package**, that signal is excluded from the count and the claim is
   narrowed to the rest.

## 4. What this licenses

*This share of the composite's weight is computed from a URL the package
controls and nobody verifies, and declaring a healthy repository moves the
score by this much.*

It does **not** license "the tool is being gamed" — no evidence of exploitation
is offered or sought. It also does not say the eight signals are *wrong*: read
against a repository that genuinely belongs to the package they may measure
exactly what they claim. The finding, if it lands, is about **who chooses the
input**, not about the signals' construction.

## 5. Hazards

- **Constructed metadata, not a live clone.** This scores what the tool would
  compute given healthy repository signals; it does not clone anything. That
  is a fair model of the arithmetic and a poor model of whether a real
  substituted repository would produce uniformly healthy readings.
- **Detection is unmodelled.** A package pointing at `facebook/react` is
  trivially spotted by a human and by nothing in the tool.
- **The fix is not obvious.** Verifying the link between package and repository
  is possible in principle (npm provenance, a reciprocal reference in the
  repository) and neither is universally available, so a finding here is not
  a demand that this be closed tomorrow.
