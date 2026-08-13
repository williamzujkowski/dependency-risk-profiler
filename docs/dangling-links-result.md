# One in five dead repository links points at a freed owner namespace

**Result for `docs/dangling-links-protocol.md`**, committed before any package
was sampled.

## The result

Of the declared repository links that failed to clone with `auth` — GitHub's
indistinguishable private / renamed / deleted response (#411) — across the four
ecosystems already sampled in `cross-ecosystem-result.md`:

| | |
|---|---:|
| distinct owners checked | 118 |
| API errors | **0** |
| **owner namespace no longer exists** | **25** |
| owner still exists | 93 |
| **share** | **0.212** |

§1's threshold was 10%. **Line 1 is met.**

## What that compounds to

| | |
|---|---:|
| declared links that fail with `auth` | 120 / 800 = **0.150** |
| of those, owner namespace missing | 25 / 118 = **0.212** |
| **⇒ declared links pointing at a freed owner namespace** | **≈ 3.2%** |

Both numbers belong in any statement of this. **21.2%** is the striking one and
is conditional on the link already being dead; **3.2%** is the share of all
declared links, and is the one that describes exposure.

> Roughly one declared repository link in thirty points at an owner namespace
> that no longer exists on the forge. For those packages, the field carrying
> **41.51% of this tool's declared weight** (#388) — and read identically by
> OpenSSF Scorecard, Snyk Advisor and deps.dev — refers to a name nobody
> currently holds.

## Per ecosystem, the dead-link rate that feeds it

| ecosystem | `auth`-failing share of declared links |
|---|---:|
| npm | 0.200 |
| RubyGems | 0.195 |
| PyPI | 0.155 |
| **Packagist** | **0.050** |

Packagist again, and the same explanation as stage two: an ecosystem whose
package identity *is* a VCS coordinate has links that are load-bearing for
installation, so they cannot rot unnoticed.

## What this is not

**It is not a claim that anything has been exploited**, or that any namespace
is registerable. Neither was measured. The study makes one read-only call per
owner asking whether it exists, and stops there.

**No package or owner names are published**, and none are in the artifacts —
only counts. That is deliberate and is stated in the protocol:

> A count of freed namespaces is a defensive measurement; a list of claimable
> ones is a target list.

`research/cross_ecosystem/dangling.py` returns aggregates by construction for
that reason.

**A live owner is not a clean bill of health.** 93 of 118 owners still exist,
but `auth` conflates private-repository and deleted-repository under a live
owner, and a deleted repository may be re-creatable by that owner. That
ambiguity is GitHub's by design (#411) and is reported as ambiguity rather than
as safety.

## The first run refused to report a number, and that was correct

The initial run fired **§4 line 3** — 59 of 118 owner checks errored, a **50%**
error share against a 20% ceiling, because the unauthenticated GitHub API
allows 60 requests an hour.

It would have reported 20.3% from the surviving half, which is within a
rounding error of the true 21.2% — and that near-miss is the argument for the
guard rather than against it. The gaps were rate-limit errors, which arrive in
bursts and are not random with respect to the order checked. Being *nearly
right by luck* is not the same as being right, and the protocol had no way to
know which it had.

Re-run with a read-only token: **0 errors, 118 of 118 checked.**

## Limits

- **A snapshot.** Namespaces are freed and taken continuously.
- **118 owners.** The share has a 95% interval of roughly ±7 points, so "about
  a fifth" is the right precision and "21.2%" should not be quoted alone.
- **GitHub only.** Declared links on other forges were excluded upstream, and
  their namespace-reuse policies differ.
