# Repository-derived scoring is computable for 56–74% of packages, and it depends on the ecosystem

**Result for `docs/cross-ecosystem-protocol.md`**, committed before any package
was sampled. #425.

Four ecosystems, 1,000 packages each, uniform samples from full published name
lists, seed 20260813. Each package's repository state comes from **that
ecosystem's own production resolver** (§3), not from a definition written for
this study.

No outcome is involved. This measures whether a score can be computed at all.

## The result

| ecosystem | sampled | resolved | resolution rate | **declares a usable repository** | declares none |
|---|---:|---:|---:|---:|---:|
| **npm** | 1,000 | 979 | 0.979 | **0.558** | 0.395 |
| **PyPI** | 1,000 | 969 | 0.969 | **0.673** | 0.311 |
| **RubyGems** | 1,000 | 1,000 | 1.000 | **0.741** | 0.234 |
| Packagist | 1,000 | 773 | 0.773 | 0.994 | 0.000 |

**Spread across the three comparable ecosystems: 18.3 percentage points**,
against a registered threshold of 15. §1's claim is supported.

> Across npm, PyPI and RubyGems, a repository-derived score is computable for
> **56% to 74%** of packages. Between a quarter and nearly half of every
> ecosystem is out of reach of the entire class of tool.

## Packagist tripped two pre-registered guards, and §7 said it would

- **§5 line 2** — resolution 0.773, below the 0.80 floor. 227 of 1,000 sampled
  names did not resolve at `repo.packagist.org`, so the name list and the
  registry disagree and the sample is not what it claims to be.
- **§5 line 3** — 0.994 declared, above the 0.95 ceiling.

Both were anticipated: §7 recorded in advance that *"Packagist is
repository-first by construction and will likely score highest for exactly that
reason"*, and pre-registered it so a high number could not later be presented
as a surprise.

It is reported here and excluded from the comparison. **The finding does not
depend on that exclusion** — the spread is 18.3 points without Packagist and
43.6 with it, and clears the threshold either way.

Packagist's 0.994 is still worth stating, because it is the useful contrast:
an ecosystem whose package identity *is* `vendor/name` from a VCS has no
repository-declaration problem at all. The gap is a property of registry
design, not of maintainer diligence.

## An independent replication fell out of it

npm's declared share here is **0.558**. The #385 cohort — a different seed, a
different draw, 2,000 packages instead of 1,000, and 2,500 names excluded —
measured **0.576**.

Two independent uniform samples of npm agreeing to within 1.8 points is the
best evidence available that the sampling frame is not doing something strange,
and it was not designed as a check. It arrived because the exclusion list made
the two draws disjoint.

## What this bounds, beyond this tool

OpenSSF Scorecard, Snyk Advisor and deps.dev all depend on the same declared
repository link (`prior-art.md` §2). Scorecard cannot run its checks on a
package with no repository any more than this tool can.

So the ceiling is shared, and none of them publishes it:

> For roughly a quarter to two-fifths of packages, depending on ecosystem,
> **every repository-derived scoring system is unable to compute most of what
> it claims to measure** — and the tools report a score anyway.

This is a bound on four tools at once, derived without any outcome, and it does
not decay.

## What it does not license

**Nothing about whether the computed scores are any good.** That is the
question this repository has spent ten studies failing to answer in its own
favour, and this study deliberately does not touch it.

**Declaration is an upper bound, not the yield.** npm declared 0.558 here and
yielded **0.464** once cloning was actually attempted (`what-this-tool-is.md`
§2) — a further 9 points lost to repositories that are declared and do not
resolve. The per-ecosystem clone stage is registered as stage two and has not
been run. Nothing here should be read as if it had.

**Four ecosystems, one draw, one date.**

---

## Stage two — clone yield, and the exact bound

Registered in §8 before running: 200 declared packages per ecosystem, drawn
from stage one's own sample, clones deleted after probing.

| ecosystem | declares | **clones, of declared** | **computable** |
|---|---:|---:|---:|
| **npm** | 0.558 | 0.745 | **0.415** |
| **PyPI** | 0.673 | 0.765 | **0.515** |
| **RubyGems** | 0.741 | 0.780 | **0.578** |
| Packagist | 0.994 | 0.900 | 0.894 |

> **A repository-derived score is fully computable for 41.5% to 57.8% of
> packages** across npm, PyPI and RubyGems. For the rest — between two-fifths
> and three-fifths of each ecosystem — the repository block cannot run, and
> every tool in this class reports a score anyway.

### Declaration is the binding constraint, and the numbers say so cleanly

| | spread across the three |
|---|---:|
| declaration rate | **18.3 points** |
| clone success, given declaration | **3.5 points** |

Clone success is nearly uniform — 0.745, 0.765, 0.780 — while declaration
varies by five times as much. **Ecosystems differ in whether maintainers
publish a repository link, not in whether the published links work.**

§8's line 5 asked whether clone success would exceed 95% everywhere, in which
case stage two would be a footnote. It does not (it is ~78%), so the level of
the bound genuinely moves — but the *ordering* is unchanged and the mechanism
is declaration, which is what §8 named as the alternative worth stating in
advance.

### Packagist again, and the same explanation fits

0.894 computable, and its `auth` failure rate is **5%** against 16–20%
everywhere else. An ecosystem whose package identity *is* a VCS coordinate has
both a higher declaration rate and more *real* links — the declarations are
load-bearing for installation, so they cannot rot unnoticed.

### One in five declared links does not resolve

`auth` — GitHub's indistinguishable private/renamed/deleted response (#411) —
accounts for 20% of npm attempts, 20% of RubyGems, 16% of PyPI.

That is a finding in its own right: **a declared repository is a claim, and
roughly one claim in five is no longer true.** Nothing in this tool, or in
Scorecard or Snyk or deps.dev, checks it.

### Cross-check against the #385 cohort

npm computes to **0.415** here against **0.464** measured on the #385 cohort —
a different draw, a different clone run, and one that carried a since-fixed
race. Two independent estimates within 5 points.
