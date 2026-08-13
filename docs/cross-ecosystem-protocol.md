# Cross-ecosystem computability — pre-registration

**Status:** committed before any package was sampled. #425.

## 0. The question

Every published validation of a package health score is single-ecosystem, and
so is every measurement in this repository. Nobody has published:

> For what fraction of packages can a repository-derived score be computed
> at all, and does that fraction differ across ecosystems?

It bounds this tool, OpenSSF Scorecard, Snyk Advisor and deps.dev
simultaneously, because all four depend on the same declared repository link
(`prior-art.md` §5).

**This study has no outcome.** None of the four requirements that closed the
outcome landscape apply. It is descriptive and cannot be invalidated by
waiting — which, after ten studies whose claims decayed, is the point.

## 1. The claim under test

> The share of packages for which a repository-derived score is computable
> differs materially across ecosystems, and is below 100% in all of them.

"Materially" is fixed at **≥15 percentage points** between the highest and
lowest ecosystem.

## 2. Cohort, fixed now

Uniform samples from the **full published name list** of each ecosystem — never
a top-N or popularity list, which would condition on the very thing being
measured and inflate declaration rates.

| ecosystem | name list | n |
|---|---|---:|
| npm | `all-the-package-names` | 1,000 |
| PyPI | `pypi.org/simple/` | 1,000 |
| Packagist (PHP) | `packagist.org/packages/list.json` | 1,000 |
| RubyGems | `rubygems.org/versions` | 1,000 |

Seed **20260813**, disjoint from every prior harvest. npm names already drawn
for the #385 cohort and the base-rate pilot are excluded.

## 3. The definition is the production code's, not this study's

The single biggest way to get this wrong is to write four bespoke definitions
of "declares a repository" and then report that the ecosystems differ — when
what differed was the definitions.

So the measurement calls each analyser's **own** `_resolve_repository`, which
returns a `RepositoryResolution` collapsing to the three states the scorer
already uses:

- **DECLARED** — canonicalised to `owner/repo` on a supported host; the
  repository-derived signals are computable
- **UNUSABLE** — something was declared and is not a usable forge URL
- **UNDECLARED** — the registry answered and names no source

Each analyser's declaration/fallback rules differ *because the registries
differ*, and that asymmetry is the tool's considered judgement, already
reviewed. Reusing it means this measures what the shipped tool can compute.

## 4. What is recorded

Per package: the three-state resolution, and whether the registry answered at
all. **No clone is attempted** in this stage — declaration is an upper bound on
computability and is the cheap half. Clone-success is a second stage, gated on
this one.

## 5. Falsification lines — fixed now

1. **If the highest and lowest ecosystem differ by <15 points**, §1's claim is
   not made and the finding is reported as *"computability is uniformly
   limited"*, which is still worth publishing.
2. **If any ecosystem resolves <80% of sampled names** at its registry, that
   ecosystem is reported separately and excluded from the comparison — a thin
   resolution rate means the name list and the registry disagree, and the
   sample is not what it claims to be.
3. **If any ecosystem's DECLARED share exceeds 95%**, it is reported as
   effectively unconstrained rather than folded into a range that implies a
   shared ceiling.
4. **If a name list turns out to be stale** — verified by spot-resolving a
   sample against the registry — that ecosystem is dropped and said so.

## 6. What it licenses

**Supported:** *"across four ecosystems, repository-derived scoring is
computable for X% of packages, ranging from Y% to Z%."* That is a bound on four
tools including this one, and it does not decay.

**Not licensed:** anything about whether the scores those tools compute are any
good. This measures whether they can be computed at all.

## 7. Named hazards

- **Registry semantics differ.** PyPI's `project_urls` is free text; RubyGems
  publishes `source_code_uri` in two places; Packagist is repository-first by
  construction and will likely score highest for exactly that reason. That is a
  finding about the ecosystems, not a confound to remove.
- **Packagist's structure may make the comparison uninteresting at one end.**
  Pre-registered so that a high number there cannot later be presented as a
  surprise.
- **Declaration is an upper bound.** npm's declared share was 57.6% and its
  measured clone yield 46.4% (`what-this-tool-is.md` §2). Stage two closes that
  gap; stage one must not be read as if it already had.
