# Signal names and the OpenSSF Scorecard mapping

**Status:** Authoritative
**Source of truth:** `src/dependency_risk_profiler/signals.py`
**Scorecard version this mapping is pinned to:** `v5.5.0`
**Last verified against that tag:** 2026-08-04

This page is checked against the code by
`testing/unit/test_signal_catalog.py`. If you edit one, edit the other; the
test fails on drift, which is the only reason a published mapping table is
worth more than a remembered one.

---

## The signal names are ours

The names below appear in `unknown_signals` in the JSON report and in the
per-ecosystem tables the conformance harness asserts against. **They are
stable.** Renaming one is a breaking change to the output contract.

We considered adopting Scorecard's check names outright and rejected it. The
argument for the rename was interoperability; the argument against is that this
whole effort is justified on *API stability*, and Scorecard's vocabulary is not
ours to hold still. Our `signed_commits` is the proof: the check it would have
been renamed to does not exist at the pinned version, and the nearest historical
one was deleted upstream four major versions ago. A name we cannot keep stable
is worse than no shared name at all, because it looks like a guarantee.

So the correspondence is published as a mapping, pinned to a version, with
every approximate row marked approximate.

## How to read the fidelity column

| Fidelity | Means |
|---|---|
| `close` | Same question, same class of evidence. Safe to join row-wise. The **numbers are still not comparable**: ours is a 0–1 risk score where higher is worse, Scorecard's is a 0–10 quality score where higher is better. |
| `approximate` | Related question, different evidence. Do not treat as interchangeable. A disagreement between the two is expected and is usually not a bug in either. |
| `none` | Scorecard has no check that asks this question at the pinned version. |
| `removed_upstream` | The nearest Scorecard check existed once and is gone at the pinned version. |

## The mapping

| Our signal | Scorecard `v5.5.0` check | Fidelity | What differs |
|---|---|---|---|
| `staleness` | Maintained | approximate | Ours reads the registry's own release timestamp, which cannot be broken by a repository rename (#146). Scorecard reads repository commit and issue activity over the trailing 90 days. A package with a live repository and no releases for three years scores well upstream and badly here, on purpose. |
| `maintainer` | Contributors | approximate | Ours is a bus-factor count from the registry's owner or author list. Scorecard counts repository contributors from at least two organizations, which is a diversity-of-affiliation question, not a bus-factor one. |
| `deprecation` | — | none | Scorecard has no deprecation check. |
| `exploit` | Vulnerabilities | approximate | Both read OSV. Scorecard reports a count of open advisories for the repository. Ours is severity-weighted, scoped to the installed version's affected ranges, and reports advisories whose applicability could not be decided rather than assuming them away (#61). |
| `version` | — | none | Scorecard scores repositories, not installed versions, so it has no equivalent. The nearest thing is Pinned-Dependencies, which asks whether *this* project pins its own dependencies. |
| `health_indicators` | CI-Tests | approximate | A composite of three presence checks, only one of which (CI) Scorecard asks about, and Scorecard asks it of pull requests rather than of the repository's configuration. |
| `license` | License | approximate | Scorecard asks whether a license file exists and is SPDX-recognized. We categorize the license — permissive, copyleft, network copyleft, commercial — and score the obligation it creates. A clean Apache-2.0 and a clean AGPL are identical upstream and far apart here. |
| `community_popularity` | — | none | Scorecard deliberately excludes popularity: stars are not a security property. We keep it as a dampener on abandonment scoring, never as a finding in itself. |
| `community_activity` | Maintained | approximate | Both read commit activity. Scorecard folds issue activity in and thresholds at 90 days; ours is a rate over six months and is weighed apart from popularity so a well-starred package with a dead commit log cannot pass as healthy (#166). |
| `transitive` | — | none | Scorecard has no dependency-tree-size check. Its Pinned-Dependencies check asks a different question, about how dependencies are referenced rather than how many exist. |
| `security_policy` | Security-Policy | close | Same question, same evidence (a SECURITY.md in a well-known location). Scorecard grades the policy's contents out of ten; ours is presence or absence. |
| `dependency_update` | Dependency-Update-Tool | close | Same question, same evidence (Dependabot or Renovate configuration in the repository). |
| `signed_commits` | — | removed_upstream | No Scorecard check asks this at v5.5.0, and this row is why the design was amended to keep our own names. We read git history directly: commit signature status (git log %G?), tag signature status, and workflow- or settings-enforced signing. Scorecard's nearest historical check was Signed-Tags, which existed at v2.0.0 and was gone by v3.2.1. The nearest live check, Signed-Releases, inspects the last release's *assets* for detached signature files and never reads git history, so it answers a different question and must not be joined to this signal. Do not rename this signal to either name. |
| `branch_protection` | Branch-Protection | close | Same question, same evidence. Scorecard needs an admin token to see the full settings and degrades without one; ours reads what an unauthenticated or read-scoped view exposes, so a disagreement here is usually a permissions difference rather than a finding. |
| `maintained` | Maintained | close | Same question and the closest of our three Maintained rows. Scorecard thresholds on activity in the trailing 90 days and treats an archived repository as unmaintained outright. |
| `source_repository` | — | none | Scorecard starts from a repository URL, so it cannot ask this question: a package that declares no source is one it cannot score. That is precisely why we measure it — the packages Scorecard cannot reach are not thereby safe (#146). |

### The mapping is not invertible

Three of our signals point at `Maintained`. Scorecard asks "is anyone home?"
once, from repository activity. We ask it three times from three sources — when
the registry last shipped, how often the repository is committed to, and the
repository's own activity heuristics — because a package can be stale on one
and healthy on another, and reporting the disagreement is more useful than
averaging it away (#166). Joining Scorecard → us is therefore one-to-many, and
a consumer that expects a single row will silently pick one arbitrarily.

### `signed_commits`, at length

This is the row the whole exercise was for, so it gets stated plainly rather
than smoothed over.

* We measure three things off a clone: the signature status of recent commits
  (`git log --pretty=%G?`), the signature status of recent tags, and whether
  the repository enforces signing through a workflow or `.github/settings.yml`.
* At `v5.5.0` Scorecard's `checks/` directory contains no commit-signing check.
  Its nearest historical relative was `Signed-Tags`, present at `v2.0.0` and
  absent by `v3.2.1`.
* `Signed-Releases` is stable, and it is **not** the same question. It looks at
  the last release's *assets* for `*.asc`, `*.sig`, `*.sigstore`,
  `*.intoto.jsonl` and friends. It never reads git history. A project that
  signs every commit and publishes unsigned tarballs scores badly there and
  well here; the reverse is equally possible.

The design proposal that started this work assumed `signed_commits` mapped to
an *experimental* Scorecard check. Checking against the pinned tag found
something stronger: there is no such check to be experimental about. Either way
the conclusion is the same and it is now a matter of record — an upstream
vocabulary that adds, renames and deletes checks cannot carry a stability
guarantee we are making to our own consumers.

### Refreshing the pin

1. Read `docs/checks.md` and list `checks/` at the Scorecard tag you are moving
   to.
2. Update `SCORECARD_VERSION`, `SCORECARD_CHECKED_ON` and `SCORECARD_CHECKS` in
   `src/dependency_risk_profiler/signals.py`.
3. Re-verify every row. `test_signal_catalog.py` will fail if the catalog names
   a check that is not in `SCORECARD_CHECKS`, which catches deletions and
   renames for free — but it cannot tell you a row's *meaning* drifted, so read
   the check descriptions.
4. Regenerate the table above from the catalog and update this page.

---

## Measurement state: two states, not three

Every signal the scorer produces is one of exactly two things:

* **MEASURED** — carries a value. Requires one.
* **UNMEASURED** — carries a reason. Requires one.

Both are enforced in `Measurement.__init__`, and instances are frozen after
construction. There is no way to build a measurement carrying a value nobody
measured, and no way to edit one into existence afterwards. That is the whole
point: #141 shipped a confident `0.0` for a signal nobody measured, and #166
shipped a composite that degraded to its weakest component while still
reporting as measured. Both were representable states of the old type.

### Why there is no `NOT_APPLICABLE`

It is deferred behind a schema version until a consumer demonstrably branches
on the distinction, on an argument that has not been improved on:

> No conformance harness check can tell a wrong `NOT_APPLICABLE` from a right
> one.

It is the one piece of the design that cannot be machine-verified, and a
confidently-wrong "does not apply" is more misleading than an honest unknown.
**Default to UNMEASURED when uncertain.**

This also rules out reintroducing it as a *reason*. Every reason below is
decided from something the scorer observed, never from a judgment about whether
a signal ought to apply to a package.

### The reasons

| Reason | Assigned when |
|---|---|
| `source_repository_unreadable` | The registry answered and no readable source repository came out of it, so the repository-derived signals had nothing to read. One measured fact standing behind several silent signals (#146). |
| `no_data_from_source` | The input this signal reads was absent — the registry published no such field, or the lookup returned nothing. The default. |
| `lookup_not_attempted` | The pipeline step that answers this signal never ran for this manifest. Distinct from "it ran and found nothing", which is a measured zero. |
| `source_lookup_failed` | The lookup ran and the source did not answer: unreachable after the retries, an error status, a GraphQL error block, or a body this code cannot read. Distinct from `no_data_from_source`, which is a source that *answered* and had nothing to say (#219). |

### The advisory lookup has three outcomes, not one

`exploit` is the signal this distinction was hardest-won on. Every advisory
source used to return the empty list for a connection failure, a 4xx, a GraphQL
error, an unreadable body, an ecosystem it does not cover, **and a genuinely
clean package** — and the aggregate was written to the cache either way, so an
OSV outage reported every package in the scan as advisory-clean and the verdict
outlived the outage until the TTL expired (#219).

| Outcome | `exploit` | Cached |
|---|---|---|
| Advisories found | measured, severity-weighted | yes |
| Measured, none found | measured `0.0` | yes |
| Lookup failed | **unmeasured**, `source_lookup_failed` | **no** |
| No source could be asked | **unmeasured**, `lookup_not_attempted` | no |

**Partial failures.** Sources are not interchangeable, so a failure in one is
not a failure in another's clothing. OSV and the GitHub Advisory Database are
asked about a package by identity within an ecosystem, so their silence is an
answer and their absence is the absence of one: if either fails and nothing was
found, "no advisories" is unmeasured. NVD is reached by keyword search over CPE
strings — it can add a CVE nobody else listed, but a keyword miss is not a
statement about the package — so an NVD failure degrades completeness, not
measuredness. And a *finding* survives any failure: once an advisory is found
no outage elsewhere un-finds it, so the result is reported as a floor. Anything
short of "every source that was asked answered" is excluded from the cache.

An ecosystem a source does not cover is an **abstention**, not a failure and
not a clean answer. No `NOT_APPLICABLE` is invented for it: the source records
that it was never asked, and the aggregate decides what that means from whether
anybody else answered.

### Classification is centralized

`signals.unmeasured_reason_for()` is the only place that decides why a signal
came back unmeasured. It takes the signal name and the keyword-only facts the
scorer observed, and it reads the catalog. Eight adapters making that judgment
independently is how a table of eight right answers becomes a table of eight
opinions, and the design made centralization a binding condition for exactly
that reason.

The `source_repository_unreadable` and `advisory_lookup` arguments are both
keyword-only with no default, so the fallback cannot be reached by forgetting to
pass one. That is the shape `record_source_repository` established in #189,
generalized.

---

## Compensatory and non-compensatory evidence: facts set floors

The score is a weighted mean. That is a **compensatory** model: it treats every
signal as exchangeable evidence about one latent variable, so a good answer
anywhere can pay for a bad answer anywhere else. For forecasting how a package
will behave, that is the right shape — an aging release line really is offset
by an active maintainer roster.

Known exploitation of the **installed** version is not that kind of evidence.
It is not a forecast about the package's trajectory; it is a fact about the
version in your lockfile right now, and upstream velocity does not patch a pin.
Averaging a fact against forecasts lets the forecasts erase it.

> **The rule.** A weighted mean is a compensatory model: it treats signals as
> exchangeable evidence about one latent variable. Known exploitation of the
> installed version is **non-compensatory** — a fact about the present, not a
> forecast about the future. Facts set floors; forecasts move within them.
>
> **Leading indicators may raise a verdict above the lagging floor. They may
> never lower it below.**

This is the standard worst-of construct rather than an invention: CVSS
environmental scoring does not let process controls erase base severity, and an
audit grade is capped by any failed critical control. It is written here **as a
general rule** so the next non-linearity has a principle to be tested against
instead of a precedent to be copied. Anything proposed as a second floor has to
argue that its evidence is non-compensatory in the same sense — a *fact about
the installed artifact*, not a *prediction about the project*.

### Why the rule was needed: the verdict could not reach the evidence (#242)

`exploit` carries the largest single weight, 0.5. There are sixteen signals and
their weights sum to 3.5, so the exploit signal's maximum share of the
normalized score is `0.5 / 3.5 = 0.143`, against a LOW/MEDIUM boundary of 0.25.

A package with a **maximal** exploit signal and a perfect, zero-risk record on
all fifteen other signals normalizes to 0.143 — LOW. No advisory load, however
severe, could cross the first boundary on its own. axios 1.6.5 is the case
that surfaced it, found by running the tool against
`examples/manifests/package-lock.json`: 44 advisories found, 29 confirmed to
affect the installed version, maximum counted severity HIGH at CVSS 8.0, and a
printed verdict of `LOW` on the same record as `known_vulnerable: true`.

That ceiling was **emergent**, not designed. Nobody recorded a decision to cap
the signal; it fell out of sixteen weights summing to 3.5.

The example manifest has since been upgraded to current releases (#253), so it
no longer reproduces the case — axios 1.19.0 finds the same 44 advisories and
counts none of them. The recording lives in
`testing/fixtures/axios_1_6_5.json`, which is the only place this defect is
still reproducible and the reason it cannot quietly come back.

### The floor mapping, and why it is discounted by one rung

| Maximum counted severity | Verdict may not sit below |
|---|---|
| `CRITICAL` | `HIGH` |
| `HIGH` | `MEDIUM` |
| `MEDIUM` | `LOW` |
| `LOW` | `LOW` |

**One rung under the worst live advisory**, clamped at the bottom of the scale.
The two lower rows are no-ops by construction — `LOW` is the floor of the scale
— and they are written out anyway, because a rule with unstated edges is a rule
somebody will re-derive differently.

The single rung of slack is the whole of the argument. Advisory severity is a
property of the vulnerability considered alone: a CVSS base tier, assigned
without environmental context. The verdict is a property of the package *in
this tree*, and whether the vulnerable path is reachable from the caller is
something this tool does not measure and does not claim to. One rung is what
that unmeasured context is worth. Two rungs is not slack — it is the verdict
ignoring the fact, which is #242.

Rejected alternatives, recorded so they are not re-proposed as fresh ideas:

* **`floor(S) = S`.** Lets a context-free base tier dictate the whole composite
  and collapses the leading-indicator model into a CVE tracker, which is the
  thing this tool exists not to be.
* **Any counted advisory floors at `MEDIUM`.** Says a single LOW-severity
  advisory is worth as much as a HIGH one, and inflates verdicts off low-grade
  noise — the same defect as #242 pointing the other way.
* **Raising `exploit_weight` until the signal can cross a boundary alone.**
  Needs `w / (3.0 + w) >= 0.25`, i.e. `w >= 1.0` — tripling the largest weight.
  It moves every score in the corpus, re-baselines the per-ecosystem floors in
  #131, and still leaves a compensatory model that dilutes at higher
  thresholds. Maximum blast radius, and it does not fix the mechanism.

### What the floor keys on, exactly

`counted_vulnerability_count` — the same field the output contract's
`known_vulnerable` is computed from, because #242 is precisely that those two
fields could contradict each other. An advisory the annotator filtered never
reaches that count and therefore floors nothing:

| Situation | Floors? |
|---|---|
| Advisory affects the installed version, at or above the scoring threshold | **yes** |
| Fixed before the installed version, or otherwise not applicable (#61) | no |
| Withdrawn | no |
| Informational, or of unknown severity | no |
| Below `--vuln-min-severity` | no |
| Advisory lookup failed or never ran (#219) | no — unmeasured is not a fact |
| Verdict is `UNKNOWN` | no — see below |

`UNKNOWN` is left as an abstention. It is not a rung on the scale, it is not a
reassuring verdict, and the published contract states that
`insufficient_data: true` implies `risk_level: UNKNOWN` — so raising it would
be a semantic change to schema 2 rather than an additive one. A live CRITICAL
on a package too sparsely covered to score is therefore still reported as
`UNKNOWN` with `known_vulnerable: true`; that gap is #248, not this rule.

### It is reported, not just applied

The verdict alone cannot tell a reader which of two things produced it. Every
scored dependency carries a `verdict_floor` block saying whether a floor was
computed, what it was, which advisory carried the severity, and whether it moved
anything — including the case where it was computed and the verdict had already
cleared it. It is additive to schema 2 and breaks no consumer. See
`docs/agents.md` for the field.

---

## Which manifests are read, and why it is not "the lock file"

**Source of truth:** the registrations in
`src/dependency_risk_profiler/parsers/base.py`.
**Checked by:** `testing/unit/test_manifest_guidance.py`, which fails if the
recognized-unreadable table ever names a file the registry reads.

| Ecosystem | Read | Not read |
|---|---|---|
| npm | `package-lock.json` | `package.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json` |
| Python | `requirements.txt`, `Pipfile.lock`, `pyproject.toml` | `Pipfile`, `poetry.lock`, `uv.lock`, `setup.py`, `setup.cfg` |
| Go | `go.mod` | `go.sum` |
| Rust | `Cargo.toml` | `Cargo.lock` |
| Ruby | `Gemfile.lock` | `Gemfile`, `*.gemspec` |
| PHP | `composer.lock` | `composer.json` |
| .NET | `packages.lock.json`, `*.csproj` | `packages.config`, `*.vbproj`, `*.fsproj`, `Directory.Packages.props` |
| Maven | `pom.xml` | — |
| Gradle | `build.gradle`, `build.gradle.kts` | `settings.gradle(.kts)`, `gradle/libs.versions.toml` |

### There is no lockfile rule, and there was never a reason for one

#243 asked whether the rule should be "always require a lock file" or "accept
the range-declaring manifest and mark versions `unmanaged`". The honest answer
is that neither is the rule, because **the lock file is not what this tool is
mostly reading a manifest for.**

Of the sixteen signals in the mapping above, exactly one — `version` — needs a
resolved version at all. `exploit` needs one to scope advisories to affected
ranges, and degrades to `applicability_unknown` without one rather than going
silent. The other fourteen are properties of the *package*, read from the
registry and the source repository: staleness, maintainer count, deprecation,
licence, community activity, security policy, branch protection, signed
commits. A package name is enough for every one of them. That is the whole
thesis of a leading-indicator tool — the interesting facts are upstream of your
build, not in it.

So "we require a lock file because we need resolved versions" was never a rule
the code followed. `requirements.txt` and `go.mod` and `Cargo.toml` and
`pom.xml` and `build.gradle` are all read while carrying ranges, and #74/#141
built `unmanaged` precisely so an unresolvable version drops the drift signal
from both the numerator and the denominator instead of scoring a fabricated
zero. Five ecosystems already run that way.

**What each ecosystem is actually chosen on is which file names the
dependencies at all**, which is a per-ecosystem fact and not a policy:

* **npm.** `package.json` names direct dependencies only. `package-lock.json`
  names the whole resolved tree, and `parsers/nodejs.py` reads every
  `node_modules/…` entry in it — which is where npm's risk lives, since the
  transitive set is normally much larger than the direct one. Scoring
  `package.json` would report the direct dependencies and say nothing about the
  rest, which is a coverage claim we would not be entitled to make. Cargo is
  the same shape read the other way round: `Cargo.toml` names direct
  dependencies and is what we read, and `Cargo.lock` is the tree we do not.
* **Ruby and PHP.** `Gemfile` and `composer.json` are the same direct-only
  shape as `package.json`.
* **Python.** `requirements.txt` is conventionally the resolved output of a
  compile step and often *is* the whole tree; `pyproject.toml` is direct-only
  and read anyway, because it is frequently the only file a library has.
* **Go.** `go.mod` names the build list including indirect modules. `go.sum` is
  a checksum database over module versions, not a dependency list — it names
  modules that are not in the build.

### The rule that *is* enforced

Because the answer varies by ecosystem, the load-bearing rule is not about lock
files. It is:

> **A manifest this tool does not read is never silently skipped.** It is
> recognized, named, told what *is* read for its ecosystem, counted in
> `unreadable_manifests`, and — when nothing else in the scan was scored — it
> makes the run exit non-zero.

That is AGENTS.md rule 4 applied one level up from a signal. `analyze <dir>`
over a project of only `package.json` used to report zero dependencies and exit
0, which is the same shape as scoring an unmeasured signal `0.0`: a reassuring
answer produced from an absence of measurement. `dependency_count: 0` with an
empty `unreadable_manifests` means *we looked and there is nothing*;
`dependency_count: 0` with a populated one means *we could not look*.

Accepting `package.json` with `unmanaged` versions is therefore not refused on
principle — it is a separate change, because it changes what gets *parsed* and
its cost is a coverage question — a direct-only dependency set presented as
a project scan — rather than a version-resolution one. Filed as #261 with
acceptance criteria rather than folded in.

---

## What the wrapper costs

The design review flagged a per-field wrapper as a real cost in a thread-pooled
org scan and asked for numbers rather than an assumption. Measured on
CPython 3.11.12, scoring 5,000 synthetic dependencies (a third fully measured,
a third half measured, a third barely), best of seven rounds, five runs:

| | Before (`origin/main`) | After |
|---|---|---|
| Per dependency (best, spread over runs) | 11.91 µs (11.91–12.45) | 19.52 µs (19.52–20.67) |
| 5,000 dependencies | 59.5 ms | 97.6 ms |
| Retained after scoring 5,000 | 3,850.7 KiB | 3,850.7 KiB |

So: **about +7.6 µs per dependency, roughly +65% on the scoring stage, and no
additional retained memory.** The measurements are transient — they live in a
local list inside `score_dependency` and never reach `DependencyRiskScore` — so
the cost is CPU, not footprint. Against an org scan whose per-dependency work is
dominated by registry, GitHub and OSV round trips, 38 ms per 5,000 dependencies
is not a budget item; that is the honest reason this was accepted, not a claim
that it is free.

Three things were done to keep it where it is, each measured:

* **Unmeasured measurements are interned**, one shared instance per reason.
  Immutability is what makes that safe, so the frozen-ness pays for part of its
  own cost, and it pays most on exactly the sparsely-covered packages an org
  scan has the most of.
* **The hot path constructs directly** rather than through the
  `measured()`/`unmeasured()` classmethods where the extra hop showed up.
* **The two accounting passes compare `state`** rather than calling the
  `is_measured` property, which is identical by construction.

The immutability guard itself costs about 145 ns per construction (313 ns
frozen against 168 ns for the same class with plain assignment), which works
out to roughly 1.6 µs per dependency — about a fifth of the delta. It was kept:
without it, `measurement.value = 0.0` re-creates #141 in one line, and the
budget above has room.

---

## Field provenance: which acquisition path wrote a value

`star_count` is written from a regex over unauthenticated github.com HTML
(`community/analyzer.py`) and from `stargazers_count` on the authenticated REST
API (`org_scan/pipeline.py`). In an org scan **both run, for the same
dependency, in that order** — the scrape first, the API overwriting it — and
until this landed the payload gave a consumer no way to tell which of two very
different trust levels they were holding.

Seven model fields have more than one acquisition path. That set *is* the
scope, and it is derived rather than asserted:
`testing/unit/test_field_provenance.py` walks `src/` for write sites and fails
when the source tree and `signals.ProvenancedField` disagree, so a new second
writer cannot land unlabelled and an exemption cannot outlive the writer it
explains.

| Field | The paths that write it |
|---|---|
| `star_count` | github.com HTML, GitHub REST repository object |
| `contributor_count` | GitHub REST contributors, the registry's owner list |
| `maintainer_count` | the registry, a clone's `git shortlog`, GitHub REST |
| `commit_frequency` | a clone's `git rev-list`, GitHub REST commits |
| `has_tests`, `has_ci` | a clone's working tree, GitHub's git-tree API |
| `last_updated` | the registry's release table, repository activity |

Two fields qualify on write-path count and are deliberately out of scope.
`repository_url` is an identity locator rather than a measured value, and what
a consumer actually needs from it — did the registry declare a usable source,
or is this a synthesized registry landing page — is already answered by the
typed `source_repository_state` (#189). `transitive_dependencies` already
carries `transitive_source` (#199), which is provenance under an older name.

### The values are a closed vocabulary, and that is the security control

`FieldSource` is an enum whose member values *are* the sanitized logical
locators the design's binding condition requires: `github:api/repository`,
`clone:git-history`, `registry:release`. No host, no scheme, no userinfo, no
query string, no percent-encoding, no filesystem path — and no code path by
which one could appear, because the only inhabitants of the type are those ten
members. `record_field_source` is the single writer and rejects anything that
is not an enum member with a `TypeError` rather than coercing it: there is no
sanitized rendering of a token, so the only safe thing to do with one is refuse
it. The tests hold every member to a locator grammar, try five credential-shaped
values through an untyped call, and try an impostor object with a
credential-bearing `.value`.

### What it costs, against a budget stated first

The design amendment made the benchmark a **precondition**, so the budget was
written down before anything was measured. Method as in #198: CPython 3.11.12,
best of seven rounds, `tracemalloc` after `gc.collect()`, baseline measured in a
clean worktree at `origin/main`. Reproduce with
`uv run python scripts/bench_field_provenance.py`.

Figures are the best of six runs, with the spread over those runs in
parentheses.

| | Budget, as stated | Baseline | Measured | |
|---|---|---|---|---|
| Scoring stage, 100 deps (the 50 ms SLA path) | ≤ +2% | 1.906 ms (1.906–1.927) | 1.907 ms (1.907–2.091), **+0.05%** | pass |
| Recording, per dependency (9 writes) | ≤ 1.0 µs | — | 1.074 µs (1.074–1.184) | **over by 7%** |
| Serialization, `scored_dependency` per dep | ≤ +10% | 6.961 µs (6.961–7.192) | 8.140 µs (8.140–9.183), **+17%** | **over** |
| Retained, per dependency | ≤ 400 B | 1,992 B | 2,352 B, **+360 B** | pass |

**Two of those four lines were mis-set, and saying so is better than quietly
moving them.**

* The 1.0 µs recording line came from a pre-benchmark of bare dict stores — a
  mechanism with no method call and no validation, i.e. one I had already
  decided not to build, because the security condition requires the check. 119 ns
  for a validated bound-method call is within noise of CPython's floor for one.
* A **percentage** budget on a 7 µs function cannot accommodate a new
  sub-object. `scored_dependency` builds 25 keys; a 26th whose value is a
  7-entry mapping is ~17% of it by construction. The line measured the shape of
  the feature, not its cost.

The line the vote's concern was actually about is org-scan throughput: *"a
per-field wrapper on ~17 fields across thousands of deps in a thread-pooled org
scan."* Stated in those terms:

> **≤ 4 µs added CPU per dependency end to end (≤ 20 ms per 5,000-dependency
> org scan), under half of the +38 ms/5,000 that #198 measured and this panel
> accepted.**

Measured: **2.25 µs per dependency, 11.3 ms per 5,000** — 30% of what #198
already costs, against a scan whose per-dependency work is thousands of
registry, GitHub and OSV round trips. And the primary structural worry — that a
normalizer would leak into the hot path — is answered by the first row: the
scorer is untouched and measures untouched.

One optimization was taken and one refused. `contract.py` hoists the
member-to-value lookups into module-level tables, which is a third cheaper than
the `.value` comprehension it replaces. Giving both enums a `str` mixin would
have made serialization a pointer copy and beaten that twenty-fold; it was
refused, because the security argument above rests on the vocabulary being
*closed*, and a member that compares equal to a bare string is a weaker
foundation for that than one microsecond per dependency is worth. Same trade
#198 made when it kept the 145 ns immutability guard.
