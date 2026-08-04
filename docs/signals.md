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

### Classification is centralized

`signals.unmeasured_reason_for()` is the only place that decides why a signal
came back unmeasured. It takes the signal name and one keyword-only fact the
scorer observed, and it reads the catalog. Eight adapters making that judgment
independently is how a table of eight right answers becomes a table of eight
opinions, and the design made centralization a binding condition for exactly
that reason.

The `source_repository_unreadable` argument is keyword-only with no default, so
the fallback cannot be reached by forgetting to pass it. That is the shape
`record_source_repository` established in #189, generalized.

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
