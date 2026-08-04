# The adapter-conformance harness

**What it is:** per-signal *value* assertions for each ecosystem adapter,
checked against payloads captured from the live registry and replayed offline.

**What it is for:** catching the dead-read class — an adapter that fetches the
registry successfully and then reads a key the registry has never sent.

Issues: [#73][73] (harness), [#145][145] (dead-read audit), [#160][160]
(ratified sequencing).

[73]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/73
[145]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/145
[160]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/160
[#178]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/178
[#179]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/179
[#180]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/180
[#182]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/182
[#183]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/183

## The gap it closes

Five confirmed dead reads shipped in one session, each found by measuring an
ecosystem by hand. `testing/unit/signal_floors.py` already floors how many
signals an ecosystem measures, and since #158 names which ones. That catches a
signal going to `None`.

It cannot catch this one:

> npm read a top-level `deprecated` key that npm has never sent. The
> deprecation flag defaulted to `False`. `False` is not `None`, so the signal
> always read as **measured** — just always measured **wrong**. No npm package
> could ever be flagged deprecated, and every count stayed green (#142).

A count-based floor is structurally blind to it. What is not blind to it is an
assertion on the signal's **value**, against a fixture whose ground truth is
the branch the buggy code can never reach.

## The rule

> **Every signal whose read collapses to a fixed default when its key is absent
> needs at least one captured fixture where the correct answer is the
> non-default value, asserted by value.**

Those are the *polarized* signals: booleans and two-state enums.
`adapter_conformance.POLARIZED_SIGNALS` declares them per ecosystem with the
default value, the non-default value, and why the signal is polarized.
`test_every_polarized_signal_has_a_non_default_fixture` enforces it.

A branch the harness cannot prove is recorded as a waiver with a reason and
printed by `unproven_branches()`. A waiver is a gap someone has looked at, not
a gap that has been closed.

## Fixtures are captured, never authored

`test_nodejs_adapter` used to describe its payloads as "trimmed to the keys the
adapter reads". That sentence is the bug: a fixture trimmed to what the adapter
reads cannot, by construction, contain the key the adapter *should* read and
doesn't — the literal mechanism behind four of the five dead reads.

So: `scripts/capture_registry_fixtures.py` fetches from the live registry, and
reducers may drop **volume** but never **key diversity**. See
`testing/fixtures/registry/README.md` for the rule, the refresh cadence, the
ownership, and the security handling of captured payloads.

Half the registries do not answer with JSON — Maven Central serves XML, nuget.org
serves a `.nuspec` beside its JSON, the Go proxy serves a `go.mod` as text — so a
manifest entry may declare `"format": "text"` and the body is recorded verbatim
and replayed as bytes. Text captures are never truncated and never reduced:
shortening a POM changes how it *parses*, which is a key difference wearing a
volume costume.

CI never touches the network. Capture is manual or run from the
`registry-fixtures` dispatch workflow; the suite replays recordings only, and
the replay fetcher raises on any URL it has no recording for.

## Verified to fail

A gate never observed failing is unverified (#153). This one was checked by
reintroducing #142 — making `NodeJSAnalyzer._is_deprecated` read a top-level
`deprecated` again — and running the suite:

| Gate | With #142 reintroduced |
|---|---|
| `test_signal_floors.py` (counts) | **passed** |
| `test_nodejs_adapter.py` floor + named-signal assertions | **passed** |
| `test_adapter_conformance.py` value assertions | **FAILED** on `nodejs/request` |

That is the claim, demonstrated rather than asserted.

Repeated for cargo when it was converted, by putting #139 back — making
`_apply_registry_metadata` read the crate object's own `created_at` again:

| Gate | With #139 reintroduced |
|---|---|
| `test_signal_floors.py` (counts) | **passed** (6/6) |
| `test_crates_adapter.py` floor + named-signal assertions | **passed** (2/2) |
| `test_adapter_conformance.py` value assertions | **FAILED** on `cargo/serde` |

And for the second read the cargo capture found, restoring `max_version` as the
latest-version source:

| Gate | With the `"0.0.0"` sentinel read restored |
|---|---|
| `test_signal_floors.py` (counts) | **passed** |
| `test_crates_adapter.py` (all 10) | **passed** |
| `test_adapter_conformance.py` value assertions | **FAILED** on `cargo/acid-store` |

Same for the PEP 639 licence read, removed again:

| Gate | With `license_expression` unread |
|---|---|
| `test_signal_floors.py` (counts) | **passed** |
| `test_python_adapter.py` floor + named-signal assertions | **passed** |
| `test_adapter_conformance.py` value assertions | **FAILED** on `python/flask` |

The `ownership` read is the instructive contrast: remove it and the count-based
floor fails *too*, because an unread maintainer count goes to `None` and `None`
leaves the measured set. That is the line between the two layers, and it only
holds because the floor was re-baselined to 8 in the same change. A floor left
at 7 would have gone green on the signal it had just started measuring.

### This round

golang, by deleting the `go.mod` read again — the exact state the adapter
shipped in until this change:

| Gate | With the `go.mod` read removed |
|---|---|
| `test_signal_floors.py` (counts) | **passed** (6/6) |
| `test_golang_version.py` + `test_go_module_path.py` | **passed** (45/45) |
| conformance floor case `golang/logrus.latest` | **passed** |
| `test_adapter_conformance.py` value assertions | **FAILED** on `golang/protobuf.latest` |

nuget, by pointing `REGISTRATION_BASE` back at `registration5-semver1` and
serving the SemVer1 payload captured from that hive — #129's behaviour replayed
against the bytes it actually got:

| Gate | With the SemVer1 hive restored |
|---|---|
| `test_signal_floors.py` (counts) | **passed** (6/6) |
| `test_nuget_adapter.py` floor + named-signal assertions | **passed** (63/63) |
| `test_adapter_conformance.py` value assertions | **FAILED**: `nuget/servicebus.nuspec: is_deprecated is False, expected True` |

That second row is the whole argument in one line. `test_nuget_adapter.py`
contains a test called `test_an_explicit_deprecation_block_is_honoured`, and it
passed — against a hand-written payload that has the key because the parser
looks for it.

maven is this round's instructive contrast, the `ownership` case again: delete
the `<lastUpdated>` read and the staleness signal goes to `None`, which drops
maven below its own floor, so both layers fail. That is the correct outcome and
the reason the floor was set at 8 in the same change rather than at the 6 the
capture first measured.

composer's is the least interesting and worth recording anyway: repoint
`abandoned` at a key Packagist does not send and the conformance value
assertion fails — but so does `test_composer_adapter.py`, which already had a
targeted deprecation test. Not every ecosystem needed this harness equally.

## Status: 8 of 8 converted

| Ecosystem | State | Notes |
|---|---|---|
| **nodejs** | converted | 3 captured packuments. Proves the mechanism against #142's phantom top-level `deprecated`. |
| **rubygems** | converted | 2 gem payloads + owners docs. A *different* dead-read shape (#134: registry sends a `licenses` list, adapter read a `license` string), on the other side of `SCORES_FROM_REGISTRY_ALONE` from npm, and small enough to capture whole. |
| **python** | converted | 3 captured project documents. #145's named blind spot, and the capture found two dead reads in it: `ownership` (#171 — the maintainer count PyPI was recorded as not publishing) and `license_expression` (PEP 639; 17 of 30 sampled popular packages publish it with a null `license` and no `License ::` classifier). |
| **cargo** | converted | 2 crate documents + owners docs. #139's *wrong-value* shape, and the only ecosystem whose deprecation non-default branch is capturable at all — crates.io answers 200 for a fully yanked crate where rubygems answers 404 (#170). Capturing it found `max_version` answering the sentinel `"0.0.0"` when nothing installable remains. |
| **composer** | converted | 3 captured p2 documents. The one audit of the four that found **no** dead read — every key the adapter reads, Packagist sends. It found two unread ones instead: the `require` block (the transitive fact nuget scores from its nuspec) and a failed lookup recorded as UNDECLARED rather than unmeasured. |
| **nuget** | converted | 7 captured documents (version index + registration index + nuspec, two packages, plus a second registration hive as evidence). The capture found #142's shape in a **fourth** adapter: the `deprecation` block exists only in `registration5-gz-semver2`, and #129 read `registration5-semver1`. |
| **maven** | converted | 6 captured XML documents, and maven's **first `signal_floors` entry ever**. The capture found `<lastUpdated>` unread (no release cadence without a clone) and no source-repository record at all. A third reading is filed rather than fixed: `<licenses>` and `<scm>` inherited from a *parent* POM are never walked to. |
| **golang** | converted | 4 captured proxy documents, and the first non-JSON registry here. The capture found #142's shape in a **fifth** adapter: Go states a module's retirement in its own `go.mod` and nothing fetched it, so `is_deprecated` was False for every Go module ever scanned. `@latest`'s `Time` was unread too. |

### What the four conversions in this round changed

| Ecosystem | Floor before | Floor after | Reaches a verdict unaided |
|---|---|---|---|
| composer | 8 | 8 (unchanged) | True (unchanged) |
| nuget | 8 | 8 (unchanged) | True (unchanged) |
| maven | **none** | **8** | — → **True** |
| golang | **none** | **6** | — → **False** |

maven and golang had no floor of any kind before this. maven's is 8 rather than
the 6 the capture first measured, because two of the readings it found were
fixed in the same change — a floor sits at measured coverage, never below it
(#158). golang's is 6 and stays there: `proxy.golang.org` publishes no licence
and no owner list, so a Go module does not clear the insufficient-data bar from
proxy metadata alone, and that is recorded rather than rounded up to match its
neighbours.

The earlier round, for reference: python moved 7 → 8 (`+ maintainer`, via
`ownership`) and False → True; cargo stayed at 8. The honest caveat there is
captured rather than rounded off — a project owned by a PyPI *organization*
reports `roles: []`, and `python/flask` is that fixture.

`adapter_conformance.CONVERSION_STATUS` carries the same table in code.
`test_the_conversion_ledger_is_honest` stops it claiming more than it has, and
`test_every_ecosystem_with_an_adapter_is_under_the_value_harness` stops it
claiming less by quietly shrinking.

## What the four captures found

Every conversion so far has found at least one reading nobody predicted. These
four kept the record intact.

| Ecosystem | Finding | Shape | Status |
|---|---|---|---|
| nuget | `deprecation` exists only in `registration5-gz-semver2`; #129 read `registration5-semver1`, where the key is simply absent. No .NET package could ever be flagged deprecated. | #142 exactly: always measured, always `False` | **fixed** — one base URL |
| golang | Go states retirement as `// Deprecated:` on the `module` directive in `go.mod`; the proxy serves the file, nothing fetched it. `is_deprecated` was `False` for every Go module. | #142 exactly | **fixed** — one extra read |
| golang | `@latest` publishes `Time` beside `Version`; unread, so a Go module had no release cadence without a clone — on the ecosystem whose repositories are least likely to clone. | unread key → `None` | **fixed** |
| maven | `maven-metadata.xml` publishes `<versioning><lastUpdated>`; unread, same consequence. | unread key → `None` | **fixed** |
| maven | The adapter never recorded whether the POM declares a source repository, so the signal was absent from the score rather than answered either way. | signal absent, not defaulted | **fixed** |
| maven | `<licenses>` and `<scm>` are conventionally declared once in a *parent* POM and inherited. The adapter reads the artifact POM and stops. guava's own POM has neither; so does every Apache and Spring artifact built the same way. | unread *document*, not key | **filed** ([#178]) — POM-graph walk |
| maven | Maven Central publishes no retirement marker at all, so deprecation reads measured-and-`False` for every artifact with no ground truth to capture. | #142's shape, unprovable | **filed** ([#179]) as an unproven branch |
| composer | The p2 entry states the package's own `require` block — the fact nuget reads from its nuspec and scores — and composer marks transitive unmeasured. | unread key | **filed** ([#180]) |
| composer | A failed Packagist lookup records the source repository as UNDECLARED rather than unmeasured, so a 404 scores as "declares no source". | error path → measured value | **filed** ([#182]) |
| nuget | Resolves a repository URL from the nuspec and still records nothing about whether one is declared, so it scores 15 signals where the rest score 16. | signal absent, not defaulted | **filed** ([#183]) |

The nuget one is the methodological point of the round. It was **not visible
from one payload**: the parser looked for `deprecation`, the hand-written
fixture had `deprecation` because the parser looked for it, and the live SemVer1
payload simply does not carry the key. Only holding both hives side by side
showed it, which is why both are captured — `nuget/servicebus.registration` and
`nuget/servicebus.registration-semver1`, same package, same version, differing
by exactly that key.

## When the new ecosystem has no registry of its own

gradle (#101) is the first entry in the ledger that adds no registry. Gradle
publishes Maven coordinates, resolves against Maven Central and routes to OSV's
Maven ecosystem, so scoring it through `MavenAnalyzer` against captured Maven
Central documents would restate maven's cases with extra steps. What it adds is
a **route**, and the route is what can break: the build-script parser produces a
key, and that key has to be exactly the `groupId:artifactId` Maven Central is
addressed by. Get it subtly wrong and every Gradle dependency 404s into
all-UNKNOWN while every count stays green — #127's collapse from a new cause.

So its driver starts at the *manifest*. Two real projects are captured as
fixtures alongside the registry documents — okhttp's Kotlin Multiplatform module
script plus its `gradle/libs.versions.toml`, and RxJava's Groovy `build.gradle`
— materialised in the layout their source URLs describe, parsed for real, and
only then handed to the analyzer. `FixtureCase.expected_version_source` asserts
*how* the version was established, because "read 3.17.0 off the declaration" and
"resolved it through a version catalog" produce an identical score and are the
whole of what the adapter does.

Two consequences to copy if you do this again:

- Its floor is maven's floor and maven's signal set, to the letter. A lower
  number would mean the route lost something on the way through the parser,
  which is exactly what the entry exists to catch.
- The project captures are pinned to a **tag**, not a branch. A build script and
  the artifact version it names are one fact, and a moving branch lets the two
  drift apart between runs — the build script bumps its catalog and the
  version-pinned POM URL beside it does not. The cost is that those fixtures
  cannot surface a new DSL shape on their own, so the refresh cadence has to be
  spent bumping the tag and reading the diff.

## Converting the next ecosystem

All nine are converted, so this is now the procedure for a *new* ecosystem —
and for re-doing one whose registry changed shape.

1. Add its packages to `testing/fixtures/registry/manifest.json`. Pick at least
   a healthy one (the coverage-floor case) plus one per polarized signal whose
   ground truth is the **non-default** branch. Add the host to
   `allowed_hosts`, and mark non-JSON documents `"format": "text"`.
2. Add a reducer to the capture script if the document is version-keyed and
   large. Volume only.
3. `python scripts/capture_registry_fixtures.py --ecosystem <name>`, then read
   the captured payload. Compare every key it contains against what the adapter
   parses; a key the registry sends and the adapter ignores is a candidate dead
   read, and a key the adapter reads and the registry never sends is a
   confirmed one.
4. Add a driver to `adapter_conformance.DRIVERS` — the adapter's fetch seam
   stubbed with `replay_fetcher`, then license → community → scoring, cloning
   off and no token.
5. Declare `POLARIZED_SIGNALS[<name>]` and write the `FixtureCase`s.
6. Flip `CONVERSION_STATUS[<name>].converted` to `True`.
7. Reintroduce a dead read by hand and watch it fail before you believe it.

## Known limits

- The community signal is scraped off a GitHub repository page, not a registry
  document, so it is stubbed rather than captured. Out of scope for a
  *registry* fixture.
- The exploit signal is set by the vulnerability aggregator from OSV, so no
  registry payload can flip its non-default branch. #73's "known-CVE package →
  more than zero advisories, per ecosystem" regression test is the piece that
  would bring it under this harness.
- A reduced fixture cannot exercise a fallback path that depends on the dropped
  volume. Those keep their synthetic tests next to the adapter.
- Some non-default branches cannot be captured at all, and those are recorded
  as waivers rather than skipped. maven's deprecation is the sharpest: Maven
  Central publishes no retirement marker of any kind, so the signal reads as
  measured and `False` for every artifact in the repository and no payload can
  make it read otherwise. rubygems' is the other: a gem whose releases are all
  yanked answers 404, so the adapter returns before the read. `unproven_branches()`
  prints every one with its reason.
- Version-pinned fixture URLs (a POM, a `go.mod`) go stale when the artifact
  ships again: the adapter asks for a URL no fixture records and the replay
  fetcher raises. That is the designed failure, not a flake — re-capture, which
  means editing the manifest URL first.
