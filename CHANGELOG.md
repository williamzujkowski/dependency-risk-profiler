# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **NuGet collects `<GlobalPackageReference>` packages, which appear in no
  project file at all.** Central Package Management lets a
  `Directory.Packages.props` apply a package to *every* project under it
  without any `<PackageReference>` in the `.csproj`. Dapper does this with
  ReferenceTrimmer; the convention is analyzers, source-link and versioning
  tools. They run during the build, which is exactly the supply-chain position
  this tool exists to examine, and they were invisible to the scanner while
  every count stayed green.

  Each is marked `build_dependency` in `DependencyMetadata.additional_info` —
  the same key `parsers/toml.py` already writes for pyproject's
  `build-system.requires`, rather than a new spelling for one ecosystem. The
  marker stops at the Python API: the unified `ScoredDependency` has no field
  for a dependency's kind or scope, and `additional_info` reaches neither
  reporter, so nothing here changes the JSON contract. Adding such a field
  concerns all nine ecosystems and belongs in its own issue.

  One #129 property is gone deliberately: a fully inline-pinned project used to
  read no file but its own manifest. A global package is a dependency of the
  pinned projects too, and there is no way to know one is there without
  reading the props file, so the lookup now always runs. Resolved versions for
  pinned and centrally-managed projects are unchanged.
- **A bar and its violation shipped in the same commit, and now they cannot.**
  AGENTS.md rule 7 said "Never commit `uv.lock`". The commit that introduced
  that rule committed `uv.lock`. Nothing noticed, because nothing was looking —
  the rule was a sentence in a file, and this repository has now produced four
  of those: the `Any` ban that `disallow_any_explicit` never enforced, a 90%
  coverage bar spelled with a pytest option that does not exist, this, and the
  one below.

  Put to a consensus vote rather than settled by preference, because the
  library-versus-application question is genuinely contested. It came back 7-0
  the other way, on a point that survives scrutiny: `uv.lock` is not packaged
  into the wheel or the sdist, so it constrains no consumer of this library and
  the entire lockfiles-in-libraries argument is about consumers. What it
  constrains is a contributor's `uv sync`. A tool whose thesis is that unpinned
  dependencies are a leading risk indicator does not get to except itself.

  The rule now says commit it, and says the opposite of what would be
  convenient: **the lockfile is not load-bearing in CI.** CI installs with
  `pip install -e ".[dev]"` and does not invoke `uv` anywhere, so the committed
  lockfile pins the contributor environment and nothing else. Six of the seven
  voters cited reproducible CI as a reason to keep it; that reason is not true
  today, and writing it down as though it were would have made this the fifth
  instance instead of the fix for the third. The contrarian voter flagged the
  install flag as a condition rather than an assumption, which is the only
  reason it was checked.

  What landed is the half that is completely correct: `uv lock --check` now runs
  in CI, so the lockfile cannot drift out of agreement with `pyproject.toml` —
  the case where someone edits a dependency and never relocks. Making the
  install itself consume the lockfile is #232, split out rather than stubbed
  because CI installs across a 3.9–3.12 matrix and a single locked resolution is
  not automatically installable on all four. Replacing a decorative lockfile
  with a red matrix is a worse trade than the status quo.

  Both gates were verified by observing them fail. Untracking `uv.lock` fails
  the new check in `test_repository_rules.py`; adding a dependency to
  `pyproject.toml` without relocking exits `uv lock --check` with status 2.

- **Four more ecosystems measure transitive dependencies, and the fifth says
  why it cannot.** nodejs, python, cargo and rubygems never populated
  `transitive_dependencies` at all. Since the fail-closed read landed, that
  read as *unmeasured* rather than as a fabricated `0.0` — honest, but blind on
  a signal three ecosystems already measured, so a Java artifact and an npm
  package with identical risk profiles scored differently purely because one
  adapter read a field.

  Each now reads its registry's own statement of what installing the package
  pulls in, and each draws the runtime line the way its registry draws it:
  nodejs from `versions[<latest>].dependencies` (not `devDependencies`,
  `peerDependencies` or `optionalDependencies`), python from
  `info.requires_dist` (not the `extra ==` entries), rubygems from
  `dependencies.runtime` (not `development`), and cargo from the per-version
  dependencies endpoint filtered to `kind: "normal"` (not `dev` or `build`).
  Three of the four cost no extra request — the data was already in a payload
  the adapter fetched. cargo costs one: the crate document carries only a
  pointer, so its request count per crate goes from two to three, taken for the
  same reason the adapter already spends a request on the owner count.

  golang abstains, and records UNMEASURED positively rather than staying
  silent. `go.mod` states no dependency scope: `go mod tidy` writes a module's
  test-only requirements into the same direct `require` block as its runtime
  ones — logrus requires `testify` beside `golang.org/x/sys` — so counting the
  block would over-report Go modules systematically, which is the opposite of
  the like-for-like comparison this change exists to restore.

  Two absences are kept distinguishable throughout: a payload that declares no
  dependencies is a measured zero, a payload that declares nothing readable is
  not. PyPI's `requires_dist: null` is the sharp case and is read as unmeasured
  — `carbon` and `graphite-web` both report null and both declare real
  `install_requires`, so null means "PyPI cannot tell you" rather than "none".

- **Schema v2 carries `field_sources`: which acquisition path wrote each field
  that has more than one.** `star_count` is written from a regex over
  unauthenticated github.com HTML *and* from `stargazers_count` on the
  authenticated REST API — in an org scan both run, for the same dependency, in
  that order — into one unlabelled integer, so two very different trust levels
  arrived indistinguishable. Seven fields collapse two or more paths this way:
  `star_count`, `contributor_count`, `maintainer_count`, `commit_frequency`,
  `has_tests`, `has_ci` and `last_updated`.

  Sources are sanitized logical locators from a closed vocabulary —
  `registry:release`, `clone:git-history`, `github:api/repository`,
  `github:html` — and never carry a host, a URL, a query string, a token or a
  filesystem path. A key is absent when nobody recorded a source, which is not
  the same as a source of "unknown".

  Additive: v2 gains a key and `--schema v1` output is unchanged, verified byte
  for byte against the previous release rather than assumed. Scope is derived
  rather than declared — `testing/unit/test_field_provenance.py` walks `src/`
  for write sites and fails when the source tree and the enumerated set
  disagree — and the cost was benchmarked against a budget stated first, with
  the numbers and the two budget lines that were mis-set written up in
  `docs/signals.md`.

### Changed

- **Risk scores move for npm, PyPI, RubyGems and crates.io packages.** A signal
  going from unmeasured to measured re-enters both the numerator and the
  denominator, so every dependency in those four ecosystems is rescored. Some
  cross a verdict boundary in the process: `express` and `request` were UNKNOWN
  purely because npm sat one signal short of the insufficient-data bar and are
  now LOW and MEDIUM, `flask` moves UNKNOWN -> LOW, and `hpricot` moves MEDIUM
  -> LOW on a measured zero.

  The per-ecosystem measured-signal floors are re-baselined upward to the new
  measured value: cargo 8 -> 9, nodejs 7 -> 8, python 8 -> 9, rubygems 8 -> 9.
  maven, gradle, nuget, composer and golang are unchanged. `nodejs` is the last
  entry to leave `SCORES_FROM_REGISTRY_ALONE = False`: npm still publishes no
  cheap maintainer count, and it clears the bar by exactly nothing — eight
  measured against eight unmeasured — so losing any one signal returns every
  npm package to UNKNOWN. golang is now the only ecosystem that cannot reach a
  verdict from registry metadata alone.

- **BREAKING CHANGE: `analyze --output json` and `scan-org` now emit one
  `ScoredDependency` shape (schema v2).** Both commands described the same
  concept and agreed on 5 keys out of ~21; the rest were silent renames of
  identical data — `installed_version`/`version`, `scores`/`component_scores`,
  `has_known_exploits`/`known_vulnerable`, `vulnerabilities`/`advisories`,
  `advisories`/`details` — so a consumer of the documented agent workflow had
  to write two parsers for one concept. Both paths now serialize from
  `dependency_risk_profiler.contract.scored_dependency`, and every document
  declares `schema_version` on its envelope.

  Org-only concepts (`blast_radius`, `usage`, `version_specs`, `remediation`)
  moved under a declared `extensions.org_scan` block. An extension may add
  keys; it may never rename or shadow a shared field.

  **`--schema v1` selects the previous pair of shapes, byte for byte**, on
  `analyze`, `scan-org` and `scan-user`. It is deprecated and **removed in
  1.0.0**. The deprecation notice goes to stderr, so stdout stays parseable.
  The v1 writers are frozen in `cli/json_v1.py` and `org_scan/report_v1.py`
  and are self-contained; they are not kept in sync with v2.

  Fixed in the process, because a mechanical rename would have preserved them:

  - **`analyze -o json` computed licence and community data on every run and
    never serialized it.** It emitted `scores.license_score` while withholding
    which licence produced it. Schema v2 emits `license` and `community` blocks
    on both paths.
  - **The advisory list was emitted twice** in `analyze`, under
    `vulnerability_summary.advisories` and again under `vulnerabilities`. It
    now appears exactly once, at `advisories.details`.
  - **`scan-org` dropped `applicability_unknown_count` /
    `applicability_unknown_reasons`**, collapsing "no applicable advisories"
    into "we could not tell whether these apply". Both survive on both paths.

- **BREAKING CHANGE: an unmeasured signal is now structurally distinct from a
  measured zero in the output.** The two-state `Measurement` stopped at the
  scorer; both writers flattened it to a bare `null`, which a consumer cannot
  tell from "measured, and the answer happens to be null". Schema v2 replaces
  `scores` / `component_scores` with `signals`, where each entry is
  `{"state": "measured", "value": …}` or `{"state": "unmeasured", "reason": …}`
  — so a consumer can tell not only *that* a signal is missing but *why*.

- **BREAKING CHANGE: `remediation` is a structured block, not a sentence.**
  `{action, fix_versions, target_version, detail}` with an enumerated action
  (`upgrade_to_fixed_version`, `upgrade_to_latest`, `replace`, `no_action`,
  `unclassified`) so an agent branches on a value instead of regexing prose.
  `unclassified` is the escape variant: an unclassifiable case is reported as
  such rather than force-fitted into a neighbouring action. `fix_versions` and
  `target_version` are treated as untrusted registry data — anything that could
  not be a version is refused rather than published.

  The CSV report's `remediation` column is now that same block rendered as one
  sentence, rather than a second precedence chain over the same facts. Two
  independent descriptions of one dependency can disagree, and this pair did
  worse than drift: the prose path printed raw registry version strings that
  the structured path had already refused as unsafe to publish. The wording of
  the column changes as a result — it names the action and the version facts
  the structure carries, and is blank for `no_action`.

### Fixed

- **A repository the scorecard checks could not read reported as a repository
  with nothing in it.** All five OpenSSF-style checks — security policy,
  dependency update tooling, signed commits, branch protection, maintained
  status — opened with `has_X = False` and returned that initial value on the
  broad `except` around the read and on the no-repository path alike. `False`
  is also the correct answer for a project that genuinely ships no
  `SECURITY.md`, so an unreadable file, a `git` subprocess that exited
  non-zero, or a type error part-way through came back as a confident negative
  finding that nothing in the output distinguished from a measured one. Unlike
  the advisory case this failed *closed*, inventing risk rather than hiding it,
  which is the more embarrassing direction to be wrong in: it accuses a project
  of neglect on the evidence of a permission bit.

  The readers underneath were the larger half of it. Each of the sixteen
  file-and-git readers caught its own exceptions and returned an all-`False`
  result dictionary, so the failure never reached the check function's own
  handler — an unreadable `.github/settings.yml`, the issue's own example, was
  swallowed a layer below where anyone was looking. Changing only the five
  return types would have produced a fix that never fired. The readers now let
  the failure propagate to their single caller, which is the one place that
  decides what it means.

  The five checks return `Optional[bool]`, answer `None` on both unmeasured
  paths, and say which one it was using the existing `UnmeasuredReason`
  vocabulary rather than a parallel one: `source_repository_unreadable` when
  there was no repository, `source_lookup_failed` when the read was attempted
  and raised. The paired score follows the same treatment — the initial `0.0`
  was the same lie with a decimal point. `analysis_helpers` guards each write on
  `is not None`, the way it already guards the contributor count and the commit
  cadence, so an unmeasured signal reaches the model as absent rather than as
  zero. Per #74 the scorer then drops it from both the numerator and the
  denominator; that arithmetic was already correct and is now pinned by a test.

  A genuine absence is still a finding. "We read the repository and there is no
  `SECURITY.md`" remains `False`, and is still scored, still reported.

  Measured on a real clone of this repository with `chmod 000` on `.git/`, which
  is what a clone owned by another account looks like in CI: before, the tool
  reported `is_maintained: false`, `has_signed_commits: false` and
  `has_branch_protection: false`, raised the total score from 0.865 to 1.341,
  moved the verdict from LOW to MEDIUM, and printed "Project does not appear to
  be actively maintained" about a repository committed to that week. After, the
  three signals report unmeasured and the verdict is UNKNOWN. The two checks
  that read only files are unaffected in both runs, and the readable control
  run is byte-identical before and after.

- **An advisory source that failed read exactly like one that found nothing.**
  `get_vulnerabilities` returned the empty list for a connection failure, a
  4xx, a GraphQL `errors` block, an unreadable body, an ecosystem the source
  does not cover, and a genuinely clean package. Six facts, one answer, and the
  answer was the reassuring one — at the tool's highest-weighted signal.

  It was also cached. An OSV outage during a scan did not merely report every
  package advisory-clean; it wrote that verdict to disk, where it was served
  back as a measurement until the TTL expired. A transient network failure
  became a persistent wrong answer, and nothing in the output told the two
  apart.

  Every source now answers with a result record rather than a list, so the
  three outcomes are distinguishable: advisories found, measured and none
  found, and lookup failed. The third leaves `exploit` **unmeasured** with the
  new `source_lookup_failed` reason, writes no advisory counts at all, adds a
  risk factor naming the sources that did not answer, and is **not written to
  the cache**. The cache schema version is bumped to 4 so that clean verdicts
  written by the old code are discarded rather than served past the fix.

  Partial failures are decided rather than lumped together. OSV and the GitHub
  Advisory Database are asked about a package by identity in an ecosystem, so
  their silence is an answer and their failure unmeasures the absence claim.
  NVD is reached by keyword search over CPE strings and can only ever add, so
  its failure degrades completeness — the result is not cached — without
  unmeasuring anything. A finding survives any failure and is reported as a
  floor: no outage elsewhere un-finds an advisory. A package is therefore never
  called clean because two sources of three answered, and a scan is never made
  unmeasured because NVD was slow.

  An ecosystem a source does not cover is an abstention, not a failure and not
  an answer. Per #164, no `NOT_APPLICABLE` is invented for it: if nobody could
  be asked at all, the signal is unmeasured with `lookup_not_attempted`.

  Measured on a seven-package Python manifest with OSV forced offline: before,
  all seven scored `exploit: 0.0`, `known_vulnerable: false`, and seven cache
  entries were written. After, all seven report `exploit: unmeasured
  (source_lookup_failed)` and nothing is cached. With OSV reachable, four of
  those seven are in fact known-vulnerable.

  One shape note for whoever edits `RiskScorer.score_dependency` next. Its
  50ms-per-100-dependencies SLA is enforced *with coverage instrumentation
  active*, and under instrumentation that method sits on a cliff: adding as few
  as five physical lines to it — comments included, which generate no bytecode
  at all — costs about 30% of the budget, while the same lines in a helper or at
  the end of the file cost nothing measurable. So the second fact travels to
  `_measure` as one tuple rather than as two arguments (a two-argument tail puts
  fifteen call sites onto four lines apiece), and the new risk-factor branches
  live in a module-level `advisory_risk_factors` with their explanation. Scoring
  ends up 5% slower than before under instrumentation and 4% slower without it,
  against an unchanged threshold.
- **NuGet resolves version properties defined in `Directory.Build.props`.** A
  `.csproj` that declares `Version="$(SomethingPackageVersion)"` and defines the
  property one directory up resolved to `unmanaged` — honest under the #141
  contract, and a total loss of the version-drift signal for a repository shape
  that is not rare. Newtonsoft.Json's own project is exactly it: seven package
  references, seven properties, none of them defined in the file that uses
  them, all seven unmeasured.

  Precedence follows MSBuild's evaluation order rather than convenience.
  `Directory.Build.props` is imported first, so anything the project defines
  wins over what it inherits, and so does anything the
  `Directory.Packages.props` defines. `ManagePackageVersionsCentrally` is read
  from it too — Dapper sets the switch there — because reading a file for
  versions and not for the property that decides whether those versions apply
  is how a confident wrong answer gets produced. Only `<PropertyGroup>` content
  is taken; `<Import>` chains and `<PackageReference>` items in that file are
  still not followed, and anything unresolved stays `unmanaged` rather than
  becoming a guess.

  Both walks share one traversal, both files are read through the XXE-safe
  reader, and an unparseable or missing one leaves the versions that needed it
  unmeasured instead of taking the parse down.

- **A package npm removed for malware read as current and undeprecated.** npm's
  security team does not delete a package it pulls; it republishes the name as
  a placeholder described `security holding package` at a version carrying a
  `-security` prerelease tag, and repoints `dist-tags.latest` at it. `crossenv`,
  pulled for stealing environment variables, answers `0.0.2-security`.

  Read as a release, that inverts the finding: an installed `6.1.1` scores as
  *ahead* of the registry, so the drift signal reports no drift, and the
  placeholder carries no `deprecated` notice, so nothing else in the payload
  flags it either. It is cargo's `"0.0.0"` in npm's dialect — a parseable semver
  of exactly the right type that is not a release of the package at all.

  The placeholder is now recognized (both markers required: the description and
  the `-security` suffix, so a legitimate out-of-band security release is not
  caught) and nothing downstream reads it as a release. `latest_version` stays
  unmeasured, its empty manifest is not read as a measured zero dependency
  count, and the dependency is marked deprecated, which is where the finding
  belongs. `additional_info.npm_security_holding_package` records why.

- **GitHub answers `cvss.score: 0` for an advisory it never scored.** The
  GraphQL `cvss` block is non-nullable, so an advisory with no CVSS vector
  still returns a score, and the score it returns is `0.0` — lodash's
  `GHSA-p6mc-m468-83gg` is severity HIGH with `{"score": 0, "vectorString":
  null}`. Copied out verbatim, a high-severity advisory claimed the bottom of
  the scale in every payload that carried the record. `vectorString` is the
  tell — null exactly when no vector was assigned — so a zero without one is
  now unmeasured, and a zero *with* one is kept as the real (if unusual) score
  it is.

- **A measured maximum CVSS of 0.0 was published as "no CVSS measured".** #216
  fixed the per-advisory falsy read (`if cvss_score:` → `is not None`) and left
  the accumulator one line down, which started at `0.0` and emitted
  `max_cvss if max_cvss > 0 else None`. It now starts unmeasured and takes a
  maximum over the advisories that actually stated a severity, so `null` in
  `max_counted_cvss_score` means nobody scored them and `0.0` means somebody
  did. An advisory whose severity is UNKNOWN contributes nothing rather than
  fabricating a measured zero.

- **A contributor count of zero was thrown away as though nobody had looked.**
  `count_contributors` answers `None` for a count it could not take (a shallow
  clone, a git failure) and an int for one it did, and the analyze path guarded
  it with `if contributor_count:` — so a measured zero left
  `maintainer_count` unset and unattributed, in the one field where "none" and
  "unknown" point opposite ways for the maintainer-concentration score. The
  same falsy read in the community pass dropped a zero on the way to
  `contributor_count`. Both guard on `None` now, as the commit-cadence read
  beside them already did.

- **A shape error in an advisory payload could still be reported as "this
  package has no advisories".** #216 hardened what the OSV and GitHub Advisory
  normalizers do with a wrong-typed field, but left them running *inside* the
  `except Exception` that wraps the fetch, so any residual parse failure was
  still caught by a handler whose answer is an empty advisory list — the
  fail-open that turned `severity.upper()` on a boolean into a clean bill of
  health. Both sources now decode the body inside the handler and normalize
  outside it, so a fetch failure still degrades quietly and a parse failure
  surfaces instead of masquerading as a clean package.

- **The advisory cache served one package's advisories for another.** Cache
  filenames were built by sanitizing the package name, and sanitizing loses
  information, so two distinct packages could land on one entry — in either
  direction: a clean package inheriting advisories, or a vulnerable one reading
  as clean. `/` was rewritten to `__`, so composer's `foo/bar` and a literal
  `foo__bar` were one file; and the key kept the source casing, so npm's
  grandfathered `Foo` and a separate `foo` were one file on macOS and Windows,
  which are case-insensitive by default. The second was the worse of the two
  because it depended on the developer's filesystem: it reproduced for some
  people and not others, on the platforms most people run locally.

  Both keys are now a SHA-256 digest of `f"{ecosystem}\x00{package_name}"`. The
  NUL separator cannot appear in either input, so no two `(ecosystem, package)`
  pairs can produce the same joined string — `("a", "b/c")` and `("a/b", "c")`
  stay distinct. Hashing rather than extending the replacement list also
  retires three problems that were queued behind the same design: a
  300-character package name exceeded `NAME_MAX` and failed to write, a NUL
  byte in a name raised `ValueError` out of `open()`, and traversal-shaped
  names stop being a question anyone has to re-answer. (They were never a
  vulnerability — `"../../etc/passwd"` produced the literal filename
  `python_..__..__etc__passwd.json` — but the digest closes it structurally.)

  The in-memory cache in `aggregator.get_cache_key` collided the same two ways
  and one more. It lowercased unconditionally, so `Foo` and `foo` shared an
  entry on *every* platform, and its `:` separator could not split maven
  coordinates back apart, where the package name is itself `group:artifact`.
  The OSV batch pre-warm folded case in its dedupe set for the same reason.
  Both are case-exact now. The cost is that `Flask` and `flask` occupy two
  entries on registries that fold case: a lookup, where the collision cost
  correctness.

  Cache filenames stop being human-readable; the `package` and `ecosystem`
  fields inside each record carry that, and nothing reads a filename for
  meaning any more — `clear(ecosystem=...)` reads the recorded ecosystem
  instead of matching a filename prefix, which is also exact where the prefix
  match was not. `CACHE_SCHEMA_VERSION` goes to 3, so a record written under
  the old layout into a shared cache directory is discarded on read rather than
  scored against. (#212)

- **A JSON `true` in a CVSS field scored as a real severity.** `bool` is a
  subclass of `int`, so `true` satisfied a numeric guard and was returned as
  `True`, behaving as `1.0` downstream: a malformed or hostile registry payload
  produced a valid-looking LOW severity finding instead of an honest refusal.
  The return path was fixed in the previous release; this is the sweep of
  everywhere else the shape survived.

  The NVD and GitHub Advisory normalizers copied `cvssData.baseScore` and
  `advisory.cvss.score` into the record verbatim, so the boolean reached the
  cache and every consumer that did not re-normalize. Both now normalize at the
  point of extraction, as OSV already did. The same pass fixes the mirror-image
  bug beside it: NVD's confidence read `severity or cvss_score`, so a *measured*
  `0.0` — a score NVD published — was treated as a missing one.

  Withdrawal got the same treatment in the other direction. `withdrawn` is an
  RFC 3339 timestamp in both OSV's and GitHub's schemas, but `bool(...)`
  accepted any truthy JSON value, so a payload carrying `"withdrawn": true`
  suppressed a real advisory from the score without ever naming a withdrawal
  date. A withdrawal now requires the timestamp its schema promises.

  Adjacent string fields that arrived as something else were doing damage of
  two kinds. `vuln.get("severity", "").upper()` and `status.lower()` raised
  `AttributeError` on a boolean or null, and the caller's broad `except
  Exception` turned that crash into "this package has no advisories" — a
  fail-open on the whole lookup. Elsewhere the wrong-typed value was simply
  copied through, putting a JSON `true` in `published`, in a `fixed_versions`
  list nothing can version-order, and in reference URLs. All of these are read
  through type-checked accessors now.

  `None` from `normalize_cvss_score` means **unmeasured**, not "no severity",
  and downstream honors that: the advisory falls to `UNKNOWN` severity and is
  filtered with the reason `unknown severity` recorded, rather than scored as
  `INFO`. A severity string NVD states independently still scores — an advisory
  rated CRITICAL with a junk `baseScore` stays CRITICAL. (#213)

- **`scan-org` produced a different risk figure for identical input across
  runs.** The org repository summary averaged a float over the dependencies in
  a repository, and read those dependencies out of a `set`. Set iteration order
  for strings varies with `PYTHONHASHSEED`, which CPython randomises per
  process, and float addition is not associative — so `average_risk_score`
  moved in its last bit from one run to the next, with nothing about the input
  changed. A last-bit difference, but a real one, in a number the tool
  publishes: it defeats byte-comparison of two reports (exactly the wall the
  schema-v2 work hit while proving its `--schema v1` guarantee, which it could
  only get by pinning `PYTHONHASHSEED=0`) and it breaks scan-to-scan diffing,
  since "what changed since last week" is worthless if a number moves when
  nothing did. The summary now accumulates in sorted identity order.

  Worth recording, since it explains why CI did not catch this: CPython 3.12
  gave `sum()` Neumaier compensation, which hides the symptom on 3.12 for
  values in this range. It was live on the 3.9-3.11 jobs. A published number's
  stability should not rest on the interpreter's summation algorithm. A test
  now asserts the property the honest way — two `scan-org` runs under different
  `PYTHONHASHSEED` values in child processes, compared byte for byte — with a
  second test pinning the fixture's order-sensitivity so the sweep cannot
  quietly become decorative. A sweep of every other `sum()` and float aggregate
  in `src/` found no second instance: the rest sum over lists, or sum integers.

### Removed

- **BREAKING CHANGE: four fields are gone from the JSON output** rather than
  carried into the frozen contract, all still available under `--schema v1`:
  `display_name` and `versions_display` were string formatting over fields
  already in the payload; `key_signals` was a third hand-maintained
  English-string generator over the same scores `risk_factors` already
  describes; the per-dependency `unknown_signal_count` is
  `len(unknown_signals)`. The HTML, terminal and CSV reports now render the
  scorer's own `risk_factors`, so there is one generator instead of three.
  `version_specs` is **kept**: it is the set of raw specifiers different
  manifests declared, and no formatting reconstructs it from one resolved
  version.

- **BREAKING CHANGE: the simulated code-signing subsystem is gone, along with
  the public API it exposed.** `src/dependency_risk_profiler/secure_release/`
  (1784 lines across `code_signing.py`, `release_build.py`,
  `release_management.py`, and a packaged `github_actions_ci_cd.yaml` template)
  is deleted, and with it these names, which were re-exported from the
  top-level package and are therefore importable by anyone who has
  `pip install`ed 0.4.0:

  - `dependency_risk_profiler.sign_artifact`
  - `dependency_risk_profiler.verify_signature`
  - `dependency_risk_profiler.create_release`
  - the `dependency_risk_profiler.secure_release` subpackage in its entirety,
    including `SigningMode`, `BuildMode`, `VersionBumpType`, `scan_for_malware`,
    and `python -m dependency_risk_profiler.secure_release.code_signing`

  None of it was reachable from any CLI command, and none of it did what its
  name said. `retrieve_signing_key` returned `os.urandom(...)` on every call in
  *both* TEST and RELEASE mode, so no key was ever persisted and no signature
  could ever be verified by a second call. `create_signature` was
  `sha256(file_hash || key)`, with the real PSS implementation sitting commented
  out directly above it — no asymmetric key, nothing a third party could check,
  no non-repudiation. `scan_for_malware` set `scan_result = True`
  unconditionally, with the `clamscan` invocation commented out, while its
  docstring advertised a `False` branch that did not exist. A supply-chain risk
  tool was publicly exporting a signature verifier that verified nothing and a
  malware scan that could not fail.

  **Removed rather than deprecated, deliberately.** A deprecation cycle would
  leave a fake signature verifier callable and importable for at least one more
  release, which is precisely backwards for a security fix: the whole problem is
  that the function is reachable and misleading. There is no correct migration
  target to point a deprecation warning at, because the project does not sign
  releases and should not do so from inside the scanner — real signing needs key
  management, timestamping, and revocation, and belongs in CI (sigstore/cosign),
  not in a library function.

  **Version implication:** this is a breaking removal of published public API.
  Under 0.x semantics this warrants a **minor bump to 0.5.0 at minimum**; post-1.0
  it would be a major bump. Maintainer's call, but do not ship it as a patch.

  **If you were calling these:** you were not getting a cryptographic guarantee,
  so there is nothing to preserve. For artifact verification, use the Sigstore
  attestations that PyPI trusted publishing already produces for this project's
  own releases, or `sigstore`/`cosign` directly for your own.

  The release workflow (`.github/workflows/release.yml`) was the one real
  consumer: it called `sign_artifact(..., SigningMode.RELEASE)` on every tagged
  release, attached the resulting `.sig` files and `signing.log` to the GitHub
  Release, and printed release notes claiming the release was "cryptographically
  signed using the project's secure release system." That step is removed, the
  `.sig`/`signing.log` uploads are dropped, and the notes now describe only what
  is actually true: SHA256 checksums plus the PyPI trusted-publishing Sigstore
  attestations (which were already enabled). Past releases carrying `.sig` files
  should be treated as unsigned. (#174)

### Security

- **The `?go-get=1` vanity lookup validated the hostname, not the address it
  resolved to.** A module path in a scanned `go.mod` names a host we then fetch
  from. Every check that fetch made was on the name — https, no credentials, no
  port, public host, no IP literal — and a name an attacker registers is free
  to resolve to `169.254.169.254`. That is DNS rebinding, it defeated all of
  them, and `scan-org` walks every repository in an organization, so one hostile
  repository in scope was enough to aim a request from the scanning host at its
  own metadata service. Fetching now resolves the host itself, refuses the host
  outright if **any** returned address is private, loopback, link-local,
  reserved, multicast or a known cloud-metadata endpoint, and connects to a
  validated address rather than to the name — while still presenting the
  hostname for SNI, the `Host` header and certificate verification, so TLS is
  unweakened. Redirects are followed by us rather than by the HTTP client
  precisely so that every hop is re-resolved and re-validated: a 302 to a
  rebinding host is refused exactly like a first hop would be.

  The control lives in a new `dependency_risk_profiler.secure_http`, not in
  `go_modules`, because #136 consolidates package-to-repository resolution
  across every ecosystem and each one turns a third-party registry string into
  an outbound request. Go is the first caller of this, not the owner of it.
  (#138)

### Fixed

- **`transitive_source` was fail-open: an absent marker read as *measured*, so
  a dependency nobody resolved scored a confident `0.0` for transitive risk.**
  This is #141's fabricated zero surviving in one field. #141 marked the
  unmeasured cases explicitly but never inverted the default, so the guarantee
  held only where someone remembered to annotate — and the places nobody
  annotated were not hypothetical. The org scan (`org_scan.pipeline`) never
  calls the transitive analyzer at all, so *every* dependency it scored arrived
  with an unset marker and got a free `0.0`; a crash part-way through
  resolution did the same to whatever the analyzer had not reached yet. PR #198
  found the near-miss that proves the hazard was live: Maven was writing its
  marker as a bare `"transitive_source"` string literal rather than through the
  recorder, one typo from silently reverting to fabricating zeros, with no test
  failing because `0.0` is a perfectly plausible score. The read now fails
  closed (`signals.transitive_is_measured`), `_calculate_transitive_score`'s
  `measured` argument is keyword-only and defaultless — the #189
  `record_source_repository` shape — and a set carrying no source marker is
  declined rather than credited to an unnamed resolver.

  **Scores move, for real dependencies.** An unmeasured signal leaves both
  numerator and denominator (#74), so removing a fabricated `0.0` *raises* the
  reported risk of everything it was diluting, and costs one measured signal
  against the insufficient-data bar. Verified against the captured registry
  fixtures for all eight ecosystems, scored the way the org scan scores them:
  12 of 25 moved, all of them in the five ecosystems whose adapter reads no
  dependency list (nodejs, python, cargo, rubygems, golang) — express 0.95 →
  1.04 and LOW → UNKNOWN, request MEDIUM → UNKNOWN, flask LOW → UNKNOWN,
  hpricot LOW → MEDIUM, sklearn 2.25 → 2.47. The three ecosystems that
  genuinely measure transitive dependencies are byte-identical: nuget reads the
  `.nuspec` `<dependencies>` (#129), maven the POM's scope-filtered
  `<dependencies>`, composer the p2 entry's `require` block (#180). An audit of
  all eight confirmed those are the only three that populate the field at all.
  `MIN_MEASURED_SIGNALS` is unchanged and correct: no ecosystem measures more
  than it did, and the three that measure transitive were already floored
  including it.

  For npm lockfiles the analyzer now records `manifest` only for packages the
  lockfile actually names. A package absent from the lock resolved to the empty
  set and was stamped as measured, which claimed the manifest said "none" when
  it said nothing. Packages the lock does name are unaffected, including the
  genuine measured zero for a leaf with no dependencies of its own. (#199)

- **The `source_repository` signal has three states, and was recording two of
  them as one.** `record_source_repository` marks whether a registry *declares*
  a source repository, which is what lets the scorer treat "this package
  publishes no repo" as one measured fact rather than eight independent
  unmeasured signals (#146). It only ever wrote DECLARED or UNDECLARED, so
  "declared a repository nobody can read" was indistinguishable from "declared
  none". Maven Central serves the pair that proves the difference:
  `commons-collections:commons-collections:3.1` carries no `<scm>` element at
  all, while `log4j:log4j:1.2.17` declares one and every spelling of it is
  Subversion. PR #175 had already found the discriminator across 25 sampled
  artifacts — 9 declaring nothing, 12 naming SVN or CVS, 4 naming a git forge
  and all 4 resolving — and it was being thrown away. There is now a third
  state, DECLARED-BUT-UNUSABLE, recorded whenever the registry's own
  source field carries something that does not canonicalize to a repository on
  a supported host. **Scores will move**: it scores 0.75 rather than the 1.0
  those packages used to get. The discount is for the declaration itself, which
  is real evidence about a project's publishing hygiene and its era; it is only
  a discount because the operative consequence is unchanged — nobody can read
  the source either way, so the eight repository-derived signals stay dark and
  the #146 collapse still applies to both states. Affected: every ecosystem, and
  Go modules most of all, where a path resolving to `go.googlesource.com` or a
  private vanity host now reads as declared-but-unusable rather than as
  declaring nothing (Go has no separate repository field — the import path *is*
  the declaration, so a Go module is never UNDECLARED). (#176)

- **nuget resolved a source repository and then reported nothing about whether
  one was declared.** `NuGetAnalyzer` read `<repository url>` off the nuspec,
  set `dep.repository_url`, and never called `record_source_repository`, so
  `_calculate_source_repository_score` returned `None` and the signal was
  dropped from `weighted_scores` entirely. nuget was the only ecosystem scoring
  15 signals where the other seven scored 16, and the absence read as though
  nuget.org had said nothing either way — it says plenty, since a nuspec either
  carries `<repository>` or it does not. Worse, a .NET package declaring no
  repository counted eight separate unknowns instead of one explained gap,
  which is the arithmetic that pushed abandoned packages to UNKNOWN in the
  first place. `MIN_MEASURED_SIGNALS["nuget"]` moves 8 → 9 in the same change,
  because a floor below measured coverage is a permission slip (#183, #158).

- **A failed registry lookup was being scored as "this package declares no
  source repository".** `ComposerAnalyzer` called `record_source_repository`
  outside the `if release is not None` guard, and `_get_latest_release`
  swallows a connection error, a non-200 and an unparseable body alike — so a
  404 and a network blip both came out as a confident 1.0, the highest score
  the signal has. Nobody asked Packagist anything. An unmeasured signal is
  excluded from both the numerator and the denominator, never defaulted (#74),
  and this is #141's fabricated zero in a different field. Sweeping the other
  seven adapters found the same ordering in maven (an artifact whose POM could
  not be fetched was recorded as declaring nothing) and in the Go vanity-import
  resolver (a host that never answered was indistinguishable from one that
  answered with nothing). All three now leave the key unset, which is the
  unmeasured branch the scorer already handled. (#182)

- **maven now follows `<parent>`, which is where Java keeps its licence.**
  Maven's convention is to declare `<licenses>` and `<scm>` once in a parent POM
  and inherit them, and the adapter read the artifact's own POM and stopped. So
  `com.google.guava:guava` reported no licence at all, and neither did any
  Apache Commons artifact — commons-lang3's licence is two hops up, in
  `org.apache:apache`. The parent chain is walked through the same bounded
  client #141 built for version resolution: `repo1.maven.org` over https only,
  redirects refused, coordinates matched against a strict grammar, a 2 MiB
  streamed cap, XXE-safe parsing, a bounded depth and the per-manifest fetch
  budget, with failures and successes memoized so twelve Spring starters sharing
  a parent cost one fetch between them. **Precedence is
  nearest-declaration-wins**, matching Maven (a child's own `<licenses>` block
  replaces the parent's rather than merging with it) and matching what #141
  already chose for properties and dependency management. The walk is lazy and
  stops once a licence and an SCM URL are known, so an artifact that declares
  both itself — jackson-databind, every modern Spring module — costs no extra
  request. Two deliberate divergences from Maven's own model builder, both
  documented in `pom_model.inherit_metadata`: the child `artifactId` is not
  appended to an inherited `<scm><url>`, because the consumer trims URLs back to
  the repository root anyway; and `<dependencies>` is not inherited, because an
  artifact's own dependency list is what it ships and a parent's is what its
  siblings ship. The `declared` argument #176 added to
  `record_source_repository` is fed the **inherited** `<scm>` rather than the
  artifact's own, so an artifact that inherits a Subversion or gitbox `<scm>`
  from its parent records UNUSABLE rather than UNDECLARED — recording it off the
  leaf POM would be #182's fabricated negative arrived at from a third
  direction, and it is not a rare shape: `org.apache.ant:ant` and
  `org.apache.velocity:velocity-engine-core` are both built that way.
  **Maven licence and source-repository scores will move for real
  dependencies**: guava and slf4j-api both go from below the measured-signal
  floor to at it (slf4j-api's `source_repository` moves 1.0 → 0.0, because it
  inherits `github.com/qos-ch/slf4j` two hops up and reading it as silence was
  the adapter's blindness rather than the artifact's), and commons-lang3 moves
  from MEDIUM to LOW on registry metadata alone. log4j and commons-collections,
  #176's three-state pair, both declare no `<parent>` and are unaffected. (#178)

- **composer now reads the Packagist `require` block.** Every p2 release entry
  names the package's own dependencies — the same fact nuget reads out of its
  `.nuspec` and maven out of its POM's `<dependencies>` — and composer marked
  the transitive signal unmeasured anyway, for every PHP package. Two judgement
  calls, both asserted by value against captured fixtures rather than described
  in a comment. **Platform constraints are not dependencies**: `php`, `php-*`,
  `ext-*`, `lib-*`, `hhvm` and `composer-*` describe the runtime a package needs,
  not something a consumer is exposed to through the dependency graph, and they
  are dropped. psr/log, whose entire `require` block is `{"php": ">=8.0.0"}`, is
  the proof — it measures zero dependencies rather than one. The filter tests
  the *vendor prefix*, not the name, because several real vendors start with
  exactly the prefixes a platform constraint does: `php-http/discovery`,
  `php-di/php-di`, `composer/semver`. mailgun/mailgun-php was captured for that
  edge — three of its six runtime dependencies are `php-http/*`, and a
  name-first filter would report three. **`require-dev` is
  not counted**: it is what building the package needs, not what installing it
  pulls in, so it is out for the same reason maven excludes `test` and
  `provided` scopes. swiftmailer is the proof — four runtime packages score
  0.1, and the six that fold in the dev block would score 0.25. **Composer risk
  levels will move**: `symfony/console` goes from UNKNOWN (insufficient data) to
  LOW, because the ninth measured signal is what carries it over the bar.
  `MIN_MEASURED_SIGNALS["composer"]` moves 8 -> 9, the highest floor of the eight
  ecosystems. (#180)

- **`community_score` measures development cadence, which it never has.**
  The score advertised a composite of popularity and development activity.
  `CommunityMetrics.commit_frequency` was read in six places and assigned in
  none, and its producer `calculate_commit_frequency` had zero callers, so the
  score was the star-count bucket verbatim — and star count is the weakest
  signal in this tool's own thesis, because it measures attention rather than
  maintenance. It was not even an honest unknown: the star half *was*
  populated, so the composite returned a confident number while silently
  dropping the half that mattered. **Community scores will move for real
  dependencies.** Cadence now comes from the GitHub commits API in both the
  analyze path and org scans; the git implementation is retained but skipped on
  the `--depth 1` clones the tool makes, because one reachable commit reads as
  a confidently dead project for every repository on earth (the split
  `count_contributors` already makes). Two consequences that had never fired in
  the tool's history now can: the "Low development activity" risk factor, and
  the matching line in the terminal report. (#166)

- **A half-measured community signal no longer reports as a whole one.**
  Popularity and cadence are now weighted independently rather than averaged
  into one entry, so an unmeasurable half leaves both the numerator and the
  denominator instead of being carried by the other half at full weight — #74's
  rule, applied one layer down. When cadence cannot be measured, output names
  `community_activity` in `unknown_signals` rather than implying it was
  considered. When *neither* half is measurable the pair still counts as one
  gap, not two, so this does not re-introduce the over-counting #146 fixed. The
  risk factors and terminal signals gate on their own half rather than on the
  average, which for a well-starred package with a dead commit log lands on
  exactly 0.5 and cleared no `> 0.5` threshold. (#166)

- **Five fields were computed, stored, and never read.** `fork_count`,
  `releases_count`, `downloads_count`, `SecurityMetrics.fixed_vulnerability_count`
  and `has_recent_security_update` reached no output, no score, and no risk
  factor. All five are deleted along with the code that produced them. This
  removes a per-dependency HTTP call to pypistats.org — an unaffiliated
  third-party service the scan contacted for a number nobody consumed. (#166)

### Added

- **A two-state measurement, enforced at construction, and a published signal
  vocabulary pinned to a Scorecard version.** (#164, steps 3 and 4)

  `signals.Measurement` is `MEASURED` with a value or `UNMEASURED` with a
  reason, and it refuses every other combination in `__init__`. Instances are
  frozen afterwards, so a value cannot be edited onto an unmeasured signal.
  That makes #141's confident `0.0` for a signal nobody measured, and #166's
  composite that degraded to its weakest component while still reporting as
  measured, unrepresentable rather than merely discouraged. The scorer now
  carries one per signal per dependency.

  Classification is centralized in `signals.unmeasured_reason_for()`, the only
  place that decides *why* a signal is unmeasured, from the catalog plus one
  keyword-only fact the scorer observed — never adapter-local judgment across
  eight adapters. `NOT_APPLICABLE` is **not** here: it is deferred behind a
  schema version until a consumer branches on it, because no conformance check
  can tell a wrong `NOT_APPLICABLE` from a right one. The reason enum is
  guarded by a test against it coming back under another name.

  `docs/signals.md` publishes the mapping from our stable signal names to
  OpenSSF Scorecard `v5.5.0`, with every approximate row marked approximate,
  and `testing/unit/test_signal_catalog.py` fails when the page and the code
  disagree. Our names are **not** renamed to Scorecard's: `signed_commits` maps
  to no Scorecard check at all at that tag — the nearest historical one,
  `Signed-Tags`, was removed after v2.0.0, and the stable `Signed-Releases`
  inspects release assets rather than git history — so adopting an upstream
  vocabulary would have traded the stability guarantee this work exists to make
  for the appearance of interop.

  Two stringly-typed measurement states move out of `additional_info` and onto
  typed fields: `DependencyMetadata.source_repository_state` (a
  `SourceRepositoryState`, written only by `record_source_repository`) and
  `.transitive_source` (written only by `record_transitive_source`, whose
  `source` argument is keyword-only with no default so the unmeasured state
  cannot be reached by omission). Maven had been writing the transitive marker
  as a bare string literal, which is the one spelling a typo would have turned
  into a permanent "unmeasured". `release_date_source` and `version_source`
  stay where they are: both record which write path won rather than whether a
  signal was measured, which is #164's provenance item, gated on its own
  benchmark and sequenced last.

  No change to the JSON output contract — verified byte-identical against
  `origin/main` on a fixed population. Cost measured rather than assumed:
  about +7.6 µs per dependency (11.91 → 19.52 µs), no additional retained
  memory, numbers and method in `docs/signals.md`.

- **A test that fails when a model field the code reads has no writer.** The
  generalized form of the sweep that found the above: any `models.py` field
  declared `= None`, read somewhere in `src/`, and assigned nowhere is a
  constant wearing a signal's name. Verified to fail when an assignment is
  removed. (#166)

- **The org-scan headline no longer reports the reassuring number on its own.**
  A scan of a 25-repo org led with "2 high-risk dependencies exposed across 1
  repositories" while 198 of its 1135 dependencies carried live advisories and
  812 could not be scored at all. Neither number means anything without the
  other, and the high-risk count is systematically depressed exactly when
  coverage is poor — a dependency that cannot be scored cannot score HIGH, while
  the advisory path keeps working — so the old headline got quieter as the tool
  measured less. The headline now reads
  `198 known-vulnerable · 2 high-risk · 812 could not be scored · 1135
  dependencies across 25 repos`, ordered by what demands action: known-vulnerable
  first (there is a fix and a version to move to), then the leading-indicator
  count, then the coverage caveat. Terminal, HTML, and JSON all carry all three;
  the JSON report gains `unscored_dependency_count`, and the HTML masthead gains
  an Unscored readout plus a sentence stating that the high-risk count is a
  floor, not a total. (#133)

- **A successful `analyze --output json` run can no longer emit zero bytes.**
  Pointing the tool at a directory with no manifests exited 0 and wrote nothing,
  so a consumer doing the obvious `run → json.load(stdout) → act` crashed on a
  run that succeeded — and walking an org means hitting manifest-free
  repositories constantly. Every path that can end a run early now emits the
  documented shape with empty collections and a `warnings` entry saying what
  happened: no manifests found, unsupported manifest, parse failure, and a
  manifest that declares no dependencies. A directory of several manifests emits
  one merged document rather than several concatenated ones, which `json.load()`
  rejected. The invariant is now enforced by a test that sweeps every one of
  those paths: **if the process exits 0 in JSON mode, stdout is parseable
  JSON.** (#147)

- **`Unsupported manifest file` now names the next step, and refusing everything
  is no longer a success.** Pointing `analyze` at `package.json` printed a bare
  error, then `Successfully analyzed: 0`, then exited 0. Requiring resolved
  versions is the right design — a range like `^4.13.4` has no version to score
  drift against — but the message said nothing about what to run instead. A
  small companion table now redirects `package.json` → `package-lock.json`,
  `Gemfile` → `Gemfile.lock`, `composer.json` → `composer.lock`, `Pipfile` →
  `Pipfile.lock`, and says whether that companion actually exists next to the
  input; `build.gradle` is told that Gradle lock file support is not implemented
  yet (#101) rather than pointed at nothing. Separately, because the parser
  registry matches manifest filenames exactly, a valid manifest saved under
  another name (`railsgoat-Gemfile.lock`) was rejected identically to an
  unsupported ecosystem — the message now names the parser that would have
  accepted the same bytes and what to rename the file to. No parser was added
  and no dispatch changed. A run that scored nothing because it refused every
  input exits 1; a directory with no manifests, and a manifest that parsed fine
  and declares nothing, both still exit 0. (#125)

- **NuGet projects using Central Package Management now resolve their versions.**
  Modern .NET solutions declare each version once in a
  `Directory.Packages.props` and leave the `PackageReference` bare — it is
  Microsoft's recommended layout for a multi-project solution, and eShopOnWeb,
  Microsoft's own reference application, uses it for all 18 of its packages. The
  parser read only the inline `Version` attribute, so every one of them parsed
  with an empty installed version, there was no drift to score, and the VERSION
  column rendered as a bare arrow. Resolution now walks up from the project
  directory to the nearest `Directory.Packages.props`, expands `$(Property)`
  references against that file's own `<PropertyGroup>` elements, honours
  `<ManagePackageVersionsCentrally>`, and lets a `VersionOverride` on the
  reference win over the central declaration. Nothing is guessed: MSBuild
  conditions are not evaluated, `<Import>` chains out of the props file are not
  followed, and a floating `1.2.*` or an open-ended range names a version only a
  restore could produce. Anything unresolved — including the common case of a
  single `.csproj` fetched without its props file — is reported as `unmanaged`
  and its version-drift signal is excluded from both numerator and denominator
  rather than scored as zero drift.

- **The NuGet analyzer now collects the signals every other ecosystem does.**
  It read a latest version and stopped, so it never set a repository URL and
  every repository-derived signal — staleness, health indicators, the five
  OpenSSF-style checks, community, license — was permanently unmeasured for
  every .NET dependency. Each package's own published `.nuspec` is now read for
  `<repository>`, the license expression, the declared authors, and the
  package's own dependencies, and the registration catalog is read for the
  publication date and the deprecation / unlisted markers. `<repository>` is
  preferred over `<projectUrl>` because a project URL is routinely a
  documentation site rather than a repository. **.NET scans will now report risk
  levels and scores where they previously reported `UNKNOWN`**, so a scan diff
  across this version can show large movement without anything having changed
  upstream. Measured against eShopOnWeb's `src/Web/Web.csproj`: 18 of 18
  `UNKNOWN` at 2.0 of 14 measured signals becomes 18 scored (7 MEDIUM, 11 LOW)
  at 13.9 of 14, with 18 of 18 versions resolved. The same manifest scanned
  alone, without its props file, still scores 18 of 18 at 10.2 of 14 with every
  version honestly reported as `unmanaged`.

  Every nuget.org read is fenced the way #128's Maven Central reads are: https
  and `api.nuget.org` only, redirects refused, ids and versions validated
  against NuGet's grammar before they become a URL path, bodies streamed and
  abandoned past 4 MiB, and a hard per-manifest fetch budget. The one URL that
  arrives inside a payload — a registration index's overflow page — is
  re-validated against the same host before it is fetched.
  `DEPENDENCY_RISK_NO_REMOTE_POMS=1` disables remote reads for NuGet too.

- **Maintenance cadence is now read from the registry first, and abandoned
  packages are scored instead of shrugged at.** Staleness was derived from the
  package's *repository*, which fails on exactly the packages the signal exists
  to catch: the more abandoned a package is, the more likely its repository is
  archived, renamed, deleted, or was never declared, so the more likely the
  lookup returned nothing and the dependency fell through to `UNKNOWN` with no
  cadence at all. `nose`, `pycrypto` and `distribute` each reported
  `staleness=None` — `pycrypto` while carrying two counted CRITICAL advisories.
  Every registry publishes when the package last shipped, and that answer
  cannot be broken by a repository rename, so it now wins and repository
  activity fills in only where the registry published no date. PyPI's per-file
  upload timestamps and `yanked` flag are read for the first time; npm's
  release date comes from the latest-tagged version rather than `time.modified`
  (which moves whenever any metadata changes, and reads July 2026 for a package
  last published in February 2020); Packagist, crates.io and RubyGems keep the
  dates they already read but stop having them overwritten by a clone. **Scores
  change for any dependency whose repository was unreachable, and shift
  slightly for the rest**, since release cadence and last-commit date are not
  the same number. Where a registry genuinely publishes no date the signal
  stays unmeasured (#74) rather than defaulting.

  Two supporting changes. PyPI's repository lookup now prefers a labelled
  `Source`/`Repository` project URL, trims it to its `owner/repo` root, ignores
  funding and issue-tracker links, and treats `home_page` — `None` on every
  modern package — as a genuine last resort instead of a way to mask a missing
  source URL. And "declares no source repository" is now a measured signal in
  its own right rather than a silent cause of `UNKNOWN`: a package that no
  longer says where its source lives is a leading indicator, and because that
  one fact explains why the seven repository-derived signals are quiet, it is
  no longer counted as seven separate gaps in the evidence. Packages with no
  declared repository — `phpstan/phpstan` on Packagist, all three abandoned
  PyPI packages above — now receive a risk level.

  The description-substring deprecation heuristic is gone. On a modern package
  `info.description` is the whole rendered README, so any project documenting a
  deprecated API of its own tripped it, and it still caught only one of five
  known-deprecated packages. It is replaced by `info.yanked` plus a strictly
  additive check of the one-line `info.summary`, which keeps the one true
  positive without the README's false-positive surface.

- **Maven dependencies that inherit their version now resolve it.** Java
  projects overwhelmingly declare a dependency without an inline `<version>`
  and inherit it from `<dependencyManagement>` — the project's own block, a
  parent POM's, or an imported BOM. WebGoat pins 4 of 46 inline. The parser
  read only the inline form, so the installed version was blank for the rest,
  the VERSION column rendered as a bare arrow, and there was no drift to score.
  Resolution now follows Maven's rules across the project's own block, the
  parent POM chain, and `<scope>import</scope>` BOMs (each resolved in its own
  property scope), fetching parent POMs and BOMs from Maven Central. Every
  remote read is fenced: https and `repo1.maven.org` only, redirects refused,
  coordinates validated before they become a URL path, bodies streamed and
  abandoned past 2 MiB, bounded parent and import depth, a per-manifest fetch
  budget, and a per-import allowance so one sprawling vendor BOM cannot spend
  it all. Set `DEPENDENCY_RISK_NO_REMOTE_POMS=1` to keep resolution offline;
  anything still unresolved is reported as `unmanaged` and its version-drift
  signal is excluded from both numerator and denominator rather than scored as
  zero drift.

- **The Maven analyzer now collects the signals every other ecosystem does.**
  It read a latest version and stopped, so it never set a repository URL and
  every repository-derived signal — staleness, health indicators, the five
  OpenSSF-style checks, community, license — was permanently unmeasured for
  every Java dependency. Each artifact's own published POM is now read from
  Maven Central for `<scm>`, `<licenses>`, and the artifact's shipped
  dependencies, and repositories are cloned once each rather than once per
  artifact (twelve Spring Boot starters share one repo). **Java scans will now
  report risk levels and scores where they previously reported `UNKNOWN`**, so
  a scan diff across this version can show large movement without anything
  having changed upstream. Measured against WebGoat's `pom.xml`: 46 of 46
  `UNKNOWN` with 502 unmeasured signals becomes 29 scored (2 HIGH, 14 MEDIUM,
  13 LOW) with 172 unmeasured; against OWASP wrongsecrets, 43 of 43 `UNKNOWN`
  with 444 unmeasured becomes 33 scored (2 HIGH, 19 MEDIUM, 12 LOW) with 103
  unmeasured.

- **An unresolved transitive dependency set is no longer scored as zero risk.**
  Transitive resolution only understands npm lockfiles and Python requirement
  sets; for every other manifest it logged `Could not extract dependency map`
  and left an empty set, which the scorer read as "no transitive dependencies,
  therefore no transitive risk". Unresolved sets are now marked unmeasured and
  excluded from the score (#74). **Scores can move in either direction for
  Maven, NuGet, RubyGems, Composer and Cargo manifests**, since one fabricated
  zero leaves the average and, for Maven, a real measurement replaces it. Two
  latent crashes on the same theme are fixed: the terminal report compared
  `deprecation_score` and `transitive_score` against a number without a `None`
  guard.

- **npm dependencies now report version drift.** `latest_version` was `None`
  for every npm dependency — 804 of 804 on OWASP NodeGoat's
  `package-lock.json` — so the version-drift signal, the one the tool leads
  with, was never computed for the largest ecosystem it supports. The registry
  data was fetched and then dropped on a shape mismatch: the packument at
  `registry.npmjs.org/<package>` has no top-level `version` key, because npm
  publishes the current release as `dist-tags.latest`. The adapter now reads
  `dist-tags.latest`, falls back to the `/<package>/latest` document for
  mirrors that omit dist-tags, percent-encodes scoped names
  (`@cypress/xvfb` -> `@cypress%2Fxvfb`), and **logs a warning when a lookup
  fails** — the failure was previously silent, which is why it survived. Two
  neighbouring reads of the same payload are fixed alongside it: deprecation is
  read from the version manifest where npm actually records it (the top-level
  `deprecated` key never existed), and repository URLs go through
  `canonical_repository_url`, so a `.git` substring inside a repository name no
  longer mangles the URL (`jekyll.github.io` -> `jekyllhub.io`). **npm scans
  will now show a version signal, and therefore different scores, for
  dependencies that previously had none.** Packages with no resolvable latest
  version keep the signal honestly unmeasured rather than scored at zero.

- **Go module paths now resolve to their source repository.** A module path is
  an import path, not a repository URL, and the resolver only understood the
  plain `github.com/owner/repo` form. Everything else — a `/vN` major-version
  suffix, a subdirectory module, a vanity import path — failed to resolve, so
  the dependency got *no* repository-derived signals at all. Measured against
  `gohugoio/hugo`'s `go.mod`, that was 93 of 180 dependencies (52%) with zero
  of ten signals, including `golang.org/x/net`, `golang.org/x/text` and the
  whole AWS SDK. One normalizer now applies the documented rules before any
  repository lookup: strip a trailing `/vN` (N >= 2); treat host plus the first
  two path segments as the repository on github.com / gitlab.com /
  bitbucket.org, with the remainder as a subdirectory; rewrite
  `golang.org/x/<name>` to its `github.com/golang/<name>` mirror without a
  network call; and resolve remaining vanity hosts from their `go-import` meta
  tag under strict bounds (hard timeout, response-size cap, redirect limit,
  public hosts only, prefix-cached so one lookup serves many modules).
  **Go scans will now report signals, and therefore risk levels and scores, for
  dependencies that previously came back `UNKNOWN`**, so a scan diff across
  this version can show large movement without anything having changed
  upstream. Modules that still do not resolve keep their signals honestly
  unmeasured rather than scored at a confident zero. As a side effect, each
  repository is cloned once per scan instead of once per module, so projects
  with many subdirectory modules from one repository do far less network work.

- **cargo and composer dependencies are scored instead of returning UNKNOWN.**
  Both adapters read a couple of fields off their registry and stopped, so the
  eight repository-derived signals — staleness, health indicators, license, and
  the five OpenSSF Scorecard-inspired checks — were never collected and every
  dependency tripped the `unmeasured > measured` bar. crates.io's `repository`
  and Packagist's `source.url` now resolve the source repository (trimmed to its
  `owner/repo` root, so workspace subdirectories and `.git` suffixes stop
  dropping it), release timestamps populate staleness, yanked/abandoned releases
  mark deprecation, and licence and maintainer counts come off the registry
  payload. **Manifests that previously reported nothing but UNKNOWN will now
  produce real risk levels**, so a scan diff across this version can show new
  findings without anything having changed upstream. Packages that genuinely
  publish no repository keep their repository-derived signals unmeasured rather
  than scored as zero. On real manifests: BurntSushi/ripgrep 0 of 13 scored →
  13 of 13 and tokio-rs/tokio 0 of 13 → 13 of 13, both going from ~5 of 14
  signals measured to 13; drupal/drupal 0 of 151 → 150 of 151, unmeasured
  signals down from 1371 to 158. The one package still `UNKNOWN`
  (`phpstan/phpstan`) publishes no source repository on Packagist at all, and
  the residual unmeasured signal on every dependency is `transitive`, which
  composer and cargo manifests have never resolved.

### Changed

- **More ecosystem spellings are now analyzed.** Analyzer dispatch is driven by
  the canonical ecosystem registry instead of a hand-maintained `if`/`elif`
  chain, so registry aliases the chain silently dropped — `java`, `dotnet`,
  `gems`, `node`, `py`, `pypi`, `go`, `ruby`, `php` — now route to the correct
  analyzer. **Scans that previously skipped dependencies under those spellings
  will now report findings for them**, so a scan diff across this version can
  show new results without anything having changed upstream. Every spelling the
  old chain accepted maps to the same analyzer as before, and unrecognized input
  is still skipped rather than raising.

### Fixed

- **Advisories are now matched against the installed version.** OSV is queried
  by package name, and every advisory it returned was counted toward
  `known_vulnerable` and scoring regardless of whether the installed version
  was in its affected range — the `affected` block was fetched and then
  discarded, so `affected_versions` was `None` on every advisory and no
  version filtering existed at all. A pin of Django 4.2 was counted for 153
  advisories including ones fixed in 1.3.4, 1.4.14, 2.0.3 and 4.0.4, and the
  CRITICAL driving its `max_counted_severity` and `has_known_exploits` flag had
  been fixed in 4.0.4, two minor releases earlier. Upgrading a package did not
  change its reading, which inverted the point of the tool.

  Affected ranges are now read from OSV's `affected[].ranges` event stream and
  `affected[].versions` enumeration and from GitHub Advisory's
  `vulnerableVersionRange`, and evaluated with **ecosystem-correct version
  ordering** — PEP 440, SemVer, RubyGems, Maven and NuGet each get their own
  comparator, because they order differently and a string or tuple comparison
  would quietly reintroduce the bug (`"1.10" < "1.9"` lexically; Maven sorts
  `1.0-alpha` below `1.0` but `1.0-foo` above it). Advisories ruled out carry
  the new `does not affect installed version` filter reason. Entries belonging
  to other packages in a multi-package advisory no longer bound this package's
  version.

  **Advisory counts drop sharply and `known_vulnerable` totals fall with
  them**, so a scan diff across this version will show large reductions
  without anything having changed upstream. On OWASP PyGoat: Django 4.2
  153 → 43 counted, Pillow 9.4.0 76 → 18, urllib3 1.26.9 19 → 8 (max severity
  CRITICAL → HIGH), cryptography 39.0.1 24 → 13. A fully patched pin now
  reports `has_known_exploits: false` instead of CRITICAL.

  Where applicability cannot be decided — no range in the advisory, no
  installed version, or a pin the ecosystem cannot parse — the advisory is
  still **counted**, and the reason is reported in the new
  `applicability_unknown` / `applicability_unknown_reasons` fields rather than
  being resolved by assumption in either direction (#74). The advisory disk
  cache carries a schema version, so entries written before this change are
  discarded on read instead of being scored for another day.
- **Calendar-versioned packages are no longer scored as SemVer.** A leading
  four-digit year in a date shape (`certifi 2022.12.7`, `pytz 2020.1`,
  `tzdata`, Go `vYYYY.MM.DD` tags) is now detected before version distance is
  computed, and drift is measured as elapsed time between the installed release
  and the latest release rather than as component distance. `certifi 2022.12.7`
  previously reported "4 major versions behind" and `pytz 2020.1` "6 major
  versions behind", warning about breaking upgrades that do not exist; they now
  read "3 years behind (calendar versioning)" and "6 years behind (calendar
  versioning)". **Version-difference scores drop for calendar-versioned
  dependencies**, most sharply for ones that are only months behind (previously
  a full major-version penalty, now scored on elapsed time), so a scan diff
  across this version can show lower scores without anything having changed
  upstream. When release timestamps are unavailable the drift signal is marked
  unmeasured and excluded from both the numerator and the denominator instead
  of being guessed at. SemVer packages and Go pseudo-versions
  (`v0.0.0-20210428235338-…`) are unaffected: detection requires the calendar
  *shape*, not merely a large leading number.

- **Unknown ecosystems no longer silently default to PyPI.** `infer_ecosystem`
  returned `"python"` for any URL it could not classify, so non-Python packages
  were queried against the wrong advisory source and came back clean. It now
  returns no ecosystem and the aggregators skip the dependency with a warning.

## [0.4.0] - 2026-08-01

### Changed

- **Scoring: the `maintained` signal now has its own tunable weight**
  (`maintained_weight`, default `0.20`). It previously reused
  `branch_protection_weight`, so the two OpenSSF Scorecard-inspired signals
  could not be tuned independently. Because this is a behavior-changing scoring
  default, **risk scores may shift for packages that expose both a
  branch-protection signal and a maintained signal.** The weight is wired
  through the config layer symmetrically with the other weights
  (`scoring_weights.maintained`).

### Fixed

- **Version-difference scoring no longer misclassifies hyphenated prereleases.**
  Installed versions containing `-` (for example `1.2.3-rc1` or Go pseudo-versions)
  were short-circuited to a flat `0.25` "version range" score. They are now parsed
  by real version distance, so a `2.0.0-beta` that is two majors behind scores as
  the major-version risk it actually is.
- **Staleness is now computed in UTC.** The last-updated timestamp is normalized
  to UTC (naive timestamps are assumed to be UTC) and compared against
  `datetime.now(timezone.utc)`, so staleness no longer varies with the host's
  local time zone.

[0.4.0]: https://github.com/williamzujkowski/dependency-risk-profiler/releases/tag/v0.4.0
