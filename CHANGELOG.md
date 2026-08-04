# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
