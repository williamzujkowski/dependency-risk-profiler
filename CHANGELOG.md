# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

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

### Fixed

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
