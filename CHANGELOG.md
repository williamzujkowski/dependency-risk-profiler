# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
