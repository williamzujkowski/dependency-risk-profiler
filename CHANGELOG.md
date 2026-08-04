# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
