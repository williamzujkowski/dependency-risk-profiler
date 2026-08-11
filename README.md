# Dependency Risk Profiler

[![CI](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![OSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/williamzujkowski/dependency-risk-profiler/badge)](https://securityscorecards.dev/viewer/?uri=github.com/williamzujkowski/dependency-risk-profiler)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Dependency Risk Profiler inventories what is knowable about a dependency across nine ecosystems — Python, JavaScript/TypeScript (npm), Go, Rust, Ruby, PHP, .NET, Java/Maven, and Java/Kotlin/Android via Gradle. It reads release cadence, maintainer concentration, provenance, version drift and license, **reports every signal it could not measure as unmeasured rather than as a clean value**, filters advisories that do not affect the installed version, and floors its verdict under any live advisory that does.

It works on a single manifest (`analyze`) or across every repository in a GitHub organization or user account (`scan-org` / `scan-user`).

## What this tool has and has not been shown to do

This README used to argue that leading indicators beat lagging ones. **That claim was tested against a pre-registered protocol and it lost**, so it has been withdrawn rather than left standing.

On 2,906 npm packages predicting two-year abandonment, **download count alone separated the classes better than the then-sixteen-signal score: AUC 0.696 against 0.577** (maintainer-clustered 95% CI on the gap [−0.155, −0.085]). Two of the protocol's own falsification lines fired. Re-run at three dates the score never exceeded 0.605, and the published figure was its best year, not its typical one. Ablations put `license` in negative territory — removing it *improved* discrimination, so it is out of the composite and reported on its own axis (#340). The composite is fifteen signals now, and no better validated for it: taking out a signal measured to be harmful is not evidence that what remains works.

So the honest summary is: **no evidence yet supports ranking dependencies by this score in preference to a popularity or advisory baseline.** What the tool does do, and what the same runs support:

- It says *unmeasured* when it has not measured something, instead of scoring the reassuring default. That is a correctness property, not a prediction, and it is enforced by tests.
- It floors a verdict under a live advisory affecting the installed version, so leading signals can raise a verdict but never lower it below a known fact. That is a policy, not a forecast.
- It filters advisories that do not affect the installed version, which is arithmetic and checkable against OSV.

### How much of the score has been tested: two signals of fifteen

Worth knowing before reading anything else here. The pilot measured `maintainer`, `license` and `source_repository`. Across seven runs — two definitions of abandonment at four dates — one carries information, one is actively harmful, and one does nothing:

| signal | effect of removing it | in how many runs |
|---|---|---|
| `maintainer` | **−0.073 to −0.084** — drops below chance in four of seven | 7 of 7, every interval excluding zero |
| `license` | **+0.016 to +0.044** — the score is *better* without it | 7 of 7, every interval excluding zero |
| `source_repository` | nothing, −0.015 to +0.013 | 7 of 7, every interval spanning zero |

`license` is no longer in the composite. It is reported on its own axis instead, as a compliance fact, and nothing has measured what it predicts (#340). So of the fifteen signals the score now weighs, two have ever been tested and one of those does nothing.

The other twelve have never been in any arm. Eight are repository-derived and untested (#339); two of those — `signed_commits` and `branch_protection` — cannot be reconstructed at a past date at all, so they may never be testable this way. `staleness` and `version` were deliberately excluded from the abandonment study as circular: low release cadence predicting the future absence of releases predicts a variable from itself.

So the composite's behaviour is unmeasured for most of what it computes. That is a statement about the evidence, not a defect report — but it is the context for every number above.

The full result, its method, and its limits are in [`docs/abandonment-pilot.md`](docs/abandonment-pilot.md); the protocol that pre-registered the falsification lines is in [`docs/validation-protocol.md`](docs/validation-protocol.md).

Three outcomes have been attempted. Abandonment ran, and is the result above. A **compromise backtest** was pre-registered and **halted at its own stop rule** — 2,074 dated npm cases arrive on only 43 distinct campaign days against a threshold of 75. A **maintainer-handover study** was pre-registered and **halted at its negative control** — its outcome turned out to be mechanically confounded with maintainer-set size, the very thing the signal measures.

[`docs/outcome-landscape.md`](docs/outcome-landscape.md) maps what is left, and why abandonment is so far the only outcome that clears all three requirements a validation needs: reconstructable at a past date, enough *independent* events, and not mechanically coupled to the signals. If a study ever supports a stronger claim, this section changes and cites it.

## Install

```bash
pip install dependency-risk-profiler      # from PyPI
pip install -e .                          # from source
```

## Quick Start: one manifest

```bash
$ dependency-risk-profiler analyze requirements.txt

Dependency Risk · requirements.txt (python)
3 dependencies · overall 1.8 / 5.0 · 2 signals could not be measured

RISK    DEPENDENCY  VERSION          LEADING SIGNALS                                   ADVISORIES              LICENSE
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
MEDIUM  flask       3.0.0 → 3.1.3    1 minor version behind · missing security policy  5 scored · 5 filtered   BSD-3-Clause
MEDIUM  urllib3     2.0.0 → 2.7.0    7 minor versions behind · unsigned commits        19 scored · 19 filtered MIT
MEDIUM  requests    2.31.0 → 2.34.2  3 minor versions behind · unsigned commits        8 scored · 8 filtered   Apache-2.0

Worst first. "filtered" = informational / withdrawn / low-confidence advisories excluded from the score.
ADVISORIES and LICENSE are reported beside the verdict, not inside it.
```

The maintainer-concentration signal reads the true contributor count from the GitHub API — supply a token via `--github-token`, the `GITHUB_TOKEN` / `GH_TOKEN` environment variables, or just an authenticated `gh` CLI (`gh auth login`). Without one it reports the count as unknown rather than guessing.

For machine-readable output:

```bash
dependency-risk-profiler analyze requirements.txt --output json
dependency-risk-profiler analyze path/to/project --recursive   # every supported manifest under a directory
```

## Scan a whole organization or account

`scan-org` and `scan-user` discover every repository for a GitHub org or user, deduplicate dependencies across them, and rank exposure by **blast radius** — how many repos each risky dependency reaches. They write a self-contained HTML report and, optionally, JSON and a flat CSV.

```bash
# Needs a GitHub token with repo read access.
dependency-risk-profiler scan-org pallets \
  --github-token "$GITHUB_TOKEN" \
  --output-html pallets-risk.html \
  --output-csv pallets-risk.csv

dependency-risk-profiler scan-user your-username --github-token "$GITHUB_TOKEN"
```

The HTML report leads with the most-exposed risky dependencies (each expandable for the full triage: why it is flagged, its advisories, every repo and manifest it appears in, and links to deps.dev / the registry / the source repo / its OpenSSF Scorecard), then the riskiest repositories, then a full inventory. Two axes are kept separate:

- **Risk level** (critical/high/medium/low/unknown) reflects the leading indicators above.
- **Known-vulnerable** is an orthogonal flag: the installed version has scored advisories. A well-maintained dependency pinned to a vulnerable version reads as *medium risk, but known-vulnerable — update the pin*.

Org and account scans derive maintainer, activity, and tests/CI signals from the authenticated GitHub API rather than cloning each repository, so they stay fast across hundreds of dependencies.

`scan-user` scans the repositories a user **owns** by default; pass `--include-collaborations` to also include repos they only contribute to in other orgs.

Useful flags: `--max-repos N`, `--include-archived`, `--include-collaborations` (scan-user), `--manifest-glob`, `--output-json`, `--concurrency N`.

## What It Scores

- **Version drift** — how far the installed version is behind the current release.
- **Release cadence** — whether the package still receives updates.
- **Maintainer concentration** — single-maintainer and low-maintainer packages carry more continuity risk.
- **Provenance and repository health** — source location, project metadata, tests, CI, contribution signals, and related supply-chain health checks.
- **License obligation** — permissive, copyleft, network copyleft, commercial, or unrecognized. Reported beside the risk level and **not scored into it**: what a licence obliges a consumer to do is a compliance fact, and folding it into a maintenance forecast measured worse in every run that tested it (#340).
- **Vulnerabilities** — advisories are considered, but withdrawn, informational, low-confidence, and below-threshold findings are filtered out of scoring (raise the bar with `--minimum-vulnerability-severity MEDIUM`). An advisory that applies to the installed version and states **no** severity is counted at every threshold, not filtered: whole databases publish none (`GO-*`, `RUSTSEC-*`, and every malicious-package `MAL-*` record), and silence about how bad something is is not a reason to say it is not there. Records that alias each other are one vulnerability and count once.

Two behaviors are intentionally conservative:

- **Unknown signals stay unknown.** The tool does not fill missing data with a confident medium score.
- **Advisory noise is separated from scored risk.** Known-vulnerability and licence obligation are each surfaced as their own axis rather than folded into the risk level. A fact about a package is not a forecast about it, and the tool refuses to average the two on your behalf.

## Commands

| Command | Purpose |
|---------|---------|
| `analyze <manifest\|dir>` | Profile a single manifest or a directory (`--recursive`). Supports `--output json`, dependency graphs (`--generate-graph`), and history/trends (`--save-history`, `--analyze-trends`). |
| `scan-org <org>` | Scan every repo in a GitHub organization; write HTML/JSON/CSV. |
| `scan-user <user>` | Same, for a user account. |
| `list-ecosystems` | List supported manifest types. |
| `generate-config <path>` | Write a sample configuration file. |

## Supported Ecosystems

Nine ecosystems, routed to OSV (and, where available, deps.dev) for advisories:

- Python: `requirements.txt`, `Pipfile.lock`, `pyproject.toml`
- JavaScript / TypeScript (npm): `package-lock.json`
- Go: `go.mod`
- Rust: `Cargo.toml` (via crates.io)
- Ruby: `Gemfile.lock`
- PHP (Composer): `composer.lock`
- .NET / C# (NuGet): `packages.lock.json`, `*.csproj`
- Java (Maven): `pom.xml`
- Java / Kotlin / Android (Gradle): `build.gradle`, `build.gradle.kts`, with versions resolved from `gradle/libs.versions.toml`

Which file each ecosystem is read from is a fact about that ecosystem, not a lockfile policy — `package-lock.json` and `Cargo.toml` are the same choice (read the file that names the whole dependency set) made in opposite directions. [`docs/signals.md`](docs/signals.md#which-manifests-are-read-and-why-it-is-not-the-lock-file) has the table of what is *not* read for each, and the argument. Anything on that list is recognized rather than skipped: `analyze` names it, says what it reads instead, and exits non-zero if it could not read anything else either — a scan that read nothing must not look like a scan that found nothing.

Gradle deserves a footnote, because it is the one entry here that is not a manifest format. `build.gradle` and `build.gradle.kts` are Groovy and Kotlin *programs*, and nothing in this tool executes them. The declarative shapes are read — string and map notation in either DSL, version-catalog aliases and bundles, `platform(...)` wrappers, `$property` interpolation from `ext { }` and `gradle.properties` — and anything computed at build time is reported with its version marked unmanaged rather than guessed at. A dynamic `1.+`, a version from an unreachable catalog, and a coordinate assembled by a helper function are all recorded as unmeasured, which drops version drift from that dependency's score instead of scoring a fabricated zero. `src/dependency_risk_profiler/parsers/gradle_dsl.py` enumerates every shape that is and is not read.

## Honest Limits

Dependency Risk Profiler is a heuristic triage tool, not a safety oracle. OpenSSF Scorecard describes its own checks as [automated heuristics](https://github.com/ossf/scorecard), and this project uses the same kind of evidence-driven approach: useful signals, not proof.

The tool relies on public package and advisory data — deps.dev, package registries, OSV, and (optionally) NVD and GitHub Advisory data. Missing metadata, registry outages, unpublished maintainer context, and private build systems can all affect results. Provenance can tell you who built or published an artifact; it does not prove that the publisher is trustworthy. Single-manifest `analyze` and org-wide `scan-org` derive some signals differently (a local clone vs. the GitHub API), so a dependency's risk level can differ slightly between them.

Use the output to prioritize review, upgrades, replacement decisions, and follow-up questions. Do not treat a low score, zero CVEs, or clean provenance as a guarantee.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Basic Usage](docs/basic-usage.md)
- [Using it from an AI agent](docs/agents.md) — the analyze → issue → fix loop, JSON fields, and `--fail-on` gating
- [Configuration](docs/configuration.md)
- [Scoring](docs/SCORING.md)
- [Information Sources](docs/INFORMATION_SOURCES.md)

## Contributing

See the [Contributing Guide](CONTRIBUTING.md).

## License

MIT License.
