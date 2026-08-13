# Dependency Risk Profiler

[![CI](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![OSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/williamzujkowski/dependency-risk-profiler/badge)](https://securityscorecards.dev/viewer/?uri=github.com/williamzujkowski/dependency-risk-profiler)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Dependency Risk Profiler inventories what is knowable about a dependency across nine ecosystems — Python, JavaScript/TypeScript (npm), Go, Rust, Ruby, PHP, .NET, Java/Maven, and Java/Kotlin/Android via Gradle. It reads release cadence, maintainer concentration, provenance, version drift and license, **reports every signal it could not measure as unmeasured rather than as a clean value**, filters advisories that do not affect the installed version, and floors its verdict under any live advisory that does.

It works on a single manifest (`analyze`) or across every repository in a GitHub organization or user account (`scan-org` / `scan-user`).

**Scope: maintenance risk.** The thing this tool tries to see is whether a dependency still has someone behind it. That matters for security because an unmaintained package with a disclosed vulnerability has nobody to fix it — measured here at **77.2% of npm packages carrying an unfixed advisory never publishing again** — but the tool does not detect compromise, malicious publishes, or exploitability, and nothing here should be read as if it did.

## What this tool has and has not been shown to do

**One place to read all of it: [`docs/what-this-tool-is.md`](docs/what-this-tool-is.md)** — ten studies, what they establish, what they do not, and the four things that are still unknown.

This README used to argue that leading indicators beat lagging ones. **That claim was tested against a pre-registered protocol and it lost**, so it has been withdrawn rather than left standing.

On 2,906 npm packages predicting two-year abandonment, **download count alone separated the classes better than the then-sixteen-signal score: AUC 0.696 against 0.577** (maintainer-clustered 95% CI on the gap [−0.155, −0.085]). Two of the protocol's own falsification lines fired. Re-run at three dates the score never exceeded 0.605, and the published figure was its best year, not its typical one. Ablations put `license` in negative territory — removing it *improved* discrimination, so it is out of the composite and reported on its own axis (#340). The composite is thirteen signals now, and no better validated for it: taking out a signal measured to be harmful is not evidence that what remains works. `signed_commits` and `branch_protection` were retired too — the first verified commits against a local GPG keyring a fresh clone never has, making it a merge-tooling detector rather than a security signal; the second could not observe the API property it was named for (#394).

So the honest summary is: **no evidence yet supports ranking dependencies by this score in preference to a popularity or advisory baseline.** What the tool does do, and what the same runs support:

- It says *unmeasured* when it has not measured something, instead of scoring the reassuring default. That is a correctness property, not a prediction, and it is enforced by tests.
- It floors a verdict under a live advisory affecting the installed version, so leading signals can raise a verdict but never lower it below a known fact. That is a policy, not a forecast.
- It filters advisories that do not affect the installed version, which is arithmetic and checkable against OSV.

### How much of the score has been tested: two signals of thirteen

Worth knowing before reading anything else here. The pilot measured `maintainer`, `license` and `source_repository`. Across seven runs — two definitions of abandonment at four dates — one carries information, one is actively harmful, and one does nothing:

| signal | effect of removing it | in how many runs |
|---|---|---|
| `maintainer` | **−0.073 to −0.084** — drops below chance in four of seven | 7 of 7, every interval excluding zero |
| `license` | **+0.016 to +0.044** — the score is *better* without it | 7 of 7, every interval excluding zero |
| `source_repository` | nothing, −0.015 to +0.013 | 7 of 7, every interval spanning zero |

`license` is no longer in the composite. It is reported on its own axis instead, as a compliance fact, and nothing has measured what it predicts (#340). So of the thirteen signals the score now weighs, two have ever been tested and one of those does nothing.

The other eleven have never been in any arm. Six are repository-derived and untested (#339). `staleness` and `version` were deliberately excluded from the abandonment study as circular: low release cadence predicting the future absence of releases predicts a variable from itself.

So the composite's behaviour is unmeasured for most of what it computes. That is a statement about the evidence, not a defect report — but it is the context for every number above.

The full result, its method, and its limits are in [`docs/abandonment-pilot.md`](docs/abandonment-pilot.md); the protocol that pre-registered the falsification lines is in [`docs/validation-protocol.md`](docs/validation-protocol.md).

Five outcomes have been attempted and the programme is now closed. Abandonment ran, and is the result above. A **compromise backtest** was pre-registered and **halted at its own stop rule** — 2,074 dated npm cases arrive on only 43 distinct campaign days against a threshold of 75. A **maintainer-handover study** was pre-registered and **halted at its negative control** — its outcome turned out to be mechanically confounded with maintainer-set size, the very thing the signal measures. A **repository arm** ran and licensed no claim. An **ownership-transfer study**, the only outcome measured independent of project activity, **halted at a channel pilot**: 41.3% of owner changes cannot be told apart from an account rename, because GitHub frees a renamed login and keeps no owner history.

**A composition study then tested what the score is made of**, with no outcome involved — and withdrew a conclusion this project had been circling. Five direct measures of publication activity explain **R² ≈ 0.099** of the composite's rank variance (0.075 / 0.094 / 0.099 at three dates). The score is **not** an activity proxy in disguise; it measures something largely orthogonal to activity and popularity alike, and that something is what fails to predict. [`docs/composition-result.md`](docs/composition-result.md).

**A sixth outcome then tested the substitution the whole programme stood in for** — *unmaintained means unpatched*. Among npm advisories with no fix at disclosure, **77.2% of packages never published again**, and of those that did, about half shipped the fix. So the abandonment framing is the right one. But against the question a user actually faces — *given a live advisory, will this get patched?* — **nothing the tool computes exceeds AUC 0.67**, `age_days` (which the tool does not compute) beats every signal that is in the composite, and CVSS severity is indistinguishable from chance at 0.4442, CI [0.3656, 0.5276]. [`docs/remediation-result.md`](docs/remediation-result.md).

[`docs/outcome-landscape.md`](docs/outcome-landscape.md) maps the retrospective attempt and why it closed. An outcome needs four things, and the fourth was learned the expensive way: reconstructable at a past date, enough *independent* events, not mechanically coupled to the signals, and **observable to a usable precision at the date it is claimed for**. Four outcomes failed on the third; the one that cleared it failed on the fourth.

### The one test that has never been run, now registered

Every result above scored a **degenerate variant** of this tool. At a reconstructed past date `staleness` was 1.0 for all 2,906 packages and `version` 0.0 for all, and the repository-derived signals were never reconstructed at all — so the score that lost to download count was a *three-signal* object. **The instrument users actually run has never been scored against any outcome.**

[`docs/prospective-protocol.md`](docs/prospective-protocol.md) fixes that by construction: score the full instrument today, on a fresh cohort, against whether each package goes quiet over the next twelve months. It is committed before any package was sampled, so the ordering is checkable from git, and it must beat **both** download count and its own `staleness` signal alone — because at a live date, time-since-last-release predicting no-release-in-a-year is autocorrelation, and a thirteen-signal instrument losing to one subtraction over its own input is a result worth naming rather than hiding.

The expected outcome, stated in advance, is that it fails. **That is the result this project has been unable to obtain in either direction for its entire history.** Readable 2027-08.

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

Two things to know about the score itself:

- **`total_score` is not comparable across packages with different measurement coverage.** The composite is a weighted mean over the signals that were *measured*, so a package scored on four signals and one scored on twelve share a scale without sharing a meaning. Measured on a uniform npm draw: the identical profile — maximally stale, single maintainer — scores a median **1.935 with no readable repository and 2.609 with one**. Nothing is imputed and no missing value is filled; the number simply summarises a different amount of evidence.
- **Read `total_score` with `insufficient_data`, never alone.** The JSON output carries `insufficient_data`, `measured_signal_count`, `unknown_signal_count` and `unknown_signals` in the same object for exactly this reason. When `insufficient_data` is true the tool is declining to issue a verdict, and the accompanying score should not be read as one.

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

### The score can be moved by the package being scored

Measured, not hypothesised, and worth knowing before anyone gates a pipeline on this number. Enumerating the scorer **over registry-only signals** — the state it is in for the ~53% of npm packages whose repository it cannot clone — gives a **twelve-cell lookup table** on maintainer band × repository state, and arithmetic over it says:

| | share of 2,906 packages |
|---|---:|
| score can be lowered at all | **88.4%** |
| lowered **with no publish at all** | **83.5%** |

`npm owner add` needs no release, and **the repository field is never verified** — nothing compares the declared repo's owner to the package's maintainers or looks for a reciprocal reference, so a package may declare any repository it likes. **41.51% of the composite's declared weight** is computed from that unverified URL. Whether declaring a repository also moves the tool from abstaining to answering is **currently unresolved, and an earlier claim here that it always does has been withdrawn** — that measurement came from a harvest that had failed to perform the advisory lookup and three other measurements the tool performs by default, so its abstentions were the harvest's, not the tool's. Re-measured with those signals collected, **no package in a uniform 2,000-package draw abstains at all**.

Scored with a repository actually cloned, the same enumeration gives 188 distinct values rather than 11 — so the lookup table describes the registry-only case, not the whole tool ([`docs/full-instrument-composition-result.md`](docs/full-instrument-composition-result.md)).

This is how repository-health scoring works generally — Scorecard, deps.dev and Libraries.io all read unverified self-declared links. What is specific here is the **concentration**, not a unique defect. An enumerated scoring function is also an instruction manual, and publishing the table obliges pricing the moves it exposes: [`docs/manipulation-result.md`](docs/manipulation-result.md), [`docs/full-instrument-manipulation-result.md`](docs/full-instrument-manipulation-result.md) and the enumerated table in [`docs/lookup-table-result.md`](docs/lookup-table-result.md).

## Documentation

- [Getting Started](docs/getting-started.md)
- [Basic Usage](docs/basic-usage.md)
- [Using it from an AI agent](docs/agents.md) — the analyze → issue → fix loop, JSON fields, and `--fail-on` gating
- [Configuration](docs/configuration.md)
- [Scoring](docs/SCORING.md)
- [Information Sources](docs/INFORMATION_SOURCES.md)
- [What this tool is, on the evidence](docs/what-this-tool-is.md) — the synthesis; start here
- [Prior art](docs/prior-art.md) — what OWASP, Scorecard, Snyk and Libraries.io measure, and what anyone has validated
- [Outcome landscape](docs/outcome-landscape.md) — every outcome attempted, and why the retrospective programme closed
- [Prospective protocol](docs/prospective-protocol.md) — the registered test of the full instrument, readable 2027-08
- [Manipulation results](docs/manipulation-result.md) — what the score costs to move

## Contributing

See the [Contributing Guide](CONTRIBUTING.md).

## License

MIT License.
