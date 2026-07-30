# Dependency Risk Profiler

[![CI](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![Docs](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/docs.yml/badge.svg)](https://williamzujkowski.github.io/dependency-risk-profiler/)
[![Coverage](https://raw.githubusercontent.com/williamzujkowski/dependency-risk-profiler/main/.github/badges/coverage.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![OSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/williamzujkowski/dependency-risk-profiler/badge)](https://securityscorecards.dev/viewer/?uri=github.com/williamzujkowski/dependency-risk-profiler)
[![OSSF Allstar](https://img.shields.io/badge/OSSF-Allstar%20Protected-success)](https://github.com/ossf/allstar)
[![Python Versions](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CVE count is a lagging indicator: it tells you what has already been reported, not whether a dependency is drifting, under-maintained, opaque, or hard to replace. Dependency Risk Profiler triages Python, Node, Go, and Rust manifests on leading signals like release cadence, maintainer concentration, provenance, version drift, and license risk; it also reports unknown signals as unknown and filters advisory noise instead of turning every low-confidence or withdrawn vulnerability into score pressure. Companion post: [Zero CVEs Is Not a Safety Rating](https://williamzujkowski.github.io/posts/2026-08-06-dependency-risk-leading-indicators/).

## Install

From PyPI:

```bash
pip install dependency-risk-profiler
```

From source:

```bash
pip install -e .
```

## Quick Start

Run the profiler against a manifest file:

```bash
$ dependency-risk-profiler analyze requirements.txt

Dependency Risk Profile
Ecosystem: python   Dependencies: 3
Overall Risk Score: 2.44/5.0   (High: 1  Medium: 2  Low: 0  Unknown: 0)
Unknown Signals: 2

Dependency   Installed  Latest   Last Update   Maintainers  Risk       Vulns                              Status
flask        2.0.0      3.1.3    2 months ago  1            3.2/5.0    10 found/5 scored (5 filtered)     HIGH (single maintainer)
urllib3      1.26.5     2.7.0    < 1 month     1            2.3/5.0    38 found/19 scored (19 filtered)   MEDIUM (single maintainer)
requests     2.31.0     2.34.2   < 1 month     1            1.9/5.0    16 found/8 scored (8 filtered)     MEDIUM (single maintainer)
```

For machine-readable output:

```bash
dependency-risk-profiler analyze requirements.txt --output json
```

## What It Scores

- Version drift: how far the installed version is behind the current release.
- Release cadence: whether the package still receives updates.
- Maintainer concentration: single-maintainer and low-maintainer packages carry more continuity risk.
- Provenance and repository health: source location, project metadata, tests, CI, contribution signals, and related supply-chain health checks.
- License risk: permissive, copyleft, missing, or unusual license signals.
- Vulnerabilities: advisories are considered, but withdrawn, informational, low-confidence, and below-threshold findings are filtered out of scoring.

Two behaviors are intentionally conservative:

- Unknown signals stay unknown. The tool does not fill missing data with a confident medium score.
- Advisory noise is separated from scored vulnerability risk. Use `--minimum-vulnerability-severity MEDIUM` or a higher threshold when you only want more severe advisories to affect the score.

## More Usage

Analyze every supported manifest under a directory:

```bash
dependency-risk-profiler analyze path/to/project --recursive
```

Generate dependency graph data:

```bash
dependency-risk-profiler analyze requirements.txt --generate-graph out.json --graph-format d3
```

Track risk over time:

```bash
dependency-risk-profiler analyze requirements.txt --save-history
dependency-risk-profiler analyze requirements.txt --analyze-trends
```

List supported manifest types:

```bash
dependency-risk-profiler list-ecosystems
```

Generate a sample config:

```bash
dependency-risk-profiler generate-config dependency-risk-profiler.toml
```

## Supported Ecosystems

- Python: `requirements.txt`, `Pipfile.lock`, `pyproject.toml`
- Node.js: `package-lock.json`
- Go: `go.mod`
- Rust: `Cargo.toml` via crates.io

## Honest Limits

Dependency Risk Profiler is a heuristic triage tool, not a safety oracle. OpenSSF Scorecard describes its own checks as [automated heuristics](https://github.com/ossf/scorecard), and this project uses the same kind of evidence-driven approach: useful signals, not proof.

The tool relies on public package and advisory data such as deps.dev, package registries, OSV, NVD, and GitHub Advisory data. Missing metadata, registry outages, unpublished maintainer context, and private build systems can all affect results. Provenance can tell you who built or published an artifact; it does not prove that the publisher is trustworthy.

Use the output to prioritize review, upgrades, replacement decisions, and follow-up questions. Do not treat a low score, zero CVEs, or clean provenance as a guarantee.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Basic Usage](docs/basic-usage.md)
- [Configuration](docs/configuration.md)
- [Scoring](docs/SCORING.md)
- [Information Sources](docs/INFORMATION_SOURCES.md)

## Contributing

See the [Contributing Guide](CONTRIBUTING.md).

## License

MIT License.
