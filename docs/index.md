# Dependency Risk Profiler

[![CI](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![Coverage](https://raw.githubusercontent.com/williamzujkowski/dependency-risk-profiler/main/.github/badges/coverage.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![OSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/williamzujkowski/dependency-risk-profiler/badge)](https://securityscorecards.dev/viewer/?uri=github.com/williamzujkowski/dependency-risk-profiler)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Dependency Risk Profiler helps answer a practical dependency question: which packages deserve review before they become incidents? CVE count is only a lagging signal, so the tool scores leading indicators such as version drift, release cadence, maintainer concentration, provenance, and license risk. It also reports unknown signals honestly and filters advisory noise out of scoring.

Read the companion post: [Zero CVEs Is Not a Safety Rating](https://williamzujkowski.github.io/posts/2026-08-06-dependency-risk-leading-indicators/).

## Install

```bash
pip install dependency-risk-profiler
```

For source installs:

```bash
pip install -e .
```

## Quick Start

```bash
dependency-risk-profiler analyze requirements.txt
```

For JSON output:

```bash
dependency-risk-profiler analyze requirements.txt --output json
```

## Documentation

- [Getting Started](getting-started.md)
- [Installation](installation.md)
- [Basic Usage](basic-usage.md)
- [Configuration](configuration.md)
- [Scoring](SCORING.md)
- [Information Sources](INFORMATION_SOURCES.md)

## Supported Ecosystems

- Python: `requirements.txt`, `Pipfile.lock`, `pyproject.toml`
- JavaScript / TypeScript (npm): `package-lock.json`
- Go: `go.mod`
- Rust: `Cargo.toml` via crates.io
- Ruby: `Gemfile.lock`
- PHP (Composer): `composer.lock`
- .NET / C# (NuGet): `packages.lock.json`, `*.csproj`
- Java (Maven): `pom.xml`
