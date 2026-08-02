# Getting Started

Dependency Risk Profiler is built for dependency triage. It looks beyond CVEs and highlights leading risk indicators: old releases, version drift, small maintainer pools, provenance gaps, license risk, and noisy vulnerability feeds.

## Prerequisites

- Python 3.9 or newer
- `pip`
- A supported manifest such as `requirements.txt`, `package-lock.json`, `go.mod`, `Cargo.toml`, `Gemfile.lock`, `composer.lock`, `packages.lock.json` / `*.csproj`, or `pom.xml`

## Installation

```bash
pip install dependency-risk-profiler
```

For a local checkout:

```bash
pip install -e .
```

## First Analysis

Run the command with the manifest as a positional argument:

```bash
dependency-risk-profiler analyze requirements.txt
```

The report includes the detected ecosystem, dependency count, overall risk score, per-dependency scores, vulnerability counts, filtered advisory counts, and unknown signal counts.

For automation:

```bash
dependency-risk-profiler analyze requirements.txt --output json
```

## Next Steps

- Use [Basic Usage](basic-usage.md) for graph, recursive, and trend commands.
- Use [Configuration](configuration.md) to tune scoring weights and advisory sources.
- Read [Scoring](SCORING.md) for the scoring model and limits.
