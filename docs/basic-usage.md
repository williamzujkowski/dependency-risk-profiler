# Basic Usage

This guide covers the essential commands and workflows for using Dependency Risk Profiler.

## Command Line Interface

Dependency Risk Profiler provides a comprehensive command-line interface (CLI) for analyzing projects.

### Available Commands

```bash
# Show help and available commands
dependency-risk-profiler --help

# List supported ecosystems
dependency-risk-profiler list-ecosystems

# Analyze a project
dependency-risk-profiler analyze path/to/project

# Generate a sample configuration file
dependency-risk-profiler generate-config --format toml
```

## Analyzing Projects

The core functionality is provided by the `analyze` command:

```bash
dependency-risk-profiler analyze [OPTIONS] PATH
```

### Common Options

- `--ecosystem TEXT`: Specify the ecosystem (python, nodejs, golang)
- `--output-format [terminal|json]`: Output format (default: terminal)
- `--config PATH`: Path to configuration file
- `--output PATH`: Write output to file
- `--verbose / --quiet`: Control log verbosity

### Examples

```bash
# Basic analysis with auto-detection
dependency-risk-profiler analyze .

# Specify ecosystem explicitly
dependency-risk-profiler analyze --ecosystem python .

# Output results as JSON
dependency-risk-profiler analyze --output-format json .

# Write results to a file
dependency-risk-profiler analyze --output results.json .

# Use a custom configuration
dependency-risk-profiler analyze --config my-config.toml .

# Analyze a specific manifest file
dependency-risk-profiler analyze requirements.txt
```

## Analyzing Multiple Projects

To analyze multiple projects or compare different dependency files:

```bash
# Analyze all Python projects in a directory
dependency-risk-profiler analyze --recursive .

# Analyze specific files
dependency-risk-profiler analyze package.json requirements.txt go.mod
```

## Working with Results

The analysis results can be used in various ways:

### Terminal Output

By default, results are displayed in a formatted terminal output:

```
Project Risk Analysis: my-project
--------------------------------
Overall Risk Score: 0.65 (MEDIUM)

Risk Categories:
  Vulnerability: 0.8 (HIGH)
  Maintenance:   0.4 (LOW)
  Community:     0.6 (MEDIUM)
  License:       0.3 (LOW)

High Risk Dependencies:
  outdated-pkg (0.9.2): 3 critical vulnerabilities
  abandoned-lib (1.0.0): No updates in 32 months
```

### JSON Output

For programmatic use or further processing, use the JSON output format:

```bash
dependency-risk-profiler analyze --output-format json . > results.json
```

This produces structured data that can be processed by other tools:

```json
{
  "project": "my-project",
  "timestamp": "2025-04-18T12:34:56Z",
  "overall_risk": {
    "score": 0.65,
    "level": "MEDIUM"
  },
  "categories": {
    "vulnerability": {"score": 0.8, "level": "HIGH"},
    "maintenance": {"score": 0.4, "level": "LOW"},
    "community": {"score": 0.6, "level": "MEDIUM"},
    "license": {"score": 0.3, "level": "LOW"}
  },
  "dependencies": [
    {
      "name": "outdated-pkg",
      "version": "0.9.2",
      "risk_score": 0.9,
      "risk_level": "HIGH",
      "issues": ["3 critical vulnerabilities"]
    },
    // More dependencies...
  ]
}
```

## Visualizing Dependencies

To visualize dependency relationships and risks:

```bash
dependency-risk-profiler visualize-graph path/to/project

# Output as different graph formats
dependency-risk-profiler visualize-graph --format d3 path/to/project
dependency-risk-profiler visualize-graph --format graphviz path/to/project
```

## Tracking Trends Over Time

To track how dependency risks change over time:

```bash
# Generate initial trend data
dependency-risk-profiler analyze --save-trends . 

# After some time/changes, update trends
dependency-risk-profiler analyze --save-trends .

# Visualize trends
dependency-risk-profiler visualize-trends
```

## Next Steps

- Learn about [Configuration](configuration.md) options
- Understand [Risk Scoring](SCORING.md) methodologies
- Explore [Information Sources](INFORMATION_SOURCES.md) used for risk assessment