# Getting Started

This guide will help you get started with Dependency Risk Profiler, a comprehensive tool for evaluating the health and risk of your project dependencies.

## Prerequisites

- Python 3.9 or higher
- Pip package manager
- Access to your project's dependency files (requirements.txt, package.json, go.mod, etc.)

## Installation

The simplest way to install Dependency Risk Profiler is via pip:

```bash
pip install dependency-risk-profiler
```

For more installation options, including development installation, see the [Installation Guide](installation.md).

## First Analysis

To analyze a project:

1. Navigate to your project directory
2. Run the analyze command:

```bash
dependency-risk-profiler analyze .
```

The tool will automatically:

1. Detect the project type (Python, Node.js, Go)
2. Scan dependency manifests
3. Analyze dependencies for various risk factors
4. Display a risk summary

## Understanding the Results

The output will include:

- Overall risk score and level
- Breakdown of risk by category
- Specific risk factors identified
- Recommended actions

Example output:

```
Risk Analysis Report for my-project
----------------------------------
Overall Risk Score: 0.42 (LOW)

Risk Categories:
- Vulnerability: 0.2 (LOW)
- Maintenance: 0.3 (LOW)
- Community: 0.5 (MEDIUM)
- License: 0.7 (MEDIUM)

High Risk Dependencies:
- outdated-lib (1.2.0): Last updated 3 years ago, no security policy
- complex-framework (2.0.1): 5 known vulnerabilities, low community activity

Recommendations:
- Update outdated-lib to version 2.0.0+
- Replace complex-framework or update to 2.1.3+ to fix vulnerabilities
```

## Next Steps

- Explore [Basic Usage](basic-usage.md) for more detailed usage information
- Learn how to [Configure](configuration.md) the tool for your specific needs
- Understand how [Risk Scoring](SCORING.md) works