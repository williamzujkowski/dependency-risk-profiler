# Dependency Risk Profiler

[![CI](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![Python Versions](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Dependency Risk Profiler is a comprehensive tool for evaluating the health and risk of your project's dependencies beyond traditional vulnerability scanning. It analyzes multiple risk factors such as maintainer activity, update frequency, community health, license compliance, and known vulnerabilities to provide a holistic risk assessment.

## Key Features

- **Multi-language Support**: Analyze dependencies in Python, JavaScript/Node.js, and Go projects
- **Comprehensive Risk Scoring**: Assess risk based on multiple factors, not just vulnerabilities
- **Supply Chain Insights**: Understand your dependency graph and identify potential risks
- **Vulnerability Detection**: Identify security vulnerabilities in your dependencies
- **License Compliance**: Check for license compatibility and compliance issues
- **Community Health Metrics**: Evaluate the health of dependency maintainer communities
- **Trend Analysis**: Track risk scores over time to identify patterns
- **CLI & API Access**: Use as a command-line tool or integrate into your own applications

## Installation

```bash
pip install dependency-risk-profiler
```

## Quick Start

Analyze a project with a single command:

```bash
dependency-risk-profiler analyze path/to/project
```

## Documentation

Explore our documentation for detailed guides on:

- [Getting Started](getting-started.md)
- [Installation Options](installation.md)
- [Basic Usage](basic-usage.md)
- [Advanced Configuration](configuration.md)
- [Understanding Risk Scores](SCORING.md)

## Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details on how to get involved.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
