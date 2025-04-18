# Dependency Risk Profiler 🔍

[![CI](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![Docs](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/docs.yml/badge.svg)](https://williamzujkowski.github.io/dependency-risk-profiler/)
[![Coverage](https://raw.githubusercontent.com/williamzujkowski/dependency-risk-profiler/main/.github/badges/coverage.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![OSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/williamzujkowski/dependency-risk-profiler/badge)](https://securityscorecards.dev/viewer/?uri=github.com/williamzujkowski/dependency-risk-profiler)
[![OSSF Allstar](https://img.shields.io/badge/OSSF-Allstar%20Protected-success)](https://github.com/ossf/allstar)
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

Or use our scripts for a customized installation:

```bash
# Python cross-platform installer
python scripts/install.py

# Linux/macOS installer
./scripts/install.sh

# Windows installer
scripts\install.bat
```

## Quick Start

Analyze a project with a single command:

```bash
dependency-risk-profiler analyze path/to/project
```

For more advanced usage:

```bash
# Analyze a specific manifest file
dependency-risk-profiler analyze --manifest path/to/requirements.txt

# Analyze with enhanced transitive dependency resolution
dependency-risk-profiler analyze --manifest path/to/package-lock.json --enhanced-transitive

# Generate dependency graph visualization
dependency-risk-profiler graph generate --manifest path/to/go.mod
```

## Documentation

Explore our [online documentation](https://williamzujkowski.github.io/dependency-risk-profiler/) for detailed guides on:

- Getting Started
- Installation Options
- Basic Usage
- Advanced Configuration
- Understanding Risk Scores

## How It Works

The Dependency Risk Profiler analyzes your project's dependencies in three main steps:

1. **Parsing**: Reads your dependency manifest file to extract dependency information
2. **Analysis**: Collects metadata for each dependency (version info, update dates, maintainer counts, etc.)
   - Optionally uses parallel processing for network requests to improve performance
   - For Python projects, can create isolated virtual environments to resolve transitive dependencies
3. **Scoring**: Calculates risk scores based on multiple factors and provides a detailed report

Risk factors include:

- How long since the last update
- Number of maintainers
- Whether the package is deprecated
- If there are known security exploits (from multiple sources, checked in parallel)
- Version difference between installed and latest
- Presence of health indicators (tests, CI, docs)
- License compatibility
- Repository activity metrics

## Project Structure

The project follows a clean, modular architecture:

- `src/dependency_risk_profiler/`: Core library code
- `scripts/`: Installation and utility scripts
- `docs/`: Comprehensive documentation
- `examples/`: Example scripts and sample data
- `testing/`: Test suite including unit and integration tests

## Contributing

We welcome contributions! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See the [Contributing Guide](https://williamzujkowski.github.io/dependency-risk-profiler/CONTRIBUTING/) for more details.

## Security Practices

The Dependency Risk Profiler project follows security best practices in open source development:

- **OSSF Scorecard**: We regularly run [OpenSSF Scorecard](https://securityscorecards.dev/) to maintain high security standards
- **OSSF Allstar**: Our repository is protected by [OpenSSF Allstar](https://github.com/ossf/allstar) to enforce security policies
- **Branch Protection**: We enforce branch protection on main branches to prevent unauthorized changes
- **Code Review**: All changes require peer review before merging
- **Dependency Management**: We use Dependabot to keep dependencies up-to-date
- **Secure Publishing**: We use OpenID Connect trusted publishing for PyPI releases

For more information, please review our [Security Policy](SECURITY.md).

## License

MIT License

## Important Note About Example Files

This project contains intentionally outdated dependencies in the following directories:
- `/examples/` 
- `/dependabot_check/`

These files contain dependencies with known vulnerabilities for testing and demonstration purposes. They serve as test cases for the Dependency Risk Profiler tool to identify and classify various risks. These dependencies are excluded from Dependabot alerts via configuration in `.github/dependabot.yml`.

**⚠️ WARNING: DO NOT use these example dependencies in production environments.**

Please review our [Security Policy](https://williamzujkowski.github.io/dependency-risk-profiler/security/SECURITY/) and [Dependency Security](https://williamzujkowski.github.io/dependency-risk-profiler/security/DEPENDENCY_SECURITY/) documentation for more information.