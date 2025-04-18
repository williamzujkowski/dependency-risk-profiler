# Dependency Risk Profiler 🔍

[![CI](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![Docs](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/docs.yml/badge.svg)](https://williamzujkowski.github.io/dependency-risk-profiler/)
[![Coverage](https://raw.githubusercontent.com/williamzujkowski/dependency-risk-profiler/main/.github/badges/coverage.svg)](https://github.com/williamzujkowski/dependency-risk-profiler/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A command-line tool that goes beyond traditional vulnerability scanners to assess the overall health and risk of a project's open-source dependencies.

## Features

### Core Features
- 🧰 **Multi-Ecosystem Support**: Analyze dependencies from Node.js, Python, Go, and TOML-based projects (Poetry, Cargo, etc.)
- 🔄 **Version Comparison**: Compare installed versions with the latest available versions
- ⏱️ **Update Recency**: Check how long ago dependencies were last updated
- 👥 **Maintainer Analysis**: Determine if dependencies are maintained by teams or individuals
- 🚫 **Deprecation Detection**: Flag deprecated dependencies
- 🧪 **Health Indicators**: Check for presence of tests, CI configuration, and contribution guidelines
- 🛡️ **Security Checks**: Scan for any public exploit information
- 📊 **Risk Scoring**: Compute a composite risk score for each dependency
- 🎨 **Colorized Output**: Clear, color-coded terminal reports
- 📋 **JSON Output**: Optional JSON output for integration with other tools
- 📂 **Directory Scanning**: Analyze all manifest files in a directory with a single command

### Enhanced Features
- 📜 **License Analysis**: Evaluate license types and compliance risks
- 🌟 **Community Health Metrics**: Assess repository stars, forks, and activity levels
- 🔄 **Transitive Dependency Analysis**: Analyze the full dependency tree beyond direct dependencies with in-depth resolution using pipdeptree for Python projects
- 📊 **Comprehensive Risk Model**: Expanded risk scoring with customizable weights for all factors
- 🔐 **Security Best Practices**: Analyze security policies, dependency update tools, signed commits, and branch protection
- 📈 **Historical Trend Analysis**: Track changes in risk metrics over time for better decision making
- 🌐 **Supply Chain Visualization**: Generate dependency graphs to visualize relationships and risk
- 🔍 **Multi-Source Vulnerability Aggregation**: Collect vulnerability data from OSV, NVD, and GitHub Advisory (with parallel processing)
- 🚀 **Asynchronous Processing**: Parallel vulnerability lookups and HTTP requests for faster scans
- ⚙️ **Configuration File Support**: Define settings in TOML or YAML files with environment variable overrides
- 💻 **Modern CLI Interface**: Rich, colorful output with excellent help documentation using Typer
- 🔏 **Secure Code Signing**: Sign release artifacts with robust cryptographic protections and timestamping
- 📦 **Secure Release Management**: Automate versioning, packaging, signing, and release notes generation

## Installation

### From PyPI

```bash
# Install directly
pip install dependency-risk-profiler

# Or use the quick installer (no need to clone the repository)
curl -sSL https://raw.githubusercontent.com/your-organization/dependency-risk-profiler/main/quickinstall.py | python3
```

### Using the Installer Scripts

This package provides convenient installer scripts for different platforms:

#### Linux/macOS

```bash
# Clone the repository
git clone https://github.com/your-organization/dependency-risk-profiler.git
cd dependency-risk-profiler

# Run the installer
./install.sh
```

#### Windows

```cmd
# Clone the repository
git clone https://github.com/your-organization/dependency-risk-profiler.git
cd dependency-risk-profiler

# Run the installer
install.bat
```

#### Cross-platform Python installer

```bash
# Clone the repository
git clone https://github.com/your-organization/dependency-risk-profiler.git
cd dependency-risk-profiler

# Run the installer
python install.py
```

### From Source (Manual Installation)

```bash
git clone https://github.com/username/dependency-risk-profiler.git
cd dependency-risk-profiler
pip install .  # Or 'pip install -e .' for development mode
```

## Usage

### Basic Usage

```bash
# Analyze a Node.js project
dependency-risk-profiler analyze --manifest /path/to/package-lock.json

# Analyze a Python project
dependency-risk-profiler analyze --manifest /path/to/requirements.txt

# Analyze a Python project with Pipfile.lock
dependency-risk-profiler analyze --manifest /path/to/Pipfile.lock

# Analyze a Python project with pyproject.toml
dependency-risk-profiler analyze --manifest /path/to/pyproject.toml

# Analyze a Rust project
dependency-risk-profiler analyze --manifest /path/to/Cargo.toml

# Analyze a Go project
dependency-risk-profiler analyze --manifest /path/to/go.mod

# Enable asynchronous dependency analysis for faster results
dependency-risk-profiler analyze --manifest /path/to/package-lock.json --async

# Analyze all manifest files in a directory
dependency-risk-profiler analyze --manifest /path/to/project_directory

# Analyze all manifest files in a directory and its subdirectories
dependency-risk-profiler analyze --manifest /path/to/project_directory --recursive

# Set a longer timeout for analyzing large projects with many dependencies
dependency-risk-profiler analyze --manifest /path/to/large_project --timeout 300

# Combine timeout and recursive scanning for large projects
dependency-risk-profiler analyze --manifest /path/to/large_project --recursive --timeout 300
```

### Configuration Files

You can use configuration files to store your settings in TOML or YAML format:

```bash
# Generate a sample config file
dependency-risk-profiler config generate --format toml --output config.toml

# Generate a sample config file in YAML format
dependency-risk-profiler config generate --format yaml --output config.yaml

# Use a specific config file
dependency-risk-profiler analyze --manifest /path/to/package-lock.json --config /path/to/config.toml
```

Example TOML configuration:

```toml
[general]
manifest = "path/to/package-lock.json"
output_format = "terminal"
debug = false
async_mode = true
cache_dir = "~/.dependency-risk-profiler/cache"

[weights]
staleness = 0.3
maintainer = 0.2
deprecation = 0.3
exploit = 0.6
version = 0.2
health = 0.1
license = 0.4
community = 0.3
transitive = 0.2

[api_keys]
github = "your-github-token"
nvd = "your-nvd-api-key"
```

You can also use environment variables with the `DRP_` prefix to override config settings:

```bash
# Use environment variables
export DRP_GITHUB_API_KEY="your-github-token"
export DRP_OUTPUT_FORMAT="json"
export DRP_ASYNC_MODE="true"

# Run the analysis (will use the environment variables)
dependency-risk-profiler analyze --manifest /path/to/package-lock.json
```

### Output Options

```bash
# Generate JSON output
dependency-risk-profiler analyze --manifest /path/to/package-lock.json --output json

# Disable color in terminal output
dependency-risk-profiler analyze --manifest /path/to/requirements.txt --no-color

# Get detailed help for any command
dependency-risk-profiler --help
dependency-risk-profiler analyze --help
dependency-risk-profiler config --help
```

### Custom Risk Scoring

You can customize the weights used for risk scoring:

```bash
# Basic risk factors
dependency-risk-profiler analyze --manifest /path/to/package-lock.json \
  --staleness-weight 0.3 \
  --maintainer-weight 0.2 \
  --deprecation-weight 0.3 \
  --exploit-weight 0.6 \
  --version-weight 0.2 \
  --health-weight 0.1

# Enhanced risk factors
dependency-risk-profiler analyze --manifest /path/to/package-lock.json \
  --license-weight 0.4 \
  --community-weight 0.3 \
  --transitive-weight 0.2
```

### Enhanced Transitive Dependency Analysis

Use the enhanced transitive dependency analysis for Python projects:

```bash
# Analyze Python projects with enhanced transitive dependency resolution
dependency-risk-profiler analyze --manifest /path/to/requirements.txt --enhanced-transitive

# Analyze with a specific virtual environment
dependency-risk-profiler analyze --manifest /path/to/requirements.txt --enhanced-transitive --venv-path ./my-venv
```

### Historical Trends Analysis

You can save scan results to a historical database and analyze trends over time:

```bash
# Save the current scan to historical data
dependency-risk-profiler trends save --manifest /path/to/package-lock.json

# Analyze historical trends for a project
dependency-risk-profiler trends analyze --manifest /path/to/package-lock.json

# Limit the number of historical scans to analyze
dependency-risk-profiler trends analyze --manifest /path/to/package-lock.json --limit 5

# Generate visualization data for trends
dependency-risk-profiler trends visualize --manifest /path/to/package-lock.json --type overall
dependency-risk-profiler trends visualize --manifest /path/to/package-lock.json --type distribution
dependency-risk-profiler trends visualize --manifest /path/to/package-lock.json --type dependencies
dependency-risk-profiler trends visualize --manifest /path/to/package-lock.json --type security
```

### Supply Chain Visualization

Generate dependency graphs to visualize relationships and risk:

```bash
# Generate dependency graph (D3.js format by default)
dependency-risk-profiler graph generate --manifest /path/to/package-lock.json

# Specify graph format
dependency-risk-profiler graph generate --manifest /path/to/package-lock.json --format graphviz
dependency-risk-profiler graph generate --manifest /path/to/package-lock.json --format cytoscape

# Specify maximum depth for transitive dependencies
dependency-risk-profiler graph generate --manifest /path/to/package-lock.json --depth 2
```

### Debug Mode

```bash
# Enable debug logging
dependency-risk-profiler analyze --manifest /path/to/package-lock.json --debug

# Get version information
dependency-risk-profiler version
```

### Performance Options

```bash
# Enable async mode for faster vulnerability lookups
dependency-risk-profiler analyze --manifest /path/to/package-lock.json --async

# Specify concurrency level for HTTP requests
dependency-risk-profiler analyze --manifest /path/to/package-lock.json --async --concurrency 20

# Use batch processing for large dependency sets
dependency-risk-profiler analyze --manifest /path/to/package-lock.json --async --batch-size 15
```

### Secure Code Signing and Release Management

The package includes advanced security features for code signing and release management:

```bash
# Sign an artifact
python -m dependency_risk_profiler.secure_release.code_signing artifact.zip --build-id my-build-123 --mode release

# Verify a signature
python -m dependency_risk_profiler.secure_release.code_signing artifact.zip --verify artifact.zip.sig

# Create a release with automatic version bumping and signing
python -m dependency_risk_profiler.secure_release.release_management --source-dir . --version-file pyproject.toml --output-dir ./dist

# Run a comprehensive release build process
python -m dependency_risk_profiler.secure_release.release_build --repo https://github.com/your-organization/dependency-risk-profiler.git --output-dir ./dist --mode production

# Run the demo script to see it all in action
python examples/secure_release_demo.py
```

## Example Output

For examples of how to use this tool, check out the [examples directory](examples/README.md). For real-world test cases, see the [testing/projects directory](testing/projects/README.md).

```
Dependency Risk Profile

Manifest: /path/to/package-lock.json
Ecosystem: nodejs
Scan Time: 2025-04-15 12:34:56
Dependencies: 42

Risk Summary
Overall Risk Score: 2.83/5.0
High Risk Dependencies: 8
Medium Risk Dependencies: 15
Low Risk Dependencies: 19

Dependency Details
Dependency                     Installed       Latest         Last Update     Maintainers  Risk Score  Status               
---------------------------------------------------------------------------------------------------------------------
outdated-package               1.0.0           2.5.0          24 months ago   1            4.8/5.0     CRITICAL (Outdated)   
deprecated-lib                 0.9.0           0.9.0          36 months ago   2            4.3/5.0     HIGH (Deprecated)    
single-maintainer-pkg          2.1.0           2.1.0          3 months ago    1            3.1/5.0     MEDIUM (Single maintainer)
...
```

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

For detailed information about the risk scoring methodology and information sources, see:
- [Scoring Methodology](docs/SCORING.md) - How risk scores are calculated
- [Information Sources](docs/INFORMATION_SOURCES.md) - Where the tool gets its data

For all documentation, see the [docs directory](docs/README.md).

## Documentation

The project documentation is built with MkDocs and available in multiple formats:

- **Online Documentation**: [View the docs online](https://williamzujkowski.github.io/dependency-risk-profiler/) (automatically updated when the main branch changes)
- **Local Documentation**: Run `mkdocs serve` in the project directory to view documentation locally at http://127.0.0.1:8000/
- **Static Site**: Run `mkdocs build` to generate a static documentation site in the `site/` directory
- **Markdown Files**: Browse the raw documentation in the [docs directory](docs/)

The documentation includes:
- User guides for installation and usage
- API references and configuration options
- Development guides and contribution guidelines
- Security and risk scoring methodologies

## Requirements

- Python 3.8+
- Git (for repository analysis)
- Internet connection (for fetching package metadata)

## Important Note About Example Files

This project contains intentionally outdated dependencies in the following directories:
- `/examples/` 
- `/dependabot_check/`

These files contain dependencies with known vulnerabilities for testing and demonstration purposes. They serve as test cases for the Dependency Risk Profiler tool to identify and classify various risks. These dependencies are excluded from Dependabot alerts via configuration in `.github/dependabot.yml`.

**⚠️ WARNING: DO NOT use these example dependencies in production environments.**

Please review our [Security Policy](docs/security/SECURITY.md) and [Dependency Security](docs/security/DEPENDENCY_SECURITY.md) documentation for more information.

## Development

### Project Structure

The Dependency Risk Profiler follows a clean, well-organized directory structure:

- `src/dependency_risk_profiler/`: Core library code
- `testing/`: Test files and resources 
  - `unit/`: Unit tests for individual components
  - `integration/`: Integration tests for multi-component functionality
  - `fixtures/`: Test fixtures and mock data
  - `manifests/`: Sample dependency manifests for testing
  - `projects/`: Complete project copies for realistic testing
- `examples/`: Example scripts and usage demos
- `docs/`: Documentation files

### Getting Started

```bash
# Clone the repository
git clone https://github.com/williamzujkowski/dependency-risk-profiler.git
cd dependency-risk-profiler

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (recommended)
pre-commit install

# Run tests
pytest

# Run tests with coverage report
pytest --cov=src

# Run specific test categories
pytest testing/unit/
pytest testing/integration/

# Format and lint code
black .
isort .
flake8
mypy src

# Security check
bandit -r src
```

## CI/CD

This project uses GitHub Actions for continuous integration and delivery:

### Continuous Integration

The CI workflow runs on every push and pull request to the `main` branch and performs the following checks:

- Runs all pre-commit hooks on changed files
- Verifies code quality with flake8
- Runs static type checking with mypy
- Performs security scanning with bandit
- Executes all tests with pytest and collects coverage metrics

### Continuous Delivery

The CD workflow automatically creates releases when version tags (e.g., `v0.3.0`) are pushed:

1. Builds the Python package (wheel and sdist)
2. Generates release notes from the changelog
3. Creates a GitHub release with the built artifacts
4. Publishes the package to PyPI

### Dependabot Integration

Dependabot is configured to scan for dependency updates weekly and create pull requests for:

- Python dependencies
- GitHub Actions
- Node.js dependencies (for example tools)
- Go dependencies (for example tools)

## Example Tools and Demos

### Historical Trends Demo

The `examples/trends_demo.py` script demonstrates how to use the historical trends analysis functionality:

```bash
# Save the current scan to historical data
python examples/trends_demo.py --manifest /path/to/requirements.txt

# Analyze historical trends
python examples/trends_demo.py --manifest /path/to/requirements.txt --analyze

# Generate visualization data
python examples/trends_demo.py --manifest /path/to/requirements.txt --visualize overall
```

### Trend Visualization

The `examples/trend_visualizer.html` file provides a simple web-based visualization tool for viewing trend data:

1. Generate trend visualization data using the CLI or trends_demo.py
2. Open the trend_visualizer.html file in a web browser
3. Click "Choose File" and select the generated JSON file
4. View the visualized trend data

### Configuration Examples

The `examples/config.toml` and `examples/config.yaml` files demonstrate configuration file examples:

```bash
# Generate example config files
dependency-risk-profiler config generate --format toml --output examples/config.toml
dependency-risk-profiler config generate --format yaml --output examples/config.yaml

# Use the example config file
dependency-risk-profiler analyze --config examples/config.toml
```

### Async HTTP Demo

The `examples/async_demo.py` script demonstrates the performance gains of asynchronous HTTP processing:

```bash
# Run the async demo with different concurrency settings
python examples/async_demo.py --concurrency 5
python examples/async_demo.py --concurrency 20
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for more details.

## Release Process

This project uses an automated CI/CD pipeline for releases:

1. Create and push a new version tag following semantic versioning:

```bash
# For a new patch release (bug fixes)
git tag v0.1.1
git push origin v0.1.1

# For a new minor release (new features)
git tag v0.2.0
git push origin v0.2.0

# For a new major release (breaking changes)
git tag v1.0.0
git push origin v1.0.0
```

2. The release workflow will automatically:
   - Build the Python package (wheel and sdist)
   - Create a GitHub Release with auto-generated release notes
   - Upload the package files to the GitHub Release
   - Publish the package to PyPI
   - Update the documentation site

This ensures that when a new version is released, it's immediately available on PyPI for installation via pip and properly documented on the project's GitHub page and documentation site.