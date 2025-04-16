# Dependency Risk Profiler 🔍

A command-line tool that goes beyond traditional vulnerability scanners to assess the overall health and risk of a project's open-source dependencies.

## Features

### Core Features
- 🧰 **Multi-Ecosystem Support**: Analyze dependencies from Node.js, Python, and Go projects
- 🔄 **Version Comparison**: Compare installed versions with the latest available versions
- ⏱️ **Update Recency**: Check how long ago dependencies were last updated
- 👥 **Maintainer Analysis**: Determine if dependencies are maintained by teams or individuals
- 🚫 **Deprecation Detection**: Flag deprecated dependencies
- 🧪 **Health Indicators**: Check for presence of tests, CI configuration, and contribution guidelines
- 🛡️ **Security Checks**: Scan for any public exploit information
- 📊 **Risk Scoring**: Compute a composite risk score for each dependency
- 🎨 **Colorized Output**: Clear, color-coded terminal reports
- 📋 **JSON Output**: Optional JSON output for integration with other tools

### Enhanced Features
- 📜 **License Analysis**: Evaluate license types and compliance risks
- 🌟 **Community Health Metrics**: Assess repository stars, forks, and activity levels
- 🔄 **Transitive Dependency Analysis**: Analyze the full dependency tree beyond direct dependencies
- 📊 **Comprehensive Risk Model**: Expanded risk scoring with customizable weights for all factors

## Installation

### From PyPI

```bash
pip install dependency-risk-profiler
```

### From Source

```bash
git clone https://github.com/username/dependency-risk-profiler.git
cd dependency-risk-profiler
pip install -e .
```

## Usage

### Basic Usage

```bash
# Analyze a Node.js project
dependency-risk-profiler --manifest /path/to/package-lock.json

# Analyze a Python project
dependency-risk-profiler --manifest /path/to/requirements.txt

# Analyze a Go project
dependency-risk-profiler --manifest /path/to/go.mod
```

### Output Options

```bash
# Generate JSON output
dependency-risk-profiler --manifest /path/to/package-lock.json --output json

# Disable color in terminal output
dependency-risk-profiler --manifest /path/to/requirements.txt --no-color
```

### Custom Risk Scoring

You can customize the weights used for risk scoring:

```bash
# Basic risk factors
dependency-risk-profiler --manifest /path/to/package-lock.json \
  --staleness-weight 0.3 \
  --maintainer-weight 0.2 \
  --deprecation-weight 0.3 \
  --exploit-weight 0.6 \
  --version-weight 0.2 \
  --health-weight 0.1

# Enhanced risk factors
dependency-risk-profiler --manifest /path/to/package-lock.json \
  --license-weight 0.4 \
  --community-weight 0.3 \
  --transitive-weight 0.2
```

### Debug Mode

```bash
dependency-risk-profiler --manifest /path/to/package-lock.json --debug
```

## Example Output

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
3. **Scoring**: Calculates risk scores based on multiple factors and provides a detailed report

Risk factors include:

- How long since the last update
- Number of maintainers
- Whether the package is deprecated
- If there are known security exploits
- Version difference between installed and latest
- Presence of health indicators (tests, CI, docs)

For detailed information about the risk scoring methodology and information sources, see:
- [Scoring Methodology](docs/SCORING.md) - How risk scores are calculated
- [Information Sources](docs/INFORMATION_SOURCES.md) - Where the tool gets its data

## Requirements

- Python 3.8+
- Git (for repository analysis)
- Internet connection (for fetching package metadata)

## Development

```bash
# Clone the repository
git clone https://github.com/username/dependency-risk-profiler.git
cd dependency-risk-profiler

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black .
isort .

# Lint code
flake8
mypy .
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