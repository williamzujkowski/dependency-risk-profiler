# Installation Guide

Dependency Risk Profiler can be installed in several ways to accommodate different environments and use cases.

## Standard Installation

For most users, installing via pip is the simplest approach:

```bash
pip install dependency-risk-profiler
```

This installs the core package with all required dependencies.

## Installation with Optional Features

Dependency Risk Profiler has several optional feature sets:

```bash
# Install with visualization support
pip install "dependency-risk-profiler[visualization]"

# Install with development tools
pip install "dependency-risk-profiler[dev]"

# Install with all optional features
pip install "dependency-risk-profiler[dev,visualization]"
```

## Quick Install Script

For a guided installation experience, you can use the quick install script:

```bash
# On Linux/macOS
curl -sSL https://raw.githubusercontent.com/williamzujkowski/dependency-risk-profiler/main/quickinstall.py | python -

# On Windows (PowerShell)
(Invoke-WebRequest -Uri https://raw.githubusercontent.com/williamzujkowski/dependency-risk-profiler/main/quickinstall.py -UseBasicParsing).Content | python -
```

The script will:
1. Check your Python version
2. Create a virtual environment (optional)
3. Install the package with your chosen options
4. Run a quick verification test

## Development Installation

For contributors or those who want the latest development version:

```bash
# Clone the repository
git clone https://github.com/williamzujkowski/dependency-risk-profiler.git
cd dependency-risk-profiler

# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with all dependencies
pip install -e ".[dev,visualization]"

# Install pre-commit hooks (for contributors)
pre-commit install
```

## System Requirements

- **Python Version**: 3.9 or higher
- **Operating Systems**: Windows, macOS, Linux
- **Disk Space**: ~100MB (including dependencies)
- **Additional Requirements**:
  - For Go analysis: Access to public Go module proxies
  - For visualization: Additional ~50MB for graphical dependencies

## Verifying Installation

After installation, verify that the tool is working correctly:

```bash
# Check the installed version
dependency-risk-profiler --version

# Run a basic command
dependency-risk-profiler list-ecosystems
```

## Troubleshooting

If you encounter installation issues:

- **Dependency Conflicts**: Try installing in a fresh virtual environment
- **Permission Errors**: Use `pip install --user` or consider using a virtual environment
- **Missing Compiler**: Some dependencies may require a C compiler; install the appropriate development tools for your OS
- **Connectivity Issues**: Ensure you have internet access for downloading dependencies

For more help, see the [Contributing Guide](CONTRIBUTING.md) or [open an issue](https://github.com/williamzujkowski/dependency-risk-profiler/issues).