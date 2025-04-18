# Contributing to Dependency Risk Profiler

Thank you for your interest in contributing to the Dependency Risk Profiler! This document outlines the process for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct: be respectful, considerate, and collaborative.

## How to Contribute

### Reporting Bugs

If you find a bug, please create a GitHub issue with the following information:

1. Clear, descriptive title
2. Steps to reproduce the bug
3. Expected behavior
4. Actual behavior
5. Your environment (OS, Python version, etc.)
6. Any relevant logs or screenshots

### Suggesting Enhancements

We welcome suggestions for new features or improvements. Please create a GitHub issue with:

1. Clear, descriptive title
2. Detailed description of the proposed enhancement
3. Use cases and benefits
4. Any implementation ideas you have

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests to ensure they pass
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Pull Request Guidelines

- Follow the code style guidelines specified in CLAUDE.md
- Include tests for new features or bug fixes
- Update documentation as needed
- Keep pull requests focused on a single topic
- Reference related issues in your PR description

## Development Process

### Setting Up Your Development Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/dependency-risk-profiler.git
cd dependency-risk-profiler

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Set up pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific tests
pytest tests/test_parsers.py

# Run tests with coverage
pytest --cov=src
```

### Code Style

We use the following tools to maintain code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking

Before submitting a PR, please run these tools:

```bash
black .
isort .
flake8
mypy .
```

## Adding Support for New Package Ecosystems

If you want to add support for a new package ecosystem, you'll need to:

1. Create a new parser module in `src/dependency_risk_profiler/parsers/`
2. Create a new analyzer module in `src/dependency_risk_profiler/analyzers/`
3. Update the factory methods in `base.py` to include your new modules
4. Add tests for your new parser and analyzer
5. Update documentation to reflect the new supported ecosystem

## Documentation

Please update documentation for any changes that affect user experience or public APIs. This includes:

- README.md
- Code docstrings
- CLI help text

## Releasing

Project maintainers will handle releases, following semantic versioning:

- **MAJOR**: Incompatible API changes (2.0.0)
- **MINOR**: New functionality, backwards compatible (1.1.0)
- **PATCH**: Bug fixes, backwards compatible (1.0.1)

## Questions?

If you have any questions about contributing, feel free to open an issue asking for clarification.