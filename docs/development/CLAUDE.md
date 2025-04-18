# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Setup Commands
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Lint & Test Commands
```bash
# Format code
black .
isort .

# Lint code
flake8
mypy .

# Run all tests
pytest

# Run a single test
pytest tests/path/to/test_file.py::test_function_name

# Run tests with coverage
pytest --cov=src
```

## Code Style Guidelines
- Use PEP 8 standards with 88 character line length (Black default)
- Snake case for variables, functions, methods: `user_count`, `calculate_total()`
- Pascal case for classes: `DependencyParser`, `RiskProfiler`
- Type annotations required for all functions and methods
- Follow Google-style docstrings
- Keep functions focused and under 50 lines when possible
- Handle exceptions with custom exception classes
- Organize imports: stdlib, third-party, local (handled by isort)