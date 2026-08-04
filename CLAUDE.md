# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Setup Commands
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Alternative: Use installer scripts
# python scripts/install.py   # Cross-platform Python installer
# ./scripts/install.sh        # Unix/Linux installer
# scripts\install.bat         # Windows installer

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
pytest testing/unit/test_file.py::test_function_name

# Run tests with coverage
pytest --cov=src
```

## Documentation Commands
```bash
# Install documentation dependencies
pip install -e ".[docs]"

# Preview documentation site (with live reloading)
mkdocs serve

# Build static documentation site
mkdocs build

# Deploy to GitHub Pages (if configured)
mkdocs gh-deploy
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

## What may land

`CLAUDE.md` covers how to build and how to format. **[`AGENTS.md`](AGENTS.md) covers what may land**, and its rules bind humans and agents equally:

1. **No simulated implementations** — a function does what its name says or does not exist. If the real thing cannot be built now, file an issue and land nothing.
2. **Rescope, don't stub** — split it, land a correct smaller piece, file the remainder with acceptance criteria.
3. **Landed code must be reachable** — a function needs a caller, a field needs a writer and a reader.
4. **Silence is not an answer** — unmeasured is structurally distinct from measured-zero.
5. **Fixtures are captured, never authored** — reducers drop volume, never key diversity.
6. **Verify that a gate bites** — reintroduce the defect, confirm the failure, revert.
7. **The bar** — no `# type: ignore` / `Any` / `# noqa` / new `# nosec`; mypy exemption list stays empty; ratchets only move down.

Read `AGENTS.md` before writing code. It explains why each rule exists, with the specific defect that motivated it.
