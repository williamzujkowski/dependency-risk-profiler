# Testing Documentation

This directory contains all the test code for the Dependency Risk Profiler project.

## Overview

The test suite follows the Minimal Testing Manifesto defined in `TESTING_STANDARDS.md` and includes:

1. Hypothesis Tests for Behavior Validation
2. Regression Tests for Known Fail States  
3. Benchmark Tests with SLA Enforcement
4. Grammatical Evolution for Fuzzing + Edge Discovery
5. Structured Logs for Agent Feedback

## Directory Structure

- `integration/` - Integration tests that test multiple components working together
- `conftest.py` - Pytest configuration and fixtures
- **Unit Tests**
  - `test_parsers.py` - Tests for manifest file parsers
  - `test_scoring.py` - Tests for risk scoring logic
  - `test_toml_parser.py` and variants - Tests for TOML file parsing
  - `test_vulnerability_cache.py` - Tests for the vulnerability caching system
  - `test_vulnerability_aggregator_with_cache.py` - Tests for vulnerability aggregation with caching
- **Comprehensive Tests**
  - `test_comprehensive_vulnerability_aggregator.py` - Full test suite for vulnerability aggregator
  - `test_comprehensive_risk_scorer.py` - Full test suite for risk scoring system

## Running Tests

From the project root directory:

```bash
# Activate the virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package in development mode
pip install -e ".[dev]"

# Run all tests
pytest

# Run only unit tests (excluding integration tests)
pytest tests/ --ignore=tests/integration/

# Run only integration tests
pytest tests/integration/

# Run tests with coverage report
pytest --cov=src

# Run specific test files
pytest tests/test_comprehensive_vulnerability_aggregator.py

# Run tests with specific marker
pytest -m benchmark

# Run tests with verbose output
pytest -v
```

## Writing New Tests

When writing new tests, follow these guidelines:

1. **Follow the test categories** defined in `TESTING_STANDARDS.md`
2. **Use descriptive test names** that document the behavior being tested
3. **Include detailed docstrings** describing the purpose and expectations
4. **Structure tests** with Arrange-Act-Assert pattern
5. **Use mock objects** to isolate the code being tested
6. **Test both positive and negative cases**
7. **Include boundary conditions** in your test cases
8. **Verify error handling behaviors**

## Test Fixtures

Common test fixtures are defined in `conftest.py`:

- `sample_nodejs_manifest` - Sample Node.js package-lock.json
- `sample_python_manifest` - Sample Python requirements.txt
- `sample_golang_manifest` - Sample Go go.mod file
- `sample_dependencies` - Dictionary of sample dependency metadata
- `mock_env_vars` - Fixture to set/restore environment variables
- `temp_cache_dir` - Temporary directory for cache testing

## Special Test Files

The following test files are excluded from standard linting and formatting checks as they contain intentional edge cases, formatting issues, or non-standard code:

- **Integration Tests**:
  - `tests/integration/test_security_policy.py` - Contains specific formatting for policy testing
  - `tests/integration/test_dependency_update.py` - Contains intentionally outdated dependencies
  - `tests/integration/test_phase2.py` - Contains specific test scenarios for Phase 2

- **Comprehensive Tests**:
  - `test_comprehensive_vulnerability_aggregator.py` - Contains extensive test cases with special formatting
  - `test_comprehensive_risk_scorer.py` - Contains edge case tests with custom formatting

These files may fail standard linting checks, but this is intentional for testing purposes. They are configured to be excluded in `setup.cfg` and `.pre-commit-config.yaml`.

## Implementation Details

For more information on the test implementation approach, see `TESTING_IMPLEMENTATION.md` in the root directory.