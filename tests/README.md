# Tests Directory

This directory contains tests for the Dependency Risk Profiler project.

## Directory Structure

- `integration/` - Integration tests that test multiple components working together
- `conftest.py` - Pytest configuration and fixtures
- Unit tests for specific components:
  - `test_parsers.py` - Tests for manifest file parsers
  - `test_scoring.py` - Tests for risk scoring logic
  - `test_toml_parser.py` and variants - Tests for TOML file parsing
  - `test_vulnerability_cache.py` - Tests for the vulnerability caching system
  - `test_vulnerability_aggregator_with_cache.py` - Tests for vulnerability aggregation with caching

## Running Tests

From the project root directory:

```bash
# Run all tests
pytest

# Run only unit tests (excluding integration tests)
pytest tests/ --ignore=tests/integration/

# Run only integration tests
pytest tests/integration/

# Run tests with coverage report
pytest --cov=src

# Run specific test files
pytest tests/test_parsers.py
```