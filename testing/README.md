# Testing Directory for Dependency Risk Profiler

This directory contains all testing-related files for the Dependency Risk Profiler project, organized in a logical structure.

## Directory Structure

- **[unit/](unit/README.md)**: Unit tests for individual functions and classes
- **[integration/](integration/README.md)**: Tests that check how multiple components work together
- **[fixtures/](fixtures/README.md)**: Reusable test data and mock objects
- **[manifests/](manifests/README.md)**: Minimal manifest files for testing with different ecosystems
- **[projects/](projects/README.md)**: Full project copies for realistic testing scenarios

## Running Tests

```bash
# Run all tests
pytest

# Run unit tests only
pytest testing/unit/

# Run integration tests only
pytest testing/integration/

# Run a specific test file
pytest testing/unit/test_config.py

# Run a specific test
pytest testing/unit/test_config.py::TestConfig::test_load_toml_config

# Run tests with coverage report
pytest --cov=src
```

For more information on testing standards and implementation, see:
- [Testing Standards](../docs/project_standards/TESTING_STANDARDS.md)
- [Testing Implementation](../docs/project_standards/TESTING_IMPLEMENTATION.md)