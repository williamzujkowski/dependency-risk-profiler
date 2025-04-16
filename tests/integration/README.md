# Integration Tests

This directory contains integration tests for the Dependency Risk Profiler that test multiple components together.

## Test Files

- `integration_test.py` - General integration tests
- `test_dependency_update.py` - Tests for dependency update detection
- `test_phase2.py` - Tests for phase 2 features (enhanced functionality)
- `test_security_policy.py` - Tests for security policy analysis
- `test_trends.py` - Tests for historical trend analysis
- `test_vuln_aggregator.py` - Tests for vulnerability data aggregation

## Running Tests

From the project root directory:

```bash
# Run all integration tests
pytest tests/integration/

# Run a specific integration test
pytest tests/integration/test_trends.py
```

These tests are slower than unit tests as they test multiple components working together.