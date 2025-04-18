# Testing Fixtures

This directory contains fixture files used for testing the Dependency Risk Profiler.

## Files

- `requirements_large.txt` - A large requirements file with many dependencies for testing parser performance
- `large_manifest.txt` - A large manifest file with many dependencies for testing parser performance
- `coverage.xml` - Example coverage report

## Usage

These files are primarily used for:
1. Testing the parsers with large input files
2. Performance testing of the dependency analysis components
3. Demonstrating code coverage reporting

## Notes

- Do not modify these files as they may be referenced by tests
- These fixtures are separate from the ones in the `testing/fixtures` directory which are used by the automated test suite