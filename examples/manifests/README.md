# Example Manifest Files

This directory contains example dependency manifest files that can be used with the Dependency Risk Profiler.

## Available Manifest Files

- `requirements.txt` - Python package dependencies
- `package-lock.json` - Node.js package dependencies
- `go.mod` - Go module dependencies

## Usage

These manifests can be used with the Dependency Risk Profiler to demonstrate its functionality:

```bash
# Analyze a Python project
dependency-risk-profiler analyze --manifest examples/manifests/requirements.txt

# Analyze a Node.js project
dependency-risk-profiler analyze --manifest examples/manifests/package-lock.json

# Analyze a Go project
dependency-risk-profiler analyze --manifest examples/manifests/go.mod
```

## Notes

These manifest files contain intentionally outdated dependencies for testing and demonstration purposes. They serve as test cases for the Dependency Risk Profiler tool to identify and classify various risks.

**⚠️ WARNING: DO NOT use these example dependencies in production environments.**