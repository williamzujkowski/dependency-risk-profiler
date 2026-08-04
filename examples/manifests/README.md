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
dependency-risk-profiler analyze examples/manifests/requirements.txt

# Analyze a Node.js project
dependency-risk-profiler analyze examples/manifests/package-lock.json

# Analyze a Go project
dependency-risk-profiler analyze examples/manifests/go.mod
```

## These are kept current, on purpose

This directory used to say the opposite — that the pins here were
"intentionally outdated" so the tool would have something to find. That was
never true of `requirements.txt` or `go.mod` (one carried current pins, the
other declares no dependencies at all), and where it *was* true it cost 30
standing Dependabot alerts on `package-lock.json` that buried the repository's
real ones (#231).

A reader copies these files. A dependency-risk tool that ships a documentation
example with known-vulnerable pins is arguing against itself. So: current pins,
maintained by Dependabot's security updates like any other manifest in the
dependency graph, and a security bump PR against this directory is one to
merge rather than triage.

The tool still has plenty to say about a current manifest — staleness,
maintainer count, deprecation and repository health are scored independently of
whether an advisory happens to be open today.

If you need a deliberately vulnerable target, point the profiler at one you
control. Do not add one here.
