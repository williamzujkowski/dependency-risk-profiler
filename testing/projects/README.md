# Test Projects

This directory contains real-world projects for testing and demonstration purposes. These projects serve as test cases for the Dependency Risk Profiler tool.

## Available Projects

### Flask (Python)
- **Description**: A lightweight WSGI web application framework for Python
- **Website**: https://flask.palletsprojects.com/
- **Location**: `flask/`

### Express (Node.js)
- **Description**: Fast, unopinionated, minimalist web framework for Node.js
- **Website**: https://expressjs.com/
- **Location**: `express/`

### Gin (Go)
- **Description**: A HTTP web framework written in Go (Golang)
- **Website**: https://gin-gonic.com/
- **Location**: `gin/`

## Usage

These projects can be used to test the Dependency Risk Profiler with real-world dependencies:

```bash
# Analyze Flask dependencies
dependency-risk-profiler analyze --manifest test-projects/flask/requirements/tests.txt

# Analyze Express dependencies
dependency-risk-profiler analyze --manifest test-projects/express/package.json

# Analyze Gin dependencies
dependency-risk-profiler analyze --manifest test-projects/gin/go.mod
```

## Note on Project Copies

These are copies of the original projects with their git repositories removed to avoid embedding git repositories within our repository. The code is included for testing and demonstration purposes only.

**⚠️ IMPORTANT**: These copies may contain outdated dependencies with known vulnerabilities. They are intended for testing the Dependency Risk Profiler's ability to detect security issues and should not be used in production.