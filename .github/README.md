# GitHub Configuration Files

This directory contains configuration files for GitHub Actions and other GitHub integrations.

## Security Tools

### CodeQL Setup

The repository includes a custom CodeQL configuration to exclude test files and examples that may contain intentional vulnerabilities for demonstration purposes.

**Important:** To use the custom CodeQL workflow, you must disable the default setup in GitHub:

1. Go to GitHub repository → Settings → Code security and analysis
2. Find "Code scanning" section
3. Turn OFF "Default setup" for CodeQL Analysis
4. Turn ON "Advanced setup" to use this custom workflow

Otherwise, you'll see this error:
```
Error: Code Scanning could not process the submitted SARIF file:
CodeQL analyses from advanced configurations cannot be processed when the default setup is enabled
```

### Dependabot Configuration

The repository includes a Dependabot configuration file that:

1. Scans Python, NPM, and Go dependencies for vulnerabilities
2. Ignores test directories and example code with intentionally outdated dependencies
3. Runs weekly checks for dependency updates

## CI/CD Workflows

### Main CI Workflow (`ci.yml`)

Runs on all pushes and pull requests to the main branch:
- Runs tests on multiple Python versions
- Performs linting and type checking
- Collects test coverage data

### Documentation Workflow (`docs.yml`)

Runs when documentation files are changed:
- Builds the MkDocs documentation site
- Deploys to GitHub Pages

### Release Workflow (`release.yml`)

Runs when a version tag is pushed:
- Builds Python packages
- Creates a GitHub release
- Publishes to PyPI
- Updates documentation