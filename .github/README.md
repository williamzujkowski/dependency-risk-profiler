# GitHub Configuration Files

This directory contains configuration files for GitHub Actions and other GitHub integrations.

## Security Tools

### CodeQL Setup

The repository includes a custom CodeQL configuration to exclude test files and examples that may contain intentional vulnerabilities for demonstration purposes.

**Important note on CodeQL setup:**

1. We've set up GitHub Advanced Security with a customized CodeQL workflow
2. The workflow is configured to use `.github/codeql/codeql-config.yml` for path exclusions
3. Test directories, example code, and other non-production files are excluded from scanning
4. This prevents false positives from intentional vulnerabilities in example code

If you're adapting this configuration for your own repository:
1. Go to GitHub repository → Settings → Code security and analysis
2. Enable "Advanced setup" for CodeQL Analysis 
3. Update the generated workflow to use the custom config file

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