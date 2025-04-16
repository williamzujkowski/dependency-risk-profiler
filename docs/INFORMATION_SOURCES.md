# Dependency Risk Profiler: Information Sources

This document details the various information sources and methodologies used by the Dependency Risk Profiler to collect dependency metadata for risk assessment.

## Package Registry APIs

### Node.js (npm)

The tool retrieves package information from the npm registry's public API:

- **Endpoint**: `https://registry.npmjs.org/{package-name}`
- **Information Retrieved**:
  - Latest version
  - Deprecation status
  - Repository URL
  - Release dates
  - Maintainer information (partial)

Example API response structure:
```json
{
  "name": "package-name",
  "version": "1.2.3",
  "deprecated": false,
  "repository": {
    "type": "git", 
    "url": "https://github.com/org/repo"
  },
  "time": {
    "1.0.0": "2023-01-01T00:00:00.000Z",
    "1.2.3": "2023-04-15T00:00:00.000Z"
  },
  "maintainers": [
    {"name": "user1", "email": "user1@example.com"}
  ]
}
```

### Python (PyPI)

The tool uses PyPI's JSON API to retrieve package metadata:

- **Endpoint**: `https://pypi.org/pypi/{package-name}/json`
- **Information Retrieved**:
  - Latest version
  - Project URLs (including repository)
  - Description (checked for deprecation indicators)
  - Release history

Example API response structure:
```json
{
  "info": {
    "name": "package-name",
    "version": "1.2.3",
    "description": "A useful package",
    "project_urls": {
      "Source": "https://github.com/org/repo",
      "Documentation": "https://docs.example.com"
    }
  },
  "releases": {
    "1.0.0": [{"upload_time": "2023-01-01T00:00:00"}],
    "1.2.3": [{"upload_time": "2023-04-15T00:00:00"}]
  }
}
```

### Go Packages

For Go packages, information is extracted from pkg.go.dev:

- **Method**: HTML scraping of `https://pkg.go.dev/{import-path}`
- **Information Retrieved**:
  - Latest version (from version indicator)
  - Repository URL (inferred from import path)

## Repository Analysis

When a repository URL is available (typically from GitHub, GitLab, or Bitbucket), the tool performs additional analysis:

### Repository Cloning

- The tool creates a temporary clone of the repository using:
  ```bash
  git clone --depth 1 {repository-url} {temp-directory}
  ```
- This shallow clone helps minimize bandwidth and storage requirements while still providing access to the latest code.

### Last Update Analysis

- **Command**: `git log -1 --format=%cd --date=iso`
- **Purpose**: Determines when the package was last updated.
- **Limitation**: A shallow clone only sees recent commit history.

### Contributor Analysis

- **Command**: `git shortlog -s -n --all`
- **Purpose**: Counts unique contributors to estimate maintainer diversity.
- **Limitation**: Shallow clones limit the accuracy of this count.

### Health Indicators Analysis

The tool scans the repository structure for indicators of project health:

1. **Tests**:
   - Looks for directories named `test`, `tests`, `spec`, or `specs`
   - Looks for files matching patterns like `*_test.py`, `*.test.js`, etc.

2. **CI Configuration**:
   - Checks for CI configuration files:
     - `.travis.yml`
     - `.github/workflows/*`
     - `.circleci/config.yml`
     - `.gitlab-ci.yml`
     - `azure-pipelines.yml`
     - `Jenkinsfile`
     - etc.

3. **Contribution Guidelines**:
   - Looks for files like:
     - `CONTRIBUTING.md`
     - `.github/CONTRIBUTING.md`
     - `DEVELOPMENT.md`
     - etc.

## Security Information

The current implementation uses a simplified approach to identify potential security issues:

- **Package Documentation**: Scans package descriptions and documentation for keywords related to security issues (e.g., "vulnerability", "security", "CVE").
- **Simple Pattern Matching**: Checks for patterns like "CVE-####-####" that might indicate known vulnerabilities.

Note: This is a basic approach and not as comprehensive as dedicated security scanners. Future versions could integrate with:
- OSV (Open Source Vulnerabilities) database
- GitHub Advisory Database
- NPM Security Advisories
- NVD (National Vulnerability Database)

## Version Comparison

The tool compares installed and latest versions using the following approach:

1. **Version Parsing**: Uses the Python `packaging.version` module to parse semantic versions.
2. **Version Difference Analysis**:
   - Compares major, minor, and patch components
   - Higher weight given to major version differences
   - Special handling for pre-release versions and non-standard versioning schemes

## Data Processing Approach

All data collection follows these principles:

1. **Public Information Only**: All information is gathered from publicly available sources, without requiring API keys or authentication.
2. **Network Resilience**: The tool handles network failures gracefully and falls back to partial information when complete data is unavailable.
3. **Local Processing**: Analysis is performed locally without sending dependency information to external services.
4. **Temporary Storage**: Repository clones and other temporary data are stored in temporary directories and cleaned up after use.

## Privacy and Security Considerations

- No dependency information is transmitted to external servers beyond the necessary API calls to public registries.
- The tool does not execute any code from the dependencies it analyzes.
- Repository credentials are never stored or used.
- All network requests use proper User-Agent identification.

## Limitations

1. **Rate Limiting**: Public APIs may impose rate limits that can restrict the tool's ability to analyze large numbers of dependencies in rapid succession.
2. **Data Availability**: Not all packages provide complete information through public APIs.
3. **Network Dependence**: The tool requires internet access to retrieve up-to-date information.
4. **Shallow Analysis**: Due to performance considerations, repository analysis uses shallow clones which may miss some historical context.

---

*This documentation describes the information sources as of version 0.1.0 of the Dependency Risk Profiler.*