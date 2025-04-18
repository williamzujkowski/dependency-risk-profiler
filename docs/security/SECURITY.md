# Security Policy

## Supported Versions

Only the latest version of the Dependency Risk Profiler is actively maintained and supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover any security issues in the Dependency Risk Profiler, please report them by following these steps:

1. **Do not open a GitHub issue if the bug is a security vulnerability**. Instead, please contact the maintainers directly via email at security@example.com.

2. Provide a detailed report, including:
   - What you were doing when you discovered the vulnerability
   - The potential impact of the vulnerability
   - Steps to reproduce the vulnerability

3. The maintainers will acknowledge your report as soon as possible, and will provide a timeline for the fix based on the severity and complexity of the issue.

4. Please do not disclose the issue publicly until it has been addressed and a release containing the fix has been published.

## Security Considerations for Dependency Risk Profiler

Since this tool analyzes and reports on security risks in dependencies, we are especially vigilant about security. In particular:

1. **Data Privacy**: The tool does not transmit your dependency information to external servers. All analysis is done locally.

2. **Safe Network Access**: When fetching package metadata from public repositories, the tool uses only anonymous access and follows best practices for secure HTTP requests.

3. **No Execution of External Code**: The tool does not execute any code from the dependencies it analyzes. It only reads and analyzes manifest files.

4. **Temporary Files**: Any temporary files created during analysis are securely managed and removed when no longer needed.

## Project Security Measures

The Dependency Risk Profiler project employs several security measures for its own codebase:

### Automated Security Scanning

- **GitHub CodeQL Analysis**: Automatically scans code for potential security vulnerabilities
  - Uses GitHub Advanced Security with a customized CodeQL workflow
  - The workflow is configured with `.github/codeql/codeql-config.yml` to exclude test directories and example code
  - Runs on every push to main, pull requests to main, and weekly scheduled scans
  - Uses extended security queries for comprehensive vulnerability detection

- **Bandit**: Python-specific security linter integrated into our CI/CD pipeline
  - Detects common security issues in Python code
  - Run via `bandit -r src -c .bandit.yml` in our CI process

### Dependency Management

- **Dependabot**: Automatically monitors our dependencies for vulnerabilities
  - Creates pull requests when security updates are available
  - Configured to exclude test directories and example code
  - Configuration is located in `.github/dependabot.yml`
  
- **Self-analysis**: We regularly run the Dependency Risk Profiler against itself

### Security in Testing

Our project contains intentionally outdated dependencies and vulnerability examples in the following directories:
- `/examples/` 
- `/testing/projects/`

These files are used for testing and demonstration purposes of the tool's capabilities and are excluded from security scanning to avoid false positives.

**⚠️ WARNING: The demonstration dependencies in test and example code should not be used in production environments.**

## Security Updates

Security updates are announced through:

1. GitHub releases
2. The CHANGELOG.md file
3. A note in the README.md for critical issues

We recommend keeping your installation up to date with the latest releases.

### Recent Security Updates

- **2025-04-16 (v0.2.0)**: Updated dependency requirements to address the following vulnerabilities:
  - requests: Updated to >=2.32.2 (fixes CVE-2024-35195)
  - urllib3: Updated to >=2.2.2 (fixes CVE-2024-37891)
  - jinja2: Updated to >=3.1.5 (fixes CVE-2024-56201)
  - certifi: Updated to >=2024.7.4 (fixes CVE-2024-39689)
  - werkzeug: Updated to >=3.0.6 (fixes CVE-2024-49766, CVE-2024-49767)
  - Development dependencies:
    - pytest: Updated to >=7.4.0
    - pytest-cov: Updated to >=4.2.0
    - black: Updated to >=24.4.0
    - isort: Updated to >=5.13.2
    - flake8: Updated to >=7.0.0
    - mypy: Updated to >=1.9.0

## Best Practices When Using This Tool

1. Always run the tool with appropriate permissions - it only needs file system read access to your dependency manifests.

2. Verify the integrity of the tool when installing it by checking the published checksums.

3. Since the tool makes network requests to package repositories, be mindful of using it in restricted network environments.

4. The tool reports security risks but does not automatically modify your dependencies. Always review the reported issues and make dependency updates according to your own assessment of risk.