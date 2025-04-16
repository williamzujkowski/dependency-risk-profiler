# Security Policy

## Supported Versions

Only the latest version of the Dependency Risk Profiler is actively maintained and supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

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

## Security Updates

Security updates are announced through:

1. GitHub releases
2. The CHANGELOG.md file
3. A note in the README.md for critical issues

We recommend keeping your installation up to date with the latest releases.

## Best Practices When Using This Tool

1. Always run the tool with appropriate permissions - it only needs file system read access to your dependency manifests.

2. Verify the integrity of the tool when installing it by checking the published checksums.

3. Since the tool makes network requests to package repositories, be mindful of using it in restricted network environments.

4. The tool reports security risks but does not automatically modify your dependencies. Always review the reported issues and make dependency updates according to your own assessment of risk.