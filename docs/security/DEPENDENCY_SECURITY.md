# Dependency Security Management

This document outlines our approach to managing and securing dependencies in the Dependency Risk Profiler project.

## Security Policy

We take the security of our project and its dependencies seriously. Our approach includes:

1. **Regular dependency auditing**: We periodically scan for security vulnerabilities in our dependencies
2. **Prompt updates**: When vulnerabilities are identified, we update affected dependencies promptly
3. **Minimizing dependency bloat**: We carefully evaluate new dependencies before adding them
4. **Version pinning with minimums**: We specify minimum versions rather than exact versions to allow for security patches

## Current Security Measures

### Core Dependencies

We maintain secure minimum versions for all dependencies:

| Dependency | Minimum Version | Security Notes |
|------------|----------------|----------------|
| requests | 2.32.2 | Addresses CVE-2024-35195 |
| urllib3 | 2.2.2 | Addresses CVE-2024-37891 |
| jinja2 | 3.1.5 | Addresses CVE-2024-56201 |
| certifi | 2024.7.4 | Addresses CVE-2024-39689 |
| werkzeug | 3.0.6 | Addresses CVE-2024-49766, CVE-2024-49767 |
| cryptography | 42.0.0 | Addresses CVE-2023-50782 and others |
| pyyaml | 6.0.1 | Addresses potential vulnerabilities |
| pygments | 2.16.1 | Addresses CVE-2023-41337 |
| pillow | 10.2.0 | Addresses CVE-2023-50447, CVE-2024-35219 |

### Development Dependencies

Development dependencies are also maintained with security in mind:

| Dependency | Minimum Version | Security Notes |
|------------|----------------|----------------|
| pytest | 7.4.4 | Current stable version |
| pytest-cov | 4.1.0 | Current stable version |
| black | 24.2.0 | Current stable version |
| isort | 5.13.2 | Current stable version |
| flake8 | 7.0.0 | Current stable version |
| mypy | 1.6.0 | Current stable version |
| responses | 0.25.0 | Added for HTTP mocking in tests |

## Security Monitoring

We use several tools to monitor for security vulnerabilities:

1. **GitHub Dependabot**: Automatically creates PRs for vulnerabilities
2. **Safety**: Scans Python dependencies for known vulnerabilities
3. **pip-audit**: Additional auditing for Python packages

## Reporting Security Issues

If you discover a security vulnerability in our dependencies or in the project itself, please report it by:

1. Opening a GitHub issue labeled "security"
2. Sending an email to security@example.com (replace with actual contact)

Please include as much information as possible about the vulnerability, including:
- The affected dependency and version
- Steps to reproduce
- Potential impact
- Suggested fixes or mitigations

## Security Updates Schedule

We review dependencies for security updates on the following schedule:

- Critical vulnerabilities: Immediate updates
- High severity: Within 7 days
- Medium/Low severity: During the next scheduled release

## Secure Dependency Management Best Practices

When contributing to this project, please follow these best practices:

1. **Don't add dependencies unnecessarily**: Consider if a new dependency is truly needed
2. **Check security history**: Before adding a dependency, review its security track record
3. **Specify secure minimums**: When adding a dependency, specify a minimum version known to be secure
4. **Document security implications**: Comment on the security implications of dependencies in code
5. **Test after updates**: Ensure functionality is maintained after security updates

## Example Files and Intentional Vulnerabilities

The project contains intentionally outdated dependencies in the following directories:
- `/examples/` 
- `/dependabot_check/`

These files contain dependencies with known vulnerabilities for testing and demonstration purposes of the Dependency Risk Profiler tool. These intentional vulnerabilities are excluded from Dependabot alerts via the configuration in `.github/dependabot.yml`.

DO NOT use these example dependencies in production environments.

## History of Security Updates

The project maintains a comprehensive changelog of security updates in [CHANGELOG.md](../CHANGELOG.md).

## Recent Example File Updates

Updated in example files to address GitHub Dependabot alerts (April 16, 2025):

### Python Dependencies (`examples/requirements.txt`)

- Django: 3.2.4 → 5.1.2 (Fixes various CVEs including SQL injection, denial of service)
- Flask: 2.0.1 → 3.0.3 (Security and feature updates)
- Requests: 2.25.0 → 2.32.2 (Fixes CVE-2024-35195)
- pytest: 6.2.5 → 8.3.5 (Latest version)
- black: 21.5b2 → 24.2.0 (Latest stable version)
- numpy: 1.20.0 → 2.2.4 (Latest version)
- pandas: 1.2.4 → 2.2.2 (Latest version)

### JavaScript Dependencies (`examples/package-lock.json`)

- express: 4.17.1 → 4.18.2 (Latest stable version with security fixes)
- lodash: 4.17.20 → 4.17.21 (Fixes prototype pollution vulnerability)
- react: 17.0.2 → 18.2.0 (Latest version)
- axios: 0.21.1 → 1.6.5 (Fixes various CVEs)

### Go Dependencies (`examples/go.mod`)

- Go version: 1.17 → 1.22 (Latest stable version)
- gin-gonic/gin: 1.7.4 → 1.9.1 (Latest stable version)
- stretchr/testify: 1.7.0 → 1.9.0 (Latest version)
- sirupsen/logrus: 1.8.1 → 1.9.3 (Latest version)
- gorilla/mux: 1.8.0 → 1.8.1 (Latest version with security fixes)
- golang.org/x/crypto: 0.0.0-20210817164053-32db794688a5 → 0.24.0 (Latest version with security fixes)

Last updated: April 16, 2025