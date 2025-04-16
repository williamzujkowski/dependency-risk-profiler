# Changelog

All notable changes to the Dependency Risk Profiler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-04-16

### Added

- License and compliance analysis for dependencies
- Community health metrics (stars, forks, contributors)
- Transitive dependency analysis for deeper supply chain insights
- Security posture analysis (security policies, branch protection, signed commits)
- Aggregation of vulnerability data from multiple sources (OSV, NVD, GitHub Advisory)
- Historical trends analysis with visualization capabilities
- Supply chain visualization with interactive dependency graphs
- Secure code signing and release management functionality
- Support for Pipfile.lock in addition to requirements.txt for Python projects
- TOML file parser for analyzing pyproject.toml (Poetry, PEP 621) and Cargo.toml (Rust) dependencies

### Security

- Updated dependency requirements to address security vulnerabilities:
  - requests: Updated to >=2.32.2 (fixes CVE-2024-35195)
  - urllib3: Updated to >=2.2.2 (fixes CVE-2024-37891)
  - jinja2: Updated to >=3.1.5 (fixes CVE-2024-56201)
  - certifi: Updated to >=2024.7.4 (fixes CVE-2024-39689)
  - werkzeug: Updated to >=3.0.6 (fixes CVE-2024-49766, CVE-2024-49767)

### Changed

- Improved code organization and documentation
- Enhanced error handling and logging
- Fixed linting issues and code style inconsistencies
- Updated installation scripts for better cross-platform compatibility

## [0.1.0] - 2025-04-15

### Added

- Initial release of the Dependency Risk Profiler
- Support for analyzing Node.js (package-lock.json), Python (requirements.txt), and Go (go.mod) dependencies
- Risk scoring based on multiple factors:
  - Update recency (staleness)
  - Number of maintainers
  - Deprecation status
  - Known vulnerabilities
  - Version differences
  - Health indicators (tests, CI, contribution guidelines)
- Color-coded terminal output
- JSON output option
- Customizable risk scoring weights
- Basic test suite