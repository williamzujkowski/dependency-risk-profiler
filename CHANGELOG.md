# Changelog

All notable changes to the Dependency Risk Profiler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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