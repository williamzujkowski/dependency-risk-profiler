# Changelog

All notable changes to the Dependency Risk Profiler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-04-17

### Added

- Directory scanning feature to analyze all manifest files in a directory with a single command
  - Support for recursive scanning of subdirectories with `--recursive` flag
  - Automatic ecosystem detection for all manifest files
  - Overall summary of risk scores across all scanned files
- Comprehensive test suite following TESTING_STANDARDS.md:
  - Hypothesis tests for behavior validation
  - Regression tests for known fail states
  - Benchmark tests with SLA enforcement
  - Fuzzing tests for edge case discovery
  - Structured logging tests for agent feedback

### Changed

- Added pytest-benchmark and numpy for performance testing
- Updated docstrings and error handling in tests
- Improved mocking and test coverage
- Refactored test code for testability and maintainability
- Fixed timezone handling in datetime comparisons
- Implemented direct testing patterns to avoid complex mocking
- Added proper benchmark test markers in pyproject.toml
- Fixed parameter mismatch in RiskScorer configuration
- Added proper HTTP session closure to prevent resource leaks

### Security

- Updated all dependencies to latest secure versions:
  - pytest: Updated to >=8.4.0
  - pytest-cov: Updated to >=4.2.0
  - black: Updated to >=24.4.0
  - mypy: Updated to >=1.9.0
  - numpy: Updated to >=2.2.4

### Fixed

- Changed dependencies to ensure wider compatibility:
  - Downgraded networkx requirement from >=3.3 to >=2.8.8 for better compatibility
  - Adjusted matplotlib requirement from >=3.8.3 to >=3.7.0
  - Changed pytest requirement from >=8.4.0 to >=7.4.0 for CI compatibility
- Fixed security vulnerabilities in example files:
  - Django: Updated to 5.1.8 (fixes multiple CVEs)
  - Express: Updated to 4.18.2
  - Lodash: Updated to 4.17.21
  - React: Updated to 18.2.0
  - Axios: Updated to 1.6.5
  - Go dependencies upgraded to latest versions
- Updated package metadata with correct author information

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
  - cryptography: Updated to >=42.0.0 (fixes CVE-2023-50782 and others)
  - pyyaml: Updated to >=6.0.1 (addresses potential vulnerabilities)
  - pygments: Added >=2.16.1 (fixes CVE-2023-41337)
  - pillow: Added >=10.2.0 (fixes CVE-2023-50447, CVE-2024-35219)
- Updated development dependencies to secure versions:
  - pytest: Updated to >=7.4.4
  - pytest-cov: Updated to >=4.1.0
  - black: Updated to >=24.2.0
  - isort: Updated to >=5.13.2
  - flake8: Updated to >=7.0.0
  - mypy: Updated to >=1.6.0
  - Added responses >=0.25.0 for HTTP mocking in tests

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