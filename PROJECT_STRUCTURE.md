# Project Structure

This document provides an overview of the Dependency Risk Profiler project structure to help developers and contributors navigate the codebase effectively.

## Root Directory

- `docs/` - Project documentation (rendered at [https://williamzujkowski.github.io/dependency-risk-profiler/](https://williamzujkowski.github.io/dependency-risk-profiler/))
- `examples/` - Example scripts, data, and demonstrations of features
- `samples/` - Sample data files for testing and demonstration
- `scripts/` - Installation and utility scripts
- `src/` - Main source code directory
- `testing/` - Tests, test fixtures, and test projects
  - `unit/` - Unit tests for individual components
  - `integration/` - Integration tests for multi-component functionality
  - `fixtures/` - Test fixtures and mock data
  - `manifests/` - Sample dependency manifests for testing
  - `projects/` - Complete project copies for testing
- `tests/` - Symlink to testing/ for backward compatibility

## Additional Files

- `LICENSE` - MIT License text
- `MANIFEST.in` - List of files to include in Python packages
- `PROJECT_STRUCTURE.md` - This file
- `README.md` - Main project documentation

## Documentation Files (in docs/)

- `docs/CHANGELOG.md` - Version history and changes
- `docs/development/CLAUDE.md` - Instructions for Claude AI when working with the codebase
- `docs/CONTRIBUTING.md` - Guide for contributors 
- `docs/security/DEPENDENCY_SECURITY.md` - Security policy for dependencies
- `docs/development/PROMPT.md` - AI assistant context and prompts
- `docs/security/SECURITY.md` - Security policies and procedures
- `docs/project_standards/TESTING_IMPLEMENTATION.md` - Implementation details for the test suite
- `docs/project_standards/TESTING_STANDARDS.md` - Standards and guidelines for writing tests

## Configuration Files

- `mkdocs.yml` - MkDocs configuration for documentation site
- `mypy.ini` - Configuration for mypy type checking
- `pyproject.toml` - Project metadata and dependencies
- `setup.cfg` - Legacy setuptools configuration
- `setup.py` - Legacy setuptools build script

## Key Directories in Source Code

- `src/dependency_risk_profiler/analyzers/` - Dependency analysis engines for different ecosystems
- `src/dependency_risk_profiler/cli/` - Command-line interface implementation
- `src/dependency_risk_profiler/community/` - Community health metrics analysis
- `src/dependency_risk_profiler/license/` - License analysis and compliance checking
- `src/dependency_risk_profiler/parsers/` - Manifest file parsers for different ecosystems
- `src/dependency_risk_profiler/scorecard/` - OpenSSF Scorecard-inspired metrics analysis
- `src/dependency_risk_profiler/scoring/` - Risk scoring implementation
- `src/dependency_risk_profiler/secure_release/` - Code signing and secure release management
- `src/dependency_risk_profiler/supply_chain/` - Supply chain analysis and visualization
- `src/dependency_risk_profiler/transitive/` - Transitive dependency analysis
- `src/dependency_risk_profiler/vulnerabilities/` - Vulnerability scanning and aggregation