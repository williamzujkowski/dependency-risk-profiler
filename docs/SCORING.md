# Dependency Risk Profiler: Scoring Methodology

This document explains how the Dependency Risk Profiler calculates risk scores for dependencies and the sources of information used in the analysis.

## Overview

The Dependency Risk Profiler evaluates dependencies across multiple dimensions to provide a comprehensive risk assessment beyond traditional vulnerability scanning. Each dependency receives a risk score on a scale of 0.0 to 5.0, which is then categorized into risk levels (LOW, MEDIUM, HIGH, or CRITICAL).

## Data Collection Sources

The tool collects information from various sources to evaluate dependency health:

### 1. Package Registries

- **Node.js (npm)**: The tool queries the npm registry API (`https://registry.npmjs.org/[package-name]`) to retrieve package metadata including latest version, deprecation status, and repository information.

- **Python (PyPI)**: The PyPI JSON API (`https://pypi.org/pypi/[package-name]/json`) provides package metadata including latest version, project URLs, and description text that might indicate deprecation.

- **Go**: For Go packages, we use the Go package site (`https://pkg.go.dev/[package]`) to extract latest version information.

### 2. Source Code Repositories

When a repository URL is available, the tool clones the repository to analyze:

- **Commit History**: Using Git commands to extract the date of the most recent commit.
- **Contributor Count**: Using Git to count unique contributors via commit history.
- **Health Indicators**: Scanning the repository for the presence of:
  - Test files/directories
  - CI configuration files (.travis.yml, .github/workflows, etc.)
  - Contribution guidelines (CONTRIBUTING.md, etc.)

### 3. Security Information

- **Vulnerability Databases**: The tool queries multiple sources including OSV (Open Source Vulnerabilities), NVD (National Vulnerability Database), and GitHub Advisory Database.
- **Security Indicators**: Analysis of security policies, branch protection rules, signed commits, and dependency update tools.
- **Security Documentation**: Checking for presence of SECURITY.md and security-related documentation.

## Risk Scoring Components

The overall risk score is calculated from multiple components, each with configurable weights. The basic components include:

### 1. Staleness Score (Default Weight: 0.25)

Measures how recently the dependency was updated:

| Last Updated | Score |
|--------------|-------|
| < 1 month    | 0.0   |
| 1-3 months   | 0.25  |
| 3-6 months   | 0.5   |
| 6-12 months  | 0.75  |
| > 1 year     | 1.0   |

### 2. Maintainer Score (Default Weight: 0.2)

Evaluates the number of active maintainers/contributors:

| Maintainer Count | Score |
|------------------|-------|
| 5+               | 0.0   |
| 3-4              | 0.25  |
| 2                | 0.5   |
| 1                | 1.0   |
| Unknown          | 0.5   |

### 3. Deprecation Score (Default Weight: 0.3)

Indicates if the package is officially deprecated:

| Status      | Score |
|-------------|-------|
| Deprecated  | 1.0   |
| Not Deprecated | 0.0   |

### 4. Exploit Score (Default Weight: 0.5)

Indicates if there are known security issues:

| Status           | Score |
|------------------|-------|
| Known Exploits   | 1.0   |
| No Known Exploits | 0.0   |

### 5. Version Difference Score (Default Weight: 0.15)

Measures how outdated the installed version is:

| Version Difference | Score |
|--------------------|-------|
| Same Version       | 0.0   |
| Patch Version (0.0.x) | 0.25  |
| Minor Version (0.x.0) | 0.5   |
| Major Version (x.0.0) | 1.0   |
| Unparseable        | 0.5   |

### 6. Health Indicators Score (Default Weight: 0.1)

Evaluates project health based on presence of tests, CI, and contribution guidelines:

| Health Indicators     | Score |
|-----------------------|-------|
| All Present           | 0.0   |
| None Present          | 1.0   |
| Some Present          | Proportional (1 - ratio of present indicators) |
| Unknown               | 0.5   |

### Enhanced Risk Components (v0.2.0+)

These additional components are part of the enhanced risk model in version 0.2.0 and later:

7. **License Risk Score (Default Weight: 0.3)**

Evaluates the license type and compliance risk:

| License Type         | Score |
|----------------------|-------|
| Permissive (MIT, Apache, BSD) | 0.0 |
| Weak Copyleft (LGPL) | 0.3   |
| Strong Copyleft (GPL)| 0.5   |
| Non-standard        | 0.7   |
| No License          | 1.0   |

8. **Community Health Score (Default Weight: 0.25)**

Evaluates community engagement metrics:

| Community Factors    | Score |
|----------------------|-------|
| Many stars, forks, and active PRs | 0.0 |
| Moderate activity    | 0.4   |
| Low activity         | 0.7   |
| Abandoned           | 1.0   |

9. **Security Policy Score (Default Weight: 0.35)**

Evaluates security practices in the repository:

| Security Practices   | Score |
|----------------------|-------|
| All security best practices | 0.0 |
| Some security practices | 0.4   |
| Few security practices | 0.7   |
| No security practices | 1.0   |

## Calculation Process

1. **Individual Scoring**: Each component is scored on a scale of 0.0 to 1.0.

2. **Weighted Average**: The component scores are combined using a weighted average:
   ```
   total_score = sum(component_score * weight for each component)
   ```

3. **Normalization**: The weighted average is normalized to the maximum score (default: 5.0):
   ```
   normalized_score = (weighted_average / sum_of_weights) * max_score
   ```

4. **Risk Level Assignment**: The normalized score is mapped to a risk level:
   
   | Score Range (% of max) | Risk Level |
   |------------------------|------------|
   | 0% - 25% (0.0 - 1.25)  | LOW        |
   | 25% - 50% (1.25 - 2.5) | MEDIUM     |
   | 50% - 75% (2.5 - 3.75) | HIGH       |
   | 75% - 100% (3.75 - 5.0) | CRITICAL   |

5. **Risk Factors Identification**: The tool identifies specific risk factors that contribute to the score, such as "Single maintainer", "Not updated in X days", or "Known security issues".

## Customizing the Scoring

Users can customize the weights for each risk component via command-line arguments:

```bash
dependency-risk-profiler --manifest package-lock.json \
  --staleness-weight 0.3 \
  --maintainer-weight 0.2 \
  --deprecation-weight 0.3 \
  --exploit-weight 0.6 \
  --version-weight 0.2 \
  --health-weight 0.1
```

This allows organizations to adjust the scoring methodology to align with their specific risk tolerance and priorities.

## Limitations and Caveats

- The tool relies on publicly available information and anonymous access to package registries.
- Some metrics might be unavailable for certain packages, leading to the use of default scores.
- Repository analysis requires Git access and may be time-consuming for large repositories.
- Security vulnerability detection is basic and not a replacement for dedicated security scanning tools.
- Version parsing may not handle all non-standard versioning schemes correctly.

## Future Enhancements

- Dependency usage analysis (how many projects depend on this package)
- More sophisticated version analysis (SemVer compliance, release frequency)
- Static code analysis metrics (code quality, test coverage)

---

*This document describes the risk scoring methodology as of version 0.2.0 of the Dependency Risk Profiler.*