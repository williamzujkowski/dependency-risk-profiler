# Configuration

Dependency Risk Profiler is highly configurable to adapt to different project needs and preferences. This guide covers the configuration options and how to customize the tool.

## Configuration File

The tool supports configuration through TOML or YAML files. You can generate a sample configuration file with:

```bash
dependency-risk-profiler generate-config --format toml > dependency-risk-profiler.toml
# or
dependency-risk-profiler generate-config --format yaml > dependency-risk-profiler.yml
```

## Configuration Locations

The tool searches for configuration in the following locations (in order of precedence):

1. File specified with `--config` command-line option
2. `dependency-risk-profiler.toml` or `dependency-risk-profiler.yml` in the current directory
3. `.dependency-risk-profiler.toml` or `.dependency-risk-profiler.yml` in the current directory
4. `$XDG_CONFIG_HOME/dependency-risk-profiler/config.toml` or `config.yml`
5. `~/.config/dependency-risk-profiler/config.toml` or `config.yml`

## Configuration Options

Here's a sample configuration file with explanations:

```toml
# Main configuration
[general]
# Default output format (terminal or json)
output_format = "terminal"

# Cache settings
cache_dir = "~/.cache/dependency-risk-profiler"
cache_ttl_days = 7

# API keys for various services
[api_keys]
github = ""  # GitHub personal access token
snyk = ""    # Snyk API key
nvd = ""     # NVD API key

# Risk scoring weights
[scoring]
vulnerability_weight = 0.4
maintenance_weight = 0.2
community_weight = 0.2
license_weight = 0.2

# Risk score thresholds
[risk_levels]
low = 0.3    # Below this is low risk
medium = 0.7 # Below this is medium risk, above is high risk

# Vulnerability scanning settings
[vulnerability]
include_experimental = false
minimum_severity = "medium"  # none, low, medium, high, critical
sources = ["osv", "github", "nvd"]

# Maintenance assessment settings
[maintenance]
max_age_days = 365  # Consider unmaintained after this many days
activity_window = 90  # Days to check for recent activity

# Community health settings
[community]
min_contributors = 3
require_security_policy = true

# License compliance settings
[license]
allowed_licenses = ["MIT", "Apache-2.0", "BSD-3-Clause"]
disallowed_licenses = ["GPL-3.0", "AGPL-3.0"]

# Ecosystem-specific settings
[ecosystems.python]
transitive_dependencies = true
max_depth = 5

[ecosystems.nodejs]
development_dependencies = false
include_peer_dependencies = true

[ecosystems.golang]
include_test_dependencies = false
```

## Environment Variables

Configuration can also be set through environment variables:

```bash
# Set API keys
export DEPENDENCY_RISK_PROFILER_GITHUB_TOKEN="your-github-token"
export DEPENDENCY_RISK_PROFILER_SNYK_TOKEN="your-snyk-token"

# Configure scoring weights
export DEPENDENCY_RISK_PROFILER_VULNERABILITY_WEIGHT="0.5"
export DEPENDENCY_RISK_PROFILER_MAINTENANCE_WEIGHT="0.2"

# Set other options
export DEPENDENCY_RISK_PROFILER_CACHE_TTL_DAYS="14"
export DEPENDENCY_RISK_PROFILER_OUTPUT_FORMAT="json"
```

Environment variables take precedence over configuration files, and command-line options take precedence over both.

## Command-Line Arguments

Many configuration options can be set directly via command-line arguments:

```bash
dependency-risk-profiler analyze \
  --output-format json \
  --min-severity high \
  --include-dev-dependencies \
  --cache-ttl-days 14 \
  --vulnerability-weight 0.5 \
  path/to/project
```

## Precedence Order

When multiple configuration sources are present, the following precedence is applied (from highest to lowest):

1. Command-line arguments
2. Environment variables
3. Project-specific configuration file
4. User configuration file
5. Default values

## Advanced Configuration

### Custom Risk Scoring

You can fine-tune risk scoring to match your organization's risk tolerance:

```toml
[scoring]
# Custom scoring model
vulnerability_weight = 0.5   # Higher weight for security issues
maintenance_weight = 0.3    
community_weight = 0.1
license_weight = 0.1

# Custom risk thresholds
[risk_levels]
low = 0.2    # Stricter threshold for low risk
medium = 0.5 # Stricter threshold for medium risk
```

### Proxy Configuration

For organizations behind a proxy:

```toml
[network]
proxy = "http://proxy.example.com:8080"
timeout_seconds = 30
max_retries = 3
```

### GitHub Enterprise Support

For GitHub Enterprise users:

```toml
[github]
api_url = "https://github.example.com/api/v3"
raw_url = "https://github.example.com/raw"
```

## Ignoring Files and Dependencies

You can create an ignore file (`.dependency-risk-profiler-ignore`) to exclude certain dependencies or issues:

```
# Ignore specific dependencies
lodash
# Ignore by pattern
test-*
# Ignore specific versions
express:4.17.1
# Ignore specific issues
CVE-2022-12345
```

## Next Steps

After configuring the tool, you may want to:

- Understand the [Risk Scoring](SCORING.md) methodology
- Learn about [Basic Usage](basic-usage.md) patterns
- Explore [Information Sources](INFORMATION_SOURCES.md) used by the tool