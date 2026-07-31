# Configuration

Dependency Risk Profiler is highly configurable to adapt to different project needs and preferences. This guide covers the configuration options and how to customize the tool.

## Configuration File

The tool supports configuration through TOML or YAML files. You can generate a sample configuration file with:

```bash
dependency-risk-profiler generate-config dependency-risk-profiler.toml
# or
dependency-risk-profiler generate-config dependency-risk-profiler.yml --format yaml
```

## Configuration Locations

The tool searches for configuration in the following locations (in order of precedence):

1. File specified with the top-level `--config` command-line option
2. `.dependency-risk-profiler.toml`, `.dependency-risk-profiler.yaml`, or `.dependency-risk-profiler.yml` in the current directory
3. `~/.config/dependency-risk-profiler/config.toml`, `config.yaml`, or `config.yml`

## Configuration Options

Here's a sample configuration file with explanations:

```toml
# Main configuration
[general]
# Default output format (terminal or json)
output_format = "terminal"
use_color = true
debug = false

# API keys for various services
[vulnerability]
enable_osv = true
enable_nvd = false
enable_github_advisory = false
github_token = ""  # GitHub personal access token
nvd_api_key = ""   # NVD API key
minimum_severity_for_scoring = "LOW"

# Risk scoring weights
[scoring_weights]
staleness = 0.25
maintainer = 0.2
deprecation = 0.3
exploit = 0.5
version_difference = 0.15
health_indicators = 0.1
license = 0.3
community = 0.2
transitive = 0.15
popularity_high_stars = 2000
popularity_high_contributors = 25
staleness_popularity_dampening = 0.5

[trends]
save_history = false
analyze = false
limit = 10

[graph]
generate = false
format = "d3"
depth = 3
```

## Environment Variables

Configuration can also be set through environment variables:

```bash
# Set API keys
export DRP_GITHUB_TOKEN="your-github-token"
export DRP_NVD_API_KEY="your-nvd-key"

# Set output and logging
export DRP_OUTPUT_FORMAT="json"
export DRP_DEBUG="true"

# Set other options
export DRP_MINIMUM_VULNERABILITY_SEVERITY="MEDIUM"
export DRP_DISABLE_CACHE="true"
```

Environment variables take precedence over configuration files, and command-line options take precedence over both.

## Command-Line Arguments

Many configuration options can be set directly via command-line arguments:

```bash
dependency-risk-profiler analyze path/to/project \
  --output json \
  --minimum-vulnerability-severity HIGH \
  --staleness-weight 0.3 \
  --maintainer-weight 0.25 \
  --license-weight 0.25
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
[scoring_weights]
# Custom scoring model
exploit = 0.6
staleness = 0.3
maintainer = 0.25
version_difference = 0.2
license = 0.25
```

`popularity_high_stars`, `popularity_high_contributors`, and
`staleness_popularity_dampening` calibrate staleness only when real popularity
metadata is available. This treats mature, widely adopted projects with slow
release cadence as lower abandonment risk without reducing bus-factor or
vulnerability/advisory risk.

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
