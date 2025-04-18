# Dependency Risk Profiler Examples

This directory contains examples, demos, and sample data for the Dependency Risk Profiler.

## Directory Structure

- [`data/`](data/README.md) - Example data files (JSON) for testing and demos
  - [`data/trends/`](data/trends/README.md) - Historical trend data for visualization
- [`fixtures/`](fixtures/README.md) - Test fixtures including sample large manifest files
- [`manifests/`](manifests/README.md) - Example dependency manifest files (requirements.txt, package-lock.json, go.mod)
- [`usage/`](usage/README.md) - Examples of using the Dependency Risk Profiler API in Python code
- [`visualization/`](visualization/README.md) - Examples of visualizing dependency risk data
- [`src/`](src/README.md) - Example source code for plugins and extensions

## Quick Start

The `demo.sh` script is available to run through a series of demos:

```bash
# Make sure the script is executable
chmod +x examples/demo.sh

# Run the demo script
./examples/demo.sh
```

## Running Examples Individually

You can also run individual examples:

### Basic API Usage

```bash
python examples/usage/api_usage.py
```

### Historical Trends Analysis

```bash
# Save a scan to history
python examples/visualization/trends_demo.py --manifest examples/manifests/requirements.txt

# Analyze trends
python examples/visualization/trends_demo.py --manifest examples/manifests/requirements.txt --analyze

# Generate visualization data
python examples/visualization/trends_demo.py --manifest examples/manifests/requirements.txt --visualize overall
```

### Visualization

After generating visualization data, open the HTML visualizer in a browser:

```bash
# Open the HTML visualizer (method depends on your system)
firefox examples/visualization/trend_visualizer.html
# OR
open examples/visualization/trend_visualizer.html
# OR
xdg-open examples/visualization/trend_visualizer.html
```

## Important Security Note

The example manifests contain intentionally outdated dependencies for testing and demonstration purposes. They serve as test cases for the Dependency Risk Profiler tool to identify and classify various risks.

**⚠️ WARNING: DO NOT use these example dependencies in production environments.**