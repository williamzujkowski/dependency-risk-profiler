# Visualization Examples

This directory contains examples of how to visualize dependency risk data using the Dependency Risk Profiler.

## Available Examples

- `trend_visualizer.html` - HTML/JavaScript tool for visualizing trend data
- `trends_demo.py` - Python script for demonstrating historical trends analysis
- `visualize_trends.py` - Python script for generating trend visualization data

## Using the Visualization Tools

### HTML Visualizer

The `trend_visualizer.html` file provides a simple web-based visualization tool:

1. Generate trend visualization data using one of the Python scripts
2. Open the trend_visualizer.html file in a web browser
3. Click "Choose File" and select the generated JSON file
4. View the visualized trend data

### Python Trend Analysis

The `trends_demo.py` script demonstrates how to use the historical trends analysis functionality:

```bash
# Save the current scan to historical data
python examples/visualization/trends_demo.py --manifest examples/manifests/requirements.txt

# Analyze historical trends
python examples/visualization/trends_demo.py --manifest examples/manifests/requirements.txt --analyze

# Generate visualization data
python examples/visualization/trends_demo.py --manifest examples/manifests/requirements.txt --visualize overall
```

### Custom Visualization

The `visualize_trends.py` script shows how to generate custom visualization data:

```bash
# Generate custom visualization data
python examples/visualization/visualize_trends.py --manifest examples/manifests/requirements.txt --output custom_viz.json
```

## Data Format

The visualization data is generated in JSON format with the following structure:

- Time-series data with timestamps
- Risk metrics for dependencies over time
- Distribution of risk levels over time
- Overall project risk score trends

See the example files in the `examples/data` directory for sample visualization data.