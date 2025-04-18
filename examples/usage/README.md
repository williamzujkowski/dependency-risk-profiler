# API Usage Examples

This directory contains examples of how to use the Dependency Risk Profiler as a library in your own Python code.

## Available Examples

- `api_usage.py` - Basic example of how to use the library API
- `simple_test.py` - Simple test script for the Dependency Risk Profiler
- `secure_release_demo.py` - Demo of the secure release management features

## Running the Examples

You can run these examples using Python:

```bash
# Run the API usage example
python examples/usage/api_usage.py

# Run the simple test
python examples/usage/simple_test.py

# Run the secure release demo
python examples/usage/secure_release_demo.py
```

## API Usage Overview

The Dependency Risk Profiler can be used as a library in your Python code. Here's a basic example:

```python
from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.cli.formatter import TerminalFormatter

# Parse a manifest file
parser = BaseParser.get_parser_for_file("requirements.txt")
dependencies = parser.parse()

# Analyze the dependencies
analyzer = BaseAnalyzer.get_analyzer_for_ecosystem("python")
dependencies = analyzer.analyze(dependencies)

# Score the dependencies
scorer = RiskScorer()
profile = scorer.create_project_profile("requirements.txt", "python", dependencies)

# Format the results
formatter = TerminalFormatter(color=True)
output = formatter.format_profile(profile)
print(output)
```

See the individual example files for more detailed usage examples.