#!/usr/bin/env python
"""Example of how to use the Dependency Risk Profiler as a library."""

import os
import sys
from pathlib import Path

# Add the parent directory to the Python path to allow importing the library
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.cli.formatter import TerminalFormatter
from dependency_risk_profiler.models import RiskLevel
from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer


def analyze_dependencies(manifest_path, custom_weights=None):
    """Analyze dependencies in a manifest file.

    Args:
        manifest_path: Path to the manifest file.
        custom_weights: Optional dictionary of custom weights for scoring.

    Returns:
        Formatted project risk profile.
    """
    # Convert to absolute path
    manifest_path = os.path.abspath(manifest_path)

    # Get the appropriate parser for the manifest file
    parser = BaseParser.get_parser_for_file(manifest_path)
    if not parser:
        print(f"Unsupported manifest file: {manifest_path}")
        return None

    # Parse the manifest file
    print(f"Parsing {manifest_path}...")
    dependencies = parser.parse()

    # Get the ecosystem from the manifest file
    file_name = os.path.basename(manifest_path).lower()
    if file_name == "package-lock.json":
        ecosystem = "nodejs"
    elif file_name in ["requirements.txt", "pipfile.lock"]:
        ecosystem = "python"
    elif file_name == "go.mod":
        ecosystem = "golang"
    else:
        ecosystem = "unknown"

    # Get the appropriate analyzer for the ecosystem
    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(ecosystem)
    if not analyzer:
        print(f"Unsupported ecosystem: {ecosystem}")
        return None

    # Analyze the dependencies
    print(f"Analyzing {len(dependencies)} dependencies...")
    dependencies = analyzer.analyze(dependencies)

    # Create a risk scorer with custom weights if provided
    if custom_weights:
        scorer = RiskScorer(**custom_weights)
    else:
        scorer = RiskScorer()

    # Score the dependencies
    print("Scoring dependencies...")
    profile = scorer.create_project_profile(manifest_path, ecosystem, dependencies)

    # Format the profile
    formatter = TerminalFormatter(color=True)
    output = formatter.format_profile(profile)

    # Return the formatted profile
    return output


def main():
    """Main function."""
    # Example 1: Analyze a Python requirements.txt file
    python_output = analyze_dependencies("requirements.txt")
    print(python_output)
    print("\n" + "=" * 50 + "\n")

    # Example 2: Analyze a Node.js package-lock.json file with custom weights
    custom_weights = {
        "staleness_weight": 0.3,
        "maintainer_weight": 0.2,
        "deprecation_weight": 0.4,
        "exploit_weight": 0.6,
        "version_difference_weight": 0.3,
        "health_indicators_weight": 0.1,
    }
    nodejs_output = analyze_dependencies("package-lock.json", custom_weights)
    print(nodejs_output)

    # Example 3: Process the results programmatically
    print("\n" + "=" * 50 + "\n")
    print("Programmatic processing example:")

    parser = BaseParser.get_parser_for_file("requirements.txt")
    dependencies = parser.parse()
    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem("python")
    dependencies = analyzer.analyze(dependencies)
    scorer = RiskScorer()
    profile = scorer.create_project_profile("requirements.txt", "python", dependencies)

    # Count dependencies by risk level
    risk_counts = {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.HIGH: 0,
        RiskLevel.CRITICAL: 0,
    }

    for dep in profile.dependencies:
        risk_counts[dep.risk_level] += 1

    print(f"Total dependencies: {len(profile.dependencies)}")
    print(f"Low risk: {risk_counts[RiskLevel.LOW]}")
    print(f"Medium risk: {risk_counts[RiskLevel.MEDIUM]}")
    print(f"High risk: {risk_counts[RiskLevel.HIGH]}")
    print(f"Critical risk: {risk_counts[RiskLevel.CRITICAL]}")

    # Find the highest risk dependency
    highest_risk_dep = max(profile.dependencies, key=lambda d: d.total_score)
    print(f"\nHighest risk dependency: {highest_risk_dep.dependency.name}")
    print(f"Risk score: {highest_risk_dep.total_score:.2f}/5.0")
    print(f"Risk level: {highest_risk_dep.risk_level.value}")
    print(f"Risk factors: {', '.join(highest_risk_dep.factors)}")


if __name__ == "__main__":
    # Change to the script's directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    main()
