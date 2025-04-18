#!/usr/bin/env python
"""
Simple test script for dependency-risk-profiler with historical trends.
"""
# ruff: noqa: E402
import os
import sys
from pathlib import Path
from typing import Tuple

sys.path.insert(
    0, str(Path(__file__).resolve().parent.parent)
)  # Add project root to path


# For testing only - patch the check_security_policy function
def mock_check_function(*args, **kwargs) -> Tuple[bool, float, list]:
    """Mock function for security checks to allow testing."""
    return True, 1.0, []


import src.dependency_risk_profiler.scorecard.branch_protection
import src.dependency_risk_profiler.scorecard.dependency_update
import src.dependency_risk_profiler.scorecard.security_policy
import src.dependency_risk_profiler.scorecard.signed_commits

# Add the mock functions to avoid errors during testing
src.dependency_risk_profiler.scorecard.security_policy.check_security_policy = (
    mock_check_function
)
src.dependency_risk_profiler.scorecard.dependency_update.check_dependency_update_tools = (
    mock_check_function
)
src.dependency_risk_profiler.scorecard.signed_commits.check_signed_commits = (
    mock_check_function
)
src.dependency_risk_profiler.scorecard.branch_protection.check_branch_protection = (
    mock_check_function
)

from src.dependency_risk_profiler import (
    analyze_historical_trends,
    generate_trend_visualization,
    save_historical_profile,
)
from src.dependency_risk_profiler.analyzers.base import BaseAnalyzer

# Continue with imports after monkey patching
from src.dependency_risk_profiler.parsers.base import BaseParser
from src.dependency_risk_profiler.scoring.risk_scorer import RiskScorer


def test_trend_analysis():
    """Test the historical trends analysis functionality."""
    # Use the requirements.txt from the examples directory
    manifest_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "requirements.txt")
    )

    # Parse the manifest
    parser = BaseParser.get_parser_for_file(manifest_path)
    if not parser:
        print(f"Unsupported manifest file: {manifest_path}")
        return

    dependencies = parser.parse()
    if not dependencies:
        print(f"No dependencies found in {manifest_path}")
        return

    print(f"Found {len(dependencies)} dependencies")

    # Analyze dependencies
    ecosystem = "python"
    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(ecosystem)
    if not analyzer:
        print(f"Unsupported ecosystem: {ecosystem}")
        return

    dependencies = analyzer.analyze(dependencies)

    # Score dependencies
    scorer = RiskScorer()
    profile = scorer.create_project_profile(manifest_path, ecosystem, dependencies)

    # Save to historical database
    history_path = save_historical_profile(profile)
    print(f"Profile saved to: {history_path}")

    # Analyze trends
    trends = analyze_historical_trends(manifest_path)
    if "error" in trends:
        print(f"Error: {trends['error']}")
        return

    # Print trend summary
    print("\nHistorical Trend Analysis:")

    # Overall risk summary
    avg_risk = trends["average_risk_over_time"]
    print(f"  Average Risk Score: {avg_risk['average']:.2f}/5.0 ({avg_risk['trend']})")

    # Print stats
    print(
        f"  Period analyzed: {trends['analyzed_period']['start']} to {trends['analyzed_period']['end']}"
    )
    print(f"  Scans analyzed: {trends['analyzed_period']['scans_analyzed']}")

    # Generate visualization data
    for viz_type in ["overall", "distribution", "dependencies", "security"]:
        viz_data = generate_trend_visualization(manifest_path, viz_type)
        if "error" not in viz_data:
            # Save visualization data
            output_file = f"{viz_type}_trends.json"
            with open(output_file, "w") as f:
                import json

                json.dump(viz_data, f, indent=2)
            print(f"Visualization data saved to: {output_file}")


if __name__ == "__main__":
    test_trend_analysis()
