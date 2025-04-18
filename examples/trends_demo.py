#!/usr/bin/env python
"""
Historical trends analysis demonstration for dependency-risk-profiler.

This example shows how to:
1. Save project risk profiles to a historical database
2. Analyze trends over time
3. Generate visualization data for trends
"""
# ruff: noqa: E402
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parent.parent)
)  # Add project root to path

# Patch the check_security_policy function for the example
import sys
from unittest.mock import MagicMock

from src.dependency_risk_profiler import (
    analyze_historical_trends,
    generate_trend_visualization,
    save_historical_profile,
)
from src.dependency_risk_profiler.analyzers.base import BaseAnalyzer
from src.dependency_risk_profiler.parsers.base import BaseParser

# Mock the security check functions to prevent errors in the examples
sys.modules["src.dependency_risk_profiler.scorecard.security_policy"] = MagicMock()
sys.modules["src.dependency_risk_profiler.scorecard.dependency_update"] = MagicMock()
sys.modules["src.dependency_risk_profiler.scorecard.signed_commits"] = MagicMock()
sys.modules["src.dependency_risk_profiler.scorecard.branch_protection"] = MagicMock()

# Create mock functions that return default values
mock_security_result = (True, 1.0, [])
sys.modules[
    "src.dependency_risk_profiler.scorecard.security_policy"
].check_security_policy = MagicMock(return_value=mock_security_result)
sys.modules[
    "src.dependency_risk_profiler.scorecard.dependency_update"
].check_dependency_update_tools = MagicMock(return_value=mock_security_result)
sys.modules[
    "src.dependency_risk_profiler.scorecard.signed_commits"
].check_signed_commits = MagicMock(return_value=mock_security_result)
sys.modules[
    "src.dependency_risk_profiler.scorecard.branch_protection"
].check_branch_protection = MagicMock(return_value=mock_security_result)
from src.dependency_risk_profiler.scoring.risk_scorer import RiskScorer


def get_ecosystem_from_manifest(manifest_path: str) -> str:
    """Determine the ecosystem from the manifest file path."""
    file_name = os.path.basename(manifest_path).lower()

    if file_name == "package-lock.json":
        return "nodejs"
    elif file_name in ["requirements.txt", "pipfile.lock"]:
        return "python"
    elif file_name == "go.mod":
        return "golang"
    else:
        return "unknown"


def analyze_and_save_profile(manifest_path: str) -> str:
    """Analyze a project and save its risk profile to history.

    Args:
        manifest_path: Path to the dependency manifest file

    Returns:
        Path to the saved history file
    """
    print(f"Analyzing {manifest_path}...")

    # Parse manifest file
    parser = BaseParser.get_parser_for_file(manifest_path)
    if not parser:
        print(f"Unsupported manifest file: {manifest_path}")
        return None

    dependencies = parser.parse()
    if not dependencies:
        print(f"No dependencies found in {manifest_path}")
        return None

    print(f"Found {len(dependencies)} dependencies")

    # Analyze dependencies
    ecosystem = get_ecosystem_from_manifest(manifest_path)
    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(ecosystem)
    if not analyzer:
        print(f"Unsupported ecosystem: {ecosystem}")
        return None

    print(f"Analyzing dependencies for {ecosystem}")
    dependencies = analyzer.analyze(dependencies)

    # Apply enhanced analyzers
    print("Applying enhanced analysis...")

    # Apply license analysis
    try:
        from src.dependency_risk_profiler.license.analyzer import analyze_license

        for name, dep in dependencies.items():
            try:
                if (
                    hasattr(analyzer, "metadata_cache")
                    and name in analyzer.metadata_cache
                ):
                    dependencies[name] = analyze_license(
                        dep, analyzer.metadata_cache[name]
                    )
            except Exception:
                print(f"No license information found for {name}")
    except ImportError as e:
        print(f"License analyzer not available: {e}")

    # Apply community metrics analysis
    try:
        from src.dependency_risk_profiler.community.analyzer import (
            analyze_community_metrics,
        )

        for name, dep in dependencies.items():
            try:
                if (
                    hasattr(analyzer, "metadata_cache")
                    and name in analyzer.metadata_cache
                ):
                    dependencies[name] = analyze_community_metrics(
                        dep, analyzer.metadata_cache[name]
                    )
                else:
                    dependencies[name] = analyze_community_metrics(dep)
            except Exception as e:
                print(f"Error analyzing community metrics for {name}: {e}")
    except ImportError as e:
        print(f"Community analyzer not available: {e}")

    # Apply security analysis - OpenSSF Scorecard-inspired metrics
    try:
        # We'll initialize security metrics without actually running the checks
        from src.dependency_risk_profiler.models import SecurityMetrics

        for name, dep in dependencies.items():
            try:
                # Initialize security metrics if not present
                if not hasattr(dep, "security_metrics") or dep.security_metrics is None:
                    dep.security_metrics = SecurityMetrics()

                # Set default values for demo purposes
                dep.security_metrics.has_security_policy = True
                dep.security_metrics.has_dependency_update_tools = True
                dep.security_metrics.has_signed_commits = True
                dep.security_metrics.has_branch_protection = True
            except Exception as e:
                print(f"Error initializing security metrics for {name}: {e}")
    except ImportError as e:
        print(f"Security metrics model not available: {e}")

    # Analyze transitive dependencies
    try:
        from src.dependency_risk_profiler.transitive.analyzer import (
            analyze_transitive_dependencies,
        )

        dependencies = analyze_transitive_dependencies(dependencies, manifest_path)
    except ImportError as e:
        print(f"Transitive dependency analyzer not available: {e}")
    except Exception as e:
        print(f"Error analyzing transitive dependencies: {e}")

    # Score dependencies
    print("Scoring dependencies...")
    scorer = RiskScorer()
    profile = scorer.create_project_profile(manifest_path, ecosystem, dependencies)

    # Save to history
    print("Saving to historical database...")
    return save_historical_profile(profile)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Historical trends analysis demo for dependency-risk-profiler"
    )

    parser.add_argument("--manifest", "-m", help="Path to the dependency manifest file")

    parser.add_argument(
        "--analyze", "-a", action="store_true", help="Analyze historical trends"
    )

    parser.add_argument(
        "--visualize",
        "-v",
        choices=["overall", "distribution", "dependencies", "security"],
        help="Generate visualization data for trends",
    )

    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=10,
        help="Maximum number of historical records to analyze",
    )

    parser.add_argument(
        "--output",
        "-o",
        help="Output file for visualization data (defaults to <type>_trends.json)",
    )

    args = parser.parse_args()

    if not args.manifest and not args.analyze and not args.visualize:
        parser.print_help()
        return 1

    # Analyze and save current profile if manifest specified
    if args.manifest:
        manifest_path = os.path.abspath(args.manifest)
        if not os.path.exists(manifest_path):
            print(f"Error: Manifest file not found: {manifest_path}")
            return 1

        history_path = analyze_and_save_profile(manifest_path)
        if history_path:
            print(f"Profile saved to: {history_path}")
        else:
            print("Failed to save profile")
            return 1

    # Analyze trends if requested
    if args.analyze:
        if not args.manifest:
            print("Error: Must specify --manifest to analyze trends")
            return 1

        print(f"Analyzing historical trends for {args.manifest}...")
        trends = analyze_historical_trends(manifest_path, args.limit)

        if "error" in trends:
            print(f"Error: {trends['error']}")
            return 1

        # Print trend summary
        print("\nHistorical Trend Analysis:")

        # Overall risk summary
        avg_risk = trends["average_risk_over_time"]
        print(
            f"  Average Risk Score: {avg_risk['average']:.2f}/5.0 ({avg_risk['trend']})"
        )

        # Improving and deteriorating dependencies
        print(f"  Improving Dependencies: {len(trends['improving_dependencies'])}")
        if trends["improving_dependencies"]:
            for dep in trends["improving_dependencies"][:3]:  # Show top 3
                print(
                    f"    - {dep['name']}: {dep['initial_score']:.1f} → {dep['current_score']:.1f} ({dep['improvement']:.1f} pts)"
                )

        print(
            f"  Deteriorating Dependencies: {len(trends['deteriorating_dependencies'])}"
        )
        if trends["deteriorating_dependencies"]:
            for dep in trends["deteriorating_dependencies"][:3]:  # Show top 3
                print(
                    f"    - {dep['name']}: {dep['initial_score']:.1f} → {dep['current_score']:.1f} ({dep['deterioration']:.1f} pts)"
                )

        # Period analyzed
        print(
            f"  Analysis Period: {trends['analyzed_period']['start']} to {trends['analyzed_period']['end']}"
        )
        print(f"  Scans Analyzed: {trends['analyzed_period']['scans_analyzed']}")

        # Velocity metrics
        if "velocity_metrics" in trends and trends["velocity_metrics"]:
            vm = trends["velocity_metrics"]
            print("\n  Dependency Velocity Metrics:")
            print(f"    New Dependencies: {vm.get('new_dependencies', 0)}")
            print(f"    Updated Dependencies: {vm.get('updated_dependencies', 0)}")
            print(f"    Removed Dependencies: {vm.get('removed_dependencies', 0)}")
            print(
                f"    Dependency Churn Rate: {vm.get('dependency_churn_rate', 0)} deps/day"
            )

    # Generate visualization if requested
    if args.visualize:
        if not args.manifest:
            print("Error: Must specify --manifest to generate visualizations")
            return 1

        print(f"Generating {args.visualize} visualization for {args.manifest}...")
        viz_data = generate_trend_visualization(
            manifest_path, args.visualize, args.limit
        )

        if "error" in viz_data:
            print(f"Error: {viz_data['error']}")
            return 1

        # Save visualization data
        output_file = args.output or f"{args.visualize}_trends.json"
        with open(output_file, "w") as f:
            json.dump(viz_data, f, indent=2)

        print(f"Visualization data saved to: {output_file}")
        print(
            "To visualize this data, you can use Chart.js, D3.js, or other visualization libraries."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
