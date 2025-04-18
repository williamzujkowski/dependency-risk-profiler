#!/usr/bin/env python
"""Test script for historical trends analysis."""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta

# Add the parent directory to the path to make imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    ProjectRiskProfile,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.supply_chain.trends import (
    analyze_historical_trends,
    generate_trend_visualization,
    save_historical_profile,
)


def create_test_profile(manifest_path: str, date_offset: int = 0) -> ProjectRiskProfile:
    """Create a test project risk profile.

    Args:
        manifest_path: Path to the manifest file
        date_offset: Number of days to offset the scan time

    Returns:
        Test project risk profile
    """
    # Create a test profile with some dependencies
    profile = ProjectRiskProfile(
        manifest_path=manifest_path,
        ecosystem="test",
        scan_time=datetime.now() - timedelta(days=date_offset),
    )

    # Create some test dependencies with varying risk scores
    dependencies = []

    # Dependency 1: A low-risk dependency
    dep1 = DependencyMetadata(
        name="safe-package",
        installed_version="1.2.3",
        latest_version="1.2.3",
        last_updated=datetime.now() - timedelta(days=date_offset + 10),
        maintainer_count=5,
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=True,
            has_signed_commits=True,
            has_branch_protection=True,
        ),
    )

    dependencies.append(
        DependencyRiskScore(
            dependency=dep1,
            staleness_score=0.1,
            maintainer_score=0.2,
            security_policy_score=0.0,
            dependency_update_score=0.0,
            signed_commits_score=0.0,
            branch_protection_score=0.0,
            total_score=0.5,
            risk_level=RiskLevel.LOW,
            factors=["up-to-date"],
        )
    )

    # Dependency 2: A medium-risk dependency
    dep2 = DependencyMetadata(
        name="medium-package",
        installed_version="2.0.0",
        latest_version="2.1.0",
        last_updated=datetime.now() - timedelta(days=date_offset + 60),
        maintainer_count=3,
        security_metrics=SecurityMetrics(
            has_security_policy=True,
            has_dependency_update_tools=False,
            has_signed_commits=False,
            has_branch_protection=True,
        ),
    )

    dependencies.append(
        DependencyRiskScore(
            dependency=dep2,
            staleness_score=0.4,
            maintainer_score=0.3,
            security_policy_score=0.0,
            dependency_update_score=0.5,
            signed_commits_score=0.6,
            branch_protection_score=0.0,
            total_score=2.2,
            risk_level=RiskLevel.MEDIUM,
            factors=["outdated version", "missing signed commits"],
        )
    )

    # Dependency 3: A high-risk dependency
    dep3 = DependencyMetadata(
        name="risky-package",
        installed_version="0.9.0",
        latest_version="1.5.0",
        last_updated=datetime.now() - timedelta(days=date_offset + 180),
        maintainer_count=1,
        security_metrics=SecurityMetrics(
            has_security_policy=False,
            has_dependency_update_tools=False,
            has_signed_commits=False,
            has_branch_protection=False,
        ),
    )

    dependencies.append(
        DependencyRiskScore(
            dependency=dep3,
            staleness_score=0.8,
            maintainer_score=0.7,
            security_policy_score=1.0,
            dependency_update_score=1.0,
            signed_commits_score=1.0,
            branch_protection_score=1.0,
            total_score=4.0,
            risk_level=RiskLevel.HIGH,
            factors=[
                "severely outdated",
                "low maintenance",
                "missing security controls",
            ],
        )
    )

    # Add dependencies to the profile
    profile.dependencies = dependencies

    # Calculate risk counts
    profile.high_risk_dependencies = sum(
        1
        for dep in dependencies
        if dep.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    )
    profile.medium_risk_dependencies = sum(
        1 for dep in dependencies if dep.risk_level == RiskLevel.MEDIUM
    )
    profile.low_risk_dependencies = sum(
        1 for dep in dependencies if dep.risk_level == RiskLevel.LOW
    )

    # Set overall risk score
    profile.overall_risk_score = sum(dep.total_score for dep in dependencies) / len(
        dependencies
    )

    return profile


def generate_test_history(project_id: str, num_profiles: int = 5):
    """Generate test historical data.

    Args:
        project_id: Project identifier
        num_profiles: Number of historical profiles to generate
    """
    for i in range(num_profiles):
        # Create a profile with a timestamp offset
        profile = create_test_profile(project_id, date_offset=i * 30)

        # Modify some risk scores to show trends
        if i > 0:
            # Make safe-package a bit worse in each scan
            profile.dependencies[0].total_score += 0.2 * i
            if profile.dependencies[0].total_score > 2.0:
                profile.dependencies[0].risk_level = RiskLevel.MEDIUM

            # Make medium-package better in each scan
            profile.dependencies[1].total_score -= 0.2 * i
            if profile.dependencies[1].total_score < 1.0:
                profile.dependencies[1].risk_level = RiskLevel.LOW

            # Make risky-package much better in the last scan
            if i == num_profiles - 1:
                profile.dependencies[2].total_score = 1.8
                profile.dependencies[2].risk_level = RiskLevel.MEDIUM
                profile.dependencies[2].security_policy_score = 0.2
                profile.dependencies[2].dependency_update_score = 0.2
                profile.dependencies[2].signed_commits_score = 0.3
                profile.dependencies[2].branch_protection_score = 0.3
                profile.dependencies[2].factors = ["improved security"]
                profile.dependencies[
                    2
                ].dependency.security_metrics.has_security_policy = True
                profile.dependencies[
                    2
                ].dependency.security_metrics.has_dependency_update_tools = True

        # Recalculate overall profile metrics
        profile.high_risk_dependencies = sum(
            1
            for dep in profile.dependencies
            if dep.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        )
        profile.medium_risk_dependencies = sum(
            1 for dep in profile.dependencies if dep.risk_level == RiskLevel.MEDIUM
        )
        profile.low_risk_dependencies = sum(
            1 for dep in profile.dependencies if dep.risk_level == RiskLevel.LOW
        )
        profile.overall_risk_score = sum(
            dep.total_score for dep in profile.dependencies
        ) / len(profile.dependencies)

        # Save to history
        save_historical_profile(profile)

        print(f"Generated and saved profile with date offset {i * 30} days")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Test historical trends analysis")

    parser.add_argument(
        "--generate", "-g", action="store_true", help="Generate test historical data"
    )

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
        "--project-id",
        "-p",
        default="test-project/requirements.txt",
        help="Project ID to use for testing",
    )

    parser.add_argument(
        "--num-profiles",
        "-n",
        type=int,
        default=5,
        help="Number of historical profiles to generate",
    )

    parser.add_argument("--output", "-o", help="Output file for visualization data")

    args = parser.parse_args()

    if args.generate:
        print(f"Generating {args.num_profiles} test profiles for {args.project_id}")
        generate_test_history(args.project_id, args.num_profiles)

    if args.analyze:
        print(f"Analyzing trends for {args.project_id}")
        trends = analyze_historical_trends(args.project_id)

        if "error" in trends:
            print(f"Error: {trends['error']}")
        else:
            print("Trend Analysis Results:")
            print(json.dumps(trends, indent=2))

    if args.visualize:
        print(f"Generating {args.visualize} visualization for {args.project_id}")
        viz_data = generate_trend_visualization(args.project_id, args.visualize)

        if "error" in viz_data:
            print(f"Error: {viz_data['error']}")
        else:
            output_file = args.output or f"{args.visualize}_trends.json"
            with open(output_file, "w") as f:
                json.dump(viz_data, f, indent=2)

            print(f"Visualization data written to {output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
