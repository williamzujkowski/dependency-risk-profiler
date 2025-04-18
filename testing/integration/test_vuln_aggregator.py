#!/usr/bin/env python
"""Test script for vulnerability aggregator."""
import argparse
import os
import sys
from typing import Optional

# Add the parent directory to the path to make imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from dependency_risk_profiler.models import DependencyMetadata, SecurityMetrics
from dependency_risk_profiler.vulnerabilities.aggregator import (
    aggregate_vulnerability_data,
)


def test_vulnerability_aggregator_basic():
    """Basic test for the vulnerability aggregator."""
    # Create a test dependency with a safe package
    package_name = "pytest"  # Using a common package that's likely safe
    dependency = DependencyMetadata(
        name=package_name, installed_version="7.0.0", security_metrics=SecurityMetrics()
    )

    # Run the aggregator
    updated_dep, vulnerabilities = aggregate_vulnerability_data(dependency)

    # Basic assertions - mainly we're just checking it runs without errors
    assert updated_dep is not None
    assert isinstance(vulnerabilities, list)


def vuln_aggregator_test_func(
    package_name: str,
    ecosystem: str = "python",
    github_token: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
) -> None:
    """Test the vulnerability aggregator for a package.

    Args:
        package_name: Name of the package to check
        ecosystem: Package ecosystem (python, nodejs, or golang)
        github_token: GitHub API token (optional)
        nvd_api_key: NVD API key (optional)
    """
    print(f"Testing vulnerability aggregator for {package_name} ({ecosystem})")

    # Create a test dependency
    dependency = DependencyMetadata(
        name=package_name, installed_version="1.0.0", security_metrics=SecurityMetrics()
    )

    # Set up API keys
    api_keys = {}
    if github_token:
        api_keys["github"] = github_token
    if nvd_api_key:
        api_keys["nvd"] = nvd_api_key

    # Aggregate vulnerability data
    try:
        updated_dep, vulnerabilities = aggregate_vulnerability_data(
            dependency, api_keys
        )

        # Print results
        print(f"\nFound {len(vulnerabilities)} vulnerabilities for {package_name}")

        if vulnerabilities:
            print("\nVulnerability Details:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(
                    f"\n{i}. {vuln.get('id', 'Unknown ID')} ({vuln.get('source', 'Unknown Source')})"
                )
                print(
                    f"   Severity: {vuln.get('severity', 'Unknown')} (CVSS: {vuln.get('cvss_score', 'N/A')})"
                )
                print(f"   Published: {vuln.get('published', 'Unknown')}")
                print(
                    f"   Summary: {vuln.get('summary', 'No summary available')[:100]}..."
                )
                if vuln.get("fixed_versions"):
                    print(f"   Fixed in: {', '.join(vuln.get('fixed_versions', []))}")

        # Print updated security metrics
        sm = updated_dep.security_metrics
        print("\nUpdated Security Metrics:")
        print(f"  Vulnerability Count: {sm.vulnerability_count}")
        print(f"  Fixed Vulnerability Count: {sm.fixed_vulnerability_count}")
        print(f"  Max CVSS Score: {sm.max_cvss_score}")
        print(f"  Has Known Exploits: {updated_dep.has_known_exploits}")
        print(f"  Has Recent Security Update: {sm.has_recent_security_update}")

    except Exception as e:
        print(f"Error aggregating vulnerability data: {e}")


def main() -> int:
    """Main function."""
    parser = argparse.ArgumentParser(description="Test vulnerability aggregator")

    parser.add_argument("package_name", help="Name of the package to check")

    parser.add_argument(
        "--ecosystem",
        choices=["python", "nodejs", "golang"],
        default="python",
        help="Package ecosystem. Defaults to python.",
    )

    parser.add_argument("--github-token", help="GitHub API token for GitHub Advisory")

    parser.add_argument("--nvd-api-key", help="NVD API key")

    args = parser.parse_args()

    vuln_aggregator_test_func(
        args.package_name, args.ecosystem, args.github_token, args.nvd_api_key
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
