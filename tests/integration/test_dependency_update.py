#!/usr/bin/env python3
"""Test script for dependency update tools detection."""
import logging
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# Add the parent directory to the path to make imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from src.dependency_risk_profiler.models import DependencyMetadata, SecurityMetrics
from src.dependency_risk_profiler.scorecard.dependency_update import (
    check_dependency_update_tools,
)
from src.dependency_risk_profiler.scoring.risk_scorer import RiskScorer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_test_repository_with_dependabot():
    """Create a temporary repository with Dependabot configuration."""
    repo_dir = tempfile.mkdtemp(prefix="dependency-update-test-")
    logger.info(f"Created test repository at {repo_dir}")

    # Create directory structure
    github_dir = Path(repo_dir) / ".github"
    github_dir.mkdir(exist_ok=True)

    # Create a Dependabot configuration file
    dependabot_content = """
# Dependabot configuration file
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
"""

    dependabot_path = github_dir / "dependabot.yml"
    with open(dependabot_path, "w") as f:
        f.write(dependabot_content)

    return repo_dir


def create_test_repository_with_renovate():
    """Create a temporary repository with Renovate configuration."""
    repo_dir = tempfile.mkdtemp(prefix="dependency-update-test-")
    logger.info(f"Created test repository at {repo_dir}")

    # Create a Renovate configuration file
    renovate_content = """{
  "extends": [
    "config:base"
  ],
  "packageRules": [
    {
      "matchPackagePatterns": ["^eslint"],
      "groupName": "eslint packages"
    },
    {
      "matchManagers": ["npm", "pip"],
      "enabled": true
    }
  ]
}"""

    renovate_path = Path(repo_dir) / "renovate.json"
    with open(renovate_path, "w") as f:
        f.write(renovate_content)

    return repo_dir


def create_test_repository_without_update_tools():
    """Create a temporary repository without update tools configuration."""
    repo_dir = tempfile.mkdtemp(prefix="dependency-update-test-")
    logger.info(f"Created test repository at {repo_dir}")

    # Just create a README file
    readme_path = Path(repo_dir) / "README.md"
    with open(readme_path, "w") as f:
        f.write(
            "# Test Repository\n\nThis repository does not use dependency update tools."
        )

    return repo_dir


def test_dependency_update_tools_detection():
    """Test the dependency update tools detection functionality."""
    logger.info("Testing dependency update tools detection...")

    # Test with Dependabot
    test_with_dependabot()

    # Test with Renovate
    test_with_renovate()

    # Test without update tools
    test_without_update_tools()


def test_with_dependabot():
    """Test the case with Dependabot configuration."""
    logger.info("\n=== TESTING WITH DEPENDABOT ===")

    # Create a test repository with Dependabot
    repo_dir = create_test_repository_with_dependabot()

    # Create a mock dependency
    dependency = DependencyMetadata(
        name="dependabot-package",
        installed_version="1.0.0",
        latest_version="1.1.0",
        last_updated=datetime.now(),
        repository_url="https://github.com/example/dependabot-package",
        security_metrics=SecurityMetrics(),
    )

    # Run the dependency update tools check
    has_update_tools, update_tools_score, issues = check_dependency_update_tools(
        dependency, repo_dir
    )

    # Make sure the dependency's security metrics are properly updated
    # This is normally done by the check_dependency_update_tools function
    # but we need to be explicit here for testing
    if dependency.security_metrics.has_dependency_update_tools is None:
        dependency.security_metrics.has_dependency_update_tools = has_update_tools

    # Print results
    logger.info(f"Has dependency update tools: {has_update_tools}")
    logger.info(f"Update tools score: {update_tools_score}")
    logger.info(f"Issues: {issues}")
    logger.info(
        f"Tools found: {dependency.additional_info.get('dependency_update_tools', 'None')}"
    )

    # Test the risk scorer integration
    logger.info("Testing risk scorer integration...")

    # Create a risk scorer
    scorer = RiskScorer()

    # Score the dependency
    score_result = scorer.score_dependency(dependency)

    # Print scores
    logger.info(
        f"Dependency update score in risk model: {score_result.dependency_update_score}"
    )
    logger.info(f"Total risk score: {score_result.total_score}")
    logger.info(f"Risk level: {score_result.risk_level}")
    logger.info(f"Risk factors: {score_result.factors}")


def test_with_renovate():
    """Test the case with Renovate configuration."""
    logger.info("\n=== TESTING WITH RENOVATE ===")

    # Create a test repository with Renovate
    repo_dir = create_test_repository_with_renovate()

    # Create a mock dependency
    dependency = DependencyMetadata(
        name="renovate-package",
        installed_version="1.0.0",
        latest_version="1.1.0",
        last_updated=datetime.now(),
        repository_url="https://github.com/example/renovate-package",
        security_metrics=SecurityMetrics(),
    )

    # Run the dependency update tools check
    has_update_tools, update_tools_score, issues = check_dependency_update_tools(
        dependency, repo_dir
    )

    # Make sure the dependency's security metrics are properly updated
    if dependency.security_metrics.has_dependency_update_tools is None:
        dependency.security_metrics.has_dependency_update_tools = has_update_tools

    # Print results
    logger.info(f"Has dependency update tools: {has_update_tools}")
    logger.info(f"Update tools score: {update_tools_score}")
    logger.info(f"Issues: {issues}")
    logger.info(
        f"Tools found: {dependency.additional_info.get('dependency_update_tools', 'None')}"
    )

    # Test the risk scorer integration
    logger.info("Testing risk scorer integration...")

    # Create a risk scorer
    scorer = RiskScorer()

    # Score the dependency
    score_result = scorer.score_dependency(dependency)

    # Print scores
    logger.info(
        f"Dependency update score in risk model: {score_result.dependency_update_score}"
    )
    logger.info(f"Total risk score: {score_result.total_score}")
    logger.info(f"Risk level: {score_result.risk_level}")
    logger.info(f"Risk factors: {score_result.factors}")


def test_without_update_tools():
    """Test the case without dependency update tools."""
    logger.info("\n=== TESTING WITHOUT UPDATE TOOLS ===")

    # Create a test repository without update tools
    repo_dir = create_test_repository_without_update_tools()

    # Create a mock dependency
    dependency = DependencyMetadata(
        name="no-update-tools-package",
        installed_version="1.0.0",
        latest_version="1.1.0",
        last_updated=datetime.now(),
        repository_url="https://github.com/example/no-update-tools-package",
        security_metrics=SecurityMetrics(),
    )

    # Run the dependency update tools check
    has_update_tools, update_tools_score, issues = check_dependency_update_tools(
        dependency, repo_dir
    )

    # Make sure the dependency's security metrics are properly updated
    if dependency.security_metrics.has_dependency_update_tools is None:
        dependency.security_metrics.has_dependency_update_tools = has_update_tools

    # Print results
    logger.info(f"Has dependency update tools: {has_update_tools}")
    logger.info(f"Update tools score: {update_tools_score}")
    logger.info(f"Issues: {issues}")

    # Test the risk scorer integration
    logger.info("Testing risk scorer integration...")

    # Create a risk scorer
    scorer = RiskScorer()

    # Score the dependency
    score_result = scorer.score_dependency(dependency)

    # Print scores
    logger.info(
        f"Dependency update score in risk model: {score_result.dependency_update_score}"
    )
    logger.info(f"Total risk score: {score_result.total_score}")
    logger.info(f"Risk level: {score_result.risk_level}")
    logger.info(f"Risk factors: {score_result.factors}")


if __name__ == "__main__":
    test_dependency_update_tools_detection()
