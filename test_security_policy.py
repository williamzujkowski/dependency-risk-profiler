#!/usr/bin/env python3
"""Test script for security policy detection."""
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path

from src.dependency_risk_profiler.models import DependencyMetadata, SecurityMetrics
from src.dependency_risk_profiler.scorecard.security_policy import check_security_policy
from src.dependency_risk_profiler.scoring.risk_scorer import RiskScorer

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_test_repository(with_security_policy=True):
    """Create a temporary repository with or without a security policy file."""
    repo_dir = tempfile.mkdtemp(prefix="security-policy-test-")
    logger.info(f"Created test repository at {repo_dir}")
    
    if with_security_policy:
        # Create a SECURITY.md file with good security policy content
        security_content = """# Security Policy
    
    ## Supported Versions
    
    Only the latest version is actively maintained and supported with security updates.
    
    | Version | Supported          |
    | ------- | ------------------ |
    | 1.0.x   | :white_check_mark: |
    | < 1.0   | :x:                |
    
    ## Reporting a Vulnerability
    
    Please report security vulnerabilities by emailing security@example.com.
    
    Do not report security vulnerabilities through public GitHub issues.
    
    We will acknowledge your email within 48 hours and provide a detailed response within 1 week.
    
    ## Security Updates
    
    Security updates are announced through GitHub releases and the CHANGELOG.md file.
    
    Please keep your installation up to date with the latest releases.
    """
        
        security_path = Path(repo_dir) / "SECURITY.md"
        with open(security_path, "w") as f:
            f.write(security_content)
        
        # Add some additional files to make it look like a real repo
        with open(Path(repo_dir) / "README.md", "w") as f:
            f.write("# Test Repository\n\nThis is a test repository.")
    else:
        # Create a repository without a security policy
        with open(Path(repo_dir) / "README.md", "w") as f:
            f.write("# Test Repository\n\nThis is a test repository without a security policy.")
    
    return repo_dir

def test_security_policy_detection():
    """Test the security policy detection functionality for both cases."""
    # Test with security policy
    test_with_security_policy()
    
    # Test without security policy
    test_without_security_policy()

def test_with_security_policy():
    """Test the case with a security policy."""
    logger.info("\n=== TESTING WITH SECURITY POLICY ===")
    
    # Create a test repository with security policy
    repo_dir = create_test_repository(with_security_policy=True)
    
    # Create a mock dependency
    dependency = DependencyMetadata(
        name="secure-package",
        installed_version="1.0.0",
        latest_version="1.1.0",
        last_updated=datetime.now(),
        repository_url="https://github.com/example/secure-package",
        security_metrics=SecurityMetrics()
    )
    
    # Run the security policy check
    has_security_policy, security_policy_score, issues = check_security_policy(dependency, repo_dir)
    
    # Print results
    logger.info(f"Has security policy: {has_security_policy}")
    logger.info(f"Security policy score: {security_policy_score}")
    logger.info(f"Issues: {issues}")
    
    # Test the risk scorer integration
    logger.info("Testing risk scorer integration...")
    
    # Create a risk scorer
    scorer = RiskScorer()
    
    # Score the dependency
    score_result = scorer.score_dependency(dependency)
    
    # Print scores
    logger.info(f"Security policy score in risk model: {score_result.security_policy_score}")
    logger.info(f"Total risk score: {score_result.total_score}")
    logger.info(f"Risk level: {score_result.risk_level}")
    logger.info(f"Risk factors: {score_result.factors}")
    
    # Clean up
    logger.info(f"Cleaning up test repository at {repo_dir}")
    # Uncomment to clean up: shutil.rmtree(repo_dir)

def test_without_security_policy():
    """Test the case without a security policy."""
    logger.info("\n=== TESTING WITHOUT SECURITY POLICY ===")
    
    # Create a test repository without security policy
    repo_dir = create_test_repository(with_security_policy=False)
    
    # Create a mock dependency
    dependency = DependencyMetadata(
        name="insecure-package",
        installed_version="1.0.0",
        latest_version="1.1.0",
        last_updated=datetime.now(),
        repository_url="https://github.com/example/insecure-package",
        security_metrics=SecurityMetrics()
    )
    
    # Run the security policy check
    has_security_policy, security_policy_score, issues = check_security_policy(dependency, repo_dir)
    
    # Print results
    logger.info(f"Has security policy: {has_security_policy}")
    logger.info(f"Security policy score: {security_policy_score}")
    logger.info(f"Issues: {issues}")
    
    # Test the risk scorer integration
    logger.info("Testing risk scorer integration...")
    
    # Create a risk scorer
    scorer = RiskScorer()
    
    # Score the dependency
    score_result = scorer.score_dependency(dependency)
    
    # Print scores
    logger.info(f"Security policy score in risk model: {score_result.security_policy_score}")
    logger.info(f"Total risk score: {score_result.total_score}")
    logger.info(f"Risk level: {score_result.risk_level}")
    logger.info(f"Risk factors: {score_result.factors}")
    
    # Clean up
    logger.info(f"Cleaning up test repository at {repo_dir}")
    # Uncomment to clean up: shutil.rmtree(repo_dir)

if __name__ == "__main__":
    test_security_policy_detection()