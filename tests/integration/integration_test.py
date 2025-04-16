#!/usr/bin/env python3
"""Integration test for the dependency risk profiler with security enhancements."""
import logging
import shutil


import sys
import os

# Add the parent directory to the path to make imports work 
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from src.dependency_risk_profiler.models import DependencyMetadata, SecurityMetrics
from src.dependency_risk_profiler.scorecard.security_policy import check_security_policy
from src.dependency_risk_profiler.scorecard.dependency_update import check_dependency_update_tools
from src.dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from src.dependency_risk_profiler.analyzers.common import clone_repo

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_with_real_repository():
    """Test with a real open source repository that has both security policy and dependency update tools."""
    logger.info("\n=== INTEGRATION TEST WITH REAL REPOSITORY ===")
    
    # Clone a well-maintained repository
    # Choosing fastapi as an example - it has both SECURITY.md and dependabot.yml
    repo_url = "https://github.com/tiangolo/fastapi.git"
    logger.info(f"Cloning {repo_url}...")
    
    clone_result = clone_repo(repo_url)
    if not clone_result:
        logger.error("Failed to clone repository")
        return
    
    repo_dir, _ = clone_result
    logger.info(f"Repository cloned to {repo_dir}")
    
    try:
        # Create a mock dependency metadata object
        dependency = DependencyMetadata(
            name="fastapi",
            installed_version="0.104.0",
            latest_version="0.104.1",
            repository_url=repo_url,
            security_metrics=SecurityMetrics()
        )
        
        # Check for security policy
        logger.info("Checking for security policy...")
        has_security_policy, security_policy_score, security_issues = check_security_policy(dependency, repo_dir)
        
        # Check for dependency update tools
        logger.info("Checking for dependency update tools...")
        has_update_tools, update_tools_score, update_issues = check_dependency_update_tools(dependency, repo_dir)
        
        # Set the metrics explicitly for testing
        dependency.security_metrics.has_security_policy = has_security_policy
        dependency.security_metrics.has_dependency_update_tools = has_update_tools
        
        # Print results
        logger.info(f"Has security policy: {has_security_policy}")
        logger.info(f"Security policy score: {security_policy_score}")
        logger.info(f"Security policy issues: {security_issues}")
        
        logger.info(f"Has dependency update tools: {has_update_tools}")
        logger.info(f"Dependency update tools score: {update_tools_score}")
        logger.info(f"Dependency update tools issues: {update_issues}")
        logger.info(f"Update tools found: {dependency.additional_info.get('dependency_update_tools', 'None')}")
        
        # Calculate risk score
        logger.info("Calculating risk score...")
        scorer = RiskScorer()
        score_result = scorer.score_dependency(dependency)
        
        # Print score details
        logger.info(f"Security policy score in risk model: {score_result.security_policy_score}")
        logger.info(f"Dependency update score in risk model: {score_result.dependency_update_score}")
        logger.info(f"Total risk score: {score_result.total_score}")
        logger.info(f"Risk level: {score_result.risk_level}")
        logger.info(f"Risk factors: {score_result.factors}")
        
    finally:
        # Clean up
        logger.info(f"Cleaning up repository at {repo_dir}")
        shutil.rmtree(repo_dir, ignore_errors=True)

if __name__ == "__main__":
    test_with_real_repository()