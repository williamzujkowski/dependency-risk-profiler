#!/usr/bin/env python3
"""Integration test for Phase 2 of OpenSSF Scorecard security enhancements."""
import logging
import shutil


import sys
import os

# Add the parent directory to the path to make imports work 
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from src.dependency_risk_profiler.models import DependencyMetadata, SecurityMetrics
from src.dependency_risk_profiler.scorecard.signed_commits import check_signed_commits
from src.dependency_risk_profiler.scorecard.branch_protection import check_branch_protection
from src.dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from src.dependency_risk_profiler.analyzers.common import clone_repo

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_with_real_repository():
    """Test with a real open source repository that has code signing and branch protection."""
    logger.info("\n=== INTEGRATION TEST WITH REAL REPOSITORY (PHASE 2) ===")
    
    # Clone a well-maintained repository
    # Choose a repository with good security practices
    repo_url = "https://github.com/expressjs/express.git"
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
            name="express",
            installed_version="4.17.1",
            latest_version="4.18.2",
            repository_url=repo_url,
            security_metrics=SecurityMetrics()
        )
        
        # Check for signed commits
        logger.info("Checking for signed commits...")
        has_signed_commits, signed_commits_score, signed_commits_issues = check_signed_commits(dependency, repo_dir)
        
        # Update security metrics
        dependency.security_metrics.has_signed_commits = has_signed_commits
        
        # Print results
        logger.info(f"Has signed commits: {has_signed_commits}")
        logger.info(f"Signed commits score: {signed_commits_score}")
        logger.info(f"Signed commits issues: {signed_commits_issues}")
        if dependency.additional_info.get('signature_data'):
            logger.info(f"Signature data: {dependency.additional_info['signature_data']}")
            
        # Check for branch protection
        logger.info("\nChecking for branch protection...")
        has_branch_protection, branch_protection_score, branch_protection_issues = check_branch_protection(dependency, repo_dir)
        
        # Update security metrics
        dependency.security_metrics.has_branch_protection = has_branch_protection
        
        # Print results
        logger.info(f"Has branch protection: {has_branch_protection}")
        logger.info(f"Branch protection score: {branch_protection_score}")
        logger.info(f"Branch protection issues: {branch_protection_issues}")
        if dependency.additional_info.get('branch_protection'):
            logger.info(f"Branch protection details: {dependency.additional_info['branch_protection']}")
        
        # Calculate risk score
        logger.info("\nCalculating risk score...")
        scorer = RiskScorer()
        score_result = scorer.score_dependency(dependency)
        
        # Print score details
        logger.info(f"Signed commits score in risk model: {score_result.signed_commits_score}")
        logger.info(f"Branch protection score in risk model: {score_result.branch_protection_score}")
        logger.info(f"Overall risk score: {score_result.total_score}")
        logger.info(f"Risk level: {score_result.risk_level}")
        logger.info(f"Risk factors: {score_result.factors}")
        
    finally:
        # Clean up
        logger.info(f"Cleaning up repository at {repo_dir}")
        shutil.rmtree(repo_dir, ignore_errors=True)

if __name__ == "__main__":
    test_with_real_repository()