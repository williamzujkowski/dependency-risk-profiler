"""Security policy detection module for dependencies."""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import DependencyMetadata, SecurityMetrics

logger = logging.getLogger(__name__)


def check_security_file_existence(repo_dir: str) -> Dict[str, bool]:
    """Check for the existence of security policy files in a repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of security file checks.
    """
    result = {}

    try:
        repo_path = Path(repo_dir)

        # Common security policy file locations
        security_file_paths = [
            "SECURITY.md",
            ".github/SECURITY.md",
            "docs/SECURITY.md",
            "security.md",
            ".github/security.md",
            "docs/security.md",
            "SECURITY.txt",
            ".github/SECURITY.txt",
            "docs/SECURITY.txt",
            "security.txt",
            ".github/security.txt",
            "docs/security.txt",
            "security/README.md",
        ]

        # Check if any security file exists
        has_security_file = any(
            repo_path.joinpath(path).exists() for path in security_file_paths
        )
        result["has_security_file"] = has_security_file

        # Find the actual file if it exists
        if has_security_file:
            for path in security_file_paths:
                file_path = repo_path.joinpath(path)
                if file_path.exists():
                    result["security_file_path"] = str(file_path)
                    break

    except Exception as e:
        logger.error(f"Error checking security file existence: {e}")

    return result


def analyze_security_file_content(file_path: str) -> Dict[str, bool]:
    """Analyze the content of a security policy file.

    Args:
        file_path: Path to the security policy file.

    Returns:
        Dictionary with security policy content analysis results.
    """
    result = {
        "has_vulnerability_reporting": False,
        "has_supported_versions": False,
        "has_security_update_process": False,
        "has_private_reporting": False,
        "has_pgp_key": False,
        "policy_quality_score": 0.0,
    }

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().lower()

            # Check for vulnerability reporting instructions
            vulnerability_patterns = [
                r"reporting\s+a\s+vulnerabilit(y|ies)",
                r"vulnerabilit(y|ies)\s+report",
                r"security\s+vulnerabilit(y|ies)",
                r"disclos(e|ing|ure)\s+vulnerabilit(y|ies)",
                r"report\s+security\s+issue",
            ]
            result["has_vulnerability_reporting"] = any(
                re.search(pattern, content) for pattern in vulnerability_patterns
            )

            # Check for supported versions information
            supported_versions_patterns = [
                r"supported\s+versions",
                r"version\s+support",
                r"security\s+support",
                r"supported\s+releases",
            ]
            result["has_supported_versions"] = any(
                re.search(pattern, content) for pattern in supported_versions_patterns
            )

            # Check for security update process
            update_patterns = [
                r"security\s+updates",
                r"update\s+process",
                r"patch(ing)?\s+process",
                r"fix\s+timeline",
                r"release\s+cycle",
            ]
            result["has_security_update_process"] = any(
                re.search(pattern, content) for pattern in update_patterns
            )

            # Check for private reporting (email, form, etc.)
            private_reporting_patterns = [
                r"do\s+not\s+(create|open|submit).*?(public|github)\s+(issue|pull)",
                r"email.*?security",
                r"privately\s+report",
                r"responsible\s+disclosure",
                r"security@",
                r"hackerone",
                r"bugcrowd",
                r"private\s+report",
            ]
            result["has_private_reporting"] = any(
                re.search(pattern, content) for pattern in private_reporting_patterns
            )

            # Check for PGP key for encrypted reports
            pgp_patterns = [
                r"pgp\s+key",
                r"gpg\s+key",
                r"encryption\s+key",
                r"public\s+key",
                r"-----BEGIN PGP PUBLIC KEY BLOCK-----",
            ]
            result["has_pgp_key"] = any(
                re.search(pattern, content) for pattern in pgp_patterns
            )

            # Calculate a simple quality score based on completeness
            policy_elements = [
                result["has_vulnerability_reporting"],
                result["has_supported_versions"],
                result["has_security_update_process"],
                result["has_private_reporting"],
                result["has_pgp_key"],
            ]
            result["policy_quality_score"] = sum(
                1 for element in policy_elements if element
            ) / len(policy_elements)

    except Exception as e:
        logger.error(f"Error analyzing security file content: {e}")

    return result


def check_other_security_indicators(repo_dir: str) -> Dict[str, bool]:
    """Check for other security indicators in the repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with other security indicator check results.
    """
    result = {}

    try:
        repo_path = Path(repo_dir)

        # Check for security workflows (GitHub Actions, etc.)
        github_workflow_dir = repo_path / ".github" / "workflows"
        if github_workflow_dir.exists() and github_workflow_dir.is_dir():
            security_workflows = []
            for workflow_file in github_workflow_dir.glob("*.yml"):
                with open(workflow_file, "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    if any(
                        term in content
                        for term in [
                            "security",
                            "codeql",
                            "sast",
                            "vulnerability",
                            "snyk",
                            "dependabot",
                        ]
                    ):
                        security_workflows.append(workflow_file.name)

            result["has_security_workflows"] = len(security_workflows) > 0
            if security_workflows:
                result["security_workflow_count"] = len(security_workflows)
                result["security_workflows"] = security_workflows
        else:
            result["has_security_workflows"] = False

        # Check for security tools configuration files
        security_tool_configs = [
            ".snyk",
            ".dependabot/config.yml",
            ".github/dependabot.yml",
            ".github/dependabot.yaml",
            "codecov.yml",
            ".codeclimate.yml",
            ".coveralls.yml",
            ".sonarcloud.properties",
        ]

        security_tools = []
        for config in security_tool_configs:
            if repo_path.joinpath(config).exists():
                security_tools.append(config)

        result["has_security_tools"] = len(security_tools) > 0
        if security_tools:
            result["security_tool_count"] = len(security_tools)
            result["security_tools"] = security_tools

        # Check for encrypted secrets in .github directory
        github_dir = repo_path / ".github"
        if github_dir.exists() and github_dir.is_dir():
            if (github_dir / "secrets").exists() or (
                github_dir / "settings.yml"
            ).exists():
                result["has_github_secrets_config"] = True
            else:
                result["has_github_secrets_config"] = False
        else:
            result["has_github_secrets_config"] = False

    except Exception as e:
        logger.error(f"Error checking other security indicators: {e}")

    return result


def calculate_security_policy_score(
    file_existence: Dict[str, bool],
    file_content: Optional[Dict[str, bool]] = None,
    other_indicators: Optional[Dict[str, bool]] = None,
) -> float:
    """Calculate an overall security policy score.

    Args:
        file_existence: Results from check_security_file_existence.
        file_content: Optional results from analyze_security_file_content.
        other_indicators: Optional results from check_other_security_indicators.

    Returns:
        Security policy score between 0.0 (no security policy) and 1.0 (comprehensive security policy).
    """
    # Initialize with a base score
    score = 0.0

    # Having a security policy file is the most important factor
    if file_existence.get("has_security_file", False):
        score += 0.5

        # If we have content analysis, factor that in
        if file_content:
            # Quality score already normalized to 0-1 range
            content_quality = file_content.get("policy_quality_score", 0)
            score += content_quality * 0.3

    # Other security indicators provide additional confidence
    if other_indicators:
        other_score = 0.0

        if other_indicators.get("has_security_workflows", False):
            other_score += 0.1

        if other_indicators.get("has_security_tools", False):
            other_score += 0.07

        if other_indicators.get("has_github_secrets_config", False):
            other_score += 0.03

        score += other_score

    # Ensure score is within 0-1 range
    return min(1.0, max(0.0, score))


def identify_security_policy_issues(
    file_existence: Dict[str, bool], file_content: Optional[Dict[str, bool]] = None
) -> List[str]:
    """Identify issues with the security policy.

    Args:
        file_existence: Results from check_security_file_existence.
        file_content: Optional results from analyze_security_file_content.

    Returns:
        List of security policy issues.
    """
    issues = []

    if not file_existence.get("has_security_file", False):
        issues.append("No security policy file found")
        return issues

    if file_content:
        if not file_content.get("has_vulnerability_reporting", False):
            issues.append("Security policy lacks vulnerability reporting instructions")

        if not file_content.get("has_supported_versions", False):
            issues.append("Security policy does not specify supported versions")

        if not file_content.get("has_security_update_process", False):
            issues.append(
                "Security policy lacks information about the security update process"
            )

        if not file_content.get("has_private_reporting", False):
            issues.append(
                "Security policy does not provide private vulnerability reporting instructions"
            )

    return issues


def check_security_policy(
    dependency: DependencyMetadata, repo_dir: Optional[str] = None
) -> Tuple[bool, float, List[str]]:
    """Check if a dependency has a security policy.

    Args:
        dependency: Dependency metadata.
        repo_dir: Optional path to cloned repository.

    Returns:
        Tuple of (has_security_policy, security_policy_score, list of issues).
    """
    has_security_policy = False
    security_policy_score = 0.0
    issues = []

    if repo_dir:
        try:
            # Check for security policy file existence
            file_existence = check_security_file_existence(repo_dir)

            # Initialize security metrics if not already present
            if dependency.security_metrics is None:
                dependency.security_metrics = SecurityMetrics()

            if file_existence.get("has_security_file", False):
                has_security_policy = True

                # Get the security file path if found
                security_file_path = file_existence.get("security_file_path")

                # Analyze content if we found a file
                file_content = None
                if security_file_path:
                    file_content = analyze_security_file_content(security_file_path)

                # Check for other security indicators
                other_indicators = check_other_security_indicators(repo_dir)

                # Calculate security policy score
                security_policy_score = calculate_security_policy_score(
                    file_existence, file_content, other_indicators
                )

                # Identify issues
                issues = identify_security_policy_issues(file_existence, file_content)
            else:
                issues.append("No security policy file found")

            # Update dependency metadata
            dependency.security_metrics.has_security_policy = has_security_policy

            # Log results
            logger.info(
                f"Security policy check for {dependency.name}: {'Found' if has_security_policy else 'Not found'}"
            )
            logger.info(
                f"Security policy score for {dependency.name}: {security_policy_score:.2f}"
            )
            for issue in issues:
                logger.info(f"Security policy issue for {dependency.name}: {issue}")

        except Exception as e:
            logger.error(f"Error checking security policy: {e}")
            issues.append(f"Error checking security policy: {str(e)}")
    else:
        issues.append(
            "No repository information available for security policy analysis"
        )

    return has_security_policy, security_policy_score, issues
