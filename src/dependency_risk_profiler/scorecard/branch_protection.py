"""Branch protection checking module for dependencies."""

import logging
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import DependencyMetadata, SecurityMetrics

logger = logging.getLogger(__name__)


def check_github_branch_protection_config(repo_dir: str) -> Dict[str, bool]:
    """Check for GitHub branch protection configuration.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with branch protection configuration status.
    """
    result = {
        "has_branch_protection": False,
        "protection_type": None,
        "protection_details": [],
    }

    try:
        repo_path = Path(repo_dir)

        # Check for GitHub settings.yml that configures branch protection
        settings_file = repo_path / ".github" / "settings.yml"
        if settings_file.exists():
            with open(settings_file, "r", encoding="utf-8") as f:
                content = f.read().lower()

                # Look for branch protection configuration
                if re.search(r"branches:", content) and re.search(
                    r"protection:", content
                ):
                    result["has_branch_protection"] = True
                    result["protection_type"] = "settings.yml"

                    # Extract protection details
                    protection_details = []

                    if re.search(r"required_pull_request_reviews:", content):
                        protection_details.append("Requires pull request reviews")

                    if re.search(r"required_status_checks:", content):
                        protection_details.append("Requires status checks")

                    if re.search(r"enforce_admins:", content):
                        protection_details.append("Enforced on administrators")

                    if re.search(r"required_signatures:\s*true", content):
                        protection_details.append("Requires signed commits")

                    if re.search(r"required_linear_history:\s*true", content):
                        protection_details.append("Requires linear history")

                    if re.search(r"allow_force_pushes:\s*false", content):
                        protection_details.append("Disallows force pushes")

                    if re.search(r"allow_deletions:\s*false", content):
                        protection_details.append("Disallows branch deletions")

                    result["protection_details"] = protection_details

        # Check for GitHub Actions workflow that enforces branch protection
        workflow_dir = repo_path / ".github" / "workflows"
        if (
            workflow_dir.exists()
            and workflow_dir.is_dir()
            and not result["has_branch_protection"]
        ):
            for workflow_file in workflow_dir.glob("*.y*ml"):
                try:
                    with open(workflow_file, "r", encoding="utf-8") as f:
                        content = f.read().lower()

                        # Look for workflows that enforce branch protection
                        if re.search(
                            r"branch.*protection|protect.*branch", content
                        ) and not re.search(r"check.*branch", content):
                            result["has_branch_protection"] = True
                            result["protection_type"] = (
                                f"GitHub Actions: {workflow_file.name}"
                            )
                            break
                except Exception as e:  # nosec B112
                    logger.debug(f"Error reading workflow file {workflow_file}: {e}")
                    continue

    except Exception as e:
        logger.error(f"Error checking GitHub branch protection: {e}")

    return result


def check_common_branch_protection_indicators(repo_dir: str) -> Dict[str, bool]:
    """Check for common indicators of branch protection.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with branch protection indicators.
    """
    result = {
        "has_protected_branches": False,
        "protected_branches": [],
        "has_code_owners": False,
        "has_codeql": False,
    }

    try:
        repo_path = Path(repo_dir)

        # Check for CODEOWNERS file
        codeowners_paths = [
            "CODEOWNERS",
            ".github/CODEOWNERS",
            "docs/CODEOWNERS",
        ]

        for path in codeowners_paths:
            if repo_path.joinpath(path).exists():
                result["has_code_owners"] = True
                break

        # Check for CodeQL
        codeql_paths = [
            ".github/workflows/codeql-analysis.yml",
            ".github/workflows/codeql.yml",
        ]

        for path in codeql_paths:
            if repo_path.joinpath(path).exists():
                result["has_codeql"] = True
                break

        # Try to detect protected branches from git config
        try:
            cmd = ["git", "config", "--local", "--list"]  # nosec B607
            output = subprocess.run(
                cmd,
                cwd=repo_dir,
                check=True,
                capture_output=True,
                text=True,  # nosec B603
            ).stdout.strip()

            # Look for protected branch patterns in git config
            protected_branches = set()
            for line in output.split("\n"):
                if "branch." in line and ".protected" in line:
                    match = re.match(r"branch\.(.+?)\.protected=true", line)
                    if match:
                        protected_branches.add(match.group(1))

            if protected_branches:
                result["has_protected_branches"] = True
                result["protected_branches"] = list(protected_branches)
        except Exception as e:  # nosec B110
            logger.debug(f"Error checking git config for protected branches: {e}")
            # Continue without protected branch info

    except Exception as e:
        logger.error(f"Error checking branch protection indicators: {e}")

    return result


def check_pull_request_patterns(repo_dir: str) -> Dict[str, bool]:
    """Check for pull request patterns that indicate branch protection.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with pull request pattern analysis results.
    """
    result = {
        "uses_pull_requests": False,
        "has_pull_request_template": False,
    }

    try:
        repo_path = Path(repo_dir)

        # Check for pull request template files
        pr_template_paths = [
            ".github/PULL_REQUEST_TEMPLATE.md",
            ".github/pull_request_template.md",
            "docs/pull_request_template.md",
            ".github/PULL_REQUEST_TEMPLATE/",
        ]

        for path in pr_template_paths:
            if repo_path.joinpath(path).exists():
                result["has_pull_request_template"] = True
                result["uses_pull_requests"] = True
                break

    except Exception as e:
        logger.error(f"Error checking pull request patterns: {e}")

    return result


def calculate_branch_protection_score(
    github_protection: Dict[str, bool],
    protection_indicators: Dict[str, bool],
    pr_patterns: Dict[str, bool],
) -> float:
    """Calculate an overall branch protection score.

    Args:
        github_protection: Results from check_github_branch_protection_config.
        protection_indicators: Results from check_common_branch_protection_indicators.
        pr_patterns: Results from check_pull_request_patterns.

    Returns:
        Branch protection score between 0.0 (no protection) and 1.0 (comprehensive protection).
    """
    # Start with a base score of 0
    score = 0.0

    # GitHub branch protection is the most reliable indicator (0.6)
    if github_protection["has_branch_protection"]:
        score += 0.4

        # Bonus for comprehensive protection details
        protection_details = github_protection.get("protection_details", [])
        if len(protection_details) >= 3:
            score += 0.2
        elif len(protection_details) > 0:
            score += 0.1

    # Check for other protection indicators (0.2)
    if protection_indicators["has_protected_branches"]:
        score += 0.1

    if protection_indicators["has_code_owners"]:
        score += 0.1

    if protection_indicators["has_codeql"]:
        score += 0.1

    # Check for pull request patterns (0.2)
    if pr_patterns["has_pull_request_template"]:
        score += 0.1

    # Ensure score is within 0-1 range
    return min(1.0, max(0.0, score))


def identify_branch_protection_issues(
    github_protection: Dict[str, bool],
    protection_indicators: Dict[str, bool],
    pr_patterns: Dict[str, bool],
) -> List[str]:
    """Identify issues with branch protection configuration.

    Args:
        github_protection: Results from check_github_branch_protection_config.
        protection_indicators: Results from check_common_branch_protection_indicators.
        pr_patterns: Results from check_pull_request_patterns.

    Returns:
        List of branch protection issues.
    """
    issues = []

    # Check for GitHub branch protection
    if not github_protection["has_branch_protection"]:
        issues.append("No GitHub branch protection configuration found")
    else:
        # Check for specific protection features
        protection_details = github_protection.get("protection_details", [])

        if "Requires pull request reviews" not in protection_details:
            issues.append("Branch protection does not require pull request reviews")

        if "Requires status checks" not in protection_details:
            issues.append("Branch protection does not require status checks")

        if "Disallows force pushes" not in protection_details:
            issues.append("Branch protection does not prevent force pushes")

    # Check for other protection indicators
    if not protection_indicators["has_code_owners"]:
        issues.append("No CODEOWNERS file found")

    if not protection_indicators["has_protected_branches"]:
        issues.append("No protected branches detected")

    # Check for pull request patterns
    if not pr_patterns["has_pull_request_template"]:
        issues.append("No pull request template found")

    return issues


def check_branch_protection(
    dependency: DependencyMetadata, repo_dir: Optional[str] = None
) -> Tuple[bool, float, List[str]]:
    """Check if a dependency implements branch protection.

    Args:
        dependency: Dependency metadata.
        repo_dir: Optional path to cloned repository.

    Returns:
        Tuple of (has_branch_protection, branch_protection_score, list of issues).
    """
    has_branch_protection = False
    branch_protection_score = 0.0
    issues = []

    if repo_dir:
        try:
            # Check for GitHub branch protection configuration
            github_protection = check_github_branch_protection_config(repo_dir)

            # Check for common branch protection indicators
            protection_indicators = check_common_branch_protection_indicators(repo_dir)

            # Check for pull request patterns
            pr_patterns = check_pull_request_patterns(repo_dir)

            # Initialize security metrics if not already present
            if dependency.security_metrics is None:
                dependency.security_metrics = SecurityMetrics()

            # Determine if the project uses branch protection
            has_branch_protection = (
                github_protection["has_branch_protection"]
                or protection_indicators["has_protected_branches"]
                or (
                    protection_indicators["has_code_owners"]
                    and pr_patterns["uses_pull_requests"]
                )
            )

            # Calculate score based on protection configuration
            branch_protection_score = calculate_branch_protection_score(
                github_protection, protection_indicators, pr_patterns
            )

            # Identify any issues
            issues = identify_branch_protection_issues(
                github_protection, protection_indicators, pr_patterns
            )

            # Store results in additional info
            protection_info = {}

            if github_protection["has_branch_protection"]:
                protection_info["protection_type"] = github_protection[
                    "protection_type"
                ]

            if protection_indicators["has_protected_branches"]:
                protection_info["protected_branches"] = str(
                    protection_indicators["protected_branches"]
                )

            if protection_info:
                dependency.additional_info["branch_protection"] = str(protection_info)

            # Log results
            logger.info(
                f"Branch protection check for {dependency.name}: {'Found' if has_branch_protection else 'Not found'}"
            )
            if has_branch_protection:
                if github_protection["has_branch_protection"]:
                    details_str = ", ".join(
                        github_protection.get("protection_details", [])
                    )
                    logger.info(
                        f"Branch protection details for {dependency.name}: {details_str}"
                    )

            logger.info(
                f"Branch protection score for {dependency.name}: {branch_protection_score:.2f}"
            )
            for issue in issues:
                logger.info(f"Branch protection issue for {dependency.name}: {issue}")

        except Exception as e:
            logger.error(f"Error checking branch protection: {e}")
            issues.append(f"Error checking branch protection: {str(e)}")
    else:
        issues.append(
            "No repository information available for branch protection analysis"
        )

    return has_branch_protection, branch_protection_score, issues
