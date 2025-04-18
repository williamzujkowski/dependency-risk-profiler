"""Dependency update tool detection module for dependencies."""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import DependencyMetadata, SecurityMetrics

logger = logging.getLogger(__name__)


def check_dependabot_configuration(repo_dir: str) -> Dict[str, bool]:
    """Check for Dependabot configuration in a repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of Dependabot configuration checks.
    """
    result = {
        "has_dependabot": False,
        "configuration_type": None,
        "ecosystems_covered": [],
    }

    try:
        repo_path = Path(repo_dir)

        # Common Dependabot configuration file locations
        dependabot_file_paths = [
            ".github/dependabot.yml",
            ".github/dependabot.yaml",
            ".dependabot/config.yml",
            ".dependabot/config.yaml",
        ]

        # Check if any Dependabot file exists
        for path in dependabot_file_paths:
            file_path = repo_path.joinpath(path)
            if file_path.exists():
                result["has_dependabot"] = True
                result["configuration_type"] = path.split("/")[-1]
                result["configuration_path"] = str(file_path)

                # Try to parse ecosystems
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                    # Look for ecosystem entries in YAML
                    ecosystems = re.findall(r'ecosystem:\s*["\'](.*?)["\']', content)
                    result["ecosystems_covered"] = ecosystems
                break

    except Exception as e:
        logger.error(f"Error checking Dependabot configuration: {e}")

    return result


def check_renovate_configuration(repo_dir: str) -> Dict[str, bool]:
    """Check for Renovate configuration in a repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of Renovate configuration checks.
    """
    result = {
        "has_renovate": False,
        "configuration_type": None,
        "package_managers": [],
    }

    try:
        repo_path = Path(repo_dir)

        # Common Renovate configuration file locations
        renovate_file_paths = [
            "renovate.json",
            ".github/renovate.json",
            "renovate.json5",
            ".github/renovate.json5",
            ".renovaterc.json",
            ".renovaterc",
        ]

        # Check if any Renovate file exists
        for path in renovate_file_paths:
            file_path = repo_path.joinpath(path)
            if file_path.exists():
                result["has_renovate"] = True
                result["configuration_type"] = path.split("/")[-1]
                result["configuration_path"] = str(file_path)

                # Try to parse package managers
                with open(file_path, "r", encoding="utf-8") as f:
                    import json

                    try:
                        renovate_config = json.load(f)
                        if "packageRules" in renovate_config:
                            managers = set()
                            for rule in renovate_config["packageRules"]:
                                if "matchPackagePatterns" in rule:
                                    managers.update(rule["matchPackagePatterns"])
                                if "matchManagers" in rule:
                                    managers.update(rule["matchManagers"])
                            result["package_managers"] = list(managers)
                    except json.JSONDecodeError:
                        # If not valid JSON, just record that we found something
                        pass
                break

    except Exception as e:
        logger.error(f"Error checking Renovate configuration: {e}")

    return result


def check_pyup_configuration(repo_dir: str) -> Dict[str, bool]:
    """Check for PyUp.io configuration in a repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of PyUp.io configuration checks.
    """
    result = {
        "has_pyup": False,
        "configuration_type": None,
    }

    try:
        repo_path = Path(repo_dir)

        # Common PyUp configuration file locations
        pyup_file_paths = [
            ".pyup.yml",
            ".pyup.yaml",
            "pyup.yml",
            "pyup.yaml",
        ]

        # Check if any PyUp file exists
        for path in pyup_file_paths:
            file_path = repo_path.joinpath(path)
            if file_path.exists():
                result["has_pyup"] = True
                result["configuration_type"] = path
                result["configuration_path"] = str(file_path)
                break

    except Exception as e:
        logger.error(f"Error checking PyUp configuration: {e}")

    return result


def check_github_actions_dependency_updates(repo_dir: str) -> Dict[str, bool]:
    """Check for GitHub Actions that update dependencies.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of GitHub Actions checks.
    """
    result = {
        "has_update_actions": False,
        "update_workflows": [],
    }

    try:
        repo_path = Path(repo_dir)
        workflow_dir = repo_path / ".github" / "workflows"

        if not workflow_dir.exists() or not workflow_dir.is_dir():
            return result

        # Known GitHub Actions that update dependencies
        update_action_patterns = [
            r"dependabot",
            r"renovate",
            r"update.*dependencies",
            r"dependency.*update",
            r"pyup",
            r"update.*packages",
        ]

        update_workflows = []

        # Search workflow files for dependency update actions
        for workflow_file in workflow_dir.glob("*.y*ml"):
            try:
                with open(workflow_file, "r", encoding="utf-8") as f:
                    content = f.read().lower()

                    if any(
                        re.search(pattern, content)
                        for pattern in update_action_patterns
                    ):
                        update_workflows.append(workflow_file.name)
            except Exception as e:
                logger.error(f"Error reading workflow file {workflow_file}: {e}")

        if update_workflows:
            result["has_update_actions"] = True
            result["update_workflows"] = update_workflows

    except Exception as e:
        logger.error(f"Error checking GitHub Actions for dependency updates: {e}")

    return result


def calculate_dependency_update_score(
    dependabot_results: Dict[str, bool],
    renovate_results: Dict[str, bool],
    pyup_results: Dict[str, bool],
    github_actions_results: Dict[str, bool],
) -> float:
    """Calculate an overall dependency update tools score.

    Args:
        dependabot_results: Results from check_dependabot_configuration.
        renovate_results: Results from check_renovate_configuration.
        pyup_results: Results from check_pyup_configuration.
        github_actions_results: Results from check_github_actions_dependency_updates.

    Returns:
        Dependency update tools score between 0.0 (no tools) and 1.0 (comprehensive tools).
    """
    # Start with a base score of 0
    score = 0.0

    # Dependabot is the most comprehensive solution, give it the highest weight
    if dependabot_results.get("has_dependabot", False):
        score += 0.7

        # Bonus for multiple ecosystems
        ecosystems = dependabot_results.get("ecosystems_covered", [])
        if len(ecosystems) >= 2:
            score += 0.1

    # Renovate is also very comprehensive
    if renovate_results.get("has_renovate", False):
        score += 0.7

        # Bonus for multiple package managers
        managers = renovate_results.get("package_managers", [])
        if len(managers) >= 2:
            score += 0.1

    # PyUp is more Python-specific
    if pyup_results.get("has_pyup", False):
        score += 0.5

    # GitHub Actions can be used for dependency updates too
    if github_actions_results.get("has_update_actions", False):
        score += 0.3

        # Bonus for multiple workflows
        workflows = github_actions_results.get("update_workflows", [])
        if len(workflows) >= 2:
            score += 0.1

    # Cap the score at 1.0
    return min(1.0, score)


def identify_dependency_update_issues(
    dependabot_results: Dict[str, bool],
    renovate_results: Dict[str, bool],
    pyup_results: Dict[str, bool],
    github_actions_results: Dict[str, bool],
) -> List[str]:
    """Identify issues with dependency update tools.

    Args:
        dependabot_results: Results from check_dependabot_configuration.
        renovate_results: Results from check_renovate_configuration.
        pyup_results: Results from check_pyup_configuration.
        github_actions_results: Results from check_github_actions_dependency_updates.

    Returns:
        List of dependency update tool issues.
    """
    issues = []

    # Check if any dependency update tools are present
    has_any_tool = (
        dependabot_results.get("has_dependabot", False)
        or renovate_results.get("has_renovate", False)
        or pyup_results.get("has_pyup", False)
        or github_actions_results.get("has_update_actions", False)
    )

    if not has_any_tool:
        issues.append("No dependency update tools found")
        return issues

    # Check for potential issues with Dependabot
    if dependabot_results.get("has_dependabot", False):
        if not dependabot_results.get("ecosystems_covered", []):
            issues.append("Dependabot configuration exists but no ecosystems specified")

    # Check for potential issues with Renovate
    if renovate_results.get("has_renovate", False):
        if not renovate_results.get("package_managers", []):
            issues.append(
                "Renovate configuration exists but package managers not clearly defined"
            )

    return issues


def check_dependency_update_tools(
    dependency: DependencyMetadata, repo_dir: Optional[str] = None
) -> Tuple[bool, float, List[str]]:
    """Check if a dependency uses tools to automatically update its dependencies.

    Args:
        dependency: Dependency metadata.
        repo_dir: Optional path to cloned repository.

    Returns:
        Tuple of (has_update_tools, update_tools_score, list of issues).
    """
    has_update_tools = False
    update_tools_score = 0.0
    issues = []

    if repo_dir:
        try:
            # Check for various dependency update tools
            dependabot_results = check_dependabot_configuration(repo_dir)
            renovate_results = check_renovate_configuration(repo_dir)
            pyup_results = check_pyup_configuration(repo_dir)
            github_actions_results = check_github_actions_dependency_updates(repo_dir)

            # Initialize security metrics if not already present
            if dependency.security_metrics is None:
                dependency.security_metrics = SecurityMetrics()

            # Determine if any update tools are present
            has_update_tools = (
                dependabot_results.get("has_dependabot", False)
                or renovate_results.get("has_renovate", False)
                or pyup_results.get("has_pyup", False)
                or github_actions_results.get("has_update_actions", False)
            )

            # Calculate score based on tools present
            update_tools_score = calculate_dependency_update_score(
                dependabot_results,
                renovate_results,
                pyup_results,
                github_actions_results,
            )

            # Identify any issues
            issues = identify_dependency_update_issues(
                dependabot_results,
                renovate_results,
                pyup_results,
                github_actions_results,
            )

            # Store the results in additional_info
            if has_update_tools:
                tools_found = []
                if dependabot_results.get("has_dependabot", False):
                    tools_found.append("Dependabot")
                if renovate_results.get("has_renovate", False):
                    tools_found.append("Renovate")
                if pyup_results.get("has_pyup", False):
                    tools_found.append("PyUp")
                if github_actions_results.get("has_update_actions", False):
                    tools_found.append("GitHub Actions")

                dependency.additional_info["dependency_update_tools"] = ", ".join(
                    tools_found
                )

            # Log results
            logger.info(
                f"Dependency update tools check for {dependency.name}: {'Found' if has_update_tools else 'Not found'}"
            )
            if has_update_tools:
                logger.info(
                    f"Update tools found for {dependency.name}: {dependency.additional_info.get('dependency_update_tools', '')}"
                )
            logger.info(
                f"Dependency update tools score for {dependency.name}: {update_tools_score:.2f}"
            )
            for issue in issues:
                logger.info(
                    f"Dependency update tools issue for {dependency.name}: {issue}"
                )

        except Exception as e:
            logger.error(f"Error checking dependency update tools: {e}")
            issues.append(f"Error checking dependency update tools: {str(e)}")
    else:
        issues.append(
            "No repository information available for dependency update tools analysis"
        )

    return has_update_tools, update_tools_score, issues
