"""Dependency update tool detection module for dependencies."""

import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple, TypedDict

from ..forge_paths import (
    DEPENDABOT_CONFIG_PATHS,
    RENOVATE_CONFIG_PATHS,
    WORKFLOW_GLOB,
    existing_workflow_dirs,
)
from ..models import DependencyMetadata, SecurityMetrics
from ..signals import UnmeasuredReason
from .unmeasured import no_repository_issue, read_failed_issue

logger = logging.getLogger(__name__)


class _WithConfigurationPath(TypedDict, total=False):
    """Path to the config file, recorded only once one is found."""

    configuration_path: str


class DependabotConfiguration(_WithConfigurationPath):
    """Dependabot setup discovered in a repository."""

    has_dependabot: bool
    configuration_type: Optional[str]
    ecosystems_covered: List[str]


class RenovateConfiguration(_WithConfigurationPath):
    """Renovate setup discovered in a repository.

    ``package_managers`` is ``Optional`` and the distinction is load-bearing:
    ``[]`` means the configuration parsed and named no package managers, and
    ``None`` means the configuration's contents were never established. Those
    used to be the same empty list, so a ``renovate.json`` that did not parse
    produced "Renovate configuration exists but package managers not clearly
    defined" — a finding about a file's contents, from a file nobody read
    (#236).
    """

    has_renovate: bool
    configuration_type: Optional[str]
    package_managers: Optional[List[str]]


class PyUpConfiguration(_WithConfigurationPath):
    """PyUp.io setup discovered in a repository."""

    has_pyup: bool
    configuration_type: Optional[str]


class DependencyUpdateWorkflows(TypedDict):
    """GitHub Actions workflows that look like they update dependencies."""

    has_update_actions: bool
    update_workflows: List[str]


def check_dependabot_configuration(repo_dir: str) -> DependabotConfiguration:
    """Check for Dependabot configuration in a repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of Dependabot configuration checks.

    Raises:
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result: DependabotConfiguration = {
        "has_dependabot": False,
        "configuration_type": None,
        "ecosystems_covered": [],
    }

    try:
        repo_path = Path(repo_dir)

        # Dependabot's configuration locations. Deliberately GitHub-shaped:
        # Dependabot is a GitHub service, not a directory convention, so on
        # Forgejo, Gitea or GitLab there is nowhere else it could be and its
        # absence is a real absence of that tooling, not an unmeasured signal
        # (#291). Renovate, below, is the one that generalises.
        for path in DEPENDABOT_CONFIG_PATHS:
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
        raise

    return result


def _renovate_package_managers(payload: object) -> Optional[List[str]]:
    """Read the package managers a parsed Renovate configuration names.

    Args:
        payload: Whatever ``json.load`` produced for the configuration file.

    Returns:
        The sorted package managers the configuration names, ``[]`` when it
        parsed and named none, or None when the payload is not shaped like a
        Renovate configuration at all. ``[]`` and None are different answers:
        the first is a measurement, the second is the absence of one, and
        collapsing them is what let an unread file report a finding (#236).
    """
    if not isinstance(payload, dict):
        return None

    rules = payload.get("packageRules", [])
    if not isinstance(rules, list):
        return None

    managers: Set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            return None
        for key in ("matchPackagePatterns", "matchManagers"):
            values = rule.get(key)
            if values is None:
                continue
            if not isinstance(values, list) or not all(
                isinstance(value, str) for value in values
            ):
                return None
            managers.update(values)
    return sorted(managers)


def check_renovate_configuration(repo_dir: str) -> RenovateConfiguration:
    """Check for Renovate configuration in a repository.

    The presence of a configuration file and the contents of that file are two
    different measurements taken from two different reads, and they fail
    independently. ``exists()`` establishes the first; only a successful parse
    establishes the second. When the parse fails, the presence finding stands
    and the contents stay unmeasured (``package_managers is None``) — the
    ``AdvisoryLookupState.PARTIAL`` position: what was read is a floor, what
    was not is reported as not read rather than as an absence.

    This is deliberately *not* the whole-signal-unmeasured treatment that an
    unreadable ``dependabot.yml`` gets. There, ``open()`` itself fails, which is
    the filesystem refusing us the file and is grounds to distrust the
    surrounding reads too. Here every byte was read successfully and only the
    schema is unrecognised, which says nothing about the reads either side of
    it, and discarding a confirmed "this project runs Renovate" over an
    unparsed bonus field would lose a real finding.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of Renovate configuration checks.

    Raises:
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result: RenovateConfiguration = {
        "has_renovate": False,
        "configuration_type": None,
        "package_managers": None,
    }

    try:
        repo_path = Path(repo_dir)

        # Renovate's configuration locations, in Renovate's own documented
        # search order. Renovate runs against GitHub, GitLab, Gitea and
        # Forgejo, so this one genuinely generalises — and the previous list
        # missed ``.gitlab/renovate.json`` and every ``.jsonc`` spelling, which
        # read as a repository with no update tooling at all (#291).
        for path in RENOVATE_CONFIG_PATHS:
            file_path = repo_path.joinpath(path)
            if file_path.exists():
                result["has_renovate"] = True
                result["configuration_type"] = path.split("/")[-1]
                result["configuration_path"] = str(file_path)

                # Try to parse package managers
                with open(file_path, "r", encoding="utf-8") as f:
                    try:
                        renovate_config = json.load(f)
                    except json.JSONDecodeError as e:
                        # Left as None on purpose: the contents were not
                        # established, and that is a different fact from
                        # "established, and no package managers were named".
                        # ``renovate.json5`` and ``.renovaterc`` may legally
                        # carry comments and trailing commas that this parser
                        # rejects, so this branch is a normal outcome and not
                        # only a malformed-file one.
                        logger.info(
                            "Renovate configuration %s did not parse as JSON, so "
                            "its package managers are unmeasured: %s",
                            file_path,
                            e,
                        )
                    else:
                        result["package_managers"] = _renovate_package_managers(
                            renovate_config
                        )
                break

    except Exception as e:
        logger.error(f"Error checking Renovate configuration: {e}")
        raise

    return result


def check_pyup_configuration(repo_dir: str) -> PyUpConfiguration:
    """Check for PyUp.io configuration in a repository.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of PyUp.io configuration checks.

    Raises:
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result: PyUpConfiguration = {
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
        raise

    return result


def check_github_actions_dependency_updates(
    repo_dir: str,
) -> DependencyUpdateWorkflows:
    """Check for GitHub Actions that update dependencies.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with results of GitHub Actions checks.

    Raises:
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result: DependencyUpdateWorkflows = {
        "has_update_actions": False,
        "update_workflows": [],
    }

    try:
        repo_path = Path(repo_dir)
        # Gitea Actions and Forgejo Actions read the same workflow format from
        # their own directories, so all of them are searched (#291).
        workflow_dirs = existing_workflow_dirs(repo_path)

        if not workflow_dirs:
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
        for workflow_dir in workflow_dirs:
            for workflow_file in sorted(workflow_dir.glob(WORKFLOW_GLOB)):
                try:
                    with open(workflow_file, "r", encoding="utf-8") as f:
                        content = f.read().lower()

                        if any(
                            re.search(pattern, content)
                            for pattern in update_action_patterns
                        ):
                            update_workflows.append(
                                f"{workflow_dir.parent.name}/{workflow_dir.name}/"
                                f"{workflow_file.name}"
                            )
                except Exception as e:
                    logger.error(f"Error reading workflow file {workflow_file}: {e}")
                    raise

        if update_workflows:
            result["has_update_actions"] = True
            result["update_workflows"] = update_workflows

    except Exception as e:
        logger.error(f"Error checking GitHub Actions for dependency updates: {e}")
        raise

    return result


def calculate_dependency_update_score(
    dependabot_results: DependabotConfiguration,
    renovate_results: RenovateConfiguration,
    pyup_results: PyUpConfiguration,
    github_actions_results: DependencyUpdateWorkflows,
) -> float:
    """Calculate an overall dependency update tools score.

    Args:
        dependabot_results: Results from check_dependabot_configuration.
        renovate_results: Results from check_renovate_configuration.
        pyup_results: Results from check_pyup_configuration.
        github_actions_results: Results from check_github_actions_dependency_updates.

    Returns:
        Dependency update tools score between 0.0 (no tools) and 1.0
        (comprehensive tools).
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

        # Bonus for multiple package managers. Awarded on read evidence only:
        # when the configuration did not parse, ``package_managers`` is None and
        # the score stays a floor rather than being topped up from a guess. The
        # issue list says the read did not happen, so the floor is not silent.
        managers = renovate_results.get("package_managers")
        if managers is not None and len(managers) >= 2:
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
    dependabot_results: DependabotConfiguration,
    renovate_results: RenovateConfiguration,
    pyup_results: PyUpConfiguration,
    github_actions_results: DependencyUpdateWorkflows,
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

    # Check for potential issues with Renovate. The None case is reported as a
    # failed read of the configuration, not as a finding about its contents:
    # before #236 both arrived as "package managers not clearly defined", which
    # for an unparsed file was a claim about bytes nobody had interpreted.
    if renovate_results.get("has_renovate", False):
        managers = renovate_results.get("package_managers")
        if managers is None:
            issues.append(
                "Renovate configuration found but could not be parsed, so its "
                f"package managers are unmeasured ({UnmeasuredReason.SOURCE_LOOKUP_FAILED.value})"
            )
        elif not managers:
            issues.append(
                "Renovate configuration exists but package managers not clearly defined"
            )

    return issues


def check_dependency_update_tools(
    dependency: DependencyMetadata, repo_dir: Optional[str] = None
) -> Tuple[Optional[bool], Optional[float], List[str]]:
    """Check if a dependency uses tools to automatically update its dependencies.

    Args:
        dependency: Dependency metadata.
        repo_dir: Optional path to cloned repository.

    Returns:
        Tuple of (has_update_tools, update_tools_score, list of issues). The
        first two are None when the signal could not be measured — no
        repository to read, or a read that raised — and the issue list says
        which of the two it was. ``False`` means the repository was read and
        runs no updater, which is a finding; ``None`` is not (#218).
    """
    has_update_tools: Optional[bool] = None
    update_tools_score: Optional[float] = None
    issues: List[str] = []

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
            tools_status = "Found" if has_update_tools else "Not found"
            logger.info(
                f"Dependency update tools check for {dependency.name}: {tools_status}"
            )
            if has_update_tools:
                update_tools = dependency.additional_info.get(
                    "dependency_update_tools", ""
                )
                logger.info(f"Update tools found for {dependency.name}: {update_tools}")
            logger.info(
                "Dependency update tools score for "
                f"{dependency.name}: {update_tools_score:.2f}"
            )
            for issue in issues:
                logger.info(
                    f"Dependency update tools issue for {dependency.name}: {issue}"
                )

        except Exception as e:
            # The read failed part-way through. Whatever was gathered before it
            # failed is not an answer, so nothing is returned as one.
            logger.error(f"Error checking dependency update tools: {e}")
            has_update_tools = None
            update_tools_score = None
            issues.append(read_failed_issue("Dependency update tools", e))
    else:
        issues.append(no_repository_issue("Dependency update tools"))

    return has_update_tools, update_tools_score, issues
