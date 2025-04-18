"""Signed commits and releases verification module for dependencies."""

import logging
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import DependencyMetadata, SecurityMetrics

logger = logging.getLogger(__name__)


def check_recent_commit_signature_status(
    repo_dir: str, commit_count: int = 20
) -> Dict[str, int]:
    """Check the signature status of recent commits.

    Args:
        repo_dir: Path to the git repository.
        commit_count: Number of recent commits to check.

    Returns:
        Dictionary with signature status counts.
    """
    result = {
        "total_commits": 0,
        "verified_commits": 0,
        "unverified_commits": 0,
        "no_signature_commits": 0,
    }

    try:
        # Get signature status for recent commits
        cmd = ["git", "log", f"-{commit_count}", "--pretty=format:%H %G?"]  # nosec B607
        output = subprocess.run(
            cmd, cwd=repo_dir, check=True, capture_output=True, text=True  # nosec B603
        ).stdout.strip()

        if not output:
            return result

        # Parse commit signature status
        for line in output.split("\n"):
            if not line.strip():
                continue

            result["total_commits"] += 1

            # Signature status codes:
            # G: valid signature with the same key as in the commit author
            # B: valid signature but with expired key
            # U: valid signature with untrusted key
            # X: invalid signature
            # Y: invalid signature, key missing
            # R: valid signature, key expired
            # E: signature can't be checked (e.g., missing key)
            # N: no signature
            try:
                _, status = line.split(" ")
                if status in [
                    "G",
                    "B",
                    "R",
                ]:  # Good signature (valid, but may be expired)
                    result["verified_commits"] += 1
                elif status in ["U", "X", "Y", "E"]:  # Bad signature
                    result["unverified_commits"] += 1
                elif status == "N":  # No signature
                    result["no_signature_commits"] += 1
                else:  # Unknown status
                    result["no_signature_commits"] += 1
            except ValueError:
                # If we can't parse the output, assume no signature
                result["no_signature_commits"] += 1

    except Exception as e:
        logger.error(f"Error checking commit signatures: {e}")

    return result


def check_release_signature_status(
    repo_dir: str, tag_count: int = 10
) -> Dict[str, int]:
    """Check the signature status of release tags.

    Args:
        repo_dir: Path to the git repository.
        tag_count: Number of recent tags to check.

    Returns:
        Dictionary with signature status counts.
    """
    result = {
        "total_tags": 0,
        "verified_tags": 0,
        "unverified_tags": 0,
        "no_signature_tags": 0,
    }

    try:
        # Get the most recent tags
        cmd = ["git", "tag", "--sort=-creatordate"]  # nosec B607
        output = subprocess.run(
            cmd, cwd=repo_dir, check=True, capture_output=True, text=True  # nosec B603
        ).stdout.strip()

        if not output:
            return result

        # Get the most recent tags
        tags = output.split("\n")[:tag_count]
        result["total_tags"] = len(tags)

        # Check signature status for each tag
        for tag in tags:
            # Check if the tag is signed
            verify_cmd = ["git", "tag", "-v", tag]  # nosec B607
            verify_result = subprocess.run(
                verify_cmd, cwd=repo_dir, capture_output=True, text=True  # nosec B603
            )

            # Parse output to determine signature status
            verify_output = verify_result.stderr + verify_result.stdout

            if "Good signature" in verify_output:
                result["verified_tags"] += 1
            elif "BAD signature" in verify_output:
                result["unverified_tags"] += 1
            elif "error: no signature found" in verify_output:
                result["no_signature_tags"] += 1
            else:
                # If we can't determine the status, assume no signature
                result["no_signature_tags"] += 1

    except Exception as e:
        logger.error(f"Error checking tag signatures: {e}")

    return result


def check_commit_signing_requirement(repo_dir: str) -> Dict[str, bool]:
    """Check if the repository requires commit signing.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with commit signing requirement status.
    """
    result = {
        "requires_commit_signing": False,
        "commit_signing_mechanism": None,
    }

    try:
        # GitHub repositories might have a CODEOWNERS file that enforces signing
        repo_path = Path(repo_dir)

        # Check for GitHub Actions workflow that enforces signed commits
        workflow_dir = repo_path / ".github" / "workflows"
        if workflow_dir.exists() and workflow_dir.is_dir():
            for workflow_file in workflow_dir.glob("*.y*ml"):
                try:
                    with open(workflow_file, "r", encoding="utf-8") as f:
                        content = f.read().lower()
                        if re.search(
                            r"signed(-|\s)commits?|commit(-|\s)sign(ing|er|ature)",
                            content,
                        ):
                            result["requires_commit_signing"] = True
                            result["commit_signing_mechanism"] = (
                                f"GitHub Actions workflow: {workflow_file.name}"
                            )
                            break
                except Exception as e:  # nosec B112
                    logger.debug(f"Error reading workflow file {workflow_file}: {e}")
                    continue

        # Check for GitHub branch protection settings in .github/settings.yml
        settings_file = repo_path / ".github" / "settings.yml"
        if settings_file.exists():
            try:
                with open(settings_file, "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    if re.search(r"require_signed_commits\s*:\s*true", content):
                        result["requires_commit_signing"] = True
                        result["commit_signing_mechanism"] = "GitHub settings.yml"
            except Exception as e:  # nosec B110
                logger.debug(f"Error reading settings file {settings_file}: {e}")
                # Continue without settings file info

    except Exception as e:
        logger.error(f"Error checking commit signing requirement: {e}")

    return result


def calculate_signed_commits_score(
    commit_signature_data: Dict[str, int],
    tag_signature_data: Dict[str, int],
    commit_signing_requirement: Dict[str, bool],
) -> float:
    """Calculate an overall signed commits score.

    Args:
        commit_signature_data: Results from check_recent_commit_signature_status.
        tag_signature_data: Results from check_release_signature_status.
        commit_signing_requirement: Results from check_commit_signing_requirement.

    Returns:
        Signed commits score between 0.0 (no signing) and 1.0 (all signed).
    """
    # Start with a base score of 0
    score = 0.0

    # Calculate commit signing score (0.0 to 0.7)
    if commit_signature_data["total_commits"] > 0:
        commit_signing_ratio = (
            commit_signature_data["verified_commits"]
            / commit_signature_data["total_commits"]
        )
        commit_signing_score = commit_signing_ratio * 0.7
        score += commit_signing_score

    # Calculate tag signing score (0.0 to 0.2)
    if tag_signature_data["total_tags"] > 0:
        tag_signing_ratio = (
            tag_signature_data["verified_tags"] / tag_signature_data["total_tags"]
        )
        tag_signing_score = tag_signing_ratio * 0.2
        score += tag_signing_score

    # Add bonus for requiring signed commits (0.0 to 0.1)
    if commit_signing_requirement["requires_commit_signing"]:
        score += 0.1

    # Ensure score is within 0-1 range
    return min(1.0, max(0.0, score))


def identify_signed_commits_issues(
    commit_signature_data: Dict[str, int],
    tag_signature_data: Dict[str, int],
    commit_signing_requirement: Dict[str, bool],
) -> List[str]:
    """Identify issues with commit signing practices.

    Args:
        commit_signature_data: Results from check_recent_commit_signature_status.
        tag_signature_data: Results from check_release_signature_status.
        commit_signing_requirement: Results from check_commit_signing_requirement.

    Returns:
        List of commit signing issues.
    """
    issues = []

    # Check commit signing issues
    if commit_signature_data["total_commits"] > 0:
        verified_ratio = (
            commit_signature_data["verified_commits"]
            / commit_signature_data["total_commits"]
        )

        if verified_ratio < 0.5:
            issues.append(
                f"Less than half of recent commits are signed ({verified_ratio:.0%})"
            )

        if commit_signature_data["unverified_commits"] > 0:
            issues.append(
                f"{commit_signature_data['unverified_commits']} recent commits have problematic signatures"
            )
    else:
        issues.append("No commit history available for signature verification")

    # Check tag signing issues
    if tag_signature_data["total_tags"] > 0:
        verified_ratio = (
            tag_signature_data["verified_tags"] / tag_signature_data["total_tags"]
        )

        if verified_ratio < 0.5:
            issues.append(
                f"Less than half of recent release tags are signed ({verified_ratio:.0%})"
            )

        if tag_signature_data["unverified_tags"] > 0:
            issues.append(
                f"{tag_signature_data['unverified_tags']} recent tags have problematic signatures"
            )
    else:
        issues.append("No release tags found for signature verification")

    # Check commit signing requirement
    if not commit_signing_requirement["requires_commit_signing"]:
        issues.append("Repository does not enforce commit signing")

    return issues


def check_signed_commits(
    dependency: DependencyMetadata, repo_dir: Optional[str] = None
) -> Tuple[bool, float, List[str]]:
    """Check if a dependency verifies commits and releases with signatures.

    Args:
        dependency: Dependency metadata.
        repo_dir: Optional path to cloned repository.

    Returns:
        Tuple of (has_signed_commits, signed_commits_score, list of issues).
    """
    has_signed_commits = False
    signed_commits_score = 0.0
    issues = []

    if repo_dir:
        try:
            # Check commit signature status
            commit_signature_data = check_recent_commit_signature_status(repo_dir)

            # Check release tag signature status
            tag_signature_data = check_release_signature_status(repo_dir)

            # Check if commit signing is required
            commit_signing_requirement = check_commit_signing_requirement(repo_dir)

            # Initialize security metrics if not already present
            if dependency.security_metrics is None:
                dependency.security_metrics = SecurityMetrics()

            # Determine if the project uses signed commits
            has_signed_commits = (
                commit_signature_data["verified_commits"] > 0
                or tag_signature_data["verified_tags"] > 0
                or commit_signing_requirement["requires_commit_signing"]
            )

            # Calculate score based on signature status
            signed_commits_score = calculate_signed_commits_score(
                commit_signature_data, tag_signature_data, commit_signing_requirement
            )

            # Identify any issues
            issues = identify_signed_commits_issues(
                commit_signature_data, tag_signature_data, commit_signing_requirement
            )

            # Store the results in additional_info
            signature_data = {}
            if commit_signature_data["total_commits"] > 0:
                commit_verified_percent = (
                    commit_signature_data["verified_commits"]
                    / commit_signature_data["total_commits"]
                    * 100
                )
                signature_data["commit_signing_rate"] = (
                    f"{commit_verified_percent:.1f}%"
                )

            if tag_signature_data["total_tags"] > 0:
                tag_verified_percent = (
                    tag_signature_data["verified_tags"]
                    / tag_signature_data["total_tags"]
                    * 100
                )
                signature_data["tag_signing_rate"] = f"{tag_verified_percent:.1f}%"

            if signature_data:
                dependency.additional_info["signature_data"] = str(signature_data)

            # Log results
            logger.info(
                f"Signed commits check for {dependency.name}: {'Found' if has_signed_commits else 'Not found'}"
            )
            if has_signed_commits:
                logger.info(
                    f"Signed commits for {dependency.name}: Verified commits: {commit_signature_data['verified_commits']}/{commit_signature_data['total_commits']}, Tags: {tag_signature_data['verified_tags']}/{tag_signature_data['total_tags']}"
                )
            logger.info(
                f"Signed commits score for {dependency.name}: {signed_commits_score:.2f}"
            )
            for issue in issues:
                logger.info(f"Signed commits issue for {dependency.name}: {issue}")

        except Exception as e:
            logger.error(f"Error checking signed commits: {e}")
            issues.append(f"Error checking signed commits: {str(e)}")
    else:
        issues.append("No repository information available for signed commits analysis")

    return has_signed_commits, signed_commits_score, issues
