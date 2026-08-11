"""Signed commits and releases verification module for dependencies."""

import logging
import re
import subprocess  # nosec B404
from pathlib import Path
from typing import Dict, List, Optional, Tuple, TypedDict

from ..forge_paths import (
    GITHUB_APP_SETTINGS_PATHS,
    WORKFLOW_GLOB,
    existing_workflow_dirs,
    first_existing,
)
from ..models import DependencyMetadata, SecurityMetrics
from .unmeasured import no_repository_issue, read_failed_issue

logger = logging.getLogger(__name__)

# ``git log --pretty=%G?`` signature status codes, grouped by the verdict each
# one establishes. Spelled out as closed sets so that the fall-through below is
# unmistakably "a code none of these tables contains" rather than a catch-all
# that quietly answers the question (#236).
#
# Descriptions are git's own, from `git log --help`. The previous block
# misdescribed five of the eight codes -- B was written down as "valid
# signature but with expired key" when git says it is a BAD signature, and R
# as "valid signature, key expired" when git says it is a good signature made
# by a REVOKED key. Both were bucketed as verified as a result, so a bad
# signature and a revoked key each counted as evidence of signing (#389).
#
# G: good (valid) signature
# B: BAD signature
# U: good signature with unknown validity
# X: good signature that has expired
# Y: good signature made by an expired key
# R: good signature made by a REVOKED key
# E: signature cannot be checked (e.g. missing key)
# N: no signature
#
# Only G establishes a verified signature. Everything from B to E means a
# signature object exists and its validity was NOT established -- which is a
# different fact from "unsigned" and must not be collapsed into it. Whether a
# BAD signature should actively raise risk rather than abstain is a scoring
# policy question, tracked separately rather than decided here.
_COMMIT_STATUS_BUCKETS: Dict[str, str] = {
    "G": "verified_commits",
    "B": "unverified_commits",
    "R": "unverified_commits",
    "U": "unverified_commits",
    "X": "unverified_commits",
    "Y": "unverified_commits",
    "E": "unverified_commits",
    "N": "no_signature_commits",
}


# ``git tag -v`` output fragments that establish a verdict, in priority order.
# Every one of these was observed from real git rather than assumed:
#
#   annotated + signed + good key -> "Good signature from ..."           (rc 0)
#   annotated + signed + bad      -> "BAD signature from ..."            (rc 1)
#   annotated + unsigned          -> "error: no signature found"         (rc 1)
#   lightweight                   -> "cannot verify a non-tag object"    (rc 1)
#
# The last one is a measured negative on purpose: a lightweight tag points
# straight at a commit and has no object that could carry a signature, so "this
# release is not signed" is established rather than assumed. Leaving it to the
# fall-through would unmeasure every repository that tags without ``-a``, which
# is most of them — laundering a real finding into an unknown is the same defect
# pointing the other way.
#
# What is deliberately *not* here: "gpg: the signature could not be verified"
# and "fatal: cannot exec '<gpg>'". A tag whose signature gpg could not evaluate
# is not an unsigned tag, and neither is a tag we could not check because gpg is
# missing. Both used to land in ``no_signature_tags`` (#236).
_TAG_VERDICTS: Tuple[Tuple[str, str], ...] = (
    ("Good signature", "verified_tags"),
    ("BAD signature", "unverified_tags"),
    ("error: no signature found", "no_signature_tags"),
    ("cannot verify a non-tag object", "no_signature_tags"),
    # A signature gpg cannot check for want of the signer's key. This is not
    # an unsigned tag -- it is the opposite, a tag that demonstrably carries a
    # signature -- and it is the *normal* state of any fresh clone, since a
    # clone imports no public keys. Leaving it out meant every sampled tag on
    # a signed repository came back uninterpretable, the "no verdict for any
    # tag" guard fired, and the whole signal raised instead of answering.
    # Measured on pallets/flask and sigstore/cosign, both of which sign every
    # release tag (#389).
    ("Can't check signature: No public key", "unverified_tags"),
    ("Can't check signature", "unverified_tags"),
    # SSH signing (git 2.34+, and what sigstore/cosign uses). Without an
    # allowed-signers file git refuses to evaluate the signature -- which is,
    # again, a signature that exists and could not be checked, not an absent
    # one. Omitting it meant a repository that signs every tag with SSH was
    # indistinguishable from a parser failure.
    ("allowedSignersFile needs to be configured", "unverified_tags"),
)


def _classify_tag_verification(verify_output: str) -> Optional[str]:
    """Map ``git tag -v`` output to the counter it establishes.

    Args:
        verify_output: The combined stderr and stdout of ``git tag -v``.

    Returns:
        The result key the output establishes, or None when the output
        establishes nothing — a gpg that could not run, a keyring that could not
        be opened, a tag that vanished between listing and verification.
    """
    for fragment, bucket in _TAG_VERDICTS:
        if fragment in verify_output:
            return bucket
    return None


def check_recent_commit_signature_status(
    repo_dir: str, commit_count: int = 20
) -> Dict[str, int]:
    """Check the signature status of recent commits.

    ``total_commits`` counts only the lines this code could interpret, and
    ``uninterpretable_commits`` counts the rest. A line ``git`` emitted that
    does not match ``<sha> <status>`` is not a commit anyone established to be
    unsigned, so it is excluded from the numerator *and* the denominator of the
    signing rate — #74's rule for whole signals, applied per record. That leaves
    the rate a measurement over the records that were actually read, which is
    the ``AdvisoryLookupState.PARTIAL`` position: an incomplete measurement is
    still a measurement, and it is reported as incomplete.

    When *no* line could be interpreted there is nothing left to measure, so the
    read is a failure and says so.

    Args:
        repo_dir: Path to the git repository.
        commit_count: Number of recent commits to check.

    Returns:
        Dictionary with signature status counts.

    Raises:
        ValueError: If ``git`` emitted commit lines and none of them could be
            interpreted. A signing rate over zero readable records is not a
            number; the caller records the signal as unmeasured instead.
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result = {
        "total_commits": 0,
        "verified_commits": 0,
        "unverified_commits": 0,
        "no_signature_commits": 0,
        "uninterpretable_commits": 0,
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

            fields = line.split(" ")
            status = fields[1] if len(fields) == 2 else ""
            bucket = _COMMIT_STATUS_BUCKETS.get(status)
            if bucket is None:
                # Neither a status this code knows nor a line it can split. It
                # used to be counted as an unsigned commit, on the strength of
                # a comment saying "assume no signature" (#236).
                logger.debug("Uninterpretable git log signature line: %r", line)
                result["uninterpretable_commits"] += 1
                continue

            result["total_commits"] += 1
            result[bucket] += 1

        if result["total_commits"] == 0 and result["uninterpretable_commits"] > 0:
            raise ValueError(
                f"git log emitted {result['uninterpretable_commits']} commit "
                "signature line(s) and none could be interpreted"
            )

    except Exception as e:
        logger.error(f"Error checking commit signatures: {e}")
        raise

    return result


def check_release_signature_status(
    repo_dir: str, tag_count: int = 10
) -> Dict[str, int]:
    """Check the signature status of release tags.

    ``total_tags`` counts only the tags whose verification output established a
    verdict; ``uninterpretable_tags`` counts the rest, and they are excluded
    from both sides of the signing rate for the reason
    :func:`check_recent_commit_signature_status` gives. When no tag could be
    classified at all, the read is a failure rather than a verdict.

    ``git tag -v`` deliberately does **not** get ``check=True``. It exits 1 for
    a genuinely unsigned tag — verified against real git, not assumed — so
    ``check=True`` would raise on the single most common honest outcome and
    unmeasure every unsigned repository. The ``check=``-equivalent is here
    instead: an output this code cannot map to a verdict is a failed read, not
    an unsigned tag. Before #236 the trailing ``else`` answered "unsigned" for a
    missing gpg, an unopenable keyring, and a signature gpg could not evaluate.

    Args:
        repo_dir: Path to the git repository.
        tag_count: Number of recent tags to check.

    Returns:
        Dictionary with signature status counts.

    Raises:
        ValueError: If tags were listed and none of them could be classified.
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result = {
        "total_tags": 0,
        "verified_tags": 0,
        "unverified_tags": 0,
        "no_signature_tags": 0,
        "uninterpretable_tags": 0,
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

        # Check signature status for each tag
        for tag in tags:
            # Check if the tag is signed
            verify_cmd = ["git", "tag", "-v", tag]  # nosec B607
            verify_result = subprocess.run(
                verify_cmd, cwd=repo_dir, capture_output=True, text=True  # nosec B603
            )

            # Parse output to determine signature status
            verify_output = verify_result.stderr + verify_result.stdout
            bucket = _classify_tag_verification(verify_output)
            if bucket is None:
                logger.debug(
                    "git tag -v %s established no signature verdict (rc=%s): %r",
                    tag,
                    verify_result.returncode,
                    verify_output,
                )
                result["uninterpretable_tags"] += 1
                continue

            result["total_tags"] += 1
            result[bucket] += 1

        if result["total_tags"] == 0 and result["uninterpretable_tags"] > 0:
            raise ValueError(
                f"git listed {result['uninterpretable_tags']} tag(s) and "
                "verification established a verdict for none of them"
            )

    except Exception as e:
        logger.error(f"Error checking tag signatures: {e}")
        raise

    return result


class CommitSigningRequirement(TypedDict):
    """Whether a repository requires signed commits, and how it enforces it."""

    requires_commit_signing: bool
    commit_signing_mechanism: Optional[str]


def check_commit_signing_requirement(repo_dir: str) -> CommitSigningRequirement:
    """Check if the repository requires commit signing.

    Args:
        repo_dir: Path to the git repository.

    Returns:
        Dictionary with commit signing requirement status.

    Raises:
        Exception: Whatever the repository read raised. A read that failed
            is not a read that found nothing (#218), so the failure now
            propagates to the single caller, which records the signal as
            unmeasured instead of as a confident negative finding.
    """
    result: CommitSigningRequirement = {
        "requires_commit_signing": False,
        "commit_signing_mechanism": None,
    }

    try:
        # GitHub repositories might have a CODEOWNERS file that enforces signing
        repo_path = Path(repo_dir)

        # Check for an Actions-compatible workflow that enforces signed
        # commits. Gitea Actions and Forgejo Actions read the same workflow
        # format from their own directories, so all of them are searched
        # (#291).
        for workflow_dir in existing_workflow_dirs(repo_path):
            if result["requires_commit_signing"]:
                break
            for workflow_file in sorted(workflow_dir.glob(WORKFLOW_GLOB)):
                try:
                    with open(workflow_file, "r", encoding="utf-8") as f:
                        content = f.read().lower()
                        if re.search(
                            r"signed(-|\s)commits?|commit(-|\s)sign(ing|er|ature)",
                            content,
                        ):
                            result["requires_commit_signing"] = True
                            result["commit_signing_mechanism"] = (
                                "Actions workflow: "
                                f"{workflow_dir.parent.name}/{workflow_dir.name}/"
                                f"{workflow_file.name}"
                            )
                            break
                except Exception as e:
                    logger.debug(f"Error reading workflow file {workflow_file}: {e}")
                    raise

        # Check the Probot Settings app's settings.yml. Not widened past
        # GitHub: no other forge has an in-tree branch-protection convention
        # (see ``forge_paths.GITHUB_APP_SETTINGS_PATHS``).
        settings_file = first_existing(repo_path, GITHUB_APP_SETTINGS_PATHS)
        if settings_file is not None:
            try:
                with open(settings_file, "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    if re.search(r"require_signed_commits\s*:\s*true", content):
                        result["requires_commit_signing"] = True
                        result["commit_signing_mechanism"] = "GitHub settings.yml"
            except Exception as e:
                logger.debug(f"Error reading settings file {settings_file}: {e}")
                raise

    except Exception as e:
        logger.error(f"Error checking commit signing requirement: {e}")
        raise

    return result


def calculate_signed_commits_score(
    commit_signature_data: Dict[str, int],
    tag_signature_data: Dict[str, int],
    commit_signing_requirement: CommitSigningRequirement,
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
    commit_signing_requirement: CommitSigningRequirement,
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
                f"{commit_signature_data['unverified_commits']} recent commits "
                "have problematic signatures"
            )
    else:
        issues.append("No commit history available for signature verification")

    # A partial read is still a measurement, and it is reported as partial
    # rather than passed off as a total (the AdvisoryLookupState.PARTIAL
    # precedent). Silence here would put the rate above in front of a reader
    # with no way to know it was taken over fewer records than git emitted.
    uninterpretable_commits = commit_signature_data.get("uninterpretable_commits", 0)
    if uninterpretable_commits > 0:
        issues.append(
            f"{uninterpretable_commits} commit signature record(s) could not be "
            "interpreted and are excluded from the commit signing rate"
        )

    # Check tag signing issues
    if tag_signature_data["total_tags"] > 0:
        verified_ratio = (
            tag_signature_data["verified_tags"] / tag_signature_data["total_tags"]
        )

        if verified_ratio < 0.5:
            issues.append(
                "Less than half of recent release tags are signed "
                f"({verified_ratio:.0%})"
            )

        if tag_signature_data["unverified_tags"] > 0:
            issues.append(
                f"{tag_signature_data['unverified_tags']} recent tags have "
                "problematic signatures"
            )
    else:
        issues.append("No release tags found for signature verification")

    uninterpretable_tags = tag_signature_data.get("uninterpretable_tags", 0)
    if uninterpretable_tags > 0:
        issues.append(
            f"{uninterpretable_tags} release tag(s) could not be verified either "
            "way and are excluded from the tag signing rate"
        )

    # Check commit signing requirement
    if not commit_signing_requirement["requires_commit_signing"]:
        issues.append("Repository does not enforce commit signing")

    return issues


def check_signed_commits(
    dependency: DependencyMetadata, repo_dir: Optional[str] = None
) -> Tuple[Optional[bool], Optional[float], List[str]]:
    """Check if a dependency verifies commits and releases with signatures.

    Args:
        dependency: Dependency metadata.
        repo_dir: Optional path to cloned repository.

    Returns:
        Tuple of (has_signed_commits, signed_commits_score, list of issues). The
        first two are None when the signal could not be measured — no repository
        to read, or a git read that raised — and the issue list says which of the
        two it was. ``False`` means the history was read and nothing in it is
        signed, which is a finding; ``None`` is not (#218).
    """
    has_signed_commits: Optional[bool] = None
    signed_commits_score: Optional[float] = None
    issues: List[str] = []

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
            # Three-way, because "I could not check" is not "there is
            # nothing to check" (#218, #389). Previously this read only
            # `verified_commits`, and since verification runs against a local
            # keyring that a fresh clone never has, it returned a definite
            # False for every repository on earth -- including ones where
            # every commit carries a signature. A read finding that is false
            # for all inputs is worse than an abstention.
            verified = (
                commit_signature_data["verified_commits"] > 0
                or tag_signature_data["verified_tags"] > 0
                or commit_signing_requirement["requires_commit_signing"]
            )
            present_but_unverifiable = (
                commit_signature_data["unverified_commits"] > 0
                or tag_signature_data.get("unverified_tags", 0) > 0
            )
            read_and_unsigned = commit_signature_data["no_signature_commits"] > 0

            if verified:
                has_signed_commits = True
            elif present_but_unverifiable:
                # Signature objects exist and their validity was not
                # established. Asserting either answer would be a claim the
                # observation does not support.
                has_signed_commits = None
            elif read_and_unsigned:
                has_signed_commits = False
            else:
                has_signed_commits = None

            # Calculate score based on signature status
            # A score alongside an abstention would be a number nobody can
            # act on: the scorer excludes unmeasured signals from both the
            # numerator and the denominator, so the score must be absent too.
            signed_commits_score = (
                calculate_signed_commits_score(
                    commit_signature_data,
                    tag_signature_data,
                    commit_signing_requirement,
                )
                if has_signed_commits is not None
                else None
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
            signed_status = "Found" if has_signed_commits else "Not found"
            logger.info(f"Signed commits check for {dependency.name}: {signed_status}")
            if has_signed_commits:
                logger.info(
                    f"Signed commits for {dependency.name}: "
                    f"Verified commits: {commit_signature_data['verified_commits']}/"
                    f"{commit_signature_data['total_commits']}, "
                    f"Tags: {tag_signature_data['verified_tags']}/"
                    f"{tag_signature_data['total_tags']}"
                )
            # The score is None whenever the signal abstains, so it cannot be
            # formatted as a float. Logging "unmeasured" is the honest line;
            # formatting a missing value is how a crash gets introduced by a
            # correctness fix.
            logger.info(
                "Signed commits score for %s: %s",
                dependency.name,
                "unmeasured"
                if signed_commits_score is None
                else f"{signed_commits_score:.2f}",
            )
            for issue in issues:
                logger.info(f"Signed commits issue for {dependency.name}: {issue}")

        except Exception as e:
            # The read failed part-way through. Whatever was gathered before it
            # failed is not an answer, so nothing is returned as one.
            logger.error(f"Error checking signed commits: {e}")
            has_signed_commits = None
            signed_commits_score = None
            issues.append(read_failed_issue("Signed commits", e))
    else:
        issues.append(no_repository_issue("Signed commits"))

    return has_signed_commits, signed_commits_score, issues
