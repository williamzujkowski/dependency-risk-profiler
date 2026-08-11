"""Stage 3: the six signals, reconstructed at T from the clone alone.

**Every value here comes from git history at the last commit before T.** No
live API is asked anything, because a live read observes the post-outcome
world — §4b's rule, and the ground on which ``signed_commits`` and
``branch_protection`` were already binned as untestable.

The file-presence signals reuse the shipped path tables from
``dependency_risk_profiler.forge_paths`` rather than restating them, so this
module cannot drift from what the tool actually looks for. The difference is
only *where* it looks: production stats a working tree, and a bare blobless
clone has none, so the same tables are matched against ``git ls-tree -r`` at
the historical commit.

**Two departures from production are forced by the as-of-T requirement and are
recorded rather than hidden.**

* ``maintained``'s score is ``commit * 0.5 + release * 0.3 + issue * 0.2``.
  §4b names commit activity as this signal's source, so the release and issue
  components are left at the neutral 0.5 the shipped function already uses for
  a component nobody measured. The arithmetic consequence is worth stating
  plainly: ``is_maintained`` becomes ``commit_score > 0.7``, i.e. roughly seven
  commits a month, or four with a rising trend. The archived flag, which §4b
  excludes as current-state, is not read at all.
* ``community_popularity`` is not computed here. See
  :data:`POPULARITY_UNMEASURED_REASON`.

**Commit counting is done once per repository, not thirteen times.** One
``git log`` over the 360-day window before T returns every commit timestamp,
and the monthly buckets and the six-month cadence are both counted from that
list in Python. Timestamps are compared as epoch integers, so no timezone
interpretation sits between git and the bucket boundaries.
"""

from __future__ import annotations

import subprocess  # nosec B404 - git is invoked with a fixed argv, never a shell string
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from dependency_risk_profiler.forge_paths import (
    CI_CONFIG_PATHS,
    CONTRIBUTING_PATHS,
    DEPENDABOT_CONFIG_PATHS,
    RENOVATE_CONFIG_PATHS,
    SECURITY_POLICY_PATHS,
)
from dependency_risk_profiler.scorecard.maintained import calculate_maintained_score

#: Why ``community_popularity`` is reported unmeasured rather than estimated.
#:
#: §5 specifies GH Archive ``WatchEvent`` cumulative to T, from 2015. That is
#: 84,000 hourly files on ``data.gharchive.org`` at roughly 79 MB each — about
#: 6.6 TB — which is not obtainable here. The one queryable public mirror
#: (ClickHouse's ``github_events``) begins 2023-01-13 and so covers 566 of the
#: 3,500 days before T, 16.2% of the window, and would understate exactly the
#: long-established repositories the signal's 100/1000/5000-star thresholds
#: are meant to separate. A truncated-window count is a proxy, and §4b drops
#: what it cannot compute rather than proxying it. A current star count is the
#: specific substitution §4b exists to forbid.
POPULARITY_UNMEASURED_REASON = (
    "gh_archive_unavailable: cumulative WatchEvent to T needs ~84,000 hourly "
    "files (~6.6 TB); the public ClickHouse mirror starts 2023-01-13, covering "
    "16.2% of the window. No current-state star count substituted (protocol 4b)."
)

#: Root-level directories production reads as evidence of a test suite.
_TEST_DIRS = ("test", "tests", "spec", "specs")

#: Root-level filename patterns production globs for tests, as
#: ``(prefix, suffix)`` pairs matched against the basename.
_TEST_FILE_PATTERNS = (("", "_test.py"), ("", "_spec.js"), ("test_", ".py"))

#: Days in each bucket of the maintained life table, and how many buckets.
_BUCKET_DAYS = 30
_BUCKETS = 12

#: The trailing window ``community_activity`` averages over, in months.
_ACTIVITY_MONTHS = 6


@dataclass(frozen=True)
class RepoSignals:
    """The repository-derived inputs for one repository, as of T."""

    slug: str
    #: The last commit whose committer date is strictly before T.
    head_at_t: Optional[str]
    has_tests: Optional[bool]
    has_ci: Optional[bool]
    has_contribution_guidelines: Optional[bool]
    has_security_policy: Optional[bool]
    has_dependency_update_tools: Optional[bool]
    #: Commits per month over the six months before T.
    commit_frequency: Optional[float]
    #: From commit activity only; see the module docstring.
    is_maintained: Optional[bool]
    #: Why nothing could be read, when nothing could.
    error: Optional[str]


def _git(repo: Path, args: Sequence[str], timeout: int = 120) -> Tuple[int, str]:
    """Run a read-only git command against a bare clone.

    Args:
        repo: The bare repository.
        args: Arguments after ``git``.
        timeout: Wall-clock ceiling in seconds.

    Returns:
        ``(returncode, stdout)``. stdout is empty on failure.
    """
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(repo.parent / ".nohome"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "TZ": "UTC",
        "LC_ALL": "C",
    }
    try:
        completed = subprocess.run(  # nosec B603, B607 - fixed argv, no shell string
            ["git", "--git-dir", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, ""
    if completed.returncode != 0:
        return completed.returncode, ""
    return 0, completed.stdout


def _tree_paths(repo: Path, commit: str) -> Optional[List[str]]:
    """List every path in the tree at ``commit``.

    Args:
        repo: The bare repository.
        commit: Commit id.

    Returns:
        Paths, or None when git could not read the tree.
    """
    code, out = _git(repo, ["ls-tree", "-r", "--name-only", commit])
    if code != 0:
        return None
    return out.splitlines()


def _has_path(paths: Sequence[str], candidates: Sequence[str]) -> bool:
    """Return whether any candidate is present as a file or a directory.

    ``git ls-tree -r`` flattens directories away, so a directory candidate such
    as ``.github/workflows`` is present exactly when some listed path starts
    with it.

    Args:
        paths: Every path in the tree.
        candidates: Paths to look for.

    Returns:
        True when at least one candidate matches.
    """
    wanted = set(candidates)
    prefixes = tuple(f"{candidate}/" for candidate in candidates)
    for path in paths:
        if path in wanted or path.startswith(prefixes):
            return True
    return False


def _has_tests(paths: Sequence[str]) -> bool:
    """Return whether the tree shows a test suite, matching production's rules.

    Production globs the repository *root* only, so this does too: a
    ``src/foo/test_x.py`` deep in the tree is not what ``check_health_indicators``
    counts, and widening the rule here would score a different signal than the
    tool ships.

    Args:
        paths: Every path in the tree.

    Returns:
        True when a root test directory or a root test file is present.
    """
    if _has_path(paths, _TEST_DIRS):
        return True
    for path in paths:
        if "/" in path:
            continue
        for prefix, suffix in _TEST_FILE_PATTERNS:
            if path.startswith(prefix) and path.endswith(suffix):
                return True
    return False


def _commit_timestamps(repo: Path, commit: str, since: datetime) -> Optional[List[int]]:
    """Return committer timestamps from ``since`` up to ``commit``.

    Args:
        repo: The bare repository.
        commit: The commit at T; nothing after it is reachable.
        since: Lower bound.

    Returns:
        Epoch seconds, or None when git could not read the log.
    """
    code, out = _git(
        repo,
        ["log", "--format=%ct", f"--since={since.isoformat()}", commit],
    )
    if code != 0:
        return None
    values: List[int] = []
    for line in out.split():
        try:
            values.append(int(line))
        except ValueError:
            continue
    return values


def _unreadable(slug: str, reason: str) -> RepoSignals:
    """Return an all-unmeasured record carrying why the clone said nothing.

    Every signal is None rather than False. A repository git could not read is
    not a repository with no tests, and #218 is the whole reason this
    distinction is typed rather than conventional.

    Args:
        slug: ``owner/repo``.
        reason: A stable reason string.

    Returns:
        The record.
    """
    return RepoSignals(
        slug=slug,
        head_at_t=None,
        has_tests=None,
        has_ci=None,
        has_contribution_guidelines=None,
        has_security_policy=None,
        has_dependency_update_tools=None,
        commit_frequency=None,
        is_maintained=None,
        error=reason,
    )


def reconstruct(repo: Path, slug: str, moment: datetime) -> RepoSignals:
    """Reconstruct one repository's signals at T.

    Args:
        repo: The bare clone.
        slug: ``owner/repo``, for the record.
        moment: T.

    Returns:
        The signals, with None wherever the clone could not answer.
    """
    code, out = _git(
        repo, ["rev-list", "-1", f"--before={moment.isoformat()}", "HEAD"]
    )
    if code != 0:
        return _unreadable(slug, "git_read_failed")
    head = out.strip()
    if not head:
        # The default branch has no commit before T: the repository was created
        # afterwards, or its history was rewritten. §10 names the second as a
        # hazard with an unmeasured rate; this counts it.
        return _unreadable(slug, "no_commit_before_T")

    paths = _tree_paths(repo, head)
    if paths is None:
        return _unreadable(slug, "ls_tree_failed")

    stamps = _commit_timestamps(
        repo, head, moment - timedelta(days=_BUCKET_DAYS * _BUCKETS)
    )
    if stamps is None:
        return _unreadable(slug, "git_log_failed")

    end = int(moment.timestamp())
    buckets: List[int] = []
    for index in range(_BUCKETS):
        upper = end - _BUCKET_DAYS * index * 86400
        lower = end - _BUCKET_DAYS * (index + 1) * 86400
        buckets.append(sum(1 for stamp in stamps if lower <= stamp < upper))

    commit_data: Dict[str, float] = {
        "average_monthly_commits": sum(buckets) / len(buckets)
    }
    recent = sum(buckets[:3]) / 3.0
    earlier = sum(buckets[3:6]) / 3.0
    commit_data["commit_trend"] = 0.0 if earlier == 0 else (recent - earlier) / earlier

    activity_floor = end - _ACTIVITY_MONTHS * _BUCKET_DAYS * 86400
    frequency = sum(1 for stamp in stamps if stamp >= activity_floor) / float(
        _ACTIVITY_MONTHS
    )
    score = calculate_maintained_score(commit_data, {}, {})

    return RepoSignals(
        slug=slug,
        head_at_t=head,
        has_tests=_has_tests(paths),
        has_ci=_has_path(paths, CI_CONFIG_PATHS),
        has_contribution_guidelines=_has_path(paths, CONTRIBUTING_PATHS),
        has_security_policy=_has_path(paths, SECURITY_POLICY_PATHS),
        has_dependency_update_tools=(
            _has_path(paths, DEPENDABOT_CONFIG_PATHS)
            or _has_path(paths, RENOVATE_CONFIG_PATHS)
        ),
        commit_frequency=frequency,
        is_maintained=score > 0.6,
        error=None,
    )
