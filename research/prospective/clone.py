"""Clone repositories for the prospective harvest. **Network.**

Deliberately *not* ``research.repo_arm.clone``. That module clones
``--bare --filter=blob:none``, which is right for the commit-metadata signals
it was built for and **wrong here**: six of the thirteen scored signals read
file *contents* (``SECURITY.md``, test directories, CI configuration, dependency
manifests). A bare blob-filtered clone has no working tree, so every one of
them would read absent, uniformly, for all two thousand packages.

That is the degenerate variant this study exists to escape, wearing a new
costume -- and worse than the retrospective version, because it fails *silently*
into a plausible-looking False rather than into a missing value. The repo has
made this exact mistake once already: ``has_tests`` read False for all eight
repos in the #339 evidence run, which looked like a dead signal and was
actually ``--filter=blob:none --no-checkout`` plus sparse-checkout never
materialising ``tests/``. A positive control with full clones settled it.

So: shallow but **not** blob-filtered and **not** bare. HEAD's tree is what the
file-content collectors read.

Depth needs more care than it first appears, and the positive control caught
this: ``--depth=1`` fetches **one commit**, so ``analyze_commit_frequency``'s
twelve-month window sees nothing and ``commit_frequency`` and
``contributor_count`` come back None for every repository -- two more of the
six signals dead, in the course of fixing the other four. The control failed on
exactly that, which is what it is for.

``--shallow-since`` is the right shape, since it bounds the clone by the same
window the collector reads. But it **fails hard on a repository with no commits
in the window** (``fatal: error processing shallow info: 4``) -- which is
precisely the abandoned repository this study is about. Using it alone would
make clone failure correlate with the outcome through the harness, a far worse
version of §4.1's hazard.

Hence: ``--shallow-since`` first, ``--depth=1`` on that specific failure. The
fallback case is not a degraded reading, it is the informative one -- no commits
in thirteen months means the true commit frequency is zero. Which path a
package took is recorded, so the two populations are never conflated.

The hardening from ``repo_arm.clone`` is kept in full, because §7 of the
registration turns it into a commitment: the URLs are self-declared by the
package and #388 established that nothing in this tool binds a package to its
repository, so these are attacker-controlled inputs.

- The URL is **constructed** from a charset-validated ``owner/repo`` slug, so
  the https-only transport allowlist holds by construction -- ``ext::``,
  ``file://`` and ``ssh://`` are unreachable, not filtered.
- ``--`` precedes the URL. Without it a slug beginning ``--upload-pack=`` is
  remote code execution.
- Credential helpers and ``core.askPass`` are disabled, so a repository that
  demands auth fails instead of prompting or spending an ambient token.
- ``--no-recurse-submodules``: a submodule URL is a second attacker-controlled
  transport that no allowlist here would see.
- ``ulimit -f`` caps file size and ``timeout`` caps wall-clock, so a zip-bomb
  or an endless pack is bounded.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import subprocess  # nosec B404 - git is invoked with a fixed argv, never a shell string
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

#: GitHub's own charset for owner and repository names. Anything outside it
#: never reaches ``git``, which is what makes the constructed URL safe.
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9._-]{1,100}$")

#: 512-byte blocks. 400 MB is far above any legitimate source tree at depth 1
#: and far below anything that would fill the disk.
FSIZE_BLOCKS = 800_000

TIMEOUT_SECONDS = 180

#: Thirteen months, one more than ``analyze_commit_frequency``'s twelve-month
#: window so a commit on the boundary is inside the clone.
SHALLOW_SINCE_DAYS = 396

#: ``ulimit -f`` applies to the shell and everything it execs, so the wrapper
#: has to be a shell. The argv after it is still fixed -- no interpolation.
_ULIMIT_WRAPPER = 'ulimit -f "$1" || exit 90; shift; exec "$@"'


@dataclass(frozen=True)
class CloneResult:
    """What happened to one clone attempt."""

    slug: str
    ok: bool
    path: Optional[Path]
    #: ``ok``, ``ok_shallow_fallback``, ``not_found``, ``auth``, ``timeout``,
    #: ``too_large``, ``bad_slug``, ``no_commits_in_window``, ``git_error``.
    #: Recorded per package so §4.1's uncloneable stratum can be described
    #: rather than merely counted.
    reason: str
    #: True when ``--shallow-since`` found no commits and the clone fell back to
    #: ``--depth=1``. Recorded rather than hidden: it means the repository has
    #: been silent for thirteen months, which is a *reading*, not a defect.
    shallow_fallback: bool


def clone_argv(slug: str, destination: Path, since: Optional[str]) -> List[str]:
    """Build the exact argv for one clone.

    Split out from :func:`clone_one` so the hardening is testable offline.

    Args:
        slug: ``owner/repo``, already charset-validated.
        destination: Where the checkout goes.
        since: A ``--shallow-since`` date, or None for the ``--depth=1``
            fallback taken when the repository has no commits in that window.
    """
    depth_argv = ["--depth=1"] if since is None else [f"--shallow-since={since}"]
    git_argv = [
        "git",
        "-c",
        "credential.helper=",
        "-c",
        "core.askPass=",
        "clone",
        # Shallow, but with a working tree and with blobs: see the module
        # docstring. Removing either silently degrades four signals, and
        # over-shallowing degrades two more.
        *depth_argv,
        "--no-recurse-submodules",
        "--no-tags",
        "--quiet",
        "--",
        f"https://github.com/{slug}.git",
        str(destination),
    ]
    return [
        "/bin/sh",
        "-c",
        _ULIMIT_WRAPPER,
        "sh",
        str(FSIZE_BLOCKS),
    ] + git_argv


def _classify(stderr: str, returncode: int) -> str:
    lowered = stderr.lower()
    if returncode == 90:
        return "too_large"
    if "could not read username" in lowered or "authentication failed" in lowered:
        return "auth"
    if "not found" in lowered or "does not exist" in lowered:
        return "not_found"
    if "file size limit exceeded" in lowered:
        return "too_large"
    if "error processing shallow info" in lowered:
        return "no_commits_in_window"
    return "git_error"


def _kill_group(expired: subprocess.TimeoutExpired) -> None:
    """Kill the timed-out clone's whole process group.

    ``TimeoutExpired`` does not carry the pid, but the popen object that raised
    it has already been killed by ``run``; what survives is its group. Killing
    the group is what actually enforces the cap.
    """
    pid = getattr(expired, "pid", None)
    if pid is None:
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):  # pragma: no cover - raced
        pass


def _attempt(slug: str, destination: Path, since: Optional[str]) -> tuple[bool, str]:
    """Run one clone attempt. Returns ``(ok, reason)``."""
    try:
        completed = subprocess.run(  # nosec B603 - fixed argv, no shell string
            clone_argv(slug, destination, since),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
            # The wall-clock cap does not hold without this. `git clone` spawns
            # `index-pack` as a grandchild; on timeout Python kills only the
            # direct child, and `capture_output` then blocks waiting for a pipe
            # that the surviving grandchild still holds open. Observed on a
            # repository of vendored font binaries, which sailed past a 180s
            # cap and was still running at 409s. A new session lets the whole
            # group be killed at once.
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as expired:
        _kill_group(expired)
        return False, "timeout"
    if completed.returncode != 0:
        return False, _classify(completed.stderr, completed.returncode)
    return True, "ok"


def clone_one(slug: str, root: Path, since: str) -> CloneResult:
    """Clone ``slug`` under ``root``, deep enough for the activity signals.

    A slug failing :data:`SLUG_RE` never reaches ``git``: it is rejected here,
    which is the allowlist. Returning a result rather than raising keeps one
    hostile package from ending a two-thousand-package harvest.
    """
    if not SLUG_RE.match(slug):
        return CloneResult(slug, False, None, "bad_slug", False)

    destination = root / slug.replace("/", "__")
    if destination.exists():
        shutil.rmtree(destination, ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)

    ok, reason = _attempt(slug, destination, since)
    if ok:
        return CloneResult(slug, True, destination, "ok", False)

    if reason != "no_commits_in_window":
        shutil.rmtree(destination, ignore_errors=True)
        return CloneResult(slug, False, None, reason, False)

    # No commits in the window. That is a reading about the repository, not a
    # failure to read it, so fall back rather than dropping the package into
    # the uncloneable stratum and correlating clone failure with the outcome.
    shutil.rmtree(destination, ignore_errors=True)
    ok, reason = _attempt(slug, destination, None)
    if not ok:
        shutil.rmtree(destination, ignore_errors=True)
        return CloneResult(slug, False, None, reason, True)
    return CloneResult(slug, True, destination, "ok_shallow_fallback", True)
