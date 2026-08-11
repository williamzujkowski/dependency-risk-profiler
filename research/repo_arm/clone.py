"""Stage 2, second half: cloning hostile input under §10's hardening.

**These clones are hostile input and the protocol treats them as such.** The
cohort is drawn from packages some of which are abandoned or compromised, and
the repository URL comes from package metadata an attacker controls. Every
defence §10 fixes is implemented here, and each one closes a specific hole:

* **The URL is passed after a ``--`` separator.** ``git clone`` parses anything
  beginning with a dash as an option, and ``--upload-pack=<command>`` is remote
  code execution. This is the single most important line in the module.
* **The URL is rebuilt, not forwarded.** ``resolve`` validates the owner and
  repository against GitHub's own charset and this module composes
  ``https://github.com/<owner>/<repo>.git`` from the validated pair, so no byte
  of registry metadata reaches the command line. The ``--`` separator stays
  anyway: defence in depth is cheap and the reviewer asked for it by name.
* **Submodules are never initialised.** ``--no-recurse-submodules`` is explicit
  even though ``--bare`` already implies it, because the guarantee is the point.
* **``--bare``**, so no working tree is written and symlink traversal is not
  reachable.
* **Each clone is size- and time-capped.** ``RLIMIT_FSIZE`` is imposed through
  a ``sh -c`` wrapper rather than ``preexec_fn``, which the standard library
  documents as unsafe in a threaded parent — and this runs in a thread pool.
  The limit is applied by ``ulimit`` to the shell that then ``exec``s git, so
  the cap is enforced by the kernel against a git bomb rather than by a size
  check that runs after the disk is full.
* **The ambient git configuration is not read.** ``GIT_CONFIG_GLOBAL`` and
  ``GIT_CONFIG_SYSTEM`` point at ``/dev/null`` and ``credential.helper`` is set
  empty, so an ``insteadOf`` rewrite or a stored credential in the operator's
  own ``~/.gitconfig`` cannot be applied to, or leaked to, one of these hosts.
* **``GIT_TERMINAL_PROMPT=0``**, so a private repository fails immediately
  instead of blocking a worker on a username prompt forever.

**A failure is classified, never folded into a success.** §9's gate is a
resolution rate, and a rate whose denominator quietly drops the timeouts is
not one.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - git is invoked with a fixed argv, never a shell string
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

#: Wall-clock ceiling for one clone, in seconds.
CLONE_TIMEOUT_SECONDS = 300

#: Hard ceiling on any single file git writes, in 512-byte blocks as
#: ``ulimit -f`` counts them. 512 MiB: a blobless clone of even a very large
#: repository is a few tens of megabytes, so this only ever fires on something
#: pathological.
FSIZE_LIMIT_BLOCKS = 1024 * 1024

#: Clone succeeded and the bare repository is on disk.
OK = "ok"

#: The repository does not exist, or is private, which github.com reports
#: identically. Both are "nobody can read this today", which is the fact §6
#: needs, so they are one category and the raw stderr is kept.
NOT_FOUND = "not_found"

#: github.com answered, but with a block: DMCA takedown or access restriction.
BLOCKED = "blocked"

#: The clone did not finish inside :data:`CLONE_TIMEOUT_SECONDS`.
TIMEOUT = "timeout"

#: git exceeded the file-size rlimit: a git bomb, or simply enormous.
TOO_LARGE = "too_large"

#: The repository exists but has no commits.
EMPTY = "empty"

#: Anything else. Kept distinct so it can be read rather than assumed.
OTHER = "other"


@dataclass(frozen=True)
class CloneResult:
    """What happened to one repository."""

    slug: str
    status: str
    seconds: float
    #: Bytes on disk, or None when nothing was written.
    size_bytes: Optional[int]
    #: The tail of git's stderr, for the categories that need reading.
    detail: str


def clone_directory(root: Path, slug: str) -> Path:
    """Return the on-disk location for one slug.

    Args:
        root: Directory holding every clone.
        slug: ``owner/repo``.

    Returns:
        The bare repository path. An owner cannot contain ``_`` (see
        ``resolve._OWNER``), so ``owner__repo`` round-trips unambiguously.
    """
    owner, _, repo = slug.partition("/")
    return root / f"{owner}__{repo}.git"


def _classify(stderr: str, returncode: int) -> str:
    """Read git's stderr and say why the clone failed.

    Args:
        stderr: git's stderr.
        returncode: git's exit status.

    Returns:
        One of the status constants in this module.
    """
    text = stderr.lower()
    if "repository not found" in text or "not found" in text and "404" in text:
        return NOT_FOUND
    if "could not read username" in text or "authentication failed" in text:
        return NOT_FOUND
    if "access blocked" in text or "dmca" in text or "451" in text:
        return BLOCKED
    if "you appear to have cloned an empty repository" in text:
        return EMPTY
    if "file size limit exceeded" in text or returncode == -25:
        return TOO_LARGE
    if "repository not found" in text:
        return NOT_FOUND
    return OTHER


#: The shell wrapper that imposes the size cap. A constant: the limit and the
#: whole git argv arrive as positional parameters, so nothing is interpolated
#: into a shell string.
_ULIMIT_WRAPPER = 'ulimit -f "$1" || exit 70; shift; exec "$@"'


def clone_argv(slug: str, destination: Path, fsize_blocks: int) -> List[str]:
    """Build the exact argv used to clone one repository.

    Split out from :func:`clone_one` so the hardening is testable without a
    network. ``testing/unit/test_repo_arm.py`` asserts the properties §10
    fixes — in particular that ``--`` precedes the URL, because a URL beginning
    ``--upload-pack=`` is remote code execution without it.

    Args:
        slug: ``owner/repo``, already charset-validated.
        destination: Where the bare repository goes.
        fsize_blocks: ``ulimit -f`` ceiling in 512-byte blocks.

    Returns:
        The argv, shell wrapper included.
    """
    git_argv = [
        "git",
        "-c",
        "credential.helper=",
        "-c",
        "core.askPass=",
        "clone",
        "--filter=blob:none",
        "--bare",
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
        str(fsize_blocks),
    ] + git_argv


def clone_one(
    slug: str,
    root: Path,
    timeout_seconds: int = CLONE_TIMEOUT_SECONDS,
    fsize_blocks: int = FSIZE_LIMIT_BLOCKS,
) -> CloneResult:
    """Clone one repository, hardened per §10.

    Args:
        slug: ``owner/repo``, already validated against GitHub's charset.
        root: Directory to clone into.
        timeout_seconds: Wall-clock ceiling.
        fsize_blocks: ``ulimit -f`` ceiling in 512-byte blocks.

    Returns:
        The outcome, including a size and a duration for the ones that worked.
    """
    destination = clone_directory(root, slug)
    if destination.exists():
        shutil.rmtree(destination, ignore_errors=True)

    argv = clone_argv(slug, destination, fsize_blocks)

    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root / ".nohome"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C",
    }

    started = time.monotonic()
    try:
        completed = subprocess.run(  # nosec B603 - fixed argv, no shell string
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(destination, ignore_errors=True)
        return CloneResult(slug, TIMEOUT, time.monotonic() - started, None, "")

    elapsed = time.monotonic() - started
    if completed.returncode == 0 and destination.exists():
        return CloneResult(slug, OK, elapsed, _directory_size(destination), "")

    status = _classify(completed.stderr, completed.returncode)
    shutil.rmtree(destination, ignore_errors=True)
    return CloneResult(slug, status, elapsed, None, completed.stderr.strip()[-400:])


def _directory_size(path: Path) -> int:
    """Return the total size of a directory tree in bytes.

    Args:
        path: Directory to measure.

    Returns:
        Sum of file sizes, following no symlinks.
    """
    total = 0
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            total += item.stat().st_size
    return total
