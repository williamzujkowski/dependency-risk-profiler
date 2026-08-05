"""Replay a captured repository layout onto disk for the scorecard checks (#291).

The scorecard checks answer presence questions with ``pathlib`` existence
checks, so a faithful fixture is the *set of paths* a real repository has.
``scripts/capture_repo_layouts.py`` records that set from a real clone; this
module turns a recording back into a directory tree and, where a test needs a
reduction, removes a named directory from it.

Why this and not a hand-built tree: a hand-built tree puts the pull request
template wherever the author believes the check looks, which is the assumption
under test. These paths were chosen by ``allauth`` and by ``gitlab-org``, not by
anyone who has read this code (AGENTS.md rule 5).

Files are created empty. Every check that reads *content* — workflow YAML, a
security policy's prose — is exercised elsewhere with real content; what these
layouts establish is which paths the checks agree to look at, and an empty file
answers ``exists()`` exactly as a full one does. Directories implied by a path
are created, which is how ``git ls-files`` output relates to a working tree: it
lists files, and the directory is whatever contains them.
"""

import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "repo_layouts"


def load_layout(name: str) -> Dict[str, object]:
    """Read one captured layout recording.

    Args:
        name: Layout name, matching a key in the capture manifest.

    Returns:
        The recorded document, including ``source_url``, ``commit``,
        ``captured_utc`` and ``paths``.
    """
    with open(FIXTURE_DIR / f"{name}.json", "r", encoding="utf-8") as handle:
        document: Dict[str, object] = json.load(handle)
    return document


def layout_paths(name: str) -> List[str]:
    """Return the tracked paths a captured layout recorded.

    Args:
        name: Layout name.

    Returns:
        Every path the real repository tracked at capture time.
    """
    paths = load_layout(name)["paths"]
    assert isinstance(paths, list)
    return [str(path) for path in paths]


def materialise(
    name: str,
    destination: Path,
    *,
    without: Optional[List[str]] = None,
    git_init: bool = True,
) -> Path:
    """Write a captured layout out as a real directory tree.

    Args:
        name: Layout name.
        destination: Directory to build the tree under. Created if absent.
        without: Top-level directories to omit, so a test can reduce a captured
            tree to a forge-native one. Keyword-only and with no default that
            hides it: dropping ``.github`` is the whole experiment in #291, and
            it must be visible at the call site rather than baked into the
            recording.
        git_init: Whether to make the result a git repository with one commit.
            Three of the five scorecard checks shell out to ``git``, so a tree
            that is not a repository makes them fail for the wrong reason.

    Returns:
        The root of the materialised tree.
    """
    omitted = tuple(f"{prefix.rstrip('/')}/" for prefix in (without or []))
    destination.mkdir(parents=True, exist_ok=True)
    for relative in layout_paths(name):
        if relative.startswith(omitted):
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()
    if git_init:
        _init_repository(destination)
    return destination


def _init_repository(root: Path) -> None:
    """Turn a materialised tree into a git repository with one commit.

    Args:
        root: The materialised tree.
    """
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for key, value in (("user.email", "fixture@example.invalid"), ("user.name", "fx")):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
    subprocess.run(
        ["git", "-C", str(root), "add", "-A"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "-qm", "captured layout"],
        check=True,
        capture_output=True,
    )
