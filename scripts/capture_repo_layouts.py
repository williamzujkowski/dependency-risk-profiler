#!/usr/bin/env python3
"""Capture real repository file layouts as scorecard-conformance fixtures (#291).

The scorecard checks answer presence questions off a shallow clone: does this
repository ship a pull request template, issue templates, a security policy, a
CODEOWNERS file, CI. Every one of those is a ``pathlib`` existence check, so the
only thing a fixture needs to reproduce is the **set of paths** a real
repository has.

Fixtures for those checks are **captured, never authored** (AGENTS.md rule 5).
A hand-written layout encodes the same assumption the check makes — it puts the
template where the check already looks — so the test passes and proves nothing.
That is exactly how ``has_pull_request_template`` stayed ``False`` on
Forgejo-native repositories: every test tree in this repository had a
``.github/`` directory because the author knew that is where the code looked.

This script is the only thing that clones a repository for fixture purposes. It
is **never run by CI** — the suite replays what is recorded here and touches no
network. Run it by hand, review the diff, and commit it::

    python scripts/capture_repo_layouts.py            # everything
    python scripts/capture_repo_layouts.py --layout gitlab-runner
    python scripts/capture_repo_layouts.py --check    # report staleness only

What to capture is declared in ``testing/fixtures/repo_layouts/manifest.json``,
which the tests read too, so the two cannot drift.

Trimming rule
-------------
**Nothing is trimmed.** ``git ls-files`` is recorded whole. The registry
fixtures reduce volume because a 200-entry ``versions`` map is megabytes; a
path list is tens of kilobytes, and any reducer here would be a judgment about
which paths matter — which is precisely the judgment the checks get wrong. A
derived layout (``.github/`` deleted, say) is produced in the test from the
captured whole, so the deletion is visible at the assertion rather than baked
into the recording.

Clone shape
-----------
``--depth 1 --filter=blob:none --no-tags``: the blobs are never read, only the
index, so a blobless clone of a large repository finishes in seconds. Only
``https`` URLs whose host is in the manifest allowlist are cloned, and
``GIT_TERMINAL_PROMPT=0`` keeps a bad URL from blocking on a credential prompt.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "testing" / "fixtures" / "repo_layouts"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"

CLONE_TIMEOUT_SECONDS = 300


def _load_manifest() -> Dict[str, object]:
    """Read the capture manifest.

    Returns:
        The parsed manifest.
    """
    with open(MANIFEST_PATH, "r", encoding="utf-8") as handle:
        manifest: Dict[str, object] = json.load(handle)
    return manifest


def _check_url(url: str, allowed_hosts: List[str]) -> None:
    """Reject a clone URL that is not an allowlisted https repository.

    Args:
        url: The clone URL from the manifest.
        allowed_hosts: Hosts the manifest permits.

    Raises:
        ValueError: If the scheme is not https or the host is not allowlisted.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"refusing to clone a non-https URL: {url}")
    if parsed.netloc.lower() not in allowed_hosts:
        raise ValueError(f"host not in the manifest allowlist: {parsed.netloc}")


def _capture(name: str, url: str, allowed_hosts: List[str]) -> Dict[str, object]:
    """Clone one repository and record its tracked paths.

    Args:
        name: Fixture name, used for the output file.
        url: The https clone URL.
        allowed_hosts: Hosts the manifest permits.

    Returns:
        The fixture document, ready to write.

    Raises:
        ValueError: If the URL fails the allowlist check.
    """
    _check_url(url, allowed_hosts)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    with tempfile.TemporaryDirectory(prefix="drp-layout-") as workdir:
        clone_dir = str(Path(workdir) / name)
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                "--filter=blob:none",
                url,
                clone_dir,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            env=env,
        )
        commit = subprocess.run(
            ["git", "-C", clone_dir, "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        listing = subprocess.run(
            ["git", "-C", clone_dir, "ls-files"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    return {
        "layout_schema": 1,
        "source_url": url,
        "commit": commit,
        "captured_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "paths": sorted(listing),
    }


def _fixture_path(name: str) -> Path:
    """Return the file a named layout is written to.

    Args:
        name: Fixture name.

    Returns:
        Path under ``testing/fixtures/repo_layouts``.
    """
    return FIXTURE_DIR / f"{name}.json"


def _report_staleness(manifest: Dict[str, object]) -> int:
    """Print the capture date of every recorded layout.

    Args:
        manifest: The parsed manifest.

    Returns:
        Process exit status: 1 if a declared layout has no recording.
    """
    layouts = manifest["layouts"]
    assert isinstance(layouts, dict)
    missing = 0
    for name in sorted(layouts):
        path = _fixture_path(name)
        if not path.exists():
            print(f"{name}: MISSING")
            missing += 1
            continue
        with open(path, "r", encoding="utf-8") as handle:
            recorded = json.load(handle)
        print(
            f"{name}: captured {recorded['captured_utc']} at {recorded['commit'][:12]}"
        )
    return 1 if missing else 0


def main(argv: List[str]) -> int:
    """Capture the declared layouts.

    Args:
        argv: Command-line arguments, without the program name.

    Returns:
        Process exit status.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", help="capture only this layout")
    parser.add_argument(
        "--check", action="store_true", help="report what is recorded, capture nothing"
    )
    args = parser.parse_args(argv)

    manifest = _load_manifest()
    layouts = manifest["layouts"]
    allowed_hosts = manifest["allowed_hosts"]
    assert isinstance(layouts, dict)
    assert isinstance(allowed_hosts, list)

    if args.check:
        return _report_staleness(manifest)

    names = [args.layout] if args.layout else sorted(layouts)
    for name in names:
        if name not in layouts:
            print(f"unknown layout: {name}", file=sys.stderr)
            return 2
        entry = layouts[name]
        print(f"capturing {name} from {entry['url']} ...")
        document = _capture(name, entry["url"], allowed_hosts)
        with open(_fixture_path(name), "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
        print(f"  {len(document['paths'])} paths at {document['commit'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
