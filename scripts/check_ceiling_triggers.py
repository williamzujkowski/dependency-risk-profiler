"""Fail when a ceiling marker's cited issue has closed. **Network.**

The half of #401 that makes a marker different from the prose it replaces.

``testing/unit/test_ceiling_markers.py`` checks marker grammar once, at write
time, and never again. That alone is the repo's dominant defect wearing a
regex: a bar checked at birth and never after. Prose ceilings cannot expire;
this makes markers expire loudly.

When a marker cites an issue and that issue closes, one of two things is true:
the ceiling was upgraded and the marker is now a lie, or the issue was closed
without the upgrade and the marker's trigger has silently discharged. Both are
worth a red build. Neither is detectable from source alone, which is why this
lives outside the offline test.

It needs the GitHub API, so it belongs in the scheduled tier rather than the
per-commit gate -- this repo has already had a security gate read as a security
finding because a CDN returned 503, and a rate limit on every push would repeat
that shape.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess  # nosec B404 - gh is invoked with a fixed argv, never a shell string
import sys
from pathlib import Path
from typing import List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "testing" / "unit"))

from test_ceiling_markers import ISSUE_REF, harvest, trigger_of  # noqa: E402

logger = logging.getLogger(__name__)


def cited_issues(text: str) -> Set[int]:
    """Issue numbers referenced by a marker's trigger.

    Read from the trigger only, not the whole block: a ceiling's *description*
    may cite the issue that measured it, which says nothing about when the
    ceiling lifts. Only the trigger's citation is a tripwire.
    """
    _, _, after = text.partition("Upgrade when")
    sentence, _, _ = after.partition(".")
    return {int(match.strip("(#)")) for match in ISSUE_REF.findall(sentence)}


def issue_state(number: int, repo: str) -> Optional[str]:
    """Return ``open``/``closed``, or None when the state cannot be read.

    An unreadable state is *not* treated as closed. A rate limit or a network
    blip would otherwise manufacture a finding, which is the failure mode the
    gitleaks 503 taught this repo to design against.
    """
    try:
        completed = subprocess.run(  # nosec B603 - fixed argv, no shell string
            ["gh", "issue", "view", str(number), "--repo", repo, "--json", "state"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if completed.returncode != 0:
        return None
    try:
        return str(json.loads(completed.stdout)["state"]).lower()
    except (ValueError, KeyError):
        return None


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default="williamzujkowski/dependency-risk-profiler")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    fired: List[str] = []
    unreadable: List[str] = []
    for marker in harvest():
        for number in cited_issues(marker.text):
            state = issue_state(number, args.repo)
            if state is None:
                unreadable.append(f"{marker.where}: #{number}")
            elif state == "closed":
                fired.append(
                    f"{marker.where}: trigger cites #{number}, which is CLOSED "
                    f"-- {trigger_of(marker.text)!r}"
                )

    for line in unreadable:
        logger.warning("could not read issue state for %s", line)

    if fired:
        logger.error(
            "Ceiling triggers have discharged. Upgrade the code and delete the "
            "marker, or re-justify the ceiling with a live trigger:\n  %s",
            "\n  ".join(fired),
        )
        return 1

    logger.info(
        "%d ceiling markers, all triggers live (%d issue states unreadable)",
        len(harvest()),
        len(unreadable),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
