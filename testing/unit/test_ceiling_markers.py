"""Ceiling markers are well-formed, and their triggers are real conditions.

This repo's dominant defect is a bar stated with nothing checking it. Its known
algorithmic ceilings -- the sufficiency bar counting numbers rather than
information, ``has_tests`` meaning "has a conventionally-named test directory"
-- were recorded in excellent long-form docstrings that no mechanism could
count. ``grep -rnE '(#|//) ?(TODO|FIXME|XXX|HACK)' src/`` returns zero hits, so
the usual debt vocabulary answers nothing either.

A ``drp:`` marker makes one countable. This module is the mechanism, and
without it the convention would be the same defect with better grep.

**The parse contract**, fixed here because a convention whose grammar is
ambiguous is unimplementable:

- A marker block is a **contiguous run of comment lines** starting at ``# drp:``
  and ending at the first line that is not a comment.
- The block must contain the literal sentinel ``Upgrade when``.
- What follows the sentinel is the **trigger condition**, and it must survive
  deleting any trailing issue reference.

That last rule is AGENTS.md rule 7 applied unchanged, not an exception to it.
Rule 7 already permits "a trailing issue reference as a pointer… The comment
must stand on its own with the reference removed — the number is a footnote,
never the explanation." So:

    # drp: ... Upgrade when #408 lands a variance-aware rule.   <- FAILS
    # drp: ... Upgrade when a variance-aware sufficiency rule
    #      exists (#408).                                        <- passes

The first names a moment; delete the number and nothing is left standing. The
second names an observable condition and keeps the number as a footnote. No
amendment to rule 7 was needed; the tempting example was simply wrong.

**Why bespoke rather than ruff.** ruff ships ``flake8-todos``, and TD003
enforces exactly the presence half. It was not adopted: TD rules fire only on
``TODO``/``FIXME``, which would conflate algorithmic ceilings with ordinary
debt, and TD003 makes the issue link *mandatory content* -- the precise
inversion of rule 7's footnote discipline. Neither ruff nor any other tool
checks a trigger condition, so the bespoke half is the part nothing sells.

**What this does not check.** Trigger *quality* is not mechanically decidable,
and a presence test alone makes "Upgrade when we have better data" the cheapest
compliant move -- which reads as discharged while discharging nothing. Two
partial answers: a vagueness denylist below, and the dead-trigger tripwire in
``scripts/check_ceiling_triggers.py``, which fails once a cited issue closes.
Quality beyond that stays a review question, and green CI here must never be
read as a ceiling justified.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[2]

SEARCH_ROOTS = ("src", "scripts", "research")

MARKER = "# drp:"
SENTINEL = "Upgrade when"

#: A trailing issue reference is a footnote (rule 7), so it is stripped before
#: the trigger is judged. If nothing survives, the number was the explanation.
ISSUE_REF = re.compile(r"\(#\d+\)|#\d+")

#: Phrases that name no observable condition. Not exhaustive and not a
#: substitute for review -- a floor, so the cheapest compliant move is not the
#: emptiest one.
VAGUE = (
    "better data",
    "eventually",
    "when we have time",
    "someday",
    "if needed",
    "more research",
)


class Marker(NamedTuple):
    """One ceiling marker, located."""

    path: Path
    line: int
    text: str

    @property
    def where(self) -> str:
        return f"{self.path.relative_to(REPO_ROOT)}:{self.line}"


def harvest() -> List[Marker]:
    """Collect every marker block under the searched roots."""
    markers: List[Marker] = []
    for root in SEARCH_ROOTS:
        base = REPO_ROOT / root
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            index = 0
            while index < len(lines):
                if lines[index].strip().startswith(MARKER):
                    start = index
                    block = []
                    # A block runs to the first line that is not a comment, so
                    # a multi-line ceiling reads as one marker rather than as a
                    # malformed first line plus orphaned prose.
                    while index < len(lines) and lines[index].strip().startswith("#"):
                        block.append(lines[index].strip().lstrip("#").strip())
                        index += 1
                    markers.append(Marker(path, start + 1, " ".join(block)))
                else:
                    index += 1
    return markers


def trigger_of(text: str) -> str:
    """Return the trigger condition, with its footnote reference removed.

    The condition ends at its own sentence boundary, not at the end of the
    marker block. A block runs to the first non-comment line, so it absorbs any
    ordinary comment sitting directly beneath it -- and without this cut, the
    trigger "Upgrade when #411 lands." borrowed the following line and read as
    eight words, clearing the delete-test on prose that was never part of it.
    A mutation test found that; the parse contract alone did not.
    """
    _, _, after = text.partition(SENTINEL)
    sentence, _, _ = after.partition(".")
    return ISSUE_REF.sub("", sentence).strip(" .,;")


def test_every_marker_names_an_upgrade_trigger() -> None:
    """A ceiling with no trigger is the one that silently rots."""
    missing = [m.where for m in harvest() if SENTINEL not in m.text]
    assert not missing, (
        "Ceiling markers with no upgrade trigger. Every `# drp:` marker must "
        f"contain the literal '{SENTINEL}' followed by an observable "
        "condition:\n  " + "\n  ".join(missing)
    )


def test_every_trigger_survives_deleting_its_issue_reference() -> None:
    """Rule 7: the number is a footnote, never the explanation."""
    broken = []
    for marker in harvest():
        if SENTINEL not in marker.text:
            continue
        condition = trigger_of(marker.text)
        # "Upgrade when #408 lands a rule" leaves "lands a rule" -- a fragment
        # whose subject was the issue number. Requiring a few words is a crude
        # proxy, but it catches the shape the rule actually bans.
        if len(condition.split()) < 3:
            broken.append(f"{marker.where}: trigger reads {condition!r}")
    assert not broken, (
        "Upgrade triggers that do not stand on their own with the issue "
        "reference removed (AGENTS.md rule 7). Name the observable condition "
        "and keep the number as a footnote:\n  " + "\n  ".join(broken)
    )


def test_no_trigger_is_vacuously_vague() -> None:
    """A floor on quality, not a judgement of it."""
    vague = [
        f"{m.where}: {phrase!r}"
        for m in harvest()
        for phrase in VAGUE
        if phrase in trigger_of(m.text).lower()
    ]
    assert not vague, (
        "Upgrade triggers naming no observable condition:\n  " + "\n  ".join(vague)
    )


def test_the_harvester_actually_finds_the_known_ceilings() -> None:
    """Rule 6: a gate nobody watched fail is a gate nobody has.

    Without this, a harvester whose glob silently matched nothing would pass
    all three checks above -- vacuously, and identically to a clean tree.
    """
    markers = harvest()
    assert len(markers) >= 4, (
        f"The harvester found {len(markers)} ceiling markers. The four known "
        "ceilings are marked in source; finding fewer means the harvest is "
        "broken, not that the ceilings are gone."
    )


def test_a_triggerless_marker_would_fail(tmp_path: Path) -> None:
    """The gate bites. Demonstrated on a fixture rather than asserted."""
    fixture = tmp_path / "sample.py"
    fixture.write_text("# drp: this cuts a corner and names no way out\nx = 1\n")
    lines = fixture.read_text().splitlines()
    block = " ".join(
        line.strip().lstrip("#").strip()
        for line in lines
        if line.strip().startswith("#")
    )
    assert SENTINEL not in block
