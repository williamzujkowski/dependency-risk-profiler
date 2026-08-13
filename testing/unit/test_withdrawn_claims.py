"""A withdrawn figure must not appear anywhere without a withdrawal marker.

Three separate times a claim corrected in one place survived in another: the
lookup-table caveat lost in transmission, the 928/928 abstention flip withdrawn
in a new section while the original table kept asserting it, and the 53.6%
abstention figure corrected in one part of a protocol and left standing four
hundred lines earlier.

The failure is structural rather than careless. **A correction gets written
where the author is looking; the claim lives wherever it was cited.** So this
reads `docs/withdrawn-claims.md` and checks the whole documentation tree.

It deliberately does not require deletion. Leaving the original sentence in
place with a marker beside it is what makes a correction legible to someone
reading later — deleting it makes the record look like the mistake never
happened.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY = REPO_ROOT / "docs" / "withdrawn-claims.md"

#: Any of these within :data:`MARKER_WINDOW` lines of an occurrence means the
#: occurrence is annotated rather than asserted.
MARKERS = ("withdraw", "artifact", "refut", "corrected", "superseded", "not the tool")

#: Generous, because a withdrawal note usually sits above a table rather than
#: on the row itself.
MARKER_WINDOW = 12

#: The registry describes its own rows in prose; those mentions are not claims.
EXEMPT = {REGISTRY}


class Occurrence(NamedTuple):
    path: Path
    line: int
    figure: str

    @property
    def where(self) -> str:
        return f"{self.path.relative_to(REPO_ROOT)}:{self.line}"


def registered_figures() -> List[str]:
    """Read the first backticked cell of every table row in the registry."""
    if not REGISTRY.exists():
        return []
    figures = []
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if not cells:
            continue
        match = re.fullmatch(r"`(.+)`", cells[0])
        if match:
            figures.append(match.group(1))
    return figures


def searched_files() -> List[Path]:
    files = [REPO_ROOT / "README.md"]
    files.extend(sorted((REPO_ROOT / "docs").rglob("*.md")))
    return [f for f in files if f.exists() and f not in EXEMPT]


def unannotated(figure: str) -> List[Occurrence]:
    """Occurrences of ``figure`` with no withdrawal marker nearby."""
    found: List[Occurrence] = []
    for path in searched_files():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            if figure not in line:
                continue
            window = lines[max(0, index - MARKER_WINDOW) : index + MARKER_WINDOW]
            context = " ".join(window).lower()
            if not any(marker in context for marker in MARKERS):
                found.append(Occurrence(path, index + 1, figure))
    return found


def test_the_registry_is_readable() -> None:
    """Rule 6: a gate that silently matched nothing is not a gate."""
    figures = registered_figures()
    assert figures, (
        f"{REGISTRY.relative_to(REPO_ROOT)} lists no figures. Either the table "
        "format changed or the file moved; either way this check is inert."
    )


def test_no_withdrawn_figure_stands_unannotated() -> None:
    problems: List[str] = []
    for figure in registered_figures():
        for occurrence in unannotated(figure):
            problems.append(f"{occurrence.where}: {figure!r}")
    assert not problems, (
        "Withdrawn figures appear with no withdrawal marker within "
        f"{MARKER_WINDOW} lines. Annotate each one (withdrawn / artifact / "
        "refuted / corrected / superseded) rather than deleting it — the "
        "original text with a marker beside it is what makes a correction "
        "legible:\n  " + "\n  ".join(problems)
    )


def test_an_unannotated_figure_would_be_caught(tmp_path: Path) -> None:
    """The gate bites, demonstrated rather than asserted."""
    lines = ["The rate was 99.9% and this is stated plainly."]
    window = lines[max(0, 0 - MARKER_WINDOW) : 0 + MARKER_WINDOW]
    context = " ".join(window).lower()
    assert not any(marker in context for marker in MARKERS)

    annotated = ["This figure is withdrawn.", "The rate was 99.9%."]
    context = " ".join(annotated).lower()
    assert any(marker in context for marker in MARKERS)
