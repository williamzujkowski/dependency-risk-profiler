"""Actionable guidance for manifest files the parser registry refuses.

The registry deliberately parses only manifests that carry *resolved* versions:
a range like ``^3.0.0`` has no version to score drift against. That is the right
design, but it made the two most common first-run mistakes indistinguishable
from a genuinely unsupported ecosystem, because both produced a bare
"Unsupported manifest file" (#125):

1. Pointing the tool at the range-declaring sibling (``package.json``) of a
   supported lock file (``package-lock.json``).
2. Pointing it at a perfectly valid manifest saved under a non-standard name
   (``railsgoat-Gemfile.lock``), which the filename-exact registry rejects
   even though the bytes are fine.

This module turns both into a message that names the next step. It adds no
parser and changes no dispatch: everything here is read-only reporting built on
the registry's public :meth:`EcosystemRegistry.get_ecosystem_details`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .parsers.base import BaseParser
from .parsers.registry import EcosystemRegistry

# Guard against reading a huge file into memory for a diagnostic message.
_CONTENT_PROBE_BYTES = 256 * 1024

_FILE_NAME_PREFIX = "File name: "
_CONTENT_PREFIX = "Content pattern: "


@dataclass(frozen=True)
class _CompanionRule:
    """How to redirect one range-declaring manifest to its resolved companion."""

    # The lock file that carries resolved versions, or None when this ecosystem
    # has no supported companion yet.
    companion: Optional[str]
    # Why this file cannot be scored, phrased as a fact about the file.
    reason: str
    # Extra sentence used when there is no companion to point at.
    fallback: str = ""


# Deliberately small. Anything absent keeps the generic message rather than
# guessing at an ecosystem the tool does not actually support.
_COMPANION_RULES: Dict[str, _CompanionRule] = {
    "package.json": _CompanionRule(
        companion="package-lock.json",
        reason="declares version ranges, not resolved versions",
    ),
    "gemfile": _CompanionRule(
        companion="Gemfile.lock",
        reason="declares version constraints, not resolved versions",
    ),
    "composer.json": _CompanionRule(
        companion="composer.lock",
        reason="declares version constraints, not resolved versions",
    ),
    "pipfile": _CompanionRule(
        companion="Pipfile.lock",
        reason="declares version constraints, not resolved versions",
    ),
    "build.gradle": _CompanionRule(
        companion=None,
        reason="declares version ranges and dynamic versions, not resolved versions",
        fallback=(
            "Gradle lock file support is not implemented yet (see issue #101). "
            "pom.xml works today for Maven-built projects."
        ),
    ),
    "build.gradle.kts": _CompanionRule(
        companion=None,
        reason="declares version ranges and dynamic versions, not resolved versions",
        fallback=(
            "Gradle lock file support is not implemented yet (see issue #101). "
            "pom.xml works today for Maven-built projects."
        ),
    ),
}


def unsupported_manifest_guidance(manifest_path: str) -> Optional[str]:
    """Return a next step for a refused manifest, or ``None`` when there is none.

    ``None`` means the caller should keep today's generic message: the file is
    not a known range-declaring companion and does not look like a supported
    manifest wearing the wrong name.
    """
    path = Path(manifest_path)
    companion_hint = _companion_guidance(path)
    if companion_hint is not None:
        return companion_hint
    return _misnamed_guidance(path)


def _companion_guidance(path: Path) -> Optional[str]:
    """Redirect a known range-declaring manifest to its resolved companion."""
    rule = _COMPANION_RULES.get(path.name.lower())
    if rule is None:
        return None

    opening = f"{path.name} {rule.reason}, so there is nothing to score drift against."
    if rule.companion is None:
        return f"{opening} {rule.fallback}".strip()

    directory = path.parent
    companion_path = _existing_companion(directory, rule.companion)
    if companion_path is not None:
        location = f"found alongside it at {companion_path}"
    else:
        location = f"not found in {directory}"
    return f"{opening} Point me at {rule.companion} instead ({location})."


def _existing_companion(directory: Path, companion: str) -> Optional[Path]:
    """Return the companion file next to the input, matching case-insensitively.

    Checking rather than asserting matters: telling someone to run a file that
    is not there is its own dead end, so the message says which case it is.
    """
    candidate = directory / companion
    if candidate.is_file():
        return candidate
    wanted = companion.lower()
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return None
    for entry in entries:
        if entry.name.lower() == wanted and entry.is_file():
            return entry
    return None


def _misnamed_guidance(path: Path) -> Optional[str]:
    """Name the parser that would have accepted this file under a valid name."""
    supported_name, evidence = _would_be_parser(path)
    if supported_name is None:
        return None
    return (
        f"{path.name} was refused because the parser registry matches manifest "
        f"filenames exactly. {evidence} Rename or copy it to {supported_name} — "
        "same bytes, supported name."
    )


def _would_be_parser(path: Path) -> Tuple[Optional[str], str]:
    """Return the canonical filename and the evidence for a misnamed manifest."""
    registered = _registered_manifests()

    # The cheap, high-signal case first: `railsgoat-Gemfile.lock` ends with a
    # supported name, so the bytes almost certainly are that manifest.
    lowered = path.name.lower()
    for ecosystem, file_names, _ in registered:
        for file_name in file_names:
            if lowered != file_name.lower() and lowered.endswith(file_name.lower()):
                return file_name, (
                    f"Its name ends with {file_name}, which the {ecosystem} "
                    "parser accepts."
                )

    # Then the content shape. The registry's own content probe reads 2KB
    # without DOTALL, so it misses a real package-lock.json whose
    # "lockfileVersion" and "dependencies" keys sit on different lines. This
    # probe is message-only and never changes which parser runs.
    content = _read_probe(path)
    if content is None:
        return None, ""
    for ecosystem, file_names, patterns in registered:
        if not file_names:
            continue
        for pattern in patterns:
            if pattern.search(content):
                evidence = f"Its contents match the {ecosystem} parser's"
                return file_names[0], f"{evidence} content pattern."
    return None, ""


def _read_probe(path: Path) -> Optional[str]:
    """Read a bounded prefix of the file for content matching."""
    try:
        with path.open("r", errors="ignore") as handle:
            return handle.read(_CONTENT_PROBE_BYTES)
    except OSError:
        return None


def _registered_manifests() -> List[Tuple[str, List[str], List[re.Pattern[str]]]]:
    """Return (ecosystem, supported file names, content patterns) per ecosystem.

    Built from the registry's public details API so this module never reaches
    into registry internals and never needs updating when a parser is added.
    """
    if not EcosystemRegistry.get_available_ecosystems():
        BaseParser._initialize_registry()

    registered: List[Tuple[str, List[str], List[re.Pattern[str]]]] = []
    for ecosystem, details in EcosystemRegistry.get_ecosystem_details().items():
        raw_patterns = details.get("file_patterns", [])
        if not isinstance(raw_patterns, list):
            continue
        file_names: List[str] = []
        content_patterns: List[re.Pattern[str]] = []
        for entry in raw_patterns:
            if not isinstance(entry, str):
                continue
            if entry.startswith(_FILE_NAME_PREFIX):
                file_names.append(entry[len(_FILE_NAME_PREFIX) :])
            elif entry.startswith(_CONTENT_PREFIX):
                source = entry[len(_CONTENT_PREFIX) :]
                try:
                    content_patterns.append(re.compile(source, re.DOTALL))
                except re.error:
                    continue
        registered.append((ecosystem, file_names, content_patterns))
    return registered
