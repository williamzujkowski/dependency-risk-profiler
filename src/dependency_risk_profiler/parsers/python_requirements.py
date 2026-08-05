"""One reading of a declared Python requirement, shared by every Python path.

A constraint is not a version. ``requests>=2.20.0`` says the project will accept
2.20.0 and everything after it; it does not say 2.20.0 is installed, and
``requests 2.32.5`` satisfies it. Until #275 both Python readers wrote the bound
into ``installed_version`` anyway, so ``requests>=2.20.0`` produced a record
byte-identical to ``requests==2.20.0`` — including ``known_vulnerable: true``
from four advisories fixed in 2.20.1, against a project that may well have none
of them. The version-drift signal reported ``measured`` off the same string, and
``billiard>=4.2.1,<5.0`` reported ``measured`` off ``"4.2.1,<5.0"``, which is
not a version by any reading.

This module is the single place that decides whether a declaration names one
concrete version, and it answers with :class:`DeclaredRequirement`, which cannot
carry both a pin and a constraint. That is AGENTS.md rule 4 by construction: the
two facts do not share a slot, so no later edit can quietly put a bound back
where a version goes.

The mechanism it feeds is not new. :data:`~.version_sources.VERSION_SOURCE_UNMANAGED`
already means "declared, but not as one concrete version", and NuGet, Maven and
Gradle already emit an empty ``installed_version`` beside it. The scorer drops
version drift from both numerator and denominator when it sees one (#74), and
``evaluate_applicability`` returns ``UNKNOWN`` with ``installed version
unknown`` rather than deciding an advisory against a number nobody stated. So
Python joins that contract rather than growing a parallel one — there are still
exactly the two states #164 ratified.

Parsing goes through :mod:`packaging`, which is already a dependency and is
pip's own PEP 508 implementation. The hand-rolled ``if "==" in line / elif ">="
in line`` chain it replaces got ``requests!=2.0`` wrong (name ``requests!``),
got ``requests; python_version < "3.9"`` wrong (name ``requests;
python_version``), and got ``coverage[toml]==7.10.6`` wrong (name
``coverage[toml]``, which is not a project on PyPI).

**Environment markers are read, not evaluated.** ``tzdata; sys_platform ==
"win32"`` is a dependency of this project whose *name* the old chain mangled,
and that is what is fixed here. Whether it applies to the machine running the
scan is a different question with a different answer — the tool profiles a
manifest, not an interpreter, and a marker-gated dependency dropped on a Linux
scanner would silently reappear on a Windows one. So markers are parsed out of
the name and the dependency is kept.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..models import DependencyMetadata
from .version_sources import (
    DECLARED_CONSTRAINT_KEY,
    VERSION_SOURCE_DECLARED,
    VERSION_SOURCE_KEY,
    VERSION_SOURCE_UNMANAGED,
)

# A comment runs from a `#` that starts the line or follows whitespace. Anchored
# on the whitespace so that a URL fragment — `… @ https://host/x.tar.gz#sha256=…`
# — is not cut in half, which a bare `split("#")` does.
_COMMENT = re.compile(r"(?:^|\s)#")

# An option trailing a requirement: `foo==1.0 --hash=sha256:…`. Same anchoring
# reason: `--` occurs inside version strings and URLs, and only a whitespace-led
# one starts an option.
_TRAILING_OPTION = re.compile(r"\s--")


@dataclass(frozen=True)
class DeclaredRequirement:
    """What a manifest said about one dependency, with pin and bound separated.

    Attributes:
        name: The project name, normalized per PEP 503 — case-folded, runs of
            ``-``, ``_`` and ``.`` collapsed to ``-``, extras removed. This is
            what PyPI's JSON API and OSV both key on, and it is what makes
            ``coverage[toml]`` resolve as ``coverage``.
        pinned_version: The one concrete version the declaration names, or None
            when it names none. Never a bound, never a range, never ``latest``.
        constraint: What was declared in the version slot when it is *not* a
            pin — a specifier set (``<5.0,>=4.2.1``), or a VCS / path / URL
            reference. Kept for the reader's benefit and never used as a
            version. None when the declaration is a pin, and None when the
            manifest stated nothing at all.

    Raises:
        ValueError: If a pin and a constraint are supplied together, or if the
            pin is not a version. Both are unrepresentable rather than
            discouraged, for the reason ``signals.Measurement`` gives.
    """

    name: str
    pinned_version: Optional[str]
    constraint: Optional[str]

    def __post_init__(self) -> None:
        """Reject every combination that would put a non-version in a pin."""
        if not self.name:
            raise ValueError("a declared requirement must name a project")
        if self.pinned_version is None:
            return
        if self.constraint is not None:
            raise ValueError(
                "a pinned requirement must not also carry a constraint: the "
                "whole point of #275 is that the two do not share a slot"
            )
        try:
            Version(self.pinned_version)
        except InvalidVersion as exc:
            raise ValueError(
                f"{self.pinned_version!r} is not a version, so it cannot be a "
                "pin; declare it as a constraint instead"
            ) from exc


def normalized_name(raw: str) -> str:
    """Return a project name folded to its PEP 503 canonical form.

    Args:
        raw: The name as the manifest wrote it, e.g. ``Flask`` or
            ``zope.interface``.

    Returns:
        The canonical name, e.g. ``flask`` or ``zope-interface``.
    """
    return canonicalize_name(raw)


def pinned_version(specifier: SpecifierSet) -> Optional[str]:
    """Return the single version a specifier set pins, or None.

    A set pins when it holds exactly one clause, that clause is ``==`` or
    ``===``, and its right-hand side is a real PEP 440 version. Everything else
    admits more than one version and is therefore not an installed version:
    ``>=2.20.0`` and ``<5.0,>=4.2.1`` obviously, but also ``==1.2.*``, whose
    right-hand side is a prefix and not a version at all.

    ``===`` is arbitrary equality — PEP 440 matches its operand as a literal
    string, which need not be a version. When it is one, it pins; when it is
    not, there is nothing here to compare against ``latest_version`` and it does
    not.

    Args:
        specifier: The parsed specifier set from a PEP 508 requirement.

    Returns:
        The pinned version, or None when the declaration admits more than one.
    """
    clauses = list(specifier)
    if len(clauses) != 1:
        return None
    only = clauses[0]
    if only.operator not in ("==", "==="):
        return None
    try:
        Version(only.version)
    except InvalidVersion:
        return None
    return only.version


def requirement_lines(text: str) -> List[str]:
    """Split a requirements file into the requirement strings it states.

    pip's file grammar, and only the parts of it that decide what a requirement
    string is: a trailing backslash continues onto the next line, a ``#``
    preceded by whitespace or starting a line begins a comment, a line whose
    first character is ``-`` is an option (``-r``, ``-c``, ``-e``,
    ``--index-url``) and names no package, and options may also trail a
    requirement.

    Continuations are why this exists rather than a loop over ``readlines``.
    ``pip-compile`` writes every pin as ``requests==2.32.5 \\`` followed by
    indented ``--hash=sha256:…`` lines, which is the *pinned* case this change
    must not break — read line-at-a-time it yielded an installed version of
    ``2.32.5 \\`` and one dependency named ``--hash=sha256`` per hash.

    Args:
        text: The whole file.

    Returns:
        One string per requirement, with comments and options removed.
    """
    joined: List[str] = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1]
            continue
        joined.append(buffer + stripped)
        buffer = ""
    if buffer:
        joined.append(buffer)

    requirements: List[str] = []
    for entry in joined:
        line = _COMMENT.split(entry, maxsplit=1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = _TRAILING_OPTION.split(line, maxsplit=1)[0].strip()
        if line:
            requirements.append(line)
    return requirements


def read_requirement(text: str) -> Optional[DeclaredRequirement]:
    """Read one PEP 508 requirement string.

    Args:
        text: The requirement as written, e.g. ``coverage[toml]==7.10.6`` or
            ``tzdata; sys_platform == "win32"``.

    Returns:
        The declaration, or None when the string is not a requirement at all.
        None is returned rather than a guess: a line ``packaging`` cannot read
        is one this code has no basis for naming a package after, and inventing
        one is how ``requests-toolbelt!`` reached a registry lookup.
    """
    try:
        requirement = Requirement(text)
    except InvalidRequirement:
        return None

    name = normalized_name(requirement.name)
    if requirement.url is not None:
        # `foo @ https://…/foo-1.0.tar.gz` — a direct reference. The filename
        # may well contain a version; reading one out of it would be a guess
        # about a naming convention, not a statement the manifest made.
        return DeclaredRequirement(
            name=name, pinned_version=None, constraint=requirement.url
        )

    pinned = pinned_version(requirement.specifier)
    if pinned is not None:
        return DeclaredRequirement(name=name, pinned_version=pinned, constraint=None)

    declared = str(requirement.specifier)
    return DeclaredRequirement(
        name=name, pinned_version=None, constraint=declared or None
    )


def read_poetry_requirement(
    name: str, declared: object
) -> Optional[DeclaredRequirement]:
    """Read one ``[tool.poetry.dependencies]`` entry.

    Poetry's syntax is its own and overlaps PEP 440 only partly, which is why
    this is a second reader rather than a call into :func:`read_requirement`.
    The trap is the bare string: in Poetry ``requests = "2.28.0"`` is an *exact*
    requirement, while in Cargo the identical ``serde = "1.0"`` means ``^1.0``.
    Same three characters, different fact, so the Cargo path deliberately does
    not come through here.

    Args:
        name: The table key, i.e. the project name as written.
        declared: The value — a version string, or a table carrying ``version``,
            ``git``, ``path`` or ``url``.

    Returns:
        The declaration, or None when the entry carries nothing that describes a
        version or a source.
    """
    if isinstance(declared, str):
        return read_version_specifier(name, declared)
    if isinstance(declared, dict):
        version = declared.get("version")
        if version is not None:
            # TOML types its scalars, so `version = 1.0` arrives as a float.
            return read_version_specifier(name, str(version))
        for key in ("git", "path", "url"):
            reference = declared.get(key)
            if reference is not None:
                return DeclaredRequirement(
                    name=normalized_name(name),
                    pinned_version=None,
                    constraint=f"{key}:{reference}",
                )
    return None


def read_version_specifier(name: str, declared: str) -> DeclaredRequirement:
    """Turn a bare version string into a pin or a constraint.

    Serves the two Python manifests that state a version apart from the name —
    Poetry's ``requests = "^2.25.0"`` and ``Pipfile.lock``'s ``{"version":
    "==1.2.3"}``. Both write a PEP 440 specifier set into that slot, or
    something that only looks like one, and the same question is being asked of
    both: does this name exactly one version?

    Args:
        name: The project name as written.
        declared: The version string, e.g. ``^2.25.0``, ``>=4.0``, ``2.28.0``,
            ``==1.2.3``, ``*``.

    Returns:
        The declaration. A bare PEP 440 version pins — that is Poetry's exact
        requirement, and it is the reason the Cargo path deliberately does not
        come through here, since ``serde = "1.0"`` means ``^1.0`` instead.
        ``==`` to one version pins. Everything else — caret, tilde, an
        inequality, a comma-joined pair, ``*`` — admits more than one version
        and is kept as a constraint.
    """
    text = declared.strip()
    canonical = normalized_name(name)
    if not text:
        return DeclaredRequirement(name=canonical, pinned_version=None, constraint=None)
    try:
        Version(text)
    except InvalidVersion:
        pass
    else:
        return DeclaredRequirement(name=canonical, pinned_version=text, constraint=None)
    try:
        pinned = pinned_version(SpecifierSet(text))
    except InvalidSpecifier:
        pinned = None
    if pinned is not None:
        return DeclaredRequirement(
            name=canonical, pinned_version=pinned, constraint=None
        )
    return DeclaredRequirement(name=canonical, pinned_version=None, constraint=text)


def python_dependency(
    requirement: DeclaredRequirement,
    additional_info: Optional[Dict[str, str]] = None,
) -> DependencyMetadata:
    """Build the metadata record for one declared Python requirement.

    This is the only place a Python parser writes ``installed_version``, so the
    invariant holds for every Python manifest format at once rather than four
    times over: the field carries the pin or it carries nothing, and a
    declaration that is not a pin is recorded as
    :data:`~.version_sources.VERSION_SOURCE_UNMANAGED` with the constraint kept
    beside it under :data:`~.version_sources.DECLARED_CONSTRAINT_KEY`.

    Args:
        requirement: The declaration, already separated into pin and constraint.
        additional_info: Anything the calling parser knows that this does not —
            the section the entry came from, whether it is a dev dependency.

    Returns:
        The dependency metadata, ready to score.
    """
    info: Dict[str, str] = dict(additional_info or {})
    if requirement.pinned_version is not None:
        info[VERSION_SOURCE_KEY] = VERSION_SOURCE_DECLARED
    else:
        info[VERSION_SOURCE_KEY] = VERSION_SOURCE_UNMANAGED
        if requirement.constraint is not None:
            info[DECLARED_CONSTRAINT_KEY] = requirement.constraint
    return DependencyMetadata(
        name=requirement.name,
        installed_version=requirement.pinned_version or "",
        repository_url=f"https://pypi.org/project/{requirement.name}/",
        additional_info=info,
    )
