"""Actionable guidance for manifest files the parser registry refuses.

The registry deliberately parses only manifests it can turn into a dependency
list. That is the right design, but it made the two most common first-run
mistakes indistinguishable from a genuinely unsupported ecosystem, because both
produced a bare "Unsupported manifest file" (#125):

1. Pointing the tool at the range-declaring sibling (``package.json``) of a
   supported lock file (``package-lock.json``).
2. Pointing it at a perfectly valid manifest saved under a non-standard name
   (``railsgoat-Gemfile.lock``), which the filename-exact registry rejects
   even though the bytes are fine.

This module turns both into a message that names the next step. It adds no
parser and changes no dispatch: everything here is read-only reporting built on
the registry's public :meth:`EcosystemRegistry.get_ecosystem_details`.

#243 widened it in two directions.

**The message now names what *is* read**, not only the one companion to
redirect to. "Unsupported format" told a user nothing about whether the tool
supports their ecosystem at all; "npm projects are read from package-lock.json"
does, and it is the same sentence whether or not the lock file happens to be
there.

**The table became a recognizer, not just a message generator.**
:func:`recognise_unreadable_manifest` is a filename-only lookup — no file is
opened — so a directory walk can afford to run it on every entry. That is what
lets ``analyze <dir> --recursive`` distinguish "this project has no
dependencies" from "this project has dependencies I could not read", which are
the same output today and must not be (AGENTS.md rule 4).

The table is deliberately a list of *recognized* names, not a heuristic. A file
it does not name keeps the generic message and is not counted as unreadable: a
confident guess about an ecosystem the tool cannot parse would be worse than
the bare message it replaces.

#262 brought the org path here, and found one thing that does not transfer.
:func:`recognise_unreadable_manifest` opens no file, but it does *stat* the
directory next to the manifest to answer "is the supported input already
there?" — and an org scan's paths are repository-relative names for files on
somebody else's server. Resolving ``package.json`` against the local working
directory is not merely useless there, it is wrong in the dangerous direction:
a ``package-lock.json`` in the operator's shell would mark a remote repository
as covered and drop it from the report again.
:func:`recognise_unreadable_manifest_in_listing` takes the sibling set
explicitly and touches no filesystem, so the two callers share one table, one
message, and no assumptions about where the bytes live.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple

from .parsers.base import BaseParser
from .parsers.registry import EcosystemRegistry

# Guard against reading a huge file into memory for a diagnostic message.
_CONTENT_PROBE_BYTES = 256 * 1024

_FILE_NAME_PREFIX = "File name: "
_CONTENT_PREFIX = "Content pattern: "

# Directories whose contents are installed dependencies rather than the project
# being scanned. A sweep that recognizes `package.json` would otherwise report
# one per installed package — thousands of them, all noise.
#
# One table, two callers: the local recursive walk in the CLI and the org
# scanner's remote tree filter. A second copy would drift, and the drift would
# show up as a warning storm on exactly one of the two paths (#262).
_VENDORED_DIRECTORIES = frozenset(
    {
        ".bundle",
        ".git",
        ".gradle",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "bower_components",
        "node_modules",
        "site-packages",
        "vendor",
        "venv",
    }
)


@dataclass(frozen=True)
class _Ecosystem:
    """An ecosystem and the manifests this tool actually reads for it."""

    # How the ecosystem is named to a user, matching README's table.
    label: str
    # The supported inputs, best first. Empty means the tool does not read this
    # ecosystem at all — which is a fact worth stating, not a gap to paper over.
    inputs: Tuple[str, ...]


_NPM = _Ecosystem("npm", ("package-lock.json",))
_PYTHON = _Ecosystem("Python", ("requirements.txt", "Pipfile.lock", "pyproject.toml"))
_GO = _Ecosystem("Go", ("go.mod",))
_RUST = _Ecosystem("Rust", ("Cargo.toml",))
_RUBY = _Ecosystem("Ruby", ("Gemfile.lock",))
_PHP = _Ecosystem("PHP (Composer)", ("composer.lock",))
_NUGET = _Ecosystem(".NET", ("packages.lock.json", "*.csproj"))
_GRADLE = _Ecosystem("Gradle", ("build.gradle", "build.gradle.kts"))
_MAVEN = _Ecosystem("Maven", ("pom.xml",))

# Ecosystems with no parser here. Naming them is the honest answer: a project
# that is entirely one of these produces no dependencies, and the user is owed
# the difference between "you have none" and "I cannot read yours".
_SBT = _Ecosystem("Scala (sbt)", ())
_COCOAPODS = _Ecosystem("CocoaPods", ())
_SWIFTPM = _Ecosystem("Swift Package Manager", ())
_PUB = _Ecosystem("Dart / Flutter (pub)", ())
_HEX = _Ecosystem("Elixir (Hex)", ())


@dataclass(frozen=True)
class _UnreadableRule:
    """Why one recognized filename is not a dependency list this tool can read."""

    ecosystem: _Ecosystem
    # A fact about *this file*, completing "<name> ...". Never a guess.
    reason: str
    # A command that produces a supported input, as a whole sentence. Empty
    # when there is no single command that does — an absent remedy is stated by
    # saying nothing, never by inventing one.
    remedy: str = ""


# Recognized-but-unreadable manifests, keyed by lowercased file name.
#
# Every entry was checked against the registry in `parsers/base.py`: a name that
# the registry matches must not appear here, or the tool would claim it cannot
# read a file it reads. `testing/unit/test_manifest_guidance.py` asserts that
# disjointness rather than trusting this comment.
_UNREADABLE_BY_NAME: Dict[str, _UnreadableRule] = {
    # npm. package.json is the one #243 was filed about.
    "package.json": _UnreadableRule(
        _NPM,
        "declares version ranges, not resolved versions, so there is nothing "
        "to score drift against",
        "Run `npm install` to generate one.",
    ),
    "npm-shrinkwrap.json": _UnreadableRule(
        _NPM,
        "is an npm shrinkwrap, which this tool does not read",
        "Run `npm install` to generate one.",
    ),
    "yarn.lock": _UnreadableRule(
        _NPM,
        "is a Yarn lock file, which this tool does not read",
        "Run `npm install --package-lock-only` to generate one.",
    ),
    "pnpm-lock.yaml": _UnreadableRule(
        _NPM,
        "is a pnpm lock file, which this tool does not read",
        "Run `npm install --package-lock-only` to generate one.",
    ),
    # Python.
    "pipfile": _UnreadableRule(
        _PYTHON,
        "declares version constraints, not resolved versions, so there is "
        "nothing to score drift against",
        "Run `pipenv lock` to generate Pipfile.lock.",
    ),
    "poetry.lock": _UnreadableRule(
        _PYTHON, "is a Poetry lock file, which this tool does not read"
    ),
    "uv.lock": _UnreadableRule(
        _PYTHON, "is a uv lock file, which this tool does not read"
    ),
    "setup.py": _UnreadableRule(
        _PYTHON, "declares dependencies in Python code, which this tool does not run"
    ),
    "setup.cfg": _UnreadableRule(
        _PYTHON, "declares dependencies in a form this tool does not read"
    ),
    # Go.
    "go.sum": _UnreadableRule(
        _GO, "is a checksum database, not a list of the modules a project requires"
    ),
    # Rust. The inverse of the npm case: here it is the *lock* file that is not
    # read and the range-declaring manifest that is.
    "cargo.lock": _UnreadableRule(_RUST, "is a lock file this tool does not read"),
    # Ruby.
    "gemfile": _UnreadableRule(
        _RUBY,
        "declares version constraints, not resolved versions, so there is "
        "nothing to score drift against",
        "Run `bundle install` to generate one.",
    ),
    # PHP.
    "composer.json": _UnreadableRule(
        _PHP,
        "declares version constraints, not resolved versions, so there is "
        "nothing to score drift against",
        "Run `composer install` to generate one.",
    ),
    # .NET.
    "packages.config": _UnreadableRule(
        _NUGET,
        "is the legacy NuGet package format, which this tool does not read",
        "Run `dotnet restore --use-lock-file` to generate packages.lock.json.",
    ),
    "directory.packages.props": _UnreadableRule(
        _NUGET,
        "supplies Central Package Management versions to the projects that "
        "reference it; it is not a dependency list of its own",
    ),
    # Gradle. build.gradle and build.gradle.kts are read (#101); these are the
    # files around them that are not.
    "settings.gradle": _UnreadableRule(
        _GRADLE, "configures the build; it does not declare the dependencies"
    ),
    "settings.gradle.kts": _UnreadableRule(
        _GRADLE, "configures the build; it does not declare the dependencies"
    ),
    "libs.versions.toml": _UnreadableRule(
        _GRADLE,
        "is a version catalog: it supplies versions to a build file, and "
        "declares no dependencies of its own",
    ),
    # Maven.
    "maven_install.json": _UnreadableRule(
        _MAVEN, "is a rules_jvm_external lock file, which this tool does not read"
    ),
    # Ecosystems with no parser at all.
    "build.sbt": _UnreadableRule(_SBT, "is an sbt build definition"),
    "podfile": _UnreadableRule(_COCOAPODS, "is a CocoaPods manifest"),
    "podfile.lock": _UnreadableRule(_COCOAPODS, "is a CocoaPods lock file"),
    "package.swift": _UnreadableRule(_SWIFTPM, "is a Swift package manifest"),
    "package.resolved": _UnreadableRule(_SWIFTPM, "is a Swift package lock file"),
    "pubspec.yaml": _UnreadableRule(_PUB, "is a pub manifest"),
    "pubspec.lock": _UnreadableRule(_PUB, "is a pub lock file"),
    "mix.exs": _UnreadableRule(_HEX, "is a Mix project definition"),
    "mix.lock": _UnreadableRule(_HEX, "is a Mix lock file"),
}

# The same table, keyed by suffix, for the manifests whose name is the project's
# rather than the ecosystem's.
_UNREADABLE_BY_SUFFIX: Dict[str, _UnreadableRule] = {
    ".vbproj": _UnreadableRule(
        _NUGET,
        "is an MSBuild project this tool does not read; of the project types "
        "only *.csproj is",
        "Run `dotnet restore --use-lock-file` to generate packages.lock.json.",
    ),
    ".fsproj": _UnreadableRule(
        _NUGET,
        "is an MSBuild project this tool does not read; of the project types "
        "only *.csproj is",
        "Run `dotnet restore --use-lock-file` to generate packages.lock.json.",
    ),
    ".gemspec": _UnreadableRule(
        _RUBY,
        "declares runtime dependencies as constraints, not resolved versions",
        "Run `bundle install` to generate one.",
    ),
}


@dataclass(frozen=True)
class UnreadableManifest:
    """A file recognized as a dependency manifest that this tool cannot read.

    ``supported_input_present`` is the field that keeps a directory scan from
    crying wolf: when a supported input for the same ecosystem sits in the same
    directory, the ecosystem *was* read and this file is not a gap in coverage.
    It is recorded rather than acted on here, because the single-file path must
    still answer for a file the user named explicitly.
    """

    path: Path
    ecosystem: str
    guidance: str
    supported_input_present: bool


def recognise_unreadable_manifest(manifest_path: str) -> Optional[UnreadableManifest]:
    """Recognize a manifest this tool cannot read, from its filename alone.

    Opens no file, so a recursive directory walk can call it per entry. Returns
    ``None`` for anything the table does not name — including every manifest the
    registry *does* read, which is asserted rather than assumed.

    Args:
        manifest_path: Path to the candidate file. Need not exist.

    Returns:
        The recognition, or ``None`` when the name is not a recognized manifest.
    """
    path = Path(manifest_path)
    rule = _unreadable_rule_for_name(path.name)
    if rule is None:
        return None
    found = _first_supported_input(path.parent, rule.ecosystem)
    return _recognised(
        path, rule, None if found is None else str(found), str(path.parent)
    )


def recognise_unreadable_manifest_in_listing(
    manifest_path: str,
    listing: Iterable[str],
    *,
    location: str,
) -> Optional[UnreadableManifest]:
    """Recognize an unreadable manifest against a listing instead of a filesystem.

    Same table, same message, no I/O at all: ``listing`` supplies the paths that
    exist beside the manifest, so this works on a remote tree the scanner has
    already fetched. That matters beyond convenience — resolving a
    repository-relative name against the local filesystem would let a stray
    ``package-lock.json`` in the operator's working directory mark somebody
    else's repository as covered (#262).

    Args:
        manifest_path: Repository-relative path of the candidate manifest.
        listing: Repository-relative paths of the manifests that *are* read.
            Only entries in the same directory as ``manifest_path`` are
            consulted.
        location: How to name the containing directory in the message, e.g.
            ``acme/web:frontend``. Required, because the local-filesystem
            spelling would be a lie here.

    Returns:
        The recognition, or ``None`` when the name is not a recognized manifest.
    """
    path = PurePosixPath(manifest_path)
    rule = _unreadable_rule_for_name(path.name)
    if rule is None:
        return None
    found = _first_listed_supported_input(path, rule.ecosystem, listing)
    return _recognised(Path(manifest_path), rule, found, location)


def is_vendored_relative_path(relative_path: str) -> bool:
    """Whether a path sits inside an installed-dependency directory.

    Scoped to the unreadable-manifest sweep on both the local and the org path.
    Which files get *scored* is not narrowed by this, because that would change
    what the tool analyzes and needs its own evidence.

    Args:
        relative_path: A path relative to the scan root or repository root.

    Returns:
        Whether any directory component names a vendored tree.
    """
    parts = PurePosixPath(relative_path).parts[:-1]
    return any(part in _VENDORED_DIRECTORIES for part in parts)


def is_recognized_unreadable_name(file_name: str) -> bool:
    """Whether a bare file name is a dependency manifest this tool cannot read.

    Filename-only and free of I/O, so a caller holding a whole repository tree
    can afford to run it on every blob without a second request. It exists so
    the org scanner's tree filter and the guidance messages read from one table
    rather than two (#262).

    Args:
        file_name: A file name or path; only the final component is used.

    Returns:
        Whether the name is in the recognized-but-unreadable table.
    """
    return _unreadable_rule_for_name(PurePosixPath(file_name).name) is not None


def _recognised(
    path: Path,
    rule: _UnreadableRule,
    found: Optional[str],
    location: str,
) -> UnreadableManifest:
    """Assemble the recognition shared by the filesystem and listing entries."""
    return UnreadableManifest(
        path=path,
        ecosystem=rule.ecosystem.label,
        guidance=_describe(path.name, rule, found, location),
        supported_input_present=found is not None,
    )


def unsupported_manifest_guidance(manifest_path: str) -> Optional[str]:
    """Return a next step for a refused manifest, or ``None`` when there is none.

    ``None`` means the caller should keep today's generic message: the file is
    not a recognized manifest and does not look like a supported manifest
    wearing the wrong name.
    """
    path = Path(manifest_path)
    recognised = recognise_unreadable_manifest(manifest_path)
    if recognised is not None:
        return recognised.guidance
    return _misnamed_guidance(path)


def _unreadable_rule_for_name(file_name: str) -> Optional[_UnreadableRule]:
    """Look one bare file name up in the recognized-unreadable table."""
    by_name = _UNREADABLE_BY_NAME.get(file_name.lower())
    if by_name is not None:
        return by_name
    return _UNREADABLE_BY_SUFFIX.get(PurePosixPath(file_name).suffix.lower())


def _describe(
    file_name: str,
    rule: _UnreadableRule,
    found: Optional[str],
    location: str,
) -> str:
    """Build the whole message: what this file is, and what is read instead."""
    opening = f"{file_name} {rule.reason}."
    ecosystem = rule.ecosystem

    if not ecosystem.inputs:
        return (
            f"{opening} {ecosystem.label} is not one of the ecosystems this tool "
            "reads — run `dependency-risk-profiler list-ecosystems` to see the "
            "ones it does."
        )

    reads = f"{ecosystem.label} projects are read from {_join(ecosystem.inputs)}"
    if found is not None:
        return f"{opening} {reads}, found alongside it at {found} — point me there."

    # Singular and plural are spelled differently on purpose: "not found in" is
    # a statement about one named file, and there is more than one here.
    absence = "not found in" if len(ecosystem.inputs) == 1 else "none found in"
    located = f"{opening} {reads} — {absence} {location}."
    return f"{located} {rule.remedy}" if rule.remedy else located


def _first_listed_supported_input(
    path: PurePosixPath, ecosystem: _Ecosystem, listing: Iterable[str]
) -> Optional[str]:
    """Return the first supported input for an ecosystem beside a listed path.

    The listing's own spelling is returned rather than a reconstructed one, so
    the message quotes a path the caller can actually go and open.
    """
    siblings = [
        candidate
        for candidate in (PurePosixPath(entry) for entry in listing)
        if candidate.parent == path.parent and candidate != path
    ]
    for name in ecosystem.inputs:
        for sibling in siblings:
            if fnmatch.fnmatch(sibling.name.lower(), name.lower()):
                return str(sibling)
    return None


def _join(names: Tuple[str, ...]) -> str:
    """Render supported input names as English, with no Oxford-comma surprises."""
    if len(names) == 1:
        return names[0]
    return f"{', '.join(names[:-1])}, or {names[-1]}"


def _first_supported_input(directory: Path, ecosystem: _Ecosystem) -> Optional[Path]:
    """Return the first supported input for an ecosystem present in a directory.

    Checking rather than asserting matters: telling someone to run a file that
    is not there is its own dead end, so the message says which case it is.
    """
    for name in ecosystem.inputs:
        found = (
            _existing_glob(directory, name)
            if name.startswith("*")
            else _existing_companion(directory, name)
        )
        if found is not None:
            return found
    return None


def _existing_glob(directory: Path, pattern: str) -> Optional[Path]:
    """Return the first file matching a supported-input glob such as ``*.csproj``."""
    try:
        matches = sorted(directory.glob(pattern))
    except OSError:
        return None
    for match in matches:
        if match.is_file():
            return match
    return None


def _existing_companion(directory: Path, companion: str) -> Optional[Path]:
    """Return the companion file next to the input, matching case-insensitively."""
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
