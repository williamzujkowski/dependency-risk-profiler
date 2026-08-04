"""Bounded, non-evaluating reading of Gradle's Groovy and Kotlin build scripts.

``build.gradle`` and ``build.gradle.kts`` are not manifests. They are programs —
Groovy and Kotlin respectively — and a dependency coordinate in one can be
computed at configuration time from an environment variable, a git describe, or
a function defined three files away. Nothing here evaluates them, because the
only honest way to evaluate a Gradle build is to run Gradle, and a risk scanner
that shells out to an untrusted build script has become the supply-chain problem
it was hired to find.

What this module does instead is read the *declarative* shapes, which is where
the overwhelming majority of real declarations live, and refuse to guess at the
rest. Refusal is not a silent skip: a declaration whose version cannot be
established statically is still reported, with its version marked
:data:`~.version_sources.VERSION_SOURCE_UNMANAGED`, so the scorer drops the
version-drift signal from both numerator and denominator (#74) rather than
scoring a fabricated zero. That is the contract #141 set for Maven's inherited
versions and #199 made the default direction everywhere.

Shapes that are read
--------------------
Inside a ``dependencies { }`` block, at any nesting depth (Kotlin Multiplatform
keeps one inside every source set, so depth matters and a top-level-only reader
finds nothing in a modern Kotlin project):

* String notation, either DSL, with or without parentheses::

      implementation 'com.squareup.okio:okio:3.18.1'
      implementation("com.squareup.okio:okio:3.18.1")
      testImplementation "junit:junit:$junitVersion"
      signature "org.codehaus.mojo.signature:java18:1.0@signature"

  The Gradle string form is ``group:name:version:classifier@extension``; the
  classifier and extension are stripped, since neither changes which artifact
  the advisory databases key on.

* Map notation, either DSL::

      implementation group: 'org.x', name: 'y', version: '1.2'
      implementation(group = "org.x", name = "y", version = "1.2")

* Version-catalog accessors — ``libs.square.okio``, ``libs.bundles.testing`` —
  resolved against ``gradle/libs.versions.toml`` by :mod:`.gradle_catalog`.

* ``platform(...)``, ``enforcedPlatform(...)`` and ``testFixtures(...)``
  wrappers, unwrapped to the coordinate inside. A BOM is itself a published
  artifact with its own advisories, so it is reported rather than discarded.

* ``kotlin("reflect")``, which is sugar for ``org.jetbrains.kotlin:kotlin-reflect``
  at whatever version the Kotlin plugin pins. The coordinate is recoverable and
  the version is not, so it is reported as unmanaged rather than dropped —
  dropping it would understate the dependency count, which is the worse error.

* ``$name`` / ``${name}`` interpolation in a version position, expanded from an
  ``ext { }`` block, a top-level ``val``/``def`` literal assignment, and any
  ``gradle.properties`` at or above the project directory.

Shapes that are deliberately not read
-------------------------------------
Each of these is *reported as unmeasured* where a coordinate is recoverable and
skipped where one is not. None of them is guessed at.

* Anything computed. ``implementation("$group:$name:${resolveVersion()}")``,
  a coordinate built in a helper function, a dependency added from a ``forEach``
  over a list, a ``dependencies`` block behind an ``if``. Reading these means
  executing the script.
* Dynamic versions — ``1.+``, ``[1.0,2.0)``, ``latest.release``. They name the
  version a resolution would pick, not one this file states, exactly like
  NuGet's floating ``1.2.*`` (#129).
* ``buildscript { dependencies { } }`` and ``pluginManagement``. Those are the
  build's own tooling classpath, the Gradle counterpart of Maven's
  ``<build><plugins>``, which ``MavenPomParser`` does not read either.
* ``constraints { }`` blocks. A constraint states a version for a dependency
  somebody else declares; counting it would double-count the dependency.
* Project dependencies — ``project(":core")``, ``projects.core`` — and file
  dependencies — ``files(...)``, ``fileTree(...)``, ``gradleApi()``. None is a
  published package, so none has a registry to score against.
* Catalogs under a name other than the default ``libs``, and catalogs declared
  inline in ``settings.gradle``. Both need the settings script evaluated.
* ``gradle.lockfile``. Gradle's dependency locking is opt-in and rare in the
  wild; when it does exist it states resolved versions, and reading it is a
  strictly additive follow-up rather than part of this contract.

The parse itself is bounded: one linear pass over the file with a fixed nesting
budget, no backtracking, no recursion into other scripts, and no ``apply from:``
following. A build script that nests deeper than :data:`MAX_BLOCK_DEPTH` stops
being read rather than costing unbounded memory.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)

# The two build-script names Gradle itself looks for.
BUILD_FILE_NAMES: Tuple[str, ...] = ("build.gradle", "build.gradle.kts")

# Java-properties file Gradle reads project properties from.
GRADLE_PROPERTIES_FILENAME = "gradle.properties"

# How far up the tree the ``gradle.properties`` search walks. Gradle itself
# reads the project's own and the one beside the settings script; a bound keeps
# "one parse cannot become thousands of stats" true on a deep temp path, the
# same reasoning as ``nuget_cpm.MAX_ANCESTOR_DEPTH``.
MAX_ANCESTOR_DEPTH = 64

# A build script nested deeper than this has stopped being declarative. The
# deepest real shape is a Kotlin Multiplatform source-set dependencies block,
# around six levels in.
MAX_BLOCK_DEPTH = 64

# Bounded expansion of ``$a`` referring to a property that is itself ``$b``.
_MAX_PROPERTY_PASSES = 8

# Blocks whose contents are not project dependencies, checked anywhere in the
# enclosing block stack.
_EXCLUDED_BLOCKS = frozenset({"buildscript", "pluginManagement", "constraints"})

# The block whose statements are dependency declarations.
_DEPENDENCIES_BLOCK = "dependencies"

# The block that declares Gradle project properties.
_EXT_BLOCK = "ext"

# A Gradle configuration name — ``implementation``, ``testRuntimeOnly``, or any
# custom configuration the build registers. Matching the shape rather than a
# fixed list is deliberate: custom configurations are ordinary in real builds
# (RxJava declares ``signature`` and ``jmh``), and a fixed list would silently
# drop them.
_IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_]*"

# Statement heads that are never a dependency declaration. Everything else that
# looks like ``name <argument>`` inside a dependencies block is treated as one.
_NOT_CONFIGURATIONS = frozenset(
    {
        "add",
        "apply",
        "artifact",
        "attributes",
        "because",
        "capabilities",
        "constraint",
        "create",
        "def",
        "dependencies",
        "else",
        "exclude",
        "extendsFrom",
        "for",
        "force",
        "from",
        "if",
        "import",
        "isForce",
        "isTransitive",
        "it",
        "package",
        "register",
        "return",
        "transitive",
        "val",
        "var",
        "version",
        "while",
    }
)

# Argument wrappers that decorate a coordinate without changing which artifact
# it names.
_WRAPPERS = ("platform", "enforcedPlatform", "testFixtures")

# Argument heads that name something with no registry behind it.
_NON_PACKAGE_ARGUMENTS = (
    "project",
    "projects",
    "files",
    "fileTree",
    "gradleApi",
    "gradleTestKit",
    "localGroovy",
    "embeddedKotlin",
)

# ``kotlin("reflect")`` expands to this group with the artifact prefixed.
_KOTLIN_SUGAR_GROUP = "org.jetbrains.kotlin"
_KOTLIN_SUGAR_PREFIX = "kotlin-"

# Version catalog accessors all hang off the default catalog name. A build that
# renames its catalog needs the settings script evaluated, so it is out.
_DEFAULT_CATALOG_ACCESSOR = "libs"

_STATEMENT_HEAD = re.compile(rf"^({_IDENTIFIER})\s*(.*)$", re.DOTALL)
_WRAPPER_CALL = re.compile(rf"^({'|'.join(_WRAPPERS)})\s*\(\s*(.*?)\s*\)$", re.DOTALL)
_KOTLIN_SUGAR = re.compile(
    r"^kotlin\s*\(\s*(['\"])(.*?)\1\s*(?:,\s*(.*))?\)$", re.DOTALL
)
_CATALOG_ACCESSOR = re.compile(
    rf"^{_DEFAULT_CATALOG_ACCESSOR}((?:\.{_IDENTIFIER})+)\s*$"
)
_BLOCK_HEAD = re.compile(rf"({_IDENTIFIER})\s*(?:\([^()]*\))?\s*$")
_LITERAL_ASSIGNMENT = re.compile(
    rf"^(?:val\s+|var\s+|def\s+)?({_IDENTIFIER})\s*=\s*(['\"])(.*?)\2$", re.DOTALL
)

# ``$name`` and ``${name}``. Gradle allows a full expression inside ``${}``;
# only a bare property reference is expanded, and anything else is left in
# place so the caller can see the version never resolved.
_INTERPOLATION = re.compile(
    r"\$\{\s*(" + _IDENTIFIER + r")\s*\}|\$(" + _IDENTIFIER + r")"
)

# A concrete Gradle/Maven version. Deliberately narrower than the version
# strings Gradle accepts: a ``+`` anywhere makes the version dynamic, and the
# bracket forms are ranges. Both name the version a *resolution* would pick
# rather than one this file states, which is NuGet's floating-version case
# (#129) wearing Gradle syntax.
_CONCRETE_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")

# Version keywords that defer the choice to the resolver entirely.
_DYNAMIC_KEYWORDS = frozenset({"latest.release", "latest.integration", "latest"})


@dataclass(frozen=True)
class GradleDeclaration:
    """One dependency declaration as written, before any version resolution.

    Attributes:
        configuration: The configuration it was declared on, e.g.
            ``implementation``. Kept for diagnostics; every configuration is
            read, the same way ``MavenPomParser`` reads every ``<dependency>``
            regardless of ``<scope>``.
        group: Maven group id, empty when the declaration names a catalog alias
            instead of a coordinate.
        artifact: Maven artifact id, empty in the same case.
        raw_version: The version exactly as written, interpolation included, or
            None when the declaration states none.
        catalog_path: The accessor path after ``libs.`` — ``("square", "okio")``
            for ``libs.square.okio`` — or None for a literal coordinate.
        source: The statement it was read from, for log messages.
    """

    configuration: str
    group: str
    artifact: str
    raw_version: Optional[str]
    catalog_path: Optional[Tuple[str, ...]]
    source: str

    @property
    def key(self) -> str:
        """Return the ``groupId:artifactId`` key, matching Maven's identity."""
        return f"{self.group}:{self.artifact}"


@dataclass(frozen=True)
class GradleScript:
    """Everything one build script states without being executed.

    Attributes:
        declarations: Dependency declarations, in document order.
        properties: Literal ``name = "value"`` assignments the script makes, from
            ``ext { }`` blocks and top-level ``val``/``def`` bindings.
        unreadable: Count of statements inside a ``dependencies { }`` block that
            declared *something* and whose coordinate could not be read — a
            computed group, an artifact held in a variable, a helper call.
            Reported rather than silently dropped, because it is the honest size
            of this parser's blind spot in a given file, and the number a reader
            needs in order to trust the ones that did come out.
    """

    declarations: Tuple[GradleDeclaration, ...]
    properties: Mapping[str, str]
    unreadable: int


def concrete_version(raw: Optional[str]) -> Optional[str]:
    """Return the one concrete version a Gradle version string names, or None.

    Gradle's version strings span three different things: a point version
    (``3.18.1``), a *dynamic* version whose value only exists after resolution
    (``1.+``, ``[1.0,2.0)``, ``latest.release``), and an unexpanded reference
    (``$okioVersion``). Only the first names a version this file states, so only
    the first is returned; the rest resolve to unmanaged rather than to a number
    this tool made up (#141, #199).

    ``-SNAPSHOT`` is treated as concrete for the same reason ``pom_model``
    does: it is what the project declares, and it is the string Maven Central
    will be asked about.

    Args:
        raw: The declared version string, or None.

    Returns:
        The concrete version, or None when the string does not name one.
    """
    if raw is None:
        return None
    value = raw.strip()
    if not value or "$" in value:
        return None
    if value.lower() in _DYNAMIC_KEYWORDS:
        return None
    if "+" in value:
        return None
    if not _CONCRETE_VERSION.match(value):
        return None
    return value


def expand_properties(value: str, properties: Mapping[str, str]) -> str:
    """Expand ``$name`` / ``${name}`` against a property map.

    Args:
        value: Raw text from a version position, e.g. ``"$okioVersion"``.
        properties: Property name to literal value.

    Returns:
        The expanded string. A reference with no matching property is left in
        place, so :func:`concrete_version` sees the ``$`` and reports the
        version as unmanaged instead of shipping a literal ``$name``.
    """
    expanded = value
    for _ in range(_MAX_PROPERTY_PASSES):
        if "$" not in expanded:
            break

        def _substitute(match: "re.Match[str]") -> str:
            name = match.group(1) or match.group(2)
            return properties.get(name, match.group(0))

        replaced = _INTERPOLATION.sub(_substitute, expanded)
        if replaced == expanded:
            break
        expanded = replaced
    return expanded


def read_gradle_properties(start_directory: Path) -> Dict[str, str]:
    """Return the ``gradle.properties`` values visible from a project directory.

    Gradle reads the project's own properties file and the one beside the
    settings script, with the nearer one winning. The walk here goes upwards and
    lets the nearest definition win, which reproduces that for the layouts that
    exist in practice without needing to find the settings script.

    Args:
        start_directory: The build script's own directory.

    Returns:
        Property name to value, nearest definition winning.
    """
    properties: Dict[str, str] = {}
    try:
        current = start_directory.resolve()
    except OSError as exc:
        logger.debug("Could not resolve %s: %s", start_directory, exc)
        return properties

    for depth, directory in enumerate([current, *current.parents]):
        if depth >= MAX_ANCESTOR_DEPTH:
            break
        candidate = directory / GRADLE_PROPERTIES_FILENAME
        try:
            if not candidate.is_file():
                continue
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("Could not read %s: %s", candidate, exc)
            continue
        for name, value in _parse_properties(text).items():
            # Nearest wins, so an already-seen name is not overwritten.
            properties.setdefault(name, value)
    return properties


def _parse_properties(text: str) -> Dict[str, str]:
    """Parse the ``key=value`` subset of the Java properties format.

    Line continuations and the ``key:value`` spelling are not handled; neither
    appears in a real ``gradle.properties``, and a wrong value here would
    become a wrong version rather than an honest unmanaged one.

    Args:
        text: File contents.

    Returns:
        Property name to value.
    """
    properties: Dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        name, separator, value = stripped.partition("=")
        if not separator:
            continue
        properties[name.strip()] = value.strip()
    return properties


def read_script(text: str) -> GradleScript:
    """Read one build script's declarations and literal properties.

    Args:
        text: The build script source, Groovy or Kotlin.

    Returns:
        Everything the script states without being executed.
    """
    declarations: List[GradleDeclaration] = []
    properties: Dict[str, str] = {}
    unreadable = 0

    for blocks, statement in _statements(text):
        if _EXCLUDED_BLOCKS.intersection(blocks):
            continue
        if _DEPENDENCIES_BLOCK in blocks:
            read, understood = _read_declaration(statement)
            declarations.extend(read)
            if not understood:
                unreadable += 1
            continue
        if blocks and blocks[-1] != _EXT_BLOCK:
            continue
        match = _LITERAL_ASSIGNMENT.match(statement.strip())
        if match is not None:
            properties.setdefault(match.group(1), match.group(3))

    return GradleScript(
        declarations=tuple(declarations),
        properties=properties,
        unreadable=unreadable,
    )


def _read_declaration(statement: str) -> Tuple[List[GradleDeclaration], bool]:
    """Read one statement inside a dependencies block.

    Args:
        statement: The statement text, comments already removed.

    Returns:
        ``(declarations, understood)``. Groovy allows several coordinates on one
        configuration, so the first element is a list. ``understood`` is False
        only when the statement looked like a dependency declaration whose
        coordinate could not be read; the caller counts those so the size of the
        blind spot is reportable rather than invisible.
    """
    text = " ".join(statement.split())
    if not text:
        return [], True

    head = _STATEMENT_HEAD.match(text)
    if head is None:
        return [], True
    configuration, rest = head.group(1), head.group(2).strip()
    if configuration in _NOT_CONFIGURATIONS or not rest:
        return [], True

    if rest.startswith("("):
        if not rest.endswith(")"):
            return [], True
        argument = rest[1:-1].strip()
    else:
        argument = rest
    if not argument:
        return [], True

    return _read_argument(configuration, argument, text)


def _read_argument(
    configuration: str, argument: str, source: str
) -> Tuple[List[GradleDeclaration], bool]:
    """Read the argument of one dependency declaration.

    Args:
        configuration: The configuration the declaration was made on.
        argument: The argument text, parentheses already removed.
        source: The whole statement, for diagnostics.

    Returns:
        The same ``(declarations, understood)`` pair as
        :func:`_read_declaration`.
    """
    for _ in range(MAX_BLOCK_DEPTH):
        wrapper = _WRAPPER_CALL.match(argument)
        if wrapper is None:
            break
        argument = wrapper.group(2).strip()

    if argument.startswith(_NON_PACKAGE_ARGUMENTS):
        # A project or file dependency: real, but with no registry behind it.
        return [], True

    catalog = _CATALOG_ACCESSOR.match(argument)
    if catalog is not None:
        path = tuple(catalog.group(1).lstrip(".").split("."))
        return (
            [
                GradleDeclaration(
                    configuration=configuration,
                    group="",
                    artifact="",
                    raw_version=None,
                    catalog_path=path,
                    source=source,
                )
            ],
            True,
        )

    sugar = _KOTLIN_SUGAR.match(argument)
    if sugar is not None:
        stated = _string_literals(sugar.group(3) or "")
        return (
            [
                GradleDeclaration(
                    configuration=configuration,
                    group=_KOTLIN_SUGAR_GROUP,
                    artifact=f"{_KOTLIN_SUGAR_PREFIX}{sugar.group(2)}",
                    raw_version=stated[0] if stated else None,
                    catalog_path=None,
                    source=source,
                )
            ],
            True,
        )

    mapped = _read_map_notation(configuration, argument, source)
    if mapped is not None:
        return [mapped], True

    literals = [
        literal
        for literal in _string_literals(argument)
        if ":" in literal.split("@")[0]
    ]
    if not literals:
        # A coordinate this parser cannot identify: computed, held in a
        # variable, or produced by a helper. Counted, never guessed at.
        logger.debug("Unreadable Gradle dependency declaration: %s", source)
        return [], False

    declarations: List[GradleDeclaration] = []
    understood = True
    for literal in literals:
        declaration = _read_string_notation(configuration, literal, source)
        if declaration is None:
            understood = False
            continue
        declarations.append(declaration)
    return declarations, understood


def _read_string_notation(
    configuration: str, literal: str, source: str
) -> Optional[GradleDeclaration]:
    """Read ``group:name:version:classifier@extension`` string notation."""
    coordinate = literal.split("@", 1)[0].strip()
    parts = coordinate.split(":")
    if len(parts) < 2:
        return None
    group, artifact = parts[0].strip(), parts[1].strip()
    if not group or not artifact or "$" in group or "$" in artifact:
        # A computed coordinate: it names a real dependency this parser cannot
        # identify, so the caller counts it rather than inventing a name.
        logger.debug("Unreadable Gradle coordinate: %s", source)
        return None
    version = parts[2].strip() if len(parts) > 2 else None
    return GradleDeclaration(
        configuration=configuration,
        group=group,
        artifact=artifact,
        raw_version=version or None,
        catalog_path=None,
        source=source,
    )


def _read_map_notation(
    configuration: str, argument: str, source: str
) -> Optional[GradleDeclaration]:
    """Read ``group: 'x', name: 'y', version: 'z'`` in either DSL's spelling."""
    group = _named_argument(argument, "group")
    artifact = _named_argument(argument, "name") or _named_argument(argument, "module")
    if group is None or artifact is None:
        return None
    return GradleDeclaration(
        configuration=configuration,
        group=group,
        artifact=artifact,
        raw_version=_named_argument(argument, "version"),
        catalog_path=None,
        source=source,
    )


def _named_argument(argument: str, name: str) -> Optional[str]:
    """Return a ``name: 'value'`` or ``name = "value"`` argument's value."""
    pattern = re.compile(rf"(?:^|[,(\s]){re.escape(name)}\s*[:=]\s*(['\"])(.*?)\1")
    match = pattern.search(argument)
    return match.group(2) if match is not None else None


def _string_literals(text: str) -> List[str]:
    """Return the contents of every string literal in ``text``, in order.

    Groovy accepts several coordinates on one configuration
    (``implementation 'a:b:1', 'c:d:2'``), so reading only the first would drop
    a declared dependency rather than report it.

    Args:
        text: An argument list with the enclosing parentheses removed.

    Returns:
        The literals' contents, quotes stripped.
    """
    literals: List[str] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in "\"'":
            literal, index = _read_string(text, index)
            quote = literal[:3] if literal[:3] == char * 3 else char
            body = literal[len(quote) :]
            if body.endswith(quote):
                body = body[: -len(quote)]
            literals.append(body)
            continue
        index += 1
    return literals


def _read_string(text: str, start: int) -> Tuple[str, int]:
    """Read one string literal, returning it with its quotes and the next index.

    Handles both quote characters, backslash escapes and the triple-quoted form
    both DSLs support. An unterminated literal consumes the rest of the input,
    which ends the scan rather than looping.

    Args:
        text: The script source.
        start: Index of the opening quote.

    Returns:
        ``(literal_including_quotes, index_after_it)``.
    """
    quote = text[start]
    triple = text[start : start + 3] == quote * 3
    closing = quote * 3 if triple else quote
    index = start + len(closing)
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if text.startswith(closing, index):
            end = index + len(closing)
            return text[start:end], end
        index += 1
    return text[start:], len(text)


def _statements(text: str) -> List[Tuple[Tuple[str, ...], str]]:
    """Split a build script into statements, each with its enclosing block names.

    One linear pass. Strings and comments are skipped as units so that a brace
    inside a string literal cannot open a block, and a statement is flushed at a
    newline, a semicolon or a brace — except while parentheses or brackets are
    open, which is what keeps a declaration split across lines in one piece.

    Args:
        text: The build script source.

    Returns:
        ``(block_stack, statement)`` pairs in document order. A block's own
        header is emitted as a statement too, so ``implementation(libs.x) { }``
        is read rather than swallowed as a block opener.
    """
    statements: List[Tuple[Tuple[str, ...], str]] = []
    blocks: List[str] = []
    buffer: List[str] = []
    nesting = 0
    index = 0
    length = len(text)

    def flush() -> str:
        pending = "".join(buffer).strip()
        buffer.clear()
        if pending:
            statements.append((tuple(blocks), pending))
        return pending

    while index < length:
        char = text[index]

        if char in "\"'":
            literal, index = _read_string(text, index)
            buffer.append(literal)
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue

        if char in "([":
            nesting += 1
        elif char in ")]":
            nesting = max(0, nesting - 1)

        if char == "{" and nesting == 0:
            header = flush()
            match = _BLOCK_HEAD.search(header)
            if len(blocks) < MAX_BLOCK_DEPTH:
                blocks.append(match.group(1) if match is not None else "")
            index += 1
            continue
        if char == "}" and nesting == 0:
            flush()
            if blocks:
                blocks.pop()
            index += 1
            continue
        if char in "\n;" and nesting == 0:
            flush()
            index += 1
            continue

        buffer.append(char)
        index += 1

    flush()
    return statements
