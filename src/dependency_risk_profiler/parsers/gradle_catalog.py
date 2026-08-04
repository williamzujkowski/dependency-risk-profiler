"""Gradle version-catalog resolution (#101).

A modern Gradle build does not pin a version on the declaration. It names an
alias, and the version lives once in ``gradle/libs.versions.toml``::

    // okhttp/build.gradle.kts
    api(libs.square.okio)

    # gradle/libs.versions.toml
    [versions]
    square-okio = "3.18.1"
    [libraries]
    square-okio = { module = "com.squareup.okio:okio", version.ref = "square-okio" }

This is the third ecosystem to declare versions somewhere other than the
manifest being scanned, after Maven's ``<dependencyManagement>`` and imported
BOMs (#141) and NuGet's ``Directory.Packages.props`` Central Package Management
(#129). It is the same fact wearing a third syntax, so it reuses the vocabulary
those two share — :mod:`.version_sources` — rather than inventing a fourth
spelling for "the version is declared somewhere this scan could not reach".
That reuse is why #164 held this adapter back until the concept existed in two
places: a third one-off would have made the concept a coincidence instead of a
contract.

Resolution follows Gradle's rules as far as a static read can honestly go: the
nearest ``gradle/libs.versions.toml`` walking up from the build script, aliases
normalised the way Gradle's generated accessors normalise them, and rich
versions read for the constraint that actually names a version.

Deliberately not modelled, because guessing would be worse than declining:

* Catalogs under a name other than ``libs``, and catalogs declared inline in
  ``settings.gradle`` via ``versionCatalogs { }``. Both need the settings script
  evaluated, and evaluating a settings script means running Gradle.
* ``from(files(...))`` catalog imports and published catalog artifacts. The
  version is then in a file or an artifact this scan cannot see, which is
  exactly the case :data:`~.version_sources.VERSION_SOURCE_UNMANAGED` exists to
  describe.
* ``prefer`` on its own. Gradle documents it as a preference that a conflict
  resolution may override, so it does not state the version that gets used the
  way ``require`` and ``strictly`` do.
* Dynamic constraints (``1.+``, ``[1.0,2.0)``). Same reasoning as NuGet's
  floating ``1.2.*``: they name the version a resolution would pick, not one the
  catalog states.

Anything unresolved is reported as unmanaged, never as an empty string (#74,
#141).
"""

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional, Tuple

from .gradle_dsl import MAX_ANCESTOR_DEPTH, concrete_version

logger = logging.getLogger(__name__)

# Where Gradle looks for the conventional catalog, relative to the settings
# directory. The build script's directory is where the walk starts.
CATALOG_DIRECTORY = "gradle"
CATALOG_FILENAME = "libs.versions.toml"

# Accessor segments that address something other than a library.
VERSIONS_SEGMENT = "versions"
BUNDLES_SEGMENT = "bundles"
PLUGINS_SEGMENT = "plugins"

# Rich-version keys that name the version a resolution will use. ``prefer`` is
# absent on purpose; see the module docstring.
_BINDING_CONSTRAINTS = ("strictly", "require")


@dataclass(frozen=True)
class CatalogLibrary:
    """One ``[libraries]`` entry, with its version already looked up.

    Attributes:
        group: Maven group id.
        artifact: Maven artifact id.
        version: The version the catalog states, or None when it states one
            this scan cannot reduce to a single value — an unresolvable
            ``version.ref``, a dynamic constraint, a bare ``prefer``.
    """

    group: str
    artifact: str
    version: Optional[str]

    @property
    def key(self) -> str:
        """Return the ``groupId:artifactId`` key, matching Maven's identity."""
        return f"{self.group}:{self.artifact}"


@dataclass(frozen=True)
class VersionCatalog:
    """The libraries and bundles one ``libs.versions.toml`` declares.

    Attributes:
        path: Where the catalog was found, for logging and tests.
        libraries: Normalised alias to its library entry.
        bundles: Normalised bundle alias to the normalised library aliases it
            names.
    """

    path: Path
    libraries: Mapping[str, CatalogLibrary]
    bundles: Mapping[str, Tuple[str, ...]]

    def library_for(self, accessor: Tuple[str, ...]) -> Optional[CatalogLibrary]:
        """Return the library a ``libs.a.b`` accessor path names, or None.

        Args:
            accessor: The accessor segments after ``libs.``.

        Returns:
            The catalog entry, or None when the accessor names no library —
            including when it addresses a version or a plugin, neither of which
            is a dependency.
        """
        if not accessor or accessor[0] in (VERSIONS_SEGMENT, PLUGINS_SEGMENT):
            return None
        return self.libraries.get(normalize_alias(".".join(accessor)))

    def bundle_for(self, accessor: Tuple[str, ...]) -> Optional[Tuple[str, ...]]:
        """Return the library aliases a ``libs.bundles.x`` accessor names.

        Args:
            accessor: The accessor segments after ``libs.``.

        Returns:
            The bundle's member aliases, or None when this is not a bundle
            accessor or names no declared bundle.
        """
        if len(accessor) < 2 or accessor[0] != BUNDLES_SEGMENT:
            return None
        return self.bundles.get(normalize_alias(".".join(accessor[1:])))


def normalize_alias(alias: str) -> str:
    """Return an alias in the one spelling accessors and declarations share.

    Gradle generates ``libs.square.okio`` for a catalog alias written
    ``square-okio``, ``square_okio`` or ``square.okio``, so the three separators
    are interchangeable and the lookup has to say so. Case is preserved:
    ``gradlePlugin-android`` generates ``libs.gradlePlugin.android``, and
    lowercasing here would merge aliases Gradle keeps apart.

    Args:
        alias: A catalog alias or an accessor path.

    Returns:
        The alias with ``-`` and ``_`` replaced by ``.``.
    """
    return alias.replace("-", ".").replace("_", ".")


def find_version_catalog(start_directory: Path) -> Optional[Path]:
    """Return the nearest ``gradle/libs.versions.toml`` at or above a directory.

    Gradle resolves the conventional catalog relative to the settings
    directory, which is at or above every build script in the build, so the
    walk goes up and stops at the first hit.

    Args:
        start_directory: The build script's own directory.

    Returns:
        Path to the catalog, or None when the walk reaches the filesystem root
        (or the depth bound) without finding one.
    """
    try:
        current = start_directory.resolve()
    except OSError as exc:
        logger.debug("Could not resolve %s: %s", start_directory, exc)
        return None

    for depth, directory in enumerate([current, *current.parents]):
        if depth >= MAX_ANCESTOR_DEPTH:
            logger.debug(
                "Stopping the %s/%s search at %d ancestors of %s",
                CATALOG_DIRECTORY,
                CATALOG_FILENAME,
                MAX_ANCESTOR_DEPTH,
                start_directory,
            )
            return None
        candidate = directory / CATALOG_DIRECTORY / CATALOG_FILENAME
        try:
            if candidate.is_file():
                return candidate
        except OSError as exc:
            logger.debug("Could not stat %s: %s", candidate, exc)
    return None


def read_version_catalog(path: Path) -> Optional[VersionCatalog]:
    """Parse a ``libs.versions.toml`` into its library and bundle tables.

    Args:
        path: Path to the catalog file.

    Returns:
        The parsed catalog, or None when the file cannot be read or parsed.
    """
    document = _load_toml(path)
    if document is None:
        return None

    versions = _read_versions(document.get("versions"))
    libraries: Dict[str, CatalogLibrary] = {}
    raw_libraries = document.get("libraries")
    if isinstance(raw_libraries, dict):
        for alias, entry in raw_libraries.items():
            library = _read_library(entry, versions)
            if library is not None:
                libraries[normalize_alias(str(alias))] = library

    bundles: Dict[str, Tuple[str, ...]] = {}
    raw_bundles = document.get("bundles")
    if isinstance(raw_bundles, dict):
        for alias, members in raw_bundles.items():
            if not isinstance(members, list):
                continue
            bundles[normalize_alias(str(alias))] = tuple(
                normalize_alias(member) for member in members if isinstance(member, str)
            )

    return VersionCatalog(path=path, libraries=libraries, bundles=bundles)


def _load_toml(path: Path) -> Optional[Dict[str, object]]:
    """Read a TOML file with the standard-library parser.

    ``tomllib`` ships with Python 3.11 and ``tomli`` is already a dependency
    below it, which is what the existing :mod:`.toml` parser uses; a version
    catalog needs no more than that.

    Args:
        path: Path to the TOML file.

    Returns:
        The parsed document, or None when it cannot be read or parsed.
    """
    if sys.version_info >= (3, 11):
        import tomllib as toml_reader
    else:
        import tomli as toml_reader

    try:
        with path.open("rb") as handle:
            document = toml_reader.load(handle)
    except (OSError, toml_reader.TOMLDecodeError) as exc:
        logger.warning("Could not read the Gradle version catalog %s: %s", path, exc)
        return None
    return document


def _read_versions(table: object) -> Dict[str, Optional[str]]:
    """Return the ``[versions]`` table, each entry reduced to one version or None."""
    versions: Dict[str, Optional[str]] = {}
    if not isinstance(table, dict):
        return versions
    for alias, value in table.items():
        versions[normalize_alias(str(alias))] = _read_version_value(value)
    return versions


def _read_version_value(value: object) -> Optional[str]:
    """Return the single version a ``[versions]`` entry names, or None.

    Args:
        value: A version string, or a rich-version table.

    Returns:
        The concrete version, or None when the entry names a range, a bare
        preference, or something that is not a version at all.
    """
    if isinstance(value, str):
        return concrete_version(value)
    if isinstance(value, dict):
        for constraint in _BINDING_CONSTRAINTS:
            stated = value.get(constraint)
            if isinstance(stated, str):
                return concrete_version(stated)
    return None


def _read_library(
    entry: object, versions: Mapping[str, Optional[str]]
) -> Optional[CatalogLibrary]:
    """Read one ``[libraries]`` entry in any of the spellings Gradle accepts.

    Args:
        entry: The alias's value: the ``"group:name:version"`` shorthand, or a
            table using ``module`` or ``group``/``name``, with ``version``,
            ``version.ref`` or a rich-version table.
        versions: The parsed ``[versions]`` table, for ``version.ref``.

    Returns:
        The library, or None when the entry names no resolvable coordinate.
    """
    if isinstance(entry, str):
        return _split_module(entry)
    if not isinstance(entry, dict):
        return None

    module = entry.get("module")
    if isinstance(module, str):
        coordinate = _split_module(module)
    else:
        group, artifact = entry.get("group"), entry.get("name")
        if not isinstance(group, str) or not isinstance(artifact, str):
            return None
        coordinate = _split_module(f"{group.strip()}:{artifact.strip()}")
    if coordinate is None:
        return None

    return CatalogLibrary(
        group=coordinate.group,
        artifact=coordinate.artifact,
        version=_entry_version(entry, versions) or coordinate.version,
    )


def _entry_version(
    entry: Mapping[str, object], versions: Mapping[str, Optional[str]]
) -> Optional[str]:
    """Return the version a ``[libraries]`` table entry states, or None.

    ``version.ref`` arrives from the TOML parser as a nested ``version`` table
    with a ``ref`` key, because ``version.ref = "x"`` is dotted-key syntax.

    Args:
        entry: The library's table.
        versions: The parsed ``[versions]`` table.

    Returns:
        The concrete version, or None when none is resolvable.
    """
    stated = entry.get("version")
    if isinstance(stated, str):
        return concrete_version(stated)
    if isinstance(stated, dict):
        reference = stated.get("ref")
        if isinstance(reference, str):
            return versions.get(normalize_alias(reference))
        for constraint in _BINDING_CONSTRAINTS:
            value = stated.get(constraint)
            if isinstance(value, str):
                return concrete_version(value)
    return None


def _split_module(module: str) -> Optional[CatalogLibrary]:
    """Split ``group:name`` or ``group:name:version`` into a library entry."""
    parts = module.split(":")
    if len(parts) < 2:
        return None
    group, artifact = parts[0].strip(), parts[1].strip()
    if not group or not artifact:
        return None
    version = concrete_version(parts[2]) if len(parts) > 2 else None
    return CatalogLibrary(group=group, artifact=artifact, version=version)
