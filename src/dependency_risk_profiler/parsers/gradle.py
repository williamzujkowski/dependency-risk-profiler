"""Parser for Gradle build scripts (``build.gradle`` / ``build.gradle.kts``).

Gradle publishes and consumes Maven coordinates, so a dependency read here is
the same ``groupId:artifactId`` a ``pom.xml`` would have produced and routes to
the same Maven Central metadata and the same OSV *Maven* ecosystem. That is a
routing alias in :mod:`..vulnerabilities.ecosystems`, not a new ecosystem key:
an advisory against ``com.squareup.okio:okio`` does not become a different
advisory because a Kotlin project declared it.

What is new is the *reading*. Where Maven parses a schema, this parses two
programming languages without running them, which is a materially weaker
position and is treated as one. :mod:`.gradle_dsl` documents exactly which
declarative shapes are read and which are refused; :mod:`.gradle_catalog` does
the same for the version catalog. The contract both serve is the one #141 set
and #199 generalised: where a version cannot be established statically, the
dependency is still reported and its version is marked
:data:`~.version_sources.VERSION_SOURCE_UNMANAGED`, so the scorer drops
version-drift from both numerator and denominator (#74) instead of scoring a
fabricated zero. A Gradle file this parser reads at 80% and is honest about is
worth more than one it reads at 100% by guessing.
"""

import logging
from typing import Dict, List, Optional, Tuple

from ..models import DependencyMetadata
from .base import BaseParser
from .gradle_catalog import (
    CATALOG_DIRECTORY,
    CATALOG_FILENAME,
    CatalogLibrary,
    VersionCatalog,
    find_version_catalog,
    read_version_catalog,
)
from .gradle_dsl import (
    GradleDeclaration,
    concrete_version,
    expand_properties,
    read_gradle_properties,
    read_script,
)
from .version_sources import (
    VERSION_SOURCE_CATALOG,
    VERSION_SOURCE_DECLARED,
    VERSION_SOURCE_KEY,
    VERSION_SOURCE_UNMANAGED,
)

logger = logging.getLogger(__name__)

# Re-exported so importers of the Gradle parser get the shared vocabulary from
# one place, the way ``parsers.maven`` re-exports it rather than owning it.
__all__ = [
    "GradleParser",
    "VERSION_SOURCE_CATALOG",
    "VERSION_SOURCE_DECLARED",
    "VERSION_SOURCE_KEY",
    "VERSION_SOURCE_UNMANAGED",
]

# How many bytes of a build script to read. Gradle scripts are source files, not
# generated documents; the largest in the wild are tens of kilobytes, and a
# bound keeps a hostile or generated file from costing memory.
MAX_SCRIPT_BYTES = 4 * 1024 * 1024


class GradleParser(BaseParser):
    """Parser for Gradle build scripts in either DSL.

    Versions resolve in the order Gradle resolves them for the declarative
    shapes: a version stated on the declaration, then the version catalog the
    declaration's alias points at. Anything still unresolved — an unreachable
    catalog, a dynamic ``1.+``, a version interpolated from something only the
    build knows — is marked ``unmanaged`` rather than guessed, the same contract
    Maven's inherited versions (#141) and NuGet's centrally managed ones (#129)
    already have.
    """

    def __init__(
        self,
        manifest_path: str,
        catalog: Optional[VersionCatalog] = None,
    ) -> None:
        """Initialize the parser.

        Args:
            manifest_path: Path to the ``build.gradle`` or ``build.gradle.kts``.
            catalog: Version catalog to resolve aliases against. Defaults to the
                nearest ``gradle/libs.versions.toml`` at or above the script's
                directory, which is where Gradle's conventional catalog lives.
        """
        super().__init__(manifest_path)
        self._catalog = catalog
        self._catalog_loaded = catalog is not None

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse the build script and extract its declared dependencies.

        Returns:
            Dictionary mapping ``groupId:artifactId`` to metadata.
        """
        dependencies: Dict[str, DependencyMetadata] = {}
        text = self._read_script()
        if text is None:
            return dependencies

        script = read_script(text)
        if not script.declarations:
            self._report(0, 0, script.unreadable)
            return dependencies

        properties = dict(read_gradle_properties(self.manifest_path.parent))
        # The script's own ``ext { }`` and top-level literals win over
        # gradle.properties, which is Gradle's own precedence for a project
        # property set in both places.
        properties.update(script.properties)

        unresolved = 0
        for declaration in script.declarations:
            for name, version, source in self._resolve(declaration, properties):
                if name in dependencies:
                    continue
                metadata = DependencyMetadata(name=name, installed_version=version)
                metadata.additional_info[VERSION_SOURCE_KEY] = source
                if source == VERSION_SOURCE_UNMANAGED:
                    unresolved += 1
                dependencies[name] = metadata

        self._report(len(dependencies), unresolved, script.unreadable)
        return dependencies

    def _read_script(self) -> Optional[str]:
        """Return the build script's text, or None when it cannot be read."""
        try:
            with self.manifest_path.open(encoding="utf-8", errors="replace") as handle:
                text = handle.read(MAX_SCRIPT_BYTES + 1)
        except OSError as exc:
            logger.error("Could not read %s: %s", self.manifest_path, exc)
            return None
        if len(text) > MAX_SCRIPT_BYTES:
            logger.error(
                "%s is larger than the %d-byte build-script bound and was not read",
                self.manifest_path,
                MAX_SCRIPT_BYTES,
            )
            return None
        return text

    def _resolve(
        self, declaration: GradleDeclaration, properties: Dict[str, str]
    ) -> List[Tuple[str, str, str]]:
        """Return the ``(name, version, source)`` triples one declaration yields.

        A bundle accessor names several libraries, so this is a list; every other
        shape yields at most one.

        Args:
            declaration: One declaration as written.
            properties: Project properties, for ``$name`` interpolation.

        Returns:
            One triple per dependency the declaration names.
        """
        if declaration.catalog_path is not None:
            return self._resolve_from_catalog(declaration)

        stated = expand_properties(declaration.raw_version or "", properties)
        version = concrete_version(stated)
        if version is None:
            return [(declaration.key, "", VERSION_SOURCE_UNMANAGED)]
        return [(declaration.key, version, VERSION_SOURCE_DECLARED)]

    def _resolve_from_catalog(
        self, declaration: GradleDeclaration
    ) -> List[Tuple[str, str, str]]:
        """Resolve a ``libs.*`` accessor against the version catalog.

        An accessor this scan cannot follow — no catalog within reach, an alias
        the catalog does not declare, a catalog under a non-default name — is
        not an error and not an empty result. It is a dependency whose version
        is declared somewhere unreachable, which is what
        :data:`~.version_sources.VERSION_SOURCE_UNMANAGED` means. But the
        accessor alone does not name a *coordinate*, so there is nothing to
        report: an alias is not a ``groupId:artifactId`` until the catalog says
        what it stands for.

        Args:
            declaration: A declaration carrying a catalog accessor path.

        Returns:
            One triple per library the accessor names; empty when the catalog
            cannot say which artifact that is.
        """
        accessor = declaration.catalog_path or ()
        catalog = self._version_catalog()
        if catalog is None:
            logger.info(
                "%s declares libs.%s but no %s/%s is within reach; the "
                "dependency cannot be named, let alone versioned",
                self.manifest_path,
                ".".join(accessor),
                CATALOG_DIRECTORY,
                CATALOG_FILENAME,
            )
            return []

        members = catalog.bundle_for(accessor)
        if members is not None:
            resolved: List[Tuple[str, str, str]] = []
            for member in members:
                library = catalog.libraries.get(member)
                if library is not None:
                    resolved.append(_catalog_triple(library))
            return resolved

        library = catalog.library_for(accessor)
        if library is None:
            logger.debug(
                "%s: libs.%s names no library in %s",
                self.manifest_path,
                ".".join(accessor),
                catalog.path,
            )
            return []
        return [_catalog_triple(library)]

    def _version_catalog(self) -> Optional[VersionCatalog]:
        """Return the version catalog, loading it at most once and only if used.

        A project that pins every version inline never touches the filesystem
        beyond its own script, which is the same lazy shape ``NuGetParser`` uses
        for ``Directory.Packages.props``.

        Returns:
            The catalog, or None when there is none within reach.
        """
        if self._catalog_loaded:
            return self._catalog
        self._catalog_loaded = True
        path = find_version_catalog(self.manifest_path.parent)
        if path is None:
            return None
        self._catalog = read_version_catalog(path)
        if self._catalog is not None:
            logger.info(
                "Resolving Gradle version-catalog aliases for %s from %s",
                self.manifest_path,
                path,
            )
        return self._catalog

    def _report(self, named: int, unresolved: int, unreadable: int) -> None:
        """Log what the parse could and could not establish.

        Both numbers are reported, and reported separately, because they are
        different failures: an unresolved version is a dependency we found and
        cannot score for drift, and an unreadable declaration is one we never
        saw at all. Rolling them together would hide the second behind the
        first.

        Args:
            named: How many dependencies were named.
            unresolved: How many of those have no resolvable version.
            unreadable: How many declarations named no coordinate.
        """
        if unresolved:
            logger.warning(
                "%d of %d dependencies in %s have no resolvable version (a "
                "dynamic version, or one declared in a version catalog this "
                "scan cannot reach); their version-drift signal is reported as "
                "unmeasured, not as zero drift",
                unresolved,
                named,
                self.manifest_path,
            )
        if unreadable:
            logger.warning(
                "%d dependency declarations in %s name a coordinate this parser "
                "cannot read statically (computed at build time); they are "
                "reported as unread rather than guessed at. Gradle build "
                "scripts are programs, not manifests — see parsers/gradle_dsl.py "
                "for the shapes that are and are not read",
                unreadable,
                self.manifest_path,
            )


def _catalog_triple(library: CatalogLibrary) -> Tuple[str, str, str]:
    """Return the ``(name, version, source)`` triple for a catalog library."""
    if library.version is None:
        return library.key, "", VERSION_SOURCE_UNMANAGED
    return library.key, library.version, VERSION_SOURCE_CATALOG
