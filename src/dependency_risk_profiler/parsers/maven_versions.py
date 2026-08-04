"""Maven version resolution across the parent chain and imported BOMs.

A Maven project rarely writes its dependency versions down. WebGoat declares 46
dependencies and pins four of them inline; the rest inherit from
``<dependencyManagement>`` — either the project's own block, its parent POM's, or
a BOM the project imports. Reading only the ``<dependency>`` element therefore
yields no version at all for the common case, which is what issue #128 reports.

This module reconstructs the parts of Maven's effective-POM calculation that
version resolution actually needs:

* property inheritance down the parent chain, nearest declaration winning;
* ``<dependencyManagement>`` inheritance, nearest POM winning;
* ``<scope>import</scope>`` BOMs, each resolved in *its own* property scope
  (an imported BOM does not see the importing project's properties);
* precedence within one POM: its own managed entries beat the BOMs it imports.

Two documented simplifications. Maven's real rule inside a single
``<dependencyManagement>`` block is declaration order, so an import written above
an explicit pin wins; here the explicit pin always wins. And resolution stops
once every version the caller asked for is known, so a BOM that manages
thousands of artifacts nobody depends on is never fully walked.

Every remote read goes through :class:`~.maven_central.MavenCentralClient`, which
is where the size, host, redirect, and count limits live. Resolution is lazy: a
POM whose dependencies are all pinned inline never touches the network.
"""

import logging
from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, Iterator, List, Optional, Set

from .maven_central import MavenCentralClient
from .pom_model import (
    PomCoordinate,
    PomDocument,
    is_resolved,
    project_properties,
    resolve_properties,
)

logger = logging.getLogger(__name__)

# Real parent chains are two or three deep (a project, a starter parent, a BOM).
# Anything deeper is either pathological or hostile; stop rather than walk it.
MAX_PARENT_DEPTH = 8

# A BOM that imports a BOM that imports a BOM is already unusual.
MAX_IMPORT_DEPTH = 4

# Per-import-subtree fetch allowance. Without it, one enormous BOM — Google's
# cloud libraries BOM imports well over a hundred of its own — spends the entire
# client budget before the next import is even looked at, so a project that also
# imports two small BOMs gets nothing from them.
MAX_FETCHES_PER_IMPORT = 32


@dataclass(frozen=True)
class _Scope:
    """The bookkeeping one resolution pass carries down the POM graph."""

    # Keys the caller still needs. None means "resolve everything reachable".
    wanted: Optional[FrozenSet[str]] = None
    # Import coordinates already on this path, to break BOM import cycles.
    seen: FrozenSet[str] = frozenset()
    import_depth: int = 0
    # Absolute client fetch count at which this subtree must stop.
    stop_after: Optional[int] = None

    def satisfied(self, managed: Dict[str, str]) -> bool:
        """Return True when every key the caller asked for now has a version."""
        return self.wanted is not None and self.wanted.issubset(managed)


class ManagedVersionResolver:
    """Resolves the effective managed versions visible to a POM."""

    def __init__(self, client: MavenCentralClient) -> None:
        """Initialize the resolver.

        Args:
            client: The bounded Maven Central client used for every remote read.
        """
        self.client = client

    def resolve(
        self, document: PomDocument, wanted: Optional[Set[str]] = None
    ) -> "ResolvedPom":
        """Return the merged properties and managed versions visible to a POM.

        Args:
            document: The project POM to resolve against.
            wanted: The ``groupId:artifactId`` keys the caller actually needs.
                Resolution stops as soon as all of them have a version. None
                means "resolve everything reachable", which is only sensible for
                small POM graphs.

        Returns:
            A :class:`ResolvedPom` holding the merged property map, the managed
            ``groupId:artifactId`` -> version map, and the parent chain that was
            actually reachable.
        """
        scope = _Scope(wanted=None if wanted is None else frozenset(wanted))
        return self._resolve(document, scope)

    def _resolve(self, document: PomDocument, scope: _Scope) -> "ResolvedPom":
        """Resolve one POM's own effective property and management scope."""
        chain = self.parent_chain(document)
        properties = self._merged_properties(chain)
        managed = self._merged_management(chain, properties, scope)
        return ResolvedPom(properties=properties, managed=managed, chain=chain)

    def iter_lineage(self, document: PomDocument) -> Iterator[PomDocument]:
        """Yield the POM and its reachable ancestors, nearest first.

        Lazy on purpose. Version resolution consumes the whole chain, but the
        metadata inheritance added in #178 stops as soon as it has a licence
        and an SCM URL, and a caller that stops after the leaf POM costs no
        network request at all. Every fetch goes through the same
        :class:`~.maven_central.MavenCentralClient` as the rest of this module,
        so the host allowlist, redirect refusal, byte cap, XXE-safe parse,
        memoization and per-manifest fetch budget all apply unchanged.

        Args:
            document: The POM to start from.

        Yields:
            ``document`` first, then each ancestor that could be fetched, up to
            :data:`MAX_PARENT_DEPTH`. A parent that cannot be retrieved ends the
            walk rather than being guessed at.
        """
        yield document
        current = document
        for _ in range(MAX_PARENT_DEPTH):
            parent_coordinate = current.parent
            if parent_coordinate is None:
                return
            parent = self.client.fetch_pom(parent_coordinate)
            if parent is None:
                logger.debug(
                    "Parent POM %s:%s is not reachable; the walk stops here",
                    parent_coordinate.key,
                    parent_coordinate.version,
                )
                return
            yield parent
            current = parent

    def parent_chain(self, document: PomDocument) -> List[PomDocument]:
        """Return the POM and its reachable ancestors, nearest first."""
        return list(self.iter_lineage(document))

    @staticmethod
    def _merged_properties(chain: List[PomDocument]) -> Dict[str, str]:
        """Merge ``<properties>`` down the chain, nearest declaration winning."""
        properties: Dict[str, str] = {}
        for document in reversed(chain):  # farthest ancestor first
            properties.update(project_properties(document))
            properties.update(document.properties)
        # ``${project.version}`` always means the leaf project's own version,
        # even when the managed entry using it was declared by an ancestor.
        properties.update(project_properties(chain[0]))
        return properties

    def _merged_management(
        self,
        chain: List[PomDocument],
        properties: Dict[str, str],
        scope: _Scope,
    ) -> Dict[str, str]:
        """Merge ``<dependencyManagement>`` across the chain and its BOMs."""
        managed: Dict[str, str] = {}
        for document in chain:  # nearest POM first; first writer wins
            for declaration in document.managed:
                if declaration.key in managed:
                    continue
                version = resolve_properties(declaration.version, properties)
                if is_resolved(version):
                    managed[declaration.key] = version
            if scope.satisfied(managed):
                return managed
            for declaration in document.bom_imports:
                if self._out_of_allowance(scope):
                    return managed
                imported = self._imported_management(
                    declaration.group_id,
                    declaration.artifact_id,
                    declaration.version,
                    properties,
                    self._descend(scope, managed),
                )
                for key, version in imported.items():
                    managed.setdefault(key, version)
                if scope.satisfied(managed):
                    return managed
        return managed

    def _descend(self, scope: _Scope, managed: Dict[str, str]) -> _Scope:
        """Return the scope for one import: fewer wants, its own allowance."""
        wanted = None if scope.wanted is None else scope.wanted - set(managed)
        stop_after = scope.stop_after
        if scope.import_depth == 0:
            # Each top-level import gets its own slice of the client budget, so
            # the first enormous BOM cannot starve the ones declared after it.
            stop_after = self.client.fetch_count + MAX_FETCHES_PER_IMPORT
        return replace(
            scope,
            wanted=wanted,
            import_depth=scope.import_depth + 1,
            stop_after=stop_after,
        )

    def _out_of_allowance(self, scope: _Scope) -> bool:
        """Return True once this import subtree has spent its fetch allowance."""
        return (
            scope.stop_after is not None and self.client.fetch_count >= scope.stop_after
        )

    def _imported_management(
        self,
        group_id: str,
        artifact_id: str,
        raw_version: Optional[str],
        properties: Dict[str, str],
        scope: _Scope,
    ) -> Dict[str, str]:
        """Return the managed versions contributed by one imported BOM."""
        if scope.import_depth > MAX_IMPORT_DEPTH:
            logger.debug(
                "BOM import depth limit reached at %s:%s", group_id, artifact_id
            )
            return {}
        version = resolve_properties(raw_version, properties)
        if not is_resolved(version):
            return {}
        coordinate = PomCoordinate(group_id, artifact_id, version)
        marker = f"{coordinate.key}:{coordinate.version}"
        if marker in scope.seen:  # a BOM import cycle
            return {}
        bom = self.client.fetch_pom(coordinate)
        if bom is None:
            return {}
        # The BOM is resolved as its own effective POM: it inherits from *its*
        # parents and sees *its* properties, not the importing project's.
        return self._resolve(bom, replace(scope, seen=scope.seen | {marker})).managed


class ResolvedPom:
    """The property and dependency-management scope visible to one POM."""

    def __init__(
        self,
        properties: Dict[str, str],
        managed: Dict[str, str],
        chain: List[PomDocument],
    ) -> None:
        """Initialize the resolved scope.

        Args:
            properties: Merged ``${property}`` map.
            managed: ``groupId:artifactId`` -> concrete version.
            chain: The POM and the ancestors that were actually reachable.
        """
        self.properties = properties
        self.managed = managed
        self.chain = chain

    @property
    def inherited(self) -> bool:
        """Return True when at least one ancestor POM was read."""
        return len(self.chain) > 1
