"""Structural reading of Maven POM documents.

Pure, offline, side-effect free: an ``xml.etree`` element in, a
:class:`PomDocument` out. Everything that needs the network (following a
``<parent>`` or an imported BOM) lives in :mod:`.maven_repositories`; everything that
needs a file lives in :mod:`.maven`. Keeping the shape-reading here is what
makes the inheritance rules testable without a single HTTP call.
"""

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .xml_utils import child_text, find_child, local_name

# ``${name}`` property reference, as used in <version> and <properties> values.
PROPERTY_REF = re.compile(r"\$\{([^}]+)\}")

# Substitution is iterative so chained (``${a}`` -> ``${b}`` -> ``1.2.3``) and
# embedded (``${lib.version}-RELEASE``) references both resolve. The bound stops
# a circular definition from looping forever.
_MAX_SUBSTITUTION_PASSES = 10


@dataclass(frozen=True)
class PomCoordinate:
    """A fully qualified ``groupId:artifactId:version`` triple."""

    group_id: str
    artifact_id: str
    version: str

    @property
    def key(self) -> str:
        """Return the ``groupId:artifactId`` key used across the profiler."""
        return f"{self.group_id}:{self.artifact_id}"


@dataclass(frozen=True)
class DependencyDeclaration:
    """One ``<dependency>`` entry, with its version left unresolved."""

    group_id: str
    artifact_id: str
    version: Optional[str]
    scope: Optional[str] = None
    dep_type: Optional[str] = None

    @property
    def key(self) -> str:
        """Return the ``groupId:artifactId`` key used across the profiler."""
        return f"{self.group_id}:{self.artifact_id}"

    @property
    def is_bom_import(self) -> bool:
        """Return True for a ``<type>pom</type><scope>import</scope>`` entry."""
        return self.dep_type == "pom" and self.scope == "import"


@dataclass
class PomDocument:
    """The parts of a POM this tool reads.

    Attributes:
        group_id: Declared ``<groupId>`` (absent when inherited from the parent).
        artifact_id: Declared ``<artifactId>``.
        version: Declared ``<version>`` (absent when inherited from the parent).
        parent: The ``<parent>`` coordinate, if any.
        properties: The ``<properties>`` block, values unresolved.
        managed: ``<dependencyManagement>`` entries that are not BOM imports.
        bom_imports: ``<dependencyManagement>`` entries importing another POM.
        direct: Entries in the project-level ``<dependencies>`` block.
        scm_url: Best available source-repository URL.
        project_url: The project ``<url>``.
        licenses: License names from ``<licenses>``.
    """

    group_id: Optional[str] = None
    artifact_id: Optional[str] = None
    version: Optional[str] = None
    parent: Optional[PomCoordinate] = None
    properties: Dict[str, str] = field(default_factory=dict)
    managed: List[DependencyDeclaration] = field(default_factory=list)
    bom_imports: List[DependencyDeclaration] = field(default_factory=list)
    direct: List[DependencyDeclaration] = field(default_factory=list)
    scm_url: Optional[str] = None
    project_url: Optional[str] = None
    licenses: List[str] = field(default_factory=list)

    @property
    def effective_group_id(self) -> Optional[str]:
        """Return the declared groupId, falling back to the parent's."""
        if self.group_id:
            return self.group_id
        return self.parent.group_id if self.parent else None

    @property
    def effective_version(self) -> Optional[str]:
        """Return the declared version, falling back to the parent's."""
        if self.version:
            return self.version
        return self.parent.version if self.parent else None


@dataclass(frozen=True)
class InheritedMetadata:
    """The project metadata a POM has after its parent chain is applied.

    Attributes:
        licenses: License names, from the nearest POM that declares any.
        scm_url: Source-repository URL, from the nearest POM that declares one.
        project_url: Project ``<url>``, from the nearest POM that declares one.
    """

    licenses: Tuple[str, ...] = ()
    scm_url: Optional[str] = None
    project_url: Optional[str] = None

    @property
    def complete(self) -> bool:
        """Return True once nothing further up the chain could change the answer.

        ``<scm>`` outranks ``<url>`` wherever both exist, so a known licence and
        a known SCM URL settle the question: an ancestor can only contribute a
        ``<url>`` that would lose anyway.
        """
        return bool(self.licenses) and self.scm_url is not None


def inherit_metadata(lineage: Iterable[PomDocument]) -> InheritedMetadata:
    """Merge ``<licenses>``, ``<scm>`` and ``<url>`` down a parent chain.

    Maven's convention is to declare these once in a parent POM and inherit
    them: guava, slf4j-api and the Apache Commons artifacts carry none of them
    in their own POM (commons-lang3's licence is two hops up, in
    ``org.apache:apache``). Reading only the artifact's POM therefore reports
    much of the mainstream Java ecosystem as having no licence and no source
    repository (#178). Not all of it — Spring publishes Gradle-generated POMs
    that declare both inline, and jackson-databind declares its own — which is
    exactly why the walk has to be lazy rather than unconditional.

    **Precedence: nearest declaration wins**, which is the rule #141 already
    chose for ``<properties>`` and ``<dependencyManagement>``. A child that
    declares its own ``<licenses>`` keeps them and the parent's are not merged
    in, matching Maven, where an inherited ``<licenses>`` block is replaced
    wholesale rather than appended to.

    One documented divergence from Maven's own model builder: Maven appends the
    child's ``artifactId`` to an inherited ``<scm><url>``, so guava's effective
    SCM URL is ``.../google/guava/guava``. That path is then trimmed straight
    back off by :func:`~..utils.canonical_repository_url`, which only
    ever wants the repository root, so the append is skipped rather than
    performed and undone.

    Args:
        lineage: The POM and its ancestors, nearest first. Consumed lazily and
            abandoned as soon as :attr:`InheritedMetadata.complete` holds, so a
            POM that declares everything itself never causes a parent fetch.

    Returns:
        The merged view. Every field is None or empty when no POM on the chain
        declares it, which stays distinguishable from a declared-empty value.
    """
    merged = InheritedMetadata()
    for document in lineage:
        merged = InheritedMetadata(
            licenses=merged.licenses or tuple(document.licenses),
            scm_url=merged.scm_url or document.scm_url,
            project_url=merged.project_url or document.project_url,
        )
        if merged.complete:
            break
    return merged


def read_pom(root: ElementTree.Element) -> PomDocument:
    """Read a ``<project>`` element into a :class:`PomDocument`.

    Args:
        root: The parsed ``<project>`` root element.

    Returns:
        The structural view of the POM, with all versions left unresolved.
    """
    document = PomDocument(
        group_id=child_text(root, "groupId"),
        artifact_id=child_text(root, "artifactId"),
        version=child_text(root, "version"),
        parent=_read_parent(root),
        properties=_read_properties(root),
        scm_url=_read_scm_url(root),
        project_url=child_text(root, "url"),
        licenses=_read_licenses(root),
    )

    # Only the <dependencies> that is a direct child of <project> holds real
    # direct dependencies; the one nested in <dependencyManagement> is a
    # constraint block and is a grandchild, so it is read separately below.
    direct_block = find_child(root, "dependencies")
    if direct_block is not None:
        document.direct = _read_dependencies(direct_block)

    management = find_child(root, "dependencyManagement")
    if management is not None:
        managed_block = find_child(management, "dependencies")
        if managed_block is not None:
            for declaration in _read_dependencies(managed_block):
                if declaration.is_bom_import:
                    document.bom_imports.append(declaration)
                else:
                    document.managed.append(declaration)

    return document


def resolve_properties(value: Optional[str], properties: Dict[str, str]) -> str:
    """Expand ``${property}`` references, including chained and embedded ones.

    Unknown properties are left as literal ``${...}`` placeholders so callers
    can tell "resolved" from "still a reference".

    Args:
        value: The raw text, e.g. ``${lib.version}-RELEASE``.
        properties: The property map to substitute from.

    Returns:
        The expanded string (empty when ``value`` is falsy).
    """
    if not value:
        return ""

    def _substitute(match: "re.Match[str]") -> str:
        return properties.get(match.group(1), match.group(0))

    resolved = value.strip()
    for _ in range(_MAX_SUBSTITUTION_PASSES):
        expanded = PROPERTY_REF.sub(_substitute, resolved)
        if expanded == resolved:
            break
        resolved = expanded
    return resolved


def is_resolved(value: str) -> bool:
    """Return True when a version is concrete (no leftover ``${...}`` ref)."""
    return bool(value) and "${" not in value


def project_properties(document: PomDocument) -> Dict[str, str]:
    """Return the implicit ``project.*`` properties a POM contributes.

    Maven exposes the model itself as properties; ``${project.version}`` (and
    its legacy ``${pom.version}`` alias) is the one BOMs lean on hardest to pin
    their own sibling modules.

    Args:
        document: The POM whose own coordinates seed the property map.

    Returns:
        A map of the ``project.*`` / ``pom.*`` properties that are knowable.
    """
    properties: Dict[str, str] = {}
    version = document.effective_version
    if version:
        properties["project.version"] = version
        properties["pom.version"] = version
    group_id = document.effective_group_id
    if group_id:
        properties["project.groupId"] = group_id
        properties["pom.groupId"] = group_id
    if document.artifact_id:
        properties["project.artifactId"] = document.artifact_id
        properties["pom.artifactId"] = document.artifact_id
    return properties


def _read_parent(root: ElementTree.Element) -> Optional[PomCoordinate]:
    """Read the ``<parent>`` coordinate, or None when there is no parent."""
    parent = find_child(root, "parent")
    if parent is None:
        return None
    group_id = child_text(parent, "groupId")
    artifact_id = child_text(parent, "artifactId")
    version = child_text(parent, "version")
    if not group_id or not artifact_id or not version:
        return None
    return PomCoordinate(group_id, artifact_id, version)


def _read_properties(root: ElementTree.Element) -> Dict[str, str]:
    """Read the ``<properties>`` block, values left unresolved."""
    properties: Dict[str, str] = {}
    block = find_child(root, "properties")
    if block is None:
        return properties
    for prop in block:
        text = (prop.text or "").strip()
        if text:
            properties[local_name(prop.tag)] = text
    return properties


def _read_dependencies(block: ElementTree.Element) -> List[DependencyDeclaration]:
    """Read every ``<dependency>`` child of a ``<dependencies>`` block."""
    declarations: List[DependencyDeclaration] = []
    for entry in block:
        if local_name(entry.tag) != "dependency":
            continue
        group_id = child_text(entry, "groupId")
        artifact_id = child_text(entry, "artifactId")
        if not group_id or not artifact_id:
            continue
        declarations.append(
            DependencyDeclaration(
                group_id=group_id,
                artifact_id=artifact_id,
                version=child_text(entry, "version"),
                scope=child_text(entry, "scope"),
                dep_type=child_text(entry, "type"),
            )
        )
    return declarations


def _read_scm_url(root: ElementTree.Element) -> Optional[str]:
    """Read the best source-repository URL from ``<scm>``.

    ``<url>`` is a browsable URL and is preferred; the ``scm:git:`` connection
    strings are the fallback and get their Maven prefixes stripped by the
    caller.
    """
    scm = find_child(root, "scm")
    if scm is None:
        return None
    for tag in ("url", "connection", "developerConnection"):
        value = child_text(scm, tag)
        if value:
            return value
    return None


def _read_licenses(root: ElementTree.Element) -> List[str]:
    """Read license names from the ``<licenses>`` block."""
    names: List[str] = []
    block = find_child(root, "licenses")
    if block is None:
        return names
    for entry in block:
        if local_name(entry.tag) != "license":
            continue
        name = child_text(entry, "name")
        if name:
            names.append(name)
    return names
