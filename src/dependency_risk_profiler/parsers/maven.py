"""Parser for Java Maven pom.xml files."""

import logging
from typing import Dict, Optional, Tuple

from ..models import DependencyMetadata
from .base import BaseParser
from .maven_central import MavenCentralClient
from .maven_versions import ManagedVersionResolver, ResolvedPom
from .pom_model import PomDocument, is_resolved, read_pom, resolve_properties
from .xml_utils import read_xml_root

logger = logging.getLogger(__name__)

# Recorded on each dependency so downstream consumers can tell a pinned version
# from an inherited one from one we could not establish at all.
VERSION_SOURCE_KEY = "version_source"
VERSION_SOURCE_DECLARED = "declared"
VERSION_SOURCE_MANAGED = "dependency-management"
VERSION_SOURCE_UNMANAGED = "unmanaged"


class MavenPomParser(BaseParser):
    """Parser for Java Maven pom.xml files.

    Versions resolve the way Maven resolves them: an inline ``<version>`` first,
    then the effective ``<dependencyManagement>`` — which spans the project's own
    block, its parent POM chain, and any imported BOM. Anything still unresolved
    is marked ``unmanaged`` rather than guessed; the scorer then drops the
    version-drift signal from both the numerator and the denominator (#74)
    instead of scoring a fabricated zero.
    """

    def __init__(
        self,
        manifest_path: str,
        client: Optional[MavenCentralClient] = None,
    ) -> None:
        """Initialize the parser.

        Args:
            manifest_path: Path to the ``pom.xml`` file.
            client: Maven Central client used to read parent POMs and imported
                BOMs. Defaults to a bounded client; tests inject a fake one and
                ``DEPENDENCY_RISK_NO_REMOTE_POMS=1`` disables remote reads.
        """
        super().__init__(manifest_path)
        self.client = client if client is not None else MavenCentralClient()

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse pom.xml and extract direct dependencies.

        Returns:
            Dictionary mapping ``groupId:artifactId`` to metadata.
        """
        dependencies: Dict[str, DependencyMetadata] = {}
        root = read_xml_root(self.manifest_path)
        if root is None:
            return dependencies

        document = read_pom(root)

        # Pass one is entirely local: no network, no parent POMs. A project that
        # pins its versions inline never needs pass two.
        offline = MavenCentralClient(enabled=False)
        local_scope = ManagedVersionResolver(offline).resolve(document)
        resolved = self._resolve_direct(document, local_scope)

        # Pass two only runs when something is genuinely inherited and there is
        # somewhere to inherit it from, and it asks only for the keys still
        # missing — so resolution stops the moment the manifest is answered
        # instead of walking every BOM a parent happens to import.
        wanted = {
            name
            for name, (_, source) in resolved.items()
            if source == VERSION_SOURCE_UNMANAGED
        }
        if wanted and (document.parent is not None or document.bom_imports):
            remote_scope = ManagedVersionResolver(self.client).resolve(
                document, wanted=wanted
            )
            resolved = self._resolve_direct(document, remote_scope)

        unresolved = 0
        for name, (version, source) in resolved.items():
            metadata = DependencyMetadata(name=name, installed_version=version)
            metadata.additional_info[VERSION_SOURCE_KEY] = source
            if source == VERSION_SOURCE_UNMANAGED:
                unresolved += 1
            dependencies[name] = metadata

        if unresolved:
            logger.warning(
                "%d of %d dependencies in %s have no resolvable version (declared "
                "in an unreachable parent POM or BOM); their version-drift signal "
                "is reported as unmeasured, not as zero drift",
                unresolved,
                len(resolved),
                self.manifest_path,
            )
        return dependencies

    @staticmethod
    def _resolve_direct(
        document: PomDocument, scope: ResolvedPom
    ) -> Dict[str, Tuple[str, str]]:
        """Map each direct dependency to its ``(version, source)`` pair."""
        resolved: Dict[str, Tuple[str, str]] = {}
        for declaration in document.direct:
            if declaration.key in resolved:
                continue
            if declaration.version:
                version = resolve_properties(declaration.version, scope.properties)
                source = VERSION_SOURCE_DECLARED
            else:
                version = scope.managed.get(declaration.key, "")
                source = VERSION_SOURCE_MANAGED
            if not is_resolved(version):
                version = ""
                source = VERSION_SOURCE_UNMANAGED
            resolved[declaration.key] = (version, source)
        return resolved
