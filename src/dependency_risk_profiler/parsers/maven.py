"""Parser for Java Maven pom.xml files."""

import logging
import re
import xml.etree.ElementTree as ElementTree
from typing import Dict, Optional

from ..models import DependencyMetadata
from .base import BaseParser
from .xml_utils import local_name, read_xml_root

logger = logging.getLogger(__name__)

_PROPERTY_REF = re.compile(r"\$\{([^}]+)\}")


class MavenPomParser(BaseParser):
    """Parser for Java Maven pom.xml files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse pom.xml and extract direct dependencies.

        Returns:
            Dictionary mapping ``groupId:artifactId`` to metadata.
        """
        dependencies: Dict[str, DependencyMetadata] = {}
        root = read_xml_root(self.manifest_path)
        if root is None:
            return dependencies

        properties = self._collect_properties(root)
        # Support ${project.version} and its ${pom.version} alias.
        project_version = self._child_text(root, "version")
        if project_version:
            properties.setdefault("project.version", project_version)
            properties.setdefault("pom.version", project_version)

        # Only the <dependencies> that is a direct child of <project> holds real
        # direct dependencies; the one nested in <dependencyManagement> is a
        # constraint block and is a grandchild, so iterating root's children skips it.
        for block in root:
            if local_name(block.tag) != "dependencies":
                continue
            for dep in block:
                if local_name(dep.tag) != "dependency":
                    continue
                group = self._child_text(dep, "groupId")
                artifact = self._child_text(dep, "artifactId")
                if not group or not artifact:
                    continue
                name = f"{group}:{artifact}"
                if name in dependencies:
                    continue
                version = self._resolve(self._child_text(dep, "version"), properties)
                dependencies[name] = DependencyMetadata(
                    name=name, installed_version=version or ""
                )
        return dependencies

    def _collect_properties(self, root: ElementTree.Element) -> Dict[str, str]:
        """Collect the <properties> map for basic ${name} substitution."""
        properties: Dict[str, str] = {}
        for block in root:
            if local_name(block.tag) != "properties":
                continue
            for prop in block:
                text = (prop.text or "").strip()
                if text:
                    properties[local_name(prop.tag)] = text
        return properties

    @staticmethod
    def _child_text(element: ElementTree.Element, name: str) -> Optional[str]:
        """Return the trimmed text of a direct child by local tag name."""
        for child in element:
            if local_name(child.tag) == name:
                text = (child.text or "").strip()
                return text or None
        return None

    @staticmethod
    def _resolve(version: Optional[str], properties: Dict[str, str]) -> Optional[str]:
        """Resolve ``${property}`` references, including chained and embedded ones.

        Substitution runs iteratively (bounded to guard against circular refs)
        so both chained values (``${a}`` -> ``${b}`` -> ``1.2.3``) and embedded
        references (``${lib.version}-RELEASE``) resolve. Unknown properties are
        left as literal ``${...}`` placeholders.
        """
        if not version:
            return None

        def _substitute(match: "re.Match[str]") -> str:
            return properties.get(match.group(1), match.group(0))

        resolved = version.strip()
        for _ in range(10):
            expanded = _PROPERTY_REF.sub(_substitute, resolved)
            if expanded == resolved:
                break
            resolved = expanded
        return resolved
