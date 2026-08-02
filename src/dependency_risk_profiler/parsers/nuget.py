"""Parser for .NET NuGet manifests (packages.lock.json and *.csproj)."""

import json
import logging
from typing import Dict

from packaging.version import InvalidVersion, Version

from ..models import DependencyMetadata
from .base import BaseParser
from .xml_utils import local_name, read_xml_root

logger = logging.getLogger(__name__)


def _is_higher_version(candidate: str, current: str) -> bool:
    """Return True if ``candidate`` is a higher resolved version than ``current``.

    Compares with :mod:`packaging` semantics; if either string is not a valid
    version, falls back to a plain string comparison (last-seen/string-max).
    """
    try:
        return Version(candidate) > Version(current)
    except InvalidVersion:
        return candidate > current


class NuGetParser(BaseParser):
    """Parser for .NET NuGet manifests."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse a NuGet manifest and extract its packages.

        Returns:
            Dictionary mapping package ids to their metadata.
        """
        name = self.manifest_path.name.lower()
        if name == "packages.lock.json":
            return self._parse_lock_file()
        if name.endswith(".csproj"):
            return self._parse_csproj()
        return {}

    def _parse_lock_file(self) -> Dict[str, DependencyMetadata]:
        """Parse packages.lock.json (concrete, resolved versions per framework)."""
        dependencies: Dict[str, DependencyMetadata] = {}
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.error("Could not read %s: %s", self.manifest_path, exc)
            return dependencies
        frameworks = data.get("dependencies")
        if not isinstance(frameworks, dict):
            return dependencies
        for packages in frameworks.values():
            if not isinstance(packages, dict):
                continue
            for pkg_name, info in packages.items():
                if not isinstance(pkg_name, str):
                    continue
                resolved = info.get("resolved") if isinstance(info, dict) else None
                version = resolved if isinstance(resolved, str) else ""
                existing = dependencies.get(pkg_name)
                # A package can resolve to different versions across target
                # frameworks; keep the highest resolved version seen.
                if existing is not None and not _is_higher_version(
                    version, existing.installed_version
                ):
                    continue
                dependencies[pkg_name] = DependencyMetadata(
                    name=pkg_name,
                    installed_version=version,
                )
        return dependencies

    def _parse_csproj(self) -> Dict[str, DependencyMetadata]:
        """Parse <PackageReference> entries from an MSBuild .csproj."""
        dependencies: Dict[str, DependencyMetadata] = {}
        root = read_xml_root(self.manifest_path)
        if root is None:
            return dependencies
        for element in root.iter():
            if local_name(element.tag) != "PackageReference":
                continue
            name = element.get("Include") or element.get("Update")
            if not name or name in dependencies:
                continue
            version = element.get("Version")
            if version is None:
                # Version can also be a child element: <Version>1.2.3</Version>.
                for child in element:
                    if local_name(child.tag) == "Version":
                        version = (child.text or "").strip()
                        break
            dependencies[name] = DependencyMetadata(
                name=name, installed_version=version or ""
            )
        return dependencies
