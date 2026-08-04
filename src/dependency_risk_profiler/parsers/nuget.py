"""Parser for .NET NuGet manifests (packages.lock.json and *.csproj)."""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree

from packaging.version import InvalidVersion, Version

from ..models import DependencyMetadata
from .base import BaseParser
from .nuget_cpm import (
    CENTRAL_PROPS_FILENAME,
    CentralPackageVersions,
    collect_properties,
    concrete_version,
    expand_properties,
    find_central_props,
    manage_centrally_setting,
    read_central_versions,
)
from .version_sources import (
    VERSION_SOURCE_CENTRAL,
    VERSION_SOURCE_DECLARED,
    VERSION_SOURCE_KEY,
    VERSION_SOURCE_OVERRIDE,
    VERSION_SOURCE_UNMANAGED,
)
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


@dataclass(frozen=True)
class _PackageReference:
    """One ``<PackageReference>`` as written, before any version resolution."""

    name: str
    version: Optional[str]
    version_override: Optional[str]


class NuGetParser(BaseParser):
    """Parser for .NET NuGet manifests.

    A ``.csproj`` resolves versions the way NuGet resolves them: a
    ``VersionOverride`` first, then an inline ``Version``, then the nearest
    ``Directory.Packages.props`` when Central Package Management is in play
    (#129). Anything still unresolved is marked ``unmanaged`` rather than
    emitted as an empty string, so the scorer drops the version-drift signal
    from both numerator and denominator (#74) instead of scoring a fabricated
    zero — the same contract Maven's inherited versions got in #141.
    """

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
                metadata = DependencyMetadata(
                    name=pkg_name,
                    installed_version=version,
                )
                # A lock file states the restored version outright, so there is
                # nothing to inherit and nothing to be honest about missing.
                metadata.additional_info[VERSION_SOURCE_KEY] = (
                    VERSION_SOURCE_DECLARED if version else VERSION_SOURCE_UNMANAGED
                )
                dependencies[pkg_name] = metadata
        return dependencies

    def _parse_csproj(self) -> Dict[str, DependencyMetadata]:
        """Parse <PackageReference> entries from an MSBuild .csproj."""
        dependencies: Dict[str, DependencyMetadata] = {}
        root = read_xml_root(self.manifest_path)
        if root is None:
            return dependencies

        references = self._read_package_references(root)
        if not references:
            return dependencies

        project_properties = collect_properties(root)
        central = self._central_versions(references, project_properties)

        unresolved = 0
        for reference in references:
            version, source = self._resolve_version(
                reference, project_properties, central
            )
            metadata = DependencyMetadata(
                name=reference.name, installed_version=version
            )
            metadata.additional_info[VERSION_SOURCE_KEY] = source
            if source == VERSION_SOURCE_UNMANAGED:
                unresolved += 1
            dependencies[reference.name] = metadata

        if unresolved:
            logger.warning(
                "%d of %d package references in %s have no resolvable version "
                "(declared in an unreachable %s, or as a floating range); their "
                "version-drift signal is reported as unmeasured, not as zero drift",
                unresolved,
                len(references),
                self.manifest_path,
                CENTRAL_PROPS_FILENAME,
            )
        return dependencies

    @staticmethod
    def _read_package_references(
        root: ElementTree.Element,
    ) -> List[_PackageReference]:
        """Collect every ``<PackageReference>`` in document order, deduplicated."""
        references: List[_PackageReference] = []
        seen: Set[str] = set()
        for element in root.iter():
            if local_name(element.tag) != "PackageReference":
                continue
            name = element.get("Include") or element.get("Update")
            if not name or name in seen:
                continue
            seen.add(name)
            references.append(
                _PackageReference(
                    name=name,
                    version=_item_value(element, "Version"),
                    version_override=_item_value(element, "VersionOverride"),
                )
            )
        return references

    def _central_versions(
        self,
        references: List[_PackageReference],
        project_properties: Dict[str, str],
    ) -> Optional[CentralPackageVersions]:
        """Load the nearest Directory.Packages.props, when it is worth loading.

        The lookup is skipped entirely when every reference already carries its
        own version, so an inline-pinned project never touches the filesystem
        beyond its own manifest.

        Args:
            references: The project's package references as written.
            project_properties: The ``.csproj``'s own properties, which may
                switch Central Package Management off for this project.

        Returns:
            The parsed central declarations, or None when there is nothing to
            resolve, no props file within reach, or CPM is explicitly disabled.
        """
        if all(
            reference.version or reference.version_override for reference in references
        ):
            return None

        project_setting = manage_centrally_setting(project_properties)
        if project_setting is False:
            logger.debug(
                "%s sets ManagePackageVersionsCentrally=false; not reading %s",
                self.manifest_path,
                CENTRAL_PROPS_FILENAME,
            )
            return None

        props_path = find_central_props(self.manifest_path.parent)
        if props_path is None:
            logger.info(
                "No %s above %s; versions declared centrally are reported as "
                "unmanaged rather than empty",
                CENTRAL_PROPS_FILENAME,
                self.manifest_path,
            )
            return None

        central = read_central_versions(props_path)
        if central is None:
            return None

        # MSBuild's modern default is to enable central management as soon as
        # the file is imported, so an unstated property is treated as enabled.
        # An explicit false anywhere wins, in either file.
        enabled = project_setting is True or central.manage_centrally is not False
        if not enabled:
            logger.debug(
                "%s sets ManagePackageVersionsCentrally=false; its "
                "<PackageVersion> entries do not apply to %s",
                props_path,
                self.manifest_path,
            )
            return None

        logger.info(
            "Resolving centrally managed versions for %s from %s",
            self.manifest_path,
            props_path,
        )
        return central

    @staticmethod
    def _resolve_version(
        reference: _PackageReference,
        project_properties: Dict[str, str],
        central: Optional[CentralPackageVersions],
    ) -> Tuple[str, str]:
        """Return the ``(version, source)`` pair for one package reference.

        Precedence is NuGet's: ``VersionOverride`` is the sanctioned escape
        hatch from a central declaration and therefore wins outright, an inline
        ``Version`` is next, and the central table answers what is left.
        """
        for declared, source in (
            (reference.version_override, VERSION_SOURCE_OVERRIDE),
            (reference.version, VERSION_SOURCE_DECLARED),
        ):
            if declared is None:
                continue
            resolved = concrete_version(expand_properties(declared, project_properties))
            if resolved is not None:
                return resolved, source
            return "", VERSION_SOURCE_UNMANAGED

        if central is not None:
            resolved = concrete_version(central.version_for(reference.name))
            if resolved is not None:
                return resolved, VERSION_SOURCE_CENTRAL

        return "", VERSION_SOURCE_UNMANAGED


def _item_value(element: ElementTree.Element, name: str) -> Optional[str]:
    """Return an MSBuild item's metadata, from the attribute or child element.

    MSBuild accepts item metadata written either way, and real ``.csproj`` files
    use both spellings in the same file.

    Args:
        element: The item element, e.g. a ``<PackageReference>``.
        name: Metadata name, e.g. ``"Version"`` or ``"VersionOverride"``.

    Returns:
        The raw value, or None when the item does not carry that metadata.
    """
    attribute = element.get(name)
    if attribute is not None:
        return attribute
    for child in element:
        if local_name(child.tag) == name:
            return (child.text or "").strip()
    return None
