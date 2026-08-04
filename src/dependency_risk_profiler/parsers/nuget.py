"""Parser for .NET NuGet manifests (packages.lock.json and *.csproj)."""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Set, Tuple
from xml.etree import ElementTree

from packaging.version import InvalidVersion, Version

from ..models import DependencyMetadata
from .base import BaseParser
from .nuget_cpm import (
    BUILD_DEPENDENCY_KEY,
    BUILD_PROPS_FILENAME,
    CENTRAL_PROPS_FILENAME,
    CentralPackageVersions,
    collect_properties,
    concrete_version,
    expand_properties,
    find_build_props,
    find_central_props,
    manage_centrally_setting,
    read_central_versions,
    read_inherited_properties,
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
    (#129). Properties come from the project first and the nearest
    ``Directory.Build.props`` second, which is MSBuild's own order (#151).
    Anything still unresolved is marked ``unmanaged`` rather than emitted as an
    empty string, so the scorer drops the version-drift signal from both
    numerator and denominator (#74) instead of scoring a fabricated zero — the
    same contract Maven's inherited versions got in #141.

    The project's own dependencies are not the whole set. A
    ``<GlobalPackageReference>`` in the Directory.Packages.props applies to
    every project under it with nothing in the ``.csproj`` to show for it, so
    those are collected too (#151) and marked
    :data:`~.nuget_cpm.BUILD_DEPENDENCY_KEY`.
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
        inherited = self._inherited_properties()
        own_properties = collect_properties(root)
        # MSBuild evaluates the imported Directory.Build.props before the
        # project body, and the last unconditional definition wins, so the
        # project overrides what it inherits and never the other way round.
        project_properties = (
            {**inherited, **own_properties} if inherited else own_properties
        )
        central = self._central_versions(project_properties, inherited)

        for reference in references:
            version, source = self._resolve_version(
                reference, project_properties, central
            )
            metadata = DependencyMetadata(
                name=reference.name, installed_version=version
            )
            metadata.additional_info[VERSION_SOURCE_KEY] = source
            dependencies[reference.name] = metadata

        self._add_global_packages(dependencies, central)

        unresolved = sum(
            1
            for metadata in dependencies.values()
            if metadata.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED
        )
        if unresolved:
            logger.warning(
                "%d of %d packages in %s have no resolvable version "
                "(declared in an unreachable %s, in a property no %s defines, "
                "or as a floating range); their version-drift signal is "
                "reported as unmeasured, not as zero drift",
                unresolved,
                len(dependencies),
                self.manifest_path,
                CENTRAL_PROPS_FILENAME,
                BUILD_PROPS_FILENAME,
            )
        return dependencies

    def _inherited_properties(self) -> Dict[str, str]:
        """Return the properties the nearest ``Directory.Build.props`` defines.

        Returns:
            The property map, or an empty one when there is no such file within
            reach or it cannot be parsed. Empty is the honest answer in both
            cases: it leaves every ``$(Property)`` it would have resolved
            visible as a reference, which :func:`~.nuget_cpm.concrete_version`
            then declines and the caller records as *unmanaged*.
        """
        props_path = find_build_props(self.manifest_path.parent)
        if props_path is None:
            logger.debug(
                "No %s above %s; properties defined there cannot be resolved",
                BUILD_PROPS_FILENAME,
                self.manifest_path,
            )
            return {}
        properties = read_inherited_properties(props_path)
        if properties:
            logger.info(
                "Reading inherited MSBuild properties for %s from %s",
                self.manifest_path,
                props_path,
            )
        return properties

    def _add_global_packages(
        self,
        dependencies: Dict[str, DependencyMetadata],
        central: Optional[CentralPackageVersions],
    ) -> None:
        """Add the tree-wide ``<GlobalPackageReference>`` packages (#151).

        These are dependencies of the project without appearing in it, so a
        scanner that reads only the ``.csproj`` cannot see them at all. They
        are conventionally build-time tooling — analyzers, source-link,
        versioning — which is why each is marked
        :data:`~.nuget_cpm.BUILD_DEPENDENCY_KEY` rather than merged silently
        into the runtime set.

        Args:
            dependencies: The project's own dependencies, modified in place.
            central: The parsed Directory.Packages.props, or None when there is
                none in reach or Central Package Management is switched off —
                in which case there are no global packages to add, because
                ``GlobalPackageReference`` is a Central Package Management item
                and MSBuild ignores it otherwise.
        """
        if central is None:
            return
        declared = {name.lower() for name in dependencies}
        for package in central.global_packages:
            if package.name.lower() in declared:
                # NuGet rejects a project that references a global package
                # itself, so this tree does not build. The project's own entry
                # is the more specific statement, and it is kept.
                logger.warning(
                    "%s declares %s and %s adds it globally; keeping the "
                    "project's own reference",
                    self.manifest_path,
                    package.name,
                    central.path,
                )
                continue
            resolved = concrete_version(package.version)
            metadata = DependencyMetadata(
                name=package.name, installed_version=resolved or ""
            )
            metadata.additional_info[VERSION_SOURCE_KEY] = (
                VERSION_SOURCE_CENTRAL if resolved else VERSION_SOURCE_UNMANAGED
            )
            metadata.additional_info[BUILD_DEPENDENCY_KEY] = "true"
            dependencies[package.name] = metadata

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
        project_properties: Dict[str, str],
        inherited: Mapping[str, str],
    ) -> Optional[CentralPackageVersions]:
        """Load the nearest Directory.Packages.props, unless it cannot apply.

        #129 skipped the lookup entirely when every reference already carried
        its own version, on the grounds that an inline-pinned project has
        nothing left to resolve. That shortcut did not survive #151: a
        ``<GlobalPackageReference>`` is a dependency of every project under the
        file including the fully pinned ones, and it is invisible without
        reading the file. So the only remaining reasons not to read it are that
        it does not exist or that Central Package Management is off.

        Args:
            project_properties: The project's effective properties — its own,
                over anything inherited from a ``Directory.Build.props``. Either
                may switch Central Package Management off for this project.
            inherited: The inherited properties on their own, passed through so
                the props file can resolve a ``$(Property)`` it does not define
                itself.

        Returns:
            The parsed central declarations, or None when there is no props
            file within reach or CPM is explicitly disabled.
        """
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

        central = read_central_versions(props_path, inherited_properties=inherited)
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
