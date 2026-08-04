"""Central Package Management resolution for NuGet projects (#129).

Modern .NET solutions do not pin a version on the ``PackageReference``. They
declare it once, in a ``Directory.Packages.props`` at or above the project
directory::

    <!-- src/Web/Web.csproj -->
    <PackageReference Include="MediatR" />

    <!-- Directory.Packages.props -->
    <PackageVersion Include="MediatR" Version="12.0.1" />

This is Microsoft's recommended layout for multi-project solutions, so a scanner
that reads only the inline ``Version`` attribute loses the installed version for
essentially every mainstream .NET repository — and with it the version-drift
signal and any chance of a confident risk level.

Resolution here follows MSBuild's rules as far as a static read can honestly go:
the nearest ``Directory.Packages.props`` walking up from the project directory,
``$(Property)`` references expanded against that file's own ``<PropertyGroup>``
elements, and ``<ManagePackageVersionsCentrally>`` respected when it is stated.

Deliberately *not* modelled, because guessing would be worse than declining:

* ``Condition`` attributes. Evaluating MSBuild conditions means evaluating
  MSBuild, so every ``<PropertyGroup>`` and ``<ItemGroup>`` is read regardless
  of its condition. The failure mode is a version read from a branch that would
  not have been taken, which is bounded and visible; the alternative is dropping
  real versions.
* ``<Import>`` chains out of the props file, and ``Directory.Build.props`` as a
  property source. Both are followed by MSBuild and neither is followed here.
* Floating versions (``1.2.*``) and open-ended ranges (``(1.0,)``). They name a
  version that only exists after a restore, so they resolve to *unmanaged*
  rather than to a number this tool made up.

Anything unresolved is reported as :data:`~.version_sources.VERSION_SOURCE_UNMANAGED`,
never as an empty string (#74, #141).
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional
from xml.etree import ElementTree

from .xml_utils import local_name, read_xml_root

logger = logging.getLogger(__name__)

# The one filename MSBuild looks for when walking up from a project directory.
CENTRAL_PROPS_FILENAME = "Directory.Packages.props"

# MSBuild walks to the drive root. A scan can be pointed at a deep path inside a
# temp directory, so the walk is bounded: 64 ancestors is far past any real
# repository layout and keeps "one parse cannot become thousands of stats" true.
MAX_ANCESTOR_DEPTH = 64

# A property reference, e.g. "$(AspNetVersion)". MSBuild property names are
# case-insensitive, which the lookup below reproduces.
_PROPERTY_REFERENCE = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_.\-]*)\)")

# Bounded expansion: a property may reference another property, but a cycle must
# terminate. Real files nest one or two deep.
_MAX_PROPERTY_PASSES = 8

# A concrete NuGet version: "1.2.3", "8.0.2-preview.1", "1.2.3+build". Anything
# with a wildcard is a floating version and is not concrete.
_CONCRETE_VERSION = re.compile(r"^[0-9][A-Za-z0-9.\-+]*$")

_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}


@dataclass(frozen=True)
class CentralPackageVersions:
    """The ``<PackageVersion>`` declarations of one Directory.Packages.props.

    Attributes:
        path: Where the file was found, for logging and tests.
        manage_centrally: The stated ``<ManagePackageVersionsCentrally>`` value,
            or None when the file does not mention it.
        versions: Package id (lowercased, because NuGet ids are
            case-insensitive) to its declared version, properties already
            expanded.
    """

    path: Path
    manage_centrally: Optional[bool]
    versions: Mapping[str, str]

    def version_for(self, package_id: str) -> Optional[str]:
        """Return the centrally declared version for a package id, or None.

        Args:
            package_id: The ``Include`` value from a ``PackageReference``.

        Returns:
            The declared version string, or None when the file declares none.
        """
        return self.versions.get(package_id.strip().lower())


def find_central_props(start_directory: Path) -> Optional[Path]:
    """Return the nearest ``Directory.Packages.props`` at or above a directory.

    MSBuild imports the first one it finds walking up, so the walk stops at the
    first hit rather than merging every file in the chain.

    Args:
        start_directory: The project's own directory.

    Returns:
        Path to the props file, or None when the walk reaches the filesystem
        root (or the depth bound) without finding one.
    """
    try:
        current = start_directory.resolve()
    except OSError as exc:
        logger.debug("Could not resolve %s: %s", start_directory, exc)
        return None

    for depth, directory in enumerate([current, *current.parents]):
        if depth >= MAX_ANCESTOR_DEPTH:
            logger.debug(
                "Stopping the %s search at %d ancestors of %s",
                CENTRAL_PROPS_FILENAME,
                MAX_ANCESTOR_DEPTH,
                start_directory,
            )
            return None
        candidate = directory / CENTRAL_PROPS_FILENAME
        try:
            if candidate.is_file():
                return candidate
        except OSError as exc:
            logger.debug("Could not stat %s: %s", candidate, exc)
    return None


def read_central_versions(path: Path) -> Optional[CentralPackageVersions]:
    """Parse a ``Directory.Packages.props`` into its central version table.

    Args:
        path: Path to the props file.

    Returns:
        The parsed declarations, or None when the file cannot be read or parsed.
        Parsing goes through :func:`~.xml_utils.read_xml_root`, so no external
        entity is ever resolved.
    """
    root = read_xml_root(path)
    if root is None:
        return None

    properties = collect_properties(root)
    manage_centrally = manage_centrally_setting(properties)

    versions: Dict[str, str] = {}
    for element in root.iter():
        if local_name(element.tag) != "PackageVersion":
            continue
        package_id = element.get("Include") or element.get("Update")
        if not package_id:
            continue
        declared = _element_version(element)
        if declared is None:
            continue
        key = package_id.strip().lower()
        if key in versions:
            continue
        versions[key] = expand_properties(declared, properties)

    return CentralPackageVersions(
        path=path, manage_centrally=manage_centrally, versions=versions
    )


def collect_properties(root: ElementTree.Element) -> Dict[str, str]:
    """Return every ``<PropertyGroup>`` child as a lowercased name/value map.

    Conditions are not evaluated (see the module docstring); the last definition
    of a property wins, which is MSBuild's own rule for the unconditional case.

    Args:
        root: Root element of an MSBuild XML file.

    Returns:
        Property name (lowercased) to its raw, unexpanded value.
    """
    properties: Dict[str, str] = {}
    for group in root.iter():
        if local_name(group.tag) != "PropertyGroup":
            continue
        for child in group:
            name = local_name(child.tag).strip().lower()
            if not name:
                continue
            properties[name] = (child.text or "").strip()
    return properties


def expand_properties(value: str, properties: Mapping[str, str]) -> str:
    """Expand ``$(Name)`` references against a property map.

    Args:
        value: Raw attribute or element text, e.g. ``"$(AspNetVersion)"``.
        properties: Lowercased property map from :func:`collect_properties`.

    Returns:
        The expanded string. References with no matching property are left
        as-is, so the caller can see the value never resolved and mark it
        unmanaged rather than shipping a literal ``$(...)`` as a version.
    """
    expanded = value
    for _ in range(_MAX_PROPERTY_PASSES):
        if "$(" not in expanded:
            break
        replaced = _PROPERTY_REFERENCE.sub(
            lambda match: properties.get(match.group(1).lower(), match.group(0)),
            expanded,
        )
        if replaced == expanded:
            break
        expanded = replaced
    return expanded


def concrete_version(raw: Optional[str]) -> Optional[str]:
    """Return the one concrete version a NuGet version string names, or None.

    A ``PackageReference`` version is a *range*, not a point: ``1.2.3`` means
    "at least 1.2.3", ``[1.2.3]`` means exactly that, and ``[1.2.3,2.0.0)`` is a
    half-open interval. Restore picks the lowest version satisfying the range,
    so an inclusive lower bound is the version that actually gets installed.
    Everything else — a floating ``1.2.*``, an exclusive lower bound ``(1.0,)``,
    a leftover ``$(Unresolved)`` — names a version only a restore could
    determine, and is reported as unknown rather than approximated.

    Args:
        raw: The declared version string, or None.

    Returns:
        The concrete version, or None when the string does not name one.
    """
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None
    if "$(" in value:
        return None

    if value.startswith("[") or value.startswith("("):
        if not (value.endswith("]") or value.endswith(")")):
            return None
        # Only an inclusive lower bound names the version restore will install.
        if value.startswith("("):
            return None
        inner = value[1:-1]
        lower = inner.split(",", 1)[0].strip()
        value = lower

    if not _CONCRETE_VERSION.match(value):
        return None
    return value


def _element_version(element: ElementTree.Element) -> Optional[str]:
    """Return an item's ``Version``, from the attribute or the child element."""
    attribute = element.get("Version")
    if attribute is not None:
        return attribute
    for child in element:
        if local_name(child.tag) == "Version":
            return (child.text or "").strip()
    return None


def manage_centrally_setting(properties: Mapping[str, str]) -> Optional[bool]:
    """Return a stated ``ManagePackageVersionsCentrally``, or None when absent.

    Either file may state it — the props file that declares the versions or the
    project that consumes them — so the reader is shared rather than written
    once per caller.

    Args:
        properties: Lowercased property map from :func:`collect_properties`.

    Returns:
        True or False when the property is stated and parseable, None otherwise.
    """
    stated = properties.get("managepackageversionscentrally")
    if stated is None:
        return None
    normalized = stated.strip().lower()
    if normalized in _TRUE:
        return True
    if normalized in _FALSE:
        return False
    return None
