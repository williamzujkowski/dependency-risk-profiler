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

Two things #129 left out and #151 added, both found by pointing the parser at
real repositories rather than at fixtures written to match it:

* ``<GlobalPackageReference>``. A Directory.Packages.props may apply a package
  to *every* project in the tree, with nothing in the ``.csproj`` naming it.
  Dapper does this with ReferenceTrimmer. These are build-time packages by
  convention — analyzers, source-link, versioning tools — which is a smaller
  risk than a runtime package and not a zero one: they execute during the
  build. They are collected here and marked with
  :data:`BUILD_DEPENDENCY_KEY`.
* ``Directory.Build.props`` as a property source. It is imported before the
  project body, so it is a *fallback*: a property the project defines itself
  wins, and so does one the Directory.Packages.props defines. Newtonsoft.Json's
  own ``.csproj`` is exactly this shape — seven ``PackageReference`` items
  whose versions are ``$(SomethingPackageVersion)``, all defined one directory
  up — and every one of them read as ``unmanaged`` before this.

Deliberately *not* modelled, because guessing would be worse than declining:

* ``Condition`` attributes. Evaluating MSBuild conditions means evaluating
  MSBuild, so every ``<PropertyGroup>`` and ``<ItemGroup>`` is read regardless
  of its condition. The failure mode is a version read from a branch that would
  not have been taken, which is bounded and visible; the alternative is dropping
  real versions.
* ``<Import>`` chains out of either props file. MSBuild follows them; this does
  not. Only the two filenames MSBuild looks for by name are read, and only the
  nearest of each, which is the same "first hit wins" rule MSBuild applies
  before a file re-imports its parent.
* ``<PackageReference>`` items declared in ``Directory.Build.props`` itself,
  which apply to every project the same way a ``GlobalPackageReference`` does.
  Dapper declares three. Reading them means deciding what an item in an
  imported file means for a project that never mentions it, which is a
  different question from the property lookup this file now does, so it is left
  named rather than half-done.
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
from typing import Dict, List, Mapping, Optional, Tuple
from xml.etree import ElementTree

from .xml_utils import local_name, read_xml_root

logger = logging.getLogger(__name__)

# The two filenames MSBuild looks for when walking up from a project directory.
# The first declares versions; the second declares properties (and much else
# that is none of this module's business).
CENTRAL_PROPS_FILENAME = "Directory.Packages.props"
BUILD_PROPS_FILENAME = "Directory.Build.props"

# Marks a dependency that runs during the build rather than shipping with the
# application. Not a new spelling: ``parsers/toml.py`` already writes this exact
# key for pyproject's ``build-system.requires``, so a consumer reading
# ``DependencyMetadata.additional_info`` sees one vocabulary across ecosystems.
#
# It stops at the Python API. The unified ``ScoredDependency`` (#205) has no
# field for a dependency's kind or scope — not ``dev``, not ``build``, not
# maven's ``<scope>`` — and ``additional_info`` is serialized by neither
# reporter, so nothing here reaches the JSON contract. Adding such a field is a
# contract change that concerns all nine ecosystems and belongs in its own
# issue rather than smuggled in behind NuGet's.
BUILD_DEPENDENCY_KEY = "build_dependency"

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
class GlobalPackage:
    """One ``<GlobalPackageReference>``: a package every project in the tree gets.

    Attributes:
        name: The ``Include`` value as written, which is what the dependency is
            named in the report. NuGet ids are case-insensitive but they are
            not case-*less*, and the report should read the way the repository
            spells it.
        version: The declared version with properties expanded, or None when
            the item carries no version at all. Never narrowed to a concrete
            version here — that is :func:`concrete_version`'s decision, and it
            is the caller who has to record *unmanaged* when it declines.
    """

    name: str
    version: Optional[str]


@dataclass(frozen=True)
class CentralPackageVersions:
    """What one Directory.Packages.props declares.

    Attributes:
        path: Where the file was found, for logging and tests.
        manage_centrally: The stated ``<ManagePackageVersionsCentrally>`` value,
            or None when the file does not mention it.
        versions: Package id (lowercased, because NuGet ids are
            case-insensitive) to its declared version, properties already
            expanded.
        global_packages: The ``<GlobalPackageReference>`` items, in document
            order. These are dependencies of every project under the file, not
            versions waiting for a project to reference them, which is why they
            are a separate list rather than more entries in ``versions``.
    """

    path: Path
    manage_centrally: Optional[bool]
    versions: Mapping[str, str]
    global_packages: Tuple[GlobalPackage, ...] = ()

    def version_for(self, package_id: str) -> Optional[str]:
        """Return the centrally declared version for a package id, or None.

        Args:
            package_id: The ``Include`` value from a ``PackageReference``.

        Returns:
            The declared version string, or None when the file declares none.
        """
        return self.versions.get(package_id.strip().lower())


def find_nearest_import(start_directory: Path, filename: str) -> Optional[Path]:
    """Return the nearest file of that name at or above a directory.

    MSBuild imports the first ``Directory.Build.props`` and the first
    ``Directory.Packages.props`` it finds walking up, so the walk stops at the
    first hit rather than merging every file in the chain. One traversal serves
    both (#151): a second copy of this loop is a second place for the depth
    bound, the ``resolve()`` failure and the "first hit wins" rule to drift.

    Args:
        start_directory: The project's own directory.
        filename: The file MSBuild would look for, unqualified.

    Returns:
        Path to the file, or None when the walk reaches the filesystem root
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
                "Stopping the %s search at %d ancestors of %s",
                filename,
                MAX_ANCESTOR_DEPTH,
                start_directory,
            )
            return None
        candidate = directory / filename
        try:
            if candidate.is_file():
                return candidate
        except OSError as exc:
            logger.debug("Could not stat %s: %s", candidate, exc)
    return None


def find_central_props(start_directory: Path) -> Optional[Path]:
    """Return the nearest ``Directory.Packages.props`` at or above a directory.

    Args:
        start_directory: The project's own directory.

    Returns:
        Path to the props file, or None when there is none within reach.
    """
    return find_nearest_import(start_directory, CENTRAL_PROPS_FILENAME)


def find_build_props(start_directory: Path) -> Optional[Path]:
    """Return the nearest ``Directory.Build.props`` at or above a directory.

    Args:
        start_directory: The project's own directory.

    Returns:
        Path to the props file, or None when there is none within reach.
    """
    return find_nearest_import(start_directory, BUILD_PROPS_FILENAME)


def read_inherited_properties(path: Path) -> Dict[str, str]:
    """Return the properties a ``Directory.Build.props`` defines.

    Only ``<PropertyGroup>`` content is taken. The file is a general MSBuild
    hook and typically carries items, targets and imports as well; none of that
    is read, because a property lookup is the whole of what #151 asked for and
    an item in an imported file raises a question this module has not answered
    (see the module docstring).

    Args:
        path: Path to the ``Directory.Build.props``.

    Returns:
        Property name (lowercased) to its raw, unexpanded value. Empty when the
        file cannot be read or parsed — an unreadable inherited file leaves the
        versions that needed it *unmanaged*, which is #141's contract, rather
        than taking the parse down.
    """
    root = read_xml_root(path)
    if root is None:
        return {}
    return collect_properties(root)


def read_central_versions(
    path: Path, inherited_properties: Optional[Mapping[str, str]] = None
) -> Optional[CentralPackageVersions]:
    """Parse a ``Directory.Packages.props`` into what it declares.

    Args:
        path: Path to the props file.
        inherited_properties: Properties from a ``Directory.Build.props`` above
            the project, used only for references this file cannot resolve
            itself. MSBuild imports ``Directory.Build.props`` first, so a
            property defined in *both* takes the value written here.

    Returns:
        The parsed declarations, or None when the file cannot be read or parsed.
        Parsing goes through :func:`~.xml_utils.read_xml_root`, so no external
        entity is ever resolved.
    """
    root = read_xml_root(path)
    if root is None:
        return None

    properties = collect_properties(root)
    if inherited_properties:
        properties = {**inherited_properties, **properties}
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
        path=path,
        manage_centrally=manage_centrally,
        versions=versions,
        global_packages=_read_global_packages(root, properties),
    )


def _read_global_packages(
    root: ElementTree.Element, properties: Mapping[str, str]
) -> Tuple[GlobalPackage, ...]:
    """Collect every ``<GlobalPackageReference>``, deduplicated, in order.

    Args:
        root: Root element of the ``Directory.Packages.props``.
        properties: The effective property map for that file.

    Returns:
        One entry per distinct package id, first declaration winning, matching
        how the ``<PackageVersion>`` table above resolves a repeated id.
    """
    packages: List[GlobalPackage] = []
    seen: Dict[str, None] = {}
    for element in root.iter():
        if local_name(element.tag) != "GlobalPackageReference":
            continue
        package_id = element.get("Include") or element.get("Update")
        if not package_id or not package_id.strip():
            continue
        key = package_id.strip().lower()
        if key in seen:
            continue
        seen[key] = None
        declared = _element_version(element)
        packages.append(
            GlobalPackage(
                name=package_id.strip(),
                version=(
                    None
                    if declared is None
                    else expand_properties(declared, properties)
                ),
            )
        )
    return tuple(packages)


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
