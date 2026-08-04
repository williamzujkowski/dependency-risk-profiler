"""Decide whether an advisory actually affects the installed version (#61).

Advisory sources answer "what has ever been wrong with this package", not "is
my pin vulnerable". Until this module existed the tool conflated the two: every
advisory ever published for a package was counted against whatever version
happened to be installed, so a fully patched Django read as carrying a live
CRITICAL that had been fixed two minor releases earlier.

The affected-version data was always in the payload and always discarded. Here
it is normalized into one shape from both sources that carry it — OSV's
``affected[].ranges`` event stream and its explicit ``affected[].versions``
enumeration, and GitHub Advisory's ``vulnerableVersionRange`` string — and then
evaluated against the installed version using the ecosystem's own ordering
rules (``dependency_risk_profiler.versioning``).

Three outcomes, never two: affected, not affected, and *unknown*. Unknown is
load-bearing. An advisory that carries no range at all, or a pin the ecosystem
cannot parse, is counted with a recorded reason rather than being silently
assumed safe (which hides real exposure) or silently assumed vulnerable (the
bug this module fixes). Honest-unknown over a confident guess, per #74.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Mapping, Optional, Sequence, Tuple

from ..versioning import VersionScheme, compare_versions

# Filter reason recorded when an advisory is excluded from the score because
# the installed version sits outside every affected range. Exposed as a
# constant because the reason histogram is a user-visible contract.
NOT_AFFECTED_FILTER_REASON = "does not affect installed version"

# Reasons an advisory is *counted* even though applicability could not be
# decided. Kept to a closed set so the histogram stays readable.
REASON_NO_INSTALLED_VERSION = "installed version unknown"
REASON_INSTALLED_UNPARSEABLE = "installed version not comparable"
REASON_NO_RANGE_DATA = "advisory carries no affected-version data"
REASON_RANGE_UNPARSEABLE = "advisory version range not comparable"

_AT_LEAST = ">="
_GREATER = ">"
_AT_MOST = "<="
_LESS = "<"
_EQUAL = "=="

# GitHub Advisory writes ranges as ">= 4.0, < 4.0.4". OSV writes an event
# stream instead; both collapse to the same conjunction of constraints.
_GITHUB_CONSTRAINT_RE = re.compile(r"^(?P<operator>>=|<=|==|=|>|<)\s*(?P<version>\S+)$")

# OSV range types that carry package versions. GIT ranges carry commit hashes,
# which no version comparator can order, so they are skipped rather than being
# fed to one.
_VERSION_RANGE_TYPES = frozenset({"SEMVER", "ECOSYSTEM"})

# OSV's "everything before the fix" sentinel.
_ZERO_VERSION = "0"


class Applicability(Enum):
    """Whether an advisory applies to the installed version."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ApplicabilityResult:
    """An applicability verdict together with the reason behind it."""

    status: Applicability
    reason: str


@dataclass(frozen=True)
class VersionConstraint:
    """One bound on an affected version range."""

    operator: str
    version: str


@dataclass(frozen=True)
class AffectedRange:
    """A conjunction of bounds; a version in range satisfies all of them."""

    constraints: Tuple[VersionConstraint, ...]


@dataclass(frozen=True)
class AffectedVersions:
    """Everything an advisory says about which versions it affects.

    ``ranges`` are disjunctive (any match means affected) and ``versions`` is
    the explicit enumeration OSV publishes for ecosystems whose releases it
    indexes. A version matches if it is in the enumeration or inside any range.
    """

    ranges: Tuple[AffectedRange, ...] = ()
    versions: Tuple[str, ...] = ()

    def is_empty(self) -> bool:
        """Return whether the advisory carries no affected-version data."""
        return not self.ranges and not self.versions

    def to_payload(self) -> Mapping[str, object]:
        """Render as the JSON-serializable shape stored on an advisory."""
        return {
            "ranges": [
                {
                    "constraints": [
                        {"operator": constraint.operator, "version": constraint.version}
                        for constraint in affected_range.constraints
                    ]
                }
                for affected_range in self.ranges
            ],
            "versions": list(self.versions),
        }


def affected_versions_from_payload(payload: object) -> Optional[AffectedVersions]:
    """Rebuild affected-version data from a stored advisory payload.

    Advisories round-trip through the disk cache and the JSON report, so the
    annotation step reads back what normalization wrote.

    Args:
        payload: The advisory's ``affected_versions`` value, whatever shape it
            arrived in.

    Returns:
        Parsed affected-version data, or None when the payload is absent or
        not the expected shape.
    """
    if not isinstance(payload, dict):
        return None

    ranges: List[AffectedRange] = []
    raw_ranges = payload.get("ranges")
    if isinstance(raw_ranges, list):
        for raw_range in raw_ranges:
            if not isinstance(raw_range, dict):
                continue
            constraints = _constraints_from_payload(raw_range.get("constraints"))
            if constraints:
                ranges.append(AffectedRange(constraints=tuple(constraints)))

    versions: List[str] = []
    raw_versions = payload.get("versions")
    if isinstance(raw_versions, list):
        versions = [item for item in raw_versions if isinstance(item, str) and item]

    parsed = AffectedVersions(ranges=tuple(ranges), versions=tuple(versions))
    return None if parsed.is_empty() else parsed


def _constraints_from_payload(payload: object) -> List[VersionConstraint]:
    """Rebuild one range's constraint list from stored payload."""
    if not isinstance(payload, list):
        return []

    constraints: List[VersionConstraint] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        operator = item.get("operator")
        version = item.get("version")
        if isinstance(operator, str) and isinstance(version, str) and version:
            constraints.append(VersionConstraint(operator=operator, version=version))
    return constraints


def affected_versions_from_osv(
    vulnerability: Mapping[str, object],
    package_name: Optional[str] = None,
    osv_ecosystem: Optional[str] = None,
) -> AffectedVersions:
    """Extract affected-version data from a raw OSV advisory.

    Args:
        vulnerability: A raw OSV vulnerability object.
        package_name: The package the lookup was for. One advisory routinely
            covers several packages across several ecosystems — the jQuery
            prototype-pollution advisory also lists ``PyPI/django``,
            ``RubyGems/jquery-rails`` and ``NuGet/jQuery`` — so entries for
            other packages are dropped rather than bounding this one's version.
        osv_ecosystem: OSV ecosystem name, which disambiguates the packages
            that share a name across ecosystems.

    Returns:
        The advisory's affected ranges and enumerated versions, empty when it
        carries neither in a comparable form.
    """
    ranges: List[AffectedRange] = []
    versions: List[str] = []

    for entry in _dict_list(vulnerability.get("affected")):
        if not _entry_matches_package(entry, package_name, osv_ecosystem):
            continue
        for range_object in _dict_list(entry.get("ranges")):
            ranges.extend(_ranges_from_osv_range(range_object))
        for version in _string_list(entry.get("versions")):
            versions.append(version)

    return AffectedVersions(ranges=tuple(ranges), versions=tuple(versions))


def _entry_matches_package(
    entry: Mapping[str, object],
    package_name: Optional[str],
    osv_ecosystem: Optional[str],
) -> bool:
    """Return whether an OSV affected entry is about the package we asked for.

    Absent identity on either side means "cannot tell", which keeps the entry:
    dropping it would silently discard a real range.
    """
    package = entry.get("package")
    if not isinstance(package, dict):
        return True

    if package_name is not None:
        name = package.get("name")
        if isinstance(name, str) and name.strip():
            if name.strip().lower() != package_name.strip().lower():
                return False

    if osv_ecosystem is not None:
        ecosystem = package.get("ecosystem")
        if isinstance(ecosystem, str) and ecosystem.strip():
            # OSV suffixes some ecosystems with a distro ("Debian:11"); the
            # part before the colon is the identity we route on.
            if ecosystem.split(":")[0].strip().lower() != osv_ecosystem.strip().lower():
                return False

    return True


def _ranges_from_osv_range(range_object: Mapping[str, object]) -> List[AffectedRange]:
    """Convert one OSV range's event stream into closed affected intervals.

    OSV events are an ordered stream: ``introduced`` opens an interval, and
    ``fixed`` (exclusive) or ``last_affected`` (inclusive) closes it. An
    interval left open at the end of the stream extends forever, which is how
    an unfixed advisory is expressed.
    """
    range_type = range_object.get("type")
    if isinstance(range_type, str) and range_type.upper() not in _VERSION_RANGE_TYPES:
        return []

    ranges: List[AffectedRange] = []
    introduced: Optional[str] = None
    interval_open = False

    for event in _dict_list(range_object.get("events")):
        introduced_value = _string_value(event.get("introduced"))
        fixed_value = _string_value(event.get("fixed"))
        last_affected_value = _string_value(event.get("last_affected"))

        if introduced_value is not None:
            if interval_open:
                ranges.append(_interval(introduced, None, None))
            introduced = introduced_value
            interval_open = True
        elif fixed_value is not None:
            ranges.append(_interval(introduced, fixed_value, None))
            introduced, interval_open = None, False
        elif last_affected_value is not None:
            ranges.append(_interval(introduced, None, last_affected_value))
            introduced, interval_open = None, False

    if interval_open:
        ranges.append(_interval(introduced, None, None))
    return ranges


def _interval(
    introduced: Optional[str], fixed: Optional[str], last_affected: Optional[str]
) -> AffectedRange:
    """Build one affected interval from its OSV bounds."""
    constraints: List[VersionConstraint] = [
        VersionConstraint(operator=_AT_LEAST, version=introduced or _ZERO_VERSION)
    ]
    if fixed is not None:
        constraints.append(VersionConstraint(operator=_LESS, version=fixed))
    elif last_affected is not None:
        constraints.append(VersionConstraint(operator=_AT_MOST, version=last_affected))
    return AffectedRange(constraints=tuple(constraints))


def affected_versions_from_github_range(range_text: object) -> AffectedVersions:
    """Parse a GitHub Advisory ``vulnerableVersionRange`` string.

    GitHub writes a single comma-separated conjunction, such as
    ``">= 4.0, < 4.0.4"`` or ``"= 0.2.0"``.

    Args:
        range_text: The raw ``vulnerableVersionRange`` value.

    Returns:
        A single affected range, or empty when the string is absent or not in
        the documented shape.
    """
    if not isinstance(range_text, str) or not range_text.strip():
        return AffectedVersions()

    constraints: List[VersionConstraint] = []
    for part in range_text.split(","):
        match = _GITHUB_CONSTRAINT_RE.match(part.strip())
        if match is None:
            return AffectedVersions()
        operator = match.group("operator")
        constraints.append(
            VersionConstraint(
                operator=_EQUAL if operator == "=" else operator,
                version=match.group("version"),
            )
        )

    if not constraints:
        return AffectedVersions()
    return AffectedVersions(ranges=(AffectedRange(constraints=tuple(constraints)),))


def evaluate_applicability(
    affected: Optional[AffectedVersions],
    installed_version: Optional[str],
    scheme: VersionScheme,
) -> ApplicabilityResult:
    """Decide whether an advisory applies to the installed version.

    Args:
        affected: The advisory's affected-version data, or None when it has none.
        installed_version: The version actually installed.
        scheme: The ecosystem's version-ordering rules.

    Returns:
        An affected / not-affected / unknown verdict with its reason. Unknown
        means the caller must count the advisory and say why, never assume.
    """
    if installed_version is None or not installed_version.strip():
        return ApplicabilityResult(Applicability.UNKNOWN, REASON_NO_INSTALLED_VERSION)
    installed = installed_version.strip()

    if affected is None or affected.is_empty():
        return ApplicabilityResult(Applicability.UNKNOWN, REASON_NO_RANGE_DATA)

    if compare_versions(installed, installed, scheme) is None:
        return ApplicabilityResult(Applicability.UNKNOWN, REASON_INSTALLED_UNPARSEABLE)

    if _matches_enumerated_version(affected.versions, installed, scheme):
        return ApplicabilityResult(
            Applicability.AFFECTED, "installed version is listed as affected"
        )

    undecidable = False
    for affected_range in affected.ranges:
        outcome = _satisfies_range(affected_range, installed, scheme)
        if outcome is None:
            undecidable = True
        elif outcome:
            return ApplicabilityResult(
                Applicability.AFFECTED, "installed version is inside an affected range"
            )

    if undecidable:
        return ApplicabilityResult(Applicability.UNKNOWN, REASON_RANGE_UNPARSEABLE)

    return ApplicabilityResult(Applicability.NOT_AFFECTED, NOT_AFFECTED_FILTER_REASON)


def _matches_enumerated_version(
    versions: Sequence[str], installed: str, scheme: VersionScheme
) -> bool:
    """Return whether the installed version appears in the affected enumeration."""
    for version in versions:
        candidate = version.strip()
        if candidate == installed:
            return True
        if compare_versions(installed, candidate, scheme) == 0:
            return True
    return False


def _satisfies_range(
    affected_range: AffectedRange, installed: str, scheme: VersionScheme
) -> Optional[bool]:
    """Return whether the installed version satisfies every bound in a range."""
    if not affected_range.constraints:
        return None

    for constraint in affected_range.constraints:
        outcome = _satisfies_constraint(constraint, installed, scheme)
        if outcome is None:
            return None
        if not outcome:
            return False
    return True


def _satisfies_constraint(
    constraint: VersionConstraint, installed: str, scheme: VersionScheme
) -> Optional[bool]:
    """Return whether the installed version satisfies one bound."""
    ordering = compare_versions(installed, constraint.version, scheme)
    if ordering is None:
        return None

    if constraint.operator == _AT_LEAST:
        return ordering >= 0
    if constraint.operator == _GREATER:
        return ordering > 0
    if constraint.operator == _AT_MOST:
        return ordering <= 0
    if constraint.operator == _LESS:
        return ordering < 0
    if constraint.operator == _EQUAL:
        return ordering == 0
    return None


def _dict_list(value: object) -> List[Mapping[str, object]]:
    """Return the mapping members of a JSON list, ignoring anything else."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: object) -> List[str]:
    """Return the non-empty string members of a JSON list."""
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _string_value(value: object) -> Optional[str]:
    """Return a non-empty string, or None for anything else."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
