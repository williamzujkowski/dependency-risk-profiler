"""Ecosystem-correct version ordering (#61).

Advisory range matching is only as good as the comparator underneath it, and
every ecosystem orders differently. The tables below are the traps that make a
naive implementation quietly wrong: string comparison puts ``1.10`` before
``1.9``; tuple comparison cannot rank a prerelease against its release; and
Maven inverts the usual intuition, sorting ``1.0-alpha`` below ``1.0`` but the
unknown qualifier ``1.0-foo`` above it.
"""

from typing import List, Tuple

import pytest

from dependency_risk_profiler.versioning import (
    VersionScheme,
    compare_versions,
    is_comparable_version,
)
from dependency_risk_profiler.vulnerabilities import ecosystems

# (lower, higher) pairs. Every one must order strictly ascending.
PEP440_ASCENDING: List[Tuple[str, str]] = [
    ("1.9", "1.10"),  # the string-comparison trap
    ("1.9.9", "1.10.0"),
    ("4.0.4", "4.2"),
    ("1.0.dev1", "1.0a1"),  # a bare dev release precedes every prerelease
    ("1.0a1", "1.0a2"),
    ("1.0a2", "1.0b1"),
    ("1.0b1", "1.0rc1"),
    ("1.0rc1", "1.0"),
    ("1.0", "1.0.post1"),
    ("1.0.post1", "1.0.post2"),
    ("1.0.post1.dev1", "1.0.post1"),  # dev of a post release precedes it
    ("1.0", "1!0.1"),  # an epoch outranks everything
    ("2022.12.7", "2023.1.1"),
]

PEP440_EQUAL: List[Tuple[str, str]] = [
    ("1.2", "1.2.0"),
    ("1.2.0", "1.2.0.0"),
    ("1.0alpha1", "1.0a1"),  # spelling aliases
    ("1.0-beta-1", "1.0b1"),
    ("1.0preview1", "1.0rc1"),
    ("1.0c1", "1.0rc1"),
    ("v1.2.3", "1.2.3"),
]

SEMVER_ASCENDING: List[Tuple[str, str]] = [
    ("1.9.0", "1.10.0"),
    ("1.0.0-alpha", "1.0.0-alpha.1"),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta"),  # numeric sorts below alphanumeric
    ("1.0.0-alpha.beta", "1.0.0-beta"),
    ("1.0.0-beta.2", "1.0.0-beta.11"),  # numeric identifiers compare as numbers
    ("1.0.0-beta.11", "1.0.0-rc.1"),
    ("1.0.0-rc.1", "1.0.0"),  # any prerelease precedes its release
    ("0.0.0-20210428235338-abcdef", "0.0.1"),  # Go pseudo-version
]

SEMVER_EQUAL: List[Tuple[str, str]] = [
    ("1.0.0", "1.0.0+build.7"),  # build metadata is ignored
    ("v1.2.3", "1.2.3"),
    ("1.2", "1.2.0"),
    ("1.2.3+incompatible", "1.2.3"),
]

RUBYGEMS_ASCENDING: List[Tuple[str, str]] = [
    ("1.9.0", "1.10.0"),
    ("1.0.0.beta", "1.0.0"),  # a textual segment always sorts below a numeric one
    ("1.0.0.beta1", "1.0.0.beta2"),
    ("1.0.0.alpha", "1.0.0.beta"),
    ("1.0.0.rc1", "1.0.0"),
    ("5.2.4.3", "5.2.4.4"),
]

RUBYGEMS_EQUAL: List[Tuple[str, str]] = [
    ("1.2", "1.2.0"),
    ("1.2.0.0", "1.2"),
]

MAVEN_ASCENDING: List[Tuple[str, str]] = [
    ("1.9", "1.10"),
    ("1.0-alpha", "1.0-beta"),
    ("1.0-beta", "1.0-milestone"),
    ("1.0-milestone", "1.0-rc"),
    ("1.0-rc", "1.0-snapshot"),
    ("1.0-snapshot", "1.0"),  # the release outranks its own snapshot
    ("1.0-alpha", "1.0"),  # the qualifier trap
    ("1.0", "1.0-sp"),  # ... and its mirror image: sp outranks the release
    ("1.0", "1.0-foo"),  # unknown qualifiers rank above every known one
    ("1.0-sp", "1.0-foo"),
    ("1.0", "1.0.1"),
    ("2.14.1", "2.15.0"),
]

MAVEN_EQUAL: List[Tuple[str, str]] = [
    ("1.0", "1.0.0"),
    ("1.0", "1.0-ga"),  # ga/final/release all spell "the release itself"
    ("1.0", "1.0-final"),
    ("1.0-a1", "1.0-alpha-1"),  # single-letter aliases
    ("1.0-b2", "1.0-beta-2"),
    ("1.0-cr1", "1.0-rc1"),
]

NUGET_ASCENDING: List[Tuple[str, str]] = [
    ("1.0.0-beta", "1.0.0"),
    ("1.0.0.1", "1.0.0.2"),  # NuGet's fourth revision component
    ("1.0.0-alpha", "1.0.0-beta"),
    ("12.0.3", "13.0.1"),
]

NUGET_EQUAL: List[Tuple[str, str]] = [
    ("1.0.0-Beta", "1.0.0-beta"),  # prerelease labels are case-insensitive
    ("1.0.0", "1.0.0.0"),
    ("01.0.0", "1.0.0"),  # leading zeros are not significant
]

ASCENDING_CASES = (
    [(VersionScheme.PEP440, lo, hi) for lo, hi in PEP440_ASCENDING]
    + [(VersionScheme.SEMVER, lo, hi) for lo, hi in SEMVER_ASCENDING]
    + [(VersionScheme.RUBYGEMS, lo, hi) for lo, hi in RUBYGEMS_ASCENDING]
    + [(VersionScheme.MAVEN, lo, hi) for lo, hi in MAVEN_ASCENDING]
    + [(VersionScheme.NUGET, lo, hi) for lo, hi in NUGET_ASCENDING]
)

EQUAL_CASES = (
    [(VersionScheme.PEP440, lo, hi) for lo, hi in PEP440_EQUAL]
    + [(VersionScheme.SEMVER, lo, hi) for lo, hi in SEMVER_EQUAL]
    + [(VersionScheme.RUBYGEMS, lo, hi) for lo, hi in RUBYGEMS_EQUAL]
    + [(VersionScheme.MAVEN, lo, hi) for lo, hi in MAVEN_EQUAL]
    + [(VersionScheme.NUGET, lo, hi) for lo, hi in NUGET_EQUAL]
)


@pytest.mark.parametrize("scheme,lower,higher", ASCENDING_CASES)
def test_ordering_is_strict_and_antisymmetric(
    scheme: VersionScheme, lower: str, higher: str
) -> None:
    """Each pair orders ascending, and reversing the arguments flips the sign."""
    assert compare_versions(lower, higher, scheme) == -1
    assert compare_versions(higher, lower, scheme) == 1


@pytest.mark.parametrize("scheme,left,right", EQUAL_CASES)
def test_equivalent_spellings_compare_equal(
    scheme: VersionScheme, left: str, right: str
) -> None:
    """Different spellings of one version are the same version."""
    assert compare_versions(left, right, scheme) == 0
    assert compare_versions(right, left, scheme) == 0


UNPARSEABLE = [
    (VersionScheme.PEP440, "not-a-version"),
    (VersionScheme.PEP440, ""),
    (VersionScheme.PEP440, "*"),
    (VersionScheme.PEP440, "latest"),
    (VersionScheme.SEMVER, "^1.2.3"),  # a range, not a version
    (VersionScheme.SEMVER, "git+https://example.invalid/pkg.git"),
    (VersionScheme.RUBYGEMS, ">= 1.2"),
    (VersionScheme.MAVEN, "${project.version}"),
    (VersionScheme.NUGET, "[1.0,2.0)"),  # a NuGet range bracket
]


@pytest.mark.parametrize("scheme,version_string", UNPARSEABLE)
def test_unparseable_versions_report_unknown_not_a_guess(
    scheme: VersionScheme, version_string: str
) -> None:
    """An unorderable string yields None, never a fabricated ordering (#74)."""
    assert compare_versions(version_string, "1.0.0", scheme) is None
    assert compare_versions("1.0.0", version_string, scheme) is None
    assert not is_comparable_version(version_string, scheme)


def test_none_version_is_not_comparable() -> None:
    """A missing version is not comparable and must not be treated as 0."""
    assert not is_comparable_version(None, VersionScheme.PEP440)


def test_string_comparison_would_have_been_wrong() -> None:
    """The regression this guards: lexical ordering inverts 1.9 and 1.10."""
    assert "1.10" < "1.9"  # what a naive implementation would conclude
    assert compare_versions("1.10", "1.9", VersionScheme.PEP440) == 1


SCHEME_BY_ECOSYSTEM = [
    ("python", VersionScheme.PEP440),
    ("pypi", VersionScheme.PEP440),
    ("nodejs", VersionScheme.SEMVER),
    ("npm", VersionScheme.SEMVER),
    ("golang", VersionScheme.SEMVER),
    ("cargo", VersionScheme.SEMVER),
    ("composer", VersionScheme.SEMVER),
    ("ruby", VersionScheme.RUBYGEMS),
    ("rubygems", VersionScheme.RUBYGEMS),
    ("maven", VersionScheme.MAVEN),
    ("java", VersionScheme.MAVEN),
    ("nuget", VersionScheme.NUGET),
    ("dotnet", VersionScheme.NUGET),
]


@pytest.mark.parametrize("ecosystem,scheme", SCHEME_BY_ECOSYSTEM)
def test_every_ecosystem_alias_routes_to_its_scheme(
    ecosystem: str, scheme: VersionScheme
) -> None:
    """The registry is the single source of truth for ordering rules too."""
    assert ecosystems.version_scheme(ecosystem) is scheme


def test_unknown_ecosystem_falls_back_to_lenient_semver() -> None:
    """An unrecognized ecosystem picks a comparator, never an ordering."""
    assert ecosystems.version_scheme("gopher-holes") is VersionScheme.SEMVER
    assert ecosystems.version_scheme("") is VersionScheme.SEMVER
