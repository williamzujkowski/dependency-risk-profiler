"""Version semantics: calendar-version detection (#126) and version ordering (#61).

Two related jobs live here because both answer "what does this version string
mean?" and neither may take a dependency.

**Calendar versioning (#126).** Calendar-versioned packages put a release date
where SemVer puts a compatibility promise. ``certifi 2022.12.7`` is a CA trust
store dated 7 December 2022; ``pytz 2020.1`` is the first tzdata refresh of
2020. Measuring their drift by component distance reports a multi-year gap as
multi-*major* drift, which warns the reader about breaking upgrades that do not
exist and hides the risk that is actually there (an ancient trust store, stale
tz rules). The helpers detect the calendar shape conservatively and re-base
drift on the elapsed time between the installed release and the latest release.

**Version ordering (#61).** Deciding whether an installed version falls inside
an advisory's affected range needs a *total order*, and every ecosystem orders
differently. Naive string comparison puts ``1.10`` before ``1.9``; naive tuple
comparison cannot rank ``1.0.0-rc1`` against ``1.0.0``; and Maven inverts the
usual intuition by sorting ``1.0-alpha`` *below* ``1.0`` while sorting the
unknown qualifier ``1.0-foo`` *above* it. ``compare_versions`` implements one
comparator per scheme (PEP 440, SemVer, RubyGems, Maven, NuGet) and returns
``None`` rather than guessing when either side does not parse, so callers can
report honest-unknown (#74) instead of silently assuming safe or vulnerable.

Deliberately stdlib-only. Adding ``packaging`` would cover PEP 440 alone and
would still leave the other four schemes to hand-roll, at the cost of a runtime
dependency in a tool whose whole job is telling people about their runtime
dependencies.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Mapping, Optional, Sequence, Tuple

from .models import DependencyMetadata

# A leading component outside this range is a version number, not a year.
CALENDAR_YEAR_MIN = 1990
CALENDAR_YEAR_MAX = 2100

# ``YYYY.MM``, ``YYYY.MM.DD`` and the sequence-style ``YYYY.N`` that pytz and
# tzdata use, optionally ``v``-prefixed for Go tags and optionally carrying a
# PEP 440-ish suffix (``2026.3.post1``).
#
# The *shape* is required, never the magnitude alone: a bare ``1999``, a
# compact ``20260722`` and a Go pseudo-version ``v0.0.0-20210428235338-...``
# all fail to match, so a genuine SemVer release can only be misread if it both
# reaches a four-digit major inside the year range and carries a date-shaped
# tail, which no real package does.
_CALENDAR_VERSION_RE = re.compile(
    r"^v?(?P<year>\d{4})"
    r"\.(?P<second>\d{1,2})"
    r"(?:\.(?P<third>\d{1,2}))?"
    r"(?P<suffix>[-.+_].*)?$"
)


def is_calendar_version(version_string: Optional[str]) -> bool:
    """Return whether a version string is calendar-versioned.

    Args:
        version_string: Version string to inspect.

    Returns:
        True when the string has a calendar shape with a plausible year.
    """
    if not version_string:
        return False

    match = _CALENDAR_VERSION_RE.match(version_string.strip())
    if match is None:
        return False

    year = int(match.group("year"))
    return CALENDAR_YEAR_MIN <= year <= CALENDAR_YEAR_MAX


def uses_calendar_versioning(
    installed_version: Optional[str], latest_version: Optional[str]
) -> bool:
    """Return whether either end of a comparison is calendar-versioned.

    Args:
        installed_version: Installed version string.
        latest_version: Latest available version string.

    Returns:
        True when component distance would be meaningless for this pair.
    """
    return is_calendar_version(installed_version) or is_calendar_version(latest_version)


def as_utc(moment: Optional[datetime]) -> Optional[datetime]:
    """Normalize a timestamp to UTC, assuming naive values are already UTC.

    Args:
        moment: Timestamp to normalize.

    Returns:
        UTC-aware timestamp, or None when the input was None.
    """
    if moment is None:
        return None
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def calendar_drift_days(
    installed_release: Optional[datetime], latest_release: Optional[datetime]
) -> Optional[int]:
    """Return elapsed days between the installed release and the latest one.

    Args:
        installed_release: Publication timestamp of the installed version.
        latest_release: Publication timestamp of the latest version.

    Returns:
        Elapsed whole days, or None when either timestamp is unavailable. A
        None result means the drift signal is unmeasured and must be excluded
        from scoring (#74) rather than guessed at.
    """
    installed = as_utc(installed_release)
    latest = as_utc(latest_release)
    if installed is None or latest is None:
        return None
    return max((latest - installed).days, 0)


def release_timestamps(
    dependency: DependencyMetadata,
) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Return the installed and latest release timestamps already collected.

    Args:
        dependency: Dependency metadata.

    Returns:
        Tuple of (installed release timestamp, latest release timestamp).
    """
    metrics = dependency.community_metrics
    if metrics is None:
        return None, None
    return metrics.installed_release_date, metrics.last_release_date


def calendar_drift_label(drift_days: Optional[int]) -> str:
    """Render calendar drift in plain language.

    Args:
        drift_days: Elapsed days between releases, or None if unmeasured.

    Returns:
        A phrase such as "3 years behind (calendar versioning)".
    """
    suffix = " (calendar versioning)"
    if drift_days is None:
        return f"behind latest{suffix}"
    if drift_days < 30:
        return f"< 1 month behind{suffix}"
    if drift_days < 365:
        months = max(drift_days // 30, 1)
        unit = "month" if months == 1 else "months"
        return f"{months} {unit} behind{suffix}"

    years = max(drift_days // 365, 1)
    unit = "year" if years == 1 else "years"
    return f"{years} {unit} behind{suffix}"


def _numeric_key(version_string: str) -> Optional[Tuple[int, ...]]:
    """Return a version's numeric identity, ignoring padding and a ``v`` prefix.

    Purely numeric so it needs no version-parsing dependency: ``2022.12.07``
    and ``2022.12.7`` collapse to the same key, and anything carrying a
    non-numeric component (``1.2.3rc1``) returns None so it can only ever match
    on an exact string.
    """
    parts = version_string.strip().lstrip("vV").split(".")
    numbers: List[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        numbers.append(int(part))
    if not numbers:
        return None
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    return tuple(numbers)


def match_release_date(
    release_dates: Mapping[str, datetime], version_string: Optional[str]
) -> Optional[datetime]:
    """Look up a version's release timestamp, tolerating normalization.

    Registries and manifests disagree on spelling (``2022.12.07`` on PyPI,
    ``2022.12.7`` in a requirements pin), so an exact key miss falls back to
    comparing numeric identity.

    Args:
        release_dates: Mapping of version string to publication timestamp.
        version_string: Version to look up.

    Returns:
        The matching timestamp, or None when no version matches.
    """
    if not version_string:
        return None

    direct = release_dates.get(version_string)
    if direct is not None:
        return direct

    target = _numeric_key(version_string)
    if target is None:
        return None

    for candidate, released in release_dates.items():
        if _numeric_key(candidate) == target:
            return released
    return None


class VersionScheme(Enum):
    """Ordering rules a packaging ecosystem applies to its version strings."""

    PEP440 = "pep440"
    SEMVER = "semver"
    RUBYGEMS = "rubygems"
    MAVEN = "maven"
    NUGET = "nuget"


# A version item, encoded so every scheme's segments share one comparable
# shape without a Union: (kind, number, text). ``kind`` orders the categories
# first (both RubyGems and Maven sort textual segments below numeric ones),
# then ``number`` or ``text`` breaks the tie inside a category.
_Item = Tuple[int, int, str]

_TEXT_ITEM = 0
_NUMBER_ITEM = 1


def _compare_scalars(left: int, right: int) -> int:
    """Return -1, 0 or 1 for two integers."""
    if left == right:
        return 0
    return -1 if left < right else 1


def _compare_text(left: str, right: str) -> int:
    """Return -1, 0 or 1 for two strings, compared codepoint by codepoint."""
    if left == right:
        return 0
    return -1 if left < right else 1


def _compare_int_sequences(left: Sequence[int], right: Sequence[int]) -> int:
    """Compare numeric release segments, padding the shorter side with zeros.

    Padding rather than comparing lengths first is what makes ``1.2`` and
    ``1.2.0`` equal, as every scheme here requires.
    """
    for index in range(max(len(left), len(right))):
        first = left[index] if index < len(left) else 0
        second = right[index] if index < len(right) else 0
        if first != second:
            return -1 if first < second else 1
    return 0


# ---------------------------------------------------------------------------
# PEP 440 (Python)
# ---------------------------------------------------------------------------

_PEP440_RE = re.compile(
    r"""
    ^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_label>alpha|a|beta|b|preview|pre|c|rc)
       [-_.]?(?P<pre_number>\d+)?)?
    (?:
        -(?P<post_implicit>\d+)
      | (?P<post>[-_.]?(?:post|rev|r)[-_.]?(?P<post_number>\d+)?)
    )?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_number>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$
    """,
    re.VERBOSE | re.IGNORECASE,
)

# PEP 440 spells one concept several ways; normalize before ordering so that
# ``1.0alpha1``, ``1.0.a1`` and ``1.0-a-1`` are the same release.
_PEP440_PRE_ALIASES: Mapping[str, str] = {
    "alpha": "a",
    "a": "a",
    "beta": "b",
    "b": "b",
    "c": "rc",
    "pre": "rc",
    "preview": "rc",
    "rc": "rc",
}

# Ranks that place a pre-release segment relative to its absence. A dev release
# with no pre-release segment (``1.0.dev1``) sorts *below* every pre-release of
# the same release; a final release sorts *above* all of them.
_PRE_BELOW_ALL = -1
_PRE_PRESENT = 0
_PRE_ABOVE_ALL = 1


@dataclass(frozen=True)
class _Pep440Version:
    """A PEP 440 version decomposed into its ordering fields."""

    epoch: int
    release: Tuple[int, ...]
    pre_rank: int
    pre_label: str
    pre_number: int
    post_rank: int
    post_number: int
    dev_rank: int
    dev_number: int
    local_rank: int


def _parse_pep440(version_string: str) -> Optional[_Pep440Version]:
    """Parse a PEP 440 version, or return None when it does not conform."""
    match = _PEP440_RE.match(version_string)
    if match is None:
        return None

    release = tuple(int(part) for part in match.group("release").split("."))

    post_implicit = match.group("post_implicit")
    if post_implicit is not None:
        post_rank, post_number = 1, int(post_implicit)
    elif match.group("post") is not None:
        post_rank, post_number = 1, int(match.group("post_number") or 0)
    else:
        post_rank, post_number = 0, 0

    has_dev = match.group("dev") is not None
    dev_rank, dev_number = (
        (0, int(match.group("dev_number") or 0)) if has_dev else (1, 0)
    )

    pre_label_raw = match.group("pre_label")
    if pre_label_raw is None:
        pre_rank = _PRE_BELOW_ALL if post_rank == 0 and has_dev else _PRE_ABOVE_ALL
        pre_label, pre_number = "", 0
    else:
        pre_rank = _PRE_PRESENT
        pre_label = _PEP440_PRE_ALIASES[pre_label_raw.lower()]
        pre_number = int(match.group("pre_number") or 0)

    return _Pep440Version(
        epoch=int(match.group("epoch") or 0),
        release=release,
        pre_rank=pre_rank,
        pre_label=pre_label,
        pre_number=pre_number,
        post_rank=post_rank,
        post_number=post_number,
        dev_rank=dev_rank,
        dev_number=dev_number,
        local_rank=0 if match.group("local") is None else 1,
    )


def _compare_pep440(left: str, right: str) -> Optional[int]:
    """Order two PEP 440 versions, or return None when either does not parse."""
    first = _parse_pep440(left)
    second = _parse_pep440(right)
    if first is None or second is None:
        return None

    ordered_fields = (
        _compare_scalars(first.epoch, second.epoch),
        _compare_int_sequences(first.release, second.release),
        _compare_scalars(first.pre_rank, second.pre_rank),
        _compare_text(first.pre_label, second.pre_label),
        _compare_scalars(first.pre_number, second.pre_number),
        _compare_scalars(first.post_rank, second.post_rank),
        _compare_scalars(first.post_number, second.post_number),
        _compare_scalars(first.dev_rank, second.dev_rank),
        _compare_scalars(first.dev_number, second.dev_number),
        _compare_scalars(first.local_rank, second.local_rank),
    )
    for result in ordered_fields:
        if result != 0:
            return result
    return 0


# ---------------------------------------------------------------------------
# SemVer (npm, Go, crates.io, Packagist) and NuGet
# ---------------------------------------------------------------------------

# Deliberately looser than the SemVer grammar: a two-component ``1.2`` and a
# four-component NuGet ``1.2.3.4`` both parse, because manifests and advisory
# databases both emit them. Build metadata is captured and then ignored, as
# SemVer requires.
_SEMVER_RE = re.compile(
    r"^\s*v?(?P<core>\d+(?:\.\d+)*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z.+-]+))?\s*$"
)


@dataclass(frozen=True)
class _SemVersion:
    """A SemVer-shaped version: a numeric core plus prerelease identifiers."""

    core: Tuple[int, ...]
    prerelease: Tuple[str, ...]


def _parse_semver(version_string: str, *, fold_case: bool) -> Optional[_SemVersion]:
    """Parse a SemVer-shaped version, folding case for NuGet's ordinal rules."""
    match = _SEMVER_RE.match(version_string)
    if match is None:
        return None

    prerelease_raw = match.group("prerelease")
    identifiers: Tuple[str, ...] = ()
    if prerelease_raw is not None:
        text = prerelease_raw.lower() if fold_case else prerelease_raw
        identifiers = tuple(text.split("."))

    return _SemVersion(
        core=tuple(int(part) for part in match.group("core").split(".")),
        prerelease=identifiers,
    )


def _compare_semver_prerelease(left: Tuple[str, ...], right: Tuple[str, ...]) -> int:
    """Order SemVer prerelease identifier lists.

    Per the SemVer spec: any prerelease sorts below no prerelease; numeric
    identifiers compare numerically and sort below alphanumeric ones; and a
    longer list wins when every shared identifier is equal.
    """
    if not left and not right:
        return 0
    if not left:
        return 1
    if not right:
        return -1

    for index in range(max(len(left), len(right))):
        if index >= len(left):
            return -1
        if index >= len(right):
            return 1
        first, second = left[index], right[index]
        first_numeric, second_numeric = first.isdigit(), second.isdigit()
        if first_numeric and second_numeric:
            result = _compare_scalars(int(first), int(second))
        elif first_numeric != second_numeric:
            return -1 if first_numeric else 1
        else:
            result = _compare_text(first, second)
        if result != 0:
            return result
    return 0


def _compare_semver(left: str, right: str, *, fold_case: bool) -> Optional[int]:
    """Order two SemVer-shaped versions, or None when either does not parse."""
    first = _parse_semver(left, fold_case=fold_case)
    second = _parse_semver(right, fold_case=fold_case)
    if first is None or second is None:
        return None

    result = _compare_int_sequences(first.core, second.core)
    if result != 0:
        return result
    return _compare_semver_prerelease(first.prerelease, second.prerelease)


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------

_RUBYGEMS_RE = re.compile(r"^\s*v?\d+(?:[.-][0-9A-Za-z]+)*\s*$")
_SEGMENT_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def _trim_trailing_zero_items(items: List[_Item]) -> List[_Item]:
    """Drop trailing numeric zeros so ``1.2`` and ``1.2.0`` compare equal."""
    trimmed = list(items)
    while trimmed and trimmed[-1] == (_NUMBER_ITEM, 0, ""):
        trimmed.pop()
    return trimmed


def _rubygems_items(version_string: str) -> Optional[List[_Item]]:
    """Split a RubyGems version into ``Gem::Version``-style segments."""
    if not _RUBYGEMS_RE.match(version_string):
        return None

    items: List[_Item] = []
    for token in _SEGMENT_TOKEN_RE.findall(version_string.strip().lstrip("vV")):
        if token.isdigit():
            items.append((_NUMBER_ITEM, int(token), ""))
        else:
            items.append((_TEXT_ITEM, 0, token.lower()))
    return _trim_trailing_zero_items(items)


def _compare_rubygems(left: str, right: str) -> Optional[int]:
    """Order two RubyGems versions, or None when either does not parse.

    Mirrors ``Gem::Version#<=>``: missing segments read as numeric zero, and a
    textual segment always sorts below a numeric one, which is what makes
    ``1.0.0.beta`` a prerelease of ``1.0.0``.
    """
    first = _rubygems_items(left)
    second = _rubygems_items(right)
    if first is None or second is None:
        return None

    zero: _Item = (_NUMBER_ITEM, 0, "")
    for index in range(max(len(first), len(second))):
        left_item = first[index] if index < len(first) else zero
        right_item = second[index] if index < len(second) else zero
        result = _compare_scalars(left_item[0], right_item[0])
        if result != 0:
            return result
        if left_item[0] == _NUMBER_ITEM:
            result = _compare_scalars(left_item[1], right_item[1])
        else:
            result = _compare_text(left_item[2], right_item[2])
        if result != 0:
            return result
    return 0


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

_MAVEN_RE = re.compile(r"^\s*[0-9A-Za-z][0-9A-Za-z._+-]*\s*$")

# Maven's ``ComparableVersion`` ranks known qualifiers by their index in this
# list and ranks anything unknown *above* all of them. The empty qualifier is
# the release itself, which is why ``1.0-alpha`` < ``1.0`` < ``1.0-sp``.
_MAVEN_QUALIFIERS: Tuple[str, ...] = (
    "alpha",
    "beta",
    "milestone",
    "rc",
    "snapshot",
    "",
    "sp",
)
_MAVEN_QUALIFIER_ALIASES: Mapping[str, str] = {
    "a": "alpha",
    "b": "beta",
    "m": "milestone",
    "cr": "rc",
    "ga": "",
    "final": "",
    "release": "",
}
_MAVEN_RELEASE_CODE = str(_MAVEN_QUALIFIERS.index(""))


def _maven_qualifier_code(qualifier: str) -> str:
    """Return the sortable code Maven assigns to a qualifier."""
    canonical = _MAVEN_QUALIFIER_ALIASES.get(qualifier, qualifier)
    if canonical in _MAVEN_QUALIFIERS:
        return str(_MAVEN_QUALIFIERS.index(canonical))
    return f"{len(_MAVEN_QUALIFIERS)}-{canonical}"


def _maven_tokens(version_string: str) -> List[str]:
    """Split a Maven version on separators and on digit/letter transitions."""
    tokens: List[str] = []
    current = ""
    previous_is_digit: Optional[bool] = None

    for char in version_string.strip().lower():
        if char in ".-_+":
            if current:
                tokens.append(current)
                current = ""
            previous_is_digit = None
            continue
        is_digit = char.isdigit()
        if previous_is_digit is not None and is_digit != previous_is_digit:
            tokens.append(current)
            current = ""
        current += char
        previous_is_digit = is_digit

    if current:
        tokens.append(current)
    return tokens


def _maven_items(version_string: str) -> Optional[List[_Item]]:
    """Split a Maven version into comparable items, or None when malformed."""
    if not _MAVEN_RE.match(version_string):
        return None

    items: List[_Item] = []
    for token in _maven_tokens(version_string):
        if token.isdigit():
            items.append((_NUMBER_ITEM, int(token), ""))
        else:
            items.append((_TEXT_ITEM, 0, _maven_qualifier_code(token)))

    while items and items[-1] in (
        (_NUMBER_ITEM, 0, ""),
        (_TEXT_ITEM, 0, _MAVEN_RELEASE_CODE),
    ):
        items.pop()
    return items


def _compare_maven_item_to_absent(item: _Item) -> int:
    """Compare one Maven item against a missing one on the other side."""
    if item[0] == _NUMBER_ITEM:
        return _compare_scalars(item[1], 0)
    return _compare_text(item[2], _MAVEN_RELEASE_CODE)


def _compare_maven(left: str, right: str) -> Optional[int]:
    """Order two Maven versions, or None when either does not parse.

    A faithful subset of Maven's ``ComparableVersion``: separator and
    digit/letter tokenization, qualifier aliasing and ranking, numeric items
    above textual ones, and trailing null items trimmed. The nested item lists
    Maven derives from ``-`` separators are not modelled; they only change the
    answer for versions that mix a hyphen-introduced numeric group with a
    dotted one, which advisory ranges do not use.
    """
    first = _maven_items(left)
    second = _maven_items(right)
    if first is None or second is None:
        return None

    for index in range(max(len(first), len(second))):
        if index >= len(first):
            result = -_compare_maven_item_to_absent(second[index])
        elif index >= len(second):
            result = _compare_maven_item_to_absent(first[index])
        else:
            left_item, right_item = first[index], second[index]
            result = _compare_scalars(left_item[0], right_item[0])
            if result == 0 and left_item[0] == _NUMBER_ITEM:
                result = _compare_scalars(left_item[1], right_item[1])
            elif result == 0:
                result = _compare_text(left_item[2], right_item[2])
        if result != 0:
            return result
    return 0


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def compare_versions(left: str, right: str, scheme: VersionScheme) -> Optional[int]:
    """Order two versions under one ecosystem's rules.

    Args:
        left: Left-hand version string.
        right: Right-hand version string.
        scheme: Ordering rules to apply.

    Returns:
        -1, 0 or 1 in the usual comparison sense, or None when either side
        cannot be parsed under ``scheme``. None means "ordering unknown" and
        must never be collapsed into an assumption either way (#74).
    """
    if scheme is VersionScheme.PEP440:
        return _compare_pep440(left, right)
    if scheme is VersionScheme.RUBYGEMS:
        return _compare_rubygems(left, right)
    if scheme is VersionScheme.MAVEN:
        return _compare_maven(left, right)
    return _compare_semver(left, right, fold_case=scheme is VersionScheme.NUGET)


def is_comparable_version(version_string: Optional[str], scheme: VersionScheme) -> bool:
    """Return whether a version string can be ordered under a scheme.

    Args:
        version_string: Version string to test.
        scheme: Ordering rules to apply.

    Returns:
        True when the string parses and can take part in comparisons.
    """
    if not version_string:
        return False
    return compare_versions(version_string, version_string, scheme) is not None
