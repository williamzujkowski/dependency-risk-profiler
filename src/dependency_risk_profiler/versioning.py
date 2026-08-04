"""Calendar-versioning detection and elapsed-time drift measurement (#126).

Calendar-versioned packages put a release date where SemVer puts a
compatibility promise. ``certifi 2022.12.7`` is a CA trust store dated 7
December 2022; ``pytz 2020.1`` is the first tzdata refresh of 2020. Measuring
their drift by component distance reports a multi-year gap as multi-*major*
drift, which warns the reader about breaking upgrades that do not exist and
hides the risk that is actually there (an ancient trust store, stale tz rules).

The helpers here detect the calendar shape conservatively and re-base drift on
the elapsed time between the installed release and the latest release, using
the release timestamps the analyzers already collect for the staleness signal.
"""

import re
from datetime import datetime, timezone
from typing import List, Mapping, Optional, Tuple

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
