"""Registry-first resolution of the maintenance-cadence date.

Staleness used to be derived from the package's *repository*: whatever
``analyze_repository`` read out of a clone won, and the registry's own release
timestamp — where it was read at all — was overwritten by it. That ordering
fails on precisely the packages the signal exists to catch. The more abandoned
a package is, the more likely its repository is archived, renamed, deleted, or
was never declared, so the more likely the repository lookup returns nothing
and the dependency scores UNKNOWN with no cadence at all. The signal degraded
exactly as the risk it measures increased (#146).

Every registry publishes when the package last shipped, that answer cannot be
broken by a repository rename, and "when did this thing last ship" is the
question the staleness signal is actually asking. So the order is inverted
here: a registry release date wins, and repository activity — a clone's last
commit, or the GitHub API's ``pushed_at`` — fills in only when the registry
published no date at all.

Where a registry genuinely publishes no date the signal stays UNMEASURED
(#74): excluded from both the numerator and the denominator rather than
defaulted to a date nobody published.
"""

import logging
from datetime import datetime
from typing import Iterable, List, Optional

from .models import DependencyMetadata
from .signals import SourceRepositoryState
from .utils import canonical_repository_url

logger = logging.getLogger(__name__)

# Provenance of ``DependencyMetadata.last_updated``. Recorded rather than
# inferred from "is it already set?" so the precedence rule is explicit: only a
# registry-sourced date blocks a later repository-sourced one.
#
# Still a stringly-typed ``additional_info`` entry, and deliberately so. This
# one records *which of two write paths won*, not whether a signal was
# measured, which puts it under the provenance item of #164 — the one gated on
# a benchmark and sequenced last. Folding it in here would be doing that work
# early and under a different name.
RELEASE_DATE_SOURCE_KEY = "release_date_source"
RELEASE_DATE_SOURCE_REGISTRY = "registry"
RELEASE_DATE_SOURCE_REPOSITORY = "repository"


def parse_registry_timestamp(value: object) -> Optional[datetime]:
    """Parse a registry ISO-8601 timestamp, or None when it is unusable.

    Args:
        value: Raw value from a registry payload, of any type.

    Returns:
        The parsed timestamp, or None when the value is absent, not a string,
        or not ISO-8601. None means unmeasured, never "now".
    """
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    # Before 3.11 ``fromisoformat`` only accepts what ``isoformat`` emits, so a
    # fractional-second field of any width other than three or six digits is
    # rejected outright. Registries publish both wider and narrower.
    normalized = _normalize_fractional_seconds(text)
    if normalized is None:
        logger.debug("Unparseable registry timestamp: %s", value)
        return None
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        logger.debug("Unparseable registry timestamp: %s", value)
        return None


def newest_timestamp(values: Iterable[object]) -> Optional[datetime]:
    """Return the newest parseable timestamp in ``values``, or None.

    Args:
        values: Raw timestamp values from a registry payload.

    Returns:
        The maximum parseable timestamp, or None when none parse. Naive and
        aware timestamps are not compared against each other: aware values win
        outright, because every registry in use publishes offsets and a naive
        value is the degenerate case.
    """
    aware: List[datetime] = []
    naive: List[datetime] = []
    for value in values:
        parsed = parse_registry_timestamp(value)
        if parsed is None:
            continue
        (aware if parsed.tzinfo is not None else naive).append(parsed)
    if aware:
        return max(aware)
    if naive:
        return max(naive)
    return None


def apply_registry_release_date(
    dependency: DependencyMetadata, released_at: Optional[datetime]
) -> None:
    """Record the registry's release date as the dependency's cadence date.

    Args:
        dependency: Dependency metadata to update in place.
        released_at: Newest release timestamp the registry published, or None
            when it published none — in which case nothing is recorded and the
            signal stays open for repository activity to answer.
    """
    if released_at is None:
        return
    dependency.last_updated = released_at
    dependency.additional_info[RELEASE_DATE_SOURCE_KEY] = RELEASE_DATE_SOURCE_REGISTRY


def apply_repository_activity_date(
    dependency: DependencyMetadata, active_at: Optional[datetime]
) -> None:
    """Fill the cadence date from repository activity, unless the registry answered.

    Repository activity is the fallback, not the primary: a package's last
    commit says when someone touched the source, while the registry says when
    consumers last received anything. Only the latter is what a dependency
    manifest actually pins.

    Args:
        dependency: Dependency metadata to update in place.
        active_at: Last commit or push timestamp, or None when unavailable.
    """
    if active_at is None:
        return
    if (
        dependency.additional_info.get(RELEASE_DATE_SOURCE_KEY)
        == RELEASE_DATE_SOURCE_REGISTRY
    ):
        return
    dependency.last_updated = active_at
    dependency.additional_info[RELEASE_DATE_SOURCE_KEY] = RELEASE_DATE_SOURCE_REPOSITORY


def record_source_repository(
    dependency: DependencyMetadata,
    repository_url: Optional[str],
    *,
    declared: Optional[str],
) -> None:
    """Record what the registry said about the package's source repository.

    The state is a :class:`~.signals.SourceRepositoryState` on the dependency
    rather than a string in ``additional_info``: this is a measurement state,
    and #164 moved measurement states out of the untyped bag so a typo cannot
    read as a different answer and mypy can see the field at all.

    Three states, and the caller has to supply the evidence for the middle one,
    which is why ``declared`` is keyword-only and has no default: the difference
    between "declared nothing" and "declared something unusable" is only visible
    in the registry's own source field, before canonicalization throws it away.

    * ``repository_url`` canonicalizes to an ``owner/repo`` root on a supported
      host -> DECLARED. The repository-derived signals can be measured.
    * it does not, but the registry's source field carried *something* ->
      UNUSABLE. A Subversion connection string, a decommissioned vanity host, a
      URL that does not parse. The package told us where its source lived and
      the answer is no longer reachable.
    * neither -> UNDECLARED. The registry answered and names no source at all.

    ``declared`` must come from the field the registry designates for the source
    repository — Maven's ``<scm>``, npm's ``repository``, a nuspec's
    ``<repository>``. A project homepage or a docs site is not a declaration of
    source, so a homepage that fails to canonicalize leaves the state
    UNDECLARED rather than promoting a landing page to a broken repository.

    Call this only when the registry actually answered. A failed lookup leaves
    the state None, which is the unmeasured state (#182).

    Args:
        dependency: Dependency metadata to update in place.
        repository_url: Repository URL resolved from the registry answer, if any.
        declared: Raw text of the registry's own source-repository field, or
            None when that field is absent or empty.
    """
    if canonical_repository_url(repository_url) is not None:
        state = SourceRepositoryState.DECLARED
    elif declared is not None and declared.strip():
        state = SourceRepositoryState.UNUSABLE
    else:
        state = SourceRepositoryState.UNDECLARED
    dependency.source_repository_state = state


def _normalize_fractional_seconds(text: str) -> Optional[str]:
    """Rewrite an ISO-8601 fractional-second field to exactly six digits.

    Args:
        text: Timestamp text whose offset is already spelled ``+00:00``.

    Returns:
        The timestamp at microsecond precision, or None when it carries no
        fractional-second field to rewrite.
    """
    dot = text.find(".")
    if dot == -1:
        return None
    end = dot + 1
    while end < len(text) and text[end].isdigit():
        end += 1
    digits = text[dot + 1 : end]
    if not digits:
        return None
    return f"{text[:dot]}.{digits[:6].ljust(6, '0')}{text[end:]}"
