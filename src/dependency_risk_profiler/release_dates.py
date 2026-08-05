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
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Iterable, List, Optional, Sequence

from .models import DependencyMetadata
from .signals import FieldSource, ProvenancedField, SourceRepositoryState
from .utils import canonical_repository_url, is_cloneable_repo_url

logger = logging.getLogger(__name__)

# Provenance of ``DependencyMetadata.last_updated``, in the coarse two-value
# form the precedence rule needs: only a registry-sourced date blocks a later
# repository-sourced one.
#
# This predates #164 step 7 and is now the *narrower* of two records. The typed
# one, ``field_sources[ProvenancedField.LAST_UPDATED]``, says which of four
# acquisition paths actually wrote the date; this one says only which of the
# two precedence classes it belongs to, and survives because it is part of the
# frozen v1 payload's ``additional_info``. It is written in the same statement
# as the typed record so the two cannot drift, and it goes away with v1 at
# ``contract.SCHEMA_V1_REMOVAL_VERSION``.
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
    dependency.record_field_source(
        ProvenancedField.LAST_UPDATED, FieldSource.REGISTRY_RELEASE
    )


def apply_repository_activity_date(
    dependency: DependencyMetadata,
    active_at: Optional[datetime],
    *,
    source: FieldSource,
) -> None:
    """Fill the cadence date from repository activity, unless the registry answered.

    Repository activity is the fallback, not the primary: a package's last
    commit says when someone touched the source, while the registry says when
    consumers last received anything. Only the latter is what a dependency
    manifest actually pins.

    "Repository activity" is two different measurements wearing one name, which
    is why ``source`` is keyword-only and has no default: a clone's last commit
    date is author-controlled and can be any value the committer typed, while
    the API's ``pushed_at`` is asserted by the server. That difference is
    exactly what #164 step 7 exists to stop collapsing, so the caller has to say
    which one it holds rather than reaching a default by forgetting to.

    Args:
        dependency: Dependency metadata to update in place.
        active_at: Last commit or push timestamp, or None when unavailable.
        source: Which acquisition path produced ``active_at``.
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
    dependency.record_field_source(ProvenancedField.LAST_UPDATED, source)


@dataclass(frozen=True)
class RepositoryResolution:
    """One sweep's answer about where a package's source lives.

    Both halves come out of one traversal of one candidate list, and that is
    the entire point of the type. They used to be produced by two sweeps over
    two key-sets: the resolver read every project URL, the declaration read a
    short list of source-ish labels, and a URL only the wider sweep could see
    therefore resolved to nothing *and* recorded "declares no source
    repository". ``python3-openid`` publishes its GitHub repository twice, and
    the tool asserted it published none (#281). A resolution failure laundered
    into a metadata assertion is a second defect on top of the failure, and it
    is unreachable once there is only one sweep to disagree with itself.

    Attributes:
        url: The canonical ``https://host/owner/repo`` root, when a candidate
            resolved to one. None means no candidate did.
        declared: Raw text of the candidate that stands as the package's
            statement about its source, exactly as the registry published it.
            None means the registry answered and named no source at all —
            which, given ``url`` is also None, is the only way UNDECLARED can
            now be reached.
    """

    url: Optional[str]
    declared: Optional[str]


def _as_published(candidate: Optional[str]) -> Optional[str]:
    """Return a candidate unchanged; the default ``prepare`` for a sweep."""
    return candidate


def resolve_repository(
    declarations: Sequence[Optional[str]],
    fallbacks: Sequence[Optional[str]] = (),
    *,
    prepare: Callable[[Optional[str]], Optional[str]] = _as_published,
) -> RepositoryResolution:
    """Resolve a package's source repository from one ordered candidate list.

    Every ecosystem hands this the same two things in its own registry's
    vocabulary:

    * ``declarations`` — the fields the registry *designates* for the source
      repository, most authoritative first: PyPI's source-labelled
      ``project_urls``, npm's ``repository``, RubyGems' ``source_code_uri``,
      Cargo's ``repository``, Packagist's ``source.url``, a nuspec's
      ``<repository>``, a POM's ``<scm>``. Whatever one of these carries is a
      statement about source, even when it is unusable.
    * ``fallbacks`` — fields that frequently *contain* a repository without
      being a declaration of one: ``home_page``, ``homepage``, ``projectUrl``,
      a POM's ``<url>``. Plenty of packages publish their repository only
      here, so they are resolved from; a docs site under one of these labels
      is still not a declaration of source, which is what #176 settled and
      what hpricot's dead ``code.whytheluckystiff.net`` homepage depends on.

    Traversal order is declarations first, then fallbacks, and it is the same
    order for both answers this returns — there is no second key-set to drift.

    A fallback earns the middle state only when it names a host this tool
    clones from and still yields no ``owner/repo`` pair
    (``https://github.com/rails``). That is a URL we recognised as a repository
    reference and could not use, which is a resolution failure and must not
    read as an absent declaration. A fallback on a host we cannot clone stays
    UNDECLARED, because "this might be a forge we have never heard of" is a
    guess, and guessing is what this repository does not do.

    Args:
        declarations: Designated source fields, most authoritative first. May
            contain None and empty entries; both mean "absent".
        fallbacks: Fields consulted only after every declaration has failed.
        prepare: Applied to each candidate before it is canonicalized, for
            registries whose designated field is not a URL. Maven's ``<scm>``
            is the one caller: ``scm:git:https://...`` has to lose its prefix
            before it parses, while ``declared`` must still carry the raw text
            so a ``<scm>`` naming Subversion stays UNUSABLE rather than
            becoming UNDECLARED.

    Returns:
        The single resolution for this package.
    """
    for candidate in (*declarations, *fallbacks):
        url = canonical_repository_url(prepare(candidate))
        if url:
            return RepositoryResolution(url=url, declared=candidate)
    for candidate in declarations:
        if candidate and candidate.strip():
            return RepositoryResolution(url=None, declared=candidate)
    for candidate in fallbacks:
        if candidate and is_cloneable_repo_url(prepare(candidate)):
            return RepositoryResolution(url=None, declared=candidate)
    return RepositoryResolution(url=None, declared=None)


def record_source_repository(
    dependency: DependencyMetadata,
    resolution: RepositoryResolution,
) -> None:
    """Record what the registry said about the package's source repository.

    The state is a :class:`~.signals.SourceRepositoryState` on the dependency
    rather than a string in ``additional_info``: this is a measurement state,
    and #164 moved measurement states out of the untyped bag so a typo cannot
    read as a different answer and mypy can see the field at all.

    Three states, and the evidence for all three arrives as one frozen
    :class:`RepositoryResolution` rather than as two independently-computed
    arguments. That is #290's half of the fix: the caller can no longer hand
    over a resolved URL and a declaration that came from a *narrower* sweep,
    because there is only one sweep and it produced both.

    * a candidate canonicalized to an ``owner/repo`` root on a supported host
      -> DECLARED. The repository-derived signals can be measured.
    * none did, but a candidate stood as a statement about source -> UNUSABLE.
      A Subversion connection string, a decommissioned vanity host, a URL that
      does not parse, a forge URL with no repository in it. The package told us
      where its source lived and the answer is not usable.
    * neither -> UNDECLARED. The registry answered and names no source at all.

    Call this only when the registry actually answered. A failed lookup leaves
    the state None, which is the unmeasured state (#182).

    Args:
        dependency: Dependency metadata to update in place.
        resolution: What this ecosystem's one sweep found, from
            :func:`resolve_repository` or built directly by an ecosystem with a
            single candidate field.
    """
    declared = resolution.declared
    if canonical_repository_url(resolution.url) is not None:
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
