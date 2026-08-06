"""Bounded, hardened retrieval of Maven documents from more than one repository.

Resolving a Maven version that lives in a parent POM or an imported BOM means
reading XML that the project author does not control and we did not write. That
is attacker-influenceable input, so every fetch here is fenced:

* **A closed host set, one scheme.** URLs are built from validated coordinates
  against the compile-time constant bases in :data:`DEFAULT_REPOSITORIES` and
  redirects are refused, so neither a hostile coordinate nor a hostile manifest
  can steer the request somewhere else. Nothing read out of a build file, a
  POM, or a repository response ever becomes a host here (#278).
* **Validated coordinates.** ``groupId`` / ``artifactId`` / ``version`` must
  match a strict character class before they are pasted into a URL path, and no
  ``groupId`` segment may be empty or ``..`` — a groupId's dots become path
  separators, which is exactly where traversal would hide.
* **Bounded bytes.** The response body is streamed and abandoned past
  ``_MAX_DOCUMENT_BYTES``, so a multi-gigabyte "POM" costs one buffer, not
  memory.
* **Bounded parsing.** Parsing goes through
  :func:`..parsers.xml_utils.parse_xml_bytes`, i.e. ``xml.etree.ElementTree``,
  which resolves no external entities (no XXE); the byte cap above is what
  bounds internal-entity expansion and quadratic-blowup cost.
* **Bounded count.** Each client has a hard fetch budget for a whole manifest's
  POM graph, so a POM chain cannot turn one ``analyze`` into thousands of
  requests.

Set ``DEPENDENCY_RISK_NO_REMOTE_POMS=1`` to disable remote resolution entirely;
version resolution then degrades to what the manifest itself can prove and
unresolved versions are reported as such rather than guessed.

Why more than one repository
----------------------------
Until #278 this module knew one base URL, ``repo1.maven.org``. Every
``androidx.*``, ``com.google.android.*`` and most ``com.android.tools*``
artifact is published to Google's Maven repository and **not** to Central, so
on Signal-Android 62 of 94 dependencies 404'd on the only repository the tool
would ask and every repository-derived signal for them was unmeasured.

Two questions are asked of a repository, and they take different answers:

* **The artifact's POM at a pinned ``groupId:artifactId:version``.** Coordinates
  are immutable, so whatever a repository serves at one is the whole answer and
  the first repository that has it wins. Order is therefore a pure cost
  question: Central is first because it holds the great majority of the JVM
  population, so a Central hit costs no second request.
* **``maven-metadata.xml``, i.e. the latest version and the last publication
  date.** That is a *per-repository view of a global fact*, and one repository's
  answer is a floor rather than a total. Central's copy of
  ``com.android.tools.build:gradle`` stops at 2.3.0 and ``lastUpdated``
  2017-03-06, the day Google moved the Android toolchain to its own repository;
  Google's is at 9.4.0-alpha07 and last week. First-hit-wins on *that* question
  reports a live artifact as nine years stale and a current project as ahead of
  the latest release — a confident wrong number, which is worse than the
  unmeasured one #278 is about. So this question is asked of **every**
  configured repository and merged on ``lastUpdated``.

What is deliberately *not* done is read the repository list out of the build.
Gradle's ``repositories { }`` and Maven's ``<repositories>`` name arbitrary
URLs — Signal's own ``settings.gradle.kts`` names two under
``raw.githubusercontent.com`` and a ``mavenLocal()`` — and honouring them turns
a fetcher with a closed host set into one whose destination is chosen by the
file under analysis, which is the SSRF sink :mod:`..secure_http` exists for.
Selecting from a fixed allowlist by what a manifest declares is a real
follow-up; taking URLs from it is not.
"""

import logging
import os
import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

import requests

from ..signals import RegistryLookupState
from .pom_model import PomCoordinate, PomDocument, read_pom
from .xml_utils import local_name, parse_xml_bytes

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MavenRepository:
    """One repository this client is willing to ask, named and pinned.

    Attributes:
        name: Short stable label, used in logs and in lookup records. Never a
            URL: these strings are rendered into reports.
        base_url: The ``maven2``-layout root, a compile-time constant. Nothing
            read out of a manifest or a response is ever put here (#278).
    """

    name: str
    base_url: str

    def pom_url(self, coordinate: PomCoordinate) -> str:
        """Return this repository's URL for a validated coordinate's POM.

        Args:
            coordinate: The artifact whose ``.pom`` is wanted. Must already
                have passed :func:`is_valid_coordinate`.

        Returns:
            The absolute URL of the ``.pom``.
        """
        group_path = coordinate.group_id.replace(".", "/")
        return (
            f"{self.base_url}/{group_path}/{coordinate.artifact_id}/"
            f"{coordinate.version}/{coordinate.artifact_id}-{coordinate.version}.pom"
        )

    def metadata_url(self, group_id: str, artifact_id: str) -> str:
        """Return this repository's ``maven-metadata.xml`` URL for an artifact.

        Args:
            group_id: The artifact's group. Must already have passed
                :func:`is_valid_artifact`.
            artifact_id: The artifact id.

        Returns:
            The absolute URL of the artifact's ``maven-metadata.xml``.
        """
        group_path = group_id.replace(".", "/")
        return f"{self.base_url}/{group_path}/{artifact_id}/maven-metadata.xml"


#: Maven Central. The default for everything that is not a Google publication,
#: and the first repository asked because it holds the great majority of the
#: JVM population — so on a non-Android project the second repository is never
#: reached and #278 costs no extra request at all.
CENTRAL = MavenRepository("central", "https://repo1.maven.org/maven2")

#: Google's Maven repository. Serves the same ``maven2`` directory layout
#: Central does, so nothing but the base URL differs. It is where every
#: ``androidx.*`` and ``com.google.android.*`` artifact lives, and where the
#: Android toolchain (``com.android.tools*``) has been published since 2017.
GOOGLE = MavenRepository("google", "https://dl.google.com/dl/android/maven2")

#: The repositories asked, in order. A closed compile-time constant: see the
#: module docstring for why a manifest is not allowed to add to it.
#:
#: Four more were measured against Signal-Android's 94 dependencies and
#: rejected, because a repository costs a request on every miss:
#:
#: * **JitPack** answered for 0 of them, and is a build service rather than a
#:   registry — a cold ``maven-metadata.xml`` for ``com.github.PhilJay:
#:   MPAndroidChart`` took 15.3 s because the request triggers a build, against
#:   ~45 ms for a miss anywhere else.
#: * **Gradle's plugin portal** answered for 0, and 303-redirects misses to
#:   Central, so it is Central plus plugin marker artifacts — and plugin
#:   coordinates live in ``buildscript``/``plugins`` blocks, which
#:   :mod:`.gradle_dsl` deliberately does not read.
#: * **repo.spring.io/release** answered ``401`` to an anonymous request for
#:   ``org.springframework:spring-core``. Spring GA releases are on Central.
#: * **Sonatype snapshots** hold ``-SNAPSHOT`` versions by construction, which
#:   are mutable and are not what a released manifest pins.
DEFAULT_REPOSITORIES: Tuple[MavenRepository, ...] = (CENTRAL, GOOGLE)

# Environment opt-out. Set to "1"/"true"/"yes" to keep resolution fully offline.
NO_REMOTE_POMS_ENV = "DEPENDENCY_RISK_NO_REMOTE_POMS"
_TRUTHY = {"1", "true", "yes", "on"}

# A published POM is a few hundred KB at the very worst (spring-boot-dependencies
# is ~100 KB) and a maven-metadata.xml is smaller still. Cap far above that and
# abandon anything larger.
_MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
_STREAM_CHUNK_BYTES = 64 * 1024

# A hard ceiling on how much of a POM graph one manifest may pull. Spring Boot
# is the realistic worst case: two parents plus roughly thirty imported BOMs,
# several with parents of their own. 192 clears that with room to spare and
# still makes "one analyze cannot become a thousand requests" a guarantee rather
# than a hope.
#
# Metadata lookups are deliberately *not* counted against it. The POM graph is
# recursive and its size is a property of what the artifacts declare, which is
# why it needs a bound; metadata lookups are one per artifact per repository,
# memoized, so their count is already bounded by the manifest.
DEFAULT_FETCH_BUDGET = 192

# Maven Central's <lastUpdated> spelling: yyyyMMddHHmmss, UTC, no separators.
_LAST_UPDATED_FORMAT = "%Y%m%d%H%M%S"

# Maven coordinate grammar, tightened. Real coordinates are ASCII identifiers;
# anything with a slash, a space, or a URL escape is rejected rather than
# encoded, because there is no legitimate coordinate that needs it.
_GROUP_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")
_ARTIFACT_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]*$")


class RepositoryOutcome(Enum):
    """What one repository said when it was asked for one document.

    Three answers, and the *absence* of an entry is a fourth thing: that
    repository was never asked. Keeping :attr:`ABSENT` and :attr:`UNANSWERED`
    apart is the #219 shape applied to repositories — an outage that reads as
    "the artifact is not published" is a confident wrong answer, and it is the
    one this whole distinction exists to make unrepresentable.
    """

    #: 200, and the body parsed. The repository has the document.
    FOUND = "found"

    #: 404 or 410. The repository answered, and it does not publish this.
    ABSENT = "absent"

    #: Anything else: a connection failure, a timeout, a 5xx, a 403, a redirect
    #: (which this client refuses), an oversized body, or a body that did not
    #: parse as XML. The repository did not answer the question.
    UNANSWERED = "unanswered"


@dataclass(frozen=True)
class RepositoryLookup:
    """Which repositories were asked for one document, and what each said.

    This is the type that makes AGENTS.md rule 4 structural rather than
    remembered. :attr:`state` is *derived* from the two fields and cannot be
    passed in, so "every repository was asked and none had it" is reachable
    only when the outcomes actually cover the configured set. A lookup that
    stopped early — because the fetch budget ran out, because the coordinate
    was malformed, because remote resolution is switched off — carries fewer
    outcomes than repositories and therefore cannot report absence.

    Attributes:
        outcomes: One entry per repository actually asked, in the order they
            were asked.
        configured: Every repository that was eligible to be asked.
    """

    outcomes: Tuple[Tuple[MavenRepository, RepositoryOutcome], ...]
    configured: Tuple[MavenRepository, ...]

    @property
    def found_in(self) -> Tuple[MavenRepository, ...]:
        """Return the repositories that had the document.

        Returns:
            The repositories whose outcome was :attr:`RepositoryOutcome.FOUND`,
            in the order they answered.
        """
        return tuple(
            repository
            for repository, outcome in self.outcomes
            if outcome is RepositoryOutcome.FOUND
        )

    @property
    def unanswered(self) -> Tuple[str, ...]:
        """Return the names of repositories that were asked and did not answer.

        Returns:
            The short names, in the order they were asked. Names only: these
            strings are rendered into reports, so a URL must never be one.
        """
        return tuple(
            repository.name
            for repository, outcome in self.outcomes
            if outcome is RepositoryOutcome.UNANSWERED
        )

    @property
    def state(self) -> RegistryLookupState:
        """Return what this lookup established, derived from the outcomes.

        The order of the tests is the argument:

        1. Something was found, so the lookup answered.
        2. Nothing was asked, so nothing was established.
        3. A repository was asked and did not answer, so absence cannot be
           claimed — the #219 rule, at repository scope.
        4. Every configured repository answered, and none had it. Only here is
           absence a measurement.
        5. Some repositories answered "no" and the rest were never reached.
           That is a lookup that did not finish, not an artifact that does not
           exist.

        Returns:
            The state the recorded outcomes support.
        """
        if any(outcome is RepositoryOutcome.FOUND for _, outcome in self.outcomes):
            return RegistryLookupState.ANSWERED
        if not self.outcomes:
            return RegistryLookupState.NOT_ATTEMPTED
        if any(outcome is RepositoryOutcome.UNANSWERED for _, outcome in self.outcomes):
            return RegistryLookupState.FAILED
        asked = {repository.name for repository, _ in self.outcomes}
        if asked >= {repository.name for repository in self.configured}:
            return RegistryLookupState.ABSENT_EVERYWHERE
        return RegistryLookupState.NOT_ATTEMPTED


@dataclass(frozen=True)
class PomLookup:
    """A POM, or the record of who was asked for it and what they said.

    Attributes:
        document: The parsed POM, or None when no repository produced one.
        lookup: Which repositories were asked and what each answered.
    """

    document: Optional[PomDocument]
    lookup: RepositoryLookup


@dataclass(frozen=True)
class ArtifactVersioning:
    """What the repositories jointly say about an artifact's release history.

    Merged rather than taken from the first answer: see the module docstring
    for ``com.android.tools.build:gradle``, where Central's view of the same
    artifact is nine years out of date.

    Attributes:
        latest: The newest release (or, failing that, latest) version any
            repository names, from whichever repository published most
            recently. None when nobody said.
        last_updated: That same repository's ``<lastUpdated>``, as UTC. None
            when nobody said. Paired with :attr:`latest` on purpose — taking
            the version from one repository and the date from another would
            fabricate a release that never happened.
        lookup: Which repositories were asked and what each answered.
    """

    latest: Optional[str]
    last_updated: Optional[datetime]
    lookup: RepositoryLookup


def remote_resolution_enabled() -> bool:
    """Return False when ``DEPENDENCY_RISK_NO_REMOTE_POMS`` opts out."""
    return os.environ.get(NO_REMOTE_POMS_ENV, "").strip().lower() not in _TRUTHY


def is_valid_artifact(group_id: str, artifact_id: str) -> bool:
    """Return True when a ``groupId:artifactId`` pair is safe to put in a path.

    Args:
        group_id: The artifact's group.
        artifact_id: The artifact id.

    Returns:
        True if both match the tightened coordinate grammar.
    """
    if not group_id or not artifact_id:
        return False
    if not all(_GROUP_SEGMENT.match(segment) for segment in group_id.split(".")):
        return False
    return bool(_ARTIFACT_ID.match(artifact_id))


def is_valid_coordinate(coordinate: PomCoordinate) -> bool:
    """Return True when a coordinate is safe to paste into a repository path.

    Args:
        coordinate: The ``groupId:artifactId:version`` triple to check.

    Returns:
        True if every part matches the tightened coordinate grammar.
    """
    if not is_valid_artifact(coordinate.group_id, coordinate.artifact_id):
        return False
    return bool(_VERSION.match(coordinate.version))


class MavenRepositoryClient:
    """Fetches and caches Maven documents from a fixed set of repositories.

    One client per manifest. It memoizes both questions it can ask, so a
    diamond in the parent graph costs one request and an artifact whose POM is
    read twice costs one lookup.
    """

    def __init__(
        self,
        timeout: int = 10,
        fetch_budget: int = DEFAULT_FETCH_BUDGET,
        enabled: Optional[bool] = None,
        repositories: Sequence[MavenRepository] = DEFAULT_REPOSITORIES,
    ) -> None:
        """Initialize the client.

        Args:
            timeout: Per-request timeout in seconds.
            fetch_budget: Maximum number of POMs fetched over this client's
                life. Metadata lookups are not counted against it; see
                :data:`DEFAULT_FETCH_BUDGET`.
            enabled: Force remote fetching on or off. Defaults to the
                ``DEPENDENCY_RISK_NO_REMOTE_POMS`` environment opt-out.
            repositories: The repositories to ask, in order. Defaults to
                :data:`DEFAULT_REPOSITORIES`; tests narrow it to prove that
                what a repository contributes is actually being read.
        """
        self.timeout = timeout
        self.fetch_budget = fetch_budget
        self.enabled = remote_resolution_enabled() if enabled is None else enabled
        self.repositories: Tuple[MavenRepository, ...] = tuple(repositories)
        self._fetches = 0
        self._budget_warned = False
        self._cache: Dict[str, PomLookup] = {}
        self._versioning_cache: Dict[str, ArtifactVersioning] = {}

    @property
    def fetch_count(self) -> int:
        """Return how many POM fetches this client has actually charged."""
        return self._fetches

    def budget_exhausted(self) -> bool:
        """Return True once the POM fetch budget for this client is spent."""
        return self._fetches >= self.fetch_budget

    def fetch_pom(
        self,
        coordinate: PomCoordinate,
        prefer: Sequence[MavenRepository] = (),
    ) -> PomLookup:
        """Return the POM for a coordinate, and who was asked for it.

        Content at a Maven coordinate is immutable, so the first repository
        that has it is the whole answer and the walk stops there.

        Args:
            coordinate: The artifact whose ``.pom`` should be read.
            prefer: Repositories to ask first — normally the ones an earlier
                metadata lookup found this artifact in, so a Google-published
                artifact does not pay a Central 404 for its POM as well. Purely
                an ordering hint: entries not in :attr:`repositories` are
                ignored and the rest are still asked on a miss, so a stale hint
                costs a request and never an answer.

        Returns:
            The lookup, whose ``document`` is None when no repository had it.
        """
        cache_key = f"{coordinate.key}:{coordinate.version}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        lookup = self._fetch_pom_uncached(coordinate, prefer)
        self._cache[cache_key] = lookup
        return lookup

    def _fetch_pom_uncached(
        self, coordinate: PomCoordinate, prefer: Sequence[MavenRepository]
    ) -> PomLookup:
        """Walk the repositories for one POM without consulting the cache."""
        empty = RepositoryLookup(outcomes=(), configured=self.repositories)
        if not self.enabled:
            return PomLookup(document=None, lookup=empty)
        if not is_valid_coordinate(coordinate):
            logger.debug("Refusing malformed Maven coordinate: %r", coordinate)
            return PomLookup(document=None, lookup=empty)

        outcomes: List[Tuple[MavenRepository, RepositoryOutcome]] = []
        document: Optional[PomDocument] = None
        for repository in self._walk_order(prefer):
            if self.budget_exhausted():
                self._warn_budget(coordinate.key)
                break
            self._fetches += 1
            root, outcome = self._fetch_document(repository.pom_url(coordinate))
            outcomes.append((repository, outcome))
            if root is not None:
                document = read_pom(root)
                break
        return PomLookup(
            document=document,
            lookup=RepositoryLookup(
                outcomes=tuple(outcomes), configured=self.repositories
            ),
        )

    def fetch_versioning(self, group_id: str, artifact_id: str) -> ArtifactVersioning:
        """Return the merged release history for an artifact.

        Every configured repository is asked, and the answer kept is the one
        from the repository that published most recently. A repository that
        states no ``<lastUpdated>`` loses to one that does, and the version and
        the date always come from the same document.

        Args:
            group_id: The artifact's group.
            artifact_id: The artifact id.

        Returns:
            The merged versioning, whose ``latest`` and ``last_updated`` are
            None when no repository stated them.
        """
        cache_key = f"{group_id}:{artifact_id}"
        cached = self._versioning_cache.get(cache_key)
        if cached is not None:
            return cached

        versioning = self._fetch_versioning_uncached(group_id, artifact_id)
        self._versioning_cache[cache_key] = versioning
        return versioning

    def _fetch_versioning_uncached(
        self, group_id: str, artifact_id: str
    ) -> ArtifactVersioning:
        """Ask every repository for one artifact's metadata and merge."""
        if not self.enabled or not is_valid_artifact(group_id, artifact_id):
            return ArtifactVersioning(
                latest=None,
                last_updated=None,
                lookup=RepositoryLookup(outcomes=(), configured=self.repositories),
            )

        outcomes: List[Tuple[MavenRepository, RepositoryOutcome]] = []
        latest: Optional[str] = None
        last_updated: Optional[datetime] = None
        kept = False
        for repository in self.repositories:
            root, outcome = self._fetch_document(
                repository.metadata_url(group_id, artifact_id)
            )
            outcomes.append((repository, outcome))
            if root is None:
                continue
            stamp = _last_updated(root)
            if _supersedes(stamp, last_updated, kept):
                latest, last_updated = _latest_from_metadata(root), stamp
                kept = True
        return ArtifactVersioning(
            latest=latest,
            last_updated=last_updated,
            lookup=RepositoryLookup(
                outcomes=tuple(outcomes), configured=self.repositories
            ),
        )

    def _walk_order(
        self, prefer: Sequence[MavenRepository]
    ) -> List[MavenRepository]:
        """Return the configured repositories with ``prefer`` moved to the front."""
        preferred = [
            repository for repository in prefer if repository in self.repositories
        ]
        return preferred + [
            repository
            for repository in self.repositories
            if repository not in preferred
        ]

    def _warn_budget(self, key: str) -> None:
        """Log once when the POM budget runs out mid-manifest."""
        if self._budget_warned:
            return
        self._budget_warned = True
        logger.warning(
            "Maven POM fetch budget (%d) exhausted at %s; the rest of the POM "
            "graph is left unresolved and is reported as unmeasured, not as "
            "absent",
            self.fetch_budget,
            key,
        )

    def _fetch_document(
        self, url: str
    ) -> Tuple[Optional[ElementTree.Element], RepositoryOutcome]:
        """Fetch and parse one document, classifying what the repository said.

        Args:
            url: Absolute URL, already built from a validated coordinate
                against a constant base.

        Returns:
            The parsed root and the outcome. The root is None for anything but
            :attr:`RepositoryOutcome.FOUND`.
        """
        headers = {"User-Agent": "dependency-risk-profiler (maven resolution)"}
        try:
            with requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                status = response.status_code
                if status in (404, 410):
                    logger.debug("%s: not published there (%s)", url, status)
                    return None, RepositoryOutcome.ABSENT
                if status != 200:
                    logger.debug("%s did not answer: HTTP %s", url, status)
                    return None, RepositoryOutcome.UNANSWERED
                body = self._read_bounded(response, url)
        except requests.RequestException as exc:
            logger.debug("Maven fetch failed for %s: %s", url, exc)
            return None, RepositoryOutcome.UNANSWERED
        if body is None:
            return None, RepositoryOutcome.UNANSWERED
        root = parse_xml_bytes(body, url)
        if root is None:
            return None, RepositoryOutcome.UNANSWERED
        return root, RepositoryOutcome.FOUND

    @staticmethod
    def _read_bounded(response: requests.Response, url: str) -> Optional[bytes]:
        """Read a streamed response body, abandoning it past the byte cap."""
        chunks = bytearray()
        for chunk in response.iter_content(chunk_size=_STREAM_CHUNK_BYTES):
            chunks.extend(chunk)
            if len(chunks) > _MAX_DOCUMENT_BYTES:
                logger.warning("Abandoning oversized Maven response from %s", url)
                return None
        return bytes(chunks)


def _supersedes(
    candidate: Optional[datetime], incumbent: Optional[datetime], kept: bool
) -> bool:
    """Decide whether a newly read repository answer replaces the kept one.

    Args:
        candidate: The ``<lastUpdated>`` the new answer states, or None.
        incumbent: The ``<lastUpdated>`` behind the answer kept so far.
        kept: Whether any answer has been kept yet.

    Returns:
        True when the new answer should be kept. Anything beats nothing; a
        dated answer beats an undated one; between two dated answers the newer
        wins; an undated answer never displaces one already kept.
    """
    if not kept:
        return True
    if candidate is None:
        return False
    if incumbent is None:
        return True
    return candidate > incumbent


def _latest_from_metadata(root: ElementTree.Element) -> Optional[str]:
    """Return <release> (preferred) or <latest> from a maven-metadata root.

    Args:
        root: Root element of a ``maven-metadata.xml``.

    Returns:
        The version the repository calls current, or None when it says neither.
    """
    for versioning in root:
        if local_name(versioning.tag) != "versioning":
            continue
        release: Optional[str] = None
        latest: Optional[str] = None
        for child in versioning:
            text = (child.text or "").strip()
            if not text:
                continue
            if local_name(child.tag) == "release":
                release = text
            elif local_name(child.tag) == "latest":
                latest = text
        return release or latest
    return None


def _last_updated(root: ElementTree.Element) -> Optional[datetime]:
    """Return ``<versioning><lastUpdated>`` as a UTC timestamp, or None.

    Maven writes it as a bare ``yyyyMMddHHmmss`` in UTC — no separators and no
    zone marker, which is why it needs its own parse rather than the shared
    ISO-8601 one.

    Args:
        root: Root element of a ``maven-metadata.xml``.

    Returns:
        The publication timestamp, or None when the document omits it or
        spells it in a shape this cannot read. None means unmeasured, never
        "now".
    """
    for versioning in root:
        if local_name(versioning.tag) != "versioning":
            continue
        for child in versioning:
            if local_name(child.tag) != "lastUpdated":
                continue
            text = (child.text or "").strip()
            try:
                stamp = datetime.strptime(text, _LAST_UPDATED_FORMAT)
            except ValueError:
                logger.debug("Unparseable maven-metadata lastUpdated: %r", text)
                return None
            return stamp.replace(tzinfo=timezone.utc)
    return None
