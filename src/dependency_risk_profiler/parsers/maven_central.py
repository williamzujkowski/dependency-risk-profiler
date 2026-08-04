"""Bounded, hardened retrieval of POMs from Maven Central.

Resolving a Maven version that lives in a parent POM or an imported BOM means
reading XML that the project author does not control and we did not write. That
is attacker-influenceable input, so every fetch here is fenced:

* **One host, one scheme.** URLs are built from validated coordinates against
  ``https://repo1.maven.org/maven2`` and redirects are refused, so a hostile
  coordinate cannot steer the request somewhere else.
* **Validated coordinates.** ``groupId`` / ``artifactId`` / ``version`` must
  match a strict character class before they are pasted into a URL path, and no
  ``groupId`` segment may be empty or ``..`` — a groupId's dots become path
  separators, which is exactly where traversal would hide.
* **Bounded bytes.** The response body is streamed and abandoned past
  ``_MAX_POM_BYTES``, so a multi-gigabyte "POM" costs one buffer, not memory.
* **Bounded parsing.** Parsing goes through
  :func:`..parsers.xml_utils.parse_xml_bytes`, i.e. ``xml.etree.ElementTree``,
  which resolves no external entities (no XXE); the byte cap above is what
  bounds internal-entity expansion and quadratic-blowup cost.
* **Bounded count.** Each client has a hard fetch budget for a whole manifest,
  so a POM chain cannot turn one ``analyze`` into thousands of requests.

Set ``DEPENDENCY_RISK_NO_REMOTE_POMS=1`` to disable remote resolution entirely;
version resolution then degrades to what the manifest itself can prove and
unresolved versions are reported as such rather than guessed.
"""

import logging
import os
import re
import xml.etree.ElementTree as ElementTree
from typing import Dict, Optional

import requests

from .pom_model import PomCoordinate, PomDocument, read_pom
from .xml_utils import parse_xml_bytes

logger = logging.getLogger(__name__)

MAVEN_CENTRAL_BASE = "https://repo1.maven.org/maven2"

# Environment opt-out. Set to "1"/"true"/"yes" to keep resolution fully offline.
NO_REMOTE_POMS_ENV = "DEPENDENCY_RISK_NO_REMOTE_POMS"
_TRUTHY = {"1", "true", "yes", "on"}

# A published POM is a few hundred KB at the very worst (spring-boot-dependencies
# is ~100 KB). Cap far above that and abandon anything larger.
_MAX_POM_BYTES = 2 * 1024 * 1024
_STREAM_CHUNK_BYTES = 64 * 1024

# A hard ceiling on how much of a POM graph one manifest may pull. Spring Boot
# is the realistic worst case: two parents plus roughly thirty imported BOMs,
# several with parents of their own. 192 clears that with room to spare and
# still makes "one analyze cannot become a thousand requests" a guarantee rather
# than a hope.
DEFAULT_FETCH_BUDGET = 192

# Maven coordinate grammar, tightened. Real coordinates are ASCII identifiers;
# anything with a slash, a space, or a URL escape is rejected rather than
# encoded, because there is no legitimate coordinate that needs it.
_GROUP_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*$")
_ARTIFACT_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]*$")


def remote_resolution_enabled() -> bool:
    """Return False when ``DEPENDENCY_RISK_NO_REMOTE_POMS`` opts out."""
    return os.environ.get(NO_REMOTE_POMS_ENV, "").strip().lower() not in _TRUTHY


def is_valid_coordinate(coordinate: PomCoordinate) -> bool:
    """Return True when a coordinate is safe to paste into a repository path.

    Args:
        coordinate: The ``groupId:artifactId:version`` triple to check.

    Returns:
        True if every part matches the tightened coordinate grammar.
    """
    if not coordinate.group_id or not coordinate.artifact_id:
        return False
    segments = coordinate.group_id.split(".")
    if not all(_GROUP_SEGMENT.match(segment) for segment in segments):
        return False
    if not _ARTIFACT_ID.match(coordinate.artifact_id):
        return False
    return bool(_VERSION.match(coordinate.version))


def pom_url(coordinate: PomCoordinate) -> str:
    """Return the Maven Central URL for a validated coordinate's POM."""
    group_path = coordinate.group_id.replace(".", "/")
    return (
        f"{MAVEN_CENTRAL_BASE}/{group_path}/{coordinate.artifact_id}/"
        f"{coordinate.version}/{coordinate.artifact_id}-{coordinate.version}.pom"
    )


class MavenCentralClient:
    """Fetches and caches POMs from Maven Central under a hard budget."""

    def __init__(
        self,
        timeout: int = 10,
        fetch_budget: int = DEFAULT_FETCH_BUDGET,
        enabled: Optional[bool] = None,
    ) -> None:
        """Initialize the client.

        Args:
            timeout: Per-request timeout in seconds.
            fetch_budget: Maximum number of POMs fetched over this client's life.
            enabled: Force remote fetching on or off. Defaults to the
                ``DEPENDENCY_RISK_NO_REMOTE_POMS`` environment opt-out.
        """
        self.timeout = timeout
        self.fetch_budget = fetch_budget
        self.enabled = remote_resolution_enabled() if enabled is None else enabled
        self._fetches = 0
        self._budget_warned = False
        self._cache: Dict[str, Optional[PomDocument]] = {}

    @property
    def fetch_count(self) -> int:
        """Return how many network fetches this client has actually made."""
        return self._fetches

    def budget_exhausted(self) -> bool:
        """Return True once the fetch budget for this client is spent."""
        return self._fetches >= self.fetch_budget

    def fetch_pom(self, coordinate: PomCoordinate) -> Optional[PomDocument]:
        """Return the POM for a coordinate, or None if it cannot be retrieved.

        Results (including failures) are memoized, so a diamond in the parent
        graph costs one request.

        Args:
            coordinate: The artifact whose ``.pom`` should be read.

        Returns:
            The parsed :class:`~.pom_model.PomDocument`, or None.
        """
        if not self.enabled:
            return None
        if not is_valid_coordinate(coordinate):
            logger.debug("Refusing malformed Maven coordinate: %r", coordinate)
            return None

        cache_key = f"{coordinate.key}:{coordinate.version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.budget_exhausted():
            if not self._budget_warned:
                self._budget_warned = True
                logger.warning(
                    "Maven POM fetch budget (%d) exhausted at %s; the rest of the "
                    "POM graph is left unresolved",
                    self.fetch_budget,
                    cache_key,
                )
            self._cache[cache_key] = None
            return None

        self._fetches += 1
        document = self._fetch_and_parse(coordinate)
        self._cache[cache_key] = document
        return document

    def _fetch_and_parse(self, coordinate: PomCoordinate) -> Optional[PomDocument]:
        """Perform one bounded fetch and parse it into a POM document."""
        url = pom_url(coordinate)
        root = self._fetch_xml(url)
        if root is None:
            return None
        return read_pom(root)

    def _fetch_xml(self, url: str) -> Optional[ElementTree.Element]:
        """Fetch a URL and parse it, refusing redirects and oversized bodies."""
        headers = {"User-Agent": "dependency-risk-profiler (pom resolution)"}
        try:
            with requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.status_code != 200:
                    logger.debug(
                        "Maven Central returned %s for %s", response.status_code, url
                    )
                    return None
                body = self._read_bounded(response, url)
        except requests.RequestException as exc:
            logger.debug("Maven Central fetch failed for %s: %s", url, exc)
            return None
        if body is None:
            return None
        return parse_xml_bytes(body, url)

    @staticmethod
    def _read_bounded(response: requests.Response, url: str) -> Optional[bytes]:
        """Read a streamed response body, abandoning it past the byte cap."""
        chunks = bytearray()
        for chunk in response.iter_content(chunk_size=_STREAM_CHUNK_BYTES):
            chunks.extend(chunk)
            if len(chunks) > _MAX_POM_BYTES:
                logger.warning("Abandoning oversized POM response from %s", url)
                return None
        return bytes(chunks)
