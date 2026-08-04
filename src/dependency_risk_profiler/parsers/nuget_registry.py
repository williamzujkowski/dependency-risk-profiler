"""Bounded, hardened reads of the NuGet V3 API.

The .NET adapter used to read one endpoint — the flat-container version index —
and stop, which left it with a latest version and nothing else: no repository,
so none of the eight repository-derived signals; no license; no release date
(#129). The data it needs is published, just across three documents:

* ``v3-flatcontainer/<id>/index.json`` — every published version.
* ``v3-flatcontainer/<id>/<version>/<id>.nuspec`` — the package manifest, which
  carries ``<repository>`` (the git URL), ``<license>``, ``<authors>``, and the
  package's own ``<dependencies>``. This is the one that matters: a package's
  ``projectUrl`` is frequently a docs site (MediatR publishes
  ``https://mediatr.io/``) while ``<repository>`` is the actual source.
* ``registration5-semver1/<id>/index.json`` — the catalog, which is the only
  place the publication date and the deprecation marker live.

Every fetch is fenced the same way #141 fenced Maven Central:

* **One host, one scheme.** URLs are built against ``https://api.nuget.org``,
  redirects are refused, and the *one* URL that arrives inside a payload (a
  registration page's ``@id``) is re-validated against the same host and scheme
  before it is fetched. Nothing else in a response is ever treated as a URL to
  request (#138).
* **Validated identifiers.** Package ids and versions must match NuGet's own
  grammar before they are pasted into a URL path — no slashes, no escapes, no
  dot segments, and a length bound.
* **Bounded bytes.** Bodies are streamed and abandoned past the cap, so an
  enormous "nuspec" costs one buffer rather than memory.
* **Bounded parsing.** XML goes through :func:`~.xml_utils.parse_xml_bytes`
  (``xml.etree.ElementTree`` resolves no external entities, so no XXE); JSON
  goes through the stdlib decoder under the same byte cap.
* **Bounded count.** Each client has a hard fetch budget for a whole manifest.

Set ``DEPENDENCY_RISK_NO_REMOTE_POMS=1`` to disable remote reads entirely; the
adapter then degrades to whatever the manifest itself proves, with every
unreachable signal honestly unmeasured (#74).
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
from xml.etree import ElementTree

import requests

from .maven_central import remote_resolution_enabled
from .xml_utils import child_text, find_child, local_name, parse_xml_bytes

logger = logging.getLogger(__name__)

NUGET_API_HOST = "api.nuget.org"
NUGET_API_BASE = f"https://{NUGET_API_HOST}"
FLAT_CONTAINER_BASE = f"{NUGET_API_BASE}/v3-flatcontainer"
REGISTRATION_BASE = f"{NUGET_API_BASE}/v3/registration5-semver1"

# nuget.org's own limits: ids are at most 100 characters of letters, digits and
# the three separators. Versions are SemVer 2 plus NuGet's legacy fourth part.
_PACKAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,99}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-+]{0,127}$")

# A nuspec is a few KB; registration pages for a package with a thousand
# versions are the large case and still well under a megabyte.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_STREAM_CHUNK_BYTES = 64 * 1024

# Three documents per package, plus at most one extra registration page. 512
# clears a large manifest with room to spare and still makes "one analyze cannot
# become thousands of requests" a guarantee rather than a hope.
DEFAULT_FETCH_BUDGET = 512

# The license URL nuget.org mints for an SPDX expression. Older packages carry
# only this, so it is the fallback when <license> is absent or file-typed.
_LICENSE_URL_PREFIX = "https://licenses.nuget.org/"

# NuGet's own placeholder for a package that declares no author.
_PLACEHOLDER_AUTHORS = {"", "unknown", "n/a", "none"}

# The fractional-seconds group of an ISO-8601 timestamp, anchored on the seconds
# field so a date-only value cannot match.
_FRACTIONAL_SECONDS = re.compile(r"(?<=:\d\d)\.(\d+)")


@dataclass(frozen=True)
class NuspecDocument:
    """The fields the profiler reads out of a package's ``.nuspec``.

    Attributes:
        package_id: The package's own declared id.
        version: The version this nuspec describes.
        repository_url: ``<repository url="...">``, the authoritative source
            pointer, or None.
        project_url: ``<projectUrl>``, which is often a docs site rather than a
            repository and is therefore only a fallback.
        license_expression: An SPDX expression, from ``<license
            type="expression">`` or a ``licenses.nuget.org`` URL. A
            ``type="file"`` license names a file inside the package, not a
            license id, and is deliberately not reported as one.
        authors: Declared authors, already split and trimmed.
        dependencies: Package ids this package itself depends on, across every
            target framework group.
        description: ``<description>``, for the report.
    """

    package_id: str
    version: str
    repository_url: Optional[str] = None
    project_url: Optional[str] = None
    license_expression: Optional[str] = None
    authors: Tuple[str, ...] = ()
    dependencies: FrozenSet[str] = field(default_factory=frozenset)
    description: Optional[str] = None


@dataclass(frozen=True)
class CatalogEntry:
    """The catalog facts that exist nowhere else in the V3 API.

    Attributes:
        version: The version this entry describes.
        published: Publication timestamp, or None when it is absent or
            unparseable.
        is_deprecated: True only when the catalog carries an explicit
            deprecation block; nuget.org's "unlisted" convention (a 1900
            publication date) counts as deprecated too.
        license_expression: SPDX expression when the catalog states one.
        project_url: ``projectUrl`` when the catalog states one.
        authors: Declared authors, already split and trimmed.
    """

    version: str
    published: Optional[datetime] = None
    is_deprecated: bool = False
    license_expression: Optional[str] = None
    project_url: Optional[str] = None
    authors: Tuple[str, ...] = ()


def is_valid_package_id(package_id: str) -> bool:
    """Return True when an id is safe to paste into a URL path."""
    return bool(_PACKAGE_ID.match(package_id)) and ".." not in package_id


def is_valid_version(version: str) -> bool:
    """Return True when a version is safe to paste into a URL path."""
    return bool(_VERSION.match(version)) and ".." not in version


def is_nuget_api_url(url: str) -> bool:
    """Return True when a URL is an https URL on api.nuget.org.

    Registration indexes reference their own overflow pages by absolute URL, so
    exactly one URL in this module comes out of a payload rather than being
    built from validated parts. Full parsing (not a substring check) is what
    stops a lookalike host such as ``https://api.nuget.org.evil.example/x``.

    Args:
        url: Candidate URL from a registration payload.

    Returns:
        True when the URL may be fetched.
    """
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.netloc.lower() == NUGET_API_HOST


class NuGetRegistryClient:
    """Reads nuget.org's V3 documents under a hard budget and a host allowlist."""

    def __init__(
        self,
        timeout: int = 10,
        fetch_budget: int = DEFAULT_FETCH_BUDGET,
        enabled: Optional[bool] = None,
    ) -> None:
        """Initialize the client.

        Args:
            timeout: Per-request timeout in seconds.
            fetch_budget: Maximum number of documents fetched over this
                client's life.
            enabled: Force remote fetching on or off. Defaults to the
                ``DEPENDENCY_RISK_NO_REMOTE_POMS`` environment opt-out, which is
                the same switch the Maven client honours.
        """
        self.timeout = timeout
        self.fetch_budget = fetch_budget
        self.enabled = remote_resolution_enabled() if enabled is None else enabled
        self._fetches = 0
        self._budget_warned = False
        self._version_cache: Dict[str, Tuple[str, ...]] = {}
        self._nuspec_cache: Dict[str, Optional[NuspecDocument]] = {}
        self._catalog_cache: Dict[str, Optional[CatalogEntry]] = {}

    @property
    def fetch_count(self) -> int:
        """Return how many network fetches this client has actually made."""
        return self._fetches

    def budget_exhausted(self) -> bool:
        """Return True once the fetch budget for this client is spent."""
        return self._fetches >= self.fetch_budget

    def list_versions(self, package_id: str) -> Tuple[str, ...]:
        """Return every published version, oldest first, or an empty tuple.

        Args:
            package_id: The NuGet package id.

        Returns:
            The flat-container version list.
        """
        if not is_valid_package_id(package_id):
            logger.debug("Refusing malformed NuGet package id: %r", package_id)
            return ()
        key = package_id.lower()
        cached = self._version_cache.get(key)
        if cached is not None:
            return cached

        payload = self._fetch_json(f"{FLAT_CONTAINER_BASE}/{key}/index.json")
        versions: Tuple[str, ...] = ()
        if isinstance(payload, dict):
            listed = payload.get("versions")
            if isinstance(listed, list):
                versions = tuple(
                    entry for entry in listed if isinstance(entry, str) and entry
                )
        self._version_cache[key] = versions
        return versions

    def fetch_nuspec(self, package_id: str, version: str) -> Optional[NuspecDocument]:
        """Return the parsed ``.nuspec`` for one version, or None.

        Args:
            package_id: The NuGet package id.
            version: The exact published version.

        Returns:
            The parsed document, or None when it cannot be retrieved.
        """
        if not is_valid_package_id(package_id) or not is_valid_version(version):
            logger.debug(
                "Refusing malformed NuGet coordinate: %r %r", package_id, version
            )
            return None
        lowered_id = package_id.lower()
        lowered_version = version.lower()
        key = f"{lowered_id}/{lowered_version}"
        if key in self._nuspec_cache:
            return self._nuspec_cache[key]

        url = (
            f"{FLAT_CONTAINER_BASE}/{lowered_id}/{lowered_version}/{lowered_id}.nuspec"
        )
        root = self._fetch_xml(url)
        document = None if root is None else parse_nuspec(root)
        self._nuspec_cache[key] = document
        return document

    def fetch_catalog_entry(
        self, package_id: str, preferred_version: Optional[str] = None
    ) -> Optional[CatalogEntry]:
        """Return the catalog entry for a package's newest (or chosen) version.

        The registration index is paged. Only the newest page is ever read,
        because publication date and deprecation are wanted for the version the
        report names — never for the whole release history.

        Args:
            package_id: The NuGet package id.
            preferred_version: Prefer the entry for this version when the newest
                page contains it, so the reported date matches the reported
                latest version rather than a later pre-release.

        Returns:
            The catalog entry, or None when the registration cannot be read.
        """
        if not is_valid_package_id(package_id):
            return None
        key = f"{package_id.lower()}#{preferred_version or ''}"
        if key in self._catalog_cache:
            return self._catalog_cache[key]

        entry = self._read_catalog_entry(package_id, preferred_version)
        self._catalog_cache[key] = entry
        return entry

    def _read_catalog_entry(
        self, package_id: str, preferred_version: Optional[str]
    ) -> Optional[CatalogEntry]:
        """Walk the registration index down to a single catalog entry."""
        index = self._fetch_json(f"{REGISTRATION_BASE}/{package_id.lower()}/index.json")
        if not isinstance(index, dict):
            return None
        pages = index.get("items")
        if not isinstance(pages, list) or not pages:
            return None

        newest_page = pages[-1]
        if not isinstance(newest_page, dict):
            return None

        leaves = newest_page.get("items")
        if not isinstance(leaves, list):
            # Large packages leave the newest page out of the index and give a
            # URL for it instead. That URL is re-validated before it is fetched.
            page_url = newest_page.get("@id")
            if not isinstance(page_url, str) or not is_nuget_api_url(page_url):
                logger.debug(
                    "Refusing off-host registration page for %s: %r",
                    package_id,
                    page_url,
                )
                return None
            page = self._fetch_json(page_url)
            if not isinstance(page, dict):
                return None
            leaves = page.get("items")
            if not isinstance(leaves, list):
                return None

        return _select_catalog_entry(leaves, preferred_version)

    def _fetch_json(self, url: str) -> Optional[object]:
        """Fetch a bounded JSON document, or None on any failure."""
        body = self._fetch_bounded(url)
        if body is None:
            return None
        try:
            decoded: object = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.debug("Could not decode JSON from %s: %s", url, exc)
            return None
        return decoded

    def _fetch_xml(self, url: str) -> Optional[ElementTree.Element]:
        """Fetch a bounded XML document, or None on any failure."""
        body = self._fetch_bounded(url)
        if body is None:
            return None
        return parse_xml_bytes(body, url)

    def _fetch_bounded(self, url: str) -> Optional[bytes]:
        """Perform one budgeted, redirect-refusing, size-capped fetch."""
        if not self.enabled:
            return None
        if not is_nuget_api_url(url):
            logger.debug("Refusing non-nuget.org URL: %r", url)
            return None
        if self.budget_exhausted():
            if not self._budget_warned:
                self._budget_warned = True
                logger.warning(
                    "NuGet fetch budget (%d) exhausted at %s; the remaining "
                    "package metadata is left unmeasured",
                    self.fetch_budget,
                    url,
                )
            return None

        self._fetches += 1
        headers = {"User-Agent": "dependency-risk-profiler (metadata lookup)"}
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
                        "nuget.org returned %s for %s", response.status_code, url
                    )
                    return None
                return self._read_bounded(response, url)
        except requests.RequestException as exc:
            logger.debug("nuget.org fetch failed for %s: %s", url, exc)
            return None

    @staticmethod
    def _read_bounded(response: requests.Response, url: str) -> Optional[bytes]:
        """Read a streamed response body, abandoning it past the byte cap."""
        chunks = bytearray()
        for chunk in response.iter_content(chunk_size=_STREAM_CHUNK_BYTES):
            chunks.extend(chunk)
            if len(chunks) > _MAX_RESPONSE_BYTES:
                logger.warning("Abandoning oversized nuget.org response from %s", url)
                return None
        return bytes(chunks)


def parse_nuspec(root: ElementTree.Element) -> Optional[NuspecDocument]:
    """Read a ``.nuspec`` root element into the fields the profiler uses.

    Args:
        root: Root ``<package>`` element.

    Returns:
        The parsed document, or None when the file carries no ``<metadata>``.
    """
    metadata = find_child(root, "metadata")
    if metadata is None:
        return None

    return NuspecDocument(
        package_id=child_text(metadata, "id") or "",
        version=child_text(metadata, "version") or "",
        repository_url=_repository_url(metadata),
        project_url=child_text(metadata, "projectUrl"),
        license_expression=_license_expression(metadata),
        authors=split_authors(child_text(metadata, "authors")),
        dependencies=_nuspec_dependencies(metadata),
        description=child_text(metadata, "description"),
    )


def split_authors(raw: Optional[str]) -> Tuple[str, ...]:
    """Split a nuspec ``<authors>`` value into individual names.

    NuGet stores authors as one comma-separated string. Placeholder values are
    dropped, because a package that declares no author must leave the maintainer
    signal unmeasured rather than claim one (#74).

    Args:
        raw: The raw ``<authors>`` text, or None.

    Returns:
        The distinct author names, in declaration order.
    """
    if not raw:
        return ()
    names: List[str] = []
    for part in raw.split(","):
        name = part.strip()
        if not name or name.lower() in _PLACEHOLDER_AUTHORS:
            continue
        if name not in names:
            names.append(name)
    return tuple(names)


def _repository_url(metadata: ElementTree.Element) -> Optional[str]:
    """Return ``<repository url="...">`` when the nuspec publishes one."""
    repository = find_child(metadata, "repository")
    if repository is None:
        return None
    url = (repository.get("url") or "").strip()
    return url or None


def _license_expression(metadata: ElementTree.Element) -> Optional[str]:
    """Return the SPDX expression a nuspec states, or None.

    ``<license type="file">LICENSE.txt</license>`` names a file inside the
    package rather than a license id; reporting it as one would put a filename
    in the license column and score it CRITICAL as an unrecognized license.
    """
    license_element = find_child(metadata, "license")
    if license_element is not None:
        license_type = (license_element.get("type") or "expression").strip().lower()
        text = (license_element.text or "").strip()
        if license_type == "expression" and text:
            return text

    license_url = child_text(metadata, "licenseUrl")
    return _expression_from_license_url(license_url)


def _expression_from_license_url(license_url: Optional[str]) -> Optional[str]:
    """Return the SPDX expression encoded in a licenses.nuget.org URL, or None."""
    if not license_url or not license_url.startswith(_LICENSE_URL_PREFIX):
        return None
    expression = license_url[len(_LICENSE_URL_PREFIX) :].strip("/").strip()
    return expression or None


def _nuspec_dependencies(metadata: ElementTree.Element) -> FrozenSet[str]:
    """Return every package id this package depends on, across all frameworks.

    A ``<dependencies>`` block may list ``<dependency>`` directly or nest them
    inside per-framework ``<group>`` elements; real packages use both.
    """
    dependencies = find_child(metadata, "dependencies")
    if dependencies is None:
        return frozenset()

    names = set()
    for element in dependencies.iter():
        if local_name(element.tag) != "dependency":
            continue
        identifier = (element.get("id") or "").strip()
        if identifier:
            names.add(identifier)
    return frozenset(names)


def _select_catalog_entry(
    leaves: Sequence[object], preferred_version: Optional[str]
) -> Optional[CatalogEntry]:
    """Pick one catalog entry off a registration page's leaves."""
    entries: List[Dict[str, object]] = []
    for leaf in leaves:
        if not isinstance(leaf, dict):
            continue
        catalog_entry = leaf.get("catalogEntry")
        # Some registration hives inline the catalog entry and some publish it
        # as a URL. Only the inlined form is used; chasing the URL would be a
        # second fetch per package for data the newest page already carries.
        if isinstance(catalog_entry, dict):
            entries.append(catalog_entry)
    if not entries:
        return None

    chosen = entries[-1]
    if preferred_version:
        wanted = preferred_version.lower()
        for entry in entries:
            version = entry.get("version")
            if isinstance(version, str) and version.lower() == wanted:
                chosen = entry
                break

    return _read_catalog_fields(chosen)


def _read_catalog_fields(entry: Dict[str, object]) -> CatalogEntry:
    """Convert one raw catalog entry into the typed record."""
    version = entry.get("version")
    published = _parse_timestamp(entry.get("published"))
    # nuget.org marks a package unlisted by rewriting its publication date to
    # 1900-01-01, which is the registry's own "do not use this" signal.
    unlisted = entry.get("listed") is False or (
        published is not None and published.year <= 1900
    )
    project_url = entry.get("projectUrl")
    authors = entry.get("authors")
    license_expression = entry.get("licenseExpression")
    if not isinstance(license_expression, str) or not license_expression:
        license_url = entry.get("licenseUrl")
        license_expression = _expression_from_license_url(
            license_url if isinstance(license_url, str) else None
        )

    return CatalogEntry(
        version=version if isinstance(version, str) else "",
        published=None if unlisted else published,
        is_deprecated=bool(entry.get("deprecation")) or unlisted,
        license_expression=license_expression or None,
        project_url=project_url if isinstance(project_url, str) else None,
        authors=split_authors(authors if isinstance(authors, str) else None),
    )


def _parse_timestamp(value: object) -> Optional[datetime]:
    """Parse a NuGet ISO-8601 timestamp, or None when it is unusable.

    Args:
        value: A raw ``published`` value from a catalog entry.

    Returns:
        The parsed timestamp, or None when the value is absent or malformed.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(normalize_iso_timestamp(value))
    except ValueError:
        logger.debug("Unparseable nuget.org timestamp: %s", value)
        return None


def normalize_iso_timestamp(value: str) -> str:
    """Pad a timestamp's fractional seconds to what ``fromisoformat`` accepts.

    nuget.org writes fractional seconds at whatever precision the value happens
    to need — ``2026-07-02T13:53:56.29+00:00`` is a real catalog entry. Before
    Python 3.11, :meth:`datetime.fromisoformat` accepted exactly three or six
    fractional digits and raised on anything else, which silently cost every
    package its publication date (and therefore its staleness signal) on 3.9 and
    3.10 while working fine on 3.11.

    Args:
        value: The raw timestamp.

    Returns:
        The same timestamp with ``Z`` spelled as an offset and the fractional
        part padded or truncated to six digits. Values without a fractional part
        are returned unchanged.
    """
    normalized = value.strip()
    if normalized.endswith("Z") or normalized.endswith("z"):
        normalized = normalized[:-1] + "+00:00"

    def pad(match: "re.Match[str]") -> str:
        return "." + match.group(1)[:6].ljust(6, "0")

    return _FRACTIONAL_SECONDS.sub(pad, normalized, count=1)
