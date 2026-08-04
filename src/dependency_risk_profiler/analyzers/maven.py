"""Analyzer for Java (Maven) dependencies."""

import logging
import re
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from ..analysis_helpers import analyze_repository
from ..models import DependencyMetadata
from ..parsers.maven_central import MavenCentralClient
from ..parsers.pom_model import PomCoordinate, PomDocument
from ..parsers.xml_utils import local_name
from ..release_dates import apply_registry_release_date, record_source_repository
from .base import BaseAnalyzer
from .common import canonical_repository_url, cloned_repo, is_cloneable_repo_url

logger = logging.getLogger(__name__)

# maven-metadata.xml is small; cap the download to bound parse cost.
_MAX_METADATA_BYTES = 2 * 1024 * 1024

# Maven Central's <lastUpdated> spelling: yyyyMMddHHmmss, UTC, no separators.
_LAST_UPDATED_FORMAT = "%Y%m%d%H%M%S"

# Scopes that describe what actually ships with the artifact. "test" and
# "provided" dependencies are not part of a consumer's runtime surface, so they
# do not belong in the transitive-dependency signal.
_SHIPPED_SCOPES = {None, "compile", "runtime"}

# Maven SCM connection strings are URLs wearing a costume: "scm:git:" prefixes,
# "git://" and "ssh://" schemes, and the scp-style "git@host:owner/repo" form.
# The scp pattern demands a dotted host and a slashed path so it cannot swallow
# an ordinary URI scheme such as "mailto:someone@example.org".
_SCM_PREFIX = re.compile(r"^scm:(?:[a-z0-9_+-]+:)?", re.IGNORECASE)
_SCP_STYLE = re.compile(r"^(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+):(?!//)([^/].*/.*)$")


class MavenAnalyzer(BaseAnalyzer):
    """Analyzer for Java dependencies published to Maven Central.

    Maven Central publishes each artifact's own POM alongside its jar, and that
    POM carries the metadata every other ecosystem gets from its registry API:
    the source repository, the license, and the artifact's own dependencies.
    Reading it is what turns a Java scan from "here are your CVEs" into the same
    signal set the profiler collects for npm, PyPI, and Go.
    """

    def __init__(
        self,
        timeout: int = 10,
        client: Optional[MavenCentralClient] = None,
    ) -> None:
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
            client: Bounded Maven Central client used to read artifact POMs.
                Defaults to a fresh one; tests inject a disabled client.
        """
        super().__init__(timeout)
        self.metadata_cache: Dict[str, Dict[str, object]] = {}
        self.client = (
            client
            if client is not None
            else MavenCentralClient(timeout=timeout, fetch_budget=512)
        )

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Java dependencies and collect Maven Central metadata.

        Args:
            dependencies: Dictionary mapping ``groupId:artifactId`` to metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info("Analyzing Maven package: %s", name)
            # Route vulnerability lookups to the Maven OSV ecosystem.
            dep.additional_info["ecosystem"] = "maven"

            try:
                latest, last_updated = self._get_versioning(name)
                if latest:
                    dep.latest_version = latest
                # maven-metadata.xml states when the artifact last shipped, in
                # <versioning><lastUpdated>. Nothing read it, so the release
                # cadence was unmeasured for every Maven artifact and staleness
                # — the signal the tool exists for — could only ever come from a
                # clone (#73).
                apply_registry_release_date(dep, last_updated)
                document = self._collect_artifact_metadata(name, dep, latest)
                # What the POM says about its source is a measured fact, and it
                # has three answers rather than two. The discriminator is not
                # whether <scm> is present but whether what it names is a git
                # forge: across 25 sampled artifacts, 9 declared no <scm> at
                # all, 12 named a Subversion or CVS host, and 4 named a forge
                # and all 4 resolved (#176). Recorded only when a POM was
                # actually read — an artifact whose POM could not be fetched is
                # unmeasured, not undeclared (#182).
                if document is not None:
                    record_source_repository(
                        dep, dep.repository_url, declared=document.scm_url
                    )
            except Exception as exc:
                logger.error("Error analyzing Maven package %s: %s", name, exc)

        if self.clone_repos:
            self._analyze_repositories(dependencies)

        return dependencies

    def _collect_artifact_metadata(
        self,
        name: str,
        dep: DependencyMetadata,
        latest: Optional[str],
    ) -> Optional[PomDocument]:
        """Read the artifact's published POM for repo, license, and deps.

        The installed version is preferred so the metadata describes what the
        project actually uses; the latest version is the fallback for artifacts
        whose version is managed somewhere we could not reach.

        Returns:
            The POM that was read, or None when no candidate version answered —
            which is a failed lookup, not a statement about the artifact.
        """
        group_id, _, artifact_id = name.partition(":")
        if not group_id or not artifact_id:
            return None

        for version in self._candidate_versions(dep, latest):
            document = self.client.fetch_pom(
                PomCoordinate(group_id, artifact_id, version)
            )
            if document is None:
                continue
            self._apply_artifact_metadata(name, dep, document)
            return document
        return None

    @staticmethod
    def _candidate_versions(
        dep: DependencyMetadata, latest: Optional[str]
    ) -> List[str]:
        """Return the versions worth trying for the artifact's own POM."""
        candidates: List[str] = []
        for version in (dep.installed_version, latest):
            if version and version not in candidates:
                candidates.append(version)
        return candidates

    def _apply_artifact_metadata(
        self, name: str, dep: DependencyMetadata, document: PomDocument
    ) -> None:
        """Copy repository, license, and dependency data off an artifact POM."""
        # <scm> is the authoritative pointer; <url> is the fallback for POMs
        # that only publish a project homepage. Both get trimmed to the
        # repository root, because monorepo artifacts point at a subdirectory
        # and both git clone and the GitHub API reject that deeper path.
        for candidate in (document.scm_url, document.project_url):
            repository_url = canonical_repository_url(normalize_scm_url(candidate))
            if repository_url:
                dep.repository_url = repository_url
                break

        # analyze_license() reads a registry-metadata mapping; give it one built
        # from <licenses>, using the plural key so the multi-license case stays
        # a list the compatibility analysis can walk.
        cached: Dict[str, object] = {"name": name}
        if document.licenses:
            cached["licenses"] = list(document.licenses)
        self.metadata_cache[name] = cached

        # An artifact's own <dependencies> block is a measured transitive
        # signal, not an assumed-empty one. Only what actually ships counts.
        shipped = {
            declaration.key
            for declaration in document.direct
            if declaration.scope in _SHIPPED_SCOPES
            and not declaration.is_bom_import
            and declaration.key != name
        }
        dep.transitive_dependencies = shipped
        dep.additional_info["transitive_source"] = "maven-pom"

    def _analyze_repositories(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> None:
        """Clone each distinct source repository once and score every user.

        Twelve Spring Boot starters share one repository. Cloning it twelve
        times would turn a Java scan into a bandwidth exercise, so dependencies
        are grouped by repository and the clone is shared.
        """
        by_repository: Dict[str, List[DependencyMetadata]] = {}
        for dep in dependencies.values():
            if dep.repository_url and is_cloneable_repo_url(dep.repository_url):
                by_repository.setdefault(dep.repository_url, []).append(dep)

        for repository_url, sharing in by_repository.items():
            logger.info(
                "Inspecting %s for %d Maven artifact(s)", repository_url, len(sharing)
            )
            with cloned_repo(repository_url) as clone_result:
                if not clone_result:
                    continue
                repo_dir, _ = clone_result
                for dep in sharing:
                    try:
                        analyze_repository(dep, repo_dir)
                    except Exception as exc:
                        logger.error(
                            "Error analyzing repository for %s: %s", dep.name, exc
                        )

    def _get_latest_version(self, coordinate: str) -> Optional[str]:
        """Return the release (or latest) version for a groupId:artifactId."""
        return self._get_versioning(coordinate)[0]

    def _get_versioning(
        self, coordinate: str
    ) -> Tuple[Optional[str], Optional[datetime]]:
        """Return the latest version and last-publication date for a coordinate.

        Args:
            coordinate: ``groupId:artifactId``.

        Returns:
            The release (or latest) version and the ``<lastUpdated>`` timestamp,
            either of which is None when maven-metadata.xml does not state it.
        """
        if ":" not in coordinate:
            return None, None
        group, artifact = coordinate.split(":", 1)
        group_path = group.replace(".", "/")
        url = (
            "https://repo1.maven.org/maven2/"
            f"{group_path}/{artifact}/maven-metadata.xml"
        )
        headers = {"User-Agent": "dependency-risk-profiler (metadata lookup)"}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("Maven Central lookup failed for %s: %s", coordinate, exc)
            return None, None
        if response.status_code != 200:
            return None, None
        content = response.content
        if len(content) > _MAX_METADATA_BYTES:
            return None, None
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return None, None
        return self._latest_from_metadata(root), self._last_updated(root)

    @staticmethod
    def _latest_from_metadata(root: ElementTree.Element) -> Optional[str]:
        """Return <release> (preferred) or <latest> from a maven-metadata root."""
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

    @staticmethod
    def _last_updated(root: ElementTree.Element) -> Optional[datetime]:
        """Return ``<versioning><lastUpdated>`` as a UTC timestamp, or None.

        Maven Central writes it as a bare ``yyyyMMddHHmmss`` in UTC — no
        separators and no zone marker, which is why it needs its own parse
        rather than the shared ISO-8601 one.

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


def normalize_scm_url(raw_url: Optional[str]) -> Optional[str]:
    """Turn a Maven ``<scm>`` value into a plain https repository URL.

    Maven SCM values arrive in four shapes: a browsable ``https://`` URL, a
    ``scm:git:`` connection string, a ``git://`` or ``ssh://`` URL, and the
    scp-style ``git@host:owner/repo``. Only the https form is useful downstream,
    and only a cloneable host survives :func:`is_cloneable_repo_url` later.

    Args:
        raw_url: The raw ``<scm>`` or ``<url>`` text.

    Returns:
        An ``https://host/path`` URL, or None if nothing usable is in there.
    """
    if not raw_url:
        return None

    url = _SCM_PREFIX.sub("", raw_url.strip())
    if not url:
        return None

    scp_match = _SCP_STYLE.match(url)
    if scp_match and "://" not in url:
        url = f"https://{scp_match.group(1)}/{scp_match.group(2)}"

    parsed = urlparse(url)
    # git:// and ssh:// are the same repository reachable over https; anything
    # else (mailto:, file:, a bare word) is not a repository at all.
    if parsed.scheme not in ("https", "http", "git", "ssh") or not parsed.netloc:
        return None

    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    if not path.strip("/"):
        return None

    # Drop credentials, query strings, and fragments: only host and path matter.
    host = parsed.netloc.rsplit("@", 1)[-1]
    return f"https://{host}{path}"
