"""Analyzer for Java (Maven) dependencies."""

import logging
import re
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from ..analysis_helpers import analyze_repository
from ..models import DependencyMetadata
from ..parsers.maven_repositories import (
    ArtifactVersioning,
    MavenRepositoryClient,
    PomLookup,
    RepositoryLookup,
    RepositoryOutcome,
)
from ..parsers.maven_versions import ManagedVersionResolver
from ..parsers.pom_model import (
    InheritedMetadata,
    PomCoordinate,
    PomDocument,
    inherit_metadata,
)
from ..release_dates import (
    RepositoryResolution,
    apply_registry_release_date,
    record_source_repository,
    resolve_repository,
)
from ..signals import RegistryLookupState
from ..transitive.analyzer_enhanced import record_transitive_source
from ..utils import cloned_repo, is_cloneable_repo_url
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

# Scopes that describe what actually ships with the artifact. "test" and
# "provided" dependencies are not part of a consumer's runtime surface, so they
# do not belong in the transitive-dependency signal.
_SHIPPED_SCOPES = {None, "compile", "runtime"}

# Recorded so the transitive signal is treated as measured rather than as an
# assumed-empty set (#141). An artifact whose POM declares no dependencies has
# a measured zero, not an unmeasured one. This used to be a bare string literal
# writing straight into ``additional_info``, which meant the one place the
# marker was spelled by hand was the one place a typo would have read as
# "unmeasured" forever (#164).
TRANSITIVE_SOURCE_MAVEN_POM = "maven-pom"

# Maven SCM connection strings are URLs wearing a costume: "scm:git:" prefixes,
# "git://" and "ssh://" schemes, and the scp-style "git@host:owner/repo" form.
# The scp pattern demands a dotted host and a slashed path so it cannot swallow
# an ordinary URI scheme such as "mailto:someone@example.org".
_SCM_PREFIX = re.compile(r"^scm:(?:[a-z0-9_+-]+:)?", re.IGNORECASE)
_SCP_STYLE = re.compile(r"^(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+):(?!//)([^/].*/.*)$")


class MavenAnalyzer(BaseAnalyzer):
    """Analyzer for Java dependencies published to a Maven repository.

    A Maven repository publishes each artifact's own POM alongside its jar, and
    that POM carries the metadata every other ecosystem gets from its registry
    API: the source repository, the license, and the artifact's own
    dependencies. Reading it is what turns a Java scan from "here are your CVEs"
    into the same signal set the profiler collects for npm, PyPI, and Go.

    Reading *only* it is not enough. Maven's convention is to declare the
    licence and the source repository once in a parent POM and inherit them, so
    the artifact's own POM is where those two are most often absent — guava's
    has neither, and neither does any Apache Commons artifact (#178). The parent
    chain is walked through the same bounded client version resolution uses.

    Reading only *Maven Central* is not enough either, which is #278. Java is
    the one ecosystem here whose registry is a set of repositories rather than
    one API, and the tool knew exactly one of them: on Signal-Android, 62 of 94
    dependencies are published to Google's Maven repository and to no other, so
    they 404'd and every signal for them was unmeasured. The client now asks
    each repository in :data:`~..parsers.maven_repositories.DEFAULT_REPOSITORIES`
    and records what each one said, so this analyzer can tell "nobody publishes
    it" from "nobody answered".
    """

    def __init__(
        self,
        timeout: int = 10,
        client: Optional[MavenRepositoryClient] = None,
    ) -> None:
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
            client: Bounded Maven repository client used to read artifact POMs
                and release metadata. Defaults to a fresh one; tests inject a
                disabled client, or one narrowed to a single repository.
        """
        super().__init__(timeout)
        self.metadata_cache: Dict[str, Dict[str, object]] = {}
        self.client = (
            client
            if client is not None
            else MavenRepositoryClient(timeout=timeout, fetch_budget=512)
        )
        # The parent walk #141 built for version resolution, reused here for the
        # metadata that lives in the parent POM (#178). One walk, one set of
        # fences, one memoizing client — twelve Spring starters sharing a parent
        # cost one fetch between them.
        self.resolver = ManagedVersionResolver(self.client)

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Java dependencies and collect Maven repository metadata.

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
                versioning = self._get_versioning(name)
                if versioning.latest:
                    dep.latest_version = versioning.latest
                # maven-metadata.xml states when the artifact last shipped, in
                # <versioning><lastUpdated>. Nothing read it, so the release
                # cadence was unmeasured for every Maven artifact and staleness
                # — the signal the tool exists for — could only ever come from a
                # clone (#73). It is now merged across repositories rather than
                # taken from the first that answers: Central's copy of the
                # Android toolchain stopped in 2017, so first-hit-wins would
                # report a live artifact as nine years stale (#278).
                apply_registry_release_date(dep, versioning.last_updated)
                inherited, state, unavailable = self._collect_artifact_metadata(
                    name, dep, versioning
                )
                # Which repositories were asked, and what each said, decides
                # what an absent signal *means* downstream. Recorded here
                # because this is the one place that has both lookups in hand.
                dep.record_registry_lookup(
                    state, repositories_unavailable=unavailable
                )
                # What the POM says about its source is a measured fact, and it
                # has three answers rather than two. The discriminator is not
                # whether <scm> is present but whether what it names is a git
                # forge: across 25 sampled artifacts, 9 declared no <scm> at
                # all, 12 named a Subversion or CVS host, and 4 named a forge
                # and all 4 resolved (#176). Recorded only when a POM was
                # actually read — an artifact whose POM could not be fetched is
                # unmeasured, not undeclared (#182).
                #
                # The declaration is the *inherited* <scm>, not the artifact's
                # own. An artifact that inherits a Subversion <scm> from its
                # parent has declared one, and reading only its own POM would
                # record UNDECLARED — #182's fabricated negative arrived at
                # from a third direction (#178).
                if inherited is not None:
                    record_source_repository(
                        dep, self._resolve_repository(inherited)
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
        versioning: ArtifactVersioning,
    ) -> Tuple[Optional[InheritedMetadata], RegistryLookupState, Tuple[str, ...]]:
        """Read the artifact's published POM for repo, license, and deps.

        The installed version is preferred so the metadata describes what the
        project actually uses; the latest version is the fallback for artifacts
        whose version is managed somewhere we could not reach.

        Args:
            name: The ``groupId:artifactId`` being analyzed.
            dep: The dependency the metadata is copied onto.
            versioning: What the repositories jointly said about the artifact's
                releases. Supplies the fallback version *and* the repositories
                that were found to publish it, so the POM fetch does not pay a
                404 at a repository the metadata lookup already ruled out.

        Returns:
            A triple of the metadata the POM has once its parent chain is
            applied (None when no candidate version answered), the state the
            registry lookups jointly established, and the names of any
            repositories that were asked and did not answer.
        """
        group_id, _, artifact_id = name.partition(":")
        if not group_id or not artifact_id:
            return None, RegistryLookupState.NOT_ATTEMPTED, ()

        lookups: List[PomLookup] = []
        inherited: Optional[InheritedMetadata] = None
        for version in self._candidate_versions(dep, versioning.latest):
            lookup = self.client.fetch_pom(
                PomCoordinate(group_id, artifact_id, version),
                prefer=versioning.lookup.found_in,
            )
            lookups.append(lookup)
            if lookup.document is not None:
                inherited = self._apply_artifact_metadata(name, dep, lookup.document)
                break
        state, unavailable = self._registry_state(versioning, lookups)
        return inherited, state, unavailable

    @staticmethod
    def _registry_state(
        versioning: ArtifactVersioning, lookups: Sequence[PomLookup]
    ) -> Tuple[RegistryLookupState, Tuple[str, ...]]:
        """Reduce the lookups this artifact needed to one recorded state.

        The POM is the document nearly every signal is read from, so when a POM
        lookup ran it is the one that decides. The metadata lookup answers only
        when there was no candidate version to ask about — which is itself the
        case where the metadata lookup found nothing.

        Both are kept rather than merged. Merging them would let a metadata
        ``FOUND`` mask a POM fetch that timed out, which is the #219 defect
        arriving by way of an aggregation.

        Args:
            versioning: The artifact-level metadata lookup.
            lookups: The per-version POM lookups, in the order they were made.

        Returns:
            The state to record and the names of repositories that did not
            answer, which is non-empty exactly for ``FAILED``.
        """
        if not lookups:
            state = versioning.lookup.state
            return state, _names_for(state, versioning.lookup.unanswered)
        if any(lookup.document is not None for lookup in lookups):
            return RegistryLookupState.ANSWERED, ()
        # Every candidate version failed. The worst outcome across them is the
        # honest summary: one repository that did not answer is enough to make
        # "not published" a claim we cannot support.
        unavailable = tuple(
            dict.fromkeys(
                name for lookup in lookups for name in lookup.lookup.unanswered
            )
        )
        if unavailable:
            return RegistryLookupState.FAILED, unavailable
        if all(
            lookup.lookup.state is RegistryLookupState.ABSENT_EVERYWHERE
            for lookup in lookups
        ):
            return RegistryLookupState.ABSENT_EVERYWHERE, ()
        return RegistryLookupState.NOT_ATTEMPTED, ()

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
    ) -> InheritedMetadata:
        """Copy repository, license, and dependency data off an artifact POM.

        ``<licenses>`` and ``<scm>`` are read across the parent chain rather
        than off the artifact's own POM, because Maven's convention is to
        declare them once in a parent and inherit them — guava's own POM has
        neither, and commons-lang3's licence is two hops up (#178).
        Precedence is nearest-declaration-wins, the same rule #141 chose for
        versions. ``<dependencies>`` is deliberately *not* inherited: an
        artifact's own dependency list is what it ships, and a parent's is what
        its siblings ship.

        Returns:
            The inherited view, so the caller can record what the artifact
            *declares* about its source separately from what resolved (#176).
        """
        inherited = inherit_metadata(self.resolver.iter_lineage(document))

        # <scm> is the authoritative pointer; <url> is the fallback for POMs
        # that only publish a project homepage. Both get trimmed to the
        # repository root, because monorepo artifacts point at a subdirectory
        # and both git clone and the GitHub API reject that deeper path.
        resolution = self._resolve_repository(inherited)
        if resolution.url:
            dep.repository_url = resolution.url

        # analyze_license() reads a registry-metadata mapping; give it one built
        # from <licenses>, using the plural key so the multi-license case stays
        # a list the compatibility analysis can walk.
        cached: Dict[str, object] = {"name": name}
        if inherited.licenses:
            cached["licenses"] = list(inherited.licenses)
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
        record_transitive_source(dep, source=TRANSITIVE_SOURCE_MAVEN_POM)
        return inherited

    @staticmethod
    def _resolve_repository(inherited: InheritedMetadata) -> RepositoryResolution:
        """Return the POM lineage's one answer about where the source lives.

        ``<scm>`` is Maven's designated source pointer and is the declaration;
        ``<url>`` is the fallback for POMs that publish only a project
        homepage. Both are read across the parent chain, because Maven's
        convention is to declare them once in a parent and inherit them, and
        an artifact that inherits a Subversion ``<scm>`` has declared one
        (#178, #182).

        A Maven ``<scm>`` is not a URL — ``scm:git:https://...``,
        ``scm:svn:http://...`` — so ``normalize_scm_url`` prepares each
        candidate before it is canonicalized, while the declaration keeps the
        raw text. That is why the ``prepare`` hook exists: a ``<scm>`` naming
        Subversion must stay UNUSABLE rather than becoming UNDECLARED because
        its connection string does not parse as a clone URL.

        Args:
            inherited: The nearest-declaration-wins view of the parent chain.

        Returns:
            The resolution the POM lineage supports.
        """
        return resolve_repository(
            declarations=[inherited.scm_url],
            fallbacks=[inherited.project_url],
            prepare=normalize_scm_url,
        )

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

    def _get_versioning(self, coordinate: str) -> ArtifactVersioning:
        """Return what every configured repository says about an artifact.

        The single network entry point for artifact-level metadata, and the
        one place the analyzer learns which repositories publish a coordinate
        at all. The fetch, the byte bound, the redirect refusal and the
        per-repository merge all live in the client, so this analyzer does not
        carry a second copy of the fences (#278).

        Args:
            coordinate: ``groupId:artifactId``.

        Returns:
            The merged versioning. ``latest`` and ``last_updated`` are None
            when no repository stated them, and ``lookup`` records who was
            asked — including the empty record for a string that is not a
            coordinate at all, which is a lookup that never ran.
        """
        group, _, artifact = coordinate.partition(":")
        if not group or not artifact:
            return ArtifactVersioning(
                latest=None,
                last_updated=None,
                lookup=RepositoryLookup(
                    outcomes=(), configured=self.client.repositories
                ),
            )
        return self.client.fetch_versioning(group, artifact)


def _names_for(
    state: RegistryLookupState, unanswered: Tuple[str, ...]
) -> Tuple[str, ...]:
    """Return the casualty names a state is allowed to carry.

    ``record_registry_lookup`` refuses a state whose names disagree with it, on
    purpose: a failure that cannot say what failed is not a report. A lookup
    where one repository timed out and another answered is ``ANSWERED`` and has
    no casualties to report, so the names are dropped rather than smuggled into
    a state that does not mean what they would imply.

    Args:
        state: The state about to be recorded.
        unanswered: Every repository that was asked and did not answer.

    Returns:
        The names for ``FAILED``, and nothing for every other state.
    """
    return unanswered if state is RegistryLookupState.FAILED else ()


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
