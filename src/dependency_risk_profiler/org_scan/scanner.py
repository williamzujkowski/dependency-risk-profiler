"""Discovery, parsing, deduplication, and aggregation for org scans."""

from __future__ import annotations

import copy
import fnmatch
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, Iterable, List, Optional, Protocol, Set, Tuple

from ..manifest_guidance import recognise_unreadable_manifest_in_listing
from ..models import DependencyMetadata, DependencyRiskScore, RiskLevel
from ..parsers.base import BaseParser
from ..parsers.registry import EcosystemRegistry
from .github import ManifestTooLargeError
from .models import (
    AccountType,
    AggregatedDependency,
    DependencyKey,
    DependencyOccurrence,
    DependencyProfiler,
    ManifestParseFailure,
    ManifestRef,
    OrgScanReport,
    RepositoryCoverage,
    RepositoryManifestListing,
    RepositoryRef,
    RepositoryRiskSummary,
    UnreadableManifestRef,
    build_headline,
    canonical_ecosystem,
    risk_points,
    risk_rank,
)

logger = logging.getLogger(__name__)

# There is no list of supported manifest names here any more. There was one —
# a tuple of thirteen exact file names — and it disagreed with the parser
# registry it was supposed to mirror: the registry expresses NuGet's primary
# manifest as an extension matcher (``*.csproj``), which an exact-name tuple
# cannot hold. So no org scan ever fetched a ``.csproj``, and after #262 every
# .NET repository was reported as ``coverage: no_manifests`` — "the tree listed
# and holds no manifest this tool recognizes" — about a repository holding a
# manifest ``analyze`` reads fine (#265).
#
# The fix is not a second list kept in sync by a test. It is asking the
# registry, which is what ``GitHubOrgClient.list_manifest_paths`` now does via
# ``EcosystemRegistry.match_ecosystem_by_path``.

ProgressCallback = Callable[[str], None]
RepositoryLister = Callable[[str, bool, Optional[int]], List[RepositoryRef]]
PackageIdentity = Tuple[str, str]


class GitHubDiscoveryClient(Protocol):
    """Structural protocol for GitHub discovery clients.

    ``GitHubOrgClient`` and the test fixtures satisfy this by shape rather than
    by inheritance, which is the whole point: this was a plain base class, so
    mypy rejected every caller that passed a real client, and the mypy gate was
    masked hard enough that nobody saw it.
    """

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """List repositories to scan."""
        raise NotImplementedError

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """List user repositories to scan."""
        raise NotImplementedError

    def list_manifest_paths(
        self,
        repo: RepositoryRef,
    ) -> RepositoryManifestListing:
        """List a repository's manifests, split into readable and unreadable."""
        raise NotImplementedError

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Fetch manifest content from a repository."""
        raise NotImplementedError


@dataclass(frozen=True)
class OrgScanOptions:
    """Options controlling repository discovery and report aggregation."""

    org: str
    account_type: AccountType = "organization"
    repository_lister: Optional[RepositoryLister] = None
    include_archived: bool = False
    max_repos: Optional[int] = None
    # A user-supplied narrowing of what gets scored, or None for "everything
    # the registry recognizes". It used to default to the scanner's own copy of
    # the supported names, which made the default run look like a filter and
    # meant deleting that copy needed a real default rather than a synonym for
    # "no filter" (#265).
    manifest_globs: Optional[Tuple[str, ...]] = None
    concurrency: int = 8


@dataclass(frozen=True)
class _Discovery:
    """What the discovery pass learned about every repository in the account."""

    manifests: List[ManifestRef]
    # Recognized dependency manifests nobody fetched, because their names say
    # the parsers cannot use them.
    unreadable: List[UnreadableManifestRef]
    # Repositories whose tree listing raised. Nothing is known about their
    # contents, which is not the same as knowing they are empty (#262).
    undiscovered: Set[str]
    # Repositories whose tree GitHub truncated, so everything above about them
    # describes a prefix. Carried rather than logged (#266).
    truncated: Set[str]
    warnings: List[str]


@dataclass(frozen=True)
class _RepoDiscovery:
    """What one repository's tree listing produced.

    A named triple rather than a bare tuple: the third field is the one that
    used to exist only as a log line, and a positional bool is exactly how it
    would go back to being ignored.
    """

    manifests: List[ManifestRef]
    unreadable: List[UnreadableManifestRef]
    truncated: bool


@dataclass
class _ParsedInventory:
    """Parsed dependency inventory before profiling."""

    repositories: List[RepositoryRef]
    manifests: List[ManifestRef]
    unique_dependencies: Dict[DependencyKey, DependencyMetadata]
    occurrences: List[DependencyOccurrence]
    # Manifests that were fetched and parsed without raising. A repository with
    # one of these was read, whether or not the file declared any dependency.
    read_manifests: Set[Tuple[str, str]] = field(default_factory=set)
    unreadable_manifests: List[UnreadableManifestRef] = field(default_factory=list)
    undiscovered_repositories: Set[str] = field(default_factory=set)
    truncated_repositories: Set[str] = field(default_factory=set)
    parse_failures: List[ManifestParseFailure] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class OrgScanRunner:
    """Run an org-wide scan using a GitHub client and dependency profiler."""

    def __init__(
        self,
        github_client: GitHubDiscoveryClient,
        dependency_profiler: DependencyProfiler,
        progress: Optional[ProgressCallback] = None,
    ) -> None:
        """Initialize the org scan runner."""
        self.github_client = github_client
        self.dependency_profiler = dependency_profiler
        self.progress = progress

    def run(self, options: OrgScanOptions) -> OrgScanReport:
        """Run discovery, parse manifests, profile unique deps, and aggregate."""
        account_label = options.account_type
        repository_lister = options.repository_lister
        if repository_lister is None:
            repository_lister = self.github_client.list_org_repositories

        self._emit(f"Listing {account_label} repositories for {options.org}")
        repositories = repository_lister(
            options.org,
            options.include_archived,
            options.max_repos,
        )
        self._emit(f"Discovered {len(repositories)} repositories to scan")

        self._ensure_parser_registry()
        discovery = self._discover_manifests(repositories, options)
        self._emit(f"Found {len(discovery.manifests)} supported manifests")
        if discovery.unreadable:
            self._emit(
                f"Recognized {len(discovery.unreadable)} manifest(s) this tool "
                "cannot read; they are reported, not scored"
            )

        parsed = self._parse_manifests(repositories, discovery)
        self._emit(
            "Parsed "
            f"{len(parsed.unique_dependencies)} unique dependencies across "
            f"{len(parsed.occurrences)} manifest occurrences"
        )

        profiles = self.dependency_profiler.profile(parsed.unique_dependencies)
        self._emit(f"Profiled {len(profiles)} unique dependency versions")

        return self._aggregate(options.org, options.account_type, parsed, profiles)

    def _discover_manifests(
        self, repositories: List[RepositoryRef], options: OrgScanOptions
    ) -> _Discovery:
        """Discover and fetch supported manifests with bounded concurrency.

        Returns the discovery warnings rather than only logging them. They used
        to be appended to a local list that the function then dropped on the
        floor, so a repository whose tree listing was refused left no trace in
        the report at all — it simply appeared with no dependencies, next to
        repositories that genuinely have none (#262).

        Args:
            repositories: Every repository the scan was asked to cover.
            options: Scan options, including discovery concurrency.

        Returns:
            The fetched manifests, the recognized-but-unreadable ones, the
            repositories whose trees never listed, and the repositories whose
            trees listed only in part.
        """
        manifests: List[ManifestRef] = []
        unreadable: List[UnreadableManifestRef] = []
        undiscovered: Set[str] = set()
        truncated: Set[str] = set()
        warnings: List[str] = []
        max_workers = max(1, options.concurrency)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._fetch_repo_manifests, repo, options): repo
                for repo in repositories
            }
            completed = 0
            for future in as_completed(futures):
                repo = futures[future]
                completed += 1
                try:
                    discovered = future.result()
                    manifests.extend(discovered.manifests)
                    unreadable.extend(discovered.unreadable)
                    if discovered.truncated:
                        truncated.add(repo.full_name)
                        # Reaches the report, not only the terminal: a consumer
                        # has to be able to see that this repository's list is
                        # a prefix (#266).
                        warnings.append(
                            f"{repo.full_name}: GitHub truncated the git tree; "
                            "the manifest list is a prefix, so this "
                            "repository's dependency count is a floor"
                        )
                except Exception as exc:
                    warning = f"{repo.full_name}: manifest discovery failed: {exc}"
                    logger.warning(warning)
                    warnings.append(warning)
                    undiscovered.add(repo.full_name)
                total = len(repositories)
                self._emit(f"Scanned manifest trees for {completed} / {total} repos")

        # Counted from `undiscovered`, not from `warnings`: the warning list
        # now also carries truncated trees, which were not skipped.
        if undiscovered:
            logger.warning(
                "Skipped %s repositories during discovery", len(undiscovered)
            )
        return _Discovery(
            manifests=sorted(
                manifests, key=lambda item: (item.repo_full_name, item.path)
            ),
            unreadable=sorted(
                unreadable, key=lambda item: (item.repo_full_name, item.path)
            ),
            undiscovered=undiscovered,
            truncated=truncated,
            # Sorted because they are appended from an `as_completed` loop, so
            # their arrival order varies run to run — the same reason the
            # repository aggregate is built in sorted order (#207).
            warnings=sorted(warnings),
        )

    def _fetch_repo_manifests(
        self, repo: RepositoryRef, options: OrgScanOptions
    ) -> _RepoDiscovery:
        """Fetch one repository's supported manifests and name its unreadable ones.

        Args:
            repo: The repository to read.
            options: Scan options, including the user's manifest globs.

        Returns:
            The fetched manifests, the recognized-but-unreadable ones, and
            whether the tree they came from was a prefix. The unreadable list
            is never fetched, so it adds no requests.
        """
        listing = self.github_client.list_manifest_paths(repo)
        selected_paths = [
            path
            for path in listing.supported
            if self._matches_manifest_globs(path, options)
        ]
        manifests: List[ManifestRef] = []
        for path in selected_paths:
            try:
                content = self.github_client.fetch_manifest_content(repo, path)
            except ManifestTooLargeError as exc:
                logger.warning(
                    "Skipping oversized manifest %s:%s: %s",
                    repo.full_name,
                    path,
                    exc,
                )
                continue
            ecosystem = self._detect_ecosystem(path)
            if ecosystem is None:
                continue
            manifests.append(
                ManifestRef(
                    repo_full_name=repo.full_name,
                    path=path,
                    ecosystem=ecosystem,
                    content=content,
                )
            )
        return _RepoDiscovery(
            manifests=manifests,
            unreadable=self._recognise_unreadable(repo, listing),
            truncated=listing.truncated,
        )

    def _recognise_unreadable(
        self, repo: RepositoryRef, listing: RepositoryManifestListing
    ) -> List[UnreadableManifestRef]:
        """Name the manifests in one repository that this tool cannot read.

        Deliberately not filtered by ``--manifest-glob``. The glob narrows what
        gets *scored*; this list answers "what did you not read", and a coverage
        gap the user cannot see is the whole defect. The default globs are the
        supported names, so filtering here would empty the list on every
        default run.

        Sibling lookup runs against ``listing.supported`` — the repository's own
        tree — so a ``package.json`` with the lock file beside it is correctly
        silent, and nothing is resolved against the local filesystem.

        Args:
            repo: The repository the listing came from.
            listing: That repository's split manifest listing.

        Returns:
            One entry per unreadable manifest that is a real coverage gap.
        """
        recognised: List[UnreadableManifestRef] = []
        for path in listing.unreadable:
            parent = str(PurePosixPath(path).parent)
            location = repo.full_name
            if parent != ".":
                location = f"{repo.full_name}:{parent}"
            entry = recognise_unreadable_manifest_in_listing(
                path, listing.supported, location=location
            )
            if entry is None or entry.supported_input_present:
                # A supported input for the same ecosystem sits in the same
                # directory, so the ecosystem was read and this file is not a
                # gap in coverage.
                continue
            recognised.append(
                UnreadableManifestRef(
                    repo_full_name=repo.full_name,
                    path=path,
                    ecosystem=entry.ecosystem,
                    guidance=entry.guidance,
                )
            )
        return recognised

    def _parse_manifests(
        self, repositories: List[RepositoryRef], discovery: _Discovery
    ) -> _ParsedInventory:
        """Parse fetched manifests through the existing parser registry.

        Args:
            repositories: Every repository the scan was asked to cover.
            discovery: What the discovery pass fetched, recognized, and failed
                to list.

        Returns:
            The parsed inventory, carrying the coverage facts through to
            aggregation rather than discarding them here.
        """
        manifests = discovery.manifests
        unique_dependencies: Dict[DependencyKey, DependencyMetadata] = {}
        occurrences: List[DependencyOccurrence] = []
        failures: List[ManifestParseFailure] = []
        read_manifests: Set[Tuple[str, str]] = set()

        with tempfile.TemporaryDirectory(prefix="dependency-risk-org-scan-") as tmp:
            temp_root = Path(tmp)
            for manifest in manifests:
                try:
                    manifest_path = self._write_temp_manifest(temp_root, manifest)
                    parser = BaseParser.get_parser_for_file(str(manifest_path))
                    if parser is None:
                        failures.append(
                            ManifestParseFailure(
                                manifest.repo_full_name,
                                manifest.path,
                                "unsupported manifest",
                            )
                        )
                        continue
                    dependencies = parser.parse()
                except Exception as exc:
                    failures.append(
                        ManifestParseFailure(
                            manifest.repo_full_name,
                            manifest.path,
                            str(exc),
                        )
                    )
                    continue

                # Parsed without raising. Recorded even when it declared
                # nothing, because "read it and it declares nothing" is a
                # measurement and has to stay distinct from "could not read
                # it" (AGENTS.md rule 4).
                read_manifests.add((manifest.repo_full_name, manifest.path))

                for dependency in dependencies.values():
                    key = DependencyKey(
                        ecosystem=manifest.ecosystem,
                        name=dependency.name,
                        version=dependency.installed_version,
                    )
                    if key not in unique_dependencies:
                        unique_dependencies[key] = copy.deepcopy(dependency)
                    occurrences.append(
                        DependencyOccurrence(
                            repo_full_name=manifest.repo_full_name,
                            manifest_path=manifest.path,
                            key=key,
                        )
                    )

        return _ParsedInventory(
            repositories=repositories,
            manifests=manifests,
            unique_dependencies=unique_dependencies,
            occurrences=occurrences,
            read_manifests=read_manifests,
            unreadable_manifests=discovery.unreadable,
            undiscovered_repositories=discovery.undiscovered,
            truncated_repositories=discovery.truncated,
            parse_failures=failures,
            warnings=discovery.warnings,
        )

    def _aggregate(
        self,
        org: str,
        account_type: AccountType,
        parsed: _ParsedInventory,
        profiles: Dict[DependencyKey, DependencyRiskScore],
    ) -> OrgScanReport:
        """Aggregate dependency profiles into org-wide exposure views."""
        repo_by_name = {repo.full_name: repo for repo in parsed.repositories}
        variant_repositories: Dict[DependencyKey, Set[str]] = {}
        variant_manifests: Dict[DependencyKey, Set[str]] = {}
        variant_repo_refs: Dict[DependencyKey, Dict[str, RepositoryRef]] = {}
        variant_manifest_paths_by_repo: Dict[DependencyKey, Dict[str, Set[str]]] = {}

        for occurrence in parsed.occurrences:
            if occurrence.key not in profiles:
                continue
            variant_repositories.setdefault(occurrence.key, set()).add(
                occurrence.repo_full_name
            )
            variant_manifests.setdefault(occurrence.key, set()).add(
                f"{occurrence.repo_full_name}:{occurrence.manifest_path}"
            )
            repo_ref = repo_by_name.get(occurrence.repo_full_name)
            if repo_ref is not None:
                variant_repo_refs.setdefault(occurrence.key, {})[
                    occurrence.repo_full_name
                ] = repo_ref
            variant_manifest_paths_by_repo.setdefault(occurrence.key, {}).setdefault(
                occurrence.repo_full_name, set()
            ).add(occurrence.manifest_path)

        variants_by_identity: Dict[PackageIdentity, List[DependencyKey]] = {}
        for key in profiles:
            identity = (canonical_ecosystem(key.ecosystem), key.name)
            variants_by_identity.setdefault(identity, []).append(key)

        by_identity: Dict[PackageIdentity, AggregatedDependency] = {}
        for identity, variant_keys in variants_by_identity.items():
            representative_key = max(
                variant_keys,
                key=lambda key: self._representative_variant_sort_key(
                    key, profiles[key], variant_repositories
                ),
            )
            representative_score = profiles[representative_key]
            aggregate = AggregatedDependency(
                key=DependencyKey(
                    ecosystem=identity[0],
                    name=identity[1],
                    version=representative_key.version,
                ),
                risk_score=representative_score,
                advisory_summary=self._advisory_summary(representative_score),
                version_specs={key.version for key in variant_keys},
            )
            for variant_key in variant_keys:
                aggregate.repositories.update(
                    variant_repositories.get(variant_key, set())
                )
                aggregate.manifests.update(variant_manifests.get(variant_key, set()))
                aggregate.repo_refs.update(variant_repo_refs.get(variant_key, {}))
                for repo_full_name, paths in variant_manifest_paths_by_repo.get(
                    variant_key, {}
                ).items():
                    aggregate.manifest_paths_by_repo.setdefault(
                        repo_full_name, set()
                    ).update(paths)
            by_identity[identity] = aggregate

        inventory = sorted(by_identity.values(), key=self._dependency_sort_key)
        most_exposed = [
            item
            for item in inventory
            if item.risk_level
            in {
                RiskLevel.CRITICAL,
                RiskLevel.HIGH,
                RiskLevel.MEDIUM,
                RiskLevel.UNKNOWN,
            }
        ]
        coverage = self._repository_coverage(parsed)
        repo_summaries = self._repository_summaries(parsed, by_identity, coverage)

        high_risk_dependencies = [
            item
            for item in inventory
            if item.risk_level in {RiskLevel.CRITICAL, RiskLevel.HIGH}
        ]
        high_risk_repos: Set[str] = set()
        for item in high_risk_dependencies:
            high_risk_repos.update(item.repositories)

        known_vulnerable_count = sum(
            1 for item in inventory if item.is_known_vulnerable
        )
        unscored_count = sum(1 for item in inventory if item.is_unscored)
        unread_repository_count = sum(
            1
            for state in coverage.values()
            if state
            in {
                RepositoryCoverage.UNREADABLE,
                RepositoryCoverage.DISCOVERY_FAILED,
            }
        )
        partially_listed_count = sum(
            1
            for state in coverage.values()
            if state is RepositoryCoverage.PARTIALLY_LISTED
        )
        headline = build_headline(
            known_vulnerable_count=known_vulnerable_count,
            high_risk_count=len(high_risk_dependencies),
            unscored_count=unscored_count,
            unread_repository_count=unread_repository_count,
            partially_listed_repository_count=partially_listed_count,
            dependency_count=len(inventory),
            repository_count=len(parsed.repositories),
        )

        return OrgScanReport(
            org=org,
            account_type=account_type,
            generated_at=datetime.now(),
            repositories_scanned=[repo.full_name for repo in parsed.repositories],
            manifests_scanned=[manifest.display_path for manifest in parsed.manifests],
            unique_dependency_count=len(inventory),
            parse_failures=parsed.parse_failures,
            unreadable_manifests=parsed.unreadable_manifests,
            inventory=inventory,
            most_exposed_risky_dependencies=most_exposed,
            riskiest_repositories=repo_summaries,
            high_risk_dependency_count=len(high_risk_dependencies),
            high_risk_exposed_repository_count=len(high_risk_repos),
            headline=headline,
            warnings=parsed.warnings,
            known_vulnerable_dependency_count=known_vulnerable_count,
            unscored_dependency_count=unscored_count,
        )

    def _repository_coverage(
        self, parsed: _ParsedInventory
    ) -> Dict[str, RepositoryCoverage]:
        """Classify how much of each repository the scan actually read.

        Every repository the scan was asked to cover gets exactly one state,
        and the four ways of ending up with no dependencies are four different
        states rather than one shared silence (#262):

        * the tree never listed, so the contents are unknown;
        * manifests were recognized and none could be read;
        * the tree listed and holds no manifest this tool knows about;
        * manifests were read and simply declare nothing.

        A truncated tree outranks all of them but the first, and the ordering
        is the whole point. Every state below it is a claim about a complete
        listing: ``no_manifests`` says the tree holds nothing, ``read`` says a
        zero is a real zero, and neither is available to a scan that saw a
        prefix. ``discovery_failed`` still wins, because knowing nothing is
        worse news than knowing part (#266).

        Args:
            parsed: The parsed inventory, carrying every coverage fact.

        Returns:
            One state per repository, keyed by full name.
        """
        read_repositories = {repo for repo, _ in parsed.read_manifests}
        unreadable_repositories = {
            entry.repo_full_name for entry in parsed.unreadable_manifests
        }
        # A manifest that was fetched and then refused is also a manifest this
        # repository was not read from. The two are reported separately — they
        # are different facts with different remedies — but at the repository
        # level they answer the same question the same way.
        refused_repositories = {
            failure.repo_full_name for failure in parsed.parse_failures
        }

        # The union, not just the listed repositories: every name that reaches
        # a summary must reach a state, so a missing one raises rather than
        # quietly picking the reassuring default.
        names = {repo.full_name for repo in parsed.repositories}
        names |= read_repositories | unreadable_repositories | refused_repositories
        names |= {occurrence.repo_full_name for occurrence in parsed.occurrences}

        coverage: Dict[str, RepositoryCoverage] = {}
        for name in names:
            if name in parsed.undiscovered_repositories:
                coverage[name] = RepositoryCoverage.DISCOVERY_FAILED
            elif name in parsed.truncated_repositories:
                coverage[name] = RepositoryCoverage.PARTIALLY_LISTED
            elif name in read_repositories:
                coverage[name] = (
                    RepositoryCoverage.PARTIALLY_READ
                    if name in unreadable_repositories or name in refused_repositories
                    else RepositoryCoverage.READ
                )
            elif name in unreadable_repositories or name in refused_repositories:
                coverage[name] = RepositoryCoverage.UNREADABLE
            else:
                coverage[name] = RepositoryCoverage.NO_MANIFESTS
        return coverage

    def _repository_summaries(
        self,
        parsed: _ParsedInventory,
        by_identity: Dict[PackageIdentity, AggregatedDependency],
        coverage: Dict[str, RepositoryCoverage],
    ) -> List[RepositoryRiskSummary]:
        """Build repository aggregate risk summaries.

        The per-repository dependency list is built in sorted identity order,
        not set order (#207). ``total_score`` below is a float sum, float
        addition is not associative, and set iteration order for strings varies
        with ``PYTHONHASHSEED`` — which CPython randomises per process. Summing
        the same values in a different order therefore moved the last bit of
        ``average_risk_score``, so two ``scan-org`` runs on identical input
        produced different JSON. Sorting a set of at most a few thousand
        ``(ecosystem, name)`` tuples costs nothing and makes the aggregate
        order-independent in fact, not just in intent.

        Worth knowing before concluding this is theoretical: CPython 3.12 gave
        ``sum()`` Neumaier compensation, which hides the symptom on 3.12 for
        values in this range. It is live on the 3.9-3.11 jobs in the CI matrix,
        and relying on an interpreter's summation algorithm to keep a published
        number stable is not a guarantee this tool should be making.
        """
        repo_identities: Dict[str, Set[PackageIdentity]] = {
            repo.full_name: set() for repo in parsed.repositories
        }
        for occurrence in parsed.occurrences:
            identity = (
                canonical_ecosystem(occurrence.key.ecosystem),
                occurrence.key.name,
            )
            repo_identities.setdefault(occurrence.repo_full_name, set()).add(identity)

        summaries: List[RepositoryRiskSummary] = []
        for repo_full_name, identities in repo_identities.items():
            dependencies = [
                by_identity[identity]
                for identity in sorted(identities)
                if identity in by_identity
            ]
            # The same mean, under the same rule as ``analyze``'s (#276): a
            # dependency the scan could not score leaves both halves of it. It
            # used to leave only the numerator, so a repository's average fell
            # toward zero once per package the scan failed to resolve — worst
            # in exactly the repositories the scan understood least.
            scored_scores = [
                dep.risk_score.total_score
                for dep in dependencies
                if not dep.is_unscored
            ]
            average_score = (
                sum(scored_scores) / len(scored_scores) if scored_scores else None
            )
            critical = sum(
                1 for dep in dependencies if dep.risk_level == RiskLevel.CRITICAL
            )
            high = sum(1 for dep in dependencies if dep.risk_level == RiskLevel.HIGH)
            medium = sum(
                1 for dep in dependencies if dep.risk_level == RiskLevel.MEDIUM
            )
            unknown = sum(
                1 for dep in dependencies if dep.risk_level == RiskLevel.UNKNOWN
            )
            points = sum(risk_points(dep.risk_level) for dep in dependencies)
            worst = sorted(dependencies, key=self._dependency_sort_key)[:5]
            summaries.append(
                RepositoryRiskSummary(
                    repo_full_name=repo_full_name,
                    dependency_count=len(dependencies),
                    scored_dependency_count=len(scored_scores),
                    critical_risk_dependencies=critical,
                    high_risk_dependencies=high,
                    medium_risk_dependencies=medium,
                    unknown_risk_dependencies=unknown,
                    risk_points=points,
                    average_risk_score=average_score,
                    worst_dependencies=worst,
                    coverage=coverage[repo_full_name],
                )
            )

        return sorted(
            summaries,
            key=lambda repo: (
                -repo.risk_points,
                -repo.critical_risk_dependencies,
                -repo.high_risk_dependencies,
                # A repository with no scored dependency has no average to
                # break the tie with. It sorts below one that does rather than
                # being given a 0.0 to sort on, which would rank "we measured
                # nothing here" as "nothing to see here" (#276).
                0 if repo.average_risk_score is None else -repo.average_risk_score,
                repo.repo_full_name.lower(),
            ),
        )

    def _dependency_sort_key(
        self, dependency: AggregatedDependency
    ) -> Tuple[int, int, float, str]:
        """Sort dependency exposure worst first."""
        return (
            risk_rank(dependency.risk_level),
            -dependency.blast_radius,
            -dependency.risk_score.total_score,
            f"{dependency.key.ecosystem}:{dependency.key.name}".lower(),
        )

    def _representative_variant_sort_key(
        self,
        key: DependencyKey,
        score: DependencyRiskScore,
        variant_repositories: Dict[DependencyKey, Set[str]],
    ) -> Tuple[float, int, float, int, str, str]:
        """Sort variant candidates so the worst profile is representative."""
        exploit_score = score.exploit_score if score.exploit_score is not None else 0.0
        return (
            score.total_score,
            len(variant_repositories.get(key, set())),
            exploit_score,
            self._advisory_count(score),
            key.ecosystem.lower(),
            key.version.lower(),
        )

    def _advisory_count(self, score: DependencyRiskScore) -> int:
        """Return advisory count for representative tie-breaking."""
        metrics = score.dependency.security_metrics
        if metrics is None:
            return 0
        if metrics.counted_vulnerability_count is not None:
            return metrics.counted_vulnerability_count
        if metrics.vulnerability_count is not None:
            return metrics.vulnerability_count
        return 0

    def _advisory_summary(self, score: DependencyRiskScore) -> str:
        """Return scored/filtered advisory counts."""
        metrics = score.dependency.security_metrics
        if metrics is None or metrics.vulnerability_count is None:
            return "unknown"
        counted = metrics.counted_vulnerability_count
        filtered = metrics.filtered_vulnerability_count
        if counted is None or filtered is None:
            if metrics.vulnerability_count == 0:
                return "0 scored / 0 filtered"
            return f"{metrics.vulnerability_count} found"
        return f"{counted} scored / {filtered} filtered"

    def _detect_ecosystem(self, manifest_path: str) -> Optional[str]:
        """Detect ecosystem from a remote manifest path."""
        return EcosystemRegistry.detect_ecosystem(Path(manifest_path))

    def _ensure_parser_registry(self) -> None:
        """Initialize built-in parsers before concurrent manifest discovery."""
        required = {
            "python",
            "nodejs",
            "golang",
            "pyproject",
            "cargo",
            "rubygems",
            "composer",
            "nuget",
            "maven",
            "gradle",
        }
        available = set(EcosystemRegistry.get_available_ecosystems())
        if not required.issubset(available):
            BaseParser._initialize_registry()

    def _matches_manifest_globs(
        self, manifest_path: str, options: OrgScanOptions
    ) -> bool:
        """Return whether a manifest path matches user-selected globs.

        No globs means no narrowing: everything the registry recognized is
        scored. ``--manifest-glob`` subtracts from that set and never adds to
        it, because a glob the registry has no parser for could only produce a
        fetch nobody can read.
        """
        if options.manifest_globs is None:
            return True
        for pattern in options.manifest_globs:
            if fnmatch.fnmatch(manifest_path, pattern) or fnmatch.fnmatch(
                Path(manifest_path).name, pattern
            ):
                return True
        return False

    def _write_temp_manifest(self, temp_root: Path, manifest: ManifestRef) -> Path:
        """Write a fetched manifest to a parser-friendly temp path.

        ``manifest.path`` comes from the GitHub API, so a hostile ``..`` segment
        could otherwise escape the temp directory and clobber a file elsewhere.
        Refuse to write anything that resolves outside the per-repo temp root.
        """
        repo_dir = temp_root / manifest.repo_full_name.replace("/", "__")
        manifest_path = repo_dir / manifest.path
        resolved_root = repo_dir.resolve()
        resolved_path = manifest_path.resolve()
        if (
            resolved_root != resolved_path
            and resolved_root not in resolved_path.parents
        ):
            logger.warning(
                "Skipping manifest with path escaping temp root: %s:%s",
                manifest.repo_full_name,
                manifest.path,
            )
            raise ValueError(
                f"Manifest path escapes temp root: {manifest.path!r} in "
                f"{manifest.repo_full_name}"
            )
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(manifest.content, encoding="utf-8")
        return manifest_path

    def _emit(self, message: str) -> None:
        """Emit progress when a callback is configured."""
        if self.progress is not None:
            self.progress(message)
