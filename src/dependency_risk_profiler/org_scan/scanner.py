"""Discovery, parsing, deduplication, and aggregation for org scans."""

from __future__ import annotations

import copy
import fnmatch
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from ..models import DependencyMetadata, DependencyRiskScore, RiskLevel
from ..parsers.base import BaseParser
from ..parsers.registry import EcosystemRegistry
from ..popularity import should_soften_low_release_cadence
from .models import (
    AccountType,
    AggregatedDependency,
    DependencyKey,
    DependencyOccurrence,
    DependencyProfiler,
    ManifestParseFailure,
    ManifestRef,
    OrgScanReport,
    RepositoryRef,
    RepositoryRiskSummary,
    canonical_ecosystem,
    risk_points,
    risk_rank,
)

logger = logging.getLogger(__name__)

SUPPORTED_MANIFEST_NAMES = (
    "requirements.txt",
    "Pipfile.lock",
    "pyproject.toml",
    "package-lock.json",
    "go.mod",
    "Cargo.toml",
    "Gemfile.lock",
)


ProgressCallback = Callable[[str], None]
RepositoryLister = Callable[[str, bool, Optional[int]], List[RepositoryRef]]
PackageIdentity = Tuple[str, str]


class GitHubDiscoveryClient:
    """Protocol-like base for GitHub discovery clients."""

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
        supported_names: Iterable[str],
    ) -> List[str]:
        """List supported manifest paths in a repository."""
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
    manifest_globs: Tuple[str, ...] = SUPPORTED_MANIFEST_NAMES
    concurrency: int = 8


@dataclass
class _ParsedInventory:
    """Parsed dependency inventory before profiling."""

    repositories: List[RepositoryRef]
    manifests: List[ManifestRef]
    unique_dependencies: Dict[DependencyKey, DependencyMetadata]
    occurrences: List[DependencyOccurrence]
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
        manifests = self._discover_manifests(repositories, options)
        self._emit(f"Found {len(manifests)} supported manifests")

        parsed = self._parse_manifests(repositories, manifests)
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
    ) -> List[ManifestRef]:
        """Discover and fetch supported manifests with bounded concurrency."""
        manifests: List[ManifestRef] = []
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
                    repo_manifests = future.result()
                    manifests.extend(repo_manifests)
                except Exception as exc:
                    warning = f"{repo.full_name}: manifest discovery failed: {exc}"
                    logger.warning(warning)
                    warnings.append(warning)
                total = len(repositories)
                self._emit(f"Scanned manifest trees for {completed} / {total} repos")

        if warnings:
            logger.warning("Skipped %s repositories during discovery", len(warnings))
        return sorted(manifests, key=lambda item: (item.repo_full_name, item.path))

    def _fetch_repo_manifests(
        self, repo: RepositoryRef, options: OrgScanOptions
    ) -> List[ManifestRef]:
        """Fetch all supported manifests for one repository."""
        paths = self.github_client.list_manifest_paths(repo, SUPPORTED_MANIFEST_NAMES)
        selected_paths = [
            path for path in paths if self._matches_manifest_globs(path, options)
        ]
        manifests: List[ManifestRef] = []
        for path in selected_paths:
            content = self.github_client.fetch_manifest_content(repo, path)
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
        return manifests

    def _parse_manifests(
        self, repositories: List[RepositoryRef], manifests: List[ManifestRef]
    ) -> _ParsedInventory:
        """Parse fetched manifests through the existing parser registry."""
        unique_dependencies: Dict[DependencyKey, DependencyMetadata] = {}
        occurrences: List[DependencyOccurrence] = []
        failures: List[ManifestParseFailure] = []

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
            parse_failures=failures,
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
                key_signals=self._key_signals(representative_score),
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
        repo_summaries = self._repository_summaries(parsed, by_identity)

        high_risk_dependencies = [
            item
            for item in inventory
            if item.risk_level in {RiskLevel.CRITICAL, RiskLevel.HIGH}
        ]
        high_risk_repos: Set[str] = set()
        for item in high_risk_dependencies:
            high_risk_repos.update(item.repositories)

        headline = (
            f"{len(high_risk_dependencies)} high-risk dependencies exposed across "
            f"{len(high_risk_repos)} repositories"
        )

        return OrgScanReport(
            org=org,
            account_type=account_type,
            generated_at=datetime.now(),
            repositories_scanned=[repo.full_name for repo in parsed.repositories],
            manifests_scanned=[manifest.display_path for manifest in parsed.manifests],
            unique_dependency_count=len(inventory),
            parse_failures=parsed.parse_failures,
            inventory=inventory,
            most_exposed_risky_dependencies=most_exposed,
            riskiest_repositories=repo_summaries,
            high_risk_dependency_count=len(high_risk_dependencies),
            high_risk_exposed_repository_count=len(high_risk_repos),
            headline=headline,
            warnings=parsed.warnings,
        )

    def _repository_summaries(
        self,
        parsed: _ParsedInventory,
        by_identity: Dict[PackageIdentity, AggregatedDependency],
    ) -> List[RepositoryRiskSummary]:
        """Build repository aggregate risk summaries."""
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
                for identity in identities
                if identity in by_identity
            ]
            total_score = sum(dep.risk_score.total_score for dep in dependencies)
            average_score = total_score / len(dependencies) if dependencies else 0.0
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
                    critical_risk_dependencies=critical,
                    high_risk_dependencies=high,
                    medium_risk_dependencies=medium,
                    unknown_risk_dependencies=unknown,
                    risk_points=points,
                    average_risk_score=average_score,
                    worst_dependencies=worst,
                )
            )

        return sorted(
            summaries,
            key=lambda repo: (
                -repo.risk_points,
                -repo.critical_risk_dependencies,
                -repo.high_risk_dependencies,
                -repo.average_risk_score,
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
            dependency.key.display_name.lower(),
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

    def _key_signals(self, score: DependencyRiskScore) -> List[str]:
        """Return plain-language signals for report display."""
        dependency = score.dependency
        if score.insufficient_data:
            return ["Insufficient data for confident risk level"]

        signals: List[str] = []
        if dependency.maintainer_count is not None and dependency.maintainer_count <= 1:
            signals.append("single maintainer")
        if dependency.is_deprecated:
            signals.append("deprecated")
        if should_soften_low_release_cadence(dependency) and (
            (score.staleness_score is not None and score.staleness_score > 0)
            or (score.maintained_score is not None and score.maintained_score > 0)
        ):
            signals.append("stable, low release cadence")
        if score.maintained_score is not None and score.maintained_score > 0.5:
            if not should_soften_low_release_cadence(dependency):
                signals.append("not actively maintained")
        if (
            score.security_policy_score is not None
            and score.security_policy_score > 0.5
        ):
            signals.append("missing security policy")
        if score.version_score is not None and score.version_score > 0:
            signals.append("behind latest")
        if score.license_score is not None and score.license_score > 0.5:
            signals.append("license risk")
        if score.exploit_score is not None and score.exploit_score > 0:
            signals.append("scored advisories")
        if dependency.transitive_dependencies:
            signals.append(f"{len(dependency.transitive_dependencies)} transitive deps")

        if not signals and score.factors:
            signals.extend(score.factors[:2])
        if not signals:
            signals.append("no leading risk signals")
        return signals[:4]

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
        required = {"python", "nodejs", "golang", "pyproject", "cargo", "rubygems"}
        available = set(EcosystemRegistry.get_available_ecosystems())
        if not required.issubset(available):
            BaseParser._initialize_registry()

    def _matches_manifest_globs(
        self, manifest_path: str, options: OrgScanOptions
    ) -> bool:
        """Return whether a manifest path matches user-selected globs."""
        for pattern in options.manifest_globs:
            if fnmatch.fnmatch(manifest_path, pattern) or fnmatch.fnmatch(
                Path(manifest_path).name, pattern
            ):
                return True
        return False

    def _write_temp_manifest(self, temp_root: Path, manifest: ManifestRef) -> Path:
        """Write a fetched manifest to a parser-friendly temp path."""
        repo_dir = temp_root / manifest.repo_full_name.replace("/", "__")
        manifest_path = repo_dir / manifest.path
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(manifest.content, encoding="utf-8")
        return manifest_path

    def _emit(self, message: str) -> None:
        """Emit progress when a callback is configured."""
        if self.progress is not None:
            self.progress(message)
