"""Adapter that reuses the existing per-manifest analysis and scoring pipeline."""

from __future__ import annotations

import asyncio
import copy
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Protocol, Tuple
from urllib.parse import urlparse

from ..analyzers.base import BaseAnalyzer
from ..models import CommunityMetrics, DependencyMetadata, DependencyRiskScore
from ..popularity import GITHUB_REPOSITORY_ARCHIVED_KEY
from ..scoring.risk_scorer import RiskScorer
from .github import RepoSignals
from .models import DependencyKey, DependencyProfiler

logger = logging.getLogger(__name__)

# Profiling each dependency is I/O-bound (npm/PyPI fetch, a shallow git clone,
# GitHub API calls, advisory lookups), so a bounded thread pool cuts wall-clock
# roughly linearly. Capped to stay a good API citizen.
DEFAULT_PROFILE_WORKERS = 8


@dataclass(frozen=True)
class VulnerabilityOptions:
    """Options for vulnerability enrichment during org scans."""

    enable_osv: bool = True
    enable_nvd: bool = False
    enable_github_advisory: bool = False
    github_token: str = ""
    nvd_api_key: str = ""
    disable_cache: bool = False
    clear_cache: bool = False
    minimum_severity_for_scoring: str = "LOW"


class RepositorySignalsClient(Protocol):
    """Protocol-like base for authenticated repository signal enrichment."""

    def get_repository_signals(self, owner_repo: str) -> RepoSignals:
        """Fetch popularity and repository state signals for owner/repo."""
        raise NotImplementedError


class ExistingDependencyProfiler(DependencyProfiler):
    """Profile unique dependencies by reusing existing analyzers and scorer."""

    def __init__(
        self,
        scoring_weights: Mapping[str, float],
        vulnerability_options: VulnerabilityOptions,
        timeout: int = 30,
        repository_signals_client: Optional[RepositorySignalsClient] = None,
        max_workers: int = DEFAULT_PROFILE_WORKERS,
    ) -> None:
        """Initialize the profiler adapter."""
        self.scoring_weights = dict(scoring_weights)
        self.vulnerability_options = vulnerability_options
        self.timeout = timeout
        self.repository_signals_client = repository_signals_client
        self.max_workers = max(1, max_workers)
        self._profile_cache: Dict[DependencyKey, DependencyRiskScore] = {}
        self._repository_signals_cache: Dict[str, RepoSignals] = {}
        # Each worker thread keeps its own analyzers so their per-call metadata
        # caches never race; the shared dicts below are guarded by locks.
        self._thread_local = threading.local()
        self._cache_lock = threading.Lock()
        self._signals_lock = threading.Lock()

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Analyze and score each unique dependency once, in parallel."""
        pending: List[Tuple[DependencyKey, DependencyMetadata]] = [
            (key, metadata)
            for key, metadata in dependencies.items()
            if key not in self._profile_cache
        ]
        if pending:
            self._prewarm_osv_batch_cache(pending)
            workers = min(self.max_workers, len(pending))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self._profile_one, key, metadata): key
                    for key, metadata in pending
                }
                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        score = future.result()
                    except Exception as exc:  # keep one bad dep from failing all
                        logger.error("Failed to profile %s: %s", key, exc)
                        continue
                    with self._cache_lock:
                        self._profile_cache[key] = score

        profiles: Dict[DependencyKey, DependencyRiskScore] = {}
        for key in dependencies:
            cached = self._profile_cache.get(key)
            if cached is not None:
                profiles[key] = cached
        return profiles

    def _prewarm_osv_batch_cache(
        self, pending: List[Tuple[DependencyKey, DependencyMetadata]]
    ) -> None:
        """Pre-warm OSV cache for pending dependencies when source-safe."""
        options = self.vulnerability_options
        if not (
            options.enable_osv
            and not options.enable_nvd
            and not options.enable_github_advisory
        ):
            return

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            logger.debug("Skipping OSV querybatch pre-warm inside a running event loop")
            return

        try:
            from ..vulnerabilities.osv_batch import prewarm_osv_querybatch_cache

            asyncio.run(
                prewarm_osv_querybatch_cache(
                    [(metadata.name, key.ecosystem) for key, metadata in pending]
                )
            )
        except Exception as exc:
            logger.debug("OSV querybatch cache pre-warm failed: %s", exc)

    def _profile_one(
        self, key: DependencyKey, metadata: DependencyMetadata
    ) -> DependencyRiskScore:
        """Analyze and score one dependency key."""
        dependency = copy.deepcopy(metadata)
        # Record the real ecosystem so vulnerability lookups query the correct
        # OSV ecosystem instead of guessing it from the repository URL (which
        # mis-routes most npm/cargo deps to PyPI and finds zero advisories).
        dependency.additional_info["ecosystem"] = key.ecosystem
        analyzer = self._get_analyzer(key.ecosystem)
        if analyzer is not None:
            analyzed = analyzer.analyze({dependency.name: dependency})
            dependency = analyzed.get(dependency.name, dependency)
            dependency = self._apply_enhanced_metadata(analyzer, dependency)

        dependency = self._apply_github_repository_signals(dependency)
        dependency = self._apply_vulnerabilities(dependency)

        scorer = RiskScorer(**self.scoring_weights)
        return scorer.score_dependency(dependency)

    def _get_analyzer(self, ecosystem: str) -> Optional[BaseAnalyzer]:
        """Return a per-thread analyzer for an ecosystem.

        Analyzers keep a mutable per-call metadata cache, so each worker thread
        gets its own instance rather than sharing one across the pool.
        """
        analyzers: Optional[Dict[str, BaseAnalyzer]] = getattr(
            self._thread_local, "analyzers", None
        )
        if analyzers is None:
            analyzers = {}
            self._thread_local.analyzers = analyzers
        if ecosystem not in analyzers:
            analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(ecosystem)
            if analyzer is None:
                logger.warning("No analyzer available for ecosystem %s", ecosystem)
                return None
            analyzer.timeout = self.timeout
            # Org scans derive last-update / tests / CI from the GitHub API
            # (see _apply_github_repository_signals) instead of cloning each dep.
            analyzer.clone_repos = False
            analyzers[ecosystem] = analyzer
        return analyzers[ecosystem]

    def _apply_enhanced_metadata(
        self, analyzer: BaseAnalyzer, dependency: DependencyMetadata
    ) -> DependencyMetadata:
        """Apply license and community enrichment using analyzer metadata cache."""
        package_metadata = self._package_metadata(analyzer, dependency.name)

        try:
            from ..community.analyzer import analyze_community_metrics
            from ..license.analyzer import analyze_license

            if isinstance(package_metadata, dict):
                dependency = analyze_license(dependency, package_metadata)
                dependency = analyze_community_metrics(dependency, package_metadata)
            else:
                dependency = analyze_community_metrics(dependency)
        except ImportError as exc:
            logger.warning("Enhanced analyzers not available: %s", exc)
        except Exception as exc:
            logger.error("Enhanced analysis failed for %s: %s", dependency.name, exc)

        return dependency

    def _apply_github_repository_signals(
        self, dependency: DependencyMetadata
    ) -> DependencyMetadata:
        """Apply authenticated GitHub signals when the dependency has a repo URL."""
        if self.repository_signals_client is None:
            return dependency
        owner_repo = self._github_owner_repo(dependency.repository_url)
        if owner_repo is None:
            return dependency

        with self._signals_lock:
            signals = self._repository_signals_cache.get(owner_repo)
        if signals is None:
            # Fetch outside the lock so distinct repos resolve concurrently.
            signals = self.repository_signals_client.get_repository_signals(owner_repo)
            with self._signals_lock:
                signals = self._repository_signals_cache.setdefault(owner_repo, signals)
        if (
            signals.star_count is None
            and signals.contributor_count is None
            and signals.archived is None
            and signals.pushed_at is None
            and signals.has_tests is None
            and signals.has_ci is None
        ):
            return dependency

        if dependency.community_metrics is None:
            dependency.community_metrics = CommunityMetrics()
        if signals.star_count is not None:
            dependency.community_metrics.star_count = signals.star_count
        if signals.contributor_count is not None:
            dependency.community_metrics.contributor_count = signals.contributor_count
            dependency.maintainer_count = signals.contributor_count
        if signals.archived is not None:
            dependency.additional_info[GITHUB_REPOSITORY_ARCHIVED_KEY] = (
                "true" if signals.archived else "false"
            )
        # These replace what the per-dependency git clone used to provide, so an
        # org scan gets maintenance cadence and test/CI presence from the API.
        if signals.pushed_at is not None:
            dependency.last_updated = signals.pushed_at
        if signals.has_tests is not None:
            dependency.has_tests = signals.has_tests
        if signals.has_ci is not None:
            dependency.has_ci = signals.has_ci
        return dependency

    def _github_owner_repo(self, repository_url: Optional[str]) -> Optional[str]:
        """Extract owner/repo from github.com repository URLs without guessing."""
        if repository_url is None:
            return None

        normalized = repository_url.strip()
        if not normalized:
            return None

        if normalized.startswith("git@github.com:"):
            path = normalized.removeprefix("git@github.com:")
        else:
            if normalized.startswith("git+"):
                normalized = normalized.removeprefix("git+")
            parsed = urlparse(normalized)
            hostname = parsed.hostname
            if hostname is None or hostname.lower() != "github.com":
                return None
            path = parsed.path

        parts = [part for part in path.strip("/").split("/") if part]
        if len(parts) < 2:
            return None
        owner = parts[0]
        repo = parts[1]
        if repo.endswith(".git"):
            repo = repo.removesuffix(".git")
        if not owner or not repo:
            return None
        return f"{owner}/{repo}"

    def _package_metadata(
        self, analyzer: BaseAnalyzer, dependency_name: str
    ) -> Optional[object]:
        """Read analyzer metadata cache without depending on analyzer internals."""
        cache = getattr(analyzer, "metadata_cache", None)
        if not isinstance(cache, dict):
            return None
        return cache.get(dependency_name)

    def _apply_vulnerabilities(
        self, dependency: DependencyMetadata
    ) -> DependencyMetadata:
        """Enrich a dependency with configured vulnerability sources."""
        options = self.vulnerability_options
        if options.disable_cache:
            import os

            os.environ["DEPENDENCY_RISK_DISABLE_CACHE"] = "1"

        if options.clear_cache:
            try:
                from ..vulnerabilities.cache import default_cache

                default_cache.clear()
            except ImportError:
                logger.warning("Vulnerability cache module not available")

        if not (
            options.enable_osv or options.enable_nvd or options.enable_github_advisory
        ):
            return dependency

        try:
            from ..vulnerabilities.aggregator_async import (
                aggregate_vulnerability_data_async,
            )

            updated, _ = aggregate_vulnerability_data_async(
                {dependency.name: dependency},
                api_keys={
                    "github": options.github_token,
                    "nvd": options.nvd_api_key,
                },
                enable_osv=options.enable_osv,
                enable_nvd=options.enable_nvd,
                enable_github=options.enable_github_advisory,
                minimum_severity=options.minimum_severity_for_scoring,
            )
            return updated.get(dependency.name, dependency)
        except ImportError:
            logger.warning("Async vulnerability aggregation not available")
            return dependency
        except Exception as exc:
            logger.error(
                "Vulnerability aggregation failed for %s: %s",
                dependency.name,
                exc,
            )
            return dependency
