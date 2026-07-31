"""Adapter that reuses the existing per-manifest analysis and scoring pipeline."""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass
from typing import Dict, Mapping, Optional

from ..analyzers.base import BaseAnalyzer
from ..models import DependencyMetadata, DependencyRiskScore
from ..scoring.risk_scorer import RiskScorer
from .models import DependencyKey, DependencyProfiler

logger = logging.getLogger(__name__)


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


class ExistingDependencyProfiler(DependencyProfiler):
    """Profile unique dependencies by reusing existing analyzers and scorer."""

    def __init__(
        self,
        scoring_weights: Mapping[str, float],
        vulnerability_options: VulnerabilityOptions,
        timeout: int = 30,
    ) -> None:
        """Initialize the profiler adapter."""
        self.scoring_weights = dict(scoring_weights)
        self.vulnerability_options = vulnerability_options
        self.timeout = timeout
        self._profile_cache: Dict[DependencyKey, DependencyRiskScore] = {}
        self._analyzers: Dict[str, BaseAnalyzer] = {}

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Analyze and score each unique dependency once."""
        profiles: Dict[DependencyKey, DependencyRiskScore] = {}
        for key, metadata in dependencies.items():
            if key not in self._profile_cache:
                self._profile_cache[key] = self._profile_one(key, metadata)
            profiles[key] = self._profile_cache[key]
        return profiles

    def _profile_one(
        self, key: DependencyKey, metadata: DependencyMetadata
    ) -> DependencyRiskScore:
        """Analyze and score one dependency key."""
        dependency = copy.deepcopy(metadata)
        analyzer = self._get_analyzer(key.ecosystem)
        if analyzer is not None:
            analyzed = analyzer.analyze({dependency.name: dependency})
            dependency = analyzed.get(dependency.name, dependency)
            dependency = self._apply_enhanced_metadata(analyzer, dependency)

        dependency = self._apply_vulnerabilities(dependency)

        scorer = RiskScorer(**self.scoring_weights)
        return scorer.score_dependency(dependency)

    def _get_analyzer(self, ecosystem: str) -> Optional[BaseAnalyzer]:
        """Return a cached analyzer for an ecosystem."""
        if ecosystem not in self._analyzers:
            analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(ecosystem)
            if analyzer is None:
                logger.warning("No analyzer available for ecosystem %s", ecosystem)
                return None
            analyzer.timeout = self.timeout
            self._analyzers[ecosystem] = analyzer
        return self._analyzers[ecosystem]

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
