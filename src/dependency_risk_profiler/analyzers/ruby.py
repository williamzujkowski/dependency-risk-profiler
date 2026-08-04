"""Analyzer for Ruby (RubyGems) dependencies."""

import logging
from datetime import datetime
from typing import Dict, List, Optional

import requests

from ..analysis_helpers import analyze_repository
from ..models import DependencyMetadata
from .base import BaseAnalyzer
from .common import canonical_repository_url, cloned_repo, is_cloneable_repo_url

logger = logging.getLogger(__name__)

RUBYGEMS_API_BASE = "https://rubygems.org/api/v1"
_USER_AGENT = "dependency-risk-profiler (metadata lookup)"


class RubyGemsAnalyzer(BaseAnalyzer):
    """Analyzer for Ruby dependencies published on rubygems.org."""

    def __init__(self, timeout: int = 10):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        self.metadata_cache: Dict[str, Dict[str, object]] = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Ruby dependencies and collect rubygems.org metadata.

        Args:
            dependencies: Dictionary mapping gem names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info("Analyzing Ruby gem: %s", name)
            # Route vulnerability lookups to the RubyGems OSV ecosystem.
            dep.additional_info["ecosystem"] = "rubygems"

            try:
                info = self._get_gem_info(name)
                if not info:
                    continue
                self.metadata_cache[name] = info
                self._apply_registry_metadata(dep, info)

                # Repository-derived signals (last commit, tests/CI, the
                # OpenSSF-style security checks) come from the source repo, the
                # same way the Python/npm/Go analyzers collect them.
                repository_url = dep.repository_url
                if (
                    self.clone_repos
                    and repository_url
                    and is_cloneable_repo_url(repository_url)
                ):
                    with cloned_repo(repository_url) as clone_result:
                        if clone_result:
                            repo_dir, _ = clone_result
                            dep = analyze_repository(dep, repo_dir)

                # Gem owners are RubyGems' own maintainer set (who may push a
                # release). Read them after the repository pass so the shallow
                # clone's contributor count — always ~1 — can't stand in for it.
                owner_count = self._get_owner_count(name)
                if owner_count is not None:
                    dep.maintainer_count = owner_count
            except Exception as exc:
                logger.error("Error analyzing Ruby gem %s: %s", name, exc)

        return dependencies

    def _apply_registry_metadata(
        self, dep: DependencyMetadata, info: Dict[str, object]
    ) -> None:
        """Copy the rubygems.org payload onto the fields the scorer reads.

        Args:
            dep: Dependency metadata to update in place.
            info: rubygems.org ``/gems/<name>.json`` payload.
        """
        latest = info.get("version")
        if isinstance(latest, str) and latest:
            dep.latest_version = latest

        repo = self._repository_url(info)
        if repo:
            dep.repository_url = repo

        # RubyGems dates the latest release, not the repository; it is the
        # release cadence a consumer of the gem actually sees. A cloned repo
        # refines this to the last commit date further down.
        released_at = self._parse_timestamp(info.get("version_created_at"))
        if released_at is not None:
            dep.last_updated = released_at

        # A yanked gem is RubyGems' explicit "do not use this" marker.
        if info.get("yanked") is True:
            dep.is_deprecated = True

    def _repository_url(self, info: Dict[str, object]) -> Optional[str]:
        """Return the gem's repository root, or None when it publishes none.

        Gems spell the repository several ways and commonly point at a tagged
        subpath (``.../tree/v2.0.6``), so each candidate is trimmed back to its
        ``owner/repo`` root before use.
        """
        metadata = info.get("metadata")
        nested: Dict[str, object] = metadata if isinstance(metadata, dict) else {}
        candidates = (
            info.get("source_code_uri"),
            nested.get("source_code_uri"),
            info.get("homepage_uri"),
            nested.get("homepage_uri"),
        )
        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate:
                continue
            canonical = canonical_repository_url(candidate)
            if canonical:
                return canonical
        return None

    @staticmethod
    def _parse_timestamp(value: object) -> Optional[datetime]:
        """Parse a rubygems.org ISO-8601 timestamp, or None if unparseable."""
        if not isinstance(value, str) or not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            logger.debug("Unparseable rubygems.org timestamp: %s", value)
            return None

    def _get_gem_info(self, gem_name: str) -> Optional[Dict[str, object]]:
        """Return rubygems.org metadata for a gem, or None on failure."""
        payload = self._get_json(f"{RUBYGEMS_API_BASE}/gems/{gem_name}.json")
        return payload if isinstance(payload, dict) else None

    def _get_owner_count(self, gem_name: str) -> Optional[int]:
        """Return the number of registered owners for a gem, or None on failure."""
        payload = self._get_json(f"{RUBYGEMS_API_BASE}/gems/{gem_name}/owners.json")
        if not isinstance(payload, list):
            return None
        owners: List[object] = payload
        return len(owners) if owners else None

    def _get_json(self, url: str) -> Optional[object]:
        """Fetch and decode a rubygems.org JSON endpoint, or None on failure."""
        headers = {"User-Agent": _USER_AGENT}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("rubygems.org lookup failed for %s: %s", url, exc)
            return None
        if response.status_code != 200:
            return None
        try:
            payload: object = response.json()
        except ValueError:
            return None
        return payload
