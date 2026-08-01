"""Analyzer for Ruby (RubyGems) dependencies."""

import logging
from typing import Dict, Optional

import requests

from ..models import DependencyMetadata
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)


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

                latest = info.get("version")
                if isinstance(latest, str) and latest:
                    dep.latest_version = latest

                repo = info.get("source_code_uri") or info.get("homepage_uri")
                if isinstance(repo, str) and repo:
                    dep.repository_url = repo
            except Exception as exc:
                logger.error("Error analyzing Ruby gem %s: %s", name, exc)

        return dependencies

    def _get_gem_info(self, gem_name: str) -> Optional[Dict[str, object]]:
        """Return rubygems.org metadata for a gem, or None on failure."""
        url = f"https://rubygems.org/api/v1/gems/{gem_name}.json"
        headers = {"User-Agent": "dependency-risk-profiler (metadata lookup)"}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("rubygems.org lookup failed for %s: %s", gem_name, exc)
            return None
        if response.status_code != 200:
            return None
        try:
            data = response.json()
        except ValueError:
            return None
        return data if isinstance(data, dict) else None
