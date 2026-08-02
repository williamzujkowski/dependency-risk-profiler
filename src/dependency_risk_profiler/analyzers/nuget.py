"""Analyzer for .NET (NuGet) dependencies."""

import logging
from typing import Dict, List, Optional

import requests

from ..models import DependencyMetadata
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)


class NuGetAnalyzer(BaseAnalyzer):
    """Analyzer for .NET dependencies published on nuget.org."""

    def __init__(self, timeout: int = 10):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        self.metadata_cache: Dict[str, List[str]] = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze .NET dependencies and collect nuget.org metadata.

        Args:
            dependencies: Dictionary mapping package ids to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info("Analyzing NuGet package: %s", name)
            # Route vulnerability lookups to the NuGet OSV ecosystem.
            dep.additional_info["ecosystem"] = "nuget"

            try:
                latest = self._get_latest_version(name)
                if latest:
                    dep.latest_version = latest
            except Exception as exc:
                logger.error("Error analyzing NuGet package %s: %s", name, exc)

        return dependencies

    def _get_latest_version(self, package_id: str) -> Optional[str]:
        """Return the latest stable NuGet version for a package id, or None."""
        # The flat-container index uses the lowercased id.
        url = (
            "https://api.nuget.org/v3-flatcontainer/" f"{package_id.lower()}/index.json"
        )
        headers = {"User-Agent": "dependency-risk-profiler (metadata lookup)"}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("nuget.org lookup failed for %s: %s", package_id, exc)
            return None
        if response.status_code != 200:
            return None
        try:
            data = response.json()
        except ValueError:
            return None
        versions = data.get("versions") if isinstance(data, dict) else None
        if not isinstance(versions, list):
            return None
        # The index lists versions oldest-first; prefer the newest stable one.
        for version in reversed(versions):
            if isinstance(version, str) and version and "-" not in version:
                return version
        # Fall back to the newest version even if it's a pre-release.
        for version in reversed(versions):
            if isinstance(version, str) and version:
                return version
        return None
