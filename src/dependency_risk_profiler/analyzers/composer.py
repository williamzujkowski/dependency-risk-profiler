"""Analyzer for PHP (Composer / Packagist) dependencies."""

import logging
from typing import Dict, List, Optional

import requests

from ..models import DependencyMetadata
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)


class ComposerAnalyzer(BaseAnalyzer):
    """Analyzer for PHP dependencies published on Packagist."""

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
        """Analyze PHP dependencies and collect Packagist metadata.

        Args:
            dependencies: Dictionary mapping package names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info("Analyzing PHP package: %s", name)
            # Route vulnerability lookups to the Packagist OSV ecosystem.
            dep.additional_info["ecosystem"] = "composer"

            try:
                latest = self._get_latest_version(name)
                if latest:
                    dep.latest_version = latest
            except Exception as exc:
                logger.error("Error analyzing PHP package %s: %s", name, exc)

        return dependencies

    def _get_latest_version(self, package_name: str) -> Optional[str]:
        """Return the latest non-dev Packagist version for a package, or None."""
        url = f"https://repo.packagist.org/p2/{package_name}.json"
        headers = {"User-Agent": "dependency-risk-profiler (metadata lookup)"}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("Packagist lookup failed for %s: %s", package_name, exc)
            return None
        if response.status_code != 200:
            return None
        try:
            data = response.json()
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return None
        versions = packages.get(package_name)
        if not isinstance(versions, list):
            return None
        # The p2 metadata lists versions newest-first; take the first stable one.
        return self._first_stable_version(versions)

    @staticmethod
    def _first_stable_version(versions: List[object]) -> Optional[str]:
        """Return the first non-dev version string from a Packagist list."""
        for entry in versions:
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and version and not version.startswith("dev-"):
                return version.lstrip("v")
        return None
