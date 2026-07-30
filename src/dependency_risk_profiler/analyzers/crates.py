"""Analyzer for Rust crates.io dependencies."""

import json
import logging
from collections.abc import Mapping
from typing import Dict, Optional

import requests

from ..models import DependencyMetadata
from .base import BaseAnalyzer
from .common import check_for_vulnerabilities

logger = logging.getLogger(__name__)


class CratesIOAnalyzer(BaseAnalyzer):
    """Analyzer for Rust dependencies published on crates.io."""

    def __init__(self, timeout: int = 10):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        self.metadata_cache: Dict[str, Mapping[str, object]] = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Rust dependencies and collect crates.io metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info(f"Analyzing Rust crate: {name}")
            dep.additional_info["ecosystem"] = "cargo"
            dep.additional_info["source"] = "crates.io"

            try:
                crate_info = self._get_crate_info(name)
                if not crate_info:
                    dep.additional_info["analysis_status"] = "unknown"
                    continue

                crate_summary = self._mapping_value(crate_info, "crate")
                if not crate_summary:
                    dep.additional_info["analysis_status"] = "unknown"
                    continue

                self.metadata_cache[name] = crate_summary
                dep.additional_info["analysis_status"] = "analyzed"

                latest_version = self._string_value(crate_summary, "max_version")
                if latest_version:
                    dep.latest_version = latest_version

                repository_url = self._string_value(crate_summary, "repository")
                if repository_url:
                    dep.repository_url = repository_url

                description = self._string_value(crate_summary, "description")
                if description:
                    dep.additional_info["description"] = description

                dep.has_known_exploits = check_for_vulnerabilities(name, "cargo")
            except Exception as e:
                logger.error(f"Error analyzing Rust crate {name}: {e}")
                dep.additional_info["analysis_status"] = "unknown"

        return dependencies

    def _get_crate_info(self, crate_name: str) -> Optional[Mapping[str, object]]:
        """Get crate information from crates.io.

        Args:
            crate_name: Name of the Rust crate.

        Returns:
            crates.io API response, or None if fetching failed.
        """
        url = f"https://crates.io/api/v1/crates/{crate_name}"
        headers = {
            "User-Agent": "dependency-risk-profiler (metadata lookup)",
        }

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            parsed: object = json.loads(response.text)
        except (json.JSONDecodeError, requests.RequestException) as e:
            logger.debug(f"Could not fetch crates.io metadata for {crate_name}: {e}")
            return None

        if not isinstance(parsed, Mapping):
            return None

        return {key: value for key, value in parsed.items() if isinstance(key, str)}

    def _mapping_value(
        self, data: Mapping[str, object], key: str
    ) -> Optional[Mapping[str, object]]:
        """Return a nested mapping value when present.

        Args:
            data: Source mapping.
            key: Key to read.

        Returns:
            Nested mapping, or None when absent or of another type.
        """
        value = data.get(key)
        if not isinstance(value, Mapping):
            return None

        return {
            nested_key: nested_value
            for nested_key, nested_value in value.items()
            if isinstance(nested_key, str)
        }

    def _string_value(self, data: Mapping[str, object], key: str) -> Optional[str]:
        """Return a string value when present.

        Args:
            data: Source mapping.
            key: Key to read.

        Returns:
            String value, or None when absent or of another type.
        """
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
        return None
