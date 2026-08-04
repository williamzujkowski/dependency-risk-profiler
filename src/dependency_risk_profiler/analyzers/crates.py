"""Analyzer for Rust crates.io dependencies."""

import json
import logging
from collections.abc import Mapping
from typing import Dict, Optional, Sequence

import requests

from ..models import DependencyMetadata
from ..release_dates import (
    apply_registry_release_date,
    parse_registry_timestamp,
    record_source_repository,
)
from .base import BaseAnalyzer
from .common import canonical_repository_url, collect_repository_signals

logger = logging.getLogger(__name__)

CRATES_API_BASE = "https://crates.io/api/v1/crates"
_USER_AGENT = "dependency-risk-profiler (metadata lookup)"


class CratesIOAnalyzer(BaseAnalyzer):
    """Analyzer for Rust dependencies published on crates.io."""

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
        """Analyze Rust dependencies and collect crates.io metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info("Analyzing Rust crate: %s", name)
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

                # crates.io splits the payload: the crate object carries the
                # repository and version pointers, while the license and the
                # release timestamp live on the version entries. The scorer and
                # the license analyzer read one metadata mapping, so the two
                # halves are merged before caching.
                release = self._latest_release(crate_info, crate_summary)
                metadata = dict(crate_summary)
                if release is not None:
                    for key in ("license", "yanked"):
                        if key in release:
                            metadata[key] = release[key]
                    # Recorded under its own key: the crate object's own
                    # `created_at` is when the crate was *first* published, and
                    # reading a 2019 date as the latest release would make an
                    # actively released crate look abandoned.
                    if "created_at" in release:
                        metadata["released_at"] = release["created_at"]

                self.metadata_cache[name] = metadata
                dep.additional_info["analysis_status"] = "analyzed"
                self._apply_registry_metadata(dep, metadata)

                # Repository-derived signals (last commit, tests/CI, the
                # OpenSSF-style security checks) come from the source repo, the
                # same way the Python/npm/Go/RubyGems analyzers collect them.
                dep = collect_repository_signals(
                    dep, dep.repository_url, self.clone_repos
                )
                dependencies[name] = dep

                # crates.io owners are the accounts allowed to publish the
                # crate. Read after the repository pass so a shallow clone's
                # contributor count — always ~1 — can't stand in for it.
                owner_count = self._get_owner_count(name)
                if owner_count is not None:
                    dep.maintainer_count = owner_count
            except Exception as exc:
                logger.error("Error analyzing Rust crate %s: %s", name, exc)
                dep.additional_info["analysis_status"] = "unknown"

        return dependencies

    def _apply_registry_metadata(
        self, dep: DependencyMetadata, metadata: Mapping[str, object]
    ) -> None:
        """Copy the crates.io payload onto the fields the scorer reads.

        Args:
            dep: Dependency metadata to update in place.
            metadata: Merged crate summary and latest-release entry.
        """
        latest_version = self._string_value(metadata, "max_version")
        if latest_version:
            dep.latest_version = latest_version

        repository_url = self._repository_url(metadata)
        if repository_url:
            dep.repository_url = repository_url
        record_source_repository(dep, repository_url)

        # The newest release date is the publication cadence a consumer of the
        # crate actually sees, and it now wins over a clone's last commit
        # rather than being overwritten by it (#146).
        apply_registry_release_date(
            dep,
            parse_registry_timestamp(
                metadata.get("released_at") or metadata.get("updated_at")
            ),
        )

        # A yanked release is crates.io's explicit "do not use this" marker.
        if metadata.get("yanked") is True:
            dep.is_deprecated = True

        description = self._string_value(metadata, "description")
        if description:
            dep.additional_info["description"] = description

    def _repository_url(self, metadata: Mapping[str, object]) -> Optional[str]:
        """Return the crate's repository root, or None when it publishes none.

        Crates in a workspace commonly point ``repository`` at their own
        subdirectory (``.../tree/master/regex-syntax``), which neither
        ``git clone`` nor the GitHub API accepts, so each candidate is trimmed
        back to its ``owner/repo`` root. ``homepage`` is the fallback because
        some crates publish the repository only there; non-repository homepages
        are rejected by the canonicalizer rather than guessed at.
        """
        for key in ("repository", "homepage"):
            canonical = canonical_repository_url(self._string_value(metadata, key))
            if canonical:
                return canonical
        return None

    def _latest_release(
        self, crate_info: Mapping[str, object], crate_summary: Mapping[str, object]
    ) -> Optional[Mapping[str, object]]:
        """Return the version entry matching the crate's newest release.

        Args:
            crate_info: Full crates.io ``/crates/<name>`` payload.
            crate_summary: The payload's ``crate`` object.

        Returns:
            The matching version entry, the first entry when no version matches,
            or None when the payload carries no version entries.
        """
        versions = crate_info.get("versions")
        if not isinstance(versions, Sequence) or isinstance(versions, (str, bytes)):
            return None
        entries = [entry for entry in versions if isinstance(entry, Mapping)]
        if not entries:
            return None

        wanted = self._string_value(crate_summary, "max_version")
        for entry in entries:
            if wanted and self._string_value(entry, "num") == wanted:
                return entry
        # crates.io lists versions newest-first, so entry zero is the fallback.
        return entries[0]

    def _get_crate_info(self, crate_name: str) -> Optional[Mapping[str, object]]:
        """Get crate information from crates.io.

        Args:
            crate_name: Name of the Rust crate.

        Returns:
            crates.io API response, or None if fetching failed.
        """
        parsed = self._get_json(f"{CRATES_API_BASE}/{crate_name}")
        if not isinstance(parsed, Mapping):
            return None

        return {key: value for key, value in parsed.items() if isinstance(key, str)}

    def _get_owner_count(self, crate_name: str) -> Optional[int]:
        """Return the number of registered owners for a crate, or None on failure."""
        payload = self._get_json(f"{CRATES_API_BASE}/{crate_name}/owners")
        if not isinstance(payload, Mapping):
            return None
        users = payload.get("users")
        if not isinstance(users, Sequence) or isinstance(users, (str, bytes)):
            return None
        return len(users) if users else None

    def _get_json(self, url: str) -> Optional[object]:
        """Fetch and decode a crates.io JSON endpoint, or None on failure."""
        headers = {"User-Agent": _USER_AGENT}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            parsed: object = json.loads(response.text)
        except (json.JSONDecodeError, requests.RequestException) as exc:
            logger.debug("Could not fetch crates.io metadata from %s: %s", url, exc)
            return None
        return parsed

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
