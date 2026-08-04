"""Analyzer for Rust crates.io dependencies."""

import json
import logging
from collections.abc import Mapping
from typing import Dict, Optional, Sequence

import requests

from ..models import DependencyMetadata
from ..parsers.crates import runtime_dependency_names
from ..release_dates import (
    apply_registry_release_date,
    parse_registry_timestamp,
    record_source_repository,
)
from ..signals import FieldSource, ProvenancedField
from ..transitive.analyzer_enhanced import record_transitive_source
from .base import BaseAnalyzer
from .common import canonical_repository_url, collect_repository_signals

logger = logging.getLogger(__name__)

CRATES_API_BASE = "https://crates.io/api/v1/crates"
_USER_AGENT = "dependency-risk-profiler (metadata lookup)"

# Recorded so the transitive signal is treated as measured rather than as an
# assumed-empty set (#141, #204).
#
# cargo is the one ecosystem of the five in #204 that costs a request for this.
# The ``/crates/<name>`` document carries no dependency list — only a
# ``links.dependencies`` pointer to the per-version endpoint — so unlike npm,
# PyPI and RubyGems there is nothing already in hand to read. That is a real
# cost in a thread-pooled org scan: it takes the adapter from two requests per
# crate to three, +50%.
#
# Taken anyway, and the precedent is in this same adapter: ``_get_owner_count``
# already spends a second request on the maintainer signal, for a signal of
# comparable weight. Without it cargo is the only registry ecosystem that
# cannot answer a dependency count at all, which is precisely the like-for-like
# problem #204 exists to close. The failure semantics mirror the owners read —
# a request that does not answer records nothing, so an unreachable endpoint
# leaves the signal unmeasured rather than fabricating a zero.
TRANSITIVE_SOURCE_CRATES_IO = "crates-io-dependencies"


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
                    # Same shape, second field: `crate.max_version` is the
                    # highest *installable* version, and crates.io answers it
                    # with the sentinel "0.0.0" when every published version is
                    # yanked. Reading that as the latest release makes a
                    # withdrawn crate look current — acid-store's newest
                    # release is 0.14.2, and against a "0.0.0" latest an
                    # installed 0.10.0 scores as a trivial patch behind. The
                    # release entry's own `num` is the version that actually
                    # exists, and equals max_version whenever max_version
                    # resolves to a real release.
                    if "num" in release:
                        metadata["released_num"] = release["num"]

                self.metadata_cache[name] = metadata
                dep.additional_info["analysis_status"] = "analyzed"
                self._apply_registry_metadata(dep, metadata)

                # The dependency list is the one crates.io fact that is not in
                # the crate document, so it costs a request. See
                # TRANSITIVE_SOURCE_CRATES_IO for why that is spent.
                self._apply_runtime_dependencies(dep, metadata)

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
                    dep.record_field_source(
                        ProvenancedField.MAINTAINER_COUNT,
                        FieldSource.REGISTRY_METADATA,
                    )
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
        latest_version = self._string_value(
            metadata, "released_num"
        ) or self._string_value(metadata, "max_version")
        if latest_version:
            dep.latest_version = latest_version

        repository_url = self._repository_url(metadata)
        if repository_url:
            dep.repository_url = repository_url
        # ``repository`` is Cargo's designated source pointer and is read raw
        # here: a crate declaring a repository nobody can clone is a different
        # fact from one declaring none (#176). ``homepage`` stays a resolution
        # fallback and is not a declaration of source.
        record_source_repository(
            dep, repository_url, declared=self._string_value(metadata, "repository")
        )

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

    def _apply_runtime_dependencies(
        self, dep: DependencyMetadata, metadata: Mapping[str, object]
    ) -> None:
        """Read the crate's runtime dependencies and record them positively.

        The endpoint is version-pinned, so this needs the version the crate
        document actually resolved to — ``released_num``, with ``max_version``
        behind it, exactly as the latest-version read does. A crate whose every
        release is yanked answers ``max_version`` with the sentinel ``0.0.0``
        and has no such document; the request 404s, ``runtime_dependency_names``
        returns None, and the signal stays unmeasured rather than becoming a
        confident zero.

        ``[dev-dependencies]`` and ``[build-dependencies]`` are excluded; see
        ``parsers.crates`` for why ``optional`` is not a third exclusion.

        Args:
            dep: Dependency metadata to update in place.
            metadata: Merged crate summary and latest-release entry.
        """
        version = self._string_value(metadata, "released_num") or self._string_value(
            metadata, "max_version"
        )
        if not version:
            return
        shipped = runtime_dependency_names(
            self._get_json(f"{CRATES_API_BASE}/{dep.name}/{version}/dependencies")
        )
        if shipped is None:
            logger.debug(
                "crates.io answered no dependencies document for %s %s; the "
                "transitive signal stays unmeasured",
                dep.name,
                version,
            )
            return
        dep.transitive_dependencies = shipped - {dep.name}
        record_transitive_source(dep, source=TRANSITIVE_SOURCE_CRATES_IO)

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
