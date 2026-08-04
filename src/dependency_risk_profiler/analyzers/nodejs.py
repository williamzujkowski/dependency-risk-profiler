"""Analyzer for Node.js dependencies."""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import quote

from ..models import DependencyMetadata
from ..release_dates import (
    apply_registry_release_date,
    newest_timestamp,
    parse_registry_timestamp,
    record_source_repository,
)
from .base import BaseAnalyzer
from .common import canonical_repository_url, collect_repository_signals, fetch_json

logger = logging.getLogger(__name__)

NPM_REGISTRY_BASE = "https://registry.npmjs.org"


def npm_registry_path(package_name: str) -> str:
    """Return the registry path segment for a package name.

    Scoped names carry a slash (``@cypress/xvfb``). Left alone it reads as a
    path separator and the registry answers 404, so it is percent-encoded to
    ``@cypress%2Fxvfb``. The ``@`` itself is legal in a path segment and the
    registry does not accept it encoded.

    Args:
        package_name: npm package name, scoped or unscoped.

    Returns:
        The percent-encoded path segment.
    """
    return quote(package_name, safe="@")


class NodeJSAnalyzer(BaseAnalyzer):
    """Analyzer for Node.js dependencies."""

    def __init__(self, timeout: int = 30):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        # Cache for package metadata
        self.metadata_cache: Dict[str, Dict[str, object]] = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Node.js dependencies and collect metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info(f"Analyzing npm package: {name}")
            # Route vulnerability lookups to the npm OSV ecosystem explicitly;
            # relying on the repository-URL heuristic misroutes packages whose
            # repo URL lacks an "npm"/"node" token (e.g. lodash) to PyPI.
            dep.additional_info["ecosystem"] = "nodejs"

            try:
                # Get npm package information
                npm_data = self._get_npm_package_info(name)
                if not npm_data:
                    logger.warning(
                        "npm registry lookup failed for %s; version drift and "
                        "every registry-derived signal stay unmeasured",
                        name,
                    )
                    continue

                # Store in cache for other analyzers to use
                self.metadata_cache[name] = npm_data
                self._apply_registry_metadata(dep, npm_data)

                # Repository-derived signals refine what the registry already
                # answered; they no longer decide whether the package has a
                # measurable release cadence at all.
                dependencies[name] = collect_repository_signals(
                    dep, dep.repository_url, self.clone_repos
                )

            except Exception as e:
                logger.error(f"Error analyzing {name}: {e}")

        return dependencies

    def _apply_registry_metadata(
        self, dep: DependencyMetadata, npm_data: Dict[str, object]
    ) -> None:
        """Copy the registry payload onto the fields the scorer reads.

        Args:
            dep: Dependency metadata to update in place.
            npm_data: ``registry.npmjs.org/<package>`` packument.
        """
        latest = self._latest_version(dep.name, npm_data)
        if latest:
            dep.latest_version = latest
        else:
            # #74: an unresolvable latest version leaves the drift signal
            # honestly unmeasured. Say so, rather than failing in silence the
            # way this did for every npm dependency before #140.
            logger.warning(
                "npm registry published no latest version for %s "
                "(no dist-tags.latest and no /latest document); "
                "version drift stays unmeasured",
                dep.name,
            )

        if self._is_deprecated(npm_data, latest):
            dep.is_deprecated = True

        repository_url = self._repository_url(npm_data)
        if repository_url:
            dep.repository_url = repository_url
        record_source_repository(
            dep, repository_url, declared=self._declared_repository(npm_data)
        )

        apply_registry_release_date(dep, self._released_at(npm_data, latest))

    @staticmethod
    def _released_at(
        npm_data: Dict[str, object], latest_version: Optional[str]
    ) -> Optional[datetime]:
        """Return when the package last published a version, or None.

        npm's ``time`` map carries a ``modified`` entry, and it is a trap: it
        moves whenever *any* metadata changes, including the deprecation notice
        itself. ``request`` was last published in February 2020 and its
        ``time.modified`` reads July 2026, which would score the most famous
        abandoned package in the registry as freshly maintained. So the
        latest-tagged version's own timestamp is preferred, then the newest
        per-version timestamp, and ``modified`` only as a last resort — the
        same trap crates.io's crate-level ``created_at`` sets in reverse
        (#139).

        Args:
            npm_data: ``registry.npmjs.org/<package>`` packument.
            latest_version: Latest version, when one resolved.

        Returns:
            The publication timestamp, or None when the registry publishes no
            usable date.
        """
        times = npm_data.get("time")
        if not isinstance(times, dict):
            return None

        if latest_version:
            tagged = parse_registry_timestamp(times.get(latest_version))
            if tagged is not None:
                return tagged

        versioned = newest_timestamp(
            value
            for key, value in times.items()
            if key not in ("created", "modified", "unpublished")
        )
        if versioned is not None:
            return versioned

        return parse_registry_timestamp(times.get("modified"))

    def _latest_version(
        self, package_name: str, npm_data: Dict[str, object]
    ) -> Optional[str]:
        """Return the package's latest published version, or None.

        The packument has no top-level ``version`` key: npm publishes the
        current release as ``dist-tags.latest``. Reading ``version`` off the
        packument is what made this None for every npm dependency (#140).

        Args:
            package_name: npm package name.
            npm_data: ``registry.npmjs.org/<package>`` packument.

        Returns:
            The latest version string, or None when the registry publishes none.
        """
        dist_tags = npm_data.get("dist-tags")
        if isinstance(dist_tags, dict):
            latest = dist_tags.get("latest")
            if isinstance(latest, str) and latest:
                return latest

        # Mirrors and private registries sometimes answer the packument without
        # dist-tags. The per-package ``latest`` document carries the version on
        # its own, so one cheap request recovers the signal.
        manifest = self._get_npm_latest_manifest(package_name)
        if manifest:
            version = manifest.get("version")
            if isinstance(version, str) and version:
                return version

        return None

    @staticmethod
    def _is_deprecated(
        npm_data: Dict[str, object], latest_version: Optional[str]
    ) -> bool:
        """Return whether the package's current release is deprecated.

        npm records deprecation per version manifest, not on the packument, so
        the top-level ``deprecated`` key this used to read never existed.

        Args:
            npm_data: ``registry.npmjs.org/<package>`` packument.
            latest_version: Latest version, when one resolved.

        Returns:
            True when the latest release carries a deprecation notice.
        """
        if not latest_version:
            return False
        versions = npm_data.get("versions")
        if not isinstance(versions, dict):
            return False
        manifest = versions.get(latest_version)
        if not isinstance(manifest, dict):
            return False
        return bool(manifest.get("deprecated"))

    @staticmethod
    def _declared_repository(npm_data: Dict[str, object]) -> Optional[str]:
        """Return the raw ``repository`` field, or None when there is none.

        This is npm's designated source pointer, and it is read raw so that a
        package which declares a repository nobody can clone stays
        distinguishable from one that declares none (#176). ``homepage`` is
        deliberately not consulted: it is a resolution fallback, not a
        declaration of source, and a docs site promoted to a broken repository
        would be a fabricated finding rather than a missed one.

        Args:
            npm_data: ``registry.npmjs.org/<package>`` packument.

        Returns:
            The declared repository URL as published, or None.
        """
        repository = npm_data.get("repository")
        if isinstance(repository, dict):
            repository = repository.get("url")
        if isinstance(repository, str) and repository.strip():
            return repository
        return None

    @staticmethod
    def _repository_url(npm_data: Dict[str, object]) -> Optional[str]:
        """Return the package's repository root, or None when it publishes none.

        package.json spells ``repository`` as either a string or a
        ``{"type", "url"}`` object, and the URL arrives in every git spelling
        there is (``git+https://``, ``git://``, ``git@host:owner/repo``, with
        or without a ``.git`` suffix). ``canonical_repository_url`` normalizes
        all of them and trims monorepo subpaths back to ``owner/repo``.

        Args:
            npm_data: ``registry.npmjs.org/<package>`` packument.

        Returns:
            An ``https://host/owner/repo`` URL, or None.
        """
        repository = npm_data.get("repository")
        candidates: List[object] = []
        if isinstance(repository, dict):
            candidates.append(repository.get("url"))
        elif isinstance(repository, str):
            candidates.append(repository)
        candidates.append(npm_data.get("homepage"))

        for candidate in candidates:
            if not isinstance(candidate, str) or not candidate:
                continue
            canonical = canonical_repository_url(candidate)
            if canonical:
                return canonical
        return None

    def _get_npm_package_info(self, package_name: str) -> Optional[Dict[str, object]]:
        """Get package information from npm registry.

        Args:
            package_name: Name of the npm package.

        Returns:
            Dictionary with package information, or None if fetching failed.
        """
        url = f"{NPM_REGISTRY_BASE}/{npm_registry_path(package_name)}"
        payload = fetch_json(url, self.timeout)
        return payload if isinstance(payload, dict) else None

    def _get_npm_latest_manifest(
        self, package_name: str
    ) -> Optional[Dict[str, object]]:
        """Get the ``latest``-tagged version manifest from the npm registry.

        Args:
            package_name: Name of the npm package.

        Returns:
            The version manifest, or None if fetching failed.
        """
        url = f"{NPM_REGISTRY_BASE}/{npm_registry_path(package_name)}/latest"
        payload = fetch_json(url, self.timeout)
        return payload if isinstance(payload, dict) else None
