"""Analyzer for Node.js dependencies."""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import quote

from ..models import DependencyMetadata
from ..parsers.nodejs import runtime_dependency_names
from ..release_dates import (
    RepositoryResolution,
    apply_registry_release_date,
    newest_timestamp,
    parse_registry_timestamp,
    record_source_repository,
    resolve_repository,
)
from ..transitive.analyzer_enhanced import record_transitive_source
from ..utils import fetch_json
from .base import BaseAnalyzer
from .common import collect_repository_signals

logger = logging.getLogger(__name__)

NPM_REGISTRY_BASE = "https://registry.npmjs.org"

# Recorded so the transitive signal is treated as measured rather than as an
# assumed-empty set (#141, #204). The latest version's own manifest states what
# installing the package pulls in — the same fact nuget reads out of its
# ``.nuspec`` and composer out of the p2 ``require`` block — and it comes out of
# the packument this adapter already fetches, at no extra request.
TRANSITIVE_SOURCE_NPM_MANIFEST = "npm-version-manifest"

# The description npm's security team publishes on the placeholder that
# replaces a package it has removed. See ``_is_security_placeholder``.
_SECURITY_HOLDING_DESCRIPTION = "security holding package"


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

        # A package npm has removed for malware is not deleted; the registry
        # republishes it as a placeholder owned by npm's security team, and
        # ``dist-tags.latest`` then points at that placeholder. See
        # ``_is_security_placeholder`` for why the version it publishes is a
        # sentinel rather than a release (#217).
        security_holding = self._is_security_placeholder(npm_data, latest)
        if security_holding:
            logger.warning(
                "npm replaced %s with a security holding package at %s; "
                "the package was removed from the registry, so version drift "
                "stays unmeasured and the dependency is marked deprecated",
                dep.name,
                latest,
            )
            dep.is_deprecated = True
            dep.additional_info["npm_security_holding_package"] = "true"
            # Nothing downstream may read the placeholder as a release: not the
            # latest version, not its (empty) dependency list, not the manifest
            # it publishes. Dropping it here is what keeps every one of those
            # reads unmeasured rather than confidently wrong.
            latest = None
        elif self._is_deprecated(npm_data, latest):
            dep.is_deprecated = True

        if latest:
            dep.latest_version = latest
        elif not security_holding:
            # #74: an unresolvable latest version leaves the drift signal
            # honestly unmeasured. Say so, rather than failing in silence the
            # way this did for every npm dependency before #140.
            logger.warning(
                "npm registry published no latest version for %s "
                "(no dist-tags.latest and no /latest document); "
                "version drift stays unmeasured",
                dep.name,
            )

        # The latest release's own manifest names its runtime dependencies. The
        # read is deliberately gated on the manifest existing rather than on the
        # key: an absent 'dependencies' key means the author declared none and
        # is a measured zero, while an absent *manifest* means nobody read a
        # list at all and must stay unmeasured (#199). devDependencies,
        # peerDependencies and optionalDependencies are not what installing the
        # package pulls in and are not read.
        shipped = runtime_dependency_names(self._version_manifest(npm_data, latest))
        if shipped is not None:
            dep.transitive_dependencies = shipped - {dep.name}
            record_transitive_source(dep, source=TRANSITIVE_SOURCE_NPM_MANIFEST)

        resolution = self._resolve_repository(npm_data)
        if resolution.url:
            dep.repository_url = resolution.url
        record_source_repository(dep, resolution)

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
    def _version_manifest(
        npm_data: Dict[str, object], latest_version: Optional[str]
    ) -> Optional[Dict[str, object]]:
        """Return the packument's manifest for a version, or None.

        The packument's ``versions`` map holds the published package.json of
        every release, and it is where both the deprecation notice and the
        dependency list live. Neither is at the top level and neither ever has
        been (#142), so this is the single seam both reads go through.

        None means the manifest is not in this packument — a mirror that
        answered without it, or a ``latest`` resolved from the ``/latest``
        document instead of from ``dist-tags``. Callers must treat that as
        "nothing was read", not as "read, and it was empty".

        Args:
            npm_data: ``registry.npmjs.org/<package>`` packument.
            latest_version: Latest version, when one resolved.

        Returns:
            The version manifest, or None when the packument has no such entry.
        """
        if not latest_version:
            return None
        versions = npm_data.get("versions")
        if not isinstance(versions, dict):
            return None
        manifest = versions.get(latest_version)
        return manifest if isinstance(manifest, dict) else None

    @classmethod
    def _is_deprecated(
        cls, npm_data: Dict[str, object], latest_version: Optional[str]
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
        manifest = cls._version_manifest(npm_data, latest_version)
        if manifest is None:
            return False
        return bool(manifest.get("deprecated"))

    @classmethod
    def _is_security_placeholder(
        cls, npm_data: Dict[str, object], latest_version: Optional[str]
    ) -> bool:
        """Return whether ``latest`` is npm's security holding package.

        When npm's security team removes a package for malware or typosquatting
        they do not delete the name — they republish it as a placeholder with
        the description ``security holding package`` at a version carrying a
        ``-security`` prerelease tag, and repoint ``dist-tags.latest`` at it.

        That version is cargo's ``"0.0.0"`` in npm's dialect: a parseable
        semver of exactly the right type that is not a release of the package
        at all. Read as the latest version it inverts the finding — crossenv,
        pulled for stealing environment variables, publishes ``0.0.2-security``
        against which an installed ``6.1.1`` reads as *ahead* of the registry,
        so a package npm removed for malware scores as current and undrifted.
        The placeholder carries no ``deprecated`` notice either, so nothing
        else in the payload flags it (#217).

        Both markers are required. The description alone would catch a package
        that merely mentions the phrase; the ``-security`` suffix alone would
        catch a legitimate security-fix prerelease.

        Args:
            npm_data: ``registry.npmjs.org/<package>`` packument.
            latest_version: Latest version, when one resolved.

        Returns:
            True when the latest version is a security holding placeholder.
        """
        if not latest_version or not latest_version.endswith("-security"):
            return False
        manifest = cls._version_manifest(npm_data, latest_version)
        if manifest is None:
            return False
        description = manifest.get("description")
        if not isinstance(description, str):
            return False
        return description.strip().lower() == _SECURITY_HOLDING_DESCRIPTION

    @staticmethod
    def _resolve_repository(npm_data: Dict[str, object]) -> RepositoryResolution:
        """Return npm's one answer about where this package's source lives.

        ``repository`` is npm's designated source pointer and is the
        declaration. package.json spells it as either a string or a
        ``{"type", "url"}`` object, and the URL arrives in every git spelling
        there is (``git+https://``, ``git://``, ``git@host:owner/repo``, with
        or without a ``.git`` suffix); ``canonical_repository_url`` normalizes
        all of them and trims monorepo subpaths back to ``owner/repo``.

        ``homepage`` is the resolution fallback: some packages publish the
        repository only there, and a docs site under that label is still not a
        declaration of source (#176).

        Args:
            npm_data: ``registry.npmjs.org/<package>`` packument.

        Returns:
            The resolution the packument supports.
        """
        repository = npm_data.get("repository")
        if isinstance(repository, dict):
            declared = _string_or_none(repository.get("url"))
        else:
            declared = _string_or_none(repository)
        return resolve_repository(
            declarations=[declared],
            fallbacks=[_string_or_none(npm_data.get("homepage"))],
        )

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


def _string_or_none(value: object) -> Optional[str]:
    """Return a non-empty string value, or None for anything else.

    Args:
        value: Raw value from an npm packument, of any type.

    Returns:
        The original string when it has content, else None.
    """
    if isinstance(value, str) and value.strip():
        return value
    return None
