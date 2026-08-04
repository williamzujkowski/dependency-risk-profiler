"""Analyzer for PHP (Composer / Packagist) dependencies."""

import logging
from typing import Dict, List, Optional

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

PACKAGIST_METADATA_BASE = "https://repo.packagist.org/p2"
_USER_AGENT = "dependency-risk-profiler (metadata lookup)"


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
                release = self._get_latest_release(name)
                if release is not None:
                    self.metadata_cache[name] = release
                    self._apply_registry_metadata(dep, release)

                # composer.lock already records source.url, so the repository is
                # resolvable even when the Packagist lookup fails; both spellings
                # are trimmed to the repo root before use.
                repository_url = canonical_repository_url(dep.repository_url)
                if repository_url:
                    dep.repository_url = repository_url
                record_source_repository(dep, repository_url)

                # Repository-derived signals (last commit, tests/CI, the
                # OpenSSF-style security checks) come from the source repo, the
                # same way the Python/npm/Go/RubyGems analyzers collect them.
                dep = collect_repository_signals(
                    dep, dep.repository_url, self.clone_repos
                )
                dependencies[name] = dep

                # composer.json's declared authors are the package's own
                # statement of who maintains it — Packagist publishes no cheap
                # per-package maintainer endpoint (its package API inlines every
                # version, megabytes per request). Applied after the repository
                # pass so a shallow clone's contributor count — always ~1 —
                # can't stand in for it, and left alone when the package
                # declares none rather than guessed at (#74).
                author_count = self._author_count(release)
                if author_count is not None:
                    dep.maintainer_count = author_count
            except Exception as exc:
                logger.error("Error analyzing PHP package %s: %s", name, exc)

        return dependencies

    def _apply_registry_metadata(
        self, dep: DependencyMetadata, release: Dict[str, object]
    ) -> None:
        """Copy the Packagist release entry onto the fields the scorer reads.

        Args:
            dep: Dependency metadata to update in place.
            release: Newest Packagist release entry for the package.
        """
        version = release.get("version")
        if isinstance(version, str) and version:
            dep.latest_version = version.lstrip("v")

        repository_url = self._repository_url(release)
        if repository_url:
            dep.repository_url = repository_url

        # Packagist dates the release, not the repository; it is the release
        # cadence a consumer of the package actually sees, and it now wins over
        # a clone's last commit rather than being overwritten by it (#146).
        apply_registry_release_date(dep, parse_registry_timestamp(release.get("time")))

        # Packagist marks a replaced package with `abandoned`: either `true` or
        # the name of the package that supersedes it.
        abandoned = release.get("abandoned")
        if abandoned is True or (isinstance(abandoned, str) and abandoned):
            dep.is_deprecated = True
            if isinstance(abandoned, str):
                dep.additional_info["abandoned_in_favor_of"] = abandoned

    @staticmethod
    def _repository_url(release: Dict[str, object]) -> Optional[str]:
        """Return the package's repository root, or None when it publishes none.

        Packagist records the VCS location under ``source.url`` and commonly
        spells it with a ``.git`` suffix; ``homepage`` is the fallback because
        some packages publish the repository only there.
        """
        source = release.get("source")
        if isinstance(source, dict):
            canonical = canonical_repository_url(_string_or_none(source.get("url")))
            if canonical:
                return canonical
        return canonical_repository_url(_string_or_none(release.get("homepage")))

    @staticmethod
    def _author_count(release: Optional[Dict[str, object]]) -> Optional[int]:
        """Return the package's declared author count, or None when it declares none."""
        if release is None:
            return None
        authors = release.get("authors")
        if not isinstance(authors, list):
            return None
        named = [author for author in authors if isinstance(author, dict)]
        return len(named) if named else None

    def _get_latest_release(self, package_name: str) -> Optional[Dict[str, object]]:
        """Return the newest Packagist release entry for a package, or None.

        Args:
            package_name: Fully qualified ``vendor/package`` name.

        Returns:
            The newest release entry, or None when Packagist has no metadata.
        """
        url = f"{PACKAGIST_METADATA_BASE}/{package_name}.json"
        headers = {"User-Agent": _USER_AGENT}
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
        # The p2 metadata lists releases newest-first, and only the first entry
        # is complete: later ones carry just the fields that changed from their
        # predecessor. Reading anything but the head would yield a half-filled
        # entry, so the newest release is the only one used.
        return self._first_stable_release(versions)

    @staticmethod
    def _first_stable_release(versions: List[object]) -> Optional[Dict[str, object]]:
        """Return the first non-dev release entry from a Packagist version list."""
        for entry in versions:
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and version and not version.startswith("dev-"):
                return {
                    key: value for key, value in entry.items() if isinstance(key, str)
                }
        return None


def _string_or_none(value: object) -> Optional[str]:
    """Return the value when it is a non-empty string, else None."""
    if isinstance(value, str) and value:
        return value
    return None
