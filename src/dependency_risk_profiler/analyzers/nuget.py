"""Analyzer for .NET (NuGet) dependencies."""

import logging
from typing import Dict, List, Optional

from ..models import DependencyMetadata
from ..parsers.nuget_registry import CatalogEntry, NuGetRegistryClient, NuspecDocument
from ..release_dates import record_source_repository
from ..signals import FieldSource, ProvenancedField
from ..transitive.analyzer_enhanced import record_transitive_source
from ..utils import canonical_repository_url
from .base import BaseAnalyzer
from .common import collect_repository_signals

logger = logging.getLogger(__name__)

# Recorded so the transitive signal is treated as measured rather than as an
# assumed-empty set (#141). The nuspec states the package's own dependencies,
# which is a real measurement, not a default.
TRANSITIVE_SOURCE_NUSPEC = "nuget-nuspec"


class NuGetAnalyzer(BaseAnalyzer):
    """Analyzer for .NET dependencies published on nuget.org.

    nuget.org publishes each package's ``.nuspec`` next to its ``.nupkg``, and
    that file carries the metadata every other ecosystem gets from its registry
    API: the source repository, the license, the declared authors, and the
    package's own dependencies. Reading it is what turns a .NET scan from "here
    are your CVEs" into the leading-indicator signal set the profiler collects
    for npm, PyPI, and crates.io (#129).
    """

    def __init__(
        self,
        timeout: int = 10,
        client: Optional[NuGetRegistryClient] = None,
    ) -> None:
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
            client: Bounded nuget.org client. Defaults to a fresh one; tests
                inject a fake so the suite makes no network calls.
        """
        super().__init__(timeout)
        self.metadata_cache: Dict[str, Dict[str, object]] = {}
        self.client = (
            client if client is not None else NuGetRegistryClient(timeout=timeout)
        )

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
            dep.additional_info["source"] = "nuget.org"

            try:
                latest = self._get_latest_version(name)
                if latest:
                    dep.latest_version = latest

                catalog = self.client.fetch_catalog_entry(name, latest)
                nuspec = self._fetch_nuspec(name, dep, latest)
                self._apply_registry_metadata(name, dep, nuspec, catalog)

                # Eight of the fourteen signals — staleness, health indicators,
                # and the five OpenSSF-style checks — only exist in the source
                # tree, so a package whose repository never resolved scores
                # UNKNOWN no matter how good its registry metadata is (#132).
                dependencies[name] = collect_repository_signals(
                    dep, dep.repository_url, self.clone_repos
                )

                # Declared authors are the last resort for the maintainer count,
                # applied only when the repository pass found nothing: a nuspec
                # <authors> value is free text ("Microsoft"), not a list of
                # accounts with publish rights, so it must not displace a real
                # contributor count.
                if dep.maintainer_count is None and nuspec is not None:
                    if nuspec.authors:
                        dep.maintainer_count = len(nuspec.authors)
                        dep.record_field_source(
                            ProvenancedField.MAINTAINER_COUNT,
                            FieldSource.REGISTRY_METADATA,
                        )
            except Exception as exc:
                logger.error("Error analyzing NuGet package %s: %s", name, exc)

        return dependencies

    def _fetch_nuspec(
        self, name: str, dep: DependencyMetadata, latest: Optional[str]
    ) -> Optional[NuspecDocument]:
        """Read the package's own nuspec, preferring the installed version.

        The installed version is tried first so the metadata describes what the
        project actually uses; the latest version is the fallback for packages
        whose version is managed somewhere this scan could not reach.
        """
        candidates: List[str] = []
        for version in (dep.installed_version, latest):
            if version and version not in candidates:
                candidates.append(version)
        for version in candidates:
            document = self.client.fetch_nuspec(name, version)
            if document is not None:
                return document
        return None

    def _apply_registry_metadata(
        self,
        name: str,
        dep: DependencyMetadata,
        nuspec: Optional[NuspecDocument],
        catalog: Optional[CatalogEntry],
    ) -> None:
        """Copy the nuget.org payloads onto the fields the scorer reads.

        Args:
            name: Package id, used as the metadata cache key.
            dep: Dependency metadata to update in place.
            nuspec: The package's own manifest, or None when unreadable.
            catalog: The registration catalog entry, or None when unreadable.
        """
        repository_url = self._repository_url(nuspec, catalog)
        if repository_url:
            dep.repository_url = repository_url

        # nuget resolved a repository and then reported nothing about whether
        # one was declared, so the signal was dropped from the score entirely
        # and nuget alone measured 15 where the other seven measured 16 (#183).
        # The nuspec's <repository> is the declaration; <projectUrl> is a
        # resolution fallback (MediatR publishes https://mediatr.io/) and does
        # not count as one. Recorded only when nuget.org answered with a
        # document at all: neither is unmeasured, not a negative finding (#182).
        if nuspec is not None or catalog is not None:
            record_source_repository(
                dep,
                repository_url,
                declared=nuspec.repository_url if nuspec is not None else None,
            )

        # The catalog is the only place a publication date exists. A cloned repo
        # refines this to the last commit; without a clone it is the release
        # cadence a consumer of the package actually sees.
        if catalog is not None:
            if catalog.published is not None:
                # Assigned directly rather than through
                # ``apply_registry_release_date``, so unlike every other adapter
                # this date does not claim the registry precedence that would
                # stop repository activity overwriting it. Left as it is here:
                # routing it through the helper would add a
                # ``release_date_source`` key to this adapter's frozen v1
                # ``additional_info`` payload, which is not this change's to
                # make. The provenance record below is accurate either way,
                # because whoever overwrites the date overwrites this too.
                dep.last_updated = catalog.published
                dep.record_field_source(
                    ProvenancedField.LAST_UPDATED, FieldSource.REGISTRY_RELEASE
                )
            if catalog.is_deprecated:
                dep.is_deprecated = True

        # analyze_license() reads a registry-metadata mapping; give it one built
        # from whichever document states an SPDX expression.
        cached: Dict[str, object] = {"name": name}
        license_expression = None
        if nuspec is not None:
            license_expression = nuspec.license_expression
        if not license_expression and catalog is not None:
            license_expression = catalog.license_expression
        if license_expression:
            cached["license"] = license_expression
        if nuspec is not None and nuspec.description:
            cached["description"] = nuspec.description
            dep.additional_info["description"] = nuspec.description
        self.metadata_cache[name] = cached

        # A package's own declared dependencies are a measured transitive
        # signal, not an assumed-empty one (#141).
        if nuspec is not None:
            dep.transitive_dependencies = {
                identifier
                for identifier in nuspec.dependencies
                if identifier.lower() != name.lower()
            }
            record_transitive_source(dep, source=TRANSITIVE_SOURCE_NUSPEC)

    @staticmethod
    def _repository_url(
        nuspec: Optional[NuspecDocument], catalog: Optional[CatalogEntry]
    ) -> Optional[str]:
        """Return the package's repository root, or None when it publishes none.

        ``<repository>`` is the authoritative pointer and is tried first:
        ``projectUrl`` is routinely a documentation site (MediatR publishes
        ``https://mediatr.io/``), which is not cloneable and would silently cost
        the package every repository-derived signal. Each candidate is trimmed
        back to its ``owner/repo`` root, because packages built out of a
        monorepo point at a subdirectory and both ``git clone`` and the GitHub
        API reject that deeper path (#134). A non-repository homepage is
        rejected by the canonicalizer rather than guessed at.
        """
        candidates: List[Optional[str]] = []
        if nuspec is not None:
            candidates.extend([nuspec.repository_url, nuspec.project_url])
        if catalog is not None:
            candidates.append(catalog.project_url)
        for candidate in candidates:
            canonical = canonical_repository_url(candidate)
            if canonical:
                return canonical
        return None

    def _get_latest_version(self, package_id: str) -> Optional[str]:
        """Return the latest stable NuGet version for a package id, or None."""
        versions = self.client.list_versions(package_id)
        # The index lists versions oldest-first; prefer the newest stable one.
        for version in reversed(versions):
            if "-" not in version:
                return version
        # Fall back to the newest version even if it's a pre-release.
        for version in reversed(versions):
            return version
        return None
