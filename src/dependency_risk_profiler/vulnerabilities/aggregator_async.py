"""Collect and normalize vulnerability information asynchronously.

This module provides asynchronous implementations of the vulnerability aggregation
functions to improve performance when processing multiple dependencies.

The async sources answer with a :class:`~.aggregator.SourceLookup` for the same
reason the synchronous ones do: an empty list cannot say whether the source
found nothing or never answered, and the aggregate was cached either way
(#219). ``AsyncHTTPClient`` already returns ``None`` for a request that failed
and a mapping for one that succeeded, so the distinction was there to be read —
``if not response_data`` threw it away, and threw an empty JSON object in with
it for good measure.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from ..async_http import AsyncHTTPClient
from ..models import DependencyMetadata
from ..signals import AdvisoryLookupState
from .aggregator import (
    DEFAULT_MINIMUM_SEVERITY_FOR_SCORING,
    GitHubAdvisorySource,
    NVDSource,
    OSVSource,
    SourceLookup,
    VulnerabilitySource,
    _update_dependency_with_vulnerabilities,
    cache_data,
    combine_source_lookups,
    get_cached_data,
    infer_ecosystem,
)

logger = logging.getLogger(__name__)

#: What to name as unavailable when the failure is upstream of the individual
#: sources — the per-package coroutine raised, or the event loop never got far
#: enough to ask anybody. Nothing answered, and no source is more to blame than
#: any other.
ALL_ADVISORY_SOURCES: Tuple[str, ...] = ("all advisory sources",)


class AsyncOSVSource(OSVSource):
    """Asynchronous Open Source Vulnerabilities (OSV) vulnerability data source."""

    def __init__(self, enabled: bool = True):
        """Initialize the async OSV vulnerability source."""
        super().__init__(enabled=enabled)
        self.http_client = AsyncHTTPClient()

    async def lookup_async(self, package_name: str, ecosystem: str) -> SourceLookup:
        """Ask OSV about a package asynchronously.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            OSV's answer, or the reason there isn't one.
        """
        if not self.enabled:
            return SourceLookup.abstained("OSV source is disabled")

        # Normalize ecosystem names to OSV format
        osv_ecosystem = self._normalize_ecosystem(ecosystem)

        # Prepare the query
        query_url = f"{self.base_url}/query"
        query_data = {"package": {"name": package_name, "ecosystem": osv_ecosystem}}

        # Prepare headers
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "dependency-risk-profiler/0.2.0",
        }

        # Make the request. ``is None`` is the failure test; ``{}`` is a reply.
        response_data = await self.http_client.post(query_url, query_data, headers)
        if response_data is None:
            return SourceLookup.failed("no readable response")

        # Extract vulnerability data
        vulns = response_data.get("vulns", [])
        return SourceLookup.answered(
            self._normalize_results(vulns, package_name, osv_ecosystem)
        )

    async def get_vulnerabilities_async(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from OSV, discarding why there are none.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            List of vulnerability dictionaries, empty if OSV found none *or*
            did not answer. Prefer :meth:`lookup_async`, which says which.
        """
        lookup = await self.lookup_async(package_name, ecosystem)
        return list(lookup.vulnerabilities)


class AsyncNVDSource(NVDSource):
    """Asynchronous National Vulnerability Database (NVD) vulnerability data source."""

    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        """Initialize the async NVD vulnerability source."""
        super().__init__(api_key=api_key, enabled=enabled)
        self.http_client = AsyncHTTPClient()

    async def lookup_async(self, package_name: str, ecosystem: str) -> SourceLookup:
        """Ask NVD about a package asynchronously.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            NVD's answer, or the reason there isn't one.
        """
        if not self.enabled:
            return SourceLookup.abstained("NVD source is disabled")

        # Map ecosystem to CPE prefix
        cpe_prefix = self._get_cpe_prefix(ecosystem)
        if not cpe_prefix:
            # No CPE naming for this ecosystem, so there is nothing to search
            # on. An abstention rather than a failure.
            return SourceLookup.abstained(f"no CPE prefix for ecosystem {ecosystem!r}")

        # Search by keyword first
        params = {"keywordSearch": f"{cpe_prefix}{package_name}", "resultsPerPage": 100}

        if self.api_key:
            params["apiKey"] = self.api_key

        # Make the request
        response_data = await self.http_client.get(self.base_url, params)
        if response_data is None:
            return SourceLookup.failed("no readable response")

        # Extract vulnerability data
        vulns = response_data.get("vulnerabilities", [])
        normalized = self._normalize_results(vulns)

        # Add a small delay to avoid rate limiting
        await asyncio.sleep(0.1)

        return SourceLookup.answered(normalized)

    async def get_vulnerabilities_async(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from NVD, discarding why there are none.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            List of vulnerability dictionaries, empty if NVD found none *or*
            did not answer. Prefer :meth:`lookup_async`, which says which.
        """
        lookup = await self.lookup_async(package_name, ecosystem)
        return list(lookup.vulnerabilities)


class AsyncGitHubAdvisorySource(GitHubAdvisorySource):
    """Asynchronous GitHub Advisory Database vulnerability data source."""

    def __init__(self, api_token: Optional[str] = None, enabled: bool = True):
        """Initialize the async GitHub Advisory vulnerability source."""
        super().__init__(api_token=api_token, enabled=enabled)
        self.http_client = AsyncHTTPClient()

    async def lookup_async(self, package_name: str, ecosystem: str) -> SourceLookup:
        """Ask the GitHub Advisory Database about a package asynchronously.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            GitHub's answer, or the reason there isn't one.
        """
        if not self.enabled:
            return SourceLookup.abstained("GitHub Advisory source is disabled")

        # GraphQL requires auth, so skip if no token
        if not self.api_token:
            logger.debug("Skipping GitHub Advisory search: No API token provided")
            return SourceLookup.abstained("no GitHub API token")

        # Normalize ecosystem name
        gh_ecosystem = self._normalize_ecosystem(ecosystem)
        if not gh_ecosystem:
            return SourceLookup.abstained(
                f"ecosystem {ecosystem!r} is not a GitHub advisory ecosystem"
            )

        # GraphQL query
        query = """
        query ($package: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
          securityVulnerabilities(
            first: 100,
            ecosystem: $ecosystem,
            package: $package
          ) {
            nodes {
              severity
              updatedAt
              vulnerableVersionRange
              advisory {
                id
                summary
                description
                publishedAt
                withdrawnAt
                references {
                  url
                }
                cvss {
                  score
                  vectorString
                }
              }
              firstPatchedVersion {
                identifier
              }
            }
          }
        }
        """

        variables = {"package": package_name, "ecosystem": gh_ecosystem}

        # Prepare headers and data
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Make the request
        response_data = await self.http_client.post(
            self.base_url, {"query": query, "variables": variables}, headers
        )

        if response_data is None:
            return SourceLookup.failed("no readable response")

        if "errors" in response_data:
            error_message = str(response_data.get("errors", []))
            logger.debug(f"GraphQL errors: {error_message}")
            return SourceLookup.failed("GraphQL error response")

        # Extract vulnerability data
        vulnerabilities = (
            response_data.get("data", {})
            .get("securityVulnerabilities", {})
            .get("nodes", [])
        )
        return SourceLookup.answered(self._normalize_results(vulnerabilities))

    async def get_vulnerabilities_async(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get GitHub advisories, discarding why there are none.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            List of vulnerability dictionaries, empty if GitHub found none *or*
            did not answer. Prefer :meth:`lookup_async`, which says which.
        """
        lookup = await self.lookup_async(package_name, ecosystem)
        return list(lookup.vulnerabilities)


async def aggregate_vulnerabilities_for_package_async(
    dependency: DependencyMetadata,
    api_keys: Optional[Dict[str, str]] = None,
    enable_osv: bool = True,
    enable_nvd: bool = False,
    enable_github: bool = False,
    minimum_severity: str = DEFAULT_MINIMUM_SEVERITY_FOR_SCORING,
) -> Tuple[DependencyMetadata, List[Dict[str, Any]]]:
    """Aggregate vulnerability data for a single package asynchronously.

    Args:
        dependency: Dependency metadata
        api_keys: API keys for vulnerability sources
        enable_osv: Whether to enable OSV vulnerability source
        enable_nvd: Whether to enable NVD vulnerability source
        enable_github: Whether to enable GitHub Advisory vulnerability source
        minimum_severity: Minimum severity that counts toward scoring

    Returns:
        Tuple of (updated dependency metadata, vulnerability details)
    """
    package_name = dependency.name
    ecosystem = infer_ecosystem(dependency)
    if not ecosystem:
        # Fail closed (#109): querying every source under a guessed ecosystem
        # returns an authoritative-looking empty result for the wrong package.
        logger.warning(
            f"Skipping vulnerability lookup for {package_name}: "
            "ecosystem could not be determined"
        )
        dependency.record_advisory_lookup(
            AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=()
        )
        return dependency, []

    # Check cache first. Only a COMPLETE lookup is ever written (#219), so a
    # cache hit is a complete measurement by construction.
    cached = get_cached_data(package_name, ecosystem)
    if cached:
        vulnerabilities, _ = cached
        return (
            _update_dependency_with_vulnerabilities(
                dependency,
                vulnerabilities,
                minimum_severity,
                lookup_state=AdvisoryLookupState.COMPLETE,
            ),
            vulnerabilities,
        )

    # Set up API keys
    api_keys = api_keys or {}
    github_token = api_keys.get("github", None)
    nvd_api_key = api_keys.get("nvd", None)

    # Initialize vulnerability sources
    sources: List[Union[AsyncOSVSource, AsyncNVDSource, AsyncGitHubAdvisorySource]] = []
    if enable_osv:
        sources.append(AsyncOSVSource(enabled=True))
    if enable_github and github_token:
        sources.append(AsyncGitHubAdvisorySource(api_token=github_token, enabled=True))
    if enable_nvd:
        sources.append(AsyncNVDSource(api_key=nvd_api_key, enabled=True))

    # Collect vulnerabilities from all sources concurrently. ``gather`` keeps
    # the results in task order, which is what lets a raised exception be
    # attributed back to the source that raised it — the old loop discarded
    # that and every failure became an anonymous nothing (#219).
    queried: List[VulnerabilitySource] = []
    tasks = []

    for source in sources:
        if source.enabled:
            logger.info(f"Checking {source.name} for vulnerabilities in {package_name}")
            queried.append(source)
            tasks.append(source.lookup_async(package_name, ecosystem))

    try:
        lookups: List[Tuple[VulnerabilitySource, SourceLookup]] = []
        if tasks:
            results: List[Union[SourceLookup, BaseException]] = await asyncio.gather(
                *tasks, return_exceptions=True
            )

            for queried_source, result in zip(queried, results):
                if isinstance(result, SourceLookup):
                    lookups.append((queried_source, result))
                elif isinstance(result, BaseException):
                    logger.error(
                        "Error fetching vulnerabilities from "
                        f"{queried_source.name}: {result}"
                    )
                    lookups.append(
                        (
                            queried_source,
                            SourceLookup.failed(f"raised {type(result).__name__}"),
                        )
                    )
                else:
                    logger.error(f"Unexpected result type: {type(result)}")
                    lookups.append(
                        (queried_source, SourceLookup.failed("unexpected result type"))
                    )

        outcome = combine_source_lookups(lookups)

        # Cache only a complete answer (#219).
        if outcome.cacheable:
            cache_data(package_name, ecosystem, outcome.vulnerabilities)
        else:
            logger.info(
                f"Not caching advisory data for {package_name} ({ecosystem}): "
                f"lookup was {outcome.state.value}"
            )

        # Update dependency metadata
        updated_dependency = _update_dependency_with_vulnerabilities(
            dependency,
            outcome.vulnerabilities,
            minimum_severity,
            lookup_state=outcome.state,
            sources_unavailable=outcome.sources_unavailable,
        )

        return updated_dependency, outcome.vulnerabilities
    finally:
        # Properly close all HTTP client sessions
        for source in sources:
            try:
                await source.http_client.close()
            except Exception as e:
                logger.debug(f"Error closing HTTP client session: {e}")


async def aggregate_vulnerability_data_async_impl(
    dependencies: Dict[str, DependencyMetadata],
    api_keys: Optional[Dict[str, str]] = None,
    enable_osv: bool = True,
    enable_nvd: bool = False,
    enable_github: bool = False,
    batch_size: int = 10,
    minimum_severity: str = DEFAULT_MINIMUM_SEVERITY_FOR_SCORING,
) -> Tuple[Dict[str, DependencyMetadata], Dict[str, int]]:
    """Aggregate vulnerability data for multiple dependencies asynchronously.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata
        api_keys: API keys for vulnerability sources
        enable_osv: Whether to enable OSV vulnerability source
        enable_nvd: Whether to enable NVD vulnerability source
        enable_github: Whether to enable GitHub Advisory vulnerability source
        batch_size: Number of dependencies to process in parallel
        minimum_severity: Minimum severity that counts toward scoring

    Returns:
        Tuple of (updated dependencies, vulnerability counts)
    """
    logger.info(
        "Aggregating vulnerability data for "
        f"{len(dependencies)} dependencies asynchronously"
    )

    # Process dependencies in batches
    dependency_names = list(dependencies.keys())
    updated_deps = {}
    vuln_counts = {}

    for i in range(0, len(dependency_names), batch_size):
        batch = dependency_names[i : i + batch_size]
        logger.debug(f"Processing batch of {len(batch)} dependencies")

        # Create tasks for the batch
        tasks = [
            aggregate_vulnerabilities_for_package_async(
                dependencies[name],
                api_keys,
                enable_osv,
                enable_nvd,
                enable_github,
                minimum_severity,
            )
            for name in batch
        ]

        # Execute tasks concurrently
        results_raw = await asyncio.gather(*tasks, return_exceptions=True)
        # Type check for mypy
        results: List[
            Union[Tuple[DependencyMetadata, List[Dict[str, Any]]], BaseException]
        ] = results_raw

        # Process results
        for j, name in enumerate(batch):
            result = results[j]
            if isinstance(result, BaseException):
                logger.error(f"Error aggregating vulnerabilities for {name}: {result}")
                # The whole per-package lookup blew up, so nothing was
                # established about this package. Recording that is the
                # difference between a scan that reports a gap and one that
                # reports a clean tree (#219).
                dependencies[name].record_advisory_lookup(
                    AdvisoryLookupState.FAILED,
                    sources_unavailable=ALL_ADVISORY_SOURCES,
                )
                updated_deps[name] = dependencies[name]
            else:
                # We know this is a tuple if it's not an exception
                dep, vulns = result
                updated_deps[name] = dep
                vuln_counts[name] = len(vulns)
                logger.debug(f"Found {len(vulns)} vulnerabilities for {name}")

    return updated_deps, vuln_counts


def aggregate_vulnerability_data_async(
    dependencies: Dict[str, DependencyMetadata],
    api_keys: Optional[Dict[str, str]] = None,
    enable_osv: bool = True,
    enable_nvd: bool = False,
    enable_github: bool = False,
    batch_size: int = 10,
    minimum_severity: str = DEFAULT_MINIMUM_SEVERITY_FOR_SCORING,
) -> Tuple[Dict[str, DependencyMetadata], Dict[str, int]]:
    """Aggregate vulnerability data for multiple dependencies asynchronously.

    This function is a synchronous wrapper around the asynchronous implementation.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata
        api_keys: API keys for vulnerability sources
        enable_osv: Whether to enable OSV vulnerability source
        enable_nvd: Whether to enable NVD vulnerability source
        enable_github: Whether to enable GitHub Advisory vulnerability source
        batch_size: Number of dependencies to process in parallel
        minimum_severity: Minimum severity that counts toward scoring

    Returns:
        Tuple of (updated dependencies, vulnerability counts)
    """
    try:
        # Create and run event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            return loop.run_until_complete(
                aggregate_vulnerability_data_async_impl(
                    dependencies,
                    api_keys,
                    enable_osv,
                    enable_nvd,
                    enable_github,
                    batch_size,
                    minimum_severity,
                )
            )
        finally:
            loop.close()
    except Exception as e:
        logger.error(
            f"Error in asynchronous vulnerability aggregation: {e}", exc_info=True
        )
        # Nothing was measured for anything. Returning the dependencies
        # untouched used to leave every one of them presenting as advisory-
        # clean, which is the failure mode #219 is about, at the scale of the
        # whole scan.
        for dependency in dependencies.values():
            dependency.record_advisory_lookup(
                AdvisoryLookupState.FAILED, sources_unavailable=ALL_ADVISORY_SOURCES
            )
        return dependencies, {}
