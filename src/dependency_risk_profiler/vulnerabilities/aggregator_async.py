"""
Asynchronous vulnerability data aggregator that collects and normalizes vulnerability
information from multiple sources.

This module provides asynchronous implementations of the vulnerability aggregation
functions to improve performance when processing multiple dependencies.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from ..async_http import AsyncHTTPClient, batch_client
from ..models import DependencyMetadata
from .aggregator import (
    GitHubAdvisorySource,
    NVDSource,
    OSVSource,
    _update_dependency_with_vulnerabilities,
    cache_data,
    get_cached_data,
)

logger = logging.getLogger(__name__)


class AsyncOSVSource(OSVSource):
    """Asynchronous Open Source Vulnerabilities (OSV) vulnerability data source."""

    def __init__(self, enabled: bool = True):
        """Initialize the async OSV vulnerability source."""
        super().__init__(enabled=enabled)
        self.http_client = AsyncHTTPClient()

    async def get_vulnerabilities_async(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from OSV for a package asynchronously.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            List of vulnerability dictionaries
        """
        if not self.enabled:
            return []

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

        # Make the request
        response_data = await self.http_client.post(query_url, query_data, headers)
        if not response_data:
            return []

        # Extract vulnerability data
        vulns = response_data.get("vulns", [])
        return self._normalize_results(vulns)


class AsyncNVDSource(NVDSource):
    """Asynchronous National Vulnerability Database (NVD) vulnerability data source."""

    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        """Initialize the async NVD vulnerability source."""
        super().__init__(api_key=api_key, enabled=enabled)
        self.http_client = AsyncHTTPClient()

    async def get_vulnerabilities_async(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from NVD for a package asynchronously.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            List of vulnerability dictionaries
        """
        if not self.enabled:
            return []

        # Map ecosystem to CPE prefix
        cpe_prefix = self._get_cpe_prefix(ecosystem)
        if not cpe_prefix:
            # Skip search for unrecognized ecosystems
            return []

        # Search by keyword first
        params = {"keywordSearch": f"{cpe_prefix}{package_name}", "resultsPerPage": 100}

        if self.api_key:
            params["apiKey"] = self.api_key

        # Make the request
        response_data = await self.http_client.get(self.base_url, params)
        if not response_data:
            return []

        # Extract vulnerability data
        vulns = response_data.get("vulnerabilities", [])
        normalized = self._normalize_results(vulns)

        # Add a small delay to avoid rate limiting
        await asyncio.sleep(0.1)

        return normalized


class AsyncGitHubAdvisorySource(GitHubAdvisorySource):
    """Asynchronous GitHub Advisory Database vulnerability data source."""

    def __init__(self, api_token: Optional[str] = None, enabled: bool = True):
        """Initialize the async GitHub Advisory vulnerability source."""
        super().__init__(api_token=api_token, enabled=enabled)
        self.http_client = AsyncHTTPClient()

    async def get_vulnerabilities_async(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from GitHub Advisory for a package asynchronously.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            List of vulnerability dictionaries
        """
        if not self.enabled:
            return []

        # GraphQL requires auth, so skip if no token
        if not self.api_token:
            logger.debug("Skipping GitHub Advisory search: No API token provided")
            return []

        # Normalize ecosystem name
        gh_ecosystem = self._normalize_ecosystem(ecosystem)
        if not gh_ecosystem:
            return []

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

        if not response_data:
            return []

        if "errors" in response_data:
            error_message = str(response_data.get("errors", []))
            logger.debug(f"GraphQL errors: {error_message}")
            return []

        # Extract vulnerability data
        vulnerabilities = (
            response_data.get("data", {})
            .get("securityVulnerabilities", {})
            .get("nodes", [])
        )
        return self._normalize_results(vulnerabilities)


async def aggregate_vulnerabilities_for_package_async(
    dependency: DependencyMetadata,
    api_keys: Optional[Dict[str, str]] = None,
    enable_osv: bool = True,
    enable_nvd: bool = False,
    enable_github: bool = False,
) -> Tuple[DependencyMetadata, List[Dict[str, Any]]]:
    """Aggregate vulnerability data for a single package asynchronously.

    Args:
        dependency: Dependency metadata
        api_keys: API keys for vulnerability sources
        enable_osv: Whether to enable OSV vulnerability source
        enable_nvd: Whether to enable NVD vulnerability source
        enable_github: Whether to enable GitHub Advisory vulnerability source

    Returns:
        Tuple of (updated dependency metadata, vulnerability details)
    """
    package_name = dependency.name
    ecosystem = "python"  # Default to Python

    # Determine ecosystem based on repository URL or other indicators
    if dependency.repository_url:
        if "npm" in dependency.repository_url or "node" in dependency.repository_url:
            ecosystem = "nodejs"
        elif "go" in dependency.repository_url:
            ecosystem = "golang"

    # Check cache first
    cached = get_cached_data(package_name, ecosystem)
    if cached:
        vulnerabilities, _ = cached
        return (
            _update_dependency_with_vulnerabilities(dependency, vulnerabilities),
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

    # Collect vulnerabilities from all sources concurrently
    all_vulnerabilities = []
    tasks = []

    for source in sources:
        if source.enabled:
            try:
                logger.info(
                    f"Checking {source.name} for vulnerabilities in {package_name}"
                )
                tasks.append(source.get_vulnerabilities_async(package_name, ecosystem))
            except Exception as e:
                logger.error(f"Error creating task for {source.name}: {e}")

    try:
        if tasks:
            results_raw = await asyncio.gather(*tasks, return_exceptions=True)
            # Type check for mypy - ensure we handle all possible result types
            results: List[Union[List[Dict[str, Any]], BaseException]] = results_raw

            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Error fetching vulnerabilities: {result}")
                elif isinstance(result, list):
                    all_vulnerabilities.extend(result)
                else:
                    logger.error(f"Unexpected result type: {type(result)}")

        # Deduplicate vulnerabilities based on ID
        seen_ids = set()
        unique_vulnerabilities = []

        for vuln in all_vulnerabilities:
            vuln_id = vuln.get("id", "")
            if vuln_id and vuln_id not in seen_ids:
                seen_ids.add(vuln_id)
                unique_vulnerabilities.append(vuln)

        # Cache the results
        cache_data(package_name, ecosystem, unique_vulnerabilities)

        # Update dependency metadata
        updated_dependency = _update_dependency_with_vulnerabilities(
            dependency, unique_vulnerabilities
        )

        return updated_dependency, unique_vulnerabilities
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
) -> Tuple[Dict[str, DependencyMetadata], Dict[str, int]]:
    """Aggregate vulnerability data for multiple dependencies asynchronously.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata
        api_keys: API keys for vulnerability sources
        enable_osv: Whether to enable OSV vulnerability source
        enable_nvd: Whether to enable NVD vulnerability source
        enable_github: Whether to enable GitHub Advisory vulnerability source
        batch_size: Number of dependencies to process in parallel

    Returns:
        Tuple of (updated dependencies, vulnerability counts)
    """
    logger.info(
        f"Aggregating vulnerability data for {len(dependencies)} dependencies asynchronously"
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
                dependencies[name], api_keys, enable_osv, enable_nvd, enable_github
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
                )
            )
        finally:
            # Clean up resources
            loop.run_until_complete(batch_client.close())
            loop.close()
    except Exception as e:
        logger.error(
            f"Error in asynchronous vulnerability aggregation: {e}", exc_info=True
        )
        # Return dependencies unchanged in case of error
        return dependencies, {}
