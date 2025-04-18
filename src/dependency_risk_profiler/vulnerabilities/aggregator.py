"""
Vulnerability data aggregator module that collects and normalizes vulnerability
information from multiple sources.

This module aggregates vulnerability data from OSV, NVD, and GitHub Advisory Database,
and caches the results to disk to reduce the number of API calls.
"""

import logging
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

from ..models import DependencyMetadata
from .cache import default_cache as disk_cache

logger = logging.getLogger(__name__)

# Cache settings
CACHE_EXPIRY = 24 * 60 * 60  # 24 hours in seconds
VULNERABILITY_CACHE = {}  # In-memory cache (for backward compatibility)

# Get cache settings from environment variables
disable_values = ("1", "true", "yes", "disable")
env_value = os.environ.get("DEPENDENCY_RISK_DISABLE_CACHE", "0").lower()
USE_DISK_CACHE = env_value not in disable_values
DISK_CACHE_EXPIRY = int(
    os.environ.get("DEPENDENCY_RISK_CACHE_EXPIRY", str(CACHE_EXPIRY))
)


class VulnerabilitySource:
    """Base class for vulnerability data sources."""

    def __init__(
        self, name: str, base_url: str, enabled: bool = True, timeout: int = 10
    ):
        """Initialize a vulnerability source.

        Args:
            name: Name of the vulnerability source
            base_url: Base URL for API requests
            enabled: Whether this source is enabled
            timeout: Request timeout in seconds
        """
        self.name = name
        self.base_url = base_url
        self.enabled = enabled
        self.timeout = timeout

    def get_vulnerabilities(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a package.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            List of vulnerability dictionaries
        """
        raise NotImplementedError("Subclasses must implement get_vulnerabilities")

    def _normalize_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize vulnerability data to a standard format.

        Args:
            results: Raw vulnerability data from the source

        Returns:
            List of normalized vulnerability dictionaries
        """
        raise NotImplementedError("Subclasses must implement _normalize_results")

    def _make_request(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ) -> Optional[Dict[str, Any]]:
        """Make an HTTP request to the vulnerability API with exponential backoff retry.

        Args:
            url: URL to request
            params: Query parameters
            max_retries: Maximum number of retry attempts (default: 3)
            backoff_factor: Backoff factor for retries (default: 0.5)
                The sleep time between retries is: {backoff_factor} * (2 ^ (retry_number - 1))

        Returns:
            JSON response data or None if the request failed
        """
        headers = {
            "User-Agent": "dependency-risk-profiler/0.2.0",
            "Accept": "application/json",
        }

        for retry in range(max_retries + 1):
            try:
                if retry > 0:
                    # Calculate delay with exponential backoff
                    delay = backoff_factor * (2 ** (retry - 1))
                    logger.debug(
                        f"Retry {retry}/{max_retries} for {url} after {delay:.2f}s delay"
                    )
                    time.sleep(delay)

                response = requests.get(
                    url, params=params, headers=headers, timeout=self.timeout
                )
                response.raise_for_status()
                return response.json()

            except requests.HTTPError as e:
                # Don't retry on 4xx client errors (except 429 Too Many Requests)
                is_client_error = (
                    e.response.status_code >= 400 and e.response.status_code < 500
                )
                is_rate_limited = e.response.status_code == 429
                if is_client_error and not is_rate_limited:
                    logger.debug(
                        f"Client error ({e.response.status_code}) fetching data from {url}: {e}"
                    )
                    return None

                if retry == max_retries:
                    logger.debug(f"Max retries reached for {url}: {e}")
                    return None

                logger.debug(
                    (
                        f"HTTP error fetching data from {url} "
                        f"(attempt {retry+1}/{max_retries+1}): {e}"
                    )
                )

            except (requests.ConnectionError, requests.Timeout) as e:
                if retry == max_retries:
                    logger.debug(f"Max retries reached for {url}: {e}")
                    return None

                logger.debug(
                    (
                        f"Connection error fetching data from {url} "
                        f"(attempt {retry+1}/{max_retries+1}): {e}"
                    )
                )

            except Exception as e:
                logger.debug(f"Unexpected error fetching data from {url}: {e}")
                return None

        return None


class OSVSource(VulnerabilitySource):
    """Open Source Vulnerabilities (OSV) vulnerability data source."""

    def __init__(self, enabled: bool = True):
        """Initialize the OSV vulnerability source."""
        super().__init__(name="OSV", base_url="https://api.osv.dev/v1", enabled=enabled)

    def get_vulnerabilities(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from OSV for a package.

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

        # Use retry mechanism for POST requests
        max_retries = 3
        backoff_factor = 0.5

        for retry in range(max_retries + 1):
            try:
                if retry > 0:
                    # Calculate delay with exponential backoff
                    delay = backoff_factor * (2 ** (retry - 1))
                    logger.debug(
                        f"Retry {retry}/{max_retries} for OSV query after {delay:.2f}s delay"
                    )
                    time.sleep(delay)

                response = requests.post(
                    query_url,
                    json=query_data,
                    headers={"Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                response.raise_for_status()
                data = response.json()

                vulns = data.get("vulns", [])
                return self._normalize_results(vulns)

            except requests.HTTPError as e:
                # Don't retry on 4xx client errors (except 429 Too Many Requests)
                is_client_error = (
                    e.response.status_code >= 400 and e.response.status_code < 500
                )
                is_rate_limited = e.response.status_code == 429
                if is_client_error and not is_rate_limited:
                    logger.debug(
                        f"Client error ({e.response.status_code}) fetching OSV data for {package_name}: {e}"
                    )
                    return []

                if retry == max_retries:
                    logger.debug(f"Max retries reached for OSV query: {e}")
                    return []

                logger.debug(
                    f"HTTP error fetching OSV data for {package_name} (attempt {retry+1}/{max_retries+1}): {e}"
                )

            except (requests.ConnectionError, requests.Timeout) as e:
                if retry == max_retries:
                    logger.debug(f"Max retries reached for OSV query: {e}")
                    return []

                logger.debug(
                    f"Connection error fetching OSV data for {package_name} (attempt {retry+1}/{max_retries+1}): {e}"
                )

            except Exception as e:
                logger.debug(
                    f"Unexpected error fetching OSV data for {package_name}: {e}"
                )
                return []

        return []

    def _normalize_ecosystem(self, ecosystem: str) -> str:
        """Normalize ecosystem names to OSV format.

        Args:
            ecosystem: Original ecosystem name

        Returns:
            OSV ecosystem name
        """
        mapping = {
            "nodejs": "npm",
            "node": "npm",
            "python": "PyPI",
            "py": "PyPI",
            "golang": "Go",
            "go": "Go",
            "maven": "Maven",
            "java": "Maven",
            "nuget": "NuGet",
            "dotnet": "NuGet",
            "ruby": "RubyGems",
            "gems": "RubyGems",
            "composer": "Packagist",
            "php": "Packagist",
        }

        return mapping.get(ecosystem.lower(), ecosystem)

    def _normalize_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize OSV vulnerability data.

        Args:
            results: OSV vulnerability data

        Returns:
            List of normalized vulnerability dictionaries
        """
        normalized = []

        for vuln in results:
            severity = None
            cvss_score = None

            # Extract CVSS score if available
            if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                severity = vuln["database_specific"]["severity"]

            # Extract CVSS score if available
            if "severity" in vuln and vuln["severity"]:
                if "score" in vuln["severity"]:
                    cvss_score = vuln["severity"]["score"]

            # Determine fixed versions
            fixed_versions = []
            if "affected" in vuln and vuln["affected"]:
                for affected in vuln["affected"]:
                    if "ranges" in affected:
                        for range_obj in affected["ranges"]:
                            if range_obj["type"] == "SEMVER" and "events" in range_obj:
                                for event in range_obj["events"]:
                                    if event["introduced"] == "0":
                                        continue
                                    if "fixed" in event:
                                        fixed_versions.append(event["fixed"])

            normalized.append(
                {
                    "id": vuln.get("id", ""),
                    "source": "OSV",
                    "published": vuln.get("published", ""),
                    "summary": vuln.get("summary", "No summary available"),
                    "details": vuln.get("details", ""),
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "fixed_versions": fixed_versions,
                    "references": [
                        ref.get("url", "") for ref in vuln.get("references", [])
                    ],
                }
            )

        return normalized


class NVDSource(VulnerabilitySource):
    """National Vulnerability Database (NVD) vulnerability data source."""

    def __init__(self, api_key: Optional[str] = None, enabled: bool = True):
        """Initialize the NVD vulnerability source.

        Args:
            api_key: NVD API key (optional)
            enabled: Whether this source is enabled
        """
        super().__init__(
            name="NVD",
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            enabled=enabled,
        )
        self.api_key = api_key

    def get_vulnerabilities(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from NVD for a package.

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
        response_data = self._make_request(self.base_url, params)
        if not response_data:
            return []

        # Extract vulnerability data
        vulns = response_data.get("vulnerabilities", [])
        normalized = self._normalize_results(vulns)

        # Add a small delay to avoid rate limiting
        time.sleep(0.1)

        return normalized

    def _get_cpe_prefix(self, ecosystem: str) -> str:
        """Get the CPE prefix for an ecosystem.

        Args:
            ecosystem: Package ecosystem

        Returns:
            CPE prefix for the ecosystem
        """
        mapping = {
            "nodejs": "cpe:2.3:a:*:node:",
            "npm": "cpe:2.3:a:*:node:",
            "python": "cpe:2.3:a:python:",
            "golang": "cpe:2.3:a:golang:",
            "maven": "cpe:2.3:a:apache:maven:",
            "java": "cpe:2.3:a:java:",
            "ruby": "cpe:2.3:a:ruby:",
            "php": "cpe:2.3:a:php:",
        }

        return mapping.get(ecosystem.lower(), "")

    def _normalize_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize NVD vulnerability data.

        Args:
            results: NVD vulnerability data

        Returns:
            List of normalized vulnerability dictionaries
        """
        normalized = []

        for vuln_entry in results:
            vuln = vuln_entry.get("cve", {})

            # Extract base data
            vuln_id = vuln.get("id", "")
            published = vuln.get("published", "")

            # Extract description
            descriptions = vuln.get("descriptions", [])
            summary = "No description available"
            details = ""

            for desc in descriptions:
                if desc.get("lang") == "en":
                    summary = desc.get("value", summary)
                    break

            # Extract CVSS score
            metrics = vuln.get("metrics", {})
            cvss_score = None
            severity = None

            # Try CVSS 3.1 first, then 3.0, then 2.0
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0]
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                severity = cvss_data.get("cvssData", {}).get("baseSeverity")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0]
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                severity = cvss_data.get("cvssData", {}).get("baseSeverity")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0]
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore")
                severity = cvss_data.get("baseSeverity")

            # Extract references
            references = []
            for ref in vuln.get("references", []):
                if "url" in ref:
                    references.append(ref["url"])

            normalized.append(
                {
                    "id": vuln_id,
                    "source": "NVD",
                    "published": published,
                    "summary": summary,
                    "details": details,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "fixed_versions": [],  # NVD doesn't provide this easily
                    "references": references,
                }
            )

        return normalized


class GitHubAdvisorySource(VulnerabilitySource):
    """GitHub Advisory Database vulnerability data source."""

    def __init__(self, api_token: Optional[str] = None, enabled: bool = True):
        """Initialize the GitHub Advisory vulnerability source.

        Args:
            api_token: GitHub API token (optional)
            enabled: Whether this source is enabled
        """
        super().__init__(
            name="GitHub Advisory",
            base_url="https://api.github.com/graphql",
            enabled=enabled,
        )
        self.api_token = api_token

    def get_vulnerabilities(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities from GitHub Advisory for a package.

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

        # Make the request with retry mechanism
        max_retries = 3
        backoff_factor = 0.5
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        for retry in range(max_retries + 1):
            try:
                if retry > 0:
                    # Calculate delay with exponential backoff
                    delay = backoff_factor * (2 ** (retry - 1))
                    logger.debug(
                        f"Retry {retry}/{max_retries} for GitHub Advisory query after {delay:.2f}s delay"
                    )
                    time.sleep(delay)

                response = requests.post(
                    self.base_url,
                    json={"query": query, "variables": variables},
                    headers=headers,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                data = response.json()

                if "errors" in data:
                    error_message = str(data.get("errors", []))
                    logger.debug(f"GraphQL errors: {error_message}")

                    # Check for rate limiting errors
                    if "rate limit" in error_message.lower() and retry < max_retries:
                        # This is a rate limit error, retry with backoff
                        continue

                    return []

                # Extract vulnerability data
                vulnerabilities = (
                    data.get("data", {})
                    .get("securityVulnerabilities", {})
                    .get("nodes", [])
                )
                return self._normalize_results(vulnerabilities)

            except requests.HTTPError as e:
                # Don't retry on 4xx client errors (except 429 Too Many Requests)
                is_client_error = (
                    e.response.status_code >= 400 and e.response.status_code < 500
                )
                is_rate_limited = e.response.status_code == 429
                if is_client_error and not is_rate_limited:
                    logger.debug(
                        f"Client error ({e.response.status_code}) fetching GitHub Advisory data for {package_name}: {e}"
                    )
                    return []

                if retry == max_retries:
                    logger.debug(f"Max retries reached for GitHub Advisory query: {e}")
                    return []

                logger.debug(
                    f"HTTP error fetching GitHub Advisory data for {package_name} (attempt {retry+1}/{max_retries+1}): {e}"
                )

            except (requests.ConnectionError, requests.Timeout) as e:
                if retry == max_retries:
                    logger.debug(f"Max retries reached for GitHub Advisory query: {e}")
                    return []

                logger.debug(
                    f"Connection error fetching GitHub Advisory data for {package_name} (attempt {retry+1}/{max_retries+1}): {e}"
                )

            except Exception as e:
                logger.debug(
                    f"Unexpected error fetching GitHub Advisory data for {package_name}: {e}"
                )
                return []

        return []

    def _normalize_ecosystem(self, ecosystem: str) -> str:
        """Normalize ecosystem names to GitHub's format.

        Args:
            ecosystem: Original ecosystem name

        Returns:
            GitHub ecosystem name
        """
        mapping = {
            "nodejs": "NPM",
            "npm": "NPM",
            "python": "PIP",
            "pypi": "PIP",
            "golang": "GO",
            "go": "GO",
            "maven": "MAVEN",
            "java": "MAVEN",
            "nuget": "NUGET",
            "dotnet": "NUGET",
            "ruby": "RUBYGEMS",
            "rubygems": "RUBYGEMS",
            "php": "COMPOSER",
            "composer": "COMPOSER",
            "rust": "RUST",
        }

        return mapping.get(ecosystem.lower(), "")

    def _normalize_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize GitHub Advisory vulnerability data.

        Args:
            results: GitHub vulnerability data

        Returns:
            List of normalized vulnerability dictionaries
        """
        normalized = []

        for vuln in results:
            advisory = vuln.get("advisory", {})

            # Extract CVSS score
            cvss_score = None
            if "cvss" in advisory and advisory["cvss"]:
                cvss_score = advisory["cvss"].get("score")

            # Extract fixed version
            fixed_versions = []
            if "firstPatchedVersion" in vuln and vuln["firstPatchedVersion"]:
                version = vuln["firstPatchedVersion"].get("identifier")
                if version:
                    fixed_versions.append(version)

            normalized.append(
                {
                    "id": advisory.get("id", ""),
                    "source": "GitHub Advisory",
                    "published": advisory.get("publishedAt", ""),
                    "summary": advisory.get("summary", "No summary available"),
                    "details": advisory.get("description", ""),
                    "severity": vuln.get("severity", "").upper(),
                    "cvss_score": cvss_score,
                    "fixed_versions": fixed_versions,
                    "references": [
                        ref.get("url", "") for ref in advisory.get("references", [])
                    ],
                }
            )

        return normalized


def normalize_cvss_score(score: Union[float, str, None]) -> Optional[float]:
    """Normalize a CVSS score to a float between 0 and 10.

    Args:
        score: CVSS score as string or float

    Returns:
        Normalized score as a float, or None if invalid
    """
    if score is None:
        return None

    try:
        # Convert to float if it's a string
        if isinstance(score, str):
            score = float(score.strip())

        # Ensure it's in the valid range
        if 0 <= score <= 10:
            return score
    except (ValueError, TypeError):
        pass

    return None


def severity_to_score(severity: Optional[str]) -> float:
    """Convert a severity string to a numerical score.

    Args:
        severity: Severity string (e.g., LOW, MEDIUM, HIGH, CRITICAL)

    Returns:
        Numerical score between 0 and 10
    """
    if not severity:
        return 0.0

    # Normalize to uppercase
    severity = severity.upper()

    # Map severity to score
    mapping = {
        "NONE": 0.0,
        "LOW": 3.0,
        "MEDIUM": 5.0,
        "MODERATE": 5.0,
        "HIGH": 8.0,
        "CRITICAL": 10.0,
    }

    return mapping.get(severity, 0.0)


def get_cache_key(package_name: str, ecosystem: str) -> str:
    """Generate a cache key for vulnerability data.

    Args:
        package_name: Package name
        ecosystem: Package ecosystem

    Returns:
        Cache key
    """
    return f"{ecosystem.lower()}:{package_name.lower()}"


def get_cached_data(
    package_name: str, ecosystem: str
) -> Optional[Tuple[List[Dict[str, Any]], float]]:
    """Get cached vulnerability data for a package.

    This function first checks the disk cache, and falls back to the in-memory cache.

    Args:
        package_name: Package name
        ecosystem: Package ecosystem

    Returns:
        Tuple of (vulnerability data, timestamp) or None if not cached or expired
    """
    # Check environment variable directly
    if os.environ.get("DEPENDENCY_RISK_DISABLE_CACHE", "0") == "1":
        logger.info(
            f"Cache disabled by environment variable, skipping cache lookup for {package_name}"
        )
        return None

    # First, try the disk cache if enabled
    if USE_DISK_CACHE:
        disk_cache_result = disk_cache.get(package_name, ecosystem)
        if disk_cache_result:
            return disk_cache_result

    # Fall back to in-memory cache
    key = get_cache_key(package_name, ecosystem)
    if key in VULNERABILITY_CACHE:
        data, timestamp = VULNERABILITY_CACHE[key]
        # Check if the cache is still valid
        if time.time() - timestamp < CACHE_EXPIRY:
            logger.debug(
                f"Serving vulnerability data for {package_name} from memory cache"
            )
            return data, timestamp

    return None


def cache_data(package_name: str, ecosystem: str, data: List[Dict[str, Any]]) -> None:
    """Cache vulnerability data for a package.

    This function stores the data in both the disk cache and in-memory cache.

    Args:
        package_name: Package name
        ecosystem: Package ecosystem
        data: Vulnerability data to cache
    """
    # Save to disk cache if enabled
    if USE_DISK_CACHE:
        disk_cache.set(package_name, ecosystem, data)

    # Also save to in-memory cache for backward compatibility
    key = get_cache_key(package_name, ecosystem)
    VULNERABILITY_CACHE[key] = (data, time.time())


def aggregate_vulnerability_data(
    dependency: DependencyMetadata, api_keys: Optional[Dict[str, str]] = None
) -> Tuple[DependencyMetadata, List[Dict[str, Any]]]:
    """Aggregate vulnerability data from multiple sources.

    Args:
        dependency: Dependency metadata
        api_keys: API keys for vulnerability sources

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
    sources = [
        OSVSource(enabled=True),
        GitHubAdvisorySource(api_token=github_token, enabled=github_token is not None),
        NVDSource(api_key=nvd_api_key, enabled=True),
    ]

    # Collect vulnerabilities from all sources
    all_vulnerabilities = []
    for source in sources:
        if source.enabled:
            try:
                logger.info(
                    f"Checking {source.name} for vulnerabilities in {package_name}"
                )
                vulnerabilities = source.get_vulnerabilities(package_name, ecosystem)
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                logger.error(f"Error fetching vulnerabilities from {source.name}: {e}")

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


def _update_dependency_with_vulnerabilities(
    dependency: DependencyMetadata, vulnerabilities: List[Dict[str, Any]]
) -> DependencyMetadata:
    """Update dependency metadata with vulnerability information.

    Args:
        dependency: Dependency metadata
        vulnerabilities: List of vulnerability data

    Returns:
        Updated dependency metadata
    """
    # Initialize security metrics if not present
    if not dependency.security_metrics:
        from ..models import SecurityMetrics

        dependency.security_metrics = SecurityMetrics()

    # Count vulnerabilities
    dependency.security_metrics.vulnerability_count = len(vulnerabilities)

    # Count fixed vulnerabilities (those with fixed versions)
    fixed_count = sum(1 for v in vulnerabilities if v.get("fixed_versions"))
    dependency.security_metrics.fixed_vulnerability_count = fixed_count

    # Find maximum CVSS score
    max_cvss = 0.0
    for vuln in vulnerabilities:
        cvss_score = vuln.get("cvss_score")
        if cvss_score is not None:
            normalized_score = normalize_cvss_score(cvss_score)
            if normalized_score is not None and normalized_score > max_cvss:
                max_cvss = normalized_score
        else:
            # If no CVSS score, try to derive from severity
            severity_score = severity_to_score(vuln.get("severity"))
            if severity_score > max_cvss:
                max_cvss = severity_score

    dependency.security_metrics.max_cvss_score = max_cvss if max_cvss > 0 else None

    # Determine if there are known exploits based on references
    for vuln in vulnerabilities:
        references = vuln.get("references", [])
        for ref in references:
            if isinstance(ref, str) and any(
                term in ref.lower() for term in ["exploit", "poc", "proof-of-concept"]
            ):
                dependency.has_known_exploits = True
                break

        # Also check summary and details
        for field in ["summary", "details"]:
            if field in vuln and any(
                term in vuln[field].lower()
                for term in ["exploit", "poc", "proof-of-concept"]
            ):
                dependency.has_known_exploits = True
                break

    # Check if there was a recent security update
    if vulnerabilities:
        # Look for recent vulnerability publications (last 90 days)
        ninety_days_ago = (datetime.now() - timedelta(days=90)).isoformat()
        recent_vulnerabilities = [
            v for v in vulnerabilities if v.get("published", "") >= ninety_days_ago
        ]

        # Look for fixed versions
        any_fixed = any(v.get("fixed_versions") for v in vulnerabilities)

        # If there are recent vulnerabilities and any have been fixed, mark as having recent security updates
        if recent_vulnerabilities and any_fixed:
            dependency.security_metrics.has_recent_security_update = True

    return dependency
