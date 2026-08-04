"""Collect and normalize vulnerability information from multiple sources.

This module aggregates vulnerability data from OSV, NVD, and GitHub Advisory Database,
and caches the results to disk to reduce the number of API calls.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

from ..models import DependencyMetadata
from ..versioning import VersionScheme
from . import affected_ranges, ecosystems
from .cache import default_cache as disk_cache

logger = logging.getLogger(__name__)


def infer_ecosystem(dependency: DependencyMetadata) -> str:
    """Return the dependency's ecosystem for vulnerability lookup, or "".

    Prefers the value callers set from the manifest (``additional_info``), which
    every analyzer stamps; only falls back to a coarse repository-URL guess when
    it is absent. The guess recognizes npm and Go tokens and otherwise fails
    closed with "", consistent with ``ecosystems.resolve``: silently defaulting
    to python mis-routed unknown dependencies to PyPI and returned a confident
    zero advisories (#66/#109). Callers skip the lookup on "".
    """
    ecosystem = dependency.additional_info.get("ecosystem", "").strip()
    if ecosystem:
        return ecosystem
    url = dependency.repository_url or ""
    if "npm" in url or "node" in url:
        return "nodejs"
    if "go" in url:
        return "golang"
    return ""


# Cache settings
CACHE_EXPIRY = 24 * 60 * 60  # 24 hours in seconds
VULNERABILITY_CACHE = {}  # In-memory cache (for backward compatibility)
DEFAULT_MINIMUM_SEVERITY_FOR_SCORING = "LOW"
SEVERITY_ORDER = {
    "INFO": 0,
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
SEVERITY_FROM_CVSS = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
)
LOW_CONFIDENCE_VALUES = {"LOW", "VERY_LOW", "UNKNOWN", "UNTRUSTED"}

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
                Sleep time between retries is:
                {backoff_factor} * (2 ^ (retry_number - 1))

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
                        f"Retry {retry}/{max_retries} for {url} after "
                        f"{delay:.2f}s delay"
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
                        f"Client error ({e.response.status_code}) fetching data "
                        f"from {url}: {e}"
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
                        f"Retry {retry}/{max_retries} for OSV query after "
                        f"{delay:.2f}s delay"
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
                return self._normalize_results(vulns, package_name, osv_ecosystem)

            except requests.HTTPError as e:
                # Don't retry on 4xx client errors (except 429 Too Many Requests)
                is_client_error = (
                    e.response.status_code >= 400 and e.response.status_code < 500
                )
                is_rate_limited = e.response.status_code == 429
                if is_client_error and not is_rate_limited:
                    logger.debug(
                        f"Client error ({e.response.status_code}) fetching OSV "
                        f"data for {package_name}: {e}"
                    )
                    return []

                if retry == max_retries:
                    logger.debug(f"Max retries reached for OSV query: {e}")
                    return []

                logger.debug(
                    f"HTTP error fetching OSV data for {package_name} "
                    f"(attempt {retry + 1}/{max_retries + 1}): {e}"
                )

            except (requests.ConnectionError, requests.Timeout) as e:
                if retry == max_retries:
                    logger.debug(f"Max retries reached for OSV query: {e}")
                    return []

                logger.debug(
                    f"Connection error fetching OSV data for {package_name} "
                    f"(attempt {retry + 1}/{max_retries + 1}): {e}"
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
        eco = ecosystems.lookup(ecosystem)
        # Unknown ecosystem is returned verbatim (historical OSV behavior).
        return eco.osv if eco is not None else ecosystem

    def _normalize_results(
        self,
        results: List[Dict[str, Any]],
        package_name: Optional[str] = None,
        osv_ecosystem: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Normalize OSV vulnerability data.

        Args:
            results: OSV vulnerability data
            package_name: Package the lookup was for, used to drop ``affected``
                entries belonging to other packages in a multi-package advisory
            osv_ecosystem: OSV ecosystem name, which disambiguates packages
                that share a name across ecosystems

        Returns:
            List of normalized vulnerability dictionaries
        """
        normalized = []

        for vuln in results:
            severity = None
            cvss_score = None

            if "database_specific" in vuln and "severity" in vuln["database_specific"]:
                severity = vuln["database_specific"]["severity"]

            # Extract CVSS score if available
            cvss_score = _extract_osv_cvss_score(vuln.get("severity"))

            # Determine fixed versions
            fixed_versions = []
            if "affected" in vuln and vuln["affected"]:
                for affected in vuln["affected"]:
                    for range_obj in affected.get("ranges", []):
                        # OSV range events are one of introduced/fixed/
                        # last_affected/limit; only "fixed" carries a fixed
                        # version. Guard against events missing "introduced"
                        # (which used to raise KeyError and silently drop the
                        # whole advisory) and don't restrict to SEMVER ranges
                        # (npm advisories use ECOSYSTEM ranges).
                        for event in range_obj.get("events", []):
                            if "fixed" in event:
                                fixed_versions.append(event["fixed"])

            # The affected block is what makes an advisory answerable against a
            # pin. Dropping it is how every advisory ever published came to be
            # counted against whatever version was installed (#61).
            affected = affected_ranges.affected_versions_from_osv(
                vuln, package_name, osv_ecosystem
            )

            normalized.append(
                {
                    "id": vuln.get("id", ""),
                    "source": "OSV",
                    "published": vuln.get("published", ""),
                    "summary": vuln.get("summary", "No summary available"),
                    "details": vuln.get("details", ""),
                    "severity": severity,
                    "normalized_severity": normalize_vulnerability_severity(
                        severity, cvss_score
                    ),
                    "cvss_score": cvss_score,
                    "withdrawn": bool(vuln.get("withdrawn")),
                    "confidence": "HIGH",
                    "fixed_versions": fixed_versions,
                    "affected_versions": (
                        None if affected.is_empty() else affected.to_payload()
                    ),
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
        eco = ecosystems.lookup(ecosystem)
        # "" means "NVD does not cover this ecosystem" (historical behavior).
        return (eco.nvd_cpe_prefix or "") if eco is not None else ""

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
            status = vuln.get("vulnStatus", "")

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
                    "normalized_severity": normalize_vulnerability_severity(
                        severity, cvss_score
                    ),
                    "cvss_score": cvss_score,
                    "withdrawn": status.lower() in ("rejected", "withdrawn"),
                    "confidence": "MEDIUM" if severity or cvss_score else "LOW",
                    "fixed_versions": [],  # NVD doesn't provide this easily
                    # NVD's CPE match criteria are not version ranges in any
                    # ecosystem's ordering, so applicability stays unknown and
                    # the advisory is counted with that reason recorded (#61).
                    "affected_versions": None,
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
                        f"Retry {retry}/{max_retries} for GitHub Advisory query "
                        f"after {delay:.2f}s delay"
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
                        f"Client error ({e.response.status_code}) fetching "
                        f"GitHub Advisory data for {package_name}: {e}"
                    )
                    return []

                if retry == max_retries:
                    logger.debug(f"Max retries reached for GitHub Advisory query: {e}")
                    return []

                logger.debug(
                    f"HTTP error fetching GitHub Advisory data for {package_name} "
                    f"(attempt {retry + 1}/{max_retries + 1}): {e}"
                )

            except (requests.ConnectionError, requests.Timeout) as e:
                if retry == max_retries:
                    logger.debug(f"Max retries reached for GitHub Advisory query: {e}")
                    return []

                logger.debug(
                    f"Connection error fetching GitHub Advisory data for "
                    f"{package_name} (attempt {retry + 1}/{max_retries + 1}): {e}"
                )

            except Exception as e:
                logger.debug(
                    f"Unexpected error fetching GitHub Advisory data for "
                    f"{package_name}: {e}"
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
        eco = ecosystems.lookup(ecosystem)
        # "" means "GitHub Advisory does not cover this ecosystem" (historical).
        return (eco.github_advisory or "") if eco is not None else ""

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

            affected = affected_ranges.affected_versions_from_github_range(
                vuln.get("vulnerableVersionRange")
            )

            normalized.append(
                {
                    "id": advisory.get("id", ""),
                    "source": "GitHub Advisory",
                    "published": advisory.get("publishedAt", ""),
                    "summary": advisory.get("summary", "No summary available"),
                    "details": advisory.get("description", ""),
                    "severity": vuln.get("severity", "").upper(),
                    "normalized_severity": normalize_vulnerability_severity(
                        vuln.get("severity"), cvss_score
                    ),
                    "cvss_score": cvss_score,
                    "withdrawn": bool(advisory.get("withdrawnAt")),
                    "confidence": "HIGH",
                    "fixed_versions": fixed_versions,
                    "affected_versions": (
                        None if affected.is_empty() else affected.to_payload()
                    ),
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


def normalize_vulnerability_severity(
    severity: object, cvss_score: object = None
) -> str:
    """Normalize advisory severity to a stable tier used for filtering.

    Args:
        severity: Source-specific severity value.
        cvss_score: Optional CVSS score used when severity is unavailable.

    Returns:
        One of INFO, LOW, MEDIUM, HIGH, CRITICAL, or UNKNOWN.
    """
    if isinstance(severity, str):
        normalized = severity.strip().upper().replace("-", "_")
        aliases = {
            "INFORMATIONAL": "INFO",
            "INFO": "INFO",
            "NONE": "INFO",
            "MODERATE": "MEDIUM",
            "MED": "MEDIUM",
            "CRIT": "CRITICAL",
        }
        normalized = aliases.get(normalized, normalized)
        if normalized in SEVERITY_ORDER:
            return normalized

    normalized_score = normalize_cvss_score(cvss_score)
    if normalized_score is not None:
        return cvss_score_to_severity(normalized_score)

    return "UNKNOWN"


def cvss_score_to_severity(score: float) -> str:
    """Convert a normalized CVSS score to a severity tier.

    Args:
        score: Normalized CVSS score from 0.0 to 10.0.

    Returns:
        Severity tier matching CVSS bands.
    """
    for minimum_score, severity in SEVERITY_FROM_CVSS:
        if score >= minimum_score:
            return severity
    return "INFO"


def exploit_score_from_cvss(score: float) -> float:
    """Convert max counted CVSS into a graduated exploit contribution.

    Args:
        score: Normalized CVSS score from 0.0 to 10.0.

    Returns:
        Exploit score from 0.0 to 1.0.
    """
    severity = cvss_score_to_severity(score)
    return exploit_score_from_severity(severity)


def exploit_score_from_severity(severity: str) -> float:
    """Convert a severity tier into a graduated exploit contribution.

    Args:
        severity: Normalized severity tier.

    Returns:
        Exploit score from 0.0 to 1.0.
    """
    mapping = {
        "LOW": 0.2,
        "MEDIUM": 0.45,
        "HIGH": 0.75,
        "CRITICAL": 1.0,
    }
    return mapping.get(severity, 0.0)


def annotate_vulnerabilities_for_scoring(
    vulnerabilities: List[Dict[str, object]],
    minimum_severity: str = DEFAULT_MINIMUM_SEVERITY_FOR_SCORING,
    installed_version: Optional[str] = None,
    ecosystem: Optional[str] = None,
) -> List[Dict[str, object]]:
    """Annotate vulnerabilities with scoring inclusion and filter reasons.

    Args:
        vulnerabilities: Vulnerability records from all sources.
        minimum_severity: Minimum severity tier that counts toward scoring.
        installed_version: The version actually installed, used to rule out
            advisories that were fixed before it (#61). Omitting it leaves
            every advisory's applicability unknown, which counts them all.
        ecosystem: Ecosystem name, which decides the version-ordering rules.

    Returns:
        Vulnerability records with transparent scoring annotations.
    """
    threshold = normalize_vulnerability_severity(minimum_severity)
    if threshold in ("UNKNOWN", "INFO", "NONE"):
        threshold = "INFO"

    scheme = ecosystems.version_scheme(ecosystem or "")

    return [
        _annotate_vulnerability_for_scoring(vuln, threshold, installed_version, scheme)
        for vuln in vulnerabilities
    ]


def _annotate_vulnerability_for_scoring(
    vulnerability: Dict[str, object],
    threshold: str,
    installed_version: Optional[str],
    scheme: VersionScheme,
) -> Dict[str, object]:
    annotated: Dict[str, object] = dict(vulnerability)
    cvss_score = normalize_cvss_score(vulnerability.get("cvss_score"))
    normalized_severity = normalize_vulnerability_severity(
        vulnerability.get("normalized_severity") or vulnerability.get("severity"),
        cvss_score,
    )
    withdrawn = _is_withdrawn(vulnerability)
    confidence = _normalize_confidence(vulnerability)
    applicability = affected_ranges.evaluate_applicability(
        affected_ranges.affected_versions_from_payload(
            vulnerability.get("affected_versions")
        ),
        installed_version,
        scheme,
    )

    filter_reasons = []
    if withdrawn:
        filter_reasons.append("withdrawn")
    if applicability.status is affected_ranges.Applicability.NOT_AFFECTED:
        filter_reasons.append(affected_ranges.NOT_AFFECTED_FILTER_REASON)
    if normalized_severity == "INFO":
        filter_reasons.append("informational")
    elif normalized_severity == "UNKNOWN":
        filter_reasons.append("unknown severity")
    elif SEVERITY_ORDER[normalized_severity] < SEVERITY_ORDER[threshold]:
        filter_reasons.append(f"below {threshold.lower()} threshold")
    if confidence in LOW_CONFIDENCE_VALUES:
        filter_reasons.append("low confidence")

    counted = not filter_reasons
    annotated["normalized_severity"] = normalized_severity
    annotated["cvss_score"] = cvss_score
    annotated["withdrawn"] = withdrawn
    annotated["confidence"] = confidence
    annotated["version_match"] = applicability.status.value
    annotated["version_match_reason"] = applicability.reason
    annotated["counted_in_score"] = counted
    annotated["filtered"] = not counted
    annotated["filter_reasons"] = filter_reasons
    return annotated


def _extract_osv_cvss_score(severity_data: object) -> Optional[float]:
    if isinstance(severity_data, dict):
        return normalize_cvss_score(severity_data.get("score"))

    if isinstance(severity_data, list):
        for severity_entry in severity_data:
            if isinstance(severity_entry, dict):
                normalized_score = normalize_cvss_score(severity_entry.get("score"))
                if normalized_score is not None:
                    return normalized_score

    return None


def _is_withdrawn(vulnerability: Dict[str, object]) -> bool:
    withdrawn = vulnerability.get("withdrawn")
    if isinstance(withdrawn, bool):
        return withdrawn
    if isinstance(withdrawn, str):
        return bool(withdrawn.strip())

    status = vulnerability.get("status") or vulnerability.get("vulnStatus")
    if isinstance(status, str):
        return status.strip().lower() in ("rejected", "withdrawn")

    return bool(vulnerability.get("withdrawn_at") or vulnerability.get("withdrawnAt"))


def _normalize_confidence(vulnerability: Dict[str, object]) -> str:
    confidence = (
        vulnerability.get("confidence")
        or vulnerability.get("source_confidence")
        or vulnerability.get("confidence_level")
    )
    if isinstance(confidence, str) and confidence.strip():
        return confidence.strip().upper().replace("-", "_")

    source = vulnerability.get("source")
    if source == "OSV" or source == "GitHub Advisory":
        return "HIGH"
    if source == "NVD":
        if vulnerability.get("severity") or vulnerability.get("cvss_score"):
            return "MEDIUM"
        return "LOW"

    return "UNKNOWN"


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
            "Cache disabled by environment variable, skipping cache lookup for "
            f"{package_name}"
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
    dependency: DependencyMetadata,
    api_keys: Optional[Dict[str, str]] = None,
    minimum_severity: str = DEFAULT_MINIMUM_SEVERITY_FOR_SCORING,
) -> Tuple[DependencyMetadata, List[Dict[str, Any]]]:
    """Aggregate vulnerability data from multiple sources.

    Args:
        dependency: Dependency metadata
        api_keys: API keys for vulnerability sources
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
        return dependency, []

    # Check cache first
    cached = get_cached_data(package_name, ecosystem)
    if cached:
        vulnerabilities, _ = cached
        return (
            _update_dependency_with_vulnerabilities(
                dependency, vulnerabilities, minimum_severity
            ),
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
        dependency, unique_vulnerabilities, minimum_severity
    )

    return updated_dependency, unique_vulnerabilities


def _update_dependency_with_vulnerabilities(
    dependency: DependencyMetadata,
    vulnerabilities: List[Dict[str, object]],
    minimum_severity: str = DEFAULT_MINIMUM_SEVERITY_FOR_SCORING,
) -> DependencyMetadata:
    """Update dependency metadata with vulnerability information.

    Args:
        dependency: Dependency metadata
        vulnerabilities: List of vulnerability data
        minimum_severity: Minimum severity that counts toward scoring

    Returns:
        Updated dependency metadata
    """
    # Initialize security metrics if not present
    if not dependency.security_metrics:
        from ..models import SecurityMetrics

        dependency.security_metrics = SecurityMetrics()

    annotated_vulnerabilities = annotate_vulnerabilities_for_scoring(
        vulnerabilities,
        minimum_severity,
        dependency.installed_version,
        infer_ecosystem(dependency),
    )
    counted_vulnerabilities = [
        vuln
        for vuln in annotated_vulnerabilities
        if vuln.get("counted_in_score") is True
    ]
    filtered_vulnerabilities = [
        vuln for vuln in annotated_vulnerabilities if vuln.get("filtered") is True
    ]
    # Advisories counted only because applicability could not be decided. They
    # inflate nothing silently: the count and its reasons are reported (#74).
    undecided_vulnerabilities = [
        vuln
        for vuln in counted_vulnerabilities
        if vuln.get("version_match") == affected_ranges.Applicability.UNKNOWN.value
    ]

    # Count vulnerabilities
    dependency.security_metrics.vulnerability_count = len(vulnerabilities)
    dependency.security_metrics.counted_vulnerability_count = len(
        counted_vulnerabilities
    )
    dependency.security_metrics.filtered_vulnerability_count = len(
        filtered_vulnerabilities
    )
    dependency.security_metrics.vulnerability_details = annotated_vulnerabilities
    dependency.security_metrics.filtered_vulnerability_reasons = _count_filter_reasons(
        filtered_vulnerabilities
    )
    dependency.security_metrics.applicability_unknown_count = len(
        undecided_vulnerabilities
    )
    dependency.security_metrics.applicability_unknown_reasons = (
        _count_applicability_reasons(undecided_vulnerabilities)
    )

    # Find maximum CVSS score
    max_cvss = 0.0
    max_severity = None
    for vuln in counted_vulnerabilities:
        cvss_score = vuln.get("cvss_score")
        if cvss_score is not None:
            normalized_score = normalize_cvss_score(cvss_score)
            if normalized_score is not None and normalized_score > max_cvss:
                max_cvss = normalized_score
        else:
            # If no CVSS score, try to derive from severity
            severity_score = severity_to_score(_get_string(vuln, "normalized_severity"))
            if severity_score > max_cvss:
                max_cvss = severity_score
        severity = _get_string(vuln, "normalized_severity")
        if severity and (
            max_severity is None
            or SEVERITY_ORDER[severity] > SEVERITY_ORDER[max_severity]
        ):
            max_severity = severity

    dependency.security_metrics.max_cvss_score = max_cvss if max_cvss > 0 else None
    dependency.security_metrics.max_vulnerability_severity = max_severity

    dependency.has_known_exploits = bool(counted_vulnerabilities)

    return dependency


def _count_filter_reasons(vulnerabilities: List[Dict[str, object]]) -> Dict[str, int]:
    reason_counts: Dict[str, int] = {}
    for vulnerability in vulnerabilities:
        filter_reasons = vulnerability.get("filter_reasons")
        if isinstance(filter_reasons, list):
            for reason in filter_reasons:
                if isinstance(reason, str):
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return reason_counts


def _count_applicability_reasons(
    vulnerabilities: List[Dict[str, object]],
) -> Dict[str, int]:
    """Tally why applicability could not be decided for counted advisories."""
    reason_counts: Dict[str, int] = {}
    for vulnerability in vulnerabilities:
        reason = _get_string(vulnerability, "version_match_reason")
        if reason:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return reason_counts


def _get_string(vulnerability: Dict[str, object], key: str) -> Optional[str]:
    value = vulnerability.get(key)
    if isinstance(value, str):
        return value
    return None
