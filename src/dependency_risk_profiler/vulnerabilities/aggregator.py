"""Collect and normalize vulnerability information from multiple sources.

This module aggregates vulnerability data from OSV, NVD, and GitHub Advisory Database,
and caches the results to disk to reduce the number of API calls.

Every source answers with a :class:`SourceLookup`, not with a bare list. The
list had exactly one way to say "nothing" and used it for a connection failure,
a 4xx, a GraphQL error block, an unreadable body, an ecosystem the source does
not cover, and a genuinely clean package — and the aggregate was cached either
way, so an outage wrote "advisory-clean" to disk for every package in the scan
and the verdict outlived the outage (#219). The three outcomes that have to be
distinguishable are: advisories found, measured and none found, and lookup
failed. Only the first two are cacheable.
"""

import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

from ..models import DependencyMetadata
from ..signals import ADVISORY_LOOKUP_UNMEASURED, AdvisoryLookupState
from ..versioning import VersionScheme
from . import affected_ranges, ecosystems
from .cache import advisory_cache_key
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


def _http_error_status(error: requests.HTTPError) -> Optional[int]:
    """Return the status code an HTTPError carries, or None if it carries none.

    `requests` raises `HTTPError` from `raise_for_status()` with a response
    attached, but the exception type does not guarantee one — a transport
    adapter or a hand-rolled raise can produce an `HTTPError` whose `response`
    is None. Callers classify on the code, so give them "unknown" rather than
    an AttributeError.

    `status_code` gets the same treatment. It is declared `int`, but
    `Response.__init__` sets it to None and requests suppresses the resulting
    error in its own source, so a response that never reached the wire carries
    no status either.
    """
    response = error.response
    if response is None:
        return None
    status_code = response.status_code
    if not isinstance(status_code, int):
        return None
    return status_code


# Cache settings
CACHE_EXPIRY = 24 * 60 * 60  # 24 hours in seconds
# In-memory cache (for backward compatibility): key -> (payloads, cached-at).
VULNERABILITY_CACHE: Dict[str, Tuple[List[Dict[str, object]], float]] = {}
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


class SourceState(Enum):
    """What one advisory source did when it was asked about a package."""

    #: It replied and the reply was readable. The advisory list it carries is
    #: the answer, and an empty one means "measured, none found".
    ANSWERED = "answered"

    #: It was asked and did not answer: unreachable after the retries, an error
    #: status, a GraphQL ``errors`` block, or a body this code cannot read.
    FAILED = "failed"

    #: It was never asked: switched off, missing the credential it needs, or it
    #: does not cover this ecosystem. Not a failure, and not an answer either.
    ABSTAINED = "abstained"


@dataclass(frozen=True)
class SourceLookup:
    """One source's answer, or the fact that there wasn't one.

    ``vulnerabilities`` is only meaningful for :attr:`SourceState.ANSWERED`,
    and the constructors below are the reason it cannot be anything else: a
    failed lookup carries no list at all, so there is no empty list to mistake
    for a clean package.
    """

    state: SourceState
    vulnerabilities: Tuple[Dict[str, Any], ...] = ()
    detail: str = ""

    @classmethod
    def answered(cls, vulnerabilities: Sequence[Dict[str, Any]]) -> "SourceLookup":
        """Record a readable reply.

        Args:
            vulnerabilities: The source's normalized advisories, possibly none.

        Returns:
            An ``ANSWERED`` lookup.
        """
        return cls(SourceState.ANSWERED, tuple(vulnerabilities), "")

    @classmethod
    def failed(cls, detail: str) -> "SourceLookup":
        """Record that the source was asked and did not answer.

        Args:
            detail: Why, in a few words, for the log and the report.

        Returns:
            A ``FAILED`` lookup carrying no advisories.
        """
        return cls(SourceState.FAILED, (), detail)

    @classmethod
    def abstained(cls, detail: str) -> "SourceLookup":
        """Record that the source was never asked.

        Args:
            detail: Why it was not asked.

        Returns:
            An ``ABSTAINED`` lookup carrying no advisories.
        """
        return cls(SourceState.ABSTAINED, (), detail)


class VulnerabilitySource:
    """Base class for vulnerability data sources."""

    #: Whether an empty answer from this source is evidence that a package has
    #: no advisories. True for the ecosystem-scoped advisory databases (OSV,
    #: GitHub Advisory), which are asked "what do you have on this package in
    #: this ecosystem" and whose silence is an answer. False for NVD, which is
    #: reached here by keyword search over CPE strings: it can add a CVE nobody
    #: else listed, but "the keyword matched nothing" is not a statement about
    #: the package. The distinction is what keeps a slow NVD from making a
    #: whole scan unmeasured while still refusing to call a package clean
    #: because OSV was down (#219).
    establishes_absence: bool = True

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

    def lookup(self, package_name: str, ecosystem: str) -> SourceLookup:
        """Ask this source about a package and say what happened.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            The source's answer, or the reason there isn't one.
        """
        raise NotImplementedError("Subclasses must implement lookup")

    def get_vulnerabilities(
        self, package_name: str, ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a package, discarding why there are none.

        Kept for callers that only want the advisories and have no way to act
        on the difference between "none" and "no answer". The aggregator is not
        one of them and calls :meth:`lookup` directly — routing it through here
        is how the empty list came to mean six different things (#219).

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (e.g., npm, pypi, golang)

        Returns:
            List of vulnerability dictionaries, empty if the source found none
            *or* did not answer.
        """
        return list(self.lookup(package_name, ecosystem).vulnerabilities)

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
                payload = response.json()
                if not isinstance(payload, dict):
                    # The signature promises a mapping. A list or scalar body
                    # is a malformed response, not a result: fail closed rather
                    # than handing callers something `.get()` will blow up on.
                    logger.debug(
                        f"Ignoring non-object JSON response from {url}: "
                        f"{type(payload).__name__}"
                    )
                    return None
                return payload

            except requests.HTTPError as e:
                # Don't retry on 4xx client errors (except 429 Too Many Requests)
                # `HTTPError.response` is optional — an adapter can raise one
                # without ever producing a response — so reading `.status_code`
                # off it unconditionally was an AttributeError waiting for a bad
                # day. No response means no status to classify: fall through to
                # the retry path rather than treating it as a client error.
                status_code = _http_error_status(e)
                is_client_error = status_code is not None and 400 <= status_code < 500
                is_rate_limited = status_code == 429
                if is_client_error and not is_rate_limited:
                    logger.debug(
                        f"Client error ({status_code}) fetching data "
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

    def lookup(self, package_name: str, ecosystem: str) -> SourceLookup:
        """Ask OSV about a package.

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

        # Use retry mechanism for POST requests
        max_retries = 3
        backoff_factor = 0.5

        # Holds the decoded body once a request succeeds. Normalization runs
        # after the loop, deliberately outside the broad ``except Exception``
        # below: a shape error while reading an advisory is not a fetch
        # failure, and letting the handler catch it turns "this payload is
        # unreadable" into "this package has no advisories" — the fail-open
        # #216 hit when a boolean severity made ``.upper()`` raise (#217).
        payload: object = None
        answered = False

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
                payload = response.json()
                answered = True
                break

            except requests.HTTPError as e:
                # Don't retry on 4xx client errors (except 429 Too Many Requests)
                status_code = _http_error_status(e)
                is_client_error = status_code is not None and 400 <= status_code < 500
                is_rate_limited = status_code == 429
                if is_client_error and not is_rate_limited:
                    logger.debug(
                        f"Client error ({status_code}) fetching OSV "
                        f"data for {package_name}: {e}"
                    )
                    return SourceLookup.failed(f"HTTP {status_code}")

                if retry == max_retries:
                    logger.debug(f"Max retries reached for OSV query: {e}")
                    return SourceLookup.failed("retries exhausted after HTTP error")

                logger.debug(
                    f"HTTP error fetching OSV data for {package_name} "
                    f"(attempt {retry + 1}/{max_retries + 1}): {e}"
                )

            except (requests.ConnectionError, requests.Timeout) as e:
                if retry == max_retries:
                    logger.debug(f"Max retries reached for OSV query: {e}")
                    return SourceLookup.failed("unreachable")

                logger.debug(
                    f"Connection error fetching OSV data for {package_name} "
                    f"(attempt {retry + 1}/{max_retries + 1}): {e}"
                )

            except Exception as e:
                logger.debug(
                    f"Unexpected error fetching OSV data for {package_name}: {e}"
                )
                return SourceLookup.failed(f"unexpected error: {type(e).__name__}")

        if not answered:
            return SourceLookup.failed("retries exhausted")

        # A body that is not a JSON object is not an answer this code can read.
        # It used to fall through ``_payload_mapping`` to ``{}`` and out as a
        # clean package, which is the junk-body member of #219's six.
        if not isinstance(payload, dict):
            logger.debug(
                f"Ignoring non-object OSV response for {package_name}: "
                f"{type(payload).__name__}"
            )
            return SourceLookup.failed("unreadable response body")

        vulns = _payload_sequence(payload.get("vulns"))
        return SourceLookup.answered(
            self._normalize_results(vulns, package_name, osv_ecosystem)
        )

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
            # A severity OSV states as anything but a string is not a severity
            # this code can read; leave it None and let the CVSS block decide.
            severity = _payload_optional_str(
                _payload_mapping(vuln.get("database_specific")).get("severity")
            )

            # Extract CVSS score if available
            cvss_score = _extract_osv_cvss_score(vuln.get("severity"))

            # Determine fixed versions
            fixed_versions = []
            for affected in _payload_sequence(vuln.get("affected")):
                for range_obj in _payload_sequence(
                    _payload_mapping(affected).get("ranges")
                ):
                    # OSV range events are one of introduced/fixed/
                    # last_affected/limit; only "fixed" carries a fixed
                    # version. Guard against events missing "introduced"
                    # (which used to raise KeyError and silently drop the
                    # whole advisory) and don't restrict to SEMVER ranges
                    # (npm advisories use ECOSYSTEM ranges).
                    for event in _payload_sequence(
                        _payload_mapping(range_obj).get("events")
                    ):
                        fixed = _payload_str(_payload_mapping(event).get("fixed"))
                        # A non-string here would enter the fixed-version list
                        # as something no version scheme can order.
                        if fixed:
                            fixed_versions.append(fixed)

            # The affected block is what makes an advisory answerable against a
            # pin. Dropping it is how every advisory ever published came to be
            # counted against whatever version was installed (#61).
            affected = affected_ranges.affected_versions_from_osv(
                vuln, package_name, osv_ecosystem
            )

            normalized.append(
                {
                    "id": _payload_str(vuln.get("id")),
                    "source": "OSV",
                    "published": _payload_str(vuln.get("published")),
                    "summary": _payload_str(
                        vuln.get("summary"), "No summary available"
                    ),
                    "details": _payload_str(vuln.get("details")),
                    "severity": severity,
                    "normalized_severity": normalize_vulnerability_severity(
                        severity, cvss_score
                    ),
                    "cvss_score": cvss_score,
                    "withdrawn": _withdrawn_timestamp(vuln.get("withdrawn")),
                    "confidence": "HIGH",
                    "fixed_versions": fixed_versions,
                    "affected_versions": (
                        None if affected.is_empty() else affected.to_payload()
                    ),
                    "references": _payload_reference_urls(vuln.get("references")),
                }
            )

        return normalized


class NVDSource(VulnerabilitySource):
    """National Vulnerability Database (NVD) vulnerability data source."""

    # Reached by keyword search over CPE strings rather than by package
    # identity, so a miss is a statement about the keyword, not the package.
    # See ``VulnerabilitySource.establishes_absence``.
    establishes_absence = False

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

    def lookup(self, package_name: str, ecosystem: str) -> SourceLookup:
        """Ask NVD about a package.

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
            # NVD has no CPE naming for this ecosystem, so there is no keyword
            # to search on. An abstention rather than a failure: nothing broke,
            # and nothing was asked (#219).
            return SourceLookup.abstained(f"no CPE prefix for ecosystem {ecosystem!r}")

        # Search by keyword first
        params = {"keywordSearch": f"{cpe_prefix}{package_name}", "resultsPerPage": 100}

        if self.api_key:
            params["apiKey"] = self.api_key

        # Make the request. ``is None`` rather than falsiness: an empty JSON
        # object is a reply NVD sent, and reading it as a failure would put the
        # #219 conflation back in from the other direction.
        response_data = self._make_request(self.base_url, params)
        if response_data is None:
            return SourceLookup.failed("no readable response")

        # Extract vulnerability data
        vulns = response_data.get("vulnerabilities", [])
        normalized = self._normalize_results(vulns)

        # Add a small delay to avoid rate limiting
        time.sleep(0.1)

        return SourceLookup.answered(normalized)

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
            vuln = _payload_mapping(_payload_mapping(vuln_entry).get("cve"))

            # Extract base data
            vuln_id = _payload_str(vuln.get("id"))
            published = _payload_str(vuln.get("published"))
            status = _payload_str(vuln.get("vulnStatus"))

            # Extract description
            summary = "No description available"
            details = ""

            for desc in _payload_sequence(vuln.get("descriptions")):
                description = _payload_mapping(desc)
                if description.get("lang") == "en":
                    summary = _payload_str(description.get("value"), summary)
                    break

            # Extract CVSS score
            cvss_score, severity = self._extract_cvss(vuln.get("metrics"))

            references = _payload_reference_urls(vuln.get("references"))

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
                    # `cvss_score is not None` rather than truthiness: a
                    # measured 0.0 is a score NVD published, not a missing one.
                    "confidence": (
                        "MEDIUM" if severity or cvss_score is not None else "LOW"
                    ),
                    "fixed_versions": [],  # NVD doesn't provide this easily
                    # NVD's CPE match criteria are not version ranges in any
                    # ecosystem's ordering, so applicability stays unknown and
                    # the advisory is counted with that reason recorded (#61).
                    "affected_versions": None,
                    "references": references,
                }
            )

        return normalized

    def _extract_cvss(self, metrics: object) -> Tuple[Optional[float], Optional[str]]:
        """Return (score, severity) from an NVD metrics block, newest first.

        The score goes through ``normalize_cvss_score`` here rather than only
        at annotation time, so the value written to the cache and handed to
        consumers is a real CVSS score or nothing. A ``baseScore`` of ``true``
        used to be copied out verbatim and, because ``bool`` is an ``int``,
        read as 1.0 wherever it was not re-normalized (#213).

        Args:
            metrics: The CVE's ``metrics`` block, as decoded from the response.

        Returns:
            Tuple of normalized CVSS score and source severity string, either
            of which is None when NVD did not supply a usable one.
        """
        metrics_map = _payload_mapping(metrics)
        # CVSS 2.0 keeps baseSeverity on the metric, not inside cvssData.
        for key, severity_on_metric in (
            ("cvssMetricV31", False),
            ("cvssMetricV30", False),
            ("cvssMetricV2", True),
        ):
            entries = _payload_sequence(metrics_map.get(key))
            if not entries:
                continue
            metric = _payload_mapping(entries[0])
            cvss_data = _payload_mapping(metric.get("cvssData"))
            severity_source = metric if severity_on_metric else cvss_data
            return (
                normalize_cvss_score(cvss_data.get("baseScore")),
                _payload_optional_str(severity_source.get("baseSeverity")),
            )

        return None, None


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

    def lookup(self, package_name: str, ecosystem: str) -> SourceLookup:
        """Ask the GitHub Advisory Database about a package.

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
            # GitHub's ``SecurityAdvisoryEcosystem`` enum has no member for
            # this ecosystem, so there is no query to send. An abstention.
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

        # Make the request with retry mechanism
        max_retries = 3
        backoff_factor = 0.5
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        # See OSVSource.get_vulnerabilities: the decoded body is normalized
        # after the loop so a shape error in an advisory cannot be caught by
        # the broad handler below and reported as "no advisories" (#217).
        payload: object = None
        answered = False

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

                if not isinstance(data, dict):
                    logger.debug(
                        f"Ignoring non-object GitHub Advisory response for "
                        f"{package_name}: {type(data).__name__}"
                    )
                    return SourceLookup.failed("unreadable response body")

                if "errors" in data:
                    error_message = str(data.get("errors", []))
                    logger.debug(f"GraphQL errors: {error_message}")

                    # Check for rate limiting errors
                    if "rate limit" in error_message.lower() and retry < max_retries:
                        # This is a rate limit error, retry with backoff
                        continue

                    # A GraphQL error block is a refusal, not an answer. It used
                    # to leave here as the empty list and be counted as a clean
                    # package (#219).
                    return SourceLookup.failed("GraphQL error response")

                payload = data
                answered = True
                break

            except requests.HTTPError as e:
                # Don't retry on 4xx client errors (except 429 Too Many Requests)
                status_code = _http_error_status(e)
                is_client_error = status_code is not None and 400 <= status_code < 500
                is_rate_limited = status_code == 429
                if is_client_error and not is_rate_limited:
                    logger.debug(
                        f"Client error ({status_code}) fetching "
                        f"GitHub Advisory data for {package_name}: {e}"
                    )
                    return SourceLookup.failed(f"HTTP {status_code}")

                if retry == max_retries:
                    logger.debug(f"Max retries reached for GitHub Advisory query: {e}")
                    return SourceLookup.failed("retries exhausted after HTTP error")

                logger.debug(
                    f"HTTP error fetching GitHub Advisory data for {package_name} "
                    f"(attempt {retry + 1}/{max_retries + 1}): {e}"
                )

            except (requests.ConnectionError, requests.Timeout) as e:
                if retry == max_retries:
                    logger.debug(f"Max retries reached for GitHub Advisory query: {e}")
                    return SourceLookup.failed("unreachable")

                logger.debug(
                    f"Connection error fetching GitHub Advisory data for "
                    f"{package_name} (attempt {retry + 1}/{max_retries + 1}): {e}"
                )

            except Exception as e:
                logger.debug(
                    f"Unexpected error fetching GitHub Advisory data for "
                    f"{package_name}: {e}"
                )
                return SourceLookup.failed(f"unexpected error: {type(e).__name__}")

        if not answered:
            return SourceLookup.failed("retries exhausted")

        vulnerabilities = _payload_sequence(
            _payload_mapping(
                _payload_mapping(_payload_mapping(payload).get("data")).get(
                    "securityVulnerabilities"
                )
            ).get("nodes")
        )
        return SourceLookup.answered(self._normalize_results(vulnerabilities))

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

        for vuln_entry in results:
            vuln = _payload_mapping(vuln_entry)
            advisory = _payload_mapping(vuln.get("advisory"))

            # Extract CVSS score. Normalized here, not just at annotation time:
            # GitHub's `cvss.score` is a payload field like any other, and a
            # `true` in it read as 1.0 anywhere the raw record was consumed.
            cvss_score = _github_cvss_score(advisory.get("cvss"))

            # Extract fixed version
            fixed_versions = []
            version = _payload_str(
                _payload_mapping(vuln.get("firstPatchedVersion")).get("identifier")
            )
            if version:
                fixed_versions.append(version)

            affected = affected_ranges.affected_versions_from_github_range(
                vuln.get("vulnerableVersionRange")
            )

            # `.upper()` on whatever the payload held raised AttributeError for
            # a null or boolean severity, and the broad handler upstream turned
            # that into "this package has no advisories".
            severity = _payload_str(vuln.get("severity"))

            normalized.append(
                {
                    "id": _payload_str(advisory.get("id")),
                    "source": "GitHub Advisory",
                    "published": _payload_str(advisory.get("publishedAt")),
                    "summary": _payload_str(
                        advisory.get("summary"), "No summary available"
                    ),
                    "details": _payload_str(advisory.get("description")),
                    "severity": severity.upper(),
                    "normalized_severity": normalize_vulnerability_severity(
                        severity, cvss_score
                    ),
                    "cvss_score": cvss_score,
                    "withdrawn": _withdrawn_timestamp(advisory.get("withdrawnAt")),
                    "confidence": "HIGH",
                    "fixed_versions": fixed_versions,
                    "affected_versions": (
                        None if affected.is_empty() else affected.to_payload()
                    ),
                    "references": _payload_reference_urls(advisory.get("references")),
                }
            )

        return normalized


def _github_cvss_score(cvss: object) -> Optional[float]:
    """Return an advisory's CVSS base score, or None when GitHub assigned none.

    GitHub's GraphQL ``cvss`` block is non-nullable, so an advisory with no
    CVSS vector still answers with a ``score``, and the score it answers with
    is ``0.0``. That is a sentinel wearing the type of a measurement: the
    lodash advisory GHSA-p6mc-m468-83gg is severity HIGH with
    ``{"score": 0, "vectorString": null}``, and copied out verbatim it says a
    high-severity advisory was scored at the bottom of the scale.

    ``vectorString`` is the tell — it is null exactly when no vector was
    assigned — so a zero without one is unmeasured, and a zero with one is a
    real (if unusual) score and is kept.

    Args:
        cvss: The advisory's raw ``cvss`` block.

    Returns:
        The base score, or None when GitHub published no CVSS for the advisory.
    """
    block = _payload_mapping(cvss)
    score = normalize_cvss_score(block.get("score"))
    if score == 0.0 and not _payload_str(block.get("vectorString")).strip():
        return None
    return score


def _payload_str(value: object, default: str = "") -> str:
    """Return a registry payload field as text, or ``default`` if it is not.

    Every normalizer reads out of a ``Dict[str, object]`` decoded straight from
    a registry response, so a field an ecosystem's schema declares as a string
    can still arrive as ``true``, a number, or null. Two things went wrong when
    it did: ``.upper()``/``.lower()`` raised AttributeError inside a broad
    ``except Exception`` that turned the whole lookup into "no advisories", and
    the value was copied verbatim into a normalized record, so a JSON ``true``
    surfaced in a field every consumer renders as a string (#213).
    """
    return value if isinstance(value, str) else default


def _payload_optional_str(value: object) -> Optional[str]:
    """Return a registry payload field as text, or None if it is not text."""
    return value if isinstance(value, str) else None


def _payload_mapping(value: object) -> Dict[str, Any]:
    """Return a registry payload field as a mapping, or an empty one."""
    return value if isinstance(value, dict) else {}


def _payload_sequence(value: object) -> List[Any]:
    """Return a registry payload field as a list, or an empty one."""
    return value if isinstance(value, list) else []


def _payload_reference_urls(value: object) -> List[str]:
    """Return the reference URLs a payload lists, dropping non-string entries.

    ``[ref.get("url", "") for ref in ...]`` assumed every entry was a mapping
    and every URL a string; neither is guaranteed by a decoded JSON body.
    """
    urls = []
    for reference in _payload_sequence(value):
        url = _payload_str(_payload_mapping(reference).get("url"))
        if url:
            urls.append(url)
    return urls


def _withdrawn_timestamp(value: object) -> bool:
    """Return whether a payload's withdrawal timestamp says it was withdrawn.

    OSV's ``withdrawn`` and GitHub's ``withdrawnAt`` are both RFC 3339 strings,
    absent when the advisory stands. The previous ``bool(...)`` accepted any
    truthy JSON value, so a payload carrying ``"withdrawn": true`` — or ``1``,
    or a non-empty object — suppressed a real advisory from the score without
    ever having named a withdrawal date. Requiring the timestamp its schema
    promises fails the other way: an unparseable value leaves the advisory
    counted (#213).
    """
    return bool(_payload_str(value).strip())


def normalize_cvss_score(score: object) -> Optional[float]:
    """Normalize a CVSS score to a float between 0 and 10.

    The parameter is ``object`` because that is the real contract: every caller
    reads this value straight out of a registry payload (``Dict[str, object]``),
    so it can be any JSON value — including a dict, which the previous
    ``Union[float, str, None]`` annotation claimed was impossible while the
    tests asserted it returned ``None`` (#202).

    Args:
        score: CVSS score from a registry payload — any JSON value.

    Returns:
        Normalized score as a float, or None if it is not a score in 0-10.
    """
    if isinstance(score, str):
        try:
            score = float(score.strip())
        except ValueError:
            return None

    # `bool` is an `int` subclass, so `true` in a payload would otherwise
    # normalize to 1.0 and be reported as a LOW finding. A boolean is not a
    # score.
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None

    value = float(score)
    if 0 <= value <= 10:
        return value

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
    """Return whether an already-normalized record is a withdrawn advisory.

    A bool is honored here, unlike in :func:`_withdrawn_timestamp`, because
    this reads a record the normalizers wrote and they write a bool. The
    distinction is the layer: registry payloads state a withdrawal date,
    normalized records state a decision.
    """
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

    Shares :func:`advisory_cache_key` with the disk cache. The previous
    ``f"{ecosystem.lower()}:{package_name.lower()}"`` collided the same two
    ways the disk cache did, and the case collision was worse here because
    lowercasing is unconditional: npm's ``Foo`` and ``foo`` shared one
    in-memory entry on every platform, not just the case-insensitive ones. The
    ``:`` separator collided maven coordinates as well, where the package name
    is itself ``group:artifact`` — ``("b:c", "a")`` and ``("c", "a:b")`` both
    keyed ``a:b:c`` (#212).

    Case-exact keying means ``Flask`` and ``flask`` now occupy two entries on
    registries that fold case. That costs a lookup, where the collision cost
    correctness.

    Args:
        package_name: Package name
        ecosystem: Package ecosystem

    Returns:
        Cache key
    """
    return advisory_cache_key(package_name, ecosystem)


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


@dataclass(frozen=True)
class AggregateOutcome:
    """What a whole package's advisory lookup established, across all sources."""

    #: Advisories from every source that answered, deduplicated by id. A floor
    #: rather than a total whenever ``state`` is ``PARTIAL``.
    vulnerabilities: List[Dict[str, Any]]
    #: The measurement state to record on the dependency.
    state: AdvisoryLookupState
    #: Names of the sources that were asked and did not answer.
    sources_unavailable: Tuple[str, ...]

    @property
    def cacheable(self) -> bool:
        """Whether this result may be written to the advisory cache.

        Only a ``COMPLETE`` lookup may. Caching anything weaker is what turned
        a transient OSV outage into a wrong answer that survived the outage:
        the empty list went to disk and was served back, as a measurement,
        until the TTL expired (#219).

        Returns:
            True only for a complete lookup.
        """
        return self.state is AdvisoryLookupState.COMPLETE


def combine_source_lookups(
    lookups: Sequence[Tuple[VulnerabilitySource, SourceLookup]],
) -> AggregateOutcome:
    """Fold every source's answer into one outcome, and say how good it is.

    **The partial-failure rule, stated once.** A source that failed is not the
    same as a source that answered "none", and the aggregate has to say which
    of those it is built from. What it does *not* do is treat every failure
    identically, because the sources are not identical:

    * A failure in a source that ``establishes_absence`` (OSV, GitHub Advisory)
      destroys the claim "this package has no advisories". Those sources are
      asked about a package by identity, in an ecosystem, and their silence is
      an answer — so their absence is the absence of an answer.
    * A failure in NVD does not, because NVD is reached here by keyword search
      over CPE strings. It can add a CVE nobody else listed; it cannot
      establish that there is nothing to list. A slow NVD therefore degrades
      completeness, not measuredness.
    * A *finding* survives any failure. Once an advisory has been found, no
      outage elsewhere un-finds it, so a lookup that found something is
      reported rather than suppressed — as a floor, marked ``PARTIAL``.

    The result: a package is never called clean because two sources of three
    answered, and a scan is never made unmeasured because NVD was slow.
    Anything short of ``COMPLETE`` is excluded from the cache regardless, since
    an incomplete advisory set read back later is indistinguishable from a
    complete one.

    Args:
        lookups: Each source paired with what it answered, in query order.

    Returns:
        The combined outcome.
    """
    seen_ids = set()
    unique_vulnerabilities: List[Dict[str, Any]] = []
    answered = False
    unavailable: List[str] = []
    absence_broken = False

    for source, lookup in lookups:
        if lookup.state is SourceState.ABSTAINED:
            logger.debug(f"{source.name} abstained: {lookup.detail}")
            continue
        if lookup.state is SourceState.FAILED:
            logger.warning(
                f"{source.name} did not answer ({lookup.detail}); its silence "
                "is not evidence that the package is clean"
            )
            unavailable.append(source.name)
            absence_broken = absence_broken or source.establishes_absence
            continue

        answered = True
        for vuln in lookup.vulnerabilities:
            vuln_id = vuln.get("id", "")
            if vuln_id and vuln_id not in seen_ids:
                seen_ids.add(vuln_id)
                unique_vulnerabilities.append(vuln)

    if not unavailable:
        state = (
            AdvisoryLookupState.COMPLETE
            if answered
            else AdvisoryLookupState.NOT_ATTEMPTED
        )
    elif unique_vulnerabilities or not absence_broken:
        state = AdvisoryLookupState.PARTIAL
    else:
        state = AdvisoryLookupState.FAILED

    return AggregateOutcome(
        vulnerabilities=unique_vulnerabilities,
        state=state,
        sources_unavailable=tuple(unavailable),
    )


def _lookup_one_source(
    source: VulnerabilitySource, package_name: str, ecosystem: str
) -> SourceLookup:
    """Ask one source, converting an escaping exception into a failure.

    The aggregator used to wrap this call in ``except Exception: pass``, so a
    source that raised contributed nothing — exactly like a source that
    answered "clean". Same shape, opposite meaning (#219).

    Args:
        source: The source to ask.
        package_name: Name of the package.
        ecosystem: Package ecosystem.

    Returns:
        The source's answer, or a failure naming what went wrong.
    """
    try:
        logger.info(f"Checking {source.name} for vulnerabilities in {package_name}")
        return source.lookup(package_name, ecosystem)
    except Exception as e:
        logger.error(f"Error fetching vulnerabilities from {source.name}: {e}")
        return SourceLookup.failed(f"raised {type(e).__name__}")


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
        dependency.record_advisory_lookup(
            AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=()
        )
        return dependency, []

    # Check cache first. Since #219 only a COMPLETE lookup is ever written, so
    # a cache hit is a complete measurement by construction.
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
    sources: List[VulnerabilitySource] = [
        OSVSource(enabled=True),
        GitHubAdvisorySource(api_token=github_token, enabled=github_token is not None),
        NVDSource(api_key=nvd_api_key, enabled=True),
    ]

    outcome = combine_source_lookups(
        [
            (source, _lookup_one_source(source, package_name, ecosystem))
            for source in sources
        ]
    )

    # Cache only a complete answer. An incomplete one read back tomorrow is
    # indistinguishable from a complete one, which is how the outage outlived
    # itself (#219).
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


def _update_dependency_with_vulnerabilities(
    dependency: DependencyMetadata,
    vulnerabilities: List[Dict[str, object]],
    minimum_severity: str = DEFAULT_MINIMUM_SEVERITY_FOR_SCORING,
    *,
    lookup_state: AdvisoryLookupState = AdvisoryLookupState.COMPLETE,
    sources_unavailable: Sequence[str] = (),
) -> DependencyMetadata:
    """Update dependency metadata with vulnerability information.

    Args:
        dependency: Dependency metadata
        vulnerabilities: List of vulnerability data
        minimum_severity: Minimum severity that counts toward scoring
        lookup_state: What the sources established. A lookup that established
            nothing writes no counts at all — a ``0`` here presents as measured
            and is the whole of #219 — and only records why.
        sources_unavailable: Names of the sources that did not answer. Required
            to be non-empty for the degraded states; see
            ``DependencyMetadata.record_advisory_lookup``.

    Returns:
        Updated dependency metadata
    """
    dependency.record_advisory_lookup(
        lookup_state, sources_unavailable=sources_unavailable
    )

    # Initialize security metrics if not present
    if not dependency.security_metrics:
        from ..models import SecurityMetrics

        dependency.security_metrics = SecurityMetrics()

    if lookup_state in ADVISORY_LOOKUP_UNMEASURED:
        # Nothing was established, so nothing is written. Leaving the counts at
        # None is the difference between "we looked and found none" and "we
        # could not look", and it is what keeps the exploit signal out of the
        # measured set instead of publishing a zero nobody measured.
        return dependency

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

    # Find maximum CVSS score. ``None`` is the unmeasured state and 0.0 is a
    # measurement: a CVSS of 0.0 and an INFO/NONE tier are both real answers
    # about how bad the counted advisories are. The accumulator used to start
    # at 0.0 and publish ``max_cvss if max_cvss > 0 else None``, so those
    # answers came out as "no CVSS was measured" — the same falsy-vs-absent
    # read #216 fixed one line above, in the guard on the per-advisory score
    # (#217). Only an advisory whose severity this code cannot read at all
    # leaves the maximum unmeasured.
    max_cvss: Optional[float] = None
    max_severity = None
    for vuln in counted_vulnerabilities:
        candidate = normalize_cvss_score(vuln.get("cvss_score"))
        if candidate is None:
            # No CVSS: derive from the tier, but only from a tier that is a
            # statement about severity. ``severity_to_score`` answers 0.0 both
            # for NONE and for anything it does not recognize, so UNKNOWN would
            # otherwise fabricate a measured zero.
            tier = _get_string(vuln, "normalized_severity")
            if tier in SEVERITY_ORDER:
                candidate = severity_to_score(tier)
        if candidate is not None:
            max_cvss = candidate if max_cvss is None else max(max_cvss, candidate)
        severity = _get_string(vuln, "normalized_severity")
        if severity and (
            max_severity is None
            or SEVERITY_ORDER[severity] > SEVERITY_ORDER[max_severity]
        ):
            max_severity = severity

    dependency.security_metrics.max_cvss_score = max_cvss
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
