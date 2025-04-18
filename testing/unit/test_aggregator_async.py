"""Tests for async vulnerability aggregator."""

import asyncio
import json
import sys
from unittest.mock import Mock, patch

import pytest

try:
    from aioresponses import aioresponses
except ImportError:
    aioresponses = None

# Mark tests as async
async_test = pytest.mark.asyncio

from dependency_risk_profiler.models import DependencyMetadata, SecurityMetrics
from dependency_risk_profiler.vulnerabilities.aggregator_async import (
    AsyncGitHubAdvisorySource,
    AsyncHTTPClient,
    AsyncNVDSource,
    AsyncOSVSource,
    aggregate_vulnerabilities_for_package_async,
    aggregate_vulnerability_data_async,
    aggregate_vulnerability_data_async_impl,
)


@pytest.fixture
def mock_aioresponse():
    """Fixture for mocking aiohttp responses."""
    with aioresponses() as mock:
        yield mock


@pytest.fixture
async def osv_source():
    """Fixture for AsyncOSVSource."""
    source = AsyncOSVSource()
    yield source
    await source.http_client.close()


@pytest.fixture
async def nvd_source():
    """Fixture for AsyncNVDSource."""
    source = AsyncNVDSource(api_key="test_key")
    yield source
    await source.http_client.close()


@pytest.fixture
async def github_source():
    """Fixture for AsyncGitHubAdvisorySource."""
    source = AsyncGitHubAdvisorySource(api_token="test_token")
    yield source
    await source.http_client.close()


@pytest.fixture
def test_dependency():
    """Fixture for a test dependency."""
    dep = DependencyMetadata(
        name="test-package",
        installed_version="1.0.0",
        repository_url="https://github.com/test/test-package",
    )
    dep.security_metrics = SecurityMetrics()
    return dep


class TestAsyncVulnerabilitySources:
    """Tests for async vulnerability sources."""

    @async_test
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.AsyncOSVSource._normalize_results"
    )
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.AsyncHTTPClient.post"
    )
    async def test_osv_source_get_vulnerabilities(
        self, mock_post, mock_normalize, osv_source
    ):
        """HYPOTHESIS: AsyncOSVSource should retrieve and normalize vulnerabilities."""
        # Arrange
        package_name = "test-package"
        ecosystem = "npm"

        # Mock the HTTP response and normalization
        mock_response = {"vulns": [{"id": "OSV-2023-123"}]}
        mock_post.return_value = mock_response

        expected_result = [
            {
                "id": "OSV-2023-123",
                "source": "OSV",
                "severity": "HIGH",
                "cvss_score": "7.5",
                "fixed_versions": ["1.0.1"],
                "references": ["https://example.com/vuln/123"],
            }
        ]
        mock_normalize.return_value = expected_result

        # Act
        vulnerabilities = await osv_source.get_vulnerabilities_async(
            package_name, ecosystem
        )

        # Assert
        assert vulnerabilities == expected_result
        mock_post.assert_called_once()
        mock_normalize.assert_called_once_with(mock_response["vulns"])

    @async_test
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.AsyncHTTPClient.post"
    )
    async def test_osv_source_empty_response(self, mock_post, osv_source):
        """HYPOTHESIS: AsyncOSVSource should handle empty responses."""
        # Arrange
        package_name = "test-package"
        ecosystem = "npm"

        # Mock empty response
        mock_post.return_value = {"vulns": []}

        # Act
        vulnerabilities = await osv_source.get_vulnerabilities_async(
            package_name, ecosystem
        )

        # Assert
        assert len(vulnerabilities) == 0
        mock_post.assert_called_once()

    @async_test
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.AsyncNVDSource._normalize_results"
    )
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.AsyncHTTPClient.get"
    )
    async def test_nvd_source_get_vulnerabilities(
        self, mock_get, mock_normalize, nvd_source
    ):
        """HYPOTHESIS: AsyncNVDSource should retrieve and normalize vulnerabilities."""
        # Arrange
        package_name = "test-package"
        ecosystem = "nodejs"

        # Mock the HTTP response and normalization
        mock_response = {"vulnerabilities": [{"cve": {"id": "CVE-2023-12345"}}]}
        mock_get.return_value = mock_response

        expected_result = [
            {
                "id": "CVE-2023-12345",
                "source": "NVD",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "references": ["https://example.com/cve/12345"],
            }
        ]
        mock_normalize.return_value = expected_result

        # Act
        vulnerabilities = await nvd_source.get_vulnerabilities_async(
            package_name, ecosystem
        )

        # Assert
        assert vulnerabilities == expected_result
        mock_get.assert_called_once()
        mock_normalize.assert_called_once_with(mock_response["vulnerabilities"])

    @async_test
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.AsyncGitHubAdvisorySource._normalize_results"
    )
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.AsyncHTTPClient.post"
    )
    async def test_github_source_get_vulnerabilities(
        self, mock_post, mock_normalize, github_source
    ):
        """HYPOTHESIS: AsyncGitHubAdvisorySource should retrieve and normalize vulnerabilities."""
        # Arrange
        package_name = "test-package"
        ecosystem = "npm"

        # Mock the HTTP response and normalization
        mock_response = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [{"advisory": {"id": "GHSA-abcd-1234-5678"}}]
                }
            }
        }
        mock_post.return_value = mock_response

        expected_result = [
            {
                "id": "GHSA-abcd-1234-5678",
                "source": "GitHub Advisory",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "fixed_versions": ["1.0.1"],
                "references": ["https://github.com/advisories/GHSA-abcd-1234-5678"],
            }
        ]
        mock_normalize.return_value = expected_result

        # Act
        vulnerabilities = await github_source.get_vulnerabilities_async(
            package_name, ecosystem
        )

        # Assert
        assert vulnerabilities == expected_result
        mock_post.assert_called_once()
        mock_normalize.assert_called_once()


class TestAsyncVulnerabilityAggregation:
    """Tests for async vulnerability aggregation functions."""

    @async_test
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.AsyncOSVSource.get_vulnerabilities_async"
    )
    @patch("dependency_risk_profiler.vulnerabilities.aggregator_async.get_cached_data")
    @patch("dependency_risk_profiler.vulnerabilities.aggregator_async.cache_data")
    async def test_aggregate_vulnerabilities_for_package(
        self, mock_cache_data, mock_get_cached, mock_get_vulns, test_dependency
    ):
        """HYPOTHESIS: aggregate_vulnerabilities_for_package_async should gather vulnerabilities."""
        # Arrange
        mock_get_cached.return_value = None  # No cache hit

        # Mock vulnerability response
        mock_vulns = [
            {
                "id": "OSV-2023-123",
                "source": "OSV",
                "severity": "HIGH",
                "fixed_versions": ["1.0.1"],
            }
        ]
        mock_get_vulns.return_value = mock_vulns

        # Act
        updated_dep, vulnerabilities = (
            await aggregate_vulnerabilities_for_package_async(
                test_dependency,
                api_keys={},
                enable_osv=True,
                enable_nvd=False,
                enable_github=False,
            )
        )

        # Assert
        assert vulnerabilities == mock_vulns
        assert updated_dep.security_metrics.vulnerability_count == 1
        mock_cache_data.assert_called_once()
        mock_get_vulns.assert_called_once()

    @async_test
    @patch("dependency_risk_profiler.vulnerabilities.aggregator_async.get_cached_data")
    async def test_aggregate_vulnerabilities_with_cache(
        self, mock_get_cached, test_dependency
    ):
        """HYPOTHESIS: aggregate_vulnerabilities_for_package_async should use cache when available."""
        # Arrange
        cached_vulns = [
            {
                "id": "CACHED-123",
                "source": "OSV",
                "severity": "HIGH",
                "summary": "Cached vulnerability",
            }
        ]
        mock_get_cached.return_value = (cached_vulns, 12345.0)  # Cache hit

        # Act
        updated_dep, vulnerabilities = (
            await aggregate_vulnerabilities_for_package_async(
                test_dependency, api_keys={}, enable_osv=True
            )
        )

        # Assert
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]["id"] == "CACHED-123"
        assert updated_dep.security_metrics.vulnerability_count == 1

    @async_test
    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.aggregate_vulnerabilities_for_package_async"
    )
    async def test_aggregate_vulnerability_data_async_impl(self, mock_aggregate_pkg):
        """HYPOTHESIS: aggregate_vulnerability_data_async_impl should process multiple dependencies."""
        # Arrange
        deps = {
            "pkg1": DependencyMetadata(name="pkg1", installed_version="1.0.0"),
            "pkg2": DependencyMetadata(name="pkg2", installed_version="2.0.0"),
        }

        # Mock responses for each package
        def mock_side_effect(dep, *args, **kwargs):
            if dep.name == "pkg1":
                vulns = [{"id": "OSV-2023-1", "severity": "HIGH"}]
                updated = DependencyMetadata(name="pkg1", installed_version="1.0.0")
                updated.security_metrics = SecurityMetrics(vulnerability_count=1)
                return updated, vulns
            else:  # pkg2
                vulns = [{"id": "OSV-2023-2", "severity": "MEDIUM"}]
                updated = DependencyMetadata(name="pkg2", installed_version="2.0.0")
                updated.security_metrics = SecurityMetrics(vulnerability_count=1)
                return updated, vulns

        mock_aggregate_pkg.side_effect = mock_side_effect

        # Act
        updated_deps, vuln_counts = await aggregate_vulnerability_data_async_impl(
            deps,
            api_keys={},
            enable_osv=True,
            enable_nvd=False,
            enable_github=False,
            batch_size=2,
        )

        # Assert
        assert len(updated_deps) == 2
        assert updated_deps["pkg1"].security_metrics.vulnerability_count == 1
        assert updated_deps["pkg2"].security_metrics.vulnerability_count == 1
        assert "pkg1" in vuln_counts and "pkg2" in vuln_counts
        assert vuln_counts["pkg1"] == 1
        assert vuln_counts["pkg2"] == 1

    @patch(
        "dependency_risk_profiler.vulnerabilities.aggregator_async.aggregate_vulnerability_data_async_impl"
    )
    def test_aggregate_vulnerability_data_async(self, mock_impl, test_dependency):
        """HYPOTHESIS: aggregate_vulnerability_data_async should correctly invoke the async implementation."""
        # Arrange
        deps = {"pkg1": test_dependency}
        mock_impl.return_value = (deps, {"pkg1": 1})

        # Act
        updated_deps, vuln_counts = aggregate_vulnerability_data_async(
            deps, api_keys={"github": "token"}, enable_osv=True, enable_github=True
        )

        # Assert
        assert updated_deps == deps
        assert "pkg1" in vuln_counts
        assert vuln_counts["pkg1"] == 1
        mock_impl.assert_called_once()


@pytest.mark.benchmark
def test_aggregator_async_performance():
    """BENCHMARK: Async aggregator should be faster than synchronous version with many dependencies.

    SLA Requirements:
    - Should be at least 2x faster than synchronous version for 10+ dependencies
    """
    # Note: This is a more complex benchmark that would require timing
    # both the sync and async versions with real (or mocked) network calls
    pytest.skip(
        "Skipping complex performance benchmark - needs real timing and comparison"
    )
