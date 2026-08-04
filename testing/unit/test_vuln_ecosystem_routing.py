"""Tests that vulnerability lookups use the dependency's real ecosystem."""

from typing import Dict, List, Tuple
from unittest import mock

import pytest

from dependency_risk_profiler.analyzers.golang import GoAnalyzer
from dependency_risk_profiler.analyzers.nodejs import NodeJSAnalyzer
from dependency_risk_profiler.analyzers.python import PythonAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.vulnerabilities import aggregator_async
from dependency_risk_profiler.vulnerabilities.aggregator import OSVSource, SourceLookup


@pytest.mark.parametrize(
    "analyzer_cls, fetch_method, expected_ecosystem",
    [
        (NodeJSAnalyzer, "_get_npm_package_info", "nodejs"),
        (GoAnalyzer, "_get_latest_version", "golang"),
        (PythonAnalyzer, "_get_pypi_package_info", "python"),
    ],
)
def test_analyzer_declares_osv_ecosystem(
    analyzer_cls: type, fetch_method: str, expected_ecosystem: str
) -> None:
    """Every analyzer stamps additional_info["ecosystem"] for OSV routing.

    Deterministic routing is the fix for npm/Go deps whose repo URL lacks the
    magic substrings and would otherwise default to PyPI and return no
    advisories.
    """
    analyzer = analyzer_cls()
    analyzer.clone_repos = False  # no network clone in a unit test
    dep = DependencyMetadata(name="pkg", installed_version="1.0.0")
    with mock.patch.object(analyzer, fetch_method, return_value=None):
        result = analyzer.analyze({"pkg": dep})
    assert result["pkg"].additional_info["ecosystem"] == expected_ecosystem


def test_normalize_ecosystem_covers_all_supported_ecosystems() -> None:
    """OSV ecosystem mapping includes cargo (was missing) and the others."""
    osv = OSVSource()
    assert osv._normalize_ecosystem("cargo") == "crates.io"
    assert osv._normalize_ecosystem("nodejs") == "npm"
    assert osv._normalize_ecosystem("python") == "PyPI"
    assert osv._normalize_ecosystem("golang") == "Go"


@pytest.mark.parametrize(
    "additional_info, repo_url, expected",
    [
        ({"ecosystem": "cargo"}, "https://github.com/x/y", "cargo"),
        ({}, "https://npmjs.com/package/x", "nodejs"),
        ({}, "https://github.com/golang/go", "golang"),
        ({}, "", ""),
        ({}, "https://example.com/some/pkg", ""),
    ],
)
def test_infer_ecosystem_dedup_helper(
    additional_info: Dict[str, str], repo_url: str, expected: str
) -> None:
    """Prefer the declared ecosystem, else a URL guess that fails closed (#109).

    One shared implementation now backs both the sync and async aggregators.
    """
    from dependency_risk_profiler.vulnerabilities.aggregator import infer_ecosystem

    dep = DependencyMetadata(
        name="pkg",
        installed_version="1.0.0",
        repository_url=repo_url,
        additional_info=additional_info,
    )
    assert infer_ecosystem(dep) == expected


def test_cargo_and_go_reach_github_advisory_and_nvd() -> None:
    """Cargo/Go resolve in the GitHub Advisory and NVD tables (#76/#77).

    The strings analyzers actually emit ("cargo", "go") must map in every source
    table, not just OSV — a missing key silently skips that source (#66 class).
    """
    from dependency_risk_profiler.vulnerabilities.aggregator import (
        GitHubAdvisorySource,
        NVDSource,
    )

    assert GitHubAdvisorySource()._normalize_ecosystem("cargo") == "RUST"
    assert NVDSource()._get_cpe_prefix("cargo") != ""
    assert NVDSource()._get_cpe_prefix("go") != ""


def test_vuln_lookup_uses_declared_ecosystem_not_url_heuristic() -> None:
    """A dep's additional_info ecosystem drives OSV, not the repo-URL guess."""
    recorded: List[Tuple[str, str]] = []

    async def _fake(self: object, package_name: str, ecosystem: str) -> SourceLookup:
        recorded.append((package_name, ecosystem))
        return SourceLookup.answered([])

    # A github.com URL with no "npm"/"node" would previously default to python.
    dep = DependencyMetadata(
        name="lodash",
        installed_version="4.17.4",
        repository_url="https://github.com/lodash/lodash",
        additional_info={"ecosystem": "nodejs"},
    )
    with (
        mock.patch.object(aggregator_async.AsyncOSVSource, "lookup_async", _fake),
        mock.patch.object(aggregator_async, "get_cached_data", return_value=None),
        mock.patch.object(aggregator_async, "cache_data"),
    ):
        aggregator_async.aggregate_vulnerability_data_async(
            {"lodash": dep},
            api_keys={},
            enable_osv=True,
            enable_nvd=False,
            enable_github=False,
            minimum_severity="INFO",
        )

    assert recorded == [("lodash", "nodejs")]


def test_vuln_lookup_falls_back_to_url_heuristic_when_ecosystem_absent() -> None:
    """Without a declared ecosystem, the URL heuristic still applies."""
    recorded: List[Tuple[str, str]] = []

    async def _fake(self: object, package_name: str, ecosystem: str) -> SourceLookup:
        recorded.append((package_name, ecosystem))
        return SourceLookup.answered([])

    dep = DependencyMetadata(
        name="somepkg",
        installed_version="1.0.0",
        repository_url="https://npmjs.com/package/somepkg",
    )
    with (
        mock.patch.object(aggregator_async.AsyncOSVSource, "lookup_async", _fake),
        mock.patch.object(aggregator_async, "get_cached_data", return_value=None),
        mock.patch.object(aggregator_async, "cache_data"),
    ):
        aggregator_async.aggregate_vulnerability_data_async(
            {"somepkg": dep},
            api_keys={},
            enable_osv=True,
            enable_nvd=False,
            enable_github=False,
            minimum_severity="INFO",
        )

    assert recorded == [("somepkg", "nodejs")]
