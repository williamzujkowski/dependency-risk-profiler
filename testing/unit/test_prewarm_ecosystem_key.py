"""Tests that the OSV prewarm keys on the same ecosystem the read path uses.

Analyzers overwrite a dependency's ecosystem (a ``pyproject.toml`` dep becomes
``python``), and the vulnerability cache is keyed on that post-analysis value.
If the prewarm wrote under the raw manifest ecosystem (``pyproject``), every
such dependency would miss on read and re-query OSV despite the prewarm.
"""

from typing import Iterable, List, Tuple

import pytest

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.org_scan.models import DependencyKey, canonical_ecosystem
from dependency_risk_profiler.org_scan.pipeline import (
    ExistingDependencyProfiler,
    VulnerabilityOptions,
)
from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.parsers.registry import EcosystemRegistry
from dependency_risk_profiler.vulnerabilities.aggregator import (
    get_cache_key,
    infer_ecosystem,
)

# Every ecosystem a manifest parser can emit, paired with the single network
# entry point of the analyzer it dispatches to. Stubbing that method makes the
# read-side derivation deterministic and offline.
MANIFEST_ECOSYSTEM_FETCHERS = (
    ("nodejs", "_get_npm_package_info"),
    ("python", "_get_pypi_package_info"),
    ("pyproject", "_get_pypi_package_info"),
    ("golang", "_get_latest_version"),
    ("cargo", "_get_crate_info"),
    ("rubygems", "_get_gem_info"),
    ("composer", "_get_latest_release"),
    ("nuget", "_get_latest_version"),
    ("maven", "_get_latest_version"),
    # Gradle declares Maven coordinates and dispatches to the Maven analyzer,
    # which stamps them "maven"; the prewarm therefore has to canonicalize
    # "gradle" -> "maven" or it writes a key nothing reads (#101).
    ("gradle", "_get_latest_version"),
)


def _osv_only_options() -> VulnerabilityOptions:
    """OSV-only options, the one configuration where prewarm runs."""
    return VulnerabilityOptions(
        enable_osv=True,
        enable_nvd=False,
        enable_github_advisory=False,
    )


def _capture_prewarm(
    monkeypatch: pytest.MonkeyPatch,
) -> "dict[str, List[Tuple[str, str]]]":
    """Patch the querybatch prewarm to record the (name, ecosystem) pairs."""
    captured: dict[str, List[Tuple[str, str]]] = {}

    async def fake_prewarm(package_ecosystems: Iterable[Tuple[str, str]]) -> None:
        captured["pairs"] = list(package_ecosystems)

    monkeypatch.setattr(
        "dependency_risk_profiler.vulnerabilities.osv_batch."
        "prewarm_osv_querybatch_cache",
        fake_prewarm,
    )
    return captured


def test_prewarm_key_matches_python_analyzer_read_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pyproject dep is prewarmed under the same key the read later uses."""
    captured = _capture_prewarm(monkeypatch)

    profiler = ExistingDependencyProfiler({}, _osv_only_options())
    key = DependencyKey("pyproject", "flask", "3.0.0")
    metadata = DependencyMetadata(name="flask", installed_version="3.0.0")
    profiler._prewarm_osv_batch_cache([(key, metadata)])

    ((write_name, write_ecosystem),) = captured["pairs"]
    assert (write_name, write_ecosystem) == ("flask", "python")

    # Derive the read-side ecosystem exactly as profiling would: run the same
    # analyzer with the network stubbed out and read what it recorded.
    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem("pyproject")
    assert analyzer is not None
    monkeypatch.setattr(analyzer, "_get_pypi_package_info", lambda name: None)
    analyzed = analyzer.analyze(
        {"flask": DependencyMetadata(name="flask", installed_version="3.0.0")}
    )["flask"]
    read_ecosystem = infer_ecosystem(analyzed)

    assert read_ecosystem == "python"
    assert get_cache_key(write_name, write_ecosystem) == get_cache_key(
        "flask", read_ecosystem
    )


def test_prewarm_normalizes_pyproject_but_preserves_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only pyproject is remapped; other ecosystems key on their own name."""
    captured = _capture_prewarm(monkeypatch)

    pending = [
        (
            DependencyKey("pyproject", "flask", "3.0.0"),
            DependencyMetadata("flask", "3.0.0"),
        ),
        (
            DependencyKey("python", "requests", "2.31.0"),
            DependencyMetadata("requests", "2.31.0"),
        ),
        (
            DependencyKey("rubygems", "rails", "7.0.0"),
            DependencyMetadata("rails", "7.0.0"),
        ),
        (
            DependencyKey("cargo", "serde", "1.0.0"),
            DependencyMetadata("serde", "1.0.0"),
        ),
    ]
    ExistingDependencyProfiler({}, _osv_only_options())._prewarm_osv_batch_cache(
        pending
    )

    assert captured["pairs"] == [
        ("flask", "python"),
        ("requests", "python"),
        ("rails", "rubygems"),
        ("serde", "cargo"),
    ]
    # Every prewarm ecosystem is the canonical (post-analysis) one.
    for (key, _metadata), (_, ecosystem) in zip(pending, captured["pairs"]):
        assert ecosystem == canonical_ecosystem(key.ecosystem)


def test_fetcher_table_covers_every_registered_parser_ecosystem() -> None:
    """#116: the parity table below must track the parser registry.

    A new manifest parser adds an ecosystem the prewarm can emit; if it is not
    listed here its cache-key parity goes unchecked.
    """
    BaseParser._initialize_registry()
    assert set(EcosystemRegistry.get_available_ecosystems()) == {
        ecosystem for ecosystem, _fetcher in MANIFEST_ECOSYSTEM_FETCHERS
    }


@pytest.mark.parametrize("manifest_ecosystem,fetcher", MANIFEST_ECOSYSTEM_FETCHERS)
def test_prewarm_key_matches_read_key_for_every_ecosystem(
    manifest_ecosystem: str, fetcher: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#116: prewarm writes and the profiling read agree on the cache key.

    Generalizes the pyproject case above to every parser ecosystem: the write
    key (``canonical_ecosystem`` of the manifest ecosystem) and the read key
    (``infer_ecosystem`` of the analyzed dependency) must be the same string, or
    the prewarm silently buys nothing and every dependency re-queries OSV.
    """
    captured = _capture_prewarm(monkeypatch)

    profiler = ExistingDependencyProfiler({}, _osv_only_options())
    key = DependencyKey(manifest_ecosystem, "pkg", "1.0.0")
    profiler._prewarm_osv_batch_cache(
        [(key, DependencyMetadata(name="pkg", installed_version="1.0.0"))]
    )
    ((write_name, write_ecosystem),) = captured["pairs"]

    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(manifest_ecosystem)
    assert analyzer is not None
    analyzer.clone_repos = False
    monkeypatch.setattr(analyzer, fetcher, lambda name: None)
    analyzed = analyzer.analyze(
        {"pkg": DependencyMetadata(name="pkg", installed_version="1.0.0")}
    )["pkg"]

    assert get_cache_key(write_name, write_ecosystem) == get_cache_key(
        "pkg", infer_ecosystem(analyzed)
    )
