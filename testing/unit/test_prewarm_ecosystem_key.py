"""Tests that the OSV prewarm keys on the same ecosystem the read path uses.

Analyzers overwrite a dependency's ecosystem (a ``pyproject.toml`` dep becomes
``python``), and the vulnerability cache is keyed on that post-analysis value.
If the prewarm wrote under the raw manifest ecosystem (``pyproject``), every
such dependency would miss on read and re-query OSV despite the prewarm.
"""

from typing import List, Tuple

from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.org_scan.models import DependencyKey, canonical_ecosystem
from dependency_risk_profiler.org_scan.pipeline import (
    ExistingDependencyProfiler,
    VulnerabilityOptions,
)
from dependency_risk_profiler.vulnerabilities.aggregator import (
    get_cache_key,
    infer_ecosystem,
)


def _osv_only_options() -> VulnerabilityOptions:
    """OSV-only options, the one configuration where prewarm runs."""
    return VulnerabilityOptions(
        enable_osv=True,
        enable_nvd=False,
        enable_github_advisory=False,
    )


def _capture_prewarm(monkeypatch) -> "dict[str, List[Tuple[str, str]]]":
    """Patch the querybatch prewarm to record the (name, ecosystem) pairs."""
    captured: dict[str, List[Tuple[str, str]]] = {}

    async def fake_prewarm(package_ecosystems) -> None:
        captured["pairs"] = list(package_ecosystems)

    monkeypatch.setattr(
        "dependency_risk_profiler.vulnerabilities.osv_batch."
        "prewarm_osv_querybatch_cache",
        fake_prewarm,
    )
    return captured


def test_prewarm_key_matches_python_analyzer_read_key(monkeypatch) -> None:
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


def test_prewarm_normalizes_pyproject_but_preserves_others(monkeypatch) -> None:
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
