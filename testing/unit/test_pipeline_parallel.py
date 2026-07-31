"""Concurrency tests for the parallel dependency profiler."""

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.org_scan.models import DependencyKey
from dependency_risk_profiler.org_scan.pipeline import (
    ExistingDependencyProfiler,
    VulnerabilityOptions,
)


def _no_vuln_options() -> VulnerabilityOptions:
    """Vulnerability options with every network source disabled."""
    return VulnerabilityOptions(
        enable_osv=False,
        enable_nvd=False,
        enable_github_advisory=False,
        github_token=None,
        nvd_api_key=None,
        minimum_severity_for_scoring="INFO",
        disable_cache=False,
        clear_cache=False,
    )


def _make_deps(count: int) -> dict:
    """Build ``count`` unknown-ecosystem deps (no analyzer, no network)."""
    deps = {}
    for i in range(count):
        key = DependencyKey("unknown-eco", f"pkg-{i}", "1.0.0")
        deps[key] = DependencyMetadata(name=f"pkg-{i}", installed_version="1.0.0")
    return deps


def test_profile_scores_every_dependency_in_parallel() -> None:
    """A parallel run scores each unique dependency exactly once."""
    deps = _make_deps(20)
    profiler = ExistingDependencyProfiler(
        {}, _no_vuln_options(), timeout=5, max_workers=8
    )
    profiles = profiler.profile(deps)
    assert set(profiles) == set(deps)
    for key in deps:
        assert profiles[key] is not None


def test_profile_results_match_serial_run() -> None:
    """Parallel and serial (max_workers=1) profiling agree per dependency."""
    deps = _make_deps(12)
    parallel = ExistingDependencyProfiler(
        {}, _no_vuln_options(), timeout=5, max_workers=8
    ).profile(deps)
    serial = ExistingDependencyProfiler(
        {}, _no_vuln_options(), timeout=5, max_workers=1
    ).profile(deps)
    assert set(parallel) == set(serial)
    for key in deps:
        assert parallel[key].risk_level == serial[key].risk_level


def test_profile_caches_across_calls() -> None:
    """A second call reuses cached scores and adds only new dependencies."""
    profiler = ExistingDependencyProfiler(
        {}, _no_vuln_options(), timeout=5, max_workers=4
    )
    first = profiler.profile(_make_deps(4))
    combined = profiler.profile(_make_deps(6))
    assert len(combined) == 6
    # The four shared keys keep their identical cached score objects.
    for key in first:
        assert combined[key] is first[key]
