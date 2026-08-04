"""Benchmark the #164 step-7 field-provenance record against its budget.

The design amendment made the benchmark a *precondition*, not a risk to note
afterwards, so this script is written to be runnable on both sides of the
change: it feature-detects the provenance API and reports whichever half of the
numbers the checkout can produce. Run it in a clean worktree at ``origin/main``
and again on the branch, and compare.

    uv run python scripts/bench_field_provenance.py

The budget, stated before measuring (see ``docs/signals.md``):

1. Scoring stage, ``create_project_profile`` over 100 dependencies — the path
   under the 50 ms SLA: **no more than +2%**. The design deliberately does not
   touch the scorer, so anything measurable there means it leaked.
2. Acquisition-side recording, every provenanced write one dependency can
   receive in an org scan: **no more than 1.0 us/dep**.
3. Serialization, ``contract.scored_dependency`` per dependency:
   **no more than +10%**.
4. Retained memory: **no more than 400 B/dep**, i.e. +2 MB at 5,000
   dependencies.

Method follows #198: best-of-seven rounds, warm, ``tracemalloc`` for retained
footprint measured after a ``gc.collect()``.
"""

import gc
import platform
import sys
import timeit
import tracemalloc
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from dependency_risk_profiler.contract import scored_dependency
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    LicenseCategory,
    LicenseInfo,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

HAS_PROVENANCE = hasattr(DependencyMetadata, "record_field_source")

if HAS_PROVENANCE:
    from dependency_risk_profiler.signals import FieldSource, ProvenancedField

    #: Every provenanced write one dependency receives in an org scan, in the
    #: order the pipeline performs them: the registry adapter, then the HTML
    #: scrape, then the authenticated API overwriting most of it.
    ORG_SCAN_WRITES: List[Tuple[object, object]] = [
        (ProvenancedField.MAINTAINER_COUNT, FieldSource.REGISTRY_METADATA),
        (ProvenancedField.LAST_UPDATED, FieldSource.REGISTRY_RELEASE),
        (ProvenancedField.STAR_COUNT, FieldSource.GITHUB_HTML_SCRAPE),
        (ProvenancedField.CONTRIBUTOR_COUNT, FieldSource.GITHUB_API_CONTRIBUTORS),
        (ProvenancedField.MAINTAINER_COUNT, FieldSource.GITHUB_API_CONTRIBUTORS),
        (ProvenancedField.COMMIT_FREQUENCY, FieldSource.GITHUB_API_COMMITS),
        (ProvenancedField.STAR_COUNT, FieldSource.GITHUB_API_REPOSITORY),
        (ProvenancedField.HAS_TESTS, FieldSource.GITHUB_API_TREE),
        (ProvenancedField.HAS_CI, FieldSource.GITHUB_API_TREE),
    ]
else:
    ORG_SCAN_WRITES = []

ROUNDS = 7


def _dependency(index: int) -> DependencyMetadata:
    """Build one synthetic dependency with a realistic spread of measurements.

    Args:
        index: Position in the synthetic project, which varies the risk shape.

    Returns:
        The dependency.
    """
    high = index % 4 == 0
    medium = index % 4 == 1
    return DependencyMetadata(
        name=f"dep-{index}",
        installed_version="1.0.0",
        latest_version="2.0.0" if high else "1.1.0" if medium else "1.0.1",
        last_updated=datetime.now()
        - timedelta(days=400 if high else 100 if medium else 10),
        maintainer_count=1 if high else 3 if medium else 5,
        is_deprecated=high,
        has_known_exploits=high,
        has_tests=not high,
        has_ci=not high and not medium,
        has_contribution_guidelines=not high,
        license_info=LicenseInfo(
            license_id="MIT",
            category=LicenseCategory.PERMISSIVE,
            is_approved=True,
            risk_level=RiskLevel.LOW,
        ),
        community_metrics=CommunityMetrics(star_count=5000, commit_frequency=10.0),
        security_metrics=SecurityMetrics(has_security_policy=True),
        transitive_dependencies={f"t{n}" for n in range(5)},
    )


def _record(dependency: DependencyMetadata) -> None:
    """Apply an org scan's full provenanced write sequence to one dependency.

    Args:
        dependency: The dependency to record sources on.
    """
    for field_name, source in ORG_SCAN_WRITES:
        dependency.record_field_source(field_name, source)


def _best(statement: object, number: int) -> float:
    """Return the best per-call time over :data:`ROUNDS` rounds, in seconds.

    Args:
        statement: A zero-argument callable to time.
        number: Calls per round.

    Returns:
        Seconds per call.
    """
    return min(timeit.repeat(statement, number=number, repeat=ROUNDS)) / number


def bench_scoring() -> float:
    """Time ``create_project_profile`` over 100 dependencies.

    Returns:
        Milliseconds per 100-dependency profile.
    """
    scorer = RiskScorer()
    dependencies: Dict[str, DependencyMetadata] = {}
    for index in range(100):
        dependency = _dependency(index)
        if HAS_PROVENANCE:
            _record(dependency)
        dependencies[dependency.name] = dependency

    def run() -> None:
        scorer.create_project_profile("requirements.txt", "python", dependencies)

    return _best(run, number=20) * 1000


def bench_recording() -> Optional[float]:
    """Time one dependency's full provenanced write sequence.

    Returns:
        Microseconds per dependency, or None on a checkout without the API.
    """
    if not HAS_PROVENANCE:
        return None

    def run() -> None:
        _record(DependencyMetadata(name="x", installed_version="1.0.0"))

    baseline = _best(
        lambda: DependencyMetadata(name="x", installed_version="1.0.0"),
        number=20_000,
    )
    return (_best(run, number=20_000) - baseline) * 1e6


def bench_serialization() -> float:
    """Time ``contract.scored_dependency`` for one scored dependency.

    Returns:
        Microseconds per dependency.
    """
    scorer = RiskScorer()
    dependency = _dependency(0)
    if HAS_PROVENANCE:
        _record(dependency)
    score = scorer.score_dependency(dependency)

    def run() -> None:
        scored_dependency(score, ecosystem="python")

    return _best(run, number=20_000) * 1e6


def bench_retained() -> float:
    """Measure bytes retained per dependency by the metadata objects.

    Returns:
        Bytes retained per dependency, for 5,000 dependencies.
    """
    count = 5_000
    gc.collect()
    tracemalloc.start()
    held = []
    for index in range(count):
        dependency = _dependency(index)
        if HAS_PROVENANCE:
            _record(dependency)
        held.append(dependency)
    current, _peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(held) == count
    return current / count


def main() -> None:
    """Run every measurement and print a table."""
    print(f"python      : {platform.python_version()} ({sys.executable})")
    print(f"provenance  : {'present' if HAS_PROVENANCE else 'absent (baseline)'}")
    print()
    print(f"scoring, 100 deps      : {bench_scoring():8.3f} ms")
    recording = bench_recording()
    if recording is not None:
        print(f"recording, per dep     : {recording:8.3f} us")
    print(f"serialization, per dep : {bench_serialization():8.3f} us")
    print(f"retained, per dep      : {bench_retained():8.1f} B")


if __name__ == "__main__":
    main()
