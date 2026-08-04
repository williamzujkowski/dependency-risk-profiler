"""Per-ecosystem measured-signal floors for the adapter regression tests.

The scorer calls a dependency UNKNOWN when it can measure fewer signals than it
cannot (``unknown > measured``), so an adapter that reads only two fields off
its registry payload scores UNKNOWN for *every* dependency while still looking
like it ran. That was #127 (rubygems, 167/167 UNKNOWN) and #132 (cargo and
composer, 0% scored on ripgrep and drupal), one root cause each time: registry
metadata never reached the fields the scorer reads.

Each floor below is what its ecosystem must be able to measure from **registry
metadata alone** — no repository clone, no GitHub token — which is the weakest
environment the tool runs in and the one a regression shows up in first. The
numbers are deliberately conservative: they pin the seven signals a registry
payload can answer (release cadence, maintainers, deprecation, version drift,
license, community, exploit), not the ~14 a full run reaches. Transitive
resolution is not among them: it only understands npm lockfiles and Python
requirement sets, so for these three ecosystems the signal is honestly
unmeasured (#141) and :func:`mark_transitive_unmeasured` reproduces that here
rather than letting an empty set score as "no transitive risk".

Seven of fourteen is exactly the edge: the scorer flips to UNKNOWN at
``unmeasured > measured``, so a registry payload is *just* enough on its own
and losing any one field takes the whole ecosystem back to the all-UNKNOWN
state of #127 / #132. That is the property worth pinning.

This module is the seam #73's adapter-conformance harness should grow into:
when that lands, it should consume this table rather than each adapter test
restating the reasoning.
"""

from typing import Dict

from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.transitive.analyzer_enhanced import (
    TRANSITIVE_SOURCE_KEY,
    TRANSITIVE_SOURCE_UNMEASURED,
)

# Minimum signals an ecosystem must measure from registry metadata alone.
#
# nuget sits one above the rest because its registry publishes one more thing:
# a package's ``.nuspec`` states the package's own dependencies, so the
# transitive signal is genuinely measured rather than absent (#129). The other
# three have no per-package dependency document to read and leave it unmeasured.
MIN_MEASURED_SIGNALS: Dict[str, int] = {
    "cargo": 7,
    "composer": 7,
    "nuget": 8,
    "rubygems": 7,
}


def mark_transitive_unmeasured(dependency: DependencyMetadata) -> DependencyMetadata:
    """Mark transitive resolution as not having run, as it does for these ecosystems.

    The real pipeline applies this marker to every manifest that is not an npm
    lockfile or a Python requirement set, so an offline adapter test that skips
    it would credit the ecosystem with a signal it never measures.

    Args:
        dependency: Dependency metadata to mark in place.

    Returns:
        The same dependency, for chaining.
    """
    dependency.additional_info[TRANSITIVE_SOURCE_KEY] = TRANSITIVE_SOURCE_UNMEASURED
    return dependency


def assert_meets_signal_floor(score: DependencyRiskScore, ecosystem: str) -> None:
    """Assert a scored dependency clears its ecosystem's measured-signal floor.

    Args:
        score: Risk score produced with no clone and no GitHub token.
        ecosystem: Registry key present in :data:`MIN_MEASURED_SIGNALS`.

    Raises:
        AssertionError: If the ecosystem measures too few signals to be scored,
            i.e. it has regressed to the all-UNKNOWN state of #127 / #132.
    """
    floor = MIN_MEASURED_SIGNALS[ecosystem]

    assert score.measured_signal_count >= floor, (
        f"{ecosystem} measured only {score.measured_signal_count} of "
        f"{score.total_signal_count} signals (floor {floor}); "
        f"unmeasured: {score.unknown_signals}"
    )
    assert score.insufficient_data is False, (
        f"{ecosystem} is still short of the insufficient-data bar: "
        f"{score.unknown_signal_count} unmeasured vs "
        f"{score.measured_signal_count} measured"
    )
    assert (
        score.risk_level is not RiskLevel.UNKNOWN
    ), f"{ecosystem} scored UNKNOWN from a complete registry payload"
