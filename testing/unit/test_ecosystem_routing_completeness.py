"""Routing-completeness safety net for the ecosystem-adapter epic (#73).

Every ecosystem string the analyzers emit (via ``additional_info["ecosystem"]``)
must resolve in EVERY downstream routing table — OSV, GitHub Advisory, NVD CPE,
and deps.dev. A string that maps in one table but silently returns empty in
another skips that vulnerability source or registry link — the #66 / #76 / #77
bug class. These tests are the mechanical guard that would have caught all
three, and they characterize the current routing so the #72 EcosystemAdapter
extraction is provably behavior-preserving (the per-ecosystem golden *output*
diffs live inside each extraction PR, where record-before-move is meaningful).

No network: pure table lookups.
"""

import pytest

from dependency_risk_profiler.org_scan.report import _deps_dev_system
from dependency_risk_profiler.vulnerabilities.aggregator import (
    GitHubAdvisorySource,
    NVDSource,
    OSVSource,
)

# The canonical ecosystem strings the four analyzers set on every dependency
# (analyzers/{nodejs,python,golang,crates}.py -> additional_info["ecosystem"]).
CANONICAL_ECOSYSTEMS = ("nodejs", "python", "golang", "cargo", "rubygems")

# Characterized current routing. Pin the stable names so the extraction cannot
# silently change where a dependency's advisories/links are looked up.
EXPECTED_ROUTING = {
    "nodejs": {"osv": "npm", "gha": "NPM", "deps_dev": "npm"},
    "python": {"osv": "PyPI", "gha": "PIP", "deps_dev": "pypi"},
    "golang": {"osv": "Go", "gha": "GO", "deps_dev": "go"},
    "cargo": {"osv": "crates.io", "gha": "RUST", "deps_dev": "cargo"},
    "rubygems": {"osv": "RubyGems", "gha": "RUBYGEMS", "deps_dev": "rubygems"},
}


@pytest.mark.parametrize("ecosystem", CANONICAL_ECOSYSTEMS)
def test_every_emitted_ecosystem_resolves_in_all_tables(ecosystem: str) -> None:
    """No emitted ecosystem string may silently miss a routing table."""
    assert OSVSource()._normalize_ecosystem(ecosystem), "missing from OSV map"
    assert GitHubAdvisorySource()._normalize_ecosystem(
        ecosystem
    ), "missing from GitHub Advisory map"
    assert NVDSource()._get_cpe_prefix(ecosystem), "missing from NVD CPE map"
    assert _deps_dev_system(ecosystem) is not None, "missing from deps.dev map"


@pytest.mark.parametrize("ecosystem", CANONICAL_ECOSYSTEMS)
def test_routing_names_are_characterized(ecosystem: str) -> None:
    """Pin the exact OSV / GitHub Advisory / deps.dev names per ecosystem."""
    expected = EXPECTED_ROUTING[ecosystem]
    assert OSVSource()._normalize_ecosystem(ecosystem) == expected["osv"]
    assert GitHubAdvisorySource()._normalize_ecosystem(ecosystem) == expected["gha"]
    assert _deps_dev_system(ecosystem) == expected["deps_dev"]


def test_canonical_set_matches_what_analyzers_emit() -> None:
    """Guard the source of truth for the routing safety net.

    If an analyzer starts emitting a new ecosystem string, this list (and the
    routing tables above) must be updated to cover it.
    """
    import pathlib
    import re

    analyzers = pathlib.Path(__file__).resolve().parents[2] / (
        "src/dependency_risk_profiler/analyzers"
    )
    emitted = set()
    for path in analyzers.glob("*.py"):
        for match in re.finditer(
            r'additional_info\["ecosystem"\]\s*=\s*"([^"]+)"', path.read_text()
        ):
            emitted.add(match.group(1))
    assert emitted == set(CANONICAL_ECOSYSTEMS), (
        f"analyzers emit {sorted(emitted)} but the routing safety net covers "
        f"{sorted(CANONICAL_ECOSYSTEMS)} — update both together"
    )
