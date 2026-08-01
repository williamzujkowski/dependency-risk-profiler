"""Frozen snapshot of the four legacy ecosystem-routing maps (#72 baseline).

Captures the EXACT current input->output of every ecosystem string the four
scattered routing tables accept, BEFORE the #72 EcosystemAdapter extraction
centralizes them into a single registry. The extraction must keep every one of
these identical — this is the parity guard the consensus panel required
(snapshot the legacy maps, don't delete them blind). The union of these keys is
the source of truth for the registry's ALIASES; covering anything less
re-introduces the #66 silent-miss.

No network — pure table lookups.
"""

import pytest

from dependency_risk_profiler.org_scan.report import _deps_dev_system
from dependency_risk_profiler.vulnerabilities.aggregator import (
    GitHubAdvisorySource,
    NVDSource,
    OSVSource,
)

# --- Frozen snapshots (pin current behavior; do not "tidy") ---

OSV_MAP = {
    "nodejs": "npm",
    "node": "npm",
    "python": "PyPI",
    "py": "PyPI",
    "pyproject": "PyPI",
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
    "crates": "crates.io",
    "rust": "crates.io",
    "maven": "Maven",
    "java": "Maven",
    "nuget": "NuGet",
    "dotnet": "NuGet",
    "ruby": "RubyGems",
    "gems": "RubyGems",
    "composer": "Packagist",
    "php": "Packagist",
}
GHA_MAP = {
    "nodejs": "NPM",
    "npm": "NPM",
    "python": "PIP",
    "pypi": "PIP",
    "golang": "GO",
    "go": "GO",
    "maven": "MAVEN",
    "java": "MAVEN",
    "nuget": "NUGET",
    "dotnet": "NUGET",
    "ruby": "RUBYGEMS",
    "rubygems": "RUBYGEMS",
    "php": "COMPOSER",
    "composer": "COMPOSER",
    "rust": "RUST",
    "cargo": "RUST",
    "crates": "RUST",
}
NVD_MAP = {
    "nodejs": "cpe:2.3:a:*:node:",
    "npm": "cpe:2.3:a:*:node:",
    "python": "cpe:2.3:a:python:",
    "golang": "cpe:2.3:a:golang:",
    "go": "cpe:2.3:a:golang:",
    "maven": "cpe:2.3:a:apache:maven:",
    "java": "cpe:2.3:a:java:",
    "ruby": "cpe:2.3:a:ruby:",
    "php": "cpe:2.3:a:php:",
    "cargo": "cpe:2.3:a:rust:",
    "rust": "cpe:2.3:a:rust:",
    "crates": "cpe:2.3:a:rust:",
}
DEPS_DEV_MAP = {
    "python": "pypi",
    "pyproject": "pypi",
    "nodejs": "npm",
    "golang": "go",
    "go": "go",
    "toml": "cargo",
    "cargo": "cargo",
}


@pytest.mark.parametrize("name,expected", sorted(OSV_MAP.items()))
def test_osv_snapshot(name: str, expected: str) -> None:
    """Every OSV alias maps to its recorded normalized name."""
    assert OSVSource()._normalize_ecosystem(name) == expected


def test_osv_unknown_returns_input_unchanged() -> None:
    """OSV returns an unknown ecosystem verbatim (current behavior)."""
    assert OSVSource()._normalize_ecosystem("no-such-eco") == "no-such-eco"


@pytest.mark.parametrize("name,expected", sorted(GHA_MAP.items()))
def test_github_advisory_snapshot(name: str, expected: str) -> None:
    """Every GitHub Advisory alias maps to its recorded name."""
    assert GitHubAdvisorySource()._normalize_ecosystem(name) == expected


def test_github_advisory_unknown_returns_empty() -> None:
    """Return "" for an ecosystem GitHub Advisory does not cover."""
    assert GitHubAdvisorySource()._normalize_ecosystem("no-such-eco") == ""


@pytest.mark.parametrize("name,expected", sorted(NVD_MAP.items()))
def test_nvd_snapshot(name: str, expected: str) -> None:
    """Every NVD alias maps to its recorded CPE prefix."""
    assert NVDSource()._get_cpe_prefix(name) == expected


def test_nvd_unknown_returns_empty() -> None:
    """NVD returns "" for an ecosystem it does not cover."""
    assert NVDSource()._get_cpe_prefix("no-such-eco") == ""


@pytest.mark.parametrize("name,expected", sorted(DEPS_DEV_MAP.items()))
def test_deps_dev_snapshot(name: str, expected: str) -> None:
    """Every deps.dev alias maps to its recorded system."""
    assert _deps_dev_system(name) == expected


def test_deps_dev_unknown_returns_none() -> None:
    """Return None for an ecosystem deps.dev does not cover."""
    assert _deps_dev_system("no-such-eco") is None


def test_alias_union_is_the_registry_source_of_truth() -> None:
    """The #72 registry ALIASES must cover the union of all four maps' keys."""
    union = set(OSV_MAP) | set(GHA_MAP) | set(NVD_MAP) | set(DEPS_DEV_MAP)
    # Spelling variants that appear in one table but not another — each must
    # survive centralization or a source silently loses coverage (#66 class).
    assert {"node", "py", "rust", "crates", "gems", "dotnet", "toml"} <= union
