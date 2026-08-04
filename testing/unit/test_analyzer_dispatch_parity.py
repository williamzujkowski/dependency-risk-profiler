"""Bidirectional parity for ecosystem -> analyzer dispatch (#115/#116).

``BaseAnalyzer.get_analyzer_for_ecosystem`` used to be a hand-maintained
if/elif with its own alias set, i.e. a second routing table that could drift
from the canonical registry in ``vulnerabilities.ecosystems``. It is now driven
by that registry, and these tests lock the two directions that drift breaks:

* forward — every ecosystem key and alias the registry knows resolves to a
  concrete analyzer, so a new registry entry cannot silently land without a
  dispatch row (the #66 class, one layer up);
* reverse — every analyzer shipped in the package is reachable from at least
  one registry name, so an analyzer cannot be added and never dispatched.

A frozen snapshot of the pre-#115 if/elif chain guards the refactor itself: no
input the chain accepted may change its answer.

No network — construction and table lookups only.
"""

import importlib
import inspect
import pkgutil
from typing import Dict, Set, Type

import pytest

from dependency_risk_profiler import analyzers as analyzers_package
from dependency_risk_profiler.analyzers.base import BaseAnalyzer
from dependency_risk_profiler.analyzers.composer import ComposerAnalyzer
from dependency_risk_profiler.analyzers.crates import CratesIOAnalyzer
from dependency_risk_profiler.analyzers.golang import GoAnalyzer
from dependency_risk_profiler.analyzers.maven import MavenAnalyzer
from dependency_risk_profiler.analyzers.nodejs import NodeJSAnalyzer
from dependency_risk_profiler.analyzers.nuget import NuGetAnalyzer
from dependency_risk_profiler.analyzers.python import PythonAnalyzer
from dependency_risk_profiler.analyzers.ruby import RubyGemsAnalyzer
from dependency_risk_profiler.vulnerabilities import ecosystems

# Frozen snapshot of the pre-#115 if/elif chain: every string it accepted and
# the analyzer it returned. Do not "tidy" — this is the parity baseline.
LEGACY_CHAIN: Dict[str, Type[BaseAnalyzer]] = {
    "nodejs": NodeJSAnalyzer,
    "python": PythonAnalyzer,
    "pyproject": PythonAnalyzer,
    "golang": GoAnalyzer,
    "cargo": CratesIOAnalyzer,
    "rust": CratesIOAnalyzer,
    "crates": CratesIOAnalyzer,
    "rubygems": RubyGemsAnalyzer,
    "composer": ComposerAnalyzer,
    "nuget": NuGetAnalyzer,
    "maven": MavenAnalyzer,
}


def _shipped_analyzer_classes() -> Set[Type[BaseAnalyzer]]:
    """Return every concrete BaseAnalyzer subclass in the analyzers package."""
    found: Set[Type[BaseAnalyzer]] = set()
    for module_info in pkgutil.iter_modules(analyzers_package.__path__):
        module = importlib.import_module(
            f"{analyzers_package.__name__}.{module_info.name}"
        )
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseAnalyzer)
                and obj is not BaseAnalyzer
                and not inspect.isabstract(obj)
                and obj.__module__ == module.__name__
            ):
                found.add(obj)
    return found


@pytest.mark.parametrize("name,expected", sorted(LEGACY_CHAIN.items()))
def test_legacy_chain_inputs_keep_their_analyzer(
    name: str, expected: Type[BaseAnalyzer]
) -> None:
    """Registry-driven dispatch answers every legacy input identically."""
    assert isinstance(BaseAnalyzer.get_analyzer_for_ecosystem(name), expected)


@pytest.mark.parametrize("alias", sorted(ecosystems._ALIASES))
def test_every_registry_alias_resolves_to_an_analyzer(alias: str) -> None:
    """Forward parity: no registry spelling is left without an analyzer."""
    analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(alias)
    assert analyzer is not None, f"no analyzer for registry alias {alias!r}"
    assert isinstance(analyzer, BaseAnalyzer)


@pytest.mark.parametrize("key", sorted(ecosystems._REGISTRY))
def test_every_registry_key_resolves_to_an_analyzer(key: str) -> None:
    """Forward parity, canonical keys: every Ecosystem has an analyzer."""
    assert BaseAnalyzer.get_analyzer_for_ecosystem(key) is not None


def test_aliases_of_one_ecosystem_share_an_analyzer() -> None:
    """Spellings that collapse to one Ecosystem dispatch to one analyzer."""
    for alias, key in ecosystems._ALIASES.items():
        alias_analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(alias)
        key_analyzer = BaseAnalyzer.get_analyzer_for_ecosystem(key)
        assert type(alias_analyzer) is type(key_analyzer), (
            f"{alias!r} and its canonical key {key!r} dispatch to different "
            f"analyzers"
        )


def test_every_shipped_analyzer_is_reachable_from_the_registry() -> None:
    """Reverse parity: an analyzer nothing routes to is dead code."""
    reachable = {
        type(analyzer)
        for analyzer in (
            BaseAnalyzer.get_analyzer_for_ecosystem(alias)
            for alias in ecosystems._ALIASES
        )
        if analyzer is not None
    }
    unreachable = _shipped_analyzer_classes() - reachable
    assert not unreachable, (
        f"analyzers unreachable from the ecosystem registry: "
        f"{sorted(cls.__name__ for cls in unreachable)}"
    )


@pytest.mark.parametrize("name", ["", "   ", "toml", "unknown", "no-such-eco"])
def test_unknown_input_still_returns_none(name: str) -> None:
    """Unknown identities stay non-raising: dispatch uses lookup, not resolve."""
    assert BaseAnalyzer.get_analyzer_for_ecosystem(name) is None
