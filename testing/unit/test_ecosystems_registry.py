"""Tests for the centralized ecosystem registry (#72)."""

from dataclasses import FrozenInstanceError
from types import MappingProxyType
from typing import MutableMapping

import pytest

from dependency_risk_profiler.vulnerabilities import ecosystems


def test_lookup_is_case_insensitive_and_trims() -> None:
    """Names are normalized before lookup."""
    assert ecosystems.lookup("NodeJS") is ecosystems.lookup("nodejs")
    assert ecosystems.lookup("  PyPI  ") is ecosystems.lookup("python")


def test_lookup_unknown_returns_none() -> None:
    """An unknown identity is None (non-raising, for legacy delegates)."""
    assert ecosystems.lookup("no-such-eco") is None


def test_resolve_fails_closed_on_unknown() -> None:
    """resolve() raises rather than silently defaulting (the #66 failure mode)."""
    with pytest.raises(ecosystems.UnknownEcosystem):
        ecosystems.resolve("no-such-eco")


def test_aliases_resolve_to_the_same_ecosystem() -> None:
    """Spelling variants collapse to one canonical Ecosystem."""
    cargo = ecosystems.resolve("cargo")
    assert ecosystems.resolve("rust") is cargo
    assert ecosystems.resolve("crates") is cargo


def test_java_and_maven_share_osv_but_diverge_in_nvd() -> None:
    """Legacy quirk preserved: same OSV/GHA name, different NVD CPE prefix."""
    java = ecosystems.resolve("java")
    maven = ecosystems.resolve("maven")
    assert java.osv == maven.osv == "Maven"
    assert java.nvd_cpe_prefix != maven.nvd_cpe_prefix


def test_registry_and_aliases_are_immutable() -> None:
    """Routing tables cannot be mutated at runtime.

    Asserted on the container type rather than by attempting a subscript
    assignment: the tables are declared ``Mapping``, so the assignment form
    was never valid code and only ever "passed" because mypy did not read
    this directory.
    """
    assert isinstance(ecosystems._REGISTRY, MappingProxyType)
    assert isinstance(ecosystems._ALIASES, MappingProxyType)
    assert not isinstance(ecosystems._REGISTRY, MutableMapping)
    assert not isinstance(ecosystems._ALIASES, MutableMapping)


def _assign(target: object, attribute: str, value: object) -> None:
    """Assign an attribute reflectively.

    A direct ``py.osv = ...`` is a static type error against a frozen
    dataclass, and ``setattr(py, "osv", ...)`` is rewritten back into one by
    ruff's B010. Going through a non-literal attribute name keeps the runtime
    behaviour under test without needing a suppression to say so.

    Args:
        target: Object to mutate.
        attribute: Attribute name.
        value: Value to assign.
    """
    setattr(target, attribute, value)


def test_ecosystem_is_frozen() -> None:
    """Ecosystem records are immutable."""
    py = ecosystems.resolve("python")
    with pytest.raises(FrozenInstanceError):
        _assign(py, "osv", "changed")
