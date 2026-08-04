"""The official purl-spec test suite, run as CI fixtures (#164).

This is the binding gate on the whole purl approach. The ratified condition on
 #164 was explicit: the official ``package-url/purl-spec`` test-suite JSON must
run as CI fixtures, and *if the hand-rolled canonicalizer cannot pass it, that
is the evidence to grant a dependency exception* and take ``packageurl-python``
instead. So this file is not a formality — it is the experiment whose result
decides whether ``src/dependency_risk_profiler/purl.py`` should exist at all.

Because of that, nothing here is allowed to soften the suite. Every test case in
every vendored file runs: both the ``base`` and the optional ``advanced`` test
groups, and all three test types. There is no skip list, no xfail, and no
filtering predicate. The only fixtures not vendored are the type files for the
34 purl types we do not model, which is a scope boundary rather than an
exclusion — and :func:`test_vendored_types_match_the_ecosystem_registry` fails
if that boundary ever drifts from the registry.

See ``testing/fixtures/purl-spec/PROVENANCE.md`` for the pinned upstream
revision, per-file hashes, and the two shape equivalences applied when
comparing (absent-versus-empty, and qualifier maps compared as maps).
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from dependency_risk_profiler.purl import PackageURL, PurlError, parse
from dependency_risk_profiler.vulnerabilities import ecosystems

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "purl-spec"

# The core-specification file plus one file per purl type we model.
SPEC_FILE = "specification-test.json"

# One upstream test case. Values are heterogeneous JSON — a purl string, a
# component object, a bool, or null — so they are read through the narrowing
# helpers below rather than being typed as ``Any``.
Case = Dict[str, object]


def _load(path: Path) -> List[Case]:
    """Read one upstream test file.

    Args:
        path: Path to a vendored ``*-test.json`` file.

    Returns:
        Its list of test cases.
    """
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    cases: List[Case] = payload["tests"]
    return cases


def _all_cases() -> List[Tuple[str, Case]]:
    """Collect every test case from every vendored file.

    Returns:
        ``(file stem, case)`` pairs, in a stable order.
    """
    collected: List[Tuple[str, Case]] = []
    for path in sorted(FIXTURE_DIR.glob("*-test.json")):
        for case in _load(path):
            collected.append((path.stem, case))
    return collected


def _case_id(item: Tuple[str, Case]) -> str:
    """Build a readable pytest id for a test case.

    Args:
        item: A ``(file stem, case)`` pair.

    Returns:
        An id of the form ``file[group/type] description``.
    """
    stem, case = item
    return f"{stem}[{case['test_group']}/{case['test_type']}] {case['description']}"


CASES = _all_cases()


def _text(value: object) -> Optional[str]:
    """Narrow a JSON value to a non-empty string, or None.

    Also implements the "absent versus empty" equivalence documented in
    PROVENANCE.md: upstream spells an absent component as ``null``.

    Args:
        value: A raw JSON value from a test case.

    Returns:
        The string, or None when it is absent or empty.
    """
    return value if isinstance(value, str) and value else None


def _qualifier_map(value: object) -> Dict[str, str]:
    """Narrow a JSON value to a qualifier mapping.

    Args:
        value: A raw JSON value from a test case.

    Returns:
        The qualifiers as a plain mapping; empty when absent.
    """
    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _build(components: Case) -> PackageURL:
    """Construct a purl from an upstream ``build``-style component object.

    Args:
        components: The upstream component object.

    Returns:
        The constructed purl.

    Raises:
        PurlError: If the components are not a valid purl. A null ``type`` or
            ``name`` becomes an empty string so the constructor reports it,
            rather than it surfacing here as a TypeError.
    """
    return PackageURL(
        type=_text(components.get("type")) or "",
        namespace=_text(components.get("namespace")),
        name=_text(components.get("name")) or "",
        version=_text(components.get("version")),
        qualifiers=_qualifier_map(components.get("qualifiers")),
        subpath=_text(components.get("subpath")),
    )


def _assert_components(actual: PackageURL, expected: Case) -> None:
    """Compare a parsed purl against an upstream expected-component object.

    Applies the two documented equivalences: an absent component may be spelled
    ``null`` or (for qualifiers) an empty mapping, and qualifier objects are
    compared as mappings rather than as ordered pairs.

    Args:
        actual: The purl our parser produced.
        expected: The upstream expected components.
    """
    assert actual.type == expected["type"]
    assert actual.namespace == _text(expected.get("namespace"))
    assert actual.name == expected["name"]
    assert actual.version == _text(expected.get("version"))
    assert dict(actual.qualifiers) == _qualifier_map(expected.get("qualifiers"))
    assert actual.subpath == _text(expected.get("subpath"))


@pytest.mark.parametrize("stem,case", CASES, ids=[_case_id(item) for item in CASES])
def test_purl_spec_conformance(stem: str, case: Case) -> None:
    """Run one official purl-spec conformance case.

    Args:
        stem: The vendored file the case came from, for failure messages.
        case: The upstream test case.
    """
    test_type = case["test_type"]
    payload = case["input"]
    expected_failure = bool(case["expected_failure"])
    expected_output = case["expected_output"]

    if test_type == "build":
        _run_build(payload, expected_failure, expected_output)
    elif test_type == "parse":
        _run_parse(payload, expected_failure, expected_output)
    elif test_type == "roundtrip":
        _run_roundtrip(payload, expected_failure, expected_output)
    else:  # pragma: no cover - upstream schema allows only these three
        pytest.fail(f"{stem}: unknown test_type {test_type!r}")


def _run_build(
    payload: object, expected_failure: bool, expected_output: object
) -> None:
    """Assert a ``build`` case: components in, canonical string out.

    Args:
        payload: The upstream component object.
        expected_failure: Whether building is expected to fail.
        expected_output: The expected canonical purl string, or None.
    """
    # Assert rather than coerce: a fixture whose shape drifted must fail the
    # gate, not quietly degrade into a test that asserts nothing.
    assert isinstance(payload, dict)
    if expected_failure:
        with pytest.raises(PurlError):
            _build(payload).to_string()
        return
    assert _build(payload).to_string() == expected_output


def _run_parse(
    payload: object, expected_failure: bool, expected_output: object
) -> None:
    """Assert a ``parse`` case: string in, decoded components out.

    Args:
        payload: The upstream purl string.
        expected_failure: Whether parsing is expected to fail.
        expected_output: The expected component object, or None.
    """
    assert isinstance(payload, str)
    if expected_failure:
        with pytest.raises(PurlError):
            parse(payload)
        return
    assert isinstance(expected_output, dict)
    _assert_components(parse(payload), expected_output)


def _run_roundtrip(
    payload: object, expected_failure: bool, expected_output: object
) -> None:
    """Assert a ``roundtrip`` case: string in, canonical string out.

    Args:
        payload: The upstream purl string.
        expected_failure: Whether the round trip is expected to fail.
        expected_output: The expected canonical purl string, or None.
    """
    assert isinstance(payload, str)
    if expected_failure:
        with pytest.raises(PurlError):
            parse(payload).to_string()
        return
    assert parse(payload).to_string() == expected_output


def test_the_suite_is_actually_loaded() -> None:
    """A silently empty fixture directory would make this whole file vacuous.

    The gate on #164 is "the official suite passes". A parametrization that
    collected nothing would pass just as loudly, so assert the shape of what
    was collected rather than trusting the glob.
    """
    assert len(CASES) > 100
    stems = {stem for stem, _ in CASES}
    assert SPEC_FILE.removesuffix(".json") in stems
    groups = {case["test_group"] for _, case in CASES}
    assert groups == {"base", "advanced"}, "the optional advanced group must run"
    types = {case["test_type"] for _, case in CASES}
    assert types == {"build", "parse", "roundtrip"}
    assert any(case["expected_failure"] for _, case in CASES)


def test_vendored_types_match_the_ecosystem_registry() -> None:
    """Every purl type we claim to support has its official test file vendored.

    This is what stops the scope boundary in PROVENANCE.md from silently
    becoming a test exclusion. Add an ecosystem to the registry without
    vendoring its upstream type file and this fails.
    """
    vendored = {
        path.stem.removesuffix("-test")
        for path in FIXTURE_DIR.glob("*-test.json")
        if path.name != SPEC_FILE
    }
    registry_types = {eco.purl_type for eco in ecosystems._ECOSYSTEMS}
    assert vendored == registry_types
