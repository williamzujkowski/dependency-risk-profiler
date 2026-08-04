"""Identity keys, per-ecosystem canonicalization, and the two-level model.

Companion to ``test_purl_conformance.py``, which proves we follow ECMA-427.
This file covers the layer above it: the primary key we derive from a purl
(#164), the per-ecosystem canonicalization rules, and the deliberate split
between a faithful identity key and a derived rollup group.

The four assertions the #164 review panel asked for by name are all here:
idempotence, ``xxhash`` versus ``xxhash/v2``, the three-platform nokogiri
collapse, and losslessness.
"""

from dataclasses import FrozenInstanceError
from types import MappingProxyType
from typing import MutableMapping, Optional

import pytest

from dependency_risk_profiler.go_modules import GoModuleResolver
from dependency_risk_profiler.purl import (
    DependencyIdentity,
    PurlError,
    canonicalize,
    collapse,
    for_dependency,
    go_module_path,
    identity_key,
    parse,
    purl_type_for_ecosystem,
    rollup_group_key,
)
from dependency_risk_profiler.vulnerabilities.ecosystems import (
    _ECOSYSTEMS,
    UnknownEcosystem,
)

# --------------------------------------------------------------------------
# The ecosystem bridge: one source of truth
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ecosystem,expected",
    [
        ("nodejs", "npm"),
        ("node", "npm"),
        ("npm", "npm"),
        ("python", "pypi"),
        ("pypi", "pypi"),
        ("golang", "golang"),
        ("go", "golang"),
        ("cargo", "cargo"),
        ("rust", "cargo"),
        ("maven", "maven"),
        ("java", "maven"),
        ("nuget", "nuget"),
        ("dotnet", "nuget"),
        ("ruby", "gem"),
        ("rubygems", "gem"),
        ("composer", "composer"),
        ("php", "composer"),
    ],
)
def test_ecosystem_keys_and_aliases_map_to_purl_types(
    ecosystem: str, expected: str
) -> None:
    """Every spelling the registry accepts yields the right purl type.

    Args:
        ecosystem: An ecosystem key or alias.
        expected: The purl type it should map to.
    """
    assert purl_type_for_ecosystem(ecosystem) == expected


def test_nine_registry_keys_yield_eight_purl_types() -> None:
    """``java`` and ``maven`` share a purl type; nothing else collides."""
    assert len(_ECOSYSTEMS) == 9
    assert len({eco.purl_type for eco in _ECOSYSTEMS}) == 8


def test_unknown_ecosystem_fails_closed() -> None:
    """A guessed purl type would be a silently wrong primary key."""
    with pytest.raises(UnknownEcosystem):
        purl_type_for_ecosystem("cobol")


def test_purl_type_is_not_a_second_table() -> None:
    """The mapping lives on the registry record, not in a parallel dict.

    A second table claiming to know what an ecosystem is drifts, and the drift
    is silent — the #66 failure mode. Assert the field is where it belongs.
    """
    for eco in _ECOSYSTEMS:
        assert eco.purl_type
        assert eco.purl_type == eco.purl_type.lower()


# --------------------------------------------------------------------------
# Per-ecosystem canonicalization
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        # PyPI folds case and maps underscore to dash (PEP 503-adjacent).
        ("pkg:pypi/Django_Package@1.0", "pkg:pypi/django-package@1.0"),
        ("pkg:PYPI/Requests@2.31.0", "pkg:pypi/requests@2.31.0"),
        # ...but NOT full PEP 503: dots survive, or every real PyPI purl breaks.
        ("pkg:pypi/zope.interface@5.4.0", "pkg:pypi/zope.interface@5.4.0"),
        # NuGet preserves case: the registry is case-insensitive but the spec
        # marks the name case-sensitive and upstream asserts it round-trips.
        (
            "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
            "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
        ),
        # Composer forces lowercase on both vendor and name.
        ("pkg:composer/Laravel/Laravel@5.5.0", "pkg:composer/laravel/laravel@5.5.0"),
        # Cargo, npm and Maven preserve case.
        ("pkg:cargo/Inflector@0.11.4", "pkg:cargo/Inflector@0.11.4"),
        ("pkg:npm/JSONStream@1.3.5", "pkg:npm/JSONStream@1.3.5"),
        (
            "pkg:maven/HTTPClient/HTTPClient@0.3-3",
            "pkg:maven/HTTPClient/HTTPClient@0.3-3",
        ),
        # Go preserves case: the module proxy bang-encodes uppercase precisely
        # so that Masterminds and masterminds stay distinct modules.
        (
            "pkg:golang/github.com/Masterminds/semver@v1.5.0",
            "pkg:golang/github.com/Masterminds/semver@v1.5.0",
        ),
        # npm scope is the namespace and its '@' is percent-encoded.
        ("pkg:npm/@angular/animation@12.3.1", "pkg:npm/%40angular/animation@12.3.1"),
    ],
)
def test_per_ecosystem_canonicalization(raw: str, expected: str) -> None:
    """Each ecosystem folds exactly what its type definition says to fold.

    Args:
        raw: A purl string, canonical or not.
        expected: Its canonical form.
    """
    assert canonicalize(raw) == expected


def test_grandfathered_npm_uppercase_is_preserved() -> None:
    """Npm names created before the 2015 lowercase rule are still valid."""
    assert canonicalize("pkg:npm/CoffeeScript@1.12.7") == "pkg:npm/CoffeeScript@1.12.7"


def test_maven_namespace_is_the_group_id() -> None:
    """The groupId is the namespace and the artifactId is the name."""
    parsed = parse("pkg:maven/org.apache.commons/commons-lang3@3.14.0")
    assert parsed.namespace == "org.apache.commons"
    assert parsed.name == "commons-lang3"


@pytest.mark.parametrize(
    "purl_string",
    [
        "pkg:maven/commons-lang3@3.14.0",
        "pkg:composer/promises@2.0.2",
        "pkg:golang/genproto",
    ],
)
def test_types_that_require_a_namespace_reject_a_bare_name(purl_string: str) -> None:
    """A Maven purl with no groupId is not a Maven coordinate.

    Args:
        purl_string: A purl missing a required namespace.
    """
    with pytest.raises(PurlError, match="namespace is required"):
        parse(purl_string)


@pytest.mark.parametrize(
    "purl_string",
    [
        "pkg:pypi/acme/django@1.0",
        "pkg:cargo/acme/rand@0.7.2",
        "pkg:gem/acme/nokogiri@1.16.0",
        "pkg:nuget/acme/Newtonsoft.Json@13.0.3",
    ],
)
def test_types_that_prohibit_a_namespace_reject_one(purl_string: str) -> None:
    """A namespaced PyPI purl is malformed input, not a package we have.

    Args:
        purl_string: A purl carrying a prohibited namespace.
    """
    with pytest.raises(PurlError, match="namespace is prohibited"):
        parse(purl_string)


# --------------------------------------------------------------------------
# Idempotence (requested by the review panel)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "pkg:PYPI/Django_package@1.11.1.dev1",
        "pkg:npm/@babel/core@7.0.0",
        "pkg:Maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=pom&classifier=sources",
        "pkg://golang/google.golang.org/genproto#/googleapis/api/annotations/",
        "pkg:gem/jruby-launcher@1.1.2?Platform=java",
        "pkg:composer/Laravel/Laravel@5.5.0",
        "pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
        "pkg:cargo/rand@0.7.2",
    ],
)
def test_canonicalization_is_idempotent(raw: str) -> None:
    """``canonicalize(canonicalize(x)) == canonicalize(x)``.

    A normalizer that keeps changing its own output has no fixed point, which
    means the primary key is not stable and equality comparisons are a coin
    flip. Assert the fixed point directly.

    Args:
        raw: A purl string, canonical or not.
    """
    once = canonicalize(raw)
    assert canonicalize(once) == once
    assert canonicalize(canonicalize(once)) == once


@pytest.mark.parametrize(
    "raw",
    [
        "pkg:PYPI/Django_package@1.11.1.dev1",
        "pkg:npm/@babel/core@7.0.0",
        "pkg:gem/jruby-launcher@1.1.2?platform=java",
        "pkg:golang/github.com/cespare/xxhash/v2@v2.2.0",
    ],
)
def test_identity_key_is_idempotent_and_reparseable(raw: str) -> None:
    """An identity key is itself a purl, and keying it again is a no-op.

    Args:
        raw: A purl string, canonical or not.
    """
    key = identity_key(parse(raw))
    assert identity_key(parse(key)) == key
    assert canonicalize(key) == key


# --------------------------------------------------------------------------
# Decision 1: Go /vN stays in the key (ratified 7-0 on #164)
# --------------------------------------------------------------------------


def test_go_major_versions_are_distinct_keys_but_one_repository() -> None:
    """``xxhash`` and ``xxhash/v2`` are two modules that share one repository.

    This is the case that forced the two-level model. Level 1 must keep them
    apart — they have independent version timelines and OSV keys advisories on
    the full module path — while level 2 must bring them together, because a
    blast-radius view cares about the repository.
    """
    v1 = parse("pkg:golang/github.com/cespare/xxhash@v1.1.0")
    v2 = parse("pkg:golang/github.com/cespare/xxhash/v2@v2.2.0")

    # Level 1: distinct.
    assert identity_key(v1) != identity_key(v2)
    assert identity_key(v1) == "pkg:golang/github.com/cespare/xxhash@v1.1.0"
    assert identity_key(v2) == "pkg:golang/github.com/cespare/xxhash/v2@v2.2.0"

    # Level 2: collides, and via the #130 resolver rather than a second
    # stripper written here.
    resolver = GoModuleResolver()
    assert rollup_group_key(v1, resolver) == rollup_group_key(v2, resolver)
    assert rollup_group_key(v1, resolver) == "https://github.com/cespare/xxhash"


def test_go_module_path_reassembles_the_major_suffix() -> None:
    """The parsing algorithm splits ``.../xxhash/v2`` oddly; this puts it back."""
    v2 = parse("pkg:golang/github.com/cespare/xxhash/v2@v2.2.0")
    assert v2.namespace == "github.com/cespare/xxhash"
    assert v2.name == "v2"
    assert go_module_path(v2) == "github.com/cespare/xxhash/v2"


def test_go_module_path_rejects_other_types() -> None:
    """The helper is Go-specific and says so rather than guessing."""
    with pytest.raises(PurlError, match="not a golang purl"):
        go_module_path(parse("pkg:npm/left-pad@1.3.0"))


def test_rollup_group_key_drops_the_version_for_non_go_types() -> None:
    """Level 2 groups all versions of a package; level 1 never does."""
    old = parse("pkg:pypi/django@4.2.0")
    new = parse("pkg:pypi/django@5.0.0")
    assert identity_key(old) != identity_key(new)
    assert rollup_group_key(old) == rollup_group_key(new) == "pkg:pypi/django"


# --------------------------------------------------------------------------
# Decision 2: RubyGems platform stays out of the key (ratified 7-0 on #164)
# --------------------------------------------------------------------------


def test_nokogiri_across_three_platforms_is_one_key() -> None:
    """One gem locked for three platforms is one dependency, not three.

    Every signal we measure for a gem is platform-invariant: the MRI, native
    and JRuby builds ship from one source repository with one maintainer, one
    release cadence and one advisory stream. The platform is recorded as an
    attribute so nothing observed is thrown away.
    """
    observed = [
        parse("pkg:gem/nokogiri@1.16.0?platform=x86_64-linux"),
        parse("pkg:gem/nokogiri@1.16.0?platform=arm64-darwin"),
        parse("pkg:gem/nokogiri@1.16.0?platform=java"),
    ]

    identity = collapse(observed)

    assert identity.key == "pkg:gem/nokogiri@1.16.0"
    assert identity.platforms == ("arm64-darwin", "java", "x86_64-linux")
    assert len(identity.platforms) == 3


def test_a_bare_gem_purl_reports_the_default_platform() -> None:
    """A bare gem purl means MRI, per the gem type definition's default."""
    identity = collapse([parse("pkg:gem/rails@7.1.0")])
    assert identity.key == "pkg:gem/rails@7.1.0"
    assert identity.platforms == ("ruby",)


def test_platform_is_omitted_from_the_key_not_invented_into_it() -> None:
    """The key abstains from the detail; it does not assert a wrong value.

    "An identity key may abstain from optional detail. It may never lie" — so
    a JRuby gem's key must not claim ``platform=ruby``.
    """
    jruby = parse("pkg:gem/jruby-launcher@1.1.2?platform=java")
    assert identity_key(jruby) == "pkg:gem/jruby-launcher@1.1.2"
    assert "platform" not in identity_key(jruby)


def test_non_gem_types_report_no_platforms() -> None:
    """``platforms`` is a RubyGems concept and stays one."""
    identity = collapse([parse("pkg:pypi/django@5.0.0")])
    assert identity.platforms == ()


# --------------------------------------------------------------------------
# Losslessness (requested by the review panel)
# --------------------------------------------------------------------------


def test_collapsed_identity_reconstructs_every_observed_purl() -> None:
    """Key plus recorded attributes rebuilds exactly what was observed.

    This is what makes dropping a qualifier from the key safe: the information
    moved, it did not disappear.
    """
    raw = [
        "pkg:gem/nokogiri@1.16.0?platform=x86_64-linux",
        "pkg:gem/nokogiri@1.16.0?platform=arm64-darwin",
        "pkg:gem/nokogiri@1.16.0?platform=java",
    ]
    identity = collapse(parse(item) for item in raw)
    assert set(identity.observed_purls()) == set(raw)


def test_losslessness_holds_for_dropped_non_platform_qualifiers() -> None:
    """Maven's classifier and type are dropped from the key but recorded."""
    raw = [
        "pkg:maven/net.sf.jacob-project/jacob@1.14.3?classifier=x86&type=dll",
        "pkg:maven/net.sf.jacob-project/jacob@1.14.3?classifier=x64&type=dll",
    ]
    identity = collapse(parse(item) for item in raw)
    assert identity.key == "pkg:maven/net.sf.jacob-project/jacob@1.14.3"
    assert set(identity.observed_purls()) == set(raw)


def test_losslessness_holds_for_a_dropped_subpath() -> None:
    """The subpath is metadata for our purposes, but it is still recorded."""
    raw = "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c#api"
    identity = collapse([parse(raw)])
    assert identity.key == (
        "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c"
    )
    assert identity.observed_purls() == (raw,)


def test_identical_spellings_collapse_to_one_variant() -> None:
    """Two lockfiles naming the same artifact is one observation, not two."""
    identity = collapse(
        [
            parse("pkg:gem/nokogiri@1.16.0?platform=java"),
            parse("pkg:gem/nokogiri@1.16.0?platform=java"),
        ]
    )
    assert len(identity.variants) == 1
    assert identity.platforms == ("java",)


def test_collapse_refuses_to_merge_different_dependencies() -> None:
    """Silently picking a winner is the fabricated-value failure #164 prevents."""
    with pytest.raises(PurlError, match="different identity keys"):
        collapse([parse("pkg:pypi/django@5.0.0"), parse("pkg:pypi/flask@3.0.0")])


def test_collapse_refuses_an_empty_input() -> None:
    """There is no identity to report for nothing observed."""
    with pytest.raises(PurlError, match="empty set"):
        collapse([])


def test_identity_without_variants_reconstructs_the_bare_key() -> None:
    """A hand-built identity with no recorded variants is still coherent."""
    identity = DependencyIdentity(key="pkg:pypi/django@5.0.0")
    assert identity.observed_purls() == ("pkg:pypi/django@5.0.0",)


# --------------------------------------------------------------------------
# Building purls from the profiler's own naming
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ecosystem,name,version,expected",
    [
        ("python", "Django_Package", "1.0", "pkg:pypi/django-package@1.0"),
        ("nodejs", "@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"),
        ("nodejs", "left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"),
        (
            "maven",
            "org.apache.commons:commons-lang3",
            "3.14.0",
            "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
        ),
        (
            "java",
            "org.apache.commons:commons-lang3",
            "3.14.0",
            "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
        ),
        (
            "golang",
            "github.com/cespare/xxhash/v2",
            "v2.2.0",
            "pkg:golang/github.com/cespare/xxhash/v2@v2.2.0",
        ),
        (
            "composer",
            "guzzlehttp/promises",
            "2.0.2",
            "pkg:composer/guzzlehttp/promises@2.0.2",
        ),
        ("cargo", "rand", "0.7.2", "pkg:cargo/rand@0.7.2"),
        ("ruby", "nokogiri", "1.16.0", "pkg:gem/nokogiri@1.16.0"),
        ("nuget", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3"),
    ],
)
def test_for_dependency_bridges_internal_naming(
    ecosystem: str, name: str, version: Optional[str], expected: str
) -> None:
    """The profiler's own dependency names become correct purls.

    Args:
        ecosystem: An ecosystem key or alias.
        name: The dependency name as the profiler spells it.
        version: The resolved version.
        expected: The expected canonical purl string.
    """
    assert for_dependency(ecosystem, name, version).to_string() == expected


def test_for_dependency_without_a_version_is_valid() -> None:
    """A version is optional in purl and optional here."""
    assert for_dependency("cargo", "rand").to_string() == "pkg:cargo/rand"


def test_for_dependency_rejects_an_empty_name() -> None:
    """An unnamed dependency has no identity to key on."""
    with pytest.raises(PurlError, match="name is required"):
        for_dependency("cargo", "   ")


def test_for_dependency_accepts_extra_qualifiers() -> None:
    """Callers can carry observed metadata even though the key drops it."""
    built = for_dependency("ruby", "nokogiri", "1.16.0", {"platform": "java"})
    assert built.to_string() == "pkg:gem/nokogiri@1.16.0?platform=java"
    assert identity_key(built) == "pkg:gem/nokogiri@1.16.0"


# --------------------------------------------------------------------------
# The PackageURL value type
# --------------------------------------------------------------------------


def _assign(target: object, attribute: str, value: object) -> None:
    """Assign an attribute reflectively.

    A direct ``one.name = ...`` is a static type error against a frozen
    dataclass, and ``setattr(one, "name", ...)`` is rewritten back into one by
    ruff's B010. Going through a non-literal attribute name keeps the runtime
    behaviour under test without needing a suppression to say so.

    Args:
        target: Object to mutate.
        attribute: Attribute name.
        value: Value to assign.
    """
    setattr(target, attribute, value)


def test_package_url_is_frozen_and_hashable() -> None:
    """Keys end up in sets and dict keys; the value type must support that."""
    one = parse("pkg:pypi/django@5.0.0")
    two = parse("pkg:PYPI/Django@5.0.0")
    assert one == two
    assert len({identity_key(one), identity_key(two)}) == 1
    with pytest.raises(FrozenInstanceError):
        _assign(one, "name", "flask")


def test_qualifiers_are_immutable() -> None:
    """A shared canonical purl must not be mutable through its qualifiers.

    Asserted on the container type: ``qualifiers`` is declared ``Mapping``, so
    a subscript assignment was never valid code — it only looked like a test
    because mypy did not read this directory.
    """
    parsed = parse("pkg:gem/jruby-launcher@1.1.2?platform=java")
    assert isinstance(parsed.qualifiers, MappingProxyType)
    assert not isinstance(parsed.qualifiers, MutableMapping)


def test_str_returns_the_canonical_form() -> None:
    """Interpolating a purl into a log line must not leak a repr."""
    parsed = parse("pkg:PYPI/Django_package@1.0")
    assert str(parsed) == "pkg:pypi/django-package@1.0"


def test_empty_qualifier_values_are_dropped() -> None:
    """ECMA-427: an empty value means the key is absent."""
    parsed = parse("pkg:maven/g/a@1.0?classifier=&type=jar")
    assert dict(parsed.qualifiers) == {"type": "jar"}
