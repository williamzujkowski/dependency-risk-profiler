"""purl (package-url, ECMA-427) parsing, building, and canonicalization.

Step 2 of the ratified design in #164: adopt purl as the dependency primary
key. This module is **additive** — nothing in the profiler reads it yet. It is
built, tested against the official ``package-url/purl-spec`` conformance suite,
and left standing on its own until the conformance harness covers enough
ecosystems to make rewiring the adapters safe.

Two layers live here, and the split is deliberate:

1. **Spec layer.** :class:`PackageURL`, :func:`parse` and
   :meth:`PackageURL.to_string` implement ECMA-427 Clause 5 plus the
   registered type definitions for the eight types we care about. This layer
   answers "is this string canonical?" and nothing else. It is validated by
   the vendored upstream test suite in ``testing/fixtures/purl-spec/`` — see
   ``testing/unit/test_purl_conformance.py``.

2. **Identity layer.** :func:`identity_key` applies *our* primary-key policy on
   top of a canonical purl, dropping the components that do not distinguish one
   dependency from another. Keeping this out of :meth:`PackageURL.to_string` is
   what lets the key be opinionated while the canonical form stays conformant.
   See "Identity policy" below for the rule and the two decisions it settles.

Stdlib only, by ratified condition: ``urllib.parse`` for percent-encoding, no
``packageurl-python`` dependency.

Ecosystem identity is **not** redeclared here. The purl type for each of our
ecosystem keys hangs off :class:`~.vulnerabilities.ecosystems.Ecosystem`, which
remains the single source of truth (#72); this module only maps through it.

Security posture (binding condition on #164)
--------------------------------------------
purl strings arrive from registry payloads and user-supplied manifests, so
:func:`parse` treats every input as hostile:

* hard length ceilings on the whole string, on each decoded component, and on
  the qualifier count, checked *before* any decoding work;
* the input must be pure ASCII with no C0/C1 control characters or DEL, both
  before and after percent-decoding;
* percent-escapes must be well-formed (``%`` followed by exactly two hex
  digits) and must decode as strict UTF-8 — ``urllib.parse.unquote`` silently
  substitutes U+FFFD otherwise, which would let a mangled byte sequence
  masquerade as a valid package name;
* **nothing in this module opens a file, builds a path, issues a request, or
  shells out.** There is no API here that returns a filesystem path or a URL.
  A decoded name containing ``../..`` stays inert data and is re-encoded as
  ``..%2F..`` on the way out. ``testing/unit/test_purl_adversarial.py`` asserts
  the absence of those sinks against the module source, so the guarantee
  survives future edits.

Identity policy: identity is not metadata
-----------------------------------------
purl already draws the line we need, and the rule generalizes past the two
cases that forced us to state it:

    **An identity key may abstain from optional detail. It may never lie.**

Whatever purl puts in the *type*, *namespace*, *name* or *version* is identity:
drop it and the key denotes a different package. Whatever purl puts in a
*qualifier* is metadata: omit it and you still have a valid, spec-legal purl —
merely a less specific one. So the key keeps every identity component and is
free to drop qualifiers.

That rule settles both of the genuinely ambiguous ecosystems (ratified 7-0 on
 #164):

* **Go's ``/vN`` stays in the key.** The major-version suffix lives in the
  *name* component. ``github.com/cespare/xxhash`` and
  ``github.com/cespare/xxhash/v2`` are distinct modules to the Go toolchain,
  with independent version timelines, and OSV keys Go advisories on the full
  module path including the suffix. Stripping ``/v2`` would not make the key
  vaguer, it would make it name a different module — the key would lie.
* **RubyGems' ``platform`` stays out of the key.** It is a *qualifier*, and
  every signal we measure is platform-invariant: the MRI, JRuby and
  native-gem builds all ship from one source repository, with one maintainer,
  one release cadence, one advisory stream. Omitting it yields a valid purl
  that is simply less specific. Observed platforms are recorded as an
  attribute instead — see :class:`DependencyIdentity` — so nothing is lost.

Two levels, named on purpose
----------------------------
Conflating these is how a key gets corrupted to fix a display problem.

1. **Primary key** — :func:`identity_key`. Faithful identity, per the rule
   above. Never widened to make a report read better.
2. **Rollup group** — :func:`rollup_group_key`. A *derived* grouping for
   blast-radius and ranking views. For Go this is the ``/vN``-stripped
   repository, which is already computed by the #130 module resolver;
   :func:`rollup_group_key` delegates to
   :class:`~.go_modules.GoModuleResolver` rather than reimplementing the
   strip. There is deliberately no second stripper in this module.

"v1 and v2 look like duplicates in the ranking" is a presentation problem and
is solved by grouping the view on level 2. The ranking layer must call
:func:`rollup_group_key` rather than re-deriving a grouping of its own.

Known interop cost (raised in the #164 review; recorded, not discovered later)
-----------------------------------------------------------------------------
Dropping ``platform`` means our emitted key for a platform-specific gem is
**not byte-identical** to the purl that a lockfile-derived SBOM carries:
CycloneDX and SPDX generators emit ``pkg:gem/nokogiri@1.16.0?platform=java``,
and we emit ``pkg:gem/nokogiri@1.16.0``. A consumer doing exact-string purl
joins against external tooling will silently miss those rows. The join must go
through :func:`identity_key` on both sides, or through
:meth:`DependencyIdentity.observed_purls` to recover the specific spellings.
This needs an explicit note in the #164 output-schema work, because a silent
miss is exactly the failure mode a shared schema is supposed to prevent.
"""

import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Dict, Iterable, Mapping, Optional, Tuple
from urllib.parse import quote, unquote

from .vulnerabilities.ecosystems import Ecosystem, resolve

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance for annotations
    from .go_modules import GoModuleResolver

__all__ = [
    "MAX_COMPONENT_LENGTH",
    "MAX_PURL_LENGTH",
    "MAX_QUALIFIERS",
    "DependencyIdentity",
    "DependencyVariant",
    "PackageURL",
    "PurlError",
    "canonicalize",
    "collapse",
    "for_dependency",
    "go_module_path",
    "identity_key",
    "parse",
    "purl_type_for_ecosystem",
    "rollup_group_key",
]


class PurlError(ValueError):
    """Raised for any purl string or component set that is not valid.

    A single exception type on purpose: callers act on "this identifier is
    unusable", not on which of a dozen syntax rules it broke. The message
    carries the detail.
    """


# --------------------------------------------------------------------------
# Input limits. Checked before decoding, so a hostile input cannot make us do
# unbounded work. The ceilings are far above anything a real registry emits —
# the longest Maven coordinate on Central is under 200 characters — and exist
# to bound memory, not to police naming.
# --------------------------------------------------------------------------

MAX_PURL_LENGTH = 4096
"""Maximum length of a purl string accepted by :func:`parse`."""

MAX_COMPONENT_LENGTH = 512
"""Maximum decoded length of any single purl component or qualifier value."""

MAX_QUALIFIERS = 32
"""Maximum number of ``key=value`` pairs in the qualifiers component."""


_SCHEME = "pkg"

# ECMA-427 Clause 5: type is ASCII letters, digits, '.' and '-', starting with
# a letter, and is never percent-encoded.
_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9.\-]*$")

# Qualifier keys are lowercase letters, digits, '.', '-' and '_', starting with
# a letter, and are never percent-encoded. Validated *after* lowercasing, which
# is what the build algorithm specifies.
_QUALIFIER_KEY_RE = re.compile(r"^[a-z][a-z0-9.\-_]*$")

# A '%' that is not the start of a well-formed triplet. urllib's unquote would
# pass these through untouched; we reject instead.
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")

# C0 controls, DEL, and C1 controls. Rejected in the raw input and again in
# every decoded component.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Characters left unencoded when building a canonical purl. urllib.parse.quote
# already exempts the alphanumerics and the punctuation characters '.-_~'; the
# spec additionally says the colon "shall not be percent-encoded, whether used
# as a Separator Character or otherwise". Everything else — including '/' and
# '@' inside a component, and ',' inside a checksum list — is encoded.
_SAFE = ":"


class _Requirement:
    """Namespace requirement values from the purl type-definition schema."""

    REQUIRED = "required"
    OPTIONAL = "optional"
    PROHIBITED = "prohibited"


@dataclass(frozen=True)
class _TypeRules:
    """Per-type canonicalization rules, transcribed from ``purl-spec/types/``.

    Each field mirrors a property of the upstream ``*-definition.json`` file so
    the transcription can be audited line by line. ``lower_*`` corresponds to
    ``case_sensitive: false``; ``name_underscore_to_dash`` corresponds to a
    ``normalization_rules`` entry.
    """

    namespace_requirement: str = _Requirement.OPTIONAL
    lower_namespace: bool = False
    lower_name: bool = False
    lower_version: bool = False
    name_underscore_to_dash: bool = False


_DEFAULT_RULES = _TypeRules()

# Transcribed from the registered type definitions at
# https://github.com/package-url/purl-spec/tree/main/types (see
# testing/fixtures/purl-spec/PROVENANCE.md for the pinned revision).
#
# Deliberate divergences from the "obvious" reading, each verified against the
# upstream test suite:
#
# * **pypi** folds case and maps '_' -> '-' only. It does *not* apply full
#   PEP 503 normalization: PEP 503 also collapses '.' into '-', which would
#   turn `pkg:pypi/zope.interface` into `pkg:pypi/zope-interface` and break
#   every real-world PyPI purl. The type definition asks for the underscore
#   rule alone. Its second normalization rule ('.' -> '_') is scoped to sdist
#   and wheel *filenames*, not to the purl name, so it is not implemented here.
# * **pypi versions** are lowercased: the type definition marks the version
#   component `case_sensitive: false`, and PEP 440 agrees that version
#   comparison is case-insensitive with a lowercase normal form.
# * **nuget** does *not* fold case. The registry is case-insensitive and
#   case-preserving, which invites folding, but the type definition marks the
#   name `case_sensitive: true` and the upstream test suite asserts
#   `pkg:nuget/EnterpriseLibrary.Common@6.0.1304` round-trips unchanged.
# * **golang** does *not* fold case either. The type definition is
#   self-contradictory here — it marks namespace and name `case_sensitive:
#   true` while a free-text note says they "must be lowercased" — and no test
#   case exercises an uppercase Go path. We follow the machine-readable field,
#   because case *is* significant to the Go module proxy, which bang-encodes
#   uppercase letters (`github.com/!masterminds/semver`) precisely so that
#   `Masterminds` and `masterminds` stay distinct modules.
_TYPE_RULES: Mapping[str, _TypeRules] = MappingProxyType(
    {
        "cargo": _TypeRules(namespace_requirement=_Requirement.PROHIBITED),
        "composer": _TypeRules(
            namespace_requirement=_Requirement.REQUIRED,
            lower_namespace=True,
            lower_name=True,
        ),
        "gem": _TypeRules(namespace_requirement=_Requirement.PROHIBITED),
        "golang": _TypeRules(namespace_requirement=_Requirement.REQUIRED),
        "maven": _TypeRules(namespace_requirement=_Requirement.REQUIRED),
        "npm": _TypeRules(namespace_requirement=_Requirement.OPTIONAL),
        "nuget": _TypeRules(namespace_requirement=_Requirement.PROHIBITED),
        "pypi": _TypeRules(
            namespace_requirement=_Requirement.PROHIBITED,
            lower_name=True,
            lower_version=True,
            name_underscore_to_dash=True,
        ),
    }
)


def _rules_for(purl_type: str) -> _TypeRules:
    """Return the canonicalization rules for a purl type.

    Unregistered types get the permissive default: canonical means "the core
    spec was followed", with no type-specific folding. Failing closed here
    would reject valid purls for the 30-odd types we do not model.

    Args:
        purl_type: A lowercased purl type.

    Returns:
        The rules for that type, or the permissive default.
    """
    return _TYPE_RULES.get(purl_type, _DEFAULT_RULES)


# --------------------------------------------------------------------------
# Untrusted-input guards
# --------------------------------------------------------------------------


def _reject_hostile(value: str, what: str) -> None:
    """Reject control characters and non-ASCII bytes in a raw purl string.

    ECMA-427 defines a purl string as ASCII; anything outside that range in the
    *encoded* form is either an encoding bug upstream or an attempt to smuggle
    a homoglyph past a comparison. Control characters are rejected everywhere,
    encoded or decoded, because a package identifier carrying a NUL or an ANSI
    escape has no legitimate reading and every log sink downstream is a
    potential injection point.

    Args:
        value: The string to check.
        what: Human-readable name of the component, for the error message.

    Raises:
        PurlError: If the string is non-ASCII or contains a control character.
    """
    if not value.isascii():
        raise PurlError(f"{what} contains non-ASCII characters")
    match = _CONTROL_RE.search(value)
    if match is not None:
        raise PurlError(
            f"{what} contains a control character (0x{ord(match.group()):02x})"
        )


def _reject_control(value: str, what: str) -> None:
    """Reject control characters in a decoded component.

    Decoded components may hold any Unicode character, so the ASCII check does
    not apply — but percent-decoding is exactly how a control character would
    be smuggled in, so this runs on every decoded value.

    Args:
        value: The decoded string to check.
        what: Human-readable name of the component, for the error message.

    Raises:
        PurlError: If the string contains a control character.
    """
    match = _CONTROL_RE.search(value)
    if match is not None:
        raise PurlError(
            f"{what} contains a control character (0x{ord(match.group()):02x})"
        )


def _decode(value: str, what: str) -> str:
    """Percent-decode one component, refusing anything malformed.

    Args:
        value: The percent-encoded component.
        what: Human-readable name of the component, for error messages.

    Returns:
        The decoded component.

    Raises:
        PurlError: If an escape is malformed, the bytes are not valid UTF-8,
            the result exceeds :data:`MAX_COMPONENT_LENGTH`, or the result
            contains a control character.
    """
    if _BAD_PERCENT_RE.search(value) is not None:
        raise PurlError(f"{what} contains a malformed percent-escape")
    try:
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PurlError(f"{what} is not valid percent-encoded UTF-8") from exc
    if len(decoded) > MAX_COMPONENT_LENGTH:
        raise PurlError(f"{what} exceeds the component length limit")
    _reject_control(decoded, what)
    return decoded


def _encode(value: str) -> str:
    """Percent-encode one component for the canonical form.

    Args:
        value: The decoded component.

    Returns:
        The percent-encoded component.
    """
    return quote(value, safe=_SAFE)


# --------------------------------------------------------------------------
# The purl itself
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PackageURL:
    """A canonical, immutable package-url.

    Instances are always canonical: the constructor validates and normalizes,
    so there is no such thing as a non-canonical :class:`PackageURL`. Build one
    with :func:`parse`, :func:`for_dependency`, or the keyword constructor.

    Attributes:
        type: The purl type, lowercased (``npm``, ``pypi``, ``maven``, ...).
        namespace: The type-specific name prefix (npm scope, Maven groupId,
            Go module prefix), or None.
        name: The package name. Always present.
        version: The version string, or None. Opaque — never parsed here.
        qualifiers: Sorted, immutable ``key=value`` map. Empty when absent.
        subpath: Slash-joined subpath within the package, or None.
    """

    type: str
    name: str
    namespace: Optional[str] = None
    version: Optional[str] = None
    qualifiers: Mapping[str, str] = field(default_factory=dict)
    subpath: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate and canonicalize every component.

        Raises:
            PurlError: If any component violates ECMA-427 or the registered
                type definition for :attr:`type`.
        """
        object.__setattr__(self, "type", _clean_type(self.type))
        rules = _rules_for(self.type)

        object.__setattr__(self, "namespace", _clean_namespace(self.namespace, rules))
        object.__setattr__(self, "name", _clean_name(self.name, rules))
        object.__setattr__(self, "version", _clean_version(self.version, rules))
        object.__setattr__(self, "qualifiers", _clean_qualifiers(self.qualifiers))
        object.__setattr__(self, "subpath", _clean_subpath(self.subpath))

    def to_string(self) -> str:
        """Render the canonical purl string.

        Strictly ECMA-427: no identity policy is applied. Use
        :func:`identity_key` for the primary key.

        Returns:
            The canonical purl string.
        """
        parts = [_SCHEME, ":", self.type, "/"]
        if self.namespace:
            parts.append("/".join(_encode(s) for s in self.namespace.split("/")))
            parts.append("/")
        parts.append(_encode(self.name))
        if self.version:
            parts.append("@")
            parts.append(_encode(self.version))
        if self.qualifiers:
            parts.append("?")
            parts.append(
                "&".join(
                    f"{key}={_encode(value)}"
                    for key, value in sorted(self.qualifiers.items())
                )
            )
        if self.subpath:
            parts.append("#")
            parts.append("/".join(_encode(s) for s in self.subpath.split("/")))
        return "".join(parts)

    def __str__(self) -> str:
        """Return the canonical purl string.

        Returns:
            The canonical purl string.
        """
        return self.to_string()


def _clean_type(value: str) -> str:
    """Validate and lowercase the type component.

    Args:
        value: The raw type.

    Returns:
        The lowercased type.

    Raises:
        PurlError: If the type is empty or has an illegal character.
    """
    if not value:
        raise PurlError("purl type is required")
    if len(value) > MAX_COMPONENT_LENGTH:
        raise PurlError("purl type exceeds the component length limit")
    if _TYPE_RE.match(value) is None:
        raise PurlError(f"invalid purl type: {value!r}")
    return value.lower()


def _clean_namespace(value: Optional[str], rules: _TypeRules) -> Optional[str]:
    """Validate and normalize the namespace component.

    Args:
        value: The raw namespace, already percent-decoded.
        rules: The type's canonicalization rules.

    Returns:
        The normalized namespace, or None when absent.

    Raises:
        PurlError: If the namespace is missing where the type requires one,
            present where the type prohibits one, or has an empty segment.
    """
    segments: Tuple[str, ...] = ()
    if value:
        _reject_control(value, "purl namespace")
        segments = tuple(s for s in value.split("/") if s)
        if not segments:
            raise PurlError("purl namespace has no non-empty segment")
        for segment in segments:
            if len(segment) > MAX_COMPONENT_LENGTH:
                raise PurlError(
                    "purl namespace segment exceeds the component length limit"
                )
        if rules.lower_namespace:
            segments = tuple(s.lower() for s in segments)

    if not segments:
        if rules.namespace_requirement == _Requirement.REQUIRED:
            raise PurlError("purl namespace is required for this type")
        return None
    if rules.namespace_requirement == _Requirement.PROHIBITED:
        raise PurlError("purl namespace is prohibited for this type")
    return "/".join(segments)


def _clean_name(value: str, rules: _TypeRules) -> str:
    """Validate and normalize the name component.

    Args:
        value: The raw name, already percent-decoded.
        rules: The type's canonicalization rules.

    Returns:
        The normalized name.

    Raises:
        PurlError: If the name is empty or over the length limit.
    """
    if not value:
        raise PurlError("purl name is required")
    _reject_control(value, "purl name")
    if len(value) > MAX_COMPONENT_LENGTH:
        raise PurlError("purl name exceeds the component length limit")
    if rules.lower_name:
        value = value.lower()
    if rules.name_underscore_to_dash:
        value = value.replace("_", "-")
    return value


def _clean_version(value: Optional[str], rules: _TypeRules) -> Optional[str]:
    """Validate and normalize the version component.

    Args:
        value: The raw version, already percent-decoded, or None.
        rules: The type's canonicalization rules.

    Returns:
        The normalized version, or None when absent.

    Raises:
        PurlError: If the version is over the length limit.
    """
    if not value:
        return None
    _reject_control(value, "purl version")
    if len(value) > MAX_COMPONENT_LENGTH:
        raise PurlError("purl version exceeds the component length limit")
    return value.lower() if rules.lower_version else value


def _clean_qualifiers(value: Mapping[str, str]) -> Mapping[str, str]:
    """Validate, lowercase, and freeze the qualifiers component.

    Args:
        value: Raw ``key=value`` pairs with already-decoded values.

    Returns:
        An immutable, key-sorted mapping. Pairs with an empty value are
        dropped: ECMA-427 says an empty value means the key is absent.

    Raises:
        PurlError: If a key is illegal, two keys collide after lowercasing, a
            value is over the length limit, or there are too many pairs.
    """
    if not value:
        return MappingProxyType({})
    if len(value) > MAX_QUALIFIERS:
        raise PurlError(f"purl has more than {MAX_QUALIFIERS} qualifiers")

    cleaned: Dict[str, str] = {}
    for raw_key, raw_value in value.items():
        key = raw_key.lower()
        if _QUALIFIER_KEY_RE.match(key) is None:
            raise PurlError(f"invalid purl qualifier key: {raw_key!r}")
        if raw_value is None or raw_value == "":
            continue
        _reject_control(raw_value, f"purl qualifier {key!r}")
        if len(raw_value) > MAX_COMPONENT_LENGTH:
            raise PurlError(
                f"purl qualifier {key!r} exceeds the component length limit"
            )
        if key in cleaned:
            raise PurlError(f"duplicate purl qualifier key: {key!r}")
        cleaned[key] = raw_value
    return MappingProxyType(dict(sorted(cleaned.items())))


def _clean_subpath(value: Optional[str]) -> Optional[str]:
    """Validate and normalize the subpath component.

    ``.`` and ``..`` segments are dropped, per ECMA-427. That is a spec rule
    rather than a security control — the subpath never becomes a filesystem
    path anywhere in this module — but it does mean a traversal-shaped subpath
    cannot survive canonicalization.

    Args:
        value: The raw subpath, already percent-decoded, or None.

    Returns:
        The normalized slash-joined subpath, or None when nothing survives.

    Raises:
        PurlError: If a segment is over the length limit.
    """
    if not value:
        return None
    _reject_control(value, "purl subpath")
    segments = [s for s in value.split("/") if s and s not in (".", "..")]
    for segment in segments:
        if len(segment) > MAX_COMPONENT_LENGTH:
            raise PurlError("purl subpath segment exceeds the component length limit")
    return "/".join(segments) or None


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def parse(value: str) -> PackageURL:
    """Parse a purl string into a canonical :class:`PackageURL`.

    Implements the right-to-left algorithm from the purl specification's
    "How to parse" guide, with the input treated as hostile throughout (see
    the module docstring).

    One documented refinement of the published algorithm: it says to split the
    remainder "once from right on '@'", which mis-parses the unencoded npm
    scope in ``pkg:npm/@babel/core`` as a version of ``babel/core``. We only
    treat an ``'@'`` as the version separator when it falls *after* the last
    ``'/'``, which is the reading the upstream test suite requires.

    Args:
        value: A purl string, canonical or not.

    Returns:
        The parsed, canonicalized purl.

    Raises:
        PurlError: If the string is not a valid purl.
    """
    if not isinstance(value, str):
        raise PurlError("purl must be a string")
    if not value:
        raise PurlError("purl is empty")
    if len(value) > MAX_PURL_LENGTH:
        raise PurlError(f"purl exceeds the {MAX_PURL_LENGTH}-character limit")
    _reject_hostile(value, "purl")

    remainder, _, subpath_str = value.rpartition("#")
    if not remainder:
        remainder, subpath_str = subpath_str, ""
    subpath = _parse_subpath(subpath_str)

    remainder, sep, qualifiers_str = remainder.rpartition("?")
    if not sep:
        remainder, qualifiers_str = qualifiers_str, ""
    qualifiers = _parse_qualifiers(qualifiers_str)

    scheme, sep, remainder = remainder.partition(":")
    if not sep:
        raise PurlError("purl is missing the 'pkg:' scheme")
    if scheme.lower() != _SCHEME:
        raise PurlError(f"purl scheme must be 'pkg', got {scheme!r}")

    # "PURL parsers shall accept URLs where the scheme and colon are followed
    # by one or more slash characters, such as 'pkg://', and shall ignore and
    # remove all such characters."
    remainder = remainder.lstrip("/")

    purl_type, sep, remainder = remainder.partition("/")
    if not sep:
        raise PurlError("purl is missing the name component")

    remainder, version_str = _split_version(remainder)
    version = _decode(version_str, "purl version") if version_str else None

    remainder = remainder.rstrip("/")
    namespace_str, _, name_str = remainder.rpartition("/")
    name = _decode(name_str, "purl name")

    namespace: Optional[str] = None
    if namespace_str:
        namespace = "/".join(
            _decode(segment, "purl namespace")
            for segment in namespace_str.split("/")
            if segment
        )

    return PackageURL(
        type=purl_type,
        namespace=namespace or None,
        name=name,
        version=version,
        qualifiers=qualifiers,
        subpath=subpath,
    )


def _split_version(remainder: str) -> Tuple[str, str]:
    """Split the path remainder into its pre-version part and the version.

    Args:
        remainder: Everything between the type and the qualifiers.

    Returns:
        A ``(remainder, version)`` pair; ``version`` is empty when absent.
    """
    at = remainder.rfind("@")
    if at == -1 or at < remainder.rfind("/"):
        return remainder, ""
    return remainder[:at], remainder[at + 1 :]


def _parse_subpath(value: str) -> Optional[str]:
    """Decode the subpath component of a purl string.

    Args:
        value: The raw text after the ``'#'`` separator.

    Returns:
        The decoded slash-joined subpath, or None.

    Raises:
        PurlError: If a decoded segment contains a slash.
    """
    if not value:
        return None
    segments = []
    for raw in value.split("/"):
        if not raw:
            continue
        segment = _decode(raw, "purl subpath")
        if "/" in segment:
            raise PurlError("purl subpath segment contains an encoded slash")
        segments.append(segment)
    return "/".join(segments) or None


def _parse_qualifiers(value: str) -> Mapping[str, str]:
    """Decode the qualifiers component of a purl string.

    Args:
        value: The raw text after the ``'?'`` separator.

    Returns:
        Decoded ``key=value`` pairs; validation happens in
        :func:`_clean_qualifiers`.

    Raises:
        PurlError: If there are too many pairs or a pair has no ``'='``.
    """
    if not value:
        return {}
    pairs = value.split("&")
    if len(pairs) > MAX_QUALIFIERS:
        raise PurlError(f"purl has more than {MAX_QUALIFIERS} qualifiers")

    parsed: Dict[str, str] = {}
    for pair in pairs:
        if not pair:
            continue
        key, sep, raw_value = pair.partition("=")
        if not sep:
            raise PurlError(f"purl qualifier {pair!r} has no '=' separator")
        key = key.lower()
        if key in parsed:
            raise PurlError(f"duplicate purl qualifier key: {key!r}")
        parsed[key] = _decode(raw_value, f"purl qualifier {key!r}")
    return parsed


def canonicalize(value: str) -> str:
    """Parse a purl string and re-render it in canonical form.

    Args:
        value: A purl string, canonical or not.

    Returns:
        The canonical purl string.

    Raises:
        PurlError: If the string is not a valid purl.
    """
    return parse(value).to_string()


# --------------------------------------------------------------------------
# Bridging our ecosystem keys to purl types
# --------------------------------------------------------------------------


def purl_type_for_ecosystem(ecosystem: str) -> str:
    """Return the purl type for one of our ecosystem keys or aliases.

    Delegates to the centralized registry (#72) so ecosystem identity keeps one
    source of truth. ``java`` and ``maven`` both map to the ``maven`` purl
    type, which is why nine registry keys yield eight purl types.

    Args:
        ecosystem: An ecosystem key or alias, e.g. ``nodejs``, ``npm``,
            ``rust``.

    Returns:
        The purl type string.

    Raises:
        UnknownEcosystem: If the name does not resolve. Failing closed is the
            registry's contract; a purl built from a guessed type would be a
            silently wrong primary key.
    """
    eco: Ecosystem = resolve(ecosystem)
    return eco.purl_type


def for_dependency(
    ecosystem: str,
    name: str,
    version: Optional[str] = None,
    qualifiers: Optional[Mapping[str, str]] = None,
) -> PackageURL:
    """Build a purl from the way this profiler already names dependencies.

    Bridges our internal naming to the purl namespace/name split:

    * Maven and Java take ``groupId:artifactId`` (the key used across the
      parsers) and also accept ``groupId/artifactId``.
    * npm takes ``@scope/name`` or a bare name.
    * Go and Composer take a slash-separated path; everything before the last
      slash is the namespace.
    * PyPI, Cargo, NuGet, and RubyGems have no namespace.

    Args:
        ecosystem: An ecosystem key or alias.
        name: The dependency name as this profiler spells it.
        version: The resolved version, if known.
        qualifiers: Extra purl qualifiers, e.g. ``{"platform": "java"}``.

    Returns:
        The canonical purl.

    Raises:
        PurlError: If the name is empty or the result is not a valid purl.
        UnknownEcosystem: If the ecosystem does not resolve.
    """
    purl_type = purl_type_for_ecosystem(ecosystem)
    if not name or not name.strip():
        raise PurlError("dependency name is required")
    namespace, package_name = _split_name(purl_type, name.strip())
    return PackageURL(
        type=purl_type,
        namespace=namespace,
        name=package_name,
        version=version,
        qualifiers=qualifiers or {},
    )


def _split_name(purl_type: str, name: str) -> Tuple[Optional[str], str]:
    """Split an internal dependency name into (namespace, name).

    Args:
        purl_type: The resolved purl type.
        name: The dependency name as this profiler spells it.

    Returns:
        A ``(namespace, name)`` pair; namespace is None when the type has none.
    """
    if purl_type == "maven":
        separator = ":" if ":" in name else "/"
        namespace, _, artifact = name.rpartition(separator)
        return (namespace or None), (artifact or name)
    if purl_type in ("npm", "golang", "composer"):
        namespace, _, package_name = name.rpartition("/")
        return (namespace or None), (package_name or name)
    return None, name


def go_module_path(purl: PackageURL) -> str:
    """Reassemble a Go module path from a ``golang`` purl.

    The purl parsing algorithm splits ``github.com/foo/bar/v2`` into namespace
    ``github.com/foo/bar`` and name ``v2``, which is faithful to the spec and
    useless to read. This puts it back together. The ``/vN`` major-version
    suffix is preserved: see "Identity policy" in the module docstring.

    Args:
        purl: A purl whose type is ``golang``.

    Returns:
        The full Go module path.

    Raises:
        PurlError: If the purl is not a ``golang`` purl.
    """
    if purl.type != "golang":
        raise PurlError(f"not a golang purl: {purl.type!r}")
    if purl.namespace:
        return f"{purl.namespace}/{purl.name}"
    return purl.name


# --------------------------------------------------------------------------
# Level 1: the primary key
# --------------------------------------------------------------------------

# Qualifiers are metadata, never identity (see the module docstring). The key
# therefore carries none of them. ``repository_url``, ``checksum``,
# ``file_name`` and ``vcs_url`` say where a copy came from; Maven's
# ``classifier`` and ``type`` say which artifact of one coordinate you took;
# RubyGems' ``platform`` says which build of one source tree you took. None of
# them changes *which package* this is, and letting any of them into the key
# would fragment one dependency into several.
#
# Nothing dropped here is lost: `collapse` records it per observed spelling and
# `DependencyIdentity.observed_purls` reconstructs the originals.


def identity_key(purl: PackageURL) -> str:
    """Return the primary key for a dependency, as a purl string.

    Keeps every identity-bearing component — type, namespace, name, version,
    including Go's ``/vN`` suffix, which lives in the name — and drops the
    components that are metadata: all qualifiers, and the subpath. A subpath
    addresses a directory inside a package rather than a different package, and
    every health signal we collect is package-level.

    The result is itself a valid canonical purl, so a key round-trips through
    :func:`parse`.

    Args:
        purl: A canonical purl.

    Returns:
        The identity key.
    """
    return PackageURL(
        type=purl.type,
        namespace=purl.namespace,
        name=purl.name,
        version=purl.version,
    ).to_string()


@dataclass(frozen=True)
class DependencyVariant:
    """One observed spelling that an identity key abstracts over.

    Holds exactly the components :func:`identity_key` discards, so that the key
    plus its variants reconstructs every purl collapsed into it.

    Attributes:
        qualifiers: The observed qualifiers, canonical and immutable.
        subpath: The observed subpath, or None.
    """

    qualifiers: Mapping[str, str] = field(default_factory=dict)
    subpath: Optional[str] = None

    def __hash__(self) -> int:
        """Hash on the observed detail.

        Returns:
            A hash over the qualifiers and subpath. Defined by hand because a
            Mapping field is not hashable by default.
        """
        return hash(self.sort_key())

    def __eq__(self, other: object) -> bool:
        """Compare two variants by their observed detail.

        Args:
            other: The object to compare against.

        Returns:
            True when both variants carry identical qualifiers and subpath.
        """
        if not isinstance(other, DependencyVariant):
            return NotImplemented
        return self.sort_key() == other.sort_key()

    def sort_key(self) -> Tuple[str, str]:
        """Return a stable ordering key.

        Returns:
            The qualifiers and subpath rendered as a sortable pair of strings.
        """
        rendered = "&".join(f"{k}={v}" for k, v in sorted(self.qualifiers.items()))
        return rendered, self.subpath or ""


@dataclass(frozen=True)
class DependencyIdentity:
    """A primary key plus the observed detail that key abstracts over.

    This is the answer to "we dropped ``platform`` from the key, so where did
    it go". :attr:`key` is the faithful identity; :attr:`variants` records each
    distinct spelling that collapsed into it, so nothing observed is lost.

    Attributes:
        key: The primary key, a canonical purl string.
        variants: Distinct observed variants, in a stable order.
    """

    key: str
    variants: Tuple[DependencyVariant, ...] = ()

    @property
    def platforms(self) -> Tuple[str, ...]:
        """Return the distinct RubyGems platforms observed for this dependency.

        A gem observed without an explicit ``platform`` qualifier reports the
        type default, ``ruby``, because that is what the gem type definition
        says a bare purl means. Non-gem dependencies report an empty tuple.

        Returns:
            The observed platforms, sorted and deduplicated.
        """
        if not self.key.startswith("pkg:gem/"):
            return ()
        seen = {
            variant.qualifiers.get("platform") or "ruby" for variant in self.variants
        }
        return tuple(sorted(seen))

    def observed_purls(self) -> Tuple[str, ...]:
        """Reconstruct the canonical purls that collapsed into this identity.

        The losslessness guarantee: this returns exactly the canonical form of
        every purl handed to :func:`collapse`, deduplicated and ordered.

        Returns:
            The observed canonical purl strings.

        Raises:
            PurlError: If :attr:`key` is not a valid purl.
        """
        base = parse(self.key)
        if not self.variants:
            return (base.to_string(),)
        return tuple(
            PackageURL(
                type=base.type,
                namespace=base.namespace,
                name=base.name,
                version=base.version,
                qualifiers=variant.qualifiers,
                subpath=variant.subpath,
            ).to_string()
            for variant in self.variants
        )


def collapse(purls: Iterable[PackageURL]) -> DependencyIdentity:
    """Collapse observed spellings of one dependency into a single identity.

    The three published builds of a gem — ``x86_64-linux``, ``arm64-darwin``
    and ``java`` — are one dependency with one key and three recorded
    platforms, not three dependencies.

    Args:
        purls: Canonical purls expected to share an identity key.

    Returns:
        The shared key and every distinct variant observed under it.

    Raises:
        PurlError: If the input is empty, or if the purls do not all share one
            identity key. Silently picking a winner would be the
            fabricated-value failure mode #164 exists to prevent.
    """
    items = list(purls)
    if not items:
        raise PurlError("cannot collapse an empty set of purls")

    keys = {identity_key(item) for item in items}
    if len(keys) > 1:
        raise PurlError(
            "cannot collapse purls with different identity keys: "
            + ", ".join(sorted(keys))
        )

    variants = {
        DependencyVariant(qualifiers=item.qualifiers, subpath=item.subpath)
        for item in items
    }
    return DependencyIdentity(
        key=keys.pop(),
        variants=tuple(sorted(variants, key=DependencyVariant.sort_key)),
    )


# --------------------------------------------------------------------------
# Level 2: the derived rollup group
# --------------------------------------------------------------------------


def rollup_group_key(
    purl: PackageURL, go_resolver: Optional["GoModuleResolver"] = None
) -> str:
    """Return the *derived* grouping key for blast-radius and ranking views.

    Level 2 of the two-level model, and coarser than :func:`identity_key` on
    purpose: it drops the version, and for Go it drops the ``/vN`` suffix so
    that ``xxhash`` and ``xxhash/v2`` — two distinct modules with two distinct
    primary keys — roll up to the one repository they actually share.

    The Go strip is **not** reimplemented here. It delegates to the #130 module
    resolver, which already handles mirrors, major-version suffixes and
    subdirectory modules, and which is the only place that logic should live.

    Args:
        purl: A canonical purl.
        go_resolver: Resolver used for ``golang`` purls. Defaults to a fresh
            :class:`~.go_modules.GoModuleResolver`. Pass a shared instance to
            reuse its vanity-path cache. Ignored for every other type.

    Returns:
        A grouping key: the repository URL for Go modules that resolve, and the
        version-less canonical purl for everything else.
    """
    if purl.type == "golang":
        # Imported lazily: go_modules pulls in the HTTP stack for vanity-path
        # lookups, and parsing a purl must never require it.
        from .go_modules import GoModuleResolver as _Resolver

        resolver = go_resolver if go_resolver is not None else _Resolver()
        repository = resolver.resolve(go_module_path(purl))
        if repository is not None:
            return repository.url

    return PackageURL(
        type=purl.type,
        namespace=purl.namespace,
        name=purl.name,
    ).to_string()
