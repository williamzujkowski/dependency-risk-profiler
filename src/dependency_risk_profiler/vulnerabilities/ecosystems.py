"""Single source of truth for ecosystem identity and vulnerability routing.

Every ecosystem the tool knows about is declared once here, with its name in
each upstream source (OSV, GitHub Advisory, NVD CPE, deps.dev). The four routing
tables that used to be hand-synced across the codebase delegate to this module,
so adding an ecosystem is a one-line change instead of a twelve-site scavenger
hunt — the desync that caused the npm->PyPI silent-zero-advisories bug (#66) and
the dormant cargo/go gaps (#76, #77).

Design (ratified by consensus on #72): a frozen dataclass per ecosystem plus an
alias map built from the union of the legacy tables' keys. ``resolve`` fails
closed on an unknown identity so new callers can never silently default;
``lookup`` is the non-raising variant the legacy delegation sites use to
preserve each table's historical unknown-input behavior exactly.

Optional fields model partial coverage honestly: ``None`` means "this source
does not cover this ecosystem" (return that source's skip value), which is not
the same as an unknown identity.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional, Tuple

from ..versioning import VersionScheme


class UnknownEcosystem(KeyError):
    """Raised by ``resolve`` when an ecosystem identity cannot be resolved."""


@dataclass(frozen=True)
class Ecosystem:
    """One ecosystem's identity and its name in each vulnerability source.

    ``purl_type`` is the ECMA-427 package-url type (#164). It lives here rather
    than in a table of its own for the same reason the four source names do:
    two tables claiming to know what an ecosystem is will drift, and the drift
    is silent (#66). Note that it is not injective — ``java`` and ``maven`` are
    separate entries that share the ``maven`` purl type — so nine keys yield
    eight purl types.
    """

    key: str
    osv: str
    github_advisory: Optional[str]
    nvd_cpe_prefix: Optional[str]
    deps_dev: Optional[str]
    version_scheme: VersionScheme
    purl_type: str


# Canonical entries. Fully-supported ecosystems (an analyzer emits them) plus
# OSV-only ones that today have routing but no analyzer yet — kept so
# centralization does not drop their working OSV coverage. ``java`` is its own
# entry, not an alias of ``maven``: the two share OSV/GHA names but diverge in
# the NVD CPE prefix, a legacy quirk preserved here.
_ECOSYSTEMS: Tuple[Ecosystem, ...] = (
    Ecosystem(
        "nodejs",
        "npm",
        "NPM",
        "cpe:2.3:a:*:node:",
        "npm",
        VersionScheme.SEMVER,
        "npm",
    ),
    Ecosystem(
        "python",
        "PyPI",
        "PIP",
        "cpe:2.3:a:python:",
        "pypi",
        VersionScheme.PEP440,
        "pypi",
    ),
    Ecosystem(
        "golang",
        "Go",
        "GO",
        "cpe:2.3:a:golang:",
        "go",
        VersionScheme.SEMVER,
        "golang",
    ),
    Ecosystem(
        "cargo",
        "crates.io",
        "RUST",
        "cpe:2.3:a:rust:",
        "cargo",
        VersionScheme.SEMVER,
        "cargo",
    ),
    Ecosystem(
        "maven",
        "Maven",
        "MAVEN",
        "cpe:2.3:a:apache:maven:",
        "maven",
        VersionScheme.MAVEN,
        "maven",
    ),
    Ecosystem(
        "java",
        "Maven",
        "MAVEN",
        "cpe:2.3:a:java:",
        "maven",
        VersionScheme.MAVEN,
        "maven",
    ),
    Ecosystem("nuget", "NuGet", "NUGET", None, "nuget", VersionScheme.NUGET, "nuget"),
    Ecosystem(
        "ruby",
        "RubyGems",
        "RUBYGEMS",
        "cpe:2.3:a:ruby:",
        "rubygems",
        VersionScheme.RUBYGEMS,
        "gem",
    ),
    Ecosystem(
        "composer",
        "Packagist",
        "COMPOSER",
        "cpe:2.3:a:php:",
        None,
        VersionScheme.SEMVER,
        "composer",
    ),
)

# Every spelling the four legacy routing tables accepted, mapped to a canonical
# key. Built from the union of those tables' keys (see
# testing/unit/test_ecosystem_routing_parity.py) — a missing alias would drop a
# source's coverage for that spelling, re-introducing the #66 class. ``toml`` is
# deliberately absent: it was a deps.dev-only, semantically-bogus alias for
# cargo, removed with the generic .toml pseudo-ecosystem (#75).
_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        "nodejs": "nodejs",
        "node": "nodejs",
        "npm": "nodejs",
        "python": "python",
        "py": "python",
        "pypi": "python",
        "pyproject": "python",
        "golang": "golang",
        "go": "golang",
        "cargo": "cargo",
        "crates": "cargo",
        "rust": "cargo",
        "maven": "maven",
        "java": "java",
        "nuget": "nuget",
        "dotnet": "nuget",
        "ruby": "ruby",
        "gems": "ruby",
        "rubygems": "ruby",
        "composer": "composer",
        "php": "composer",
    }
)

_REGISTRY: Mapping[str, Ecosystem] = MappingProxyType(
    {eco.key: eco for eco in _ECOSYSTEMS}
)


def lookup(name: str) -> Optional[Ecosystem]:
    """Return the Ecosystem for an ecosystem name or alias, or None if unknown.

    Case-insensitive. Non-raising: the legacy routing delegates use this so they
    can preserve each table's historical unknown-input behavior.
    """
    key = _ALIASES.get(name.strip().lower())
    return _REGISTRY.get(key) if key is not None else None


def resolve(name: str) -> Ecosystem:
    """Return the Ecosystem for a name or alias; fail closed on unknown.

    New code should use this: an unresolved ecosystem raises rather than
    silently defaulting (the failure mode behind #66).
    """
    eco = lookup(name)
    if eco is None:
        raise UnknownEcosystem(name)
    return eco


def version_scheme(name: str) -> VersionScheme:
    """Return the version-ordering rules for an ecosystem name or alias.

    Unlike the source-routing lookups, this one has a defensible default: an
    unrecognized ecosystem falls back to the lenient SemVer comparator, which
    orders the numeric-dotted shape every ecosystem shares and reports
    "unparseable" for anything else. It never guesses an *ordering* — that
    would be the #61 failure mode — only which comparator to try.

    Args:
        name: Ecosystem name or alias.

    Returns:
        The ecosystem's version scheme, or ``VersionScheme.SEMVER`` when the
        name is not recognized.
    """
    eco = lookup(name)
    return eco.version_scheme if eco is not None else VersionScheme.SEMVER
