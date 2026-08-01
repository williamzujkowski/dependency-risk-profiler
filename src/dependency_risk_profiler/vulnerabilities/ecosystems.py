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


class UnknownEcosystem(KeyError):
    """Raised by ``resolve`` when an ecosystem identity cannot be resolved."""


@dataclass(frozen=True)
class Ecosystem:
    """One ecosystem's identity and its name in each vulnerability source."""

    key: str
    osv: str
    github_advisory: Optional[str]
    nvd_cpe_prefix: Optional[str]
    deps_dev: Optional[str]


# Canonical entries. Fully-supported ecosystems (an analyzer emits them) plus
# OSV-only ones that today have routing but no analyzer yet — kept so
# centralization does not drop their working OSV coverage. ``java`` is its own
# entry, not an alias of ``maven``: the two share OSV/GHA names but diverge in
# the NVD CPE prefix, a legacy quirk preserved here.
_ECOSYSTEMS: Tuple[Ecosystem, ...] = (
    Ecosystem("nodejs", "npm", "NPM", "cpe:2.3:a:*:node:", "npm"),
    Ecosystem("python", "PyPI", "PIP", "cpe:2.3:a:python:", "pypi"),
    Ecosystem("golang", "Go", "GO", "cpe:2.3:a:golang:", "go"),
    Ecosystem("cargo", "crates.io", "RUST", "cpe:2.3:a:rust:", "cargo"),
    Ecosystem("maven", "Maven", "MAVEN", "cpe:2.3:a:apache:maven:", None),
    Ecosystem("java", "Maven", "MAVEN", "cpe:2.3:a:java:", None),
    Ecosystem("nuget", "NuGet", "NUGET", None, None),
    Ecosystem("ruby", "RubyGems", "RUBYGEMS", "cpe:2.3:a:ruby:", "rubygems"),
    Ecosystem("composer", "Packagist", "COMPOSER", "cpe:2.3:a:php:", None),
)

# Every spelling the four legacy routing tables accepted, mapped to a canonical
# key. Built from the union of those tables' keys (see
# testing/unit/test_ecosystem_routing_parity.py) — a missing alias would drop a
# source's coverage for that spelling, re-introducing the #66 class. ``toml`` is
# deliberately absent: it was a deps.dev-only, semantically-bogus alias for
# cargo and is handled as a vestigial special case in _deps_dev_system (pending
# removal in #75) rather than leaking "cargo" into OSV/GHA/NVD.
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
