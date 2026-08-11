"""How much of the composite is computed from a URL the package chooses?

`docs/full-instrument-manipulation-protocol.md`. Exact and offline: the weight
share is read from the scorer's own constructor rather than retyped here, so a
re-weighted scorer changes this answer instead of leaving it stale.

The eight repository-derived signals are read from whatever repository the
`repository` field names, and `record_source_repository` assigns DECLARED to
any URL that canonicalizes to an `owner/repo` root on a supported host. Nothing
checks that the repository relates to the package.
"""

from __future__ import annotations

import inspect
from typing import Dict, Tuple

from dependency_risk_profiler.scoring.risk_scorer import RiskScorer

#: Signals computed from the contents of the declared repository. Each is read
#: by cloning or querying whatever `repository` names, so each is chosen by the
#: package rather than observed independently of it.
REPOSITORY_DERIVED: Tuple[str, ...] = (
    "health_indicators",
    "community",
    "transitive",
    "security_policy",
    "dependency_update",
    "signed_commits",
    "branch_protection",
    "maintained",
)

#: Read from the registry, not from the repository. `source_repository` is
#: deliberately NOT counted as repository-derived: it records whether a URL was
#: declared, which is a registry fact, even though it is the same field the
#: attack manipulates.
REGISTRY_DERIVED: Tuple[str, ...] = (
    "staleness",
    "maintainer",
    "deprecation",
    "exploit",
    "version_difference",
    "source_repository",
)


def declared_weights() -> Dict[str, float]:
    """Every weight the scorer's constructor declares, by signal name.

    Read from the signature so the numbers cannot drift out of step with the
    code. A weight added without a corresponding entry in the two tuples above
    is caught by `total_accounted`, not silently ignored.
    """
    signature = inspect.signature(RiskScorer.__init__)
    out: Dict[str, float] = {}
    for name, parameter in signature.parameters.items():
        if not name.endswith("_weight"):
            continue
        if not isinstance(parameter.default, (int, float)):
            continue
        out[name[: -len("_weight")]] = float(parameter.default)
    return out


def attacker_surface() -> Dict[str, object]:
    """The share of declared weight computed from the package's chosen URL."""
    weights = declared_weights()
    repository = {k: v for k, v in weights.items() if k in REPOSITORY_DERIVED}
    registry = {k: v for k, v in weights.items() if k in REGISTRY_DERIVED}
    unaccounted = sorted(
        set(weights) - set(REPOSITORY_DERIVED) - set(REGISTRY_DERIVED)
    )
    total = sum(weights.values())
    return {
        "weights": dict(sorted(weights.items())),
        "repository_derived_weight": sum(repository.values()),
        "registry_derived_weight": sum(registry.values()),
        "total_declared_weight": total,
        "attacker_controlled_share": (
            sum(repository.values()) / total if total else 0.0
        ),
        "unaccounted_signals": unaccounted,
        "repository_derived": dict(sorted(repository.items())),
    }
