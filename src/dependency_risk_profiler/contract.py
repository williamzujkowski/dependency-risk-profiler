"""The one ``ScoredDependency`` shape both reporters serialize (#164 step 5).

Before this module there were two of them. ``analyze --output json`` and
``scan-org`` described the same concept — a dependency somebody scored — and
agreed on five keys out of about twenty-one. The rest were silent renames of
identical data (``installed_version`` / ``version``, ``scores`` /
``component_scores``, ``has_known_exploits`` / ``known_vulnerable``,
``vulnerabilities`` / ``advisories``), so a consumer had to write two parsers
for one concept and could not tell from the payload which one it was holding.

This module is the single serializer. Both paths call :func:`scored_dependency`
and neither is allowed a private opinion about a shared field.

What v2 fixes beyond the renames
--------------------------------
* **License and community facts are serialized on both paths (#162.1).**
  ``analyze`` computed them on every run and threw them away, emitting
  ``license_score: 0.0`` while withholding *which licence*. A score without its
  evidence is not actionable.
* **The advisory list is emitted exactly once (#162.2).** v1's ``analyze``
  payload carried the same list under both ``vulnerability_summary.advisories``
  and ``vulnerabilities``; two keys pointing at one object is a divergence bug
  that has not happened yet.
* **``applicability_unknown_*`` survives both paths (#162.3).** ``scan-org``
  dropped it, which collapses "no applicable advisories" into "we could not
  tell whether these apply" — the exact honest-unknown distinction the rest of
  the codebase is built to preserve.
* **UNMEASURED is structurally distinct from a measured zero.** ``signals``
  reports each signal as ``{"state": "measured", "value": …}`` or
  ``{"state": "unmeasured", "reason": …}``. #198 made that unrepresentable in
  the scorer; v1 flattened it back to a bare ``null`` on the way out, which is
  indistinguishable from "the key exists and happens to be null". A consumer
  can now tell not only *that* a signal is missing but *why*.

What v2 deletes
---------------
``display_name`` and ``versions_display`` were string formatting over fields
already in the payload. ``key_signals`` was a third hand-maintained
English-string generator over the same scores that ``risk_factors`` already
describes. ``unknown_signal_count`` is ``len(unknown_signals)``. All four are
gone; ``version_specs`` stays, because the set of raw specifiers different
manifests used cannot be reconstructed from one resolved version.

The extension rule
------------------
Concepts that only exist in an org scan — ``blast_radius``, ``usage``,
``remediation``, ``version_specs`` — live under ``extensions.org_scan``. An
extension block may add keys. It may never rename, shadow, or redefine a shared
field, which is what keeps one parser sufficient for both paths.

Versioning
----------
The envelope carries :data:`SCHEMA_VERSION`. ``--schema v1`` routes to the
frozen v1 writers (``cli/json_v1.py``, ``org_scan/report_v1.py``) and is
removed in :data:`SCHEMA_V1_REMOVAL_VERSION`. The deprecation notice goes to
stderr so stdout stays parseable.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Mapping, Optional, Sequence

from .models import (
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
    LicenseInfo,
    SecurityMetrics,
)
from .signals import Measurement, MeasurementState

#: The schema this module emits. Bump only for a breaking change to the shape.
SCHEMA_VERSION = 2

#: The pre-unification schema, still reachable through ``--schema v1``.
LEGACY_SCHEMA_VERSION = 1

#: The release that removes ``--schema v1``. Stated as a number at v2 launch
#: rather than as a vague "later", which is what the design vote asked for.
SCHEMA_V1_REMOVAL_VERSION = "1.0.0"


def schema_deprecation_notice() -> str:
    """Return the warning shown when a caller asks for the legacy schema.

    Returns:
        A single line naming the replacement and the removal version.
    """
    return (
        f"warning: --schema v{LEGACY_SCHEMA_VERSION} is deprecated. "
        f"v{SCHEMA_VERSION} is the default and unifies the analyze and "
        f"scan-org payloads; v{LEGACY_SCHEMA_VERSION} is removed in "
        f"{SCHEMA_V1_REMOVAL_VERSION}. See docs/agents.md."
    )


# --- Untrusted registry data ------------------------------------------------

#: Longest version string worth carrying. Registry payloads are not trusted to
#: be short, and a remediation field is the one place in this contract that a
#: careless consumer is most likely to paste into a command line.
MAX_VERSION_LENGTH = 64

#: Everything a version string may contain. Deliberately narrower than any real
#: ecosystem's grammar: this is not a version parser, it is a refusal to hand a
#: consumer a string containing a shell metacharacter, a space, a quote, or a
#: path separator. Anything rejected here is reported as unclassified rather
#: than passed along, because a wrong-but-confident upgrade target is the same
#: failure mode as a wrong-but-confident risk verdict.
_VERSION_CHARACTERS = frozenset(
    "0123456789" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ".-+_~"
)


def safe_version(value: object) -> Optional[str]:
    """Return ``value`` if it is safe to publish as a version, else ``None``.

    ``fix_versions`` and ``target_version`` are **untrusted registry data**
    (binding security condition on #164). Nothing in this repository builds a
    package-manager invocation, but this contract is documented as agent-facing
    and an agent will. So the tool refuses to emit a "version" that could not
    be one.

    Args:
        value: A candidate version, from an advisory payload or a registry.

    Returns:
        The string unchanged when it is non-empty, within
        :data:`MAX_VERSION_LENGTH`, and made only of
        :data:`_VERSION_CHARACTERS`. ``None`` otherwise.
    """
    if not isinstance(value, str):
        return None
    if not value or len(value) > MAX_VERSION_LENGTH:
        return None
    if not _VERSION_CHARACTERS.issuperset(value):
        return None
    return value


# --- Structured remediation -------------------------------------------------


class RemediationAction(Enum):
    """What to do about a dependency, as an enum an agent can branch on.

    v1 shipped a sentence. An agent that wants to act on it has to regex prose,
    and prose drifts. These are the actions the measured data actually
    supports, plus an escape variant, because a confidently-wrong action enum
    is the remediation-shaped version of the confidently-wrong
    ``NOT_APPLICABLE`` this design already rejected.
    """

    #: Scored advisories apply and at least one published fix version is known.
    UPGRADE_TO_FIXED_VERSION = "upgrade_to_fixed_version"
    #: The installed version trails the latest published one, with no advisory.
    UPGRADE_TO_LATEST = "upgrade_to_latest"
    #: Deprecated upstream, or vulnerable with no published fix. Either way the
    #: answer is a different package, not a different version.
    REPLACE = "replace"
    #: Nothing measured demands an action.
    NO_ACTION = "no_action"
    #: Something demands an action and the data does not say which. The escape
    #: variant: an unclassifiable case is reported as unclassifiable rather
    #: than force-fitted into a neighbouring enum value. Always carries
    #: ``detail``.
    UNCLASSIFIED = "unclassified"


def remediation(
    metadata: DependencyMetadata, *, fix_versions: Sequence[object]
) -> Dict[str, object]:
    """Describe the supported action for one dependency.

    Precedence follows what the data supports, worst first: scored advisories,
    then deprecation, then version drift. ``target_version`` is only filled in
    when exactly one candidate exists; picking among several fix versions needs
    cross-ecosystem range resolution this tool does not claim to do, and
    guessing would be the confidently-wrong answer again.

    Args:
        metadata: The dependency's metadata.
        fix_versions: Fix versions from the advisories that counted toward the
            score, in the order they were published. Untrusted; filtered
            through :func:`safe_version`.

    Returns:
        ``{"action", "fix_versions", "target_version", "detail"}``.
    """
    safe_fixes: List[str] = []
    for candidate in fix_versions:
        cleaned = safe_version(candidate)
        if cleaned is not None and cleaned not in safe_fixes:
            safe_fixes.append(cleaned)
    rejected = len(list(fix_versions)) - len(safe_fixes)

    if known_vulnerable(metadata):
        if safe_fixes:
            return _remediation(
                RemediationAction.UPGRADE_TO_FIXED_VERSION,
                fix_versions=safe_fixes,
                target_version=safe_fixes[0] if len(safe_fixes) == 1 else None,
                detail=(
                    "Scored advisories apply to the installed version. Upgrade "
                    "to a version at or past the listed fixes."
                ),
            )
        if rejected:
            return _remediation(
                RemediationAction.UNCLASSIFIED,
                detail=(
                    "Scored advisories apply, and every published fix version "
                    "was rejected as unsafe to publish. Read the advisories "
                    "directly rather than acting on a version string from here."
                ),
            )
        return _remediation(
            RemediationAction.REPLACE,
            detail=(
                "Scored advisories apply and no fix version is published. "
                "Evaluate a replacement."
            ),
        )

    if metadata.is_deprecated:
        return _remediation(
            RemediationAction.REPLACE,
            detail="Deprecated upstream. Evaluate a maintained replacement.",
        )

    latest = safe_version(metadata.latest_version)
    if latest is not None and latest != metadata.installed_version:
        return _remediation(
            RemediationAction.UPGRADE_TO_LATEST,
            target_version=latest,
            detail="Behind the latest published version.",
        )
    if metadata.latest_version and latest is None:
        return _remediation(
            RemediationAction.UNCLASSIFIED,
            detail=(
                "The registry reported a latest version that was rejected as "
                "unsafe to publish."
            ),
        )

    return _remediation(
        RemediationAction.NO_ACTION,
        detail="No advisory, deprecation, or version drift was measured.",
    )


def _remediation(
    action: RemediationAction,
    *,
    fix_versions: Optional[List[str]] = None,
    target_version: Optional[str] = None,
    detail: str,
) -> Dict[str, object]:
    """Build one remediation block.

    Args:
        action: The classified action.
        fix_versions: Sanitized fix versions, if any.
        target_version: The single unambiguous upgrade target, if there is one.
        detail: Why this action, in one sentence. Never empty.

    Returns:
        The remediation block.
    """
    return {
        "action": action.value,
        "fix_versions": fix_versions or [],
        "target_version": target_version,
        "detail": detail,
    }


# --- Shared field definitions -----------------------------------------------


def known_vulnerable(metadata: DependencyMetadata) -> bool:
    """Whether the installed version has advisories that counted in the score.

    One definition for what v1 called ``has_known_exploits`` on one path and
    ``known_vulnerable`` on the other. They were computed from the same fact —
    ``aggregator`` sets ``has_known_exploits = bool(counted_vulnerabilities)``
    — so this reads the counted total when the aggregator ran and falls back to
    the flag when it did not.

    Deliberately orthogonal to ``risk_level``: risk level is driven by leading
    maintenance indicators, this is concrete exposure in the shipped version.

    Args:
        metadata: The dependency's metadata.

    Returns:
        True when at least one advisory counted toward the score.
    """
    metrics = metadata.security_metrics
    if metrics is not None and metrics.counted_vulnerability_count is not None:
        return bool(metrics.counted_vulnerability_count)
    return bool(metadata.has_known_exploits)


def measurement_to_dict(measurement: Measurement) -> Dict[str, object]:
    """Serialize one signal's two-state measurement.

    Both keys are always present, so a consumer reads ``state`` and then one
    field rather than inferring the state from which key is null.

    Args:
        measurement: The signal's measurement.

    Returns:
        ``{"state", "value", "reason"}``.
    """
    if measurement.state is MeasurementState.MEASURED:
        return {"state": "measured", "value": measurement.value, "reason": None}
    reason = measurement.reason
    return {
        "state": "unmeasured",
        "value": None,
        "reason": None if reason is None else reason.value,
    }


def signals_to_dict(
    measurements: Mapping[str, Measurement],
) -> Dict[str, object]:
    """Serialize every signal the scorer weighed, in catalog order.

    This replaces v1's ``scores`` and ``component_scores``, which were the same
    numbers under two names and could not tell a measured ``0.0`` from a signal
    nobody could read.

    Args:
        measurements: The scorer's per-signal measurements.

    Returns:
        Mapping of stable signal name to its measurement block.
    """
    return {
        name: measurement_to_dict(measurement)
        for name, measurement in measurements.items()
    }


def license_to_dict(license_info: Optional[LicenseInfo]) -> Optional[Dict[str, object]]:
    """Serialize the licence facts behind ``signals.license``.

    ``analyze`` computed these on every run and never emitted them (#162.1), so
    a consumer saw a licence risk score with no way to learn which licence.

    Args:
        license_info: The dependency's licence information, if any was read.

    Returns:
        The licence block, or ``None`` when no licence was read at all —
        which is distinct from a licence that was read and categorized
        ``UNKNOWN``.
    """
    if license_info is None:
        return None
    return {
        "id": license_info.license_id,
        "category": license_info.category.value,
        "is_approved": license_info.is_approved,
        "url": license_info.url,
        "risk_level": license_info.risk_level.value,
    }


def community_to_dict(
    metrics: Optional[CommunityMetrics],
) -> Optional[Dict[str, object]]:
    """Serialize the community facts behind the popularity/activity signals.

    Args:
        metrics: The dependency's community metrics, if any were read.

    Returns:
        The community block, or ``None`` when nobody looked.
    """
    if metrics is None:
        return None
    return {
        "star_count": metrics.star_count,
        "contributor_count": metrics.contributor_count,
        "commit_frequency": metrics.commit_frequency,
        "last_release_date": _iso(metrics.last_release_date),
        "installed_release_date": _iso(metrics.installed_release_date),
    }


def advisories_to_dict(metrics: Optional[SecurityMetrics]) -> Dict[str, object]:
    """Serialize advisory accounting and the advisory list, exactly once.

    Args:
        metrics: The dependency's security metrics, if any were read.

    Returns:
        The advisory block. Counts are ``None`` rather than ``0`` when no
        lookup happened, because zero advisories found and no advisory lookup
        are not the same claim.
    """
    if metrics is None:
        return {
            "total_found": None,
            "counted_in_score": None,
            "filtered": None,
            "filtered_reasons": {},
            "applicability_unknown": None,
            "applicability_unknown_reasons": {},
            "max_counted_cvss_score": None,
            "max_counted_severity": None,
            "details": [],
        }
    return {
        "total_found": metrics.vulnerability_count,
        "counted_in_score": metrics.counted_vulnerability_count,
        "filtered": metrics.filtered_vulnerability_count,
        "filtered_reasons": dict(metrics.filtered_vulnerability_reasons),
        # Dropped entirely by scan-org in v1 (#162.3). These record advisories
        # whose applicability to the installed version could not be decided
        # (#61); without them "none apply" and "we could not tell" read alike.
        "applicability_unknown": metrics.applicability_unknown_count,
        "applicability_unknown_reasons": dict(metrics.applicability_unknown_reasons),
        "max_counted_cvss_score": metrics.max_cvss_score,
        "max_counted_severity": metrics.max_vulnerability_severity,
        "details": list(metrics.vulnerability_details),
    }


def scored_dependency(
    score: DependencyRiskScore,
    *,
    ecosystem: Optional[str],
    extensions: Optional[Mapping[str, object]] = None,
) -> Dict[str, object]:
    """Serialize one scored dependency. The contract both reporters emit.

    Args:
        score: The scored dependency.
        ecosystem: The ecosystem key the dependency was resolved under, or
            ``None`` when the caller genuinely does not know.
        extensions: Path-specific blocks, keyed by path name (``org_scan``).
            An extension may add keys; it may never rename or shadow a shared
            field, and this function does not merge it into the top level.

    Returns:
        The ``ScoredDependency`` mapping, with JSON-native values only.
    """
    metadata = score.dependency
    return {
        "name": metadata.name,
        "ecosystem": ecosystem,
        # v1 called this ``installed_version`` on one path and ``version`` on
        # the other. The longer name wins because ``version`` reads as "the
        # package's version" next to ``version_specs`` and ``latest_version``.
        "installed_version": metadata.installed_version,
        "latest_version": metadata.latest_version,
        "last_updated": _iso(metadata.last_updated),
        "repository_url": metadata.repository_url,
        "is_deprecated": metadata.is_deprecated,
        "known_vulnerable": known_vulnerable(metadata),
        "maintainer_count": metadata.maintainer_count,
        "risk_level": score.risk_level.value,
        "risk_score": score.total_score,
        "risk_factors": list(score.factors),
        "insufficient_data": score.insufficient_data,
        "license": license_to_dict(metadata.license_info),
        "community": community_to_dict(metadata.community_metrics),
        "health": {
            "has_tests": metadata.has_tests,
            "has_ci": metadata.has_ci,
            "has_contribution_guidelines": metadata.has_contribution_guidelines,
        },
        "transitive_dependency_count": len(metadata.transitive_dependencies),
        "advisories": advisories_to_dict(metadata.security_metrics),
        "signals": signals_to_dict(score.measurements),
        "unknown_signals": list(score.unknown_signals),
        # ``unknown_signal_count`` is gone: it is ``len(unknown_signals)``.
        # These two are not, because they count the signals that entered the
        # weighted score, which is a smaller set than the catalog whenever a
        # signal leaves both numerator and denominator (#74).
        "measured_signal_count": score.measured_signal_count,
        "total_signal_count": score.total_signal_count,
        "extensions": dict(extensions) if extensions else {},
    }


def _iso(value: Optional[datetime]) -> Optional[str]:
    """Render a datetime as ISO-8601, or pass ``None`` through.

    Args:
        value: The datetime to render.

    Returns:
        The ISO-8601 string, or ``None``.
    """
    return None if value is None else value.isoformat()
