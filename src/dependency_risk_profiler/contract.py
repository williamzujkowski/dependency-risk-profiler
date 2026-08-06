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
* **``field_sources`` says which acquisition path wrote a field that has more
  than one.** ``star_count`` is written from an unauthenticated github.com HTML
  regex scrape and from the authenticated REST API — both live in a single org
  scan, in that order — into one unlabelled integer. Seven fields collapse two
  or more trust levels this way; v2 labels them (#164 step 7).

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

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .models import (
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
    LicenseInfo,
    SecurityMetrics,
    VerdictFloor,
)
from .signals import FieldSource, Measurement, MeasurementState, ProvenancedField

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


@dataclass(frozen=True)
class Remediation:
    """The supported action for one dependency, with both its renderings.

    One structure, two views of it. :meth:`to_dict` is what the v2 JSON carries
    and what an agent branches on; :meth:`sentence` is the prose a CSV cell or
    a human-facing report shows. The sentence is *derived from* the structure
    rather than classified again beside it: v1 had a separate prose generator
    with its own precedence rules, which is how two descriptions of the same
    dependency could disagree — and, worse, how a version string the structured
    path refused as unsafe still reached the CSV. #205 collapsed three
    hand-maintained English-string generators into one. This is not a fourth.
    """

    #: The classified action. Branch on this.
    action: RemediationAction
    #: Published fix versions that survived :func:`safe_version`, in the order
    #: the advisories published them. **Untrusted registry data**: never
    #: interpolate into a package-manager command line, pass as an argument.
    fix_versions: Tuple[str, ...]
    #: The single unambiguous upgrade target, or ``None`` when there is not
    #: exactly one. **Untrusted registry data**, same rule as ``fix_versions``.
    target_version: Optional[str]
    #: Why this action, in one sentence. Never empty.
    detail: str

    def to_dict(self) -> Dict[str, object]:
        """Serialize as the ``extensions.org_scan.remediation`` block.

        Returns:
            ``{"action", "fix_versions", "target_version", "detail"}``.
        """
        return {
            "action": self.action.value,
            "fix_versions": list(self.fix_versions),
            "target_version": self.target_version,
            "detail": self.detail,
        }

    def sentence(self) -> str:
        """Render the one-line prose form, for terminal, HTML and CSV reports.

        Reads the structure; it does not re-derive the action. Returns the
        empty string for :attr:`RemediationAction.NO_ACTION` so a report can
        leave the cell blank rather than print a sentence saying nothing.

        Returns:
            The sentence, or ``""`` when no action is called for.
        """
        if self.action is RemediationAction.NO_ACTION:
            return ""
        if self.target_version is not None:
            return f"{self.detail} Target: {self.target_version}."
        if self.fix_versions:
            return f"{self.detail} Published fixes: {', '.join(self.fix_versions)}."
        return self.detail


def remediation(
    metadata: DependencyMetadata, *, fix_versions: Sequence[object]
) -> Remediation:
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
        The classified :class:`Remediation`.
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
) -> Remediation:
    """Build one remediation block.

    Args:
        action: The classified action.
        fix_versions: Sanitized fix versions, if any.
        target_version: The single unambiguous upgrade target, if there is one.
        detail: Why this action, in one sentence. Never empty.

    Returns:
        The remediation block.
    """
    return Remediation(
        action=action,
        fix_versions=tuple(fix_versions or ()),
        target_version=target_version,
        detail=detail,
    )


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


#: Member-to-value lookups, built once. ``Enum.value`` is a descriptor call,
#: and this block is built per dependency across thousands of them in an org
#: scan, so the lookup is hoisted out of the loop. Measured at a third of the
#: cost of the ``.value`` comprehension it replaces; see ``docs/signals.md``.
#:
#: A ``str`` mixin on the enums would make this a pointer copy and beat both,
#: and it was rejected: the design's security condition rests on the vocabulary
#: being *closed*, and a member that compares equal to a bare string is a
#: weaker foundation for that argument than one microsecond per dependency is
#: worth.
_FIELD_NAMES: Mapping[ProvenancedField, str] = {
    field_name: field_name.value for field_name in ProvenancedField
}
_SOURCE_NAMES: Mapping[FieldSource, str] = {
    source: source.value for source in FieldSource
}


def field_sources_to_dict(metadata: DependencyMetadata) -> Dict[str, str]:
    """Serialize which acquisition path wrote each multiply-written field.

    v2-only, and the reason the provenance work was worth doing at all: a
    ``star_count`` regex-scraped out of github.com HTML and one read from the
    authenticated REST API arrived in the same key with nothing to tell them
    apart, and in an org scan *both* write it, in that order. Seven fields have
    more than one acquisition path; see :class:`~.signals.ProvenancedField`.

    Only fields something actually wrote appear. An absent key means nobody
    recorded a source, which is distinct from a source of "unknown" — the same
    rule the rest of this contract follows about not inventing measurements.

    Args:
        metadata: The dependency's metadata.

    Returns:
        Mapping of field name to its sanitized logical locator. Both sides are
        closed vocabularies, so nothing here can carry a credential, a host, a
        query string or a filesystem path.
    """
    return {
        _FIELD_NAMES[field_name]: _SOURCE_NAMES[source]
        for field_name, source in metadata.field_sources.items()
    }


def forge_to_dict(metadata: DependencyMetadata) -> Dict[str, object]:
    """Serialize which forge was asked, and what it answered per capability.

    The reason a package hosted somewhere without an adapter scores on fewer
    signals than a GitHub one, readable from the payload alone (#292). Fifteen
    of sixteen signals are read from a ``git clone`` and are unaffected by any
    of this; the ones reported here are the facts a clone cannot carry, so a
    consumer can attribute a missing ``community_popularity`` to the host
    rather than to the package.

    ``software`` is ``None`` when no registered adapter claims the host. That
    is not a failure and must not read as one — the repository is cloneable and
    every clone-derived signal is measured exactly as it is on GitHub.

    Args:
        metadata: The dependency's metadata.

    Returns:
        The forge block. ``capabilities`` is empty when nothing asked a forge
        about this dependency at all, which is the case for a package that
        declares no usable source repository.
    """
    return {
        "software": metadata.forge.value if metadata.forge is not None else None,
        "capabilities": {
            capability.value: (
                {
                    "state": answer.state.value,
                    "field_source": (
                        _SOURCE_NAMES[answer.field_source]
                        if answer.field_source is not None
                        else None
                    ),
                }
                if answer.is_measured
                else {
                    "state": answer.state.value,
                    "reason": answer.reason.value if answer.reason else None,
                }
            )
            for capability, answer in metadata.forge_answers.items()
        },
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
            "severity_unknown": None,
            "severity_unknown_reasons": {},
            "cvss_unknown": None,
            "cvss_unknown_reasons": {},
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
        # Counted advisories that state no severity, and why (#272). Additive,
        # and load-bearing for reading the two fields below: a non-zero count
        # here with a null ``max_counted_severity`` is a package with live
        # advisories none of whose publishers scored them, which is the normal
        # case for Go and Rust and for every malicious-package advisory.
        "severity_unknown": metrics.severity_unknown_count,
        "severity_unknown_reasons": dict(metrics.severity_unknown_reasons),
        # Counted advisories that carry no CVSS base score, and why (#273).
        # Additive, and load-bearing for reading the field below it:
        # ``max_counted_cvss_score`` is the maximum over the advisories that
        # *are* scored, and this says how many are not. A null maximum beside a
        # non-zero count here is a package whose live advisories nobody scored;
        # a null maximum beside a zero count is a package with no counted
        # advisories at all. Before #273 neither could be told from a 10.0,
        # because an unscored advisory had the tier constant written in for it.
        "cvss_unknown": metrics.cvss_unknown_count,
        "cvss_unknown_reasons": dict(metrics.cvss_unknown_reasons),
        "max_counted_cvss_score": metrics.max_cvss_score,
        "max_counted_severity": metrics.max_vulnerability_severity,
        "details": list(metrics.vulnerability_details),
    }


def verdict_floor_to_dict(floor: Optional[VerdictFloor]) -> Dict[str, object]:
    """Serialize the lagging-evidence floor under a verdict (#242).

    Additive: ``risk_level`` keeps its meaning and its position, and this block
    says whether a fact rather than the weighted mean is what put it there.
    Every key is always present, and ``applied`` carries the state — the same
    shape ``measurement_to_dict`` uses, and for the same reason: a consumer
    should read one field, not infer a state from which key is null.

    ``applied: false`` with a non-null ``floor`` is the informative case. It
    says the floor was computed and the verdict already cleared it, which is
    what lets a test assert the *cause* of a verdict rather than only its
    value. ``floor`` is published rather than left to be re-derived from
    ``max_counted_severity``: a consumer should not have to reimplement the
    rule to read the record of it being applied.

    Args:
        floor: The floor the scorer recorded, or None when the counted
            advisories established none.

    Returns:
        The ``verdict_floor`` block.
    """
    if floor is None:
        return {
            "applied": False,
            "max_counted_severity": None,
            "advisory_id": None,
            "floor": None,
            "from": None,
            "to": None,
        }
    return {
        "applied": floor.applied,
        "max_counted_severity": floor.max_counted_severity,
        "advisory_id": floor.advisory_id,
        "floor": floor.floor_level.value,
        "from": floor.unfloored_level.value,
        "to": floor.floor_level.value if floor.applied else None,
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
        # Additive in schema 2 (#242). Says whether ``risk_level`` is where the
        # weighted mean left it or where a counted advisory held it.
        "verdict_floor": verdict_floor_to_dict(score.verdict_floor),
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
        # Which acquisition path wrote each field that has more than one (#164
        # step 7). Sits beside ``signals`` because it answers the neighbouring
        # question: ``signals`` says whether a value exists and why not, this
        # says how much the value that does exist is worth.
        "field_sources": field_sources_to_dict(metadata),
        # Which forge served the facts a clone cannot carry, and what it said
        # to each. Sits beside ``field_sources`` because it answers the
        # neighbouring question: that says how much a value is worth, this says
        # whether anything could have produced one at all (#292).
        "forge": forge_to_dict(metadata),
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
