"""The frozen schema-v1 JSON writer for org scans. Do not change this file.

``--schema v1`` routes here. This is the pre-unification writer, lifted out of
``org_scan/report.py`` **verbatim** so that a v1 payload is byte-identical to
what the previous release emitted, and so that nobody has to keep two writers
in sync as v2 evolves.

It is self-contained on purpose. ``display_name``, ``versions_display`` and
``key_signals`` were deleted from the models in the v2 work — they were string
formatting and a third hand-maintained English-string generator over scores
already in the payload — so the private helpers below recompute them, once,
here, frozen. Nothing in ``report.py`` is imported for them.

Removed in ``contract.SCHEMA_V1_REMOVAL_VERSION``. Until then the only
acceptable edits are ones that keep the bytes identical.

Its known defects are the reason v2 exists and are **not** fixed here:

* ``applicability_unknown_count`` / ``applicability_unknown_reasons`` are
  dropped, so "no applicable advisories" and "we could not tell whether these
  apply" (#61) read alike;
* every shared field is renamed relative to ``analyze --output json``;
* ``remediation`` is a free-text sentence an agent has to regex.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from ..models import DependencyRiskScore, SecurityMetrics
from ..popularity import should_soften_low_release_cadence
from .models import (
    AggregatedDependency,
    DependencyKey,
    OrgScanReport,
    RepositoryRiskSummary,
)


def write_json_report_v1(report: OrgScanReport, output_path: Path) -> None:
    """Write the aggregate report model as schema-v1 JSON.

    Args:
        report: The org scan report.
        output_path: Where to write the document.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report_to_dict_v1(report), indent=2),
        encoding="utf-8",
    )


def report_to_dict_v1(report: OrgScanReport) -> Dict[str, object]:
    """Convert an org scan report into schema-v1 JSON-compatible data.

    Args:
        report: The org scan report.

    Returns:
        The v1 document body.
    """
    return {
        "org": report.org,
        "account": report.org,
        "account_type": report.account_type,
        "generated_at": report.generated_at.isoformat(),
        "repositories_scanned": report.repositories_scanned,
        "repository_count": len(report.repositories_scanned),
        "manifests_scanned": report.manifests_scanned,
        "manifest_count": len(report.manifests_scanned),
        "unique_dependency_count": report.unique_dependency_count,
        "known_vulnerable_dependency_count": _known_vulnerable_count(report),
        "unscored_dependency_count": _unscored_count(report),
        "headline": report.headline,
        "high_risk_dependency_count": report.high_risk_dependency_count,
        "high_risk_exposed_repository_count": (
            report.high_risk_exposed_repository_count
        ),
        "most_exposed_risky_dependencies": [
            _dependency_to_dict(dep, len(report.repositories_scanned))
            for dep in report.most_exposed_risky_dependencies
        ],
        "riskiest_repositories": [
            _repository_to_dict(repo) for repo in report.riskiest_repositories
        ],
        "inventory": [
            _dependency_to_dict(dep, len(report.repositories_scanned))
            for dep in report.inventory
        ],
        "parse_failures": [
            {
                "repo": failure.repo_full_name,
                "path": failure.path,
                "reason": failure.reason,
            }
            for failure in report.parse_failures
        ],
        "warnings": report.warnings,
    }


def _known_vulnerable_count(report: OrgScanReport) -> int:
    """Count unique dependencies whose installed version has scored advisories.

    Args:
        report: The org scan report.

    Returns:
        The count.
    """
    return sum(1 for dep in report.inventory if dep.is_known_vulnerable)


def _unscored_count(report: OrgScanReport) -> int:
    """Count unique dependencies the scan could not score (#133).

    Args:
        report: The org scan report.

    Returns:
        The count.
    """
    return sum(1 for dep in report.inventory if dep.is_unscored)


def _dependency_to_dict(
    dependency: AggregatedDependency, repo_count: int
) -> Dict[str, object]:
    """Serialize dependency exposure.

    Args:
        dependency: The aggregated dependency.
        repo_count: How many repositories the scan covered.

    Returns:
        The v1 dependency entry.
    """
    score = dependency.risk_score
    return {
        "ecosystem": dependency.key.ecosystem,
        "name": dependency.key.name,
        "version": dependency.key.version,
        "version_specs": dependency.version_specs_list,
        "versions_display": _versions_display(dependency),
        "display_name": _display_name(dependency.key),
        "risk_level": dependency.risk_level.value,
        "known_vulnerable": dependency.is_known_vulnerable,
        "remediation": _remediation_hint(dependency),
        "risk_score": score.total_score,
        "component_scores": _component_scores_to_dict(score),
        "insufficient_data": score.insufficient_data,
        "unknown_signals": score.unknown_signals,
        "key_signals": _key_signals(score),
        "blast_radius": {
            "repository_count": dependency.blast_radius,
            "total_repositories_scanned": repo_count,
            "repositories": sorted(dependency.repositories),
            "manifests": sorted(dependency.manifests),
        },
        "usage": _usage_to_dict(dependency),
        "advisories": _advisory_to_dict(score),
        "risk_factors": score.factors,
        "metadata": _metadata_to_dict(score),
    }


def _display_name(key: DependencyKey) -> str:
    """Return the ecosystem-qualified label v1 emitted.

    Args:
        key: The dependency key.

    Returns:
        ``ecosystem:name@version``.
    """
    return f"{key.ecosystem}:{key.name}@{key.version}"


def _versions_display(dependency: AggregatedDependency) -> str:
    """Return the compact display of all seen version specs v1 emitted.

    Args:
        dependency: The aggregated dependency.

    Returns:
        The comma-joined specs.
    """
    return ", ".join(dependency.version_specs_list)


def _key_signals(score: DependencyRiskScore) -> List[str]:
    """Return the plain-language signal list v1 emitted.

    Args:
        score: The dependency's risk score.

    Returns:
        Up to four English signal phrases.
    """
    dependency = score.dependency
    if score.insufficient_data:
        return ["Insufficient data for confident risk level"]

    signals: List[str] = []
    if dependency.maintainer_count is not None and dependency.maintainer_count <= 1:
        signals.append("single maintainer")
    if dependency.is_deprecated:
        signals.append("deprecated")
    if should_soften_low_release_cadence(dependency) and (
        (score.staleness_score is not None and score.staleness_score > 0)
        or (score.maintained_score is not None and score.maintained_score > 0)
    ):
        signals.append("stable, low release cadence")
    if score.maintained_score is not None and score.maintained_score > 0.5:
        if not should_soften_low_release_cadence(dependency):
            signals.append("not actively maintained")
    if score.security_policy_score is not None and score.security_policy_score > 0.5:
        signals.append("missing security policy")
    if score.version_score is not None and score.version_score > 0:
        signals.append("behind latest")
    if score.license_score is not None and score.license_score > 0.5:
        signals.append("license risk")
    if score.exploit_score is not None and score.exploit_score > 0:
        signals.append("scored advisories")
    if dependency.transitive_dependencies:
        signals.append(f"{len(dependency.transitive_dependencies)} transitive deps")

    if not signals and score.factors:
        signals.extend(score.factors[:2])
    if not signals:
        signals.append("no leading risk signals")
    return signals[:4]


def _usage_to_dict(dependency: AggregatedDependency) -> List[Dict[str, object]]:
    """Serialize dependency repository/manifest occurrences.

    Args:
        dependency: The aggregated dependency.

    Returns:
        One entry per repository.
    """
    usage: List[Dict[str, object]] = []
    for repo_full_name in sorted(dependency.manifest_paths_by_repo):
        repo_ref = dependency.repo_refs.get(repo_full_name)
        usage.append(
            {
                "repo": repo_full_name,
                "html_url": repo_ref.html_url if repo_ref is not None else None,
                "default_branch": (
                    repo_ref.default_branch if repo_ref is not None else None
                ),
                "manifests": sorted(dependency.manifest_paths_by_repo[repo_full_name]),
            }
        )
    return usage


def _component_scores_to_dict(score: DependencyRiskScore) -> Dict[str, object]:
    """Serialize component risk scores for drill-down consumers.

    Args:
        score: The dependency's risk score.

    Returns:
        The component score map.
    """
    return {
        "staleness": score.staleness_score,
        "maintainer": score.maintainer_score,
        "deprecation": score.deprecation_score,
        "exploit": score.exploit_score,
        "version": score.version_score,
        "health_indicators": score.health_indicators_score,
        "license": score.license_score,
        "community": score.community_score,
        "transitive": score.transitive_score,
        "source_repository": score.source_repository_score,
        "security_policy": score.security_policy_score,
        "dependency_update": score.dependency_update_score,
        "signed_commits": score.signed_commits_score,
        "branch_protection": score.branch_protection_score,
        "maintained": score.maintained_score,
    }


def _repository_to_dict(repo: RepositoryRiskSummary) -> Dict[str, object]:
    """Serialize repository summary.

    Args:
        repo: The repository summary.

    Returns:
        The v1 repository entry.
    """
    return {
        "repo": repo.repo_full_name,
        "dependency_count": repo.dependency_count,
        "critical_risk_dependencies": repo.critical_risk_dependencies,
        "high_risk_dependencies": repo.high_risk_dependencies,
        "medium_risk_dependencies": repo.medium_risk_dependencies,
        "unknown_risk_dependencies": repo.unknown_risk_dependencies,
        "risk_points": repo.risk_points,
        "average_risk_score": repo.average_risk_score,
        "worst_dependencies": [
            {
                "ecosystem": dep.key.ecosystem,
                "name": dep.key.name,
                "version": dep.key.version,
                "version_specs": dep.version_specs_list,
                "versions_display": _versions_display(dep),
                "risk_level": dep.risk_level.value,
                "blast_radius": dep.blast_radius,
            }
            for dep in repo.worst_dependencies
        ],
    }


def _advisory_to_dict(score: DependencyRiskScore) -> Dict[str, object]:
    """Serialize vulnerability summary.

    Args:
        score: The dependency's risk score.

    Returns:
        The v1 advisory block.
    """
    metrics = score.dependency.security_metrics
    if metrics is None:
        return {
            "total_found": None,
            "counted_in_score": None,
            "filtered": None,
            "filtered_reasons": {},
            "max_counted_cvss_score": None,
            "max_counted_severity": None,
            "details": [],
        }
    return _security_metrics_to_dict(metrics)


def _security_metrics_to_dict(metrics: SecurityMetrics) -> Dict[str, object]:
    """Serialize security metrics vulnerability fields.

    Args:
        metrics: The dependency's security metrics.

    Returns:
        The v1 advisory block.
    """
    return {
        "total_found": metrics.vulnerability_count,
        "counted_in_score": metrics.counted_vulnerability_count,
        "filtered": metrics.filtered_vulnerability_count,
        "filtered_reasons": metrics.filtered_vulnerability_reasons,
        "max_counted_cvss_score": metrics.max_cvss_score,
        "max_counted_severity": metrics.max_vulnerability_severity,
        "details": metrics.vulnerability_details,
    }


def _metadata_to_dict(score: DependencyRiskScore) -> Dict[str, object]:
    """Serialize dependency metadata relevant to the org report.

    Args:
        score: The dependency's risk score.

    Returns:
        The v1 metadata block.
    """
    dependency = score.dependency
    license_info = dependency.license_info
    community = dependency.community_metrics
    return {
        "latest_version": dependency.latest_version,
        "last_updated": (
            dependency.last_updated.isoformat() if dependency.last_updated else None
        ),
        "maintainer_count": dependency.maintainer_count,
        "star_count": community.star_count if community is not None else None,
        "contributor_count": (
            community.contributor_count if community is not None else None
        ),
        "is_deprecated": dependency.is_deprecated,
        "repository_url": dependency.repository_url,
        "license": license_info.license_id if license_info is not None else None,
        "license_category": (
            license_info.category.value if license_info is not None else None
        ),
        "license_approved": (
            license_info.is_approved if license_info is not None else None
        ),
        "has_tests": dependency.has_tests,
        "has_ci": dependency.has_ci,
        "has_contribution_guidelines": dependency.has_contribution_guidelines,
        "transitive_dependency_count": len(dependency.transitive_dependencies),
    }


def _is_counted_advisory(detail: Dict[str, object]) -> bool:
    """Return whether a vulnerability detail counted in the score.

    Args:
        detail: One advisory detail.

    Returns:
        True when it counted.
    """
    counted = detail.get("counted_in_score")
    if isinstance(counted, bool):
        return counted
    return not _is_filtered_advisory(detail)


def _is_filtered_advisory(detail: Dict[str, object]) -> bool:
    """Return whether a vulnerability detail was filtered from the score.

    Args:
        detail: One advisory detail.

    Returns:
        True when it was filtered.
    """
    filtered = detail.get("filtered")
    if isinstance(filtered, bool) and filtered:
        return True
    withdrawn = detail.get("withdrawn")
    if isinstance(withdrawn, bool) and withdrawn:
        return True
    counted = detail.get("counted_in_score")
    if isinstance(counted, bool):
        return not counted
    return bool(_filter_reasons(detail))


def _filter_reasons(detail: Dict[str, object]) -> List[str]:
    """Return normalized filter reasons from advisory details.

    Args:
        detail: One advisory detail.

    Returns:
        The reasons, possibly empty.
    """
    value = detail.get("filter_reasons")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        reasons: List[str] = []
        for item in value:
            if isinstance(item, str):
                reasons.append(item)
        return reasons
    value = detail.get("filter_reason")
    if isinstance(value, str):
        return [value]
    return []


def _scored_fixed_versions(dependency: AggregatedDependency) -> List[str]:
    """Collect fixed versions from the advisories that counted toward the score.

    Args:
        dependency: The aggregated dependency.

    Returns:
        De-duplicated fix versions in publication order.
    """
    metrics = dependency.risk_score.dependency.security_metrics
    if metrics is None:
        return []
    versions: List[str] = []
    seen: set[str] = set()
    for detail in metrics.vulnerability_details:
        if not _is_counted_advisory(detail):
            continue
        fixed = detail.get("fixed_versions")
        if not isinstance(fixed, list):
            continue
        for version in fixed:
            if isinstance(version, str) and version and version not in seen:
                seen.add(version)
                versions.append(version)
    return versions


def _remediation_hint(dependency: AggregatedDependency) -> Optional[str]:
    """Return the one-line remediation sentence v1 emitted.

    Args:
        dependency: The aggregated dependency.

    Returns:
        The sentence, or ``None`` when no action was supported.
    """
    metadata = dependency.risk_score.dependency
    installed = metadata.installed_version or "the installed version"
    if dependency.is_known_vulnerable:
        fixes = _scored_fixed_versions(dependency)
        if fixes:
            return (
                f"{installed} has scored advisories; upgrade to a version at or "
                f"past the fix(es): {', '.join(fixes)}"
            )
        return (
            f"{installed} has scored advisories with no published fix; "
            "evaluate a replacement"
        )
    if metadata.is_deprecated:
        return "deprecated upstream; evaluate a maintained replacement"
    latest = metadata.latest_version
    if latest and latest != installed:
        return f"behind latest; upgrade {installed} → {latest}"
    return None
