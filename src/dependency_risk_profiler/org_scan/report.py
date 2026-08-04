"""HTML, JSON, and terminal reporting for org-wide scans."""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

from ..contract import SCHEMA_VERSION, Remediation, remediation, scored_dependency
from ..models import DependencyMetadata, DependencyRiskScore, RiskLevel, SecurityMetrics
from ..versioning import (
    calendar_drift_days,
    calendar_drift_label,
    release_timestamps,
    uses_calendar_versioning,
)
from ..vulnerabilities import ecosystems
from .models import (
    AggregatedDependency,
    DependencyKey,
    OrgScanReport,
    RepositoryCoverage,
    RepositoryRef,
    RepositoryRiskSummary,
    risk_rank,
)
from .report_v1 import write_json_report_v1


def render_terminal_summary(report: OrgScanReport) -> str:
    """Render the org scan terminal summary."""
    lines = [
        f"Dependency Risk {_account_title(report)} Scan · {report.org}",
        (
            f"{len(report.repositories_scanned)} repos · "
            f"{len(report.manifests_scanned)} manifests · "
            f"{report.unique_dependency_count} unique dependencies"
        ),
        report.headline,
        "",
        "Most exposed risky dependencies:",
    ]
    for index, dependency in enumerate(report.most_exposed_risky_dependencies[:10], 1):
        lines.append(
            f"{index}. {_display_label(dependency.key)} · "
            f"{dependency.risk_level.value} · "
            f"{dependency.blast_radius} / {len(report.repositories_scanned)} repos · "
            f"{_signal_phrases(dependency)} · "
            f"{dependency.advisory_summary}"
        )

    if not report.most_exposed_risky_dependencies:
        lines.append("No medium, high, or critical dependencies found.")

    lines.extend(["", "Riskiest repositories:"])
    for index, repo in enumerate(report.riskiest_repositories[:5], 1):
        worst = ", ".join(dep.key.name for dep in repo.worst_dependencies[:3])
        if not worst:
            worst = _no_dependencies_reason(repo.coverage)
        lines.append(
            f"{index}. {repo.repo_full_name} · {repo.risk_points} risk points · "
            f"{repo.critical_risk_dependencies} critical, "
            f"{repo.high_risk_dependencies} high · worst: {worst}"
        )

    lines.extend(_unread_repository_lines(report))
    lines.extend(_partially_listed_repository_lines(report))

    if report.parse_failures:
        lines.extend(
            [
                "",
                f"Manifest parse failures: {len(report.parse_failures)} "
                "(included in JSON/HTML methodology notes)",
            ]
        )

    return "\n".join(lines)


def _no_dependencies_reason(coverage: RepositoryCoverage) -> str:
    """Say why a repository contributed no dependencies.

    "worst: none" was printed for a repository that declares nothing and for
    one the scan could not read a single manifest of. Those are opposite facts
    and they had the same four letters (#262).
    """
    reasons = {
        RepositoryCoverage.READ: "none",
        RepositoryCoverage.PARTIALLY_READ: "none read",
        RepositoryCoverage.PARTIALLY_LISTED: "none in the part we saw",
        RepositoryCoverage.UNREADABLE: "NOT READ",
        RepositoryCoverage.NO_MANIFESTS: "no manifests",
        RepositoryCoverage.DISCOVERY_FAILED: "NOT LISTED",
    }
    return reasons[coverage]


def _coverage_label(coverage: RepositoryCoverage) -> str:
    """Return the short human label for a repository's coverage state."""
    labels = {
        RepositoryCoverage.READ: "read",
        RepositoryCoverage.PARTIALLY_READ: "partly read",
        RepositoryCoverage.PARTIALLY_LISTED: "listed in part",
        RepositoryCoverage.UNREADABLE: "not read",
        RepositoryCoverage.NO_MANIFESTS: "no manifests",
        RepositoryCoverage.DISCOVERY_FAILED: "not listed",
    }
    return labels[coverage]


def _unread_repository_lines(report: OrgScanReport) -> List[str]:
    """Render the repositories the scan measured nothing in, with the next step.

    Named at the top level rather than folded into the methodology notes: an
    org scan is where nobody is watching any individual repository, so a repo
    missing from the numbers is a repo nobody notices is missing.

    Args:
        report: The completed org scan report.

    Returns:
        The summary lines, empty when every repository was read.
    """
    unread = [
        repo
        for repo in report.riskiest_repositories
        if repo.coverage
        in {RepositoryCoverage.UNREADABLE, RepositoryCoverage.DISCOVERY_FAILED}
    ]
    if not unread and not report.unreadable_manifests:
        return []

    lines = ["", f"Repositories with no measurement: {len(unread)}"]
    for repo in unread[:10]:
        if repo.coverage is RepositoryCoverage.DISCOVERY_FAILED:
            lines.append(f"- {repo.repo_full_name} · repository could not be listed")
        else:
            lines.append(
                f"- {repo.repo_full_name} · dependency manifests found, none readable"
            )
    if len(unread) > 10:
        lines.append(f"- ... and {len(unread) - 10} more")

    if report.unreadable_manifests:
        lines.append("")
        lines.append(
            "Recognized manifests this tool cannot read: "
            f"{len(report.unreadable_manifests)}"
        )
        for entry in report.unreadable_manifests[:5]:
            lines.append(f"- {entry.display_path} · {entry.guidance}")
        if len(report.unreadable_manifests) > 5:
            lines.append(f"- ... and {len(report.unreadable_manifests) - 5} more")
    return lines


def _partially_listed_repository_lines(report: OrgScanReport) -> List[str]:
    """Name the repositories whose manifest list is a prefix (#266).

    Its own block, not folded into "no measurement": these repositories were
    measured, and the fact worth stating is that nobody can say how completely.
    GitHub caps the recursive tree it will return, and the repositories most
    likely to hit that cap are the ones with the most dependencies.

    Args:
        report: The completed org scan report.

    Returns:
        The summary lines, empty when every tree listed in full.
    """
    partial = [
        repo
        for repo in report.riskiest_repositories
        if repo.coverage is RepositoryCoverage.PARTIALLY_LISTED
    ]
    if not partial:
        return []

    lines = ["", f"Repositories listed only in part: {len(partial)}"]
    for repo in partial[:10]:
        lines.append(
            f"- {repo.repo_full_name} · GitHub truncated the git tree, so "
            f"{repo.dependency_count} is a floor, not a total"
        )
    if len(partial) > 10:
        lines.append(f"- ... and {len(partial) - 10} more")
    return lines


def write_json_report(
    report: OrgScanReport, output_path: Path, *, legacy_schema: bool = False
) -> None:
    """Write the aggregate report model as JSON.

    Args:
        report: The org scan report.
        output_path: Where to write the document.
        legacy_schema: Route to the frozen schema-v1 writer instead of the
            unified v2 contract.
    """
    if legacy_schema:
        write_json_report_v1(report, output_path)
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report_to_dict(report), indent=2),
        encoding="utf-8",
    )


CSV_COLUMNS: Tuple[str, ...] = (
    "package",
    "ecosystem",
    "risk_level",
    "risk_score",
    "repos_exposed",
    "repos_scanned",
    "installed_version",
    "version_specs",
    "latest_version",
    "stars",
    "contributors",
    "last_updated",
    "license",
    "deprecated",
    "known_vulnerable",
    "remediation",
    "advisories_scored",
    "advisories_filtered",
    "signals",
    "repositories",
    "manifests",
    "source_repo",
    "deps_dev",
)


def write_csv_report(report: OrgScanReport, output_path: Path) -> None:
    """Write the dependency inventory as a flat CSV, one row per dependency.

    The CSV is the spreadsheet-friendly companion to the HTML report: every
    dependency becomes a row with its risk verdict, blast radius, real GitHub
    signals, advisory counts, and the same investigate-upstream links, so a
    triager can sort and filter in any spreadsheet or BI tool.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    repo_count = len(report.repositories_scanned)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        for dependency in report.inventory:
            writer.writerow(_dependency_to_csv_row(dependency, repo_count))


def _dependency_to_csv_row(
    dependency: AggregatedDependency, repo_count: int
) -> Dict[str, object]:
    """Flatten one dependency into a CSV row."""
    metadata = dependency.risk_score.dependency
    community = metadata.community_metrics
    metrics = metadata.security_metrics
    license_info = metadata.license_info
    return {
        "package": dependency.key.name,
        "ecosystem": dependency.key.ecosystem,
        "risk_level": dependency.risk_level.value,
        "risk_score": f"{dependency.risk_score.total_score:.3f}",
        "repos_exposed": dependency.blast_radius,
        "repos_scanned": repo_count,
        "installed_version": metadata.installed_version,
        "version_specs": _versions_display(dependency),
        "latest_version": metadata.latest_version or "",
        "stars": community.star_count if community is not None else "",
        "contributors": community.contributor_count if community is not None else "",
        "last_updated": (
            metadata.last_updated.date().isoformat() if metadata.last_updated else ""
        ),
        "license": license_info.license_id if license_info is not None else "",
        "deprecated": "yes" if metadata.is_deprecated else "no",
        "known_vulnerable": "yes" if dependency.is_known_vulnerable else "no",
        "remediation": _remediation_for(dependency).sentence(),
        "advisories_scored": (
            metrics.counted_vulnerability_count if metrics is not None else ""
        ),
        "advisories_filtered": (
            metrics.filtered_vulnerability_count if metrics is not None else ""
        ),
        "signals": _signal_phrases(dependency, separator="; "),
        "repositories": "; ".join(sorted(dependency.repositories)),
        "manifests": "; ".join(sorted(dependency.manifests)),
        "source_repo": metadata.repository_url or "",
        "deps_dev": _deps_dev_url(dependency.key.ecosystem, dependency.key.name) or "",
    }


def render_html_report(report: OrgScanReport) -> str:
    """Render a self-contained offline HTML report."""
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_html_title(report)}</title>",
            f"<style>{_css()}</style>",
            "</head>",
            "<body>",
            '<main class="wrap">',
            _header(report),
            _most_exposed_section(report),
            _riskiest_repos_section(report),
            _inventory_section(report),
            _methodology_footer(report),
            "</main>",
            "</body>",
            "</html>",
        ]
    )


def report_to_dict(report: OrgScanReport) -> Dict[str, object]:
    """Convert an org scan report into schema-v2 JSON-compatible data.

    Every dependency entry is ``contract.scored_dependency`` — the same shape
    ``analyze --output json`` emits — with the org-only concepts under
    ``extensions.org_scan``.

    Args:
        report: The org scan report.

    Returns:
        The v2 document body.
    """
    return {
        "schema_version": SCHEMA_VERSION,
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
        # Present on every scan, empty when everything recognized was read. A
        # key that only materializes when non-empty is one a consumer cannot
        # branch on, which is how the count reads the same either way (#262).
        "unreadable_manifests": [
            {
                "repo": entry.repo_full_name,
                "manifest_path": entry.path,
                "ecosystem": entry.ecosystem,
                "guidance": entry.guidance,
            }
            for entry in report.unreadable_manifests
        ],
        "unread_repository_count": _unread_repository_count(report),
        # Present on every scan, so a consumer can branch on "some repository's
        # dependency list is a prefix" without parsing warning prose (#266).
        "partially_listed_repository_count": _partially_listed_repository_count(report),
        "warnings": report.warnings,
    }


def _unread_repository_count(report: OrgScanReport) -> int:
    """Count repositories the scan produced no measurement for (#262).

    Counts repositories, not manifests: one repository with four unreadable
    manifests is one repository nobody measured, and a reader comparing this
    against ``repository_count`` needs the same unit on both sides.
    """
    return sum(
        1
        for repo in report.riskiest_repositories
        if repo.coverage
        in {RepositoryCoverage.UNREADABLE, RepositoryCoverage.DISCOVERY_FAILED}
    )


def _partially_listed_repository_count(report: OrgScanReport) -> int:
    """Count repositories whose git tree GitHub truncated (#266).

    Kept apart from ``_unread_repository_count``: these repositories produced a
    measurement, and the caveat is that it covers an unknown fraction of them.
    Folding the two together would report a repository that was read in part as
    one that was not read at all, which is the mirror of the defect #262 fixed.
    """
    return sum(
        1
        for repo in report.riskiest_repositories
        if repo.coverage is RepositoryCoverage.PARTIALLY_LISTED
    )


def _known_vulnerable_count(report: OrgScanReport) -> int:
    """Count unique dependencies whose installed version has scored advisories."""
    return sum(1 for dep in report.inventory if dep.is_known_vulnerable)


def _unscored_count(report: OrgScanReport) -> int:
    """Count unique dependencies the scan could not score (#133)."""
    return sum(1 for dep in report.inventory if dep.is_unscored)


def _header(report: OrgScanReport) -> str:
    """Render report header."""
    total_repos = len(report.repositories_scanned)
    return f"""
<header class="mast">
  <div>
    <p class="kicker">Dependency exposure · github {_account_kind(report)}</p>
    <h1><span class="at">@</span>{escape(report.org)}</h1>
    <p class="verdict">{_verdict_sentence(report)}</p>
  </div>
  <dl class="readout" aria-label="Scan totals">
    <div><dt>Repos</dt><dd class="num">{total_repos}</dd></div>
    <div><dt>Unique deps</dt><dd class="num">{report.unique_dependency_count}</dd></div>
    <div><dt>Known-vuln</dt><dd class="num vuln">
      {_known_vulnerable_count(report)}
    </dd></div>
    <div><dt>High-risk</dt><dd class="num hot">
      {report.high_risk_dependency_count}
    </dd></div>
    <div><dt>Unscored</dt><dd class="num unknown">
      {_unscored_count(report)}
    </dd></div>
    <div><dt>Unread repos</dt><dd class="num unknown">
      {_unread_repository_count(report)}
    </dd></div>
  </dl>
</header>
"""


def _html_title(report: OrgScanReport) -> str:
    """Return the HTML report title."""
    return f"Dependency Risk {_account_title(report)} Scan · {escape(report.org)}"


def _account_kind(report: OrgScanReport) -> str:
    """Return the short account source label used in the redesign."""
    if report.account_type == "user":
        return "user"
    return "org"


def _verdict_sentence(report: OrgScanReport) -> str:
    """Render the masthead plain-language verdict.

    Leads with both risk axes and the coverage caveat, in that order, so the
    reassuring number can never appear on its own (#133).
    """
    total_repos = len(report.repositories_scanned)
    high_risk_count = report.high_risk_dependency_count
    vulnerable_count = _known_vulnerable_count(report)
    exposed_repos = report.high_risk_exposed_repository_count
    vuln_label = _pluralize(vulnerable_count, "dependency")
    high_label = _pluralize(high_risk_count, "dependency")
    repo_label = _pluralize(exposed_repos, "repository")

    lead = (
        f"<b>{vulnerable_count} known-vulnerable</b> {vuln_label} and "
        f"<b>{high_risk_count} high-risk</b> {high_label}, out of "
        f"{report.unique_dependency_count} scanned across "
        f"{total_repos} {_pluralize(total_repos, 'repo')}; the high-risk ones "
        f"reach {exposed_repos} {repo_label}."
    )
    coverage = _coverage_caveat(report)

    if report.most_exposed_risky_dependencies:
        widest = report.most_exposed_risky_dependencies[0]
        reach = "every repo scanned"
        if widest.blast_radius != total_repos or total_repos == 0:
            reach = (
                f"{widest.blast_radius} of {total_repos} "
                f"{_pluralize(total_repos, 'repo')}"
            )
        signals = _signals_text(widest)
        tail = (
            f" The widest exposure is <code>{escape(widest.key.name)}</code> — "
            f"{signals} — reaching {escape(reach)}."
        )
    else:
        tail = (
            " No medium, high, critical, or unknown dependencies were found in "
            "the scanned manifests."
        )

    return f"{lead}{coverage}{tail}"


def _coverage_caveat(report: OrgScanReport) -> str:
    """Return the sentences that keep the counts from reading as totals.

    Two separate caveats, because they are two separate holes. An unscored
    dependency was found and could not be profiled; an unread repository never
    contributed a dependency to be counted in the first place, so it depresses
    the denominator as well as the numerator (#262).
    """
    sentences = []
    unscored = _unscored_count(report)
    if unscored:
        sentences.append(
            f" {unscored} of {report.unique_dependency_count} could not be scored, "
            "so the high-risk count is a floor, not a total."
        )
    unread = _unread_repository_count(report)
    if unread:
        total_repos = len(report.repositories_scanned)
        sentences.append(
            f" {unread} of {total_repos} {_pluralize(total_repos, 'repository')} "
            "produced no measurement at all — dependency manifests were found "
            "and not read, or the repository could not be listed — so those "
            "repositories are absent from every number above."
        )
    partial = _partially_listed_repository_count(report)
    if partial:
        total_repos = len(report.repositories_scanned)
        sentences.append(
            f" GitHub truncated the git tree for {partial} of {total_repos} "
            f"{_pluralize(total_repos, 'repository')}, so what was scanned "
            "there is a prefix of what is in them and their dependency counts "
            "are floors (#266)."
        )
    return "".join(sentences)


def _account_title(report: OrgScanReport) -> str:
    """Return title-case account source for report labels."""
    if report.account_type == "user":
        return "User"
    return "Org"


def _most_exposed_section(report: OrgScanReport) -> str:
    """Render the flagship dependency exposure table."""
    rows = [
        _exposure_row(dep, len(report.repositories_scanned))
        for dep in report.most_exposed_risky_dependencies
    ]
    body = "\n".join(rows) if rows else _empty_exposure()
    return f"""
<section id="most-exposed-risky-dependencies" class="section">
  <h2>Most exposed risky dependencies</h2>
  <p class="sub">
    Fix from the top. Bar length = share of repos exposed; color = severity.
  </p>
  <div class="exposure"
    aria-label="Dependencies ranked by risk and blast radius">
{body}
  </div>
</section>
"""


def _riskiest_repos_section(report: OrgScanReport) -> str:
    """Render repository risk ranking."""
    rows = "\n".join(
        _repository_row(repo) for repo in report.riskiest_repositories
    ) or _empty_row(4, "No repositories contained supported dependencies.")
    return f"""
<section id="riskiest-repositories" class="section">
  <h2>Riskiest repositories</h2>
  <p class="sub">
    Ranked by aggregate exposure. Bars show each repo's high-risk dependency load.
  </p>
  <div class="tbl-wrap">
    <table>
      <caption class="sr-only">
        Repositories ranked by aggregate dependency risk
      </caption>
      <thead>
        <tr>
          <th scope="col">Repository</th>
          <th scope="col">Risk load</th>
          <th scope="col">High-risk deps</th>
          <th scope="col">Worst deps</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
"""


def _inventory_section(report: OrgScanReport) -> str:
    """Render full dependency inventory."""
    rows = "\n".join(_inventory_row(dep) for dep in report.inventory) or _empty_row(
        5, "No dependencies found."
    )
    return f"""
<section id="full-dependency-inventory" class="section">
  <h2>Full inventory</h2>
  <p class="sub">
    Every unique dependency, ordered worst-first. To sort, filter, or pivot,
    open the CSV export alongside this report.
  </p>
  <div class="tbl-wrap">
    <table id="inventory-table">
      <caption class="sr-only">Inventory of every unique dependency</caption>
      <thead>
        <tr>
          <th scope="col">Dependency</th>
          <th scope="col">Eco</th>
          <th scope="col">Risk</th>
          <th scope="col">Repos</th>
          <th scope="col">Signals</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
"""


def _methodology_footer(report: OrgScanReport) -> str:
    """Render methodology and caveats."""
    failures = ""
    if report.parse_failures:
        failure_items = "\n".join(
            "<li>"
            f"{escape(failure.repo_full_name)}:{escape(failure.path)} — "
            f"{escape(failure.reason)}"
            "</li>"
            for failure in report.parse_failures[:10]
        )
        failures = (
            f"<p>{len(report.parse_failures)} manifests could not be parsed.</p>"
            f"<ul>{failure_items}</ul>"
        )
    unreadable = ""
    if report.unreadable_manifests:
        unreadable_items = "\n".join(
            "<li>"
            f"{escape(entry.display_path)} ({escape(entry.ecosystem)}) — "
            f"{escape(entry.guidance)}"
            "</li>"
            for entry in report.unreadable_manifests[:10]
        )
        unreadable = (
            f"<p>{len(report.unreadable_manifests)} recognized dependency "
            "manifests were not read, so the repositories holding them are "
            "under-counted above.</p>"
            f"<ul>{unreadable_items}</ul>"
        )
    warnings = ""
    if report.warnings:
        warning_items = "\n".join(
            f"<li>{escape(warning)}</li>" for warning in report.warnings[:10]
        )
        warnings = (
            f"<p>{len(report.warnings)} repositories could not be listed.</p>"
            f"<ul>{warning_items}</ul>"
        )
    return f"""
<footer class="foot">
  <p>
    <b>How to read this.</b> Risk levels are heuristic signals, not verdicts.
    <b>Unknown</b> stays unknown — a dependency we couldn't measure is shown as
    its own state, never rounded to low or high. Advisories that don't affect
    the installed version — along with informational, withdrawn, and
    low-confidence ones — are <b>filtered out of the score</b> (shown as
    "filtered"), so neither a patched-long-ago advisory nor a single noisy one
    can inflate a dependency's risk. Where an advisory carries no version range
    or the pin can't be parsed, it is counted and the reason recorded. Blast
    radius counts direct occurrences across scanned manifests.
  </p>
  <p>
    <b>Known-vulnerable</b> is a separate axis from the risk level. The risk
    level reflects maintenance and other leading indicators; the
    <span class="vuln-tag">known-vuln</span> tag flags that the installed
    version has scored advisories — a concrete, present exposure. A
    well-maintained dependency pinned to a vulnerable version can therefore be
    medium risk yet known-vulnerable; update the pin.
  </p>
  <p>
    <b>Coverage.</b> A repository shown with no dependencies is only good news
    when it is marked <i>read</i>. <i>not read</i> means dependency manifests
    were found and none of them could be parsed; <i>not listed</i> means the
    repository's file tree never came back. Both contribute nothing to every
    count on this page, which is why they are named rather than left as a zero.
  </p>
  {unreadable}
  {warnings}
  {failures}
</footer>
"""


def _exposure_row(dependency: AggregatedDependency, repo_count: int) -> str:
    """Render a dependency exposure row."""
    risk_class = _risk_class(dependency.risk_level)
    advisory = _advisory_line(dependency)
    signal_text = _signals_text(dependency)
    label = (
        f"{dependency.blast_radius} / {repo_count} repos exposed to "
        f"{dependency.key.name}"
    )
    return f"""
    <details class="exp-row drill" data-risk="{risk_rank(dependency.risk_level)}"
      data-search="{escape(_dependency_search_text(dependency))}">
      <summary class="exp-summary">
      <span class="exp-dep">{escape(dependency.key.name)}
        <span class="eco">· {escape(dependency.key.ecosystem)}</span>
      </span>
      <span>{_risk_badge(dependency.risk_level)}{_vuln_tag(dependency)}</span>
      <span class="exp-bar">
        <meter class="bar {risk_class}" min="0" max="{max(repo_count, 1)}"
          value="{dependency.blast_radius}" aria-label="{escape(label)}"></meter>
        <span class="bar-label">
          <b>{dependency.blast_radius}</b> / {repo_count} repos
        </span>
      </span>
      <span class="exp-signals">{signal_text}<span class="adv">{advisory}</span></span>
      </summary>
      {_dependency_panel(dependency)}
    </details>
""".rstrip()


def _vuln_tag(dependency: AggregatedDependency) -> str:
    """Return a 'known-vulnerable' chip for deps with scored advisories.

    This axis is orthogonal to the risk badge: it flags a concrete known
    exposure in the installed version, independent of the maintenance-driven
    risk level.
    """
    if not dependency.is_known_vulnerable:
        return ""
    return (
        '<span class="vuln-tag" '
        'title="Installed version has known advisories">known-vuln</span>'
    )


def _inventory_row(dependency: AggregatedDependency) -> str:
    """Render a full inventory table row."""
    key = dependency.key
    search_text = escape(_dependency_search_text(dependency))
    signals = _signals_text(dependency)
    return (
        f'<tr data-risk="{risk_rank(dependency.risk_level)}" '
        f'data-search="{search_text}">'
        f"{_linked_dependency_td(key.name, _display_label(key), key.ecosystem)}"
        f'{_td(key.ecosystem, key.ecosystem, "mono")}'
        f"{_risk_td(dependency.risk_level)}"
        f'{_td(str(dependency.blast_radius), str(dependency.blast_radius), "num")}'
        f'<td class="exp-signals" data-value="{escape(signals)}">'
        f"{_vuln_tag(dependency)}{signals}</td>"
        "</tr>"
    )


def _repository_row(repo: RepositoryRiskSummary) -> str:
    """Render a repository table row."""
    worst = escape(", ".join(dep.key.name for dep in repo.worst_dependencies[:3]))
    if not worst:
        worst = escape(_no_dependencies_reason(repo.coverage))
    if not repo.coverage.is_complete:
        worst = (
            f'{worst} <span class="badge unknown tiny">'
            f"{escape(_coverage_label(repo.coverage))}</span>"
        )
    if repo.unknown_risk_dependencies > 0:
        worst = (
            f'{worst} <span class="badge unknown tiny">'
            f"{repo.unknown_risk_dependencies} unknown</span>"
        )
    high_risk_count = repo.critical_risk_dependencies + repo.high_risk_dependencies
    return (
        "<tr>"
        f'{_td(repo.repo_full_name, repo.repo_full_name, "repo")}'
        f'{_td(str(repo.risk_points), str(repo.risk_points), "num")}'
        f'<td data-value="{high_risk_count}">'
        f'{_mini_bars(repo)} <span class="num">{high_risk_count}</span></td>'
        f'<td class="worst mono" data-value="{escape(worst)}">{worst}</td>'
        "</tr>"
    )


def _td(text: str, value: str, class_name: str = "") -> str:
    """Render a table cell with sort data."""
    class_attr = f' class="{class_name}"' if class_name else ""
    return f'<td{class_attr} data-value="{escape(value)}">{escape(text)}</td>'


def _linked_dependency_td(name: str, value: str, ecosystem: str) -> str:
    """Render a dependency table cell linked to deps.dev when possible."""
    url = _deps_dev_url(ecosystem, name)
    if url is None:
        body = escape(name)
    else:
        body = _external_link(url, name)
    return f'<td class="dep" data-value="{escape(value)}">{body}</td>'


def _risk_td(risk_level: RiskLevel) -> str:
    """Render a risk badge table cell."""
    return (
        f'<td data-value="{risk_rank(risk_level)}">' f"{_risk_badge(risk_level)}</td>"
    )


def _risk_badge(risk_level: RiskLevel) -> str:
    """Render a severity badge."""
    return (
        f'<span class="badge {_risk_class(risk_level)}">'
        f"{escape(_risk_label(risk_level))}</span>"
    )


def _risk_class(risk_level: RiskLevel) -> str:
    """Return the redesign CSS class for a risk level."""
    classes: Dict[RiskLevel, str] = {
        RiskLevel.CRITICAL: "crit",
        RiskLevel.HIGH: "high",
        RiskLevel.MEDIUM: "med",
        RiskLevel.LOW: "low",
        RiskLevel.UNKNOWN: "unknown",
    }
    return classes[risk_level]


def _risk_label(risk_level: RiskLevel) -> str:
    """Return the redesign display label for a risk level."""
    if risk_level == RiskLevel.CRITICAL:
        return "CRIT"
    if risk_level == RiskLevel.HIGH:
        return "HIGH"
    if risk_level == RiskLevel.MEDIUM:
        return "MEDIUM"
    if risk_level == RiskLevel.LOW:
        return "LOW"
    return "UNKNOWN"


def _mini_bars(repo: RepositoryRiskSummary) -> str:
    """Render compact high-risk dependency bars for a repository."""
    classes = ["crit"] * repo.critical_risk_dependencies
    classes.extend(["high"] * repo.high_risk_dependencies)
    bars = "".join(
        f'<span class="mini {class_name}"></span>' for class_name in classes[:5]
    )
    return f'<span class="mini-bars" aria-hidden="true">{bars}</span>'


def _empty_row(colspan: int, text: str) -> str:
    """Render an empty-state table row."""
    return f'<tr><td colspan="{colspan}" class="empty">{escape(text)}</td></tr>'


def _empty_exposure() -> str:
    """Render the exposure list empty state."""
    return '    <div class="exp-row empty">No risky dependencies found.</div>'


def _dependency_search_text(dependency: AggregatedDependency) -> str:
    """Return searchable text for an inventory row."""
    parts = [
        _display_label(dependency.key),
        _versions_display(dependency),
        " ".join(sorted(dependency.repositories)),
        _signal_phrases(dependency),
        dependency.advisory_summary,
        dependency.risk_level.value,
    ]
    return " ".join(parts).lower()


def _signals_text(dependency: AggregatedDependency) -> str:
    """Return escaped plain-language dependency signals.

    Args:
        dependency: The aggregated dependency.

    Returns:
        The escaped signal prose for an inventory row.
    """
    return escape(_signal_phrases(dependency))


#: How many risk factors a display cell shows before it stops being scannable.
_DISPLAYED_SIGNAL_LIMIT = 4


def _signal_phrases(dependency: AggregatedDependency, *, separator: str = " · ") -> str:
    """Render the dependency's leading risk factors as prose.

    This used to read ``AggregatedDependency.key_signals``, a third
    hand-maintained English-string generator over the same scores that
    ``risk_factors`` already describes — deleted in the schema-v2 work. The
    display now renders the scorer's own factors, so there is one generator and
    the HTML, the terminal summary and the CSV cannot drift from the JSON.

    Args:
        dependency: The aggregated dependency.
        separator: What to put between phrases.

    Returns:
        Up to :data:`_DISPLAYED_SIGNAL_LIMIT` factors, or a plain statement
        that nothing led.
    """
    factors = dependency.risk_score.factors[:_DISPLAYED_SIGNAL_LIMIT]
    if not factors:
        return "no leading risk signals"
    return separator.join(_sentence_case_lower(factor) for factor in factors)


def _display_label(key: DependencyKey) -> str:
    """Render an ecosystem-qualified dependency label for display.

    Formatting over fields the payload already carries, so it is a presentation
    concern and no longer a model property or a serialized field.

    Args:
        key: The dependency key.

    Returns:
        ``ecosystem:name@version``.
    """
    return f"{key.ecosystem}:{key.name}@{key.version}"


def _versions_display(dependency: AggregatedDependency) -> str:
    """Render every observed version spec as one compact display string.

    Args:
        dependency: The aggregated dependency.

    Returns:
        The specs, comma-joined in deterministic order.
    """
    return ", ".join(dependency.version_specs_list)


def _sentence_case_lower(text: str) -> str:
    """Normalize generated signal fragments for inline prose."""
    return text[:1].lower() + text[1:] if text else text


def _advisory_line(dependency: AggregatedDependency) -> str:
    """Return the redesign advisory sub-line."""
    if dependency.risk_level == RiskLevel.UNKNOWN:
        return "advisories: unknown"

    metrics = dependency.risk_score.dependency.security_metrics
    if metrics is None or metrics.vulnerability_count is None:
        return "advisories: unknown"

    counted = metrics.counted_vulnerability_count
    filtered = metrics.filtered_vulnerability_count
    if counted is None or filtered is None:
        if metrics.vulnerability_count == 0:
            counted = 0
            filtered = 0
        else:
            return escape(f"{metrics.vulnerability_count} found")

    return f"{counted} scored · {filtered} filtered"


def _dependency_panel(dependency: AggregatedDependency) -> str:
    """Render the expanded triage drill-down for one dependency."""
    return f"""
      <div class="triage-panel">
        {_triage_group("Why it's flagged", _why_flagged(dependency))}
        {_triage_group("Advisories", _advisories_panel(dependency))}
        {_triage_group("Where it's used", _usage_panel(dependency))}
        {_triage_group("Investigate upstream", _upstream_panel(dependency))}
        {_triage_group("Metadata", _metadata_panel(dependency))}
      </div>
""".rstrip()


def _triage_group(title: str, body: str) -> str:
    """Render one labeled drill-down group."""
    return f"""
        <section class="triage-group">
          <h3>{escape(title)}</h3>
          {body}
        </section>
""".rstrip()


def _why_flagged(dependency: AggregatedDependency) -> str:
    """Render measured and unknown risk reasons for a dependency."""
    lines = _why_lines(dependency)
    items = "".join(f"<li>{escape(line)}</li>" for line in lines)
    return f'<ul class="why-list">{items}</ul>'


def _why_lines(dependency: AggregatedDependency) -> List[str]:
    """Return plain-language reasons derived from scores and metadata."""
    score = dependency.risk_score
    metadata = score.dependency
    metrics = metadata.security_metrics
    lines: List[str] = []

    if _score_fired(score.maintainer_score) or (
        metadata.maintainer_count is not None and metadata.maintainer_count <= 1
    ):
        if metadata.maintainer_count is None:
            lines.append("Bus factor: maintainer count raised risk")
        else:
            maintainer_label = _pluralize(metadata.maintainer_count, "maintainer")
            lines.append(
                f"Bus factor: {metadata.maintainer_count} primary {maintainer_label}"
            )

    if _score_fired(score.staleness_score) or _score_fired(score.maintained_score, 0.5):
        if metadata.last_updated is None:
            lines.append("Maintenance: last update unknown; slowed cadence")
        else:
            lines.append(
                "Maintenance: last update "
                f"{metadata.last_updated.date().isoformat()}; slowed cadence"
            )

    if _score_fired(score.signed_commits_score):
        signed_releases = None
        if metrics is not None:
            signed_releases = metrics.has_signed_commits
        if signed_releases is not True:
            lines.append("Provenance: no signed releases")

    if _score_fired(score.security_policy_score):
        has_policy = None
        if metrics is not None:
            has_policy = metrics.has_security_policy
        if has_policy is not True:
            lines.append("Provenance: missing security policy")

    if _score_fired(score.dependency_update_score):
        lines.append("Provenance: missing dependency update automation")

    if _score_fired(score.branch_protection_score):
        lines.append("Provenance: missing branch protection")

    if _score_fired(score.health_indicators_score):
        missing_health = _missing_health_facts(metadata.has_tests, metadata.has_ci)
        if missing_health:
            lines.append(f"Provenance: {missing_health}")

    if _score_fired(score.version_score):
        lines.append(_version_drift_line(metadata))

    if _score_fired(score.license_score):
        lines.append(_license_risk_line(score))

    if metadata.is_deprecated or _score_fired(score.deprecation_score):
        lines.append("Deprecation: upstream marks this dependency as deprecated")

    if _score_fired(score.exploit_score):
        counted = _counted_advisory_count(metrics)
        advisory_label = _pluralize(counted, "advisory")
        lines.append(f"Advisories: {counted} scored {advisory_label}")

    if _score_fired(score.transitive_score):
        transitive_count = len(metadata.transitive_dependencies)
        dep_label = _pluralize(transitive_count, "transitive dependency")
        lines.append(f"Transitive risk: {transitive_count} {dep_label}")

    if _score_fired(score.community_score):
        lines.append(
            "Community health: package activity or support signals raised risk"
        )

    if score.unknown_signals:
        lines.append(f"couldn't measure: {', '.join(score.unknown_signals)}")
    if score.insufficient_data:
        lines.append("insufficient data for a confident risk level")

    if not lines:
        return ["No measured risk signals fired."]
    return lines


def _score_fired(score: Optional[float], threshold: float = 0.0) -> bool:
    """Return whether a component score raised risk."""
    return score is not None and score > threshold


def _missing_health_facts(has_tests: Optional[bool], has_ci: Optional[bool]) -> str:
    """Return a compact health indicator explanation."""
    if has_tests is False and has_ci is False:
        return "no CI/tests"
    if has_tests is False:
        return "no tests"
    if has_ci is False:
        return "no CI"
    return ""


def _version_drift_line(metadata: DependencyMetadata) -> str:
    """Return a version drift fact line."""
    installed = metadata.installed_version
    latest = metadata.latest_version
    if latest is None:
        return f"Version drift: installed {installed}; latest version unknown"

    # Calendar versions encode a date, not a compatibility promise, so their
    # drift is reported as elapsed time rather than major/minor distance (#126).
    if uses_calendar_versioning(installed, latest):
        installed_release, latest_release = release_timestamps(metadata)
        drift_days = calendar_drift_days(installed_release, latest_release)
        label = calendar_drift_label(drift_days)
        return f"Version drift: {installed} → {latest} ({label})"

    drift = _version_drift(installed, latest)
    if drift:
        return f"Version drift: {installed} → {latest} ({drift} behind)"
    return f"Version drift: {installed} → {latest} (behind latest)"


def _version_drift(installed: str, latest: str) -> str:
    """Return the major/minor version distance when parseable."""
    installed_version = _major_minor_version(installed)
    latest_version = _major_minor_version(latest)
    if installed_version is None or latest_version is None:
        return ""

    installed_major, installed_minor = installed_version
    latest_major, latest_minor = latest_version
    major_delta = latest_major - installed_major
    minor_delta = latest_minor - installed_minor
    parts: List[str] = []
    if major_delta > 0:
        parts.append(f"{major_delta} {_pluralize(major_delta, 'major')}")
    if major_delta == 0 and minor_delta > 0:
        parts.append(f"{minor_delta} {_pluralize(minor_delta, 'minor')}")
    return ", ".join(parts)


def _major_minor_version(version: str) -> Optional[Tuple[int, int]]:
    """Parse leading major/minor integers from a version string."""
    match = re.match(r"^\D*(\d+)(?:\.(\d+))?", version)
    if match is None:
        return None
    major = int(match.group(1))
    minor_text = match.group(2)
    minor = int(minor_text) if minor_text is not None else 0
    return major, minor


def _license_risk_line(score: DependencyRiskScore) -> str:
    """Return a license risk explanation."""
    license_info = score.dependency.license_info
    if license_info is None:
        return "License: missing or unknown license"
    if license_info.is_approved is False:
        return f"License: {license_info.license_id} is not approved"
    if license_info.license_id.lower() in {"", "unknown", "none"}:
        return "License: missing or unknown license"
    return (
        f"License: {license_info.license_id} flagged as {license_info.category.value}"
    )


def _advisories_panel(dependency: AggregatedDependency) -> str:
    """Render advisory drill-down with scored and filtered transparency."""
    metrics = dependency.risk_score.dependency.security_metrics
    if metrics is None or metrics.vulnerability_count is None:
        return '<p class="muted">Advisories could not be measured.</p>'
    if metrics.vulnerability_count == 0:
        return '<p class="muted">No advisories were reported.</p>'

    counted: List[Dict[str, object]] = []
    filtered: List[Dict[str, object]] = []
    for detail in metrics.vulnerability_details:
        if _is_counted_advisory(detail):
            counted.append(detail)
        elif _is_filtered_advisory(detail):
            filtered.append(detail)
        else:
            counted.append(detail)

    sections: List[str] = []
    sections.append(_advisory_list("Scored", counted, filtered=False))
    sections.append(_advisory_list("Filtered out", filtered, filtered=True))
    return "\n".join(sections)


def _is_counted_advisory(detail: Dict[str, object]) -> bool:
    """Return whether a vulnerability detail counted in the score."""
    counted = detail.get("counted_in_score")
    if isinstance(counted, bool):
        return counted
    return not _is_filtered_advisory(detail)


def _is_filtered_advisory(detail: Dict[str, object]) -> bool:
    """Return whether a vulnerability detail was filtered from the score."""
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


def _scored_fixed_versions(dependency: AggregatedDependency) -> List[str]:
    """Collect fixed versions from the advisories that counted toward the score.

    Order-preserving and de-duplicated, so an agent gets the fix targets in a
    stable order. Filtered/withdrawn advisories are excluded — only the
    advisories that actually drive ``known_vulnerable`` contribute.
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


def _remediation_for(dependency: AggregatedDependency) -> Remediation:
    """Classify what to do about one dependency, once, for every renderer.

    The JSON embeds :meth:`Remediation.to_dict` and the CSV prints
    :meth:`Remediation.sentence`, so both describe the same classification
    rather than two of them (#164 step 6). Until this existed the CSV ran a
    second precedence chain of its own, which — beyond drifting from the
    structured block — printed raw registry version strings that the structured
    path had already refused as unsafe to publish.
    """
    return remediation(
        dependency.risk_score.dependency,
        fix_versions=_scored_fixed_versions(dependency),
    )


def _advisory_list(
    label: str, advisories: List[Dict[str, object]], filtered: bool
) -> str:
    """Render a labeled advisory list."""
    if not advisories:
        return f'<p class="muted mono">{escape(label)}: none</p>'
    items = "".join(_advisory_item(detail, filtered) for detail in advisories)
    return (
        f'<div class="advisory-block"><p class="advisory-label mono">'
        f"{escape(label)}</p><ul>{items}</ul></div>"
    )


def _advisory_item(detail: Dict[str, object], filtered: bool) -> str:
    """Render one advisory item."""
    advisory_id = _detail_text(detail, "id") or "unknown advisory"
    severity = _detail_text(detail, "severity") or "UNKNOWN"
    advisory_url = _advisory_url(advisory_id)
    advisory_link = escape(advisory_id)
    if advisory_url is not None:
        advisory_link = _external_link(advisory_url, advisory_id)
    reason = ""
    if filtered:
        reason = (
            f' <span class="muted">excluded: {escape(_filter_reason(detail))}</span>'
        )
    return (
        "<li>"
        f'{advisory_link} <span class="sev mono">{escape(severity.upper())}</span>'
        f"{reason}</li>"
    )


def _detail_text(detail: Dict[str, object], key: str) -> str:
    """Return a string field from vulnerability details."""
    value = detail.get(key)
    if isinstance(value, str):
        return value
    return ""


def _advisory_url(advisory_id: str) -> Optional[str]:
    """Return the public advisory URL for an advisory ID."""
    if not advisory_id or advisory_id == "unknown advisory":
        return None
    encoded_id = quote(advisory_id, safe="")
    if advisory_id.upper().startswith("GHSA-"):
        return f"https://github.com/advisories/{encoded_id}"
    return f"https://osv.dev/vulnerability/{encoded_id}"


def _filter_reason(detail: Dict[str, object]) -> str:
    """Return a human-readable advisory filter reason."""
    reasons = _filter_reasons(detail)
    if reasons:
        return ", ".join(reasons)
    withdrawn = detail.get("withdrawn")
    if isinstance(withdrawn, bool) and withdrawn:
        return "withdrawn"
    severity = _detail_text(detail, "severity").upper()
    if severity in {"INFO", "INFORMATIONAL"}:
        return "informational"
    filtered = detail.get("filtered")
    if isinstance(filtered, bool) and filtered:
        return "low-confidence"
    return "not counted in score"


def _filter_reasons(detail: Dict[str, object]) -> List[str]:
    """Return normalized filter reasons from advisory details."""
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


def _usage_panel(dependency: AggregatedDependency) -> str:
    """Render repository and manifest occurrence links."""
    if not dependency.manifest_paths_by_repo:
        return '<p class="muted">No manifest locations were preserved.</p>'

    items: List[str] = []
    for repo_full_name in sorted(dependency.manifest_paths_by_repo):
        repo_ref = dependency.repo_refs.get(repo_full_name)
        repo_label = repo_full_name
        if repo_ref is not None:
            repo_link = _external_link(repo_ref.html_url, repo_ref.full_name)
        else:
            repo_link = escape(repo_label)
        manifest_items = "".join(
            _manifest_link_item(repo_ref, path)
            for path in sorted(dependency.manifest_paths_by_repo[repo_full_name])
        )
        items.append(f"<li>{repo_link}<ul>{manifest_items}</ul></li>")
    return f'<ul class="usage-list">{"".join(items)}</ul>'


def _manifest_link_item(repo_ref: Optional[RepositoryRef], path: str) -> str:
    """Render one manifest link if repository metadata is available."""
    if repo_ref is not None:
        blob_url = _repo_blob_url(repo_ref.html_url, repo_ref.default_branch, path)
        return f"<li>{_external_link(blob_url, path)}</li>"
    return f"<li>{escape(path)}</li>"


def _repo_blob_url(repo_html_url: str, default_branch: str, path: str) -> str:
    """Return a GitHub blob URL for a manifest path."""
    branch = quote(default_branch or "HEAD", safe="")
    encoded_path = quote(path, safe="/")
    return f"{repo_html_url.rstrip('/')}/blob/{branch}/{encoded_path}"


def _upstream_panel(dependency: AggregatedDependency) -> str:
    """Render investigation links for package and upstream repository."""
    metadata = dependency.risk_score.dependency
    links: List[Tuple[str, str]] = []
    deps_dev_url = _deps_dev_url(dependency.key.ecosystem, dependency.key.name)
    if deps_dev_url is not None:
        links.append(("deps.dev", deps_dev_url))
    registry_url = _registry_url(dependency.key.ecosystem, dependency.key.name)
    if registry_url is not None:
        links.append(("Registry", registry_url))
    source_url = _source_repo_url(metadata.repository_url)
    if source_url is not None:
        links.append(("Source repo", source_url))
        scorecard_uri = _github_scorecard_uri(source_url)
        if scorecard_uri is not None:
            scorecard_url = (
                "https://securityscorecards.dev/viewer/?uri="
                f"{quote(scorecard_uri, safe='')}"
            )
            links.append(("OpenSSF Scorecard", scorecard_url))

    if not links:
        return '<p class="muted">No upstream links available.</p>'

    items = "".join(f"<li>{_external_link(url, label)}</li>" for label, url in links)
    return f'<ul class="link-row">{items}</ul>'


def _metadata_panel(dependency: AggregatedDependency) -> str:
    """Render compact dependency metadata facts."""
    metadata = dependency.risk_score.dependency
    license_text = "unknown"
    if metadata.license_info is not None:
        license_text = metadata.license_info.license_id
    community = metadata.community_metrics
    star_count = community.star_count if community is not None else None
    contributor_count = community.contributor_count if community is not None else None
    facts = [
        (
            "installed → latest",
            f"{metadata.installed_version} → {_optional_text(metadata.latest_version)}",
        ),
        ("version specs", _versions_display(dependency)),
        ("last updated", _date_text(metadata.last_updated)),
    ]
    # Prefer the real GitHub signals (stars, contributor count) when the scan
    # enriched them; fall back to the maintainer count otherwise. Labelling the
    # contributor count as "maintainers" would misrepresent what it measures.
    if star_count is not None:
        facts.append(("stars", _optional_count(star_count)))
    if contributor_count is not None:
        facts.append(("contributors", _optional_count(contributor_count)))
    else:
        facts.append(("maintainers", _optional_int(metadata.maintainer_count)))
    facts += [
        ("license", license_text),
        ("tests", _boolean_mark(metadata.has_tests)),
        ("CI", _boolean_mark(metadata.has_ci)),
        ("docs", _boolean_mark(metadata.has_contribution_guidelines)),
    ]
    entries = "".join(
        "<div>" f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>" "</div>"
        for label, value in facts
    )
    return f'<dl class="fact-grid mono">{entries}</dl>'


def _deps_dev_url(ecosystem: str, name: str) -> Optional[str]:
    """Return a deps.dev package URL for supported ecosystems."""
    system = _deps_dev_system(ecosystem)
    if system is None:
        return None
    return f"https://deps.dev/{system}/{quote(name, safe='')}"


def _deps_dev_system(ecosystem: str) -> Optional[str]:
    """Map internal ecosystem names to deps.dev systems."""
    eco = ecosystems.lookup(ecosystem)
    return eco.deps_dev if eco is not None else None


def _registry_url(ecosystem: str, name: str) -> Optional[str]:
    """Return the ecosystem registry URL for a dependency."""
    system = _deps_dev_system(ecosystem)
    if system == "pypi":
        return f"https://pypi.org/project/{quote(name, safe='')}/"
    if system == "npm":
        return f"https://www.npmjs.com/package/{quote(name, safe='@/')}"
    if system == "cargo":
        return f"https://crates.io/crates/{quote(name, safe='')}"
    if system == "go":
        return f"https://pkg.go.dev/{quote(name, safe='/')}"
    return None


def _source_repo_url(repository_url: Optional[str]) -> Optional[str]:
    """Normalize a repository URL into an HTTP link when possible."""
    if repository_url is None:
        return None
    url = repository_url.removeprefix("git+")
    if url.startswith("git@github.com:"):
        repo_path = url.removeprefix("git@github.com:").removesuffix(".git")
        return f"https://github.com/{repo_path}"
    parsed = urlparse(url)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return url
    return None


def _github_scorecard_uri(repository_url: str) -> Optional[str]:
    """Return securityscorecards.dev URI input for GitHub repositories."""
    parsed = urlparse(repository_url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1].removesuffix(".git")
    return f"github.com/{owner}/{repo}"


def _external_link(url: str, label: str) -> str:
    """Render an escaped external link when the URL is HTTP(S)."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return escape(label)
    return (
        f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener">'
        f"{escape(label)}</a>"
    )


def _date_text(value: Optional[datetime]) -> str:
    """Return a compact date string for metadata facts."""
    if value is None:
        return "unknown"
    return value.date().isoformat()


def _optional_text(value: Optional[str]) -> str:
    """Return text for optional string metadata."""
    if value is None:
        return "unknown"
    return value


def _optional_int(value: Optional[int]) -> str:
    """Return text for optional integer metadata."""
    if value is None:
        return "unknown"
    return str(value)


def _optional_count(value: Optional[int]) -> str:
    """Return a thousands-separated count for optional integer metadata."""
    if value is None:
        return "unknown"
    return f"{value:,}"


def _boolean_mark(value: Optional[bool]) -> str:
    """Return compact yes/no/unknown metadata marker."""
    if value is True:
        return "✓"
    if value is False:
        return "—"
    return "unknown"


def _counted_advisory_count(metrics: Optional[SecurityMetrics]) -> int:
    """Return counted advisory count with a conservative fallback."""
    if metrics is None:
        return 0
    if metrics.counted_vulnerability_count is not None:
        return metrics.counted_vulnerability_count
    if metrics.vulnerability_count is not None:
        return metrics.vulnerability_count
    return 0


def _pluralize(count: int, singular: str) -> str:
    """Return a count-aware noun phrase without the count."""
    if count == 1:
        return singular
    if singular.endswith("y") and singular[-2:-1].lower() not in {
        "a",
        "e",
        "i",
        "o",
        "u",
    }:
        return f"{singular[:-1]}ies"
    return f"{singular}s"


def _dependency_to_dict(
    dependency: AggregatedDependency, repo_count: int
) -> Dict[str, object]:
    """Serialize one dependency in the shared contract, plus the org extension.

    The org scan adds four concepts ``analyze`` has no notion of: how many
    repositories a dependency reaches, where exactly it is declared, which raw
    version specifiers those manifests used, and what to do about it. They go
    under ``extensions.org_scan`` rather than at the top level, so a consumer
    written against the shared shape reads the same keys on both paths and can
    ignore the extension entirely.

    Args:
        dependency: The aggregated dependency.
        repo_count: How many repositories the scan covered.

    Returns:
        The ``ScoredDependency`` entry.
    """
    return scored_dependency(
        dependency.risk_score,
        ecosystem=dependency.key.ecosystem,
        extensions={
            "org_scan": {
                "blast_radius": {
                    "repository_count": dependency.blast_radius,
                    "total_repositories_scanned": repo_count,
                    "repositories": sorted(dependency.repositories),
                    "manifests": sorted(dependency.manifests),
                },
                "usage": _usage_to_dict(dependency),
                # Kept, unlike the deleted display strings: this is the set of
                # raw specifiers the manifests actually declared, and it cannot
                # be reconstructed from one resolved version.
                "version_specs": dependency.version_specs_list,
                "remediation": _remediation_for(dependency).to_dict(),
            }
        },
    )


def _usage_to_dict(dependency: AggregatedDependency) -> List[Dict[str, object]]:
    """Serialize dependency repository/manifest occurrences.

    Args:
        dependency: The aggregated dependency.

    Returns:
        One entry per repository, sorted.
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


def _repository_to_dict(repo: RepositoryRiskSummary) -> Dict[str, object]:
    """Serialize repository summary.

    Args:
        repo: The repository summary.

    Returns:
        The repository entry.
    """
    return {
        "repo": repo.repo_full_name,
        # Emitted next to the count so the count can never be read alone: zero
        # under "read" is a real zero, zero under "unreadable" is a gap (#262).
        "coverage": repo.coverage.value,
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
                "risk_level": dep.risk_level.value,
                "blast_radius": dep.blast_radius,
            }
            for dep in repo.worst_dependencies
        ],
    }


def _css() -> str:
    """Return inline CSS."""
    return """
/* Palette ported from the Remarque design system (williamzujkowski.io):
   warm-cream / ferric-ink light, phosphor-green dark, radar-green accent.
   Severity ramp derived in the same oklch space as Remarque's semantic
   error/warning/success tokens. */
:root{
  --paper:oklch(0.95 0.015 75); --surface:oklch(0.975 0.008 75);
  --raise:oklch(0.93 0.015 75);
  --ink:oklch(0.18 0.04 25); --muted:oklch(0.42 0.04 25);
  --faint:oklch(0.52 0.03 25); --hair:oklch(0.85 0.02 75);
  --crit:oklch(0.50 0.15 25); --high:oklch(0.55 0.13 52);
  --med:oklch(0.60 0.10 85); --low:oklch(0.50 0.13 145);
  --unknown:oklch(0.52 0.03 25);
  --crit-wash:oklch(0.50 0.15 25 / 0.12); --high-wash:oklch(0.55 0.13 52 / 0.12);
  --med-wash:oklch(0.60 0.10 85 / 0.14); --low-wash:oklch(0.50 0.13 145 / 0.12);
  --unk-wash:oklch(0.52 0.03 25 / 0.10);
  --accent:oklch(0.48 0.15 140); --focus:oklch(0.48 0.15 140);
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",sans-serif;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root{
  --paper:oklch(0.14 0.015 140); --surface:oklch(0.17 0.015 140);
  --raise:oklch(0.19 0.015 140);
  --ink:oklch(0.92 0.03 140); --muted:oklch(0.85 0.03 140);
  --faint:oklch(0.70 0.03 140); --hair:oklch(0.28 0.02 140);
  --crit:oklch(0.68 0.16 25); --high:oklch(0.74 0.14 55);
  --med:oklch(0.80 0.11 90); --low:oklch(0.78 0.16 145);
  --unknown:oklch(0.70 0.03 140);
  --crit-wash:oklch(0.68 0.16 25 / 0.18); --high-wash:oklch(0.74 0.14 55 / 0.18);
  --med-wash:oklch(0.80 0.11 90 / 0.16); --low-wash:oklch(0.78 0.16 145 / 0.16);
  --unk-wash:oklch(0.70 0.03 140 / 0.14);
  --accent:oklch(0.82 0.17 140); --focus:oklch(0.82 0.17 140); color-scheme:dark;
}}
:root[data-theme="dark"]{
  --paper:oklch(0.14 0.015 140); --surface:oklch(0.17 0.015 140);
  --raise:oklch(0.19 0.015 140);
  --ink:oklch(0.92 0.03 140); --muted:oklch(0.85 0.03 140);
  --faint:oklch(0.70 0.03 140); --hair:oklch(0.28 0.02 140);
  --crit:oklch(0.68 0.16 25); --high:oklch(0.74 0.14 55);
  --med:oklch(0.80 0.11 90); --low:oklch(0.78 0.16 145);
  --unknown:oklch(0.70 0.03 140);
  --crit-wash:oklch(0.68 0.16 25 / 0.18); --high-wash:oklch(0.74 0.14 55 / 0.18);
  --med-wash:oklch(0.80 0.11 90 / 0.16); --low-wash:oklch(0.78 0.16 145 / 0.16);
  --unk-wash:oklch(0.70 0.03 140 / 0.14);
  --accent:oklch(0.82 0.17 140); --focus:oklch(0.82 0.17 140); color-scheme:dark;
}
:root[data-theme="light"]{
  --paper:oklch(0.95 0.015 75); --surface:oklch(0.975 0.008 75);
  --raise:oklch(0.93 0.015 75);
  --ink:oklch(0.18 0.04 25); --muted:oklch(0.42 0.04 25);
  --faint:oklch(0.52 0.03 25); --hair:oklch(0.85 0.02 75);
  --crit:oklch(0.50 0.15 25); --high:oklch(0.55 0.13 52);
  --med:oklch(0.60 0.10 85); --low:oklch(0.50 0.13 145);
  --unknown:oklch(0.52 0.03 25);
  --crit-wash:oklch(0.50 0.15 25 / 0.12); --high-wash:oklch(0.55 0.13 52 / 0.12);
  --med-wash:oklch(0.60 0.10 85 / 0.14); --low-wash:oklch(0.50 0.13 145 / 0.12);
  --unk-wash:oklch(0.52 0.03 25 / 0.10);
  --accent:oklch(0.48 0.15 140); --focus:oklch(0.48 0.15 140); color-scheme:light;
}
*{box-sizing:border-box;}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;}
.wrap{width:min(1180px,calc(100% - 40px));margin:0 auto;
padding:34px 0 56px;}
code,.mono,.dep,.num,.risk,.bar-label,th{font-family:var(--mono);}
.num{font-variant-numeric:tabular-nums;}

/* ---- masthead ---- */
.mast{display:flex;justify-content:space-between;align-items:flex-start;gap:28px;
flex-wrap:wrap;padding-bottom:20px;border-bottom:1px solid var(--hair);}
.kicker{font-family:var(--mono);font-size:11px;letter-spacing:.14em;
text-transform:uppercase;color:var(--faint);margin:0 0 8px;}
.mast h1{font-family:var(--mono);font-size:30px;font-weight:600;
letter-spacing:-.01em;margin:0 0 6px;}
.mast h1 .at{color:var(--faint);font-weight:400;}
.verdict{margin:0;font-size:15px;color:var(--muted);max-width:52ch;}
.verdict b{color:var(--ink);font-weight:600;}
.readout{display:grid;grid-template-columns:repeat(4,auto);gap:0;
border:1px solid var(--hair);border-radius:10px;overflow:hidden;
background:var(--surface);}
.readout div{padding:11px 18px;border-right:1px solid var(--hair);}
.readout div:last-child{border-right:0;}
.readout dt{font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;
text-transform:uppercase;color:var(--faint);margin:0 0 3px;}
.readout dd{margin:0;font-family:var(--mono);font-size:24px;font-weight:600;
font-variant-numeric:tabular-nums;}
.readout dd.hot{color:var(--crit);}
.readout dd.vuln{color:var(--high);}
.readout dd.unknown{color:var(--unknown);}
/* known-vulnerable: an axis orthogonal to the risk badge, so a distinct
   underlined/dotted chip rather than a filled severity pill */
.vuln-tag{display:inline-flex;align-items:center;gap:5px;margin-left:7px;
font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.03em;
white-space:nowrap;text-transform:uppercase;color:var(--crit);padding:2px 7px;
border-radius:4px;border:1px dashed var(--crit);background:var(--crit-wash);
vertical-align:middle;}
.vuln-tag::before{content:"";width:6px;height:6px;border-radius:1px;
background:var(--crit);transform:rotate(45deg);}
td .vuln-tag{margin-left:0;margin-right:8px;}

/* ---- sections ---- */
.section{margin-top:38px;}
.section > h2{font-size:13px;font-family:var(--mono);letter-spacing:.06em;
text-transform:uppercase;color:var(--muted);margin:0 0 4px;font-weight:600;}
.section > .sub{margin:0 0 14px;color:var(--faint);font-size:13px;}

/* ---- exposure list (the signature) ---- */
.exposure{display:flex;flex-direction:column;gap:2px;}
.exp-row{border-radius:9px;}
.exp-row.empty{padding:12px 14px;}
.exp-row:hover,.exp-row[open]{background:var(--raise);}
.exp-summary{display:grid;grid-template-columns:minmax(150px,1.4fr) 78px
minmax(210px,2fr) minmax(120px,1fr);gap:18px;align-items:center;
padding:12px 14px;cursor:pointer;list-style:none;border-radius:9px;}
.exp-summary::-webkit-details-marker{display:none;}
.exp-row[open] .exp-summary{border-bottom:1px solid var(--hair);
border-radius:9px 9px 0 0;}
.exp-summary > span{min-width:0;}
.exp-dep{font-family:var(--mono);font-size:14px;font-weight:600;word-break:break-all;}
.exp-dep .eco{color:var(--faint);font-weight:400;font-size:12px;}
.badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);
font-size:11px;font-weight:700;letter-spacing:.04em;padding:3px 9px 3px 8px;
border-radius:999px;border:1px solid transparent;}
.badge::before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;}
.badge.crit{color:var(--crit);background:var(--crit-wash);border-color:var(--crit);}
.badge.high{color:var(--high);background:var(--high-wash);border-color:var(--high);}
.badge.med{color:var(--med);background:var(--med-wash);border-color:var(--med);}
.badge.low{color:var(--low);background:var(--low-wash);border-color:var(--low);}
.badge.unknown{color:var(--unknown);background:var(--unk-wash);
border-color:var(--unknown);border-style:dashed;}
/* the exposure bar — semantic <meter>, blast radius = value / repos scanned */
.exp-bar{display:flex;flex-direction:column;gap:4px;}
meter.bar{-webkit-appearance:none;appearance:none;width:100%;height:9px;
border:0;border-radius:5px;background:var(--hair);}
meter.bar::-webkit-meter-bar{background:var(--hair);border:0;border-radius:5px;}
meter.bar::-moz-meter-bar{border-radius:5px;}
meter.bar.crit::-webkit-meter-optimum-value{background:var(--crit);border-radius:5px;}
meter.bar.high::-webkit-meter-optimum-value{background:var(--high);border-radius:5px;}
meter.bar.med::-webkit-meter-optimum-value{background:var(--med);border-radius:5px;}
meter.bar.low::-webkit-meter-optimum-value{background:var(--low);border-radius:5px;}
meter.bar.unknown::-webkit-meter-optimum-value{background:repeating-linear-gradient(
90deg,var(--unknown),var(--unknown) 3px,transparent 3px,transparent 6px);}
meter.bar.crit::-moz-meter-bar{background:var(--crit);}
meter.bar.high::-moz-meter-bar{background:var(--high);}
meter.bar.med::-moz-meter-bar{background:var(--med);}
meter.bar.low::-moz-meter-bar{background:var(--low);}
meter.bar.unknown::-moz-meter-bar{background:repeating-linear-gradient(
90deg,var(--unknown),var(--unknown) 3px,transparent 3px,transparent 6px);}
.bar-label{font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums;}
.bar-label b{color:var(--ink);}
.exp-signals{font-size:12.5px;color:var(--muted);}
.exp-signals .adv{color:var(--faint);font-family:var(--mono);font-size:11px;
display:block;margin-top:2px;}
a{color:var(--accent);text-decoration:none;}
a:hover{text-decoration:underline;}
.triage-panel{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);
gap:18px 24px;padding:14px;border-top:0;}
.triage-group h3{font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;
text-transform:uppercase;color:var(--faint);font-weight:600;margin:0 0 7px;}
.triage-group p{margin:0;}
.why-list,.usage-list,.advisory-block ul,.link-row{margin:0;padding-left:17px;}
.why-list li,.usage-list li,.advisory-block li,.link-row li{margin:3px 0;}
.usage-list ul{margin:4px 0 8px;padding-left:16px;font-family:var(--mono);
font-size:12px;}
.link-row{display:flex;flex-wrap:wrap;gap:7px 14px;padding-left:0;list-style:none;}
.advisory-block{margin:0 0 8px;}
.advisory-label{margin:0 0 4px;color:var(--muted);font-size:11px;}
.sev{display:inline-block;color:var(--faint);font-size:10.5px;margin-left:5px;}
.muted{color:var(--faint);}
.fact-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px 16px;
margin:0;}
.fact-grid div{min-width:0;}
.fact-grid dt{color:var(--faint);font-size:10.5px;text-transform:uppercase;}
.fact-grid dd{margin:1px 0 0;color:var(--muted);word-break:break-word;}

/* ---- tables ---- */
.tbl-wrap{border:1px solid var(--hair);border-radius:10px;overflow-x:auto;
background:var(--surface);}
table{width:100%;border-collapse:collapse;min-width:640px;}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--hair);
vertical-align:middle;}
th{font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;
color:var(--faint);font-weight:600;background:var(--raise);}
th button{all:unset;cursor:pointer;font:inherit;color:inherit;}
th button::after{content:" ↕";opacity:.4;}
tr:last-child td{border-bottom:0;}
td.num,td .num{font-variant-numeric:tabular-nums;}
.repo{font-family:var(--mono);font-size:13px;}
.mini-bars{display:inline-flex;gap:2px;vertical-align:middle;}
.mini{width:9px;height:16px;border-radius:2px;background:var(--hair);}
.mini.crit{background:var(--crit);}
.mini.high{background:var(--high);}
.mini.unknown{background:var(--unknown);opacity:.5;}
.worst{color:var(--muted);font-size:12.5px;}
details.repos summary{cursor:pointer;color:var(--accent);
font-family:var(--mono);font-size:11px;list-style:none;}
details.repos summary::-webkit-details-marker{display:none;}
details.repos[open] summary{color:var(--muted);}
details.repos ul{margin:6px 0 0;padding-left:16px;color:var(--muted);
font-family:var(--mono);font-size:11.5px;}

.search{display:flex;gap:8px;align-items:center;margin:0 0 12px;}
.search input{flex:1;max-width:340px;padding:8px 11px;
border:1px solid var(--hair);border-radius:8px;background:var(--surface);
color:var(--ink);font:13px var(--mono);}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px;}

.foot{margin-top:44px;padding-top:18px;border-top:1px solid var(--hair);
color:var(--faint);font-size:12.5px;max-width:70ch;}
.foot b{color:var(--muted);}
.empty{color:var(--muted);}
.tiny{font-size:9px;padding:1px 6px;}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;
overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;}
@media (max-width:720px){
  .exp-summary{grid-template-columns:1fr auto;gap:8px 14px;}
  .exp-bar,.exp-signals{grid-column:1 / -1;}
  .triage-panel{grid-template-columns:1fr;}
  .fact-grid{grid-template-columns:1fr;}
  .readout{grid-template-columns:1fr 1fr;}
  .readout div:nth-child(2){border-right:0;}
}
"""
