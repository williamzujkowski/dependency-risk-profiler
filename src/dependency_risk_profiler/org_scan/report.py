"""HTML, JSON, and terminal reporting for org-wide scans."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Dict

from ..models import DependencyRiskScore, RiskLevel, SecurityMetrics
from .models import (
    AggregatedDependency,
    OrgScanReport,
    RepositoryRiskSummary,
    risk_rank,
)


def render_terminal_summary(report: OrgScanReport) -> str:
    """Render the org scan terminal summary."""
    lines = [
        f"Dependency Risk Org Scan · {report.org}",
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
            f"{index}. {dependency.key.display_name} · "
            f"{dependency.risk_level.value} · "
            f"{dependency.blast_radius} / {len(report.repositories_scanned)} repos · "
            f"{', '.join(dependency.key_signals)} · "
            f"{dependency.advisory_summary}"
        )

    if not report.most_exposed_risky_dependencies:
        lines.append("No medium, high, or critical dependencies found.")

    lines.extend(["", "Riskiest repositories:"])
    for index, repo in enumerate(report.riskiest_repositories[:5], 1):
        worst = ", ".join(dep.key.name for dep in repo.worst_dependencies[:3])
        if not worst:
            worst = "none"
        lines.append(
            f"{index}. {repo.repo_full_name} · {repo.risk_points} risk points · "
            f"{repo.critical_risk_dependencies} critical, "
            f"{repo.high_risk_dependencies} high · worst: {worst}"
        )

    if report.parse_failures:
        lines.extend(
            [
                "",
                f"Manifest parse failures: {len(report.parse_failures)} "
                "(included in JSON/HTML methodology notes)",
            ]
        )

    return "\n".join(lines)


def write_json_report(report: OrgScanReport, output_path: Path) -> None:
    """Write the aggregate report model as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report_to_dict(report), indent=2),
        encoding="utf-8",
    )


def render_html_report(report: OrgScanReport) -> str:
    """Render a self-contained offline HTML report."""
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>Dependency Risk Org Scan · {escape(report.org)}</title>",
            f"<style>{_css()}</style>",
            "</head>",
            "<body>",
            '<main class="page">',
            _header(report),
            _most_exposed_section(report),
            _riskiest_repos_section(report),
            _inventory_section(report),
            _methodology_footer(report),
            "</main>",
            f"<script>{_javascript()}</script>",
            "</body>",
            "</html>",
        ]
    )


def report_to_dict(report: OrgScanReport) -> Dict[str, object]:
    """Convert an org scan report into JSON-compatible data."""
    return {
        "org": report.org,
        "generated_at": report.generated_at.isoformat(),
        "repositories_scanned": report.repositories_scanned,
        "repository_count": len(report.repositories_scanned),
        "manifests_scanned": report.manifests_scanned,
        "manifest_count": len(report.manifests_scanned),
        "unique_dependency_count": report.unique_dependency_count,
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


def _header(report: OrgScanReport) -> str:
    """Render report header."""
    return f"""
<header class="report-header">
  <div>
    <p class="eyebrow">GitHub organization dependency exposure</p>
    <h1>{escape(report.org)}</h1>
    <p class="headline">{escape(report.headline)}</p>
  </div>
  <dl class="metrics" aria-label="Scan totals">
    <div><dt>Repos scanned</dt><dd>{len(report.repositories_scanned)}</dd></div>
    <div><dt>Manifests</dt><dd>{len(report.manifests_scanned)}</dd></div>
    <div><dt>Unique deps</dt><dd>{report.unique_dependency_count}</dd></div>
  </dl>
</header>
"""


def _most_exposed_section(report: OrgScanReport) -> str:
    """Render the flagship dependency exposure table."""
    rows = [
        _dependency_row(dep, len(report.repositories_scanned), inventory=False)
        for dep in report.most_exposed_risky_dependencies
    ]
    body = "\n".join(rows) if rows else _empty_row(5, "No risky dependencies found.")
    return f"""
<section id="most-exposed-risky-dependencies" class="section">
  <div class="section-heading">
    <h2>Most exposed risky dependencies</h2>
  </div>
  <div class="table-wrap">
    <table data-sortable>
      <caption class="sr-only">Dependencies ranked by risk and blast radius</caption>
      <thead>
        <tr>
          <th><button type="button" data-sort="text">Dependency</button></th>
          <th><button type="button" data-sort="risk">Risk</button></th>
          <th><button type="button" data-sort="number">Blast radius</button></th>
          <th>Key signals</th>
          <th>Advisories</th>
        </tr>
      </thead>
      <tbody>{body}</tbody>
    </table>
  </div>
</section>
"""


def _riskiest_repos_section(report: OrgScanReport) -> str:
    """Render repository risk ranking."""
    rows = "\n".join(
        _repository_row(repo) for repo in report.riskiest_repositories
    ) or _empty_row(6, "No repositories contained supported dependencies.")
    return f"""
<section id="riskiest-repositories" class="section">
  <div class="section-heading">
    <h2>Riskiest repositories</h2>
  </div>
  <div class="table-wrap">
    <table data-sortable>
      <caption class="sr-only">
        Repositories ranked by aggregate dependency risk
      </caption>
      <thead>
        <tr>
          <th><button type="button" data-sort="text">Repository</button></th>
          <th><button type="button" data-sort="number">Risk points</button></th>
          <th><button type="button" data-sort="number">Critical</button></th>
          <th><button type="button" data-sort="number">High</button></th>
          <th><button type="button" data-sort="number">Unknown</button></th>
          <th>Worst deps</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
"""


def _inventory_section(report: OrgScanReport) -> str:
    """Render full dependency inventory."""
    rows = "\n".join(
        _dependency_row(dep, len(report.repositories_scanned), inventory=True)
        for dep in report.inventory
    ) or _empty_row(6, "No dependencies found.")
    return f"""
<section id="full-dependency-inventory" class="section">
  <div class="section-heading inventory-heading">
    <h2>Full dependency inventory</h2>
    <label class="search-label">
      <span>Search</span>
      <input id="inventory-search" type="search" autocomplete="off"
        placeholder="dependency, repo, signal" aria-controls="inventory-table">
    </label>
  </div>
  <div class="table-wrap">
    <table id="inventory-table" data-sortable data-filterable>
      <caption class="sr-only">Searchable inventory of every unique dependency</caption>
      <thead>
        <tr>
          <th><button type="button" data-sort="text">Dependency</button></th>
          <th><button type="button" data-sort="text">Ecosystem</button></th>
          <th><button type="button" data-sort="risk">Risk</button></th>
          <th><button type="button" data-sort="number">Repos</button></th>
          <th>Key signals</th>
          <th>Advisories</th>
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
    return f"""
<footer class="methodology">
  <h2>Methodology</h2>
  <p>
    Risk levels are heuristic signals, not certainty. Unknown and insufficient-data
    results are shown as their own state instead of being converted into fake low or
    high risk. Filtered advisories are excluded from scoring.
  </p>
  {failures}
</footer>
"""


def _dependency_row(
    dependency: AggregatedDependency, repo_count: int, inventory: bool
) -> str:
    """Render a dependency table row."""
    key = dependency.key
    repo_list = ", ".join(sorted(dependency.repositories))
    signals = ", ".join(dependency.key_signals)
    blast = f"{dependency.blast_radius} / {repo_count} repos"
    risk_sort = risk_rank(dependency.risk_level)
    if inventory:
        cells = [
            _td(key.name, key.display_name),
            _td(key.ecosystem, key.ecosystem),
            _risk_td(dependency.risk_level),
            _td(str(dependency.blast_radius), str(dependency.blast_radius)),
            _td(signals, signals),
            _td(dependency.advisory_summary, dependency.advisory_summary),
        ]
    else:
        cells = [
            _td(key.display_name, key.display_name),
            _risk_td(dependency.risk_level),
            (
                f'<td data-value="{dependency.blast_radius}" '
                f'data-text="{escape(repo_list)}">'
                f"<details><summary>{escape(blast)}</summary>"
                f"<p>{escape(repo_list)}</p></details></td>"
            ),
            _td(signals, signals),
            _td(dependency.advisory_summary, dependency.advisory_summary),
        ]

    search_text = escape(_dependency_search_text(dependency))
    return (
        f'<tr data-risk="{risk_sort}" data-search="{search_text}">'
        + "".join(cells)
        + "</tr>"
    )


def _repository_row(repo: RepositoryRiskSummary) -> str:
    """Render a repository table row."""
    worst = ", ".join(
        f"{dep.key.name} ({dep.risk_level.value})" for dep in repo.worst_dependencies
    )
    critical = str(repo.critical_risk_dependencies)
    high = str(repo.high_risk_dependencies)
    unknown = str(repo.unknown_risk_dependencies)
    return (
        "<tr>"
        f"{_td(repo.repo_full_name, repo.repo_full_name)}"
        f"{_td(str(repo.risk_points), str(repo.risk_points))}"
        f"{_td(critical, critical)}"
        f"{_td(high, high)}"
        f"{_td(unknown, unknown)}"
        f"{_td(worst, worst)}"
        "</tr>"
    )


def _td(text: str, value: str) -> str:
    """Render a table cell with sort data."""
    return f'<td data-value="{escape(value)}">{escape(text)}</td>'


def _risk_td(risk_level: RiskLevel) -> str:
    """Render a risk badge table cell."""
    return (
        f'<td data-value="{risk_rank(risk_level)}">'
        f'<span class="risk {escape(risk_level.value.lower())}">'
        f"{escape(risk_level.value)}</span></td>"
    )


def _empty_row(colspan: int, text: str) -> str:
    """Render an empty-state table row."""
    return f'<tr><td colspan="{colspan}" class="empty">{escape(text)}</td></tr>'


def _dependency_search_text(dependency: AggregatedDependency) -> str:
    """Return searchable text for an inventory row."""
    parts = [
        dependency.key.display_name,
        " ".join(sorted(dependency.repositories)),
        " ".join(dependency.key_signals),
        dependency.advisory_summary,
        dependency.risk_level.value,
    ]
    return " ".join(parts).lower()


def _dependency_to_dict(
    dependency: AggregatedDependency, repo_count: int
) -> Dict[str, object]:
    """Serialize dependency exposure."""
    score = dependency.risk_score
    return {
        "ecosystem": dependency.key.ecosystem,
        "name": dependency.key.name,
        "version": dependency.key.version,
        "display_name": dependency.key.display_name,
        "risk_level": dependency.risk_level.value,
        "risk_score": score.total_score,
        "insufficient_data": score.insufficient_data,
        "unknown_signals": score.unknown_signals,
        "key_signals": dependency.key_signals,
        "blast_radius": {
            "repository_count": dependency.blast_radius,
            "total_repositories_scanned": repo_count,
            "repositories": sorted(dependency.repositories),
            "manifests": sorted(dependency.manifests),
        },
        "advisories": _advisory_to_dict(score),
        "risk_factors": score.factors,
        "metadata": _metadata_to_dict(score),
    }


def _repository_to_dict(repo: RepositoryRiskSummary) -> Dict[str, object]:
    """Serialize repository summary."""
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
                "risk_level": dep.risk_level.value,
                "blast_radius": dep.blast_radius,
            }
            for dep in repo.worst_dependencies
        ],
    }


def _advisory_to_dict(score: DependencyRiskScore) -> Dict[str, object]:
    """Serialize vulnerability summary."""
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
    """Serialize security metrics vulnerability fields."""
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
    """Serialize dependency metadata relevant to the org report."""
    dependency = score.dependency
    return {
        "latest_version": dependency.latest_version,
        "last_updated": (
            dependency.last_updated.isoformat() if dependency.last_updated else None
        ),
        "maintainer_count": dependency.maintainer_count,
        "is_deprecated": dependency.is_deprecated,
        "repository_url": dependency.repository_url,
        "has_tests": dependency.has_tests,
        "has_ci": dependency.has_ci,
        "has_contribution_guidelines": dependency.has_contribution_guidelines,
        "transitive_dependency_count": len(dependency.transitive_dependencies),
    }


def _css() -> str:
    """Return inline CSS."""
    return """
:root {
  color-scheme: light;
  --bg: #f7f8fa;
  --panel: #ffffff;
  --text: #17202a;
  --muted: #5f6b7a;
  --line: #d9dee7;
  --low: #16784c;
  --medium: #936316;
  --high: #b42318;
  --critical: #7a271a;
  --unknown: #667085;
  --focus: #2563eb;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.page {
  width: min(1440px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 40px;
}
.report-header {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 24px;
  align-items: end;
  padding: 0 0 18px;
  border-bottom: 1px solid var(--line);
}
.eyebrow {
  margin: 0 0 4px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
}
h1, h2, p { margin-top: 0; }
h1 {
  margin-bottom: 6px;
  font-size: 32px;
  letter-spacing: 0;
}
h2 {
  margin-bottom: 0;
  font-size: 18px;
  letter-spacing: 0;
}
.headline {
  margin-bottom: 0;
  color: var(--muted);
  font-size: 16px;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(3, minmax(92px, 1fr));
  gap: 8px;
  margin: 0;
}
.metrics div {
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}
.metrics dt {
  color: var(--muted);
  font-size: 12px;
}
.metrics dd {
  margin: 0;
  font-size: 24px;
  font-variant-numeric: tabular-nums;
  font-weight: 700;
}
.section {
  margin-top: 28px;
}
.section-heading {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
  margin-bottom: 10px;
}
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}
table {
  width: 100%;
  border-collapse: collapse;
  min-width: 880px;
}
th, td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}
th {
  background: #eef2f6;
  color: #344054;
  font-size: 12px;
  text-transform: uppercase;
}
th button {
  border: 0;
  background: transparent;
  color: inherit;
  cursor: pointer;
  font: inherit;
  font-weight: 700;
  padding: 0;
}
th button:focus-visible,
input:focus-visible,
summary:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
td {
  font-variant-numeric: tabular-nums;
}
tr:last-child td {
  border-bottom: 0;
}
.risk {
  display: inline-block;
  min-width: 72px;
  padding: 2px 8px;
  border-radius: 999px;
  color: #ffffff;
  font-size: 12px;
  font-weight: 700;
  text-align: center;
}
.risk.low { background: var(--low); }
.risk.medium { background: var(--medium); }
.risk.high { background: var(--high); }
.risk.critical { background: var(--critical); }
.risk.unknown { background: var(--unknown); }
details summary {
  cursor: pointer;
  color: #1d4ed8;
}
details p {
  max-width: 720px;
  margin: 8px 0 0;
  color: var(--muted);
}
.search-label {
  display: flex;
  gap: 8px;
  align-items: center;
  color: var(--muted);
}
.search-label input {
  width: min(360px, 42vw);
  padding: 7px 10px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #fff;
  color: var(--text);
}
.methodology {
  margin-top: 28px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
  color: var(--muted);
}
.methodology h2 {
  color: var(--text);
}
.empty {
  color: var(--muted);
  text-align: center;
}
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
@media (max-width: 760px) {
  .page { width: min(100% - 20px, 1440px); padding-top: 18px; }
  .report-header { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: repeat(3, 1fr); }
  .metrics div { padding: 8px; }
  .metrics dd { font-size: 20px; }
  .inventory-heading { align-items: flex-start; flex-direction: column; }
  .search-label, .search-label input { width: 100%; }
}
"""


def _javascript() -> str:
    """Return inline vanilla JavaScript for sorting and filtering."""
    return """
function cellValue(row, index) {
  const cell = row.children[index];
  if (!cell) return "";
  return cell.getAttribute("data-value") || cell.textContent.trim();
}
document.querySelectorAll("table[data-sortable]").forEach((table) => {
  table.querySelectorAll("th button[data-sort]").forEach((button, index) => {
    button.setAttribute("aria-sort", "none");
    button.addEventListener("click", () => {
      const tbody = table.querySelector("tbody");
      const rows = Array.from(tbody.querySelectorAll("tr"));
      const type = button.getAttribute("data-sort");
      const current = button.getAttribute("aria-sort");
      const ascending = current !== "ascending";
      table.querySelectorAll("th button[data-sort]").forEach((other) => {
        other.setAttribute("aria-sort", "none");
      });
      button.setAttribute("aria-sort", ascending ? "ascending" : "descending");
      rows.sort((a, b) => {
        const av = cellValue(a, index);
        const bv = cellValue(b, index);
        let result = 0;
        if (type === "number" || type === "risk") {
          result = Number(av) - Number(bv);
        } else {
          result = av.localeCompare(bv, undefined, { sensitivity: "base" });
        }
        return ascending ? result : -result;
      });
      rows.forEach((row) => tbody.appendChild(row));
    });
  });
});
const search = document.getElementById("inventory-search");
const inventory = document.getElementById("inventory-table");
if (search && inventory) {
  search.addEventListener("input", () => {
    const term = search.value.trim().toLowerCase();
    inventory.querySelectorAll("tbody tr").forEach((row) => {
      const haystack = row.getAttribute("data-search") || row.textContent.toLowerCase();
      row.hidden = term.length > 0 && !haystack.includes(term);
    });
  });
}
"""
