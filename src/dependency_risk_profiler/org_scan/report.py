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
            f"<script>{_javascript()}</script>",
            "</body>",
            "</html>",
        ]
    )


def report_to_dict(report: OrgScanReport) -> Dict[str, object]:
    """Convert an org scan report into JSON-compatible data."""
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
    <div><dt>Manifests</dt><dd class="num">{len(report.manifests_scanned)}</dd></div>
    <div><dt>Unique deps</dt><dd class="num">{report.unique_dependency_count}</dd></div>
    <div><dt>High-risk</dt><dd class="num hot">
      {report.high_risk_dependency_count}
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
    """Render the masthead plain-language verdict."""
    total_repos = len(report.repositories_scanned)
    high_risk_count = report.high_risk_dependency_count
    exposed_repos = report.high_risk_exposed_repository_count
    count_label = _pluralize(high_risk_count, "high-risk dependency")
    repo_label = _pluralize(exposed_repos, "repository")
    verb = "is" if high_risk_count == 1 else "are"

    if report.most_exposed_risky_dependencies:
        widest = report.most_exposed_risky_dependencies[0]
        reach = "every repo scanned"
        if widest.blast_radius != total_repos or total_repos == 0:
            reach = (
                f"{widest.blast_radius} of {total_repos} "
                f"{_pluralize(total_repos, 'repo')}"
            )
        signals = _signals_text(widest)
        return (
            f"<b>{high_risk_count} {count_label}</b> {verb} in play across "
            f"{exposed_repos} {repo_label}. The widest exposure is "
            f"<code>{escape(widest.key.name)}</code> — {signals} — "
            f"reaching {escape(reach)}."
        )

    return (
        f"<b>{high_risk_count} {count_label}</b> {verb} in play across "
        f"{exposed_repos} {repo_label}. No medium, high, critical, or unknown "
        "dependencies were found in the scanned manifests."
    )


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
    <table data-sortable>
      <caption class="sr-only">
        Repositories ranked by aggregate dependency risk
      </caption>
      <thead>
        <tr>
          <th><button type="button" data-sort="text">Repository</button></th>
          <th><button type="button" data-sort="number">Risk load</button></th>
          <th>High-risk deps</th>
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
    rows = "\n".join(_inventory_row(dep) for dep in report.inventory) or _empty_row(
        5, "No dependencies found."
    )
    return f"""
<section id="full-dependency-inventory" class="section">
  <h2>Full inventory</h2>
  <div class="search">
    <input id="inventory-search" type="search" autocomplete="off"
      placeholder="filter · dependency, repo, signal"
      aria-label="Filter dependency inventory"
      aria-controls="inventory-table">
  </div>
  <div class="tbl-wrap">
    <table id="inventory-table" data-sortable data-filterable>
      <caption class="sr-only">Searchable inventory of every unique dependency</caption>
      <thead>
        <tr>
          <th><button type="button" data-sort="text">Dependency</button></th>
          <th><button type="button" data-sort="text">Eco</button></th>
          <th><button type="button" data-sort="risk">Risk</button></th>
          <th><button type="button" data-sort="number">Repos</button></th>
          <th>Signals</th>
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
<footer class="foot">
  <p>
    <b>How to read this.</b> Risk levels are heuristic signals, not verdicts.
    <b>Unknown</b> stays unknown — a dependency we couldn't measure is shown as
    its own state, never rounded to low or high. Informational, withdrawn, and
    low-confidence advisories are counted but <b>filtered out of the score</b>
    (shown as "filtered"), so a single noisy advisory can't inflate a
    dependency's risk. Blast radius counts direct occurrences across scanned
    manifests.
  </p>
  {failures}
</footer>
"""


def _exposure_row(dependency: AggregatedDependency, repo_count: int) -> str:
    """Render a dependency exposure row."""
    width = _exposure_width(dependency.blast_radius, repo_count)
    risk_class = _risk_class(dependency.risk_level)
    advisory = _advisory_line(dependency)
    signal_text = _signals_text(dependency)
    label = (
        f"{dependency.blast_radius} / {repo_count} repos exposed to "
        f"{dependency.key.name}"
    )
    return f"""
    <div class="exp-row" data-risk="{risk_rank(dependency.risk_level)}"
      data-search="{escape(_dependency_search_text(dependency))}">
      <div class="exp-dep">{escape(dependency.key.name)}
        <span class="eco">· {escape(dependency.key.ecosystem)}</span>
      </div>
      <div>{_risk_badge(dependency.risk_level)}</div>
      <div class="exp-bar" role="img" aria-label="{escape(label)}">
        <div class="bar-track">
          <div class="bar-fill {risk_class}" style="width:{width}%"></div>
        </div>
        <div class="bar-label">
          <b>{dependency.blast_radius}</b> / {repo_count} repos
        </div>
      </div>
      <div class="exp-signals">{signal_text}<span class="adv">{advisory}</span></div>
    </div>
""".rstrip()


def _inventory_row(dependency: AggregatedDependency) -> str:
    """Render a full inventory table row."""
    key = dependency.key
    search_text = escape(_dependency_search_text(dependency))
    signals = _signals_text(dependency)
    return (
        f'<tr data-risk="{risk_rank(dependency.risk_level)}" '
        f'data-search="{search_text}">'
        f'{_td(key.name, key.display_name, "dep")}'
        f'{_td(key.ecosystem, key.ecosystem, "mono")}'
        f"{_risk_td(dependency.risk_level)}"
        f'{_td(str(dependency.blast_radius), str(dependency.blast_radius), "num")}'
        f'<td class="exp-signals" data-value="{escape(signals)}">{signals}</td>'
        "</tr>"
    )


def _repository_row(repo: RepositoryRiskSummary) -> str:
    """Render a repository table row."""
    worst = escape(", ".join(dep.key.name for dep in repo.worst_dependencies[:3]))
    if not worst:
        worst = "none"
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
        dependency.key.display_name,
        " ".join(sorted(dependency.repositories)),
        " ".join(dependency.key_signals),
        dependency.advisory_summary,
        dependency.risk_level.value,
    ]
    return " ".join(parts).lower()


def _signals_text(dependency: AggregatedDependency) -> str:
    """Return escaped plain-language dependency signals."""
    if not dependency.key_signals:
        return "no leading risk signals"
    return escape(
        " · ".join(_sentence_case_lower(signal) for signal in dependency.key_signals)
    )


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


def _exposure_width(blast_radius: int, repo_count: int) -> int:
    """Return the exposure bar width as an integer percentage."""
    if repo_count <= 0:
        return 0
    percent = int((blast_radius / repo_count) * 100)
    return min(100, max(0, percent))


def _pluralize(count: int, singular: str) -> str:
    """Return a count-aware noun phrase without the count."""
    if count == 1:
        return singular
    return f"{singular}s"


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
:root{
  --paper:#f4f6f1; --surface:#ffffff; --raise:#fbfcf9;
  --ink:#15201a; --muted:#5b6b61; --faint:#8a978d; --hair:#dbe2da;
  --crit:#9e1f12; --high:#b25415; --med:#8f6d12; --low:#2f7d52;
  --unknown:#6b7570;
  --crit-wash:#9e1f1216; --high-wash:#b2541516;
  --med-wash:#8f6d1216; --low-wash:#2f7d5216; --unk-wash:#6b757012;
  --accent:#1c7d51; --focus:#1c7d51;
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",sans-serif;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root{
  --paper:#0d1310; --surface:#121b16; --raise:#16211b;
  --ink:#e6ede8; --muted:#8ba295; --faint:#5f7268; --hair:#25332b;
  --crit:#ef6a55; --high:#e08a3c; --med:#d3b24e; --low:#57c98a;
  --unknown:#8ba295;
  --crit-wash:#ef6a5520; --high-wash:#e08a3c20;
  --med-wash:#d3b24e20; --low-wash:#57c98a20; --unk-wash:#8ba29518;
  --accent:#57c98a; --focus:#57c98a; color-scheme:dark;
}}
:root[data-theme="dark"]{
  --paper:#0d1310; --surface:#121b16; --raise:#16211b;
  --ink:#e6ede8; --muted:#8ba295; --faint:#5f7268; --hair:#25332b;
  --crit:#ef6a55; --high:#e08a3c; --med:#d3b24e; --low:#57c98a;
  --unknown:#8ba295;
  --crit-wash:#ef6a5520; --high-wash:#e08a3c20;
  --med-wash:#d3b24e20; --low-wash:#57c98a20; --unk-wash:#8ba29518;
  --accent:#57c98a; --focus:#57c98a; color-scheme:dark;
}
:root[data-theme="light"]{
  --paper:#f4f6f1; --surface:#ffffff; --raise:#fbfcf9;
  --ink:#15201a; --muted:#5b6b61; --faint:#8a978d; --hair:#dbe2da;
  --crit:#9e1f12; --high:#b25415; --med:#8f6d12; --low:#2f7d52;
  --unknown:#6b7570;
  --crit-wash:#9e1f1216; --high-wash:#b2541516;
  --med-wash:#8f6d1216; --low-wash:#2f7d5216; --unk-wash:#6b757012;
  --accent:#1c7d51; --focus:#1c7d51; color-scheme:light;
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

/* ---- sections ---- */
.section{margin-top:38px;}
.section > h2{font-size:13px;font-family:var(--mono);letter-spacing:.06em;
text-transform:uppercase;color:var(--muted);margin:0 0 4px;font-weight:600;}
.section > .sub{margin:0 0 14px;color:var(--faint);font-size:13px;}

/* ---- exposure list (the signature) ---- */
.exposure{display:flex;flex-direction:column;gap:2px;}
.exp-row{display:grid;grid-template-columns:minmax(150px,1.4fr) 78px
minmax(210px,2fr) minmax(120px,1fr);gap:18px;align-items:center;
padding:12px 14px;border-radius:9px;}
.exp-row:hover{background:var(--raise);}
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
/* the exposure bar */
.exp-bar{display:flex;flex-direction:column;gap:4px;}
.bar-track{position:relative;height:9px;border-radius:5px;background:var(--hair);
overflow:hidden;}
.bar-fill{position:absolute;inset:0 auto 0 0;border-radius:5px;}
.bar-fill.crit{background:var(--crit);}
.bar-fill.high{background:var(--high);}
.bar-fill.med{background:var(--med);}
.bar-fill.low{background:var(--low);}
.bar-fill.unknown{background:repeating-linear-gradient(90deg,var(--unknown),
var(--unknown) 3px,transparent 3px,transparent 6px);}
.bar-label{font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums;}
.bar-label b{color:var(--ink);}
.exp-signals{font-size:12.5px;color:var(--muted);}
.exp-signals .adv{color:var(--faint);font-family:var(--mono);font-size:11px;
display:block;margin-top:2px;}

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
  .exp-row{grid-template-columns:1fr auto;gap:8px 14px;}
  .exp-bar,.exp-signals{grid-column:1 / -1;}
  .readout{grid-template-columns:1fr 1fr;}
  .readout div:nth-child(2){border-right:0;}
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
