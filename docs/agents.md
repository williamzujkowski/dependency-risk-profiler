# Using Dependency Risk Profiler from an AI agent

This tool is designed to be driven by an autonomous agent (or a CI job), not
just a human at a terminal. Its whole output is structured, it never prompts
interactively, and it exposes an exit-code gate. The intended loop is:

**identify risk → open issues → find the fix → open the upgrade PR → a human reviews and merges.**

## The commands an agent uses

```bash
# One project — emit JSON to stdout (nothing else goes to stdout in this mode).
dependency-risk-profiler analyze <manifest-or-dir> --output json

# A whole GitHub org or user — write structured reports, and (optionally) gate.
dependency-risk-profiler scan-org  <org>  --github-token "$TOKEN" \
  --output-json org.json --output-csv org.csv --fail-on high
dependency-risk-profiler scan-user <user> --github-token "$TOKEN" \
  --output-json user.json
```

`--fail-on <critical|high|medium|low|known-vulnerable>` makes the scan exit
**code 2** when any dependency meets the threshold, so an agent or CI step can
branch on the exit code instead of parsing first. Exit `0` = under threshold,
`1` = the scan itself failed (bad token, network), `2` = the gate tripped.

## The schema

Every JSON document carries `schema_version` on the envelope. **Schema 2 is the
current contract and the default.**

Before schema 2 there were two contracts. `analyze --output json` and
`scan-org` described the same concept — a dependency somebody scored — and
agreed on five keys out of about twenty-one; the rest were silent renames
(`installed_version` / `version`, `scores` / `component_scores`,
`has_known_exploits` / `known_vulnerable`, `vulnerabilities` / `advisories`).
A consumer had to write two parsers for one concept.

Schema 2 makes both paths emit the **same `ScoredDependency` shape**, with
org-only concepts under a declared extension block.

`--schema v1` still selects the old pair of shapes, byte for byte, on
`analyze`, `scan-org` and `scan-user`. It is **deprecated and removed in
1.0.0**; the deprecation notice is written to stderr, so stdout stays
parseable. Migrate.

## `ScoredDependency` — the shape both paths emit

```jsonc
{
  "name": "jinja2",
  "ecosystem": "python",
  "installed_version": "3.1.2",     // the resolved version actually installed
  "latest_version": "3.1.6",        // null when the registry lookup didn't resolve
  "last_updated": "2024-03-01T12:00:00",
  "repository_url": "https://github.com/pallets/jinja",
  "is_deprecated": false,
  "known_vulnerable": true,         // scored advisories apply to installed_version
  "maintainer_count": 2,
  "risk_level": "MEDIUM",           // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
  "risk_score": 3.2,                // 0..5
  "risk_factors": ["Known security issues (1 counted, max severity HIGH)"],
  "insufficient_data": false,
  "license":   { "id": "BSD-3-Clause", "category": "PERMISSIVE",
                 "is_approved": true, "url": "…", "risk_level": "LOW" },
  "community": { "star_count": 10000, "contributor_count": 300,
                 "commit_frequency": 4.5,
                 "last_release_date": "…", "installed_release_date": "…" },
  "health":    { "has_tests": true, "has_ci": true,
                 "has_contribution_guidelines": null },
  "transitive_dependency_count": 0,
  "advisories": {
    "total_found": 3,
    "counted_in_score": 1,
    "filtered": 1,
    "filtered_reasons": { "withdrawn": 1 },
    "applicability_unknown": 1,               // #61: could not decide applicability
    "applicability_unknown_reasons": { "no_affected_ranges": 1 },
    "max_counted_cvss_score": 7.5,
    "max_counted_severity": "HIGH",
    "details": [ { "id": "GHSA-…", "counted_in_score": true,
                   "fixed_versions": ["3.1.4"] } ]
  },
  "signals": {
    "staleness":  { "state": "measured",   "value": 0.0,  "reason": null },
    "maintained": { "state": "unmeasured", "value": null,
                    "reason": "source_repository_unreadable" }
  },
  "field_sources": {                           // which path wrote each value
    "star_count": "github:api/repository",
    "maintainer_count": "registry:metadata",
    "last_updated": "registry:release"
  },
  "unknown_signals": ["maintained"],
  "measured_signal_count": 2,
  "total_signal_count": 3,
  "extensions": { }                            // see below
}
```

### `signals` — measured zero is not the same as unmeasured

This is the field to read before trusting anything else. Every signal is
reported as one of exactly two states:

| `state` | Means | Carries |
|---------|-------|---------|
| `measured` | Somebody looked and this is the answer. `value: 0.0` means **zero risk was measured**. | `value` |
| `unmeasured` | Nobody could look. It is not zero and not safe. | `reason` |

`reason` is one of `no_data_from_source` (the input this signal reads was
absent from whatever answered), `source_repository_unreadable` (the registry
answered and named no readable source repository, which silences every
repository-derived signal at once), `lookup_not_attempted` (the pipeline
step never ran for this manifest), or `source_lookup_failed` (it ran and the
source did not answer — an outage, an error status, an unreadable body).

The last one is the one to watch on `exploit`. `exploit: unmeasured` with
`source_lookup_failed` means the advisory databases could not be reached for
that package, so `known_vulnerable: false` is "we could not tell", not "we
checked". Nothing from such a run is cached, so a later scan re-asks rather
than replaying the gap (#219).

**Do not treat `unmeasured` as good news.** An unmeasured signal is excluded
from both the numerator and the denominator of `risk_score`, so a
sparsely-covered package gets a score computed over less evidence, not a lower
one. `insufficient_data: true` means the scan could not produce a confident
risk level at all, and `risk_level` is `UNKNOWN`.

The signal names are ours and they are stable. `docs/signals.md` publishes the
correspondence to OpenSSF Scorecard's checks, pinned to a Scorecard version,
with every approximate row marked approximate.

### `field_sources` — how much a value that *is* there is worth

`signals` says whether a value exists and why it does not. `field_sources`
answers the neighbouring question about the values that do: which acquisition
path produced them.

Seven fields have more than one. `star_count` is the sharp case: it is written
from a regex over unauthenticated github.com HTML *and* from `stargazers_count`
on the authenticated REST API, and in an org scan **both write it, in that
order**, into the same integer. Those are not the same number with different
latency — one is parsed out of markup that GitHub may restyle whenever it likes.

| Key | Also written by |
|---|---|
| `star_count` | github.com HTML, GitHub REST |
| `contributor_count` | GitHub REST, the registry's owner list |
| `maintainer_count` | the registry, a clone's `git shortlog`, GitHub REST |
| `commit_frequency` | a clone's `git rev-list`, GitHub REST |
| `has_tests`, `has_ci` | a clone's working tree, GitHub's tree API |
| `last_updated` | the registry's release table, repository activity |

Values are sanitized logical locators from a closed vocabulary: `registry:…`,
`clone:…`, `github:api/…`, `github:html`. They never carry a host, a URL, a
query string, a token or a filesystem path, and there is no code path by which
they could — both sides of the mapping are enums.

**A key is absent when nobody recorded a source**, which is not the same as a
source of "unknown". Same rule as the rest of this contract: nothing here
invents a fact.

Rough ordering of trust, for a consumer that wants one: `registry:*` and
`github:api/*` are asserted by a server; `clone:git-history` is
author-controlled and is worth much less from a shallow clone;
`github:html` is a regex over a web page.

### `extensions` — path-specific blocks

An extension may add keys. It never renames, shadows, or redefines a shared
field, so one parser reads both paths. `analyze` emits `"extensions": {}`.

`scan-org` and `scan-user` emit `extensions.org_scan`:

```jsonc
"extensions": {
  "org_scan": {
    "blast_radius": { "repository_count": 12, "total_repositories_scanned": 25,
                      "repositories": ["acme/api", …],
                      "manifests": ["acme/api:requirements.txt", …] },
    "usage": [ { "repo": "acme/api",
                 "html_url": "https://github.com/acme/api",
                 "default_branch": "main",
                 "manifests": ["requirements.txt"] } ],
    "version_specs": [">=3.1.2", "3.1.6"],   // the raw specifiers the manifests declared
    "remediation": { "action": "upgrade_to_fixed_version",
                     "fix_versions": ["3.1.4"],
                     "target_version": "3.1.4",
                     "detail": "Scored advisories apply to the installed version…" }
  }
}
```

### `remediation` — branch on the enum, not on prose

| `action` | What to do |
|----------|------------|
| `upgrade_to_fixed_version` | Scored advisories apply and at least one published fix version is known. `fix_versions` lists them. |
| `upgrade_to_latest` | Version drift, no advisory. `target_version` is the latest published version. |
| `replace` | Deprecated upstream, or vulnerable with no published fix. A different version will not help. |
| `no_action` | Nothing measured demands an action. |
| `unclassified` | Something demands an action and the data does not say which. **Read `detail` and decide yourself.** Never treated as one of the above. |

`target_version` is filled in only when exactly one candidate exists. Picking
among several fix versions needs cross-ecosystem range resolution this tool
does not claim to do, so it abstains rather than guessing; use the smallest
version that is `>=` every relevant `fix_versions` entry.

> **Security.** `fix_versions` and `target_version` originate in registry and
> advisory payloads. They are **untrusted input**. The tool refuses to publish
> a string that could not be a version (anything containing whitespace, shell
> metacharacters, quotes, or path separators is rejected, and the action
> becomes `unclassified`), but you must still pass them as **arguments**, never
> interpolate them into a shell string. Same for `name` and `installed_version`.

The `remediation` column in the CSV report is this same block rendered as one
sentence — `detail`, plus the target or the published fixes, and blank for
`no_action`. It is generated from the structure, not classified beside it, so
the CSV cannot describe a dependency differently from the JSON and cannot print
a version string the JSON refused. Branch on the JSON; read the CSV.

## The envelopes

### `analyze --output json`

**If the process exits 0 in JSON mode, stdout is parseable JSON.** There is no
case — no manifests found, unsupported file, parse failure, nothing declared —
where a successful run writes nothing, so `json.load(stdout)` never needs a
guard. Every run emits exactly one document with the same top-level keys:

| Field | Always present |
|-------|----------------|
| `schema_version` | Yes; `2`. |
| `dependency_count`, `dependencies` | Yes; `0` and `[]` when there was nothing to report. |
| `overall_risk_score` | Yes, but `null` when nothing was measured — never `0.0`, which would read as "safe". |
| `manifests[]` | Every manifest that was successfully analyzed, with its own path, ecosystem, and count. Empty when none were. |
| `warnings[]` | Why anything was skipped or refused, in plain language. Empty on a clean run. |
| `ecosystem` | `null` for a mixed-ecosystem directory scan or an empty run. Each dependency still carries its own `ecosystem`. |

A directory containing several manifests emits one merged document, not one per
manifest.

`analyze` exit codes: `0` = the run completed, including "nothing to do";
`1` = the run failed, or every manifest you named was refused and nothing was
scored. A refused manifest also explains itself — pointing `analyze` at
`package.json` names `package-lock.json` and says whether it is there.

### `scan-org` / `scan-user`

Top level: `schema_version`, `org`, `account_type`, `generated_at`,
`repositories_scanned` / `repository_count`, `manifests_scanned` /
`manifest_count`, `unique_dependency_count`, `known_vulnerable_dependency_count`,
`unscored_dependency_count`, `high_risk_dependency_count`,
`high_risk_exposed_repository_count`, `headline`, `riskiest_repositories`,
`parse_failures`, `warnings`, and two arrays of `ScoredDependency`:
`inventory` (everything) and `most_exposed_risky_dependencies` (the triage
list).

The headline carries both risk axes plus the coverage caveat, in the order they
demand action: `198 known-vulnerable · 2 high-risk · 812 could not be scored ·
1135 dependencies across 25 repos`. Read all of it. `high_risk_dependency_count`
is depressed whenever coverage is poor — a dependency that could not be scored
cannot score high — so `unscored_dependency_count` is what tells you whether a
low high-risk count means "clean" or "we measured almost nothing".

## A worked loop

1. `scan-org <org> --output-json org.json --fail-on high`. If exit code is `0`,
   there's nothing above the bar — stop.
2. Parse `org.json`. Check `schema_version == 2`. For each entry in `inventory`
   where `known_vulnerable` is true or `risk_level` is `high`/`critical`:
   - **Open an issue** summarizing `name`, `ecosystem`, `installed_version`,
     `risk_level`, `risk_factors`, the advisories, and every repo/manifest from
     `extensions.org_scan.usage[]`.
   - **Determine the fix:** branch on
     `extensions.org_scan.remediation.action`. On `upgrade_to_fixed_version`
     use `target_version` when present, else the smallest version `>=` every
     `fix_versions` entry. On `upgrade_to_latest` use `target_version`. On
     `replace`, investigate a replacement via `repository_url` / deps.dev
     instead of a version bump. On `unclassified`, read `detail` and escalate
     to a human rather than acting.
   - **Open a PR** that edits each manifest in `usage[]` to the fix version.
3. Leave the merge decision to a human. The tool identifies and the agent
   prepares; a person keeps the judgment call.

## Guarantees an agent can rely on

- **One shape, two commands.** A `ScoredDependency` from `analyze` and one from
  `scan-org` have the same keys with the same meanings.
- **stdout is machine-clean.** In `--output json` mode, diagnostics — including
  the `--schema v1` deprecation notice — go to stderr; stdout is JSON only.
- **Non-interactive.** No prompts, ever.
- **Unknown stays unknown.** A signal the tool couldn't measure is reported as
  `unmeasured` with a reason, never as a zero. Don't treat `unknown` as safe.
- **Advisory noise is filtered.** `advisories.filtered` are counted but excluded
  from the score and from `known_vulnerable`; act on the scored ones.
  `advisories.applicability_unknown` are advisories whose applicability to the
  installed version could not be decided — neither "applies" nor "doesn't".
- **Versioned.** Breaking changes bump `schema_version` and are announced with
  a removal version, not a vague "later".
