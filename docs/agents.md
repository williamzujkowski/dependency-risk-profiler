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

## The fields to read (org/user scan JSON)

Each entry under `inventory` and `most_exposed_risky_dependencies` carries what
you need to act, no reconstruction required:

| Field | Use it to |
|-------|-----------|
| `name`, `ecosystem`, `version` | Identify the package. |
| `risk_level` | Prioritize (critical/high/medium/low/unknown). |
| `known_vulnerable` | A separate axis: the installed version has scored advisories. Fix these regardless of risk level. |
| `remediation` | A one-line, ready-to-use action string when one applies (upgrade past the fix versions, upgrade to latest, or replace a deprecated package), else `null`. Put it straight in the issue/PR body. It names fix versions but does **not** resolve the exact target across version ranges — you still pick the precise pin. |
| `metadata.latest_version` | The upgrade target for drift — but may be `null` when the registry lookup didn't resolve; treat `null` as unknown and fall back to `deps_dev` / `repository_url`. |
| `advisories.details[].fixed_versions` | The version(s) that close each advisory — the reliable target for a known-vulnerable dep. |
| `key_signals` / `risk_factors` | The "why", for the issue body. |
| `usage[]` → `repo`, `html_url`, `manifests[]` | **Which repo and which manifest file to edit.** Each manifest links to the exact file. |
| `blast_radius.repository_count` | How many repos this reaches — fix the widest first. |
| `metadata.repository_url`, `deps_dev` (CSV) | Where to investigate a replacement. |

The headline (`headline`, and the lead line of the terminal and HTML reports)
carries both risk axes plus the coverage caveat, in the order they demand
action: `198 known-vulnerable · 2 high-risk · 812 could not be scored · 1135
dependencies across 25 repos`. Read all of it. `high_risk_dependency_count` is
depressed whenever coverage is poor — a dependency that could not be scored
cannot score high — so `unscored_dependency_count` is what tells you whether a
low high-risk count means "clean" or "we measured almost nothing".

For a single-project `analyze --output json`, the shape is flatter: a top-level
`dependencies` array with `name`, `installed_version`, `latest_version`,
`risk_level`, `vulnerabilities` (each with `fixed_versions`), `risk_factors`,
and `repository_url`.

### The `analyze --output json` contract

**If the process exits 0 in JSON mode, stdout is parseable JSON.** There is no
case — no manifests found, unsupported file, parse failure, nothing declared —
where a successful run writes nothing, so `json.load(stdout)` never needs a
guard. Every run emits exactly one document with the same top-level keys:

| Field | Always present |
|-------|----------------|
| `dependency_count`, `dependencies` | Yes; `0` and `[]` when there was nothing to report. |
| `overall_risk_score` | Yes, but `null` when nothing was measured — never `0.0`, which would read as "safe". |
| `manifests[]` | Every manifest that was successfully analyzed, with its own path, ecosystem, and count. Empty when none were. |
| `warnings[]` | Why anything was skipped or refused, in plain language. Empty on a clean run. |
| `ecosystem` | `null` for a mixed-ecosystem directory scan or an empty run. |

A directory containing several manifests emits one merged document, not one per
manifest.

`analyze` exit codes: `0` = the run completed, including "nothing to do";
`1` = the run failed, or every manifest you named was refused and nothing was
scored. A refused manifest also explains itself — pointing `analyze` at
`package.json` names `package-lock.json` and says whether it is there.

## A worked loop

1. `scan-org <org> --output-json org.json --fail-on high`. If exit code is `0`,
   there's nothing above the bar — stop.
2. Parse `org.json`. For each dependency where `known_vulnerable` is true or
   `risk_level` is `high`/`critical`:
   - **Open an issue** summarizing `name`, `risk_level`, `key_signals`, the
     advisories, and every repo/manifest from `usage[]`.
   - **Determine the fix:** start from `remediation` — it states the action
     directly. When you need to pick the exact pin, use the smallest version
     that is `>=` every relevant `fixed_versions` entry; otherwise
     `latest_version`. If `remediation` says to replace (deprecated /
     unmaintained, no published fix), investigate a replacement via
     `repository_url` / deps.dev instead of a version bump.
   - **Open a PR** that edits each manifest in `usage[]` to the fix version.
3. Leave the merge decision to a human. The tool identifies and the agent
   prepares; a person keeps the judgment call.

## Guarantees an agent can rely on

- **stdout is machine-clean.** In `--output json` mode, diagnostics go to
  stderr; stdout is JSON only.
- **Non-interactive.** No prompts, ever.
- **Unknown stays unknown.** A signal the tool couldn't measure is reported as
  unknown, not guessed — don't treat `unknown` as safe.
- **Advisory noise is filtered.** `advisories.filtered` are counted but excluded
  from the score and from `known_vulnerable`; act on the scored ones.
