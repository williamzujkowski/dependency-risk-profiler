# Forge coverage: what each host can and cannot answer

**Status:** Authoritative
**Source of truth:** `src/dependency_risk_profiler/forges/`
**Last verified against the code:** 2026-08-06

This page is checked against the code by `testing/unit/test_forge_contract.py`.
The two tables below are generated from the registered adapters; the test fails
on drift, which is the only reason a published coverage table is worth more than
a remembered one.

---

## Most signals do not need a forge at all

Eight of this tool's sixteen signals are repository-derived, and **seven of the
eight are read from a shallow `git clone`** — `pathlib` existence checks against
the path table in `forge_paths.py`, plus `git log` and `git tag` subprocesses.
None of them asks a forge API anything. That is why a package hosted on a forge
nobody wrote an adapter for is not a package this tool cannot score:

| | needs a forge API? |
|---|---|
| `health_indicators`, `security_policy`, `dependency_update`, `signed_commits`, `branch_protection`, `maintained` | no — clone worktree and git history |
| `community_activity` | no — clone git history, when the clone is not shallow |
| `community_popularity` | **yes** — a star count is a forge-native social metric with no representation in git |

The other eight signals are registry-derived and never touch a forge.

So the adapter layer exists for a short list of facts, and its job is not to
serve many forges. It is to make the difference between them **visible instead
of silent**: a signal missing because nothing serves the host reads differently
in the output from one the forge was asked for and did not supply.

## Why the list of adapters is short

Measured over 8,870 packages across eight ecosystems (#289), of the packages
that declare a forge at all:

| Forge | share |
|---|---|
| GitHub | 97.49% |
| GitLab.com | 0.73% |
| Gitee | 0.68% |
| self-hosted `git.*` / `gitea.*` / `code.*` | 0.45% |
| Bitbucket Cloud | 0.31% |
| self-hosted GitLab | 0.19% |
| Codeberg (Forgejo) | 0.12% |
| SourceHut | 0.04% |

Known-host routing covers 99.55% of them with no probing. Identifying a
self-hosted instance is not possible from its hostname — `git.autistici.org` is
GitLab and `git.9pm.me` is Forgejo, so a `git.` prefix discriminates nothing —
and probing means an outbound request to a host named by third-party registry
metadata. That is filed as #294 and defaults off.

---

## Capability coverage

Which forge can be asked for which fact a clone cannot supply. Generated from
each adapter's own `capabilities` set.

<!-- BEGIN GENERATED: capability coverage -->
| Capability | `github` |
| --- | --- |
| `star_count` | yes |
| `contributor_count` | yes |
| `commit_frequency` | yes |
<!-- END GENERATED: capability coverage -->

**Declaring a capability is not promising an answer.** The column says the
endpoint exists, not that a given call succeeds. Both of GitHub's REST-backed
capabilities need a token; without one the answer is `unmeasured` and the
capability is still declared. That split is deliberate — the declaration
describes the API surface, the answer describes the call.

## Host routing

Every host this tool will `git clone` from, and whether an adapter claims it.
Generated from `utils._CLONEABLE_HOSTS` and the registered host matchers.

<!-- BEGIN GENERATED: host routing -->
| Host | Adapter | Forge-only facts |
| --- | --- | --- |
| `github.com` | `github` | measured |
| `gitlab.com` | none | unmeasured |
| `bitbucket.org` | none | unmeasured |
| `codeberg.org` | none | unmeasured |
| `gitea.com` | none | unmeasured |
| `git.sr.ht` | none | unmeasured |
| `gitee.com` | none | unmeasured |
<!-- END GENERATED: host routing -->

A host with no adapter is **still cloned and still scored**. It loses
`community_popularity` outright, because a star count exists nowhere but the
forge, and it falls back to the clone for everything else. It does not lose the
seven clone-derived signals, and it is not reported as a package with no source
repository.

## Reading this from the output

Schema v2 carries a `forge` block on every scored dependency:

```json
"forge": {
  "software": null,
  "capabilities": {
    "contributor_count": {"state": "unmeasured", "reason": "lookup_not_attempted"},
    "commit_frequency":  {"state": "unmeasured", "reason": "lookup_not_attempted"},
    "star_count":        {"state": "unmeasured", "reason": "lookup_not_attempted"}
  }
}
```

`software: null` means no registered adapter claims the host. Paired with
`lookup_not_attempted`, that says the fact was never asked for, as distinct from
`no_data_from_source` — which is what a forge that *was* asked and had nothing to
say produces. A GitHub-hosted package with no token available reports the second
for its two REST-backed facts, and `github` as its software.

That distinction is the point of the whole layer. Without it, a Codeberg-hosted
package and a GitHub-hosted package whose API call failed produce the same
silence.

## What is deliberately not built

Recorded as decisions rather than oversights, each with the number that argues
it:

- **SourceHut (0.04%)** — no anonymous API exists at any price; both the REST
  shim and the GraphQL endpoint require a personal OAuth2 token. An adapter
  would be a class whose every method returns unmeasured. The clone gives it
  seven of eight signals already.
- **Bitbucket Cloud (0.31%)** — its API has no star metric at all. `watchers`
  is a different thing and must not be written into a star count. Every cell it
  could fill is a hole, so the holes are published here instead.
- **Gitee (0.68%)** — the API is GitHub-v5-shaped and would be cheap, but 60
  requests/hour anonymously and a near-entirely China-domestic package
  population make it a poor next adapter. Deferred, not refused.
- **GitLab and Forgejo/Gitea** — the two worth building, in that order, and
  they are #293.
