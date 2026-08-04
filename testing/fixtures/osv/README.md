# Captured OSV advisory responses

Live `POST https://api.osv.dev/v1/query` bodies, recorded so the advisory
pipeline can be replayed offline. Each file is
`{"provenance": {...}, "payload": <the response body>}` and the provenance
block carries the exact command that fetched it and the date it was taken.

**Do not hand-edit these files.** A hand-written advisory encodes the same
assumption the normalizer makes — the key the parser looks for is present in
the fixture and absent from OSV — which is how a whole class of dead reads
survived (#145). If a fixture is wrong, re-capture it with the command in its
own provenance block.

## What is queried

The queries here are **package-level** (`{"package": {...}}`, no `version`),
because that is exactly what `OSVSource.lookup` sends: the tool asks OSV for
everything it holds on a package and decides applicability itself against the
installed version. Capturing the versioned query instead would record a body
the production path never receives, and would move OSV's range matching inside
the fixture where the tool's own matcher is the thing under test.

## The trimming rule

Reducers may remove **volume**. They may never remove **key diversity** — the
keys the normalizer does *not* read are precisely the ones that reveal the next
dead read. Two reductions are applied, both recorded per-file in `trimming`:

| Reduction | Why it is volume |
|---|---|
| `details` truncated to 400 characters | Prose. No adapter reads it; the key stays, with a string value. |
| `references` cut to the first 3 entries | A list of identically-shaped `{type, url}` links. The key and the entry shape survive. |

Nothing else is touched. No advisory is dropped from `vulns`, because the
counts these fixtures pin (51 found, 50 filtered, 1 counted for
`golang.org/x/net`) are the whole point of them.

## Re-capturing

Run the command in the file's own `provenance.captured_by`, then re-wrap it
with a provenance block. Review the diff: **a changed key shape in that diff is
the finding, not the noise.** Advisory databases add severities and re-scope
records, and either can silently change what the tool counts.
