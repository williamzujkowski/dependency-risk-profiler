# Captured registry fixtures

Live registry payloads, recorded so the adapter-conformance harness can replay
them offline. Every file here was fetched by
`scripts/capture_registry_fixtures.py` and carries the URL it came from and the
date it was taken.

**Do not hand-edit these files.** A hand-written fixture encodes the same
assumption the parser makes — the key the adapter looks for is present in the
fixture and absent from the registry — and that is exactly how five dead reads
survived (#145). If a fixture is wrong, re-capture it.

## Layout

```
manifest.json                 what to capture, and the shared limits
<ecosystem>/<name>.json       {"provenance": {...}, "payload": <registry document>}
```

`manifest.json` is read by both the capture script and the test harness, so
what CI replays and what a refresh fetches cannot drift apart.

## Not everything is JSON

Half the ecosystems answer with something else, so a manifest entry may declare
`"format": "text"` and the body is recorded verbatim as a JSON string:

| Ecosystem | Documents |
|---|---|
| maven | `maven-metadata.xml`, the artifact `.pom` — XML |
| nuget | flat-container index and registration index (JSON) plus the `.nuspec` (XML) |
| golang | `@latest` (JSON) plus the module's `go.mod` (plain text) |

Two ecosystems also capture something no registry serves at all: a **project
file** out of somebody's repository, from `raw.githubusercontent.com`. Gradle
needs one because it has no registry of its own and the parse is the thing that
can break (#101); nuget needs one because a `.csproj` states neither its
versions nor its full dependency set, and the `Directory.Packages.props` and
`Directory.Build.props` above it are where the rest lives (#129, #151). The
drivers partition their fixtures on that host prefix and materialise each file
at the path its source URL describes, so the walk-up runs against the
repository's real layout rather than one a test author arranged.

Text payloads are never string-truncated and never reduced. Shortening a POM
changes how it *parses*, which is a key difference wearing a volume costume;
the capture script refuses the combination outright.

**Version-pinned URLs.** A POM lives at `.../<version>/<artifact>-<version>.pom`
and a `go.mod` at `.../@v/<version>.mod`, so the manifest pins the version that
was current at capture. When the artifact ships again, the adapter asks for a
URL no fixture records and the replay fetcher raises — loudly, by design.
Re-capturing those means editing the manifest URL first, which gets the same
review as any other refresh.

## Refreshing

```bash
python scripts/capture_registry_fixtures.py --check      # ages only, no network
python scripts/capture_registry_fixtures.py              # re-capture everything
python scripts/capture_registry_fixtures.py --ecosystem nodejs
```

Review the diff before committing. **A changed key shape in that diff is the
finding, not the noise** — it is the registry telling you an adapter's
assumption just expired.

Cadence: every release cycle, and always after an adapter changes what it
reads. Owner: whoever is on the adapter rotation for the release, the
repository maintainer by default. The suite warns past `warn_after_days` and
fails past `fail_after_days` (both in `manifest.json`), so the refresh has a
trigger rather than depending on memory.

## The trimming rule

Reducers may remove **volume**. They may never remove **key diversity**.

Six exist, one per document shape: `none`, `npm-packument`, `pypi-project`
(samples the `releases` map), `crates-io` (samples the `versions` list),
`packagist-p2` (samples each package's release list) and `nuget-registration`
(keeps the newest registration page and samples its leaves). Each keeps the
entries the adapter resolves against plus the oldest and newest, in their
original order, with every key intact.

- Dropping 285 of express's 288 release manifests is volume.
- Dropping 314 of serde's 316 release entries is volume.
- Dropping 763 of symfony/console's 766 p2 entries is volume; the head is kept,
  because Packagist's minified format means only the head is complete.
- Capping a 40 KB `readme` string at 2000 characters is volume; the key stays.
- Dropping a key the adapter does not parse yet is **not allowed**. Those are
  precisely the keys that reveal the next dead read — `versions[<latest>]
  .deprecated` was one of them until #142 went looking for it, and Packagist's
  `require` block is one of them today.

Sometimes the *absence* of a key is the finding, and then two payloads have to
be captured rather than one. `nuget/servicebus.registration` and
`nuget/servicebus.registration-semver1` are the same catalog entry for the same
package and version out of nuget.org's two registration hives; they differ by
exactly the `deprecation` block, and holding them side by side is what turns
"the key is missing" into "the registry does not send it here".

One honest consequence: a reduced fixture cannot exercise a fallback path that
depends on the dropped volume. Those paths keep their synthetic tests next to
the adapter, which is what synthetic fixtures are legitimately for.

## Security

Captured payloads are untrusted data (#160's security conditions).

- Capture only fetches `https` URLs whose host is in the manifest allowlist,
  and caps how much of a response it will read.
- Values under credential-shaped keys are redacted at capture; every fixture is
  re-scanned for credential-shaped values on load.
- Fixture and ecosystem ids are validated and the resolved path is
  containment-checked before any file is opened. Nothing inside a payload ever
  becomes a filesystem path or a URL.
- Each file is refused above `max_fixture_bytes`.
- The test suite never touches the network: the replay fetcher raises on any
  URL it has no recording for.
