# Dependency Risk Profiler: Information Sources

This document details the various information sources and methodologies used by the Dependency Risk Profiler to collect dependency metadata for risk assessment.

## Package Registry APIs

### Node.js (npm)

The tool retrieves package information from the npm registry's public API:

- **Endpoint**: `https://registry.npmjs.org/{package-name}`
- **Information Retrieved**:
  - Latest version
  - Deprecation status
  - Repository URL
  - Release dates
  - Maintainer information (partial)
  - The latest release's `dependencies`, which is the transitive signal

Both the deprecation notice and the dependency list live in
`versions[<dist-tags.latest>]`, the published `package.json` as npm stores it,
and neither has ever existed at the top level of a packument. `devDependencies`,
`peerDependencies` and `optionalDependencies` are not what installing the
package pulls in and are not counted.

A manifest with no `dependencies` key is a **measured zero** — that is how npm's
own tooling spells "declares none", and lodash, ms, react and chalk all ship
that way. A packument with no manifest for the latest version at all is a
different thing: nobody read a dependency list, and the signal stays unmeasured.

Example API response structure:
```json
{
  "name": "package-name",
  "version": "1.2.3",
  "deprecated": false,
  "repository": {
    "type": "git",
    "url": "https://github.com/org/repo"
  },
  "time": {
    "1.0.0": "2023-01-01T00:00:00.000Z",
    "1.2.3": "2023-04-15T00:00:00.000Z"
  },
  "maintainers": [
    {"name": "user1", "email": "user1@example.com"}
  ]
}
```

### Python (PyPI)

The tool uses PyPI's JSON API to retrieve package metadata:

- **Endpoint**: `https://pypi.org/pypi/{package-name}/json`
- **Information Retrieved**:
  - Latest version
  - Project URLs (including repository)
  - Description (checked for deprecation indicators)
  - Release history
  - `info.requires_dist`, which is the transitive signal

Requirements gated behind an extra (`PySocks; extra == "socks"`) are optional
tooling and are dropped; requirements gated behind an ordinary environment
marker (`importlib-metadata; python_version < "3.10"`) are runtime on the
interpreters they name and are kept. The test is the marker section after the
semicolon, never a substring of the requirement — `extras`, `pytest-extra` and
`sphinx-extras` are real, installable projects.

**`requires_dist: null` is not zero dependencies.** PyPI sends null whenever the
newest release publishes no `Requires-Dist` metadata, which is true both of
packages that genuinely have none (`six`, `certifi`, `pytz`) and of sdist-only
uploads predating metadata 2.1 that have plenty (`carbon` and `graphite-web`
both report null and both declare real `install_requires`). Null therefore
leaves the signal unmeasured. The cost is real: the zero-dependency packages
lose a signal they could have had, and that is preferred to a confident wrong
number for the sdist population.

Example API response structure:
```json
{
  "info": {
    "name": "package-name",
    "version": "1.2.3",
    "description": "A useful package",
    "project_urls": {
      "Source": "https://github.com/org/repo",
      "Documentation": "https://docs.example.com"
    }
  },
  "releases": {
    "1.0.0": [{"upload_time": "2023-01-01T00:00:00"}],
    "1.2.3": [{"upload_time": "2023-04-15T00:00:00"}]
  }
}
```

### Go Packages

- **Method**: JSON request to the Go module proxy, `https://proxy.golang.org/{module}/@latest`
- **Information Retrieved**: latest version (pseudo-versions and `+incompatible` handled correctly)
- **Repository resolution**: a module path is an import path, not a repository URL. The
  normalizer strips a trailing `/vN` major-version suffix, treats host plus the first two
  path segments as the repository on github.com / gitlab.com / bitbucket.org (the remainder
  being a subdirectory module), and rewrites `golang.org/x/<name>` to its
  `github.com/golang/<name>` mirror offline. Remaining vanity import paths are resolved from
  the `go-import` meta tag at `https://{module}?go-get=1` — a bounded fetch (hard timeout,
  response-size cap, redirect limit, https and public hosts only) whose response is trusted
  for nothing but the `go-import` content, cached per import prefix. The host is resolved
  before the connection is opened and refused if any of its addresses is private, loopback,
  link-local or a cloud-metadata endpoint; the socket then goes to a validated address
  rather than to the name, so a public-looking vanity domain cannot rebind onto an internal
  one. Every redirect hop repeats the whole check. A module that does not resolve keeps its
  repository-derived signals unmeasured rather than scored.
- **Transitive dependencies: not measured, on purpose.** The module's `go.mod`
  is already fetched (for the `// Deprecated:` marker) and its `require` block
  is right there, but Go states no dependency **scope**: `go mod tidy` writes a
  module's test-only requirements into the same direct `require` block as its
  runtime ones. `github.com/sirupsen/logrus` requires `github.com/stretchr/testify`
  beside `golang.org/x/sys`, and the `// indirect` marker separates depth rather
  than scope, so nothing in the file distinguishes them. Counting the block
  would report roughly double for the large share of Go modules that test with
  testify — systematically, and in the direction that makes Go look riskier than
  the ecosystems it is compared against. The adapter therefore records the
  signal as UNMEASURED explicitly rather than staying silent about it.

### Rust (crates.io)

- **Method**: three JSON requests. `https://crates.io/api/v1/crates/{crate}`
  for the crate document, `.../{crate}/owners` for the maintainer count, and
  `.../{crate}/{version}/dependencies` for the dependency list.
- **Information Retrieved**: latest version, repository URL, description, owner
  count, and the crate's `kind: "normal"` dependencies, which is the transitive
  signal.

crates.io is the only registry here whose package document does not carry the
dependency list — it publishes a `versions[].links.dependencies` pointer
instead — so this signal costs a request rather than being read out of a
payload already in hand. That is a deliberate trade: without it crates.io is
the one registry ecosystem that cannot answer a dependency count, and
cross-ecosystem comparisons stop being like-for-like.

`[dev-dependencies]` and `[build-dependencies]` are excluded. `optional = true`
is **not** excluded: it is a feature gate inside `[dependencies]`, not a scope,
and resolving which ones a default build enables would need Cargo's feature
closure rather than a read. A crate can name the same dependency under two
kinds — `acid-store` names `rand` and `tempfile` as both `dev` and optional
`normal` — so names are collected into a set after the kind filter.

### Ruby (RubyGems)

- **Method**: JSON request to `https://rubygems.org/api/v1/gems/{gem}.json`,
  plus `.../gems/{gem}/owners.json` for the maintainer count.
- **Information Retrieved**: latest version, release date, source/homepage URL,
  license list, owner count, description, and `dependencies.runtime`, which is
  the transitive signal.

`dependencies` is an **object keyed by scope**, not a list:
`{"development": [...], "runtime": [...]}`. Only `runtime` is what installing
the gem pulls in. A gemspec states its interpreter and toolchain floors in
`required_ruby_version` and `required_rubygems_version`, which are separate
fields this payload does not publish at all, so unlike Composer there is no
platform construct to filter out of the runtime list.

#### Yanks are removals, not tombstones

RubyGems does not keep a withdrawn release visible with a flag on it; it takes
it out of the index. Every place a yank could surface was checked live:

| Endpoint | What it does with a yanked release |
|---|---|
| `/api/v1/gems/{gem}.json` | Answers with the newest release that still exists; reports `yanked: false` for every gem. |
| `/api/v1/versions/{gem}.json` | Carries no `yanked` key at all, and omits withdrawn releases (`rest-client` 1.6.10, `strong_password` 0.0.7, `bootstrap-sass` 3.2.0.3 are simply absent). |
| `/api/v2/rubygems/{gem}/versions/{version}.json` | Reports `yanked: false`; 404s once the release is withdrawn. |
| `index.rubygems.org/info/{gem}` | Omits withdrawn releases. |

Two consequences the risk score inherits:

- **`yanked: true` is not obtainable.** The adapter still reads the key so it is
  correct the day rubygems.org starts sending it, but the deprecation signal for
  gems comes from the published description instead. crates.io keeps the
  withdrawn release visible with `yanked: true`, so the same idea *is* capturable
  one ecosystem over — the difference is the registry's model, not the read.
- **A gem whose every release is yanked is not separable from a gem that never
  existed.** Both 404 on every endpoint above, identically. That case is left
  honestly unmeasured rather than guessed at, because flagging a 404 as
  deprecated would flag every private, internal, or misspelled gem name too.

### PHP (Composer / Packagist)

- **Method**: JSON request to `https://repo.packagist.org/p2/{vendor}/{package}.json`
- **Information Retrieved**: latest stable version (dev branches skipped)

### .NET (NuGet)

- **Method**: three reads from nuget.org. The flat-container index
  (`https://api.nuget.org/v3-flatcontainer/{id-lower}/index.json`) for the
  version list; the package's own `.nuspec`
  (`.../{id-lower}/{version}/{id-lower}.nuspec`) for everything the package
  declares about itself; and the registration catalog
  (`https://api.nuget.org/v3/registration5-semver1/{id-lower}/index.json`) for
  the facts that exist nowhere else.
- **Information Retrieved**: newest stable version (pre-releases deprioritized);
  `<repository url>` source-repository URL, with `<projectUrl>` as a fallback;
  the SPDX license expression (from `<license type="expression">` or a
  `licenses.nuget.org` URL — a `type="file"` license names a file in the
  package, not a license id, and is not reported as one); declared `<authors>`,
  used only as a maintainer-count fallback; the package's own `<dependencies>`,
  which is the transitive signal; and from the catalog, the publication date and
  the deprecation / unlisted markers.

`<repository>` is read before `<projectUrl>` deliberately: a package's project
URL is routinely a documentation site (MediatR publishes `https://mediatr.io/`),
which is not cloneable, and using it would cost the package every
repository-derived signal.

#### Centrally managed versions (Central Package Management)

Modern .NET solutions declare each version once in a `Directory.Packages.props`
and leave the `PackageReference` bare. Resolution walks up from the project
directory to the nearest such file, expands `$(Property)` references against
that file's own `<PropertyGroup>` elements, honours `<ManagePackageVersionsCentrally>`,
and lets a `VersionOverride` on the reference win over the central declaration.
MSBuild `Condition` attributes are not evaluated, `<Import>` chains out of the
props file are not followed, and floating versions (`1.2.*`) and open-ended
ranges are not guessed at — each of those resolves to `unmanaged` instead.

Every nuget.org read is fenced the same way the Maven Central reads are: https
and `api.nuget.org` only, redirects refused, package ids and versions validated
against NuGet's own grammar before they become a URL path, response bodies
streamed and abandoned past 4 MiB, and a hard per-manifest fetch budget. The one
URL that arrives inside a payload — a registration index's overflow page — is
re-validated against the same host and scheme before it is fetched.

Set `DEPENDENCY_RISK_NO_REMOTE_POMS=1` to disable remote reads; the adapter then
degrades to what the manifest itself proves, with everything else honestly
unmeasured.

### Java (Maven)

- **Method**: two reads from Maven Central. `maven-metadata.xml`
  (`https://repo1.maven.org/maven2/{group-path}/{artifact}/maven-metadata.xml`)
  for the latest version, and the artifact's own published POM
  (`.../{version}/{artifact}-{version}.pom`) for everything else.
- **Information Retrieved**: `<release>` (preferred) or `<latest>` version;
  `<scm>` source-repository URL; `<licenses>`; and the artifact's own shipped
  (compile/runtime scope) dependencies, which is the transitive signal.

#### Maven coverage is a function of artifact age

An artifact's repository-derived signals — last commit, tests/CI, and the
OpenSSF-style security checks — all depend on resolving a cloneable git
repository from its POM. Artifacts published before git won became the norm in
the Java ecosystem cannot supply one, so for them `repository_url` is `None` and
those signals are honestly unmeasured. This is `#74` working correctly, not a
gap to be closed; measuring them would mean guessing at a repository the
artifact never declared.

Two distinct shapes produce it, and neither is a defect:

1. **No `<scm>` block at all.** `commons-collections:3.1`, `axis:1.2`,
   `org.apache.tomcat:tomcat-catalina:7.0.27`, `com.google.guava:guava:19.0`,
   `org.slf4j:slf4j-api:1.7.25` and others predate the convention entirely.
2. **An `<scm>` block that names Subversion or CVS.** `log4j:log4j:1.2.17`
   declares `scm:svn:http://svn.apache.org/repos/asf/logging/log4j/tags/v1_2_17_rc3`
   with an `<url>` pointing at ViewVC. `normalize_scm_url` parses it correctly —
   the `scm:svn:` prefix comes off and an `https://` URL comes out — and
   `canonical_repository_url` then correctly refuses it, because there is no
   `owner/repo` on a cloneable host behind it. `org.jdom:jdom:1.1` and
   `dom4j:dom4j:1.6.1` are the CVS equivalents (`scm:cvs:pserver:...`).

So the discriminator is not whether the POM declares `<scm>`; it is whether what
it declares is a git forge. Across a 25-artifact sample spanning both eras, 9
published no `<scm>`, 12 published one naming SVN or CVS, and 4
(`junit:4.12`, `hibernate-core:4.3.11.Final`, `spring-core:4.3.0.RELEASE`,
`mockito-core:1.10.19`) named GitHub and resolved. The same sample found **no**
artifact whose `<scm><url>` was unusable while one of its `<connection>`
elements was usable, so the `url` → `connection` → `developerConnection`
preference order in `_read_scm_url` costs nothing.

A manifest full of pre-git-era artifacts will therefore report a low scored
percentage and a large unmeasured-signal count. That is the tool declining to
invent data, and the unmeasured counts are the record of it.

#### Inherited versions

Most Java projects declare dependencies without an inline `<version>` and
inherit it from `<dependencyManagement>`. Resolution follows Maven's rules
across the project's own block, its parent POM chain, and any
`<scope>import</scope>` BOM, fetching parent POMs and BOMs from Maven Central as
needed. Every remote read is fenced: https and `repo1.maven.org` only, redirects
refused, coordinates validated against a strict grammar before they become a URL
path, response bodies streamed and abandoned past 2 MiB, and a hard per-manifest
fetch budget with a per-import allowance so one sprawling vendor BOM cannot spend
it all.

Set `DEPENDENCY_RISK_NO_REMOTE_POMS=1` to disable remote resolution. Versions
then resolve only from what the manifest itself proves; anything inherited is
reported as `unmanaged` and its version-drift signal is excluded from both the
numerator and the denominator of the risk score rather than scored as zero
drift.

### Java / Kotlin / Android (Gradle)

- **Method**: none of its own. Gradle publishes and consumes Maven coordinates,
  so every dependency read out of a `build.gradle` or `build.gradle.kts` is
  scored through the Maven Central reads described above and routed to OSV's
  **Maven** ecosystem. `gradle` is an alias onto the `maven` entry in
  `vulnerabilities/ecosystems.py` rather than a tenth ecosystem: an advisory
  against `com.squareup.okio:okio` is the same advisory whichever build tool
  declared it.
- **Information Retrieved**: the `groupId:artifactId` coordinate and, where it
  can be established statically, the installed version. Everything downstream —
  latest version, licence, source repository, shipped dependencies — comes from
  Maven Central.

#### What "statically" means here, and what it costs

`build.gradle` and `build.gradle.kts` are Groovy and Kotlin programs. A
coordinate in one can be computed from an environment variable, a `git describe`,
or a function defined in another file, and the only way to evaluate a Gradle
build is to run Gradle — which a scanner reading untrusted repositories must not
do. So the parser reads the declarative shapes and refuses the rest:

- **Read**: string notation in either DSL (`implementation 'g:a:1.2'`,
  `implementation("g:a:1.2")`), map notation (`group:`/`name:`/`version:` and the
  Kotlin `group = …` spelling), version-catalog aliases and bundles resolved
  against `gradle/libs.versions.toml`, `platform(...)` /
  `enforcedPlatform(...)` / `testFixtures(...)` wrappers, `kotlin("reflect")`
  sugar, and `$name` / `${name}` interpolation expanded from an `ext { }` block,
  a top-level literal binding, or any `gradle.properties` at or above the
  project directory. Declarations are read at any nesting depth, because Kotlin
  Multiplatform keeps every one of them inside a source-set block.
- **Not read**: anything computed at configuration time; dynamic versions
  (`1.+`, `[1.0,2.0)`, `latest.release`); `buildscript { }` and
  `pluginManagement` blocks (the build's own tooling classpath, which is Maven's
  `<build><plugins>` and is skipped there too); `constraints { }` blocks, which
  state a version for a dependency somebody else declares; `project(":x")` and
  `files(...)` dependencies, which have no registry; catalogs under a
  non-default name or declared inline in `settings.gradle`; and `gradle.lockfile`.

Where a coordinate is recoverable and its version is not, the dependency is
reported with the version marked `unmanaged` — the same state Maven's inherited
versions and NuGet's centrally managed ones use, from the same shared
vocabulary in `parsers/version_sources.py`. Version drift is then dropped from
both the numerator and the denominator of the score rather than recorded as
zero drift. Where the *coordinate* itself is computed, the declaration is
counted and logged as unread, because inventing a package name would be worse
than an honest gap.

Two consequences worth knowing before you read a report:

1. In `scan-org` / `scan-user`, manifests are fetched one file at a time, so a
   build script's version catalog is out of reach and catalog-declared versions
   come back unmanaged. The dependency set, the advisories and every registry
   signal are still measured; only version drift is not.
2. Only Maven Central is read. Android projects routinely depend on `androidx.*`
   and `com.google.android.*` artifacts, which are published to Google's Maven
   repository and not to Maven Central, so their POM lookup finds nothing and
   they score UNKNOWN with every registry signal unmeasured — the version is
   resolved, and there is no registry behind it to ask. Profiling okhttp's
   `okhttp/build.gradle.kts` is a fair illustration: 28 dependencies named, 25
   scored, and the 3 UNKNOWNs are exactly the three `androidx` artifacts. That
   is the tool declining to invent data rather than a parse failure.

## Repository Analysis

When a repository URL is available (typically from GitHub, GitLab, or Bitbucket), the tool performs additional analysis:

### Repository Cloning

- The tool creates a temporary clone of the repository using:
  ```bash
  git clone --depth 1 {repository-url} {temp-directory}
  ```
- This shallow clone helps minimize bandwidth and storage requirements while still providing access to the latest code.

### Last Update Analysis

- **Command**: `git log -1 --format=%cd --date=iso`
- **Purpose**: Determines when the package was last updated.
- **Limitation**: A shallow clone only sees recent commit history.

### Contributor Analysis

- **Command**: `git shortlog -s -n --all`
- **Purpose**: Counts unique contributors to estimate maintainer diversity.
- **Limitation**: Shallow clones limit the accuracy of this count.

### Health Indicators Analysis

The tool scans the repository structure for indicators of project health:

1. **Tests**:
   - Looks for directories named `test`, `tests`, `spec`, or `specs`
   - Looks for files matching patterns like `*_test.py`, `*.test.js`, etc.

2. **CI Configuration**:
   - Checks for CI configuration files:
     - `.travis.yml`
     - `.github/workflows/*`
     - `.circleci/config.yml`
     - `.gitlab-ci.yml`
     - `azure-pipelines.yml`
     - `Jenkinsfile`
     - etc.

3. **Contribution Guidelines**:
   - Looks for files like:
     - `CONTRIBUTING.md`
     - `.github/CONTRIBUTING.md`
     - `DEVELOPMENT.md`
     - etc.

## Security Information

The current implementation uses a simplified approach to identify potential security issues:

- **Package Documentation**: Scans package descriptions and documentation for keywords related to security issues (e.g., "vulnerability", "security", "CVE").
- **Simple Pattern Matching**: Checks for patterns like "CVE-####-####" that might indicate known vulnerabilities.

Note: This is a basic approach and not as comprehensive as dedicated security scanners. Future versions could integrate with:
- OSV (Open Source Vulnerabilities) database
- GitHub Advisory Database
- NPM Security Advisories
- NVD (National Vulnerability Database)

## Version Comparison

The tool compares installed and latest versions using the following approach:

1. **Version Parsing**: Uses the Python `packaging.version` module to parse semantic versions.
2. **Version Difference Analysis**:
   - Compares major, minor, and patch components
   - Higher weight given to major version differences
   - Special handling for pre-release versions and non-standard versioning schemes
3. **Calendar Versioning**: A version whose leading component is a four-digit
   year in a plausible range and whose shape is `YYYY.MM`, `YYYY.MM.DD` or
   `YYYY.N` (`certifi`, `pytz`, `tzdata`, Go `vYYYY.MM.DD` tags) is detected
   before distance is computed. Component distance carries no compatibility
   meaning there, so drift is measured as elapsed time between the installed
   release and the latest release, using the release timestamps already
   collected for the staleness signal, and reported as "N years behind
   (calendar versioning)". Without those timestamps the drift signal is
   reported as unmeasured rather than estimated. Detection requires the
   calendar shape, so Go pseudo-versions (`v0.0.0-20210428235338-…`) and
   ordinary semantic versions are unaffected.

## Data Processing Approach

All data collection follows these principles:

1. **Public Information Only**: All information is gathered from publicly available sources, without requiring API keys or authentication.
2. **Network Resilience**: The tool handles network failures gracefully and falls back to partial information when complete data is unavailable.
3. **Local Processing**: Analysis is performed locally without sending dependency information to external services.
4. **Temporary Storage**: Repository clones and other temporary data are stored in temporary directories and cleaned up after use.

## Privacy and Security Considerations

- No dependency information is transmitted to external servers beyond the necessary API calls to public registries.
- The tool does not execute any code from the dependencies it analyzes.
- Repository credentials are never stored or used.
- All network requests use proper User-Agent identification.

## Limitations

1. **Rate Limiting**: Public APIs may impose rate limits that can restrict the tool's ability to analyze large numbers of dependencies in rapid succession.
2. **Data Availability**: Not all packages provide complete information through public APIs.
3. **Network Dependence**: The tool requires internet access to retrieve up-to-date information.
4. **Shallow Analysis**: Due to performance considerations, repository analysis uses shallow clones which may miss some historical context.

---

*This documentation describes the information sources as of version 0.1.0 of the Dependency Risk Profiler.*
