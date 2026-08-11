# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **A captured fixture republished three of Signal's credentials.** GitHub's
  secret scanner opened an alert for a Google Maps API key in
  `testing/fixtures/registry/gradle/signal.build.gradle.kts.json`; a local
  sweep found two Stripe publishable keys in the same file.

  All three belong to `signalapp/Signal-Android` and are published in their own
  repository. An Android Maps key ships inside every APK by design and is
  restricted by package name and signing certificate rather than by secrecy; a
  Stripe `pk_` key is the publishable half and can only tokenize, never charge.
  So this is not a leak of anything that was secret. It is us republishing a
  third party's credentials, which is not ours to do, and a fixture that trips
  every scanner trains people to ignore the scanner.

  Redacted, with a `redactions` block recording what was replaced and why, so a
  recapture cannot quietly restore them. No assertion read the values — the
  fixture exercises Gradle dependency-coordinate parsing.

  The cause is structural rather than careless: rule 5 requires conformance
  fixtures to be **captured** from live sources, never authored, and a real file
  from a real project can contain real credentials. So the fix is a gate at the
  boundary rather than a check inside each capture script — gitleaks now runs in
  the `security` job, which is a required status check. `.gitleaks.toml` records
  the deliberately credential-shaped values with the reason each is allowlisted,
  because an allowlist entry without a reason is indistinguishable from a
  mistake.

  The repository had **no** secret scanning of its own before this. GitHub's
  scanner found it first, which is a fine outcome once and a poor arrangement
  twice.

  **And gitleaks alone would not have caught it.** Verified by reintroducing the
  key and scanning: a fixture stores its payload as a JSON string, so a key
  inside it is written `\"AIza...\"`, and the escaped quote defeats the trailing
  word boundary that provider rules use. The identical key is found in a `.txt`
  file, found in a `.json` file as raw text, and **missed** once JSON-encoded.
  So gitleaks covers source and configuration, where it works, and a repository
  rule decodes fixture payloads and searches them as the source they are. On the
  same tree with the same key: gitleaks reports *no leaks found*; the rule fails
  and names the file.

- **And then the gate itself turned out to be scanning nothing.** The paragraph
  above says gitleaks now runs in the `security` job. It ran; it did not scan.
  `gitleaks-action` scans a commit range on `pull_request`, `actions/checkout`
  fetches shallow, so `<base>^` was not in the object store. Git errored and the
  scan reported `scanned ~0 bytes (0)` and then `no leaks found`. The job went
  red only because the action surfaced git's exit code — the scanner's own
  verdict, over zero bytes, was a pass. That is rule 6 and the same shape as
  `Analyze (go)` in #231: a required check answering for a subject it never
  looked at.

  Resolving the range would not have been enough. A diff scan cannot see a
  secret that is *already* in the tree, and that is exactly how this key
  survived: it entered in b43e41e and was redacted in ec45676, and every pull
  request in between was legitimately clean, because the key was in no diff.
  That is the real reason GitHub's scanner found it first — a diff-scoped gate
  structurally could not have.

  So the scan reads the working tree, `--no-git --source .`, covering 5.86 MB
  in CI where the old step covered none of it. The binary is invoked directly
  and pinned by SHA-256; the action's only remaining value was installing it,
  its scan mode is not overridable, and dropping it takes a third-party
  JavaScript action holding `GITHUB_TOKEN` out of the job.

  And the step now scans a planted credential *before* it scans the tree, under
  the same `--config`, and fails if that comes back clean. A scanner that cannot
  fail is indistinguishable from one that found nothing, which is the shape of
  every silent-pass defect in this file. `test_secret_scan_reads_the_tree_and_
  proves_it_can_fail` holds both properties.

  Pinning the version also surfaced two findings the older local binary missed:
  the canary literal itself, moved out of the workflow into
  `.github/secret-scan-canary.txt` and allowlisted by exact path, and
  `slf4j-parent.pom` scoring 3.88 on `generic-api-key` — a Maven fixture
  filename, allowlisted by a pattern narrowed to the two extensions the
  conformance fixtures actually name.

  The key remains reachable in git history at `2555c50`. Purging it needs a
  history rewrite, which is the owner's call: #323.


### Added

- **The abandonment pilot, and the answer is that the score loses to download
  count.** `docs/validation-protocol.md` stages the validation work and stage 2
  is a pilot on abandonment with release cadence and version drift ablated,
  because "low cadence predicts the future absence of releases" predicts a
  variable from itself. This is that pilot: 2,906 npm packages sampled at
  T = 2024-08-01, labelled on whether they published anything in the two years
  after, scored by the shipped `RiskScorer` at its shipped weights from inputs
  reconstructed as they stood at T.

  **Download count at T alone separates the two classes at AUC 0.696. The score
  reaches 0.577 on the same packages** — 0.119 behind, clustered 95% CI
  [−0.155, −0.085]. Against package age and dependency count it is nominally
  ahead by 0.015 and 0.024 with intervals spanning zero, and against a star
  count read *today* — which knows which of these projects went on to be
  popular, and was left advantaged deliberately — it is a dead tie. The
  protocol's stage 3 says to stop and report when the trivial baselines cannot
  be beaten, and this is that report: `docs/abandonment-pilot.md`.

  Two of the protocol's four falsification lines are met. Line 1, the primary
  one, by 0.119 in the wrong direction. Line 3 because the HIGH bucket carries
  1.11× the base rate against a 2× requirement, and no package in 2,906 reaches
  CRITICAL at all. Neither triggers a documentation change here: the pilot is
  one outcome on one ecosystem, and line 1 is written against the
  advisory-arrival experiment that stage 4 has yet to run.

  **N is measured, not assumed.** Abandonment needs a silence length, and two
  years is the conventional one. Rather than inherit it, the harness builds an
  actuarial life table of release silences over 36,420 sampled packages and
  reads off the 12-month resumption hazard: after one year of silence an npm
  package still has a 12.0% chance of publishing again within the year, after
  two years 4.5%, after three 2.2%. N = 2 is the first whole year under 10%,
  and the same answer comes out at all four candidate cut-off dates. The
  convention turns out to be right. It is now also a measurement.

  The population fed to that table is every sampled package, not the cohort,
  and the difference is not pedantry. The cohort has to be alive at T, so its
  silences are the ones that ended; built on it, the hazard plateaus near 40%
  out to seven years and no year clears any cutoff. Selecting on activity and
  then measuring how often activity resumes is the same circularity the pilot
  exists to avoid, one level down.

  **Three findings about shipped code fell out of driving it.** `deprecation`
  cannot be reported unmeasured — `is_deprecated` is a `bool` with a `False`
  default, so every package is scored with a confident "not deprecated" even
  though #312 found the underlying npm field is unreconstructable at a past
  date and applied retroactively. Leaving `advisory_lookup_state` unset hands
  every package a confident clean `0.0` at the tool's largest single weight;
  that is deliberate backward compatibility for offline runs, and for a
  backtest it is a fabricated measurement — recording `NOT_ATTEMPTED` moved 174
  packages into the HIGH bucket that were otherwise nowhere near it. And the
  scorer declines a verdict on 79% of this cohort, because a package that
  declares a repository nobody read has eight unexplained silent signals; that
  is the rule working, and it means a registry-only deployment is mostly
  abstentions.

  The per-signal ablation says `maintainer` is the only one of the three
  surviving signals carrying anything — drop it and the model falls to 0.488,
  below chance — and that `license` is **actively harmful** here, since
  dropping it *raises* AUC to 0.600 with an interval excluding zero.

  The harness lives in `research/`, is not packaged, and adds no runtime
  dependency: AUC is a rank sum and average precision is a walk down a sorted
  list, so `research/abandonment_pilot/stats.py` is stdlib. The protocol asks
  for a paired DeLong test and, separately, for clustered intervals because
  packages sharing a maintainer are not independent; those two are in tension,
  and the clustered paired bootstrap that replaces DeLong is argued in the
  results document rather than substituted quietly. It is not a cosmetic
  difference: on the star comparison the clustered interval is 3.7 times wider
  than the independent one.

  Data is pinned. `research/data/npm-2026-08-06/` carries a manifest of SHA-256
  digests and the loader refuses a snapshot that has drifted, so a rerun either
  reproduces the published numbers or says why it cannot. CI never touches a
  registry: the negative control runs against the pinned snapshot, and a test
  asserts that no analysis module can so much as import an HTTP client.

- **A forge adapter contract, so a coverage gap is visible instead of silent.**
  The community pass was named `analyze_github_community_metrics` and gated on
  a regex that looked for `github.com` anywhere in the repository URL. A
  package on any other host fell out of the top of it and returned unchanged,
  so its star count, contributor count and commit cadence were simply never
  attempted — and the report said the same thing about that package as it said
  about a GitHub package whose API call failed. Two different facts, one
  silence.

  Repositories now route by host through `ForgeRegistry`, which mirrors
  `EcosystemRegistry` including its name-only tier, so there is one table
  rather than a second hand-written host list to drift out of agreement with
  the first (#265 is what that costs). GitHub is the first adapter and
  reproduces exactly what the previous code did: the same three lookups
  against the same endpoints, in the same order.

  The layer is deliberately small, because the measurement says it should be.
  **Seven of the eight repository-derived signals are read from a shallow `git
  clone`** — `pathlib` checks and `git` subprocesses — and need no forge API at
  all, so a host nobody wrote an adapter for still scores on them. Exactly one
  signal, `community_popularity`, has no reading outside a forge, and the two
  refinements beside it are countable from git history a `--depth 1` clone does
  not have. That is three capabilities, not eight; `ForgeCapability` names the
  three that a caller asks for and an adapter serves, and nothing else.

  `ForgeAnswer` is the same two-state gate as `Measurement` and reuses
  `UnmeasuredReason` rather than inventing a vocabulary beside it: measured
  carries a value and the acquisition path that produced it, unmeasured carries
  a reason and can carry neither a value nor a source. An adapter that omits
  `capabilities` raises at class-definition time, and the router never calls
  `fetch` for a capability the adapter did not declare — so there is no code
  path in which an adapter could answer `0` for something its API does not
  serve, because nothing asks it.

  The difference reaches the output. Schema v2 gains a `forge` block naming the
  resolved forge and, per capability, either the path that answered or the
  reason nothing did. A Codeberg-hosted package reports
  `lookup_not_attempted` against a `null` forge; a GitHub-hosted package with
  no token reports `no_data_from_source` against `github`. `docs/forge-coverage.md`
  publishes both tables and is generated from the adapters' own `capabilities`
  sets, checked by `testing/unit/test_forge_contract.py` so it cannot drift.

  No GitHub-hosted package moves, measured against a noise floor established
  before the change rather than assumed. Four runs of the unmodified tool over
  a 30-package corpus (28 of them GitHub-hosted): three runs minutes apart
  agreed in every field, and one 25 minutes later differed in **3** — two
  commit cadences and one star count, all live GitHub counts, one of which
  oscillated back on the next run. Against the closest-in-time baseline, this
  change moves **no** field on any GitHub-hosted package.

  It moves two on the one Codeberg-hosted package, and the direction is worth
  stating: the branch that reuses a registry-declared maintainer count when the
  forge cannot supply one sat *after* the GitHub-only early return, so it never
  ran for any other host. `django-allauth` now reports the contributor count
  PyPI publishes, attributed to `registry:metadata` rather than to a forge. Its
  risk level, score and unmeasured-signal count are unchanged (#292).

### Changed

- **`license` leaves the scored composite and is reported on its own axis
  (#340).** Removing it *raised* the model's discrimination in all seven
  abandonment ablations — two outcome definitions at four dates, effects from
  +0.016 to +0.044 AUC, every maintainer-clustered 95% interval excluding zero.

  **This is not the model getting better.** A signal measured to be harmful was
  removed; the composite is still unvalidated, still scores 0.577 to 0.605
  against a 0.696 download-count baseline, and the README's withdrawn claim
  stays withdrawn. Twelve of the fifteen remaining signals have never been in
  any arm. What changed is that one thing we know is wrong has stopped
  happening.

  The licence is not deleted, because a restrictive or unrecognized licence is
  a genuine legal and compliance risk to a consumer. It is real; it is simply
  not a forecast of abandonment, and averaging a compliance fact into a risk
  forecast is the category error #242 fixed for advisories. So it is reported
  the way `known_vulnerable` is: `license_flagged` beside `risk_level` in the
  schema-2 payload (additive), a `LICENSE` column in the terminal table and the
  CSV, and its own panel in the org report beside Advisories. It leaves
  `risk_factors`, which names what moved the verdict.

  **The predictive value of the licence axis has not been measured, for any
  outcome.** It is published as a fact, labelled as one, and nothing here
  claims it forecasts anything.

  Three consequences, none of them absorbed quietly:

  - **Every composite moves slightly.** A signal leaves the denominator as well
    as the numerator (#74), so a package with a clean permissive licence scores
    marginally *higher* and one with a flagged licence marginally lower. axios
    1.6.5's unfloored mean goes 1.136 → 1.250 of 5.
  - **No ecosystem reaches a verdict from a registry document alone any more.**
    A verdict costs eight measured signals of fifteen, and seven is the most a
    registry-only scan (no clone, no token, no advisory lookup) can reach. Six
    ecosystems — cargo, composer, nodejs, nuget, python, rubygems — were sitting
    exactly on the bar at eight of sixteen, and the eighth was the licence. Being
    carried over the line by the one signal measured to make the forecast worse
    was not a margin. Asking an advisory source restores a verdict for all six,
    with a margin of one; it is the single input that moves every ecosystem up
    by one.
  - **`--license-weight` and the `scoring_weights.license` config key are
    gone.** A weight on a signal nothing weighs is a flag that lies.

  The measured-signal floors move with it: the registry-only ceiling is 7 rather
  than 8, the six ecosystems above drop 8 → 7, maven and gradle 6 → 5, and
  golang stays at 5 (its registry never published a licence, so the subtraction
  loses a term on both sides). `SCORES_FROM_REGISTRY_ALONE` is now False for
  every ecosystem.

  Enforced rather than asserted in prose: `SIGNAL_CATALOG` carries a `scored`
  flag, `docs/signals.md` publishes it in a column the catalog test reads back,
  and a test scores one recorded crates.io payload twice — differing only in
  whether a licence was declared — and requires the mean, the verdict, and both
  signal counts to be identical.

- **AGENTS.md states the ponytail ladder rather than gesturing at it, and adds
  a rule about comments.** The ponytail section named "the reuse rung" without
  ever listing the rungs, so the operative mechanism was a reference rather
  than an instruction. All seven are now written out, each with a worked
  example from this repository — including one where the ladder's first rung
  applied to a fix already in progress: a terminal-width budget was computed to
  size a report column and reproduced the bug it was meant to fix, because the
  columns already exceed any terminal and there was no budget to spend.

  New rule 7: **comments are evergreen.** A comment states what is true now and
  why the code is as it is; it does not narrate the change that produced it.
  The test is to delete the history and ask whether what remains still explains
  the code. Trailing issue references stay as pointers, rationale stays, and
  test docstrings may still name the defect they guard — a regression test's
  subject *is* the historical defect.

  Rule 7 is not mechanised, and the reason is recorded rather than left as a
  gap: a grep for "previously" or "no longer" fires on legitimate prose about
  external facts, and this file's own standard is that a check firing on
  legitimate work is a bug in the check.

  Four comments fixed as demonstration, one of them written the same day the
  rule was: a column-width comment that explained itself by reference to the
  constant it replaced. The remaining sweep is #309, measured at 255 comments
  carrying issue references and 165 written in past tense about the code — an
  upper bound, since both forms are sometimes legitimate.


### Changed

- **`main` is now branch-protected, and the Allstar policy describes what is
  actually set rather than what someone hoped.** The policy file demanded
  approvals, required status checks, and no force pushes while the branch had
  **no protection at all** — `gh api .../branches/main/protection` returned 404 —
  and the README carried a hardcoded `OSSF Allstar Protected` badge on top of
  that, published to PyPI through the long description.

  Set on `main`: the six CI jobs that do real work as required contexts, strict
  up-to-date branches, no force pushes, no deletions. That closes all seven ways
  found in one day for a pull request to reach "no red anywhere" without being
  tested (#152) — a conflicting PR gets zero runs, a stacked PR matches no
  trigger, retargeting does not re-fire, an aggregate check reports `neutral`
  over red jobs, and a required check can analyse an empty file set. GitHub
  blocks on an **absent** required check exactly as it blocks on a red one.

  `requireApproval` is deliberately `false` and says so: one maintainer means an
  approval requirement blocks every change on the only person who could approve
  it, including the dependency updates this project exists to encourage. Written
  down as a trade-off rather than left for Allstar to file an issue about.

  The static badge is gone. It rendered green unconditionally — a shields.io
  image, not a status endpoint — beside two badges that do report real state.


### Fixed

- **Two questions nobody asked, and the reassuring answers the scorer invented
  for them.** `advisory_lookup_state` was `Optional` and an unrecorded state
  read as *measured*, so `exploit` scored a confident `0.0` from
  `has_known_exploits` for every dependency nobody asked an advisory source
  about — at the tool's largest single weight, 0.5 of 3.5. `is_deprecated` was
  a `bool` defaulting to `False`, so `deprecation` was *always* measured and no
  adapter could say nobody looked, which is the only honest answer for Maven
  Central: it publishes no retirement marker of any kind. Both are the same
  defect, a type whose most reassuring inhabitant is also its default, and they
  are fixed together because fixing either alone re-baselines the same nine
  per-ecosystem floors twice (#320, #321).

  The cost, measured rather than argued. Driving the production scorer over a
  pinned 2,906-package npm cohort at a past date, the unrecorded advisory state
  put a fabricated `0.0` into the weighted mean for every package and left the
  HIGH bucket **entirely empty**; recording the honest `NOT_ATTEMPTED` moved
  **174 packages** out of LOW and MEDIUM into HIGH. A reader of the first table
  would have concluded the thresholds were unreachable.

  `advisory_lookup_state` is no longer optional. It is an `AdvisoryLookupState`
  defaulting to `NOT_ATTEMPTED`, which is what a manifest parser produces and
  what a registry-only scan ends on, and `advisory_lookup_is_measured` now
  fails closed exactly as `transitive_is_measured` has since #199. Recording
  the state explicitly and recording nothing are byte-identical — verified on
  the same cohort — so the fabricated zero is unreachable from any call site
  rather than merely discouraged at all of them. `is_deprecated` is
  `Optional[bool]` defaulting to `None`, written only through
  `record_deprecation`, whose argument is required and keyword-only. `False` is
  a measurement; `None` is the absence of one.

  Seven registries state retirement and their adapters now record both answers:
  npm's per-version `deprecated`, Packagist's `abandoned`, crates.io's and
  PyPI's `yanked`, RubyGems' description, NuGet's SemVer2 catalog `deprecation`
  block, and Go's `// Deprecated:` directive. Three of those reads could not
  express "no document was read" and returned `False` for it — npm when the
  packument carries no manifest for `latest`, Go when the proxy sends no
  `go.mod`, crates.io when no release entry was merged — and each now returns
  `None` instead. Maven and Gradle record nothing.

  **The nine measured-signal floors are re-baselined in the same change, and
  four ecosystems lose their verdict.** They are derived from what each
  registry answers in the weakest deployment mode — no clone, no token, no
  advisory lookup — not chosen to reproduce the previous output distribution,
  which would only move the lie from the signal into the floor. cargo, composer,
  nuget, python and rubygems 9 → 8; nodejs 8 → 7; maven and gradle 8 → 6;
  golang 6 → 5. Eight of sixteen is the insufficient-data edge, so golang,
  gradle, maven and nodejs now report UNKNOWN from registry metadata alone and
  `SCORES_FROM_REGISTRY_ALONE` says so. That is a true statement about what a
  registry-only scan can know, and asking one advisory source is the single
  input that moves every ecosystem in the table back up by one.

  **Scores move, and both directions are the honest one.** Dropping a signal
  from the denominator raises the score of anything carrying risk: across the
  34-case captured conformance corpus, LOW 20 → 5, MEDIUM 12 → 13, HIGH 0 → 3,
  CRITICAL 0 → 1, UNKNOWN 2 → 12. On the npm cohort the shift is larger still,
  because npm packages never answered the deprecation question either: LOW
  2144 → 882, MEDIUM 588 → 1349, HIGH 174 → 496, CRITICAL 0 → 179. Nothing in
  the scale changed. Two fabricated zeros left it.

  **Read that npm row with its abstention rate or it says more than it knows.**
  On the same run, `insufficient_data` goes 2303 → **2906**: every package in
  the cohort, without exception. So those four buckets are where the thresholds
  land, not verdicts the tool will publish — a registry-only npm scan now
  declines to score the entire cohort, which is the honest answer once npm
  answers neither the advisory question nor the deprecation one. Quoting the
  distribution without the abstention would repeat, in the entry describing the
  fix, the shape of the defect being fixed. Discrimination is unchanged
  (AUC 0.5658 → 0.5665), exactly as expected: `deprecation` was constant across
  the cohort, so removing it cannot reorder anything — it moves absolute scores
  and the calibration buckets, and nothing else.

  **One ecosystem was measured; eight were derived.** The cohort above is npm.
  The other eight floors — including maven and gradle, which fall by two and
  are therefore the largest claim in the table — rest on the attribution
  argument and the conformance corpus, not on distribution data. The npm run
  does not vouch for them.

  The state is validated wherever it is set, not only where it is recorded.
  `record_advisory_lookup` is the writer, but a dataclass field is settable at
  construction too, and that is the shape a deserializer takes: read a state
  out of a stored record and hand it to the constructor. Both now go through
  one validator, so a `FAILED` that cannot name what failed is rejected however
  it arrives, and a dependency built with nothing said about advisories comes
  out claiming nothing rather than inheriting a state that reads as a
  measurement. There is no compatibility fallback for an omitted state.

  The floors carry their attribution as data rather than as prose.
  `REGISTRY_ONLY_CEILING` names the eight signals a registry-only scan can
  reach and `REGISTRY_UNANSWERED_SIGNALS` names what each registry withholds,
  and every floor is checked to be exactly that subtraction. The tables are
  hand-maintained and deliberately not derived from the scorer: a floor
  computed from whatever the code measures cannot disagree with the code, which
  is the one thing a floor exists to be able to do. Before this, an ecosystem's
  missing signal could be swapped for a different one with every count
  unchanged, leaving the recorded reason quietly false.

  This is a **contract change**. Schema v2 emits `is_deprecated: null` for a
  package no registry answered for, and `signals.deprecation` and
  `signals.exploit` carry `{"state": "unmeasured", "reason": …}` where they
  previously carried a measured `0.0`. `NOT_ATTEMPTED` and `FAILED` remain
  distinct as *reasons* — an operator needs to tell an outage from a scan that
  asked nobody — and collapse to one thing only at the scoring boundary, where
  both mean the signal has no value.

- **A clone that failed was not remembered, so one unusable repository cost 60
  seconds per package that pointed at it.** Eight of the eighteen NuGet packages
  in eShopOnWeb's `Web.csproj` resolve to `github.com/dotnet/dotnet`, the .NET
  unified-source monorepo. A shallow clone of it does not finish inside the
  60-second timeout, and it did not finish eight separate times: **480 of that
  run's 576 seconds**, at a metronomic 60-63 second cadence, re-learning a fact
  that was known after the first attempt. Every other ecosystem in the corpus
  runs at 1.5-2 seconds per dependency; this one ran at 32.

  A clone failure is now recorded for the rest of the process and keyed on the
  normalized clone URL — the exact argument handed to `git clone`, which is
  what decides the outcome. Not the package, because the eight packages are
  eight names for one repository; not the registry's raw string, because
  registries spell one repository several ways and each spelling would buy its
  own timeout. Same manifest, same machine, two runs each way: **576s and 636s
  before, 163s and 155s after, with one clone attempt against `dotnet/dotnet`
  instead of eight.** A project whose clones succeed is unaffected — ripgrep's
  `Cargo.toml` measured 20s before and 18s after.

  The 60-second timeout is unchanged, and measuring it was what settled that.
  It is not too generous; it is already tight. A successful shallow clone of
  `Azure/azure-sdk-for-net` — which this same manifest depends on — takes **65
  seconds** for 1.8 GB, which is why that one package flips between measured and
  unmeasured from run to run. `dotnet/runtime` clones in 38s. Lowering the
  timeout would buy at most a one-off `60 - T` seconds per unusable repository,
  now that the cost no longer multiplies, and would pay for it by turning large
  repositories that currently succeed into permanently unmeasured ones.

  The cache does not outlive the run, and that is the design rather than a
  shortcut. A cached failure silences eight signals, so persisting one to disk
  would mean a network blip during today's run goes on reporting a repository
  as unreadable tomorrow, after the condition has cleared — a stale negative
  served past the fix, which is the shape of #219. Keeping the entry in the
  process keeps it inside the run where the failure was actually observed, and
  leaves nothing on disk for a URL built from package metadata to collide with
  or escape from.

  What a user gets back is unchanged, and that was the point: the cached answer
  is the same `None` the failing clone returns, so there is one downstream code
  path rather than two, and a cached failure cannot become a measured zero. The
  JSON for all eighteen packages is identical across the change, signal for
  signal and verdict for verdict.

  Failed clones also stopped leaving their partial checkouts behind.
  `clone_repo` creates the destination before it shells out, git writes into it
  as it goes, and only the success path was ever cleaned up — one eShopOnWeb run
  left eight orphaned trees at 340-410 MB each, and a machine that had been
  running the corpus had 6.4 GB of them, the largest a single 1.3 GB fragment.
  Those are now zero bytes. An *empty* directory can still survive, because the
  timeout kills `git` but not the transport helper it spawned, which recreates
  its destination on the way out; that last scrap is folded into #301.

  Reusing a *successful* worktree across the dependencies that share it is the
  same win in the healthier direction and is #301. A failed clone still reports
  `no_data_from_source`, which names the wrong cause — the registry answered and
  was right — and that is #302.
- **`max_counted_cvss_score` was a severity label wearing a number's clothes.**
  `_extract_osv_cvss_score` read OSV's `severity[].score` as a number. The OSV
  schema defines that field as the CVSS **vector string** —
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — so `normalize_cvss_score`
  answered `None` for every OSV record the tool has ever fetched. In a 2247-
  advisory corpus across nine ecosystems, **0 of 1412** deduplicated advisories
  carried a numeric CVSS. The read had never once succeeded.

  Nothing crashed, because there was a fallback: `severity_to_score(tier)`, which
  maps the *label* to a representative number. That number was then published as
  `max_counted_cvss_score`, a field whose name asserts a measurement. Across 29
  packages it took exactly three values — 5.0, 8.0 and 10.0 — and it was wrong
  against GitHub's own published base score for all six advisories checked:

  | advisory | package | before | after | GitHub v3.1 |
  |---|---|---|---|---|
  | GHSA-frmv-pr5f-9mcr | Django | 10.0 | **9.1** | 9.1 |
  | GHSA-xqr8-7jwr-rhp7 | certifi | 8.0 | **7.5** | 7.5 |
  | GHSA-2g68-c3qc-8985 | Werkzeug | 8.0 | **7.5** | 7.5 |
  | GHSA-9hjg-9r4m-mvj7 | requests | 5.0 | **5.3** | 5.3 |
  | GHSA-3pqx-4fqf-j49f | PyYAML | 10.0 | *unmeasured: CVSS:4.0* | 9.8 |
  | GHSA-3f63-hfp8-52jq | Pillow | 10.0 | *unmeasured: CVSS:4.0* | 8.1 |

  The vector is now decoded. `vulnerabilities/cvss.py` computes CVSS v3.0 and
  v3.1 base scores from the eight base metrics — the specification's closed-form
  arithmetic, no new dependency — and is checked against every distinct
  `(vectorString, baseScore)` pair NVD publishes, 498 of them, captured into
  `testing/fixtures/cvss/`. 674 of the corpus's 1412 advisories now carry a
  score, spread across **52 distinct values** instead of three.

  **CVSS v4.0 is not scored, and says so.** Its base score is a 270-entry
  MacroVector lookup with an interpolation over neighbouring equivalence
  classes, and NVD publishes only 164 distinct v4 pairs to check one against —
  too few to cover the table. An advisory whose highest severity entry is v4.0
  reports no score and names the version it could not compute, in a new
  `cvss_unknown` / `cvss_unknown_reasons` pair beside the maximum. It does not
  reach past the v4 entry to the v3 one beside it: a publisher that rescores an
  advisory under v4.0 sets its label from the v4 score, and 41 of the 161
  dual-scored advisories surveyed have a v3.1 band that contradicts their own
  label for exactly that reason.

  Two things follow, neither of them cosmetic. `normalize_vulnerability_severity`
  has always had a CVSS fallback for advisories that publish a vector and no
  label, and it had been unreachable for as long as the score arrived `None`;
  **204 of 2246 advisories** move out of `UNKNOWN` and state a severity, and the
  unlabelled-but-scored records turn out to be PYSEC, not RUSTSEC. And the
  maximum no longer covers every counted advisory, so the exploit signal stops
  reading it alone — it takes the worse of the maximum and the severity label.
  Without that, this fix would have quietly *lowered* the exploit signal for five
  of 29 packages, pillow and `github.com/docker/docker` from 1.0 to 0.75.

  The verdict floor is unmoved: it keys on `max_counted_severity`, the label, and
  every risk level, floor and exploit score in the corpus is byte-identical
  before and after. The only field that changed is the one that was lying.

- **The Maven resolver knew one repository, so every `androidx` artifact was
  unmeasurable.** `repo1.maven.org` was the only base URL in the tool. Every
  `androidx.*`, `com.google.android.*` and most `com.android.tools*` artifact
  is published to Google's Maven repository and to no other, so the lookup
  404'd and the artifact came back with thirteen unmeasured signals and
  `risk_level: UNKNOWN`. On Signal-Android that was **64 of 94 dependencies**
  — a real, large, extremely ordinary Android project scoring nothing for two
  thirds of what it ships, because of one missing constant.

  Central and Google are both asked now, and the two questions a repository
  answers get different rules. The POM at a pinned coordinate is immutable, so
  the first repository that has it is the whole answer; Central is asked first,
  which is why a project with no Google-published dependencies pays **zero**
  extra POM requests. `maven-metadata.xml` is a per-repository *view* of a
  global fact, so every repository is asked and the answer merged on
  `lastUpdated` — Central's copy of `com.android.tools.build:gradle` stops at
  2.3.0 and 2017-03-06, the day Google moved the Android toolchain to its own
  repository, and taking it would report a live artifact as nine years stale
  and a current project as *ahead* of the latest release. That is a confident
  wrong number, which is worse than the unmeasured one being fixed.

  On Signal-Android's `app/build.gradle.kts`: UNKNOWN **64 -> 2**, measured
  signal coverage **373/1504 (24.8%) -> 685/1504 (45.6%)**. The two that remain
  are honest. `com.mobilecoin:android-sdk` is published to none of the six
  repositories that were measured — Signal serves it from its own repository —
  and reports as absent from every repository we ask rather than as unread;
  `net.zetetic:sqlcipher-android` resolves fine and simply has too little
  evidence behind it, which it also did before. On WebGoat's `pom.xml` the
  output is **identical in every field**: 46 dependencies, 1 UNKNOWN,
  358/736 signals. Central resolution did not move.

  The cost was measured rather than assumed, because a repository is a request
  on every miss. WebGoat: 169 -> 215 requests, **+1 per dependency**, all of it
  the metadata merge and none of it POM reads. Signal-Android: 189 -> 292,
  +1.10 per dependency — and Central POM reads *fell* from 95 to 38, because
  the metadata lookup already established which repository publishes an
  artifact and the POM read starts there. Without that, Signal would have cost
  358 requests instead of 292.

  Four more repositories were measured against Signal's dependency list and
  rejected, each with a reason beyond its zero: JitPack is a build service
  whose cold metadata request triggers a build and took 15.3 s; Gradle's plugin
  portal 303-redirects misses to Central and serves coordinates this tool
  deliberately does not read; `repo.spring.io/release` answers 401 to an
  anonymous request; a snapshot repository holds versions no released manifest
  pins. The list stays a compile-time constant and the build file cannot add to
  it — Gradle's `repositories { }` names arbitrary URLs, and honouring them
  would turn a fetcher with a closed host set into one whose destination is
  chosen by the file under analysis.

  A repository that answers 404 and one that does not answer at all are now
  different facts, and "every repository was asked and none has it" is
  unreachable unless the recorded outcomes actually cover the configured set.
  A spent fetch budget therefore leaves an artifact *unread*, never
  *unpublished* — the #219 defect at repository scope, closed by construction
  rather than by convention.

  One inconsistency fixed alongside it: `DEPENDENCY_RISK_NO_REMOTE_POMS=1`
  claimed to keep resolution fully offline and still fetched
  `maven-metadata.xml` over the network. It no longer does.

- **A Python constraint was scored as though it were the installed version.**
  `requests>=2.20.0` produced a record byte-identical to `requests==2.20.0`:
  the same `known_vulnerable: true`, decided from four advisories fixed in
  2.20.1, about a project that may well be running 2.32.5 and have none of
  them. `billiard>=4.2.1,<5.0` landed as `installed_version: "4.2.1,<5.0"`
  with a version-drift signal reporting `measured` off a string that is not a
  version by any reading. An unpinned line became the word `latest`, which then
  rendered as `latest → 5.4.4 · behind latest` beside a count of `0 signals
  could not be measured`.

  A bound is not a version, and the two no longer share a slot.
  `installed_version` now holds one concrete version or nothing at all, the
  declaration is kept beside it as `declared_constraint`, and an unpinned
  requirement is marked `unmanaged` — the same contract NuGet's unreachable
  `Directory.Packages.props`, Maven's inherited versions and Gradle's dynamic
  versions have had since #141. So version drift comes back `unmeasured`
  rather than as a number computed against an invention, and an advisory
  reports `applicability_unknown` with `installed version unknown` instead of
  a verdict it had no version to reach.

  What a user gets back is different in both directions. On celery's
  `requirements/default.txt` all nine drift signals become unmeasured, which is
  the honest answer for a file that pins nothing — and measured coverage still
  *rises*, 128/143 to 133/144, because `backports.zoneinfo[tzdata]` had been
  queried as a PyPI project of that literal name, found nothing, and scored
  2 of 15. Extras are not part of a name; it now resolves as
  `backports-zoneinfo` and scores.

  The sharper case is the one that was supposed to be safe. Read a line at a
  time, `pip-compile --generate-hashes` output — the most thoroughly pinned
  manifest Python has — gave every package a version with a trailing backslash
  (`26.1.2 \`) and one extra dependency named `--hash`. Nothing could be
  compared against a version in that shape, so on warehouse's lockfile
  **seven packages reported `known_vulnerable: true` on 27 advisories nobody
  could place**, `pip` among them with twelve. All 27 now resolve against the
  real pin and none of them applies.

  Both Python readers go through one PEP 508 parse now. `parsers/python.py`
  used to strip the operator and `parsers/toml.py` used to keep it, so the same
  line read two different wrong ways depending on which file it was written in;
  the chain they replace also turned `requests!=2.0` into a package called
  `requests!` and `tzdata; sys_platform == "win32"` into one called
  `tzdata; sys_platform`. Environment markers are parsed off the name and the
  dependency is kept: whether it applies to the machine running the scan is a
  different question, and the tool reads a manifest, not an interpreter.

- **A repository that keeps its metadata where its own forge looks for it read
  as a repository that has none.** The `scorecard/` checks and
  `utils.check_health_indicators` searched GitHub-shaped paths — `.github/`,
  and only `.github/`, for pull request templates, issue templates, CODEOWNERS,
  security policies, workflows and CI. On a Forgejo-, Gitea- or GitLab-native
  layout the file is there and the check said `False`, which the scorer counts
  as evidence against the project. This is the #218 defect one layer out: #218
  made a read that *raised* unmeasured, and a read that succeeds against the
  wrong path stayed a confident negative finding.

  Measured, not reasoned about. Taking the real Codeberg clone of
  `allauth/django-allauth`, which ships `.gitea/pull_request_template.md` and
  `.gitea/ISSUE_TEMPLATE/` beside a `.github/` kept for its GitHub mirror, and
  deleting `.github/`:

  | signal | before | after | truth |
  |---|---|---|---|
  | `has_pull_request_template` | False | **True** | `.gitea/pull_request_template.md` |
  | `uses_pull_requests` | False | **True** | it does |
  | `has_issue_templates` | False | **True** | `.gitea/ISSUE_TEMPLATE/` |
  | `has_ci` | False | **True** | `.woodpecker.yaml`, in the root, all along |
  | `has_security_file` | False | False | genuinely absent outside `.github/` |
  | `has_dependabot` | False | False | Forgejo does not run Dependabot |

  And on the real `gitlab-org/gitlab-runner`, which has no `.github/` at all:
  `has_pull_request_template` False → True (`.gitlab/merge_request_templates/`),
  `has_codeowners` False → True (`.gitlab/CODEOWNERS`), `has_renovate` False →
  True (`.gitlab/renovate.json`), and `branch_protection` False → True end to
  end. Its `has_security_file` stays False, because it ships no security policy.

  Every path now lives in one table, `forge_paths.py`, taken from each forge's
  own documentation, and every check consults the whole table. The negative
  findings say where they looked, so a `False` is attributable to somewhere
  rather than implying `.github/` and not saying so.

  **Nothing became an unknown.** Widening a path set only ever turns `False`
  into `True`, and only when a file exists on disk. Two path sets were
  deliberately left GitHub-shaped, because generalising them would have been
  inventing a convention: Dependabot is a service rather than a directory
  layout, so its absence on Forgejo is a real absence of update tooling, and
  `.github/settings.yml` belongs to a GitHub App with no in-tree equivalent
  anywhere else. Both are asserted to stay `False`, against tests that would
  pass if they went quiet.

  This lands independently of any forge adapter — seven of the eight
  repository-derived signals come off a shallow clone with no API — so it
  applies today to GitLab and Bitbucket, which this tool already clones, and to
  repositories on GitHub that simply keep their templates somewhere else.
- **Every repository-derived signal was thrown away over a URL scheme, and the
  loss was then reported as a fact about the package's metadata.** Two defects
  in one path, and the second is the worse one.

  `normalize_clone_url` upgraded `git://` to https — a protocol GitHub switched
  off in 2022 — and refused plain `http://`. A survey of 8,870 packages across
  eight ecosystems found 2.63% declaring their repository over `http://`, more
  than every non-GitHub forge combined and 15.35% of RubyGems, and **114 of
  those 233 rows are on `github.com`**: repositories the tool already supported,
  discarded because a gemspec written before the host had TLS was never
  rewritten. The host allowlist was three strings, so Codeberg, Gitea,
  SourceHut and Gitee were "not a reachable git forge" despite cloning fine.
  `https://WWW.github.com/x/y` was a second identity for one repository, which
  the Go analyzer duly cloned twice. And a URL carrying a credential was
  *accepted*: `netloc.split("@")[-1]` threw the secret away and cloned the
  repository, recording neither.

  Plain `http://` is now upgraded to https and cloned over https — never over
  cleartext, because fetching an artifact through a channel an attacker can
  rewrite in order to score that artifact's supply-chain risk measures the
  attacker. The allowlist covers the six forges verified cloneable with
  `git clone --depth 1 --no-tags`. `www.` comes off the host. A URL carrying a
  credential is refused outright rather than sanitised, and every log line that
  echoes a rejected URL redacts the userinfo first, so the refusal is not what
  writes the token to disk.

  Measured end to end against live registries, with the production analyzers
  and scorer: `python3-openid` and `django-allauth` each go from 7 of 16
  measured signals to 13, `python3-openid` from MEDIUM to HIGH; the same for
  `quick-error` and `gethostname` on crates.io and `coderay`, `compass` and
  `colorize` on RubyGems. Across PyGoat's 34 dependencies, measured coverage
  goes from 92.28% to 94.85% and nothing loses a signal.

- **A package that stated its GitHub repository twice was reported as declaring
  no source repository.** `_declared_source` and `_repository_url` swept
  different key-sets. The resolver read every `project_urls` entry; the
  declaration read a short list of source-ish labels. `python3-openid` labels
  its repository `Download` and `Homepage`, so the resolver saw two candidates,
  failed on the scheme, and the declaration sweep — which had never looked at
  either key — left the state UNDECLARED. The tool then printed "Declares no
  source repository", which is a claim about PyPI's metadata rather than about
  our own resolver, and it was false. Six of the eight ecosystems had the same
  split.

  Each ecosystem now runs one sweep over one key-set in one order, and returns
  both answers as a single frozen `RepositoryResolution` that
  `record_source_repository` takes whole. UNDECLARED is reachable only when
  nothing in the payload named a source: a fallback field naming a host we
  clone from, which still yields no `owner/repo` pair, is UNUSABLE — a
  resolution failure, said as one. A fallback naming a host we cannot clone
  stays UNDECLARED, so hpricot's dead `code.whytheluckystiff.net` homepage is
  still not promoted to a broken repository (#176).

- **The report could not name the dependencies it was describing.** The
  dependency column was the constant 12 cells, so every ecosystem with
  namespaced names rendered only the part they have in common. On gin's
  `go.mod`, 26 of 35 rows read `github.com/…`; the same went for maven
  `group:artifact`, `Microsoft.*` and `androidx.*`. Two dependencies differing
  only after the prefix were indistinguishable, which made the default human
  report unusable for exactly the ecosystems whose names carry the most
  information.

  The column is now sized to the names actually present, floored at the old 12
  so short names render unchanged and capped at 48.

  No terminal-width arithmetic, deliberately, and the first attempt at this was
  wrong for an instructive reason: the other four columns and their separators
  already total 117 cells, so this table has never fitted an 80-column terminal
  and does not fit 100 either. Computing a budget against the terminal and
  redistributing the slack reproduced the truncation exactly, because there was
  no slack — it just arrived via more arithmetic. The table is as wide as the
  names require.


### Removed

- **Two CI steps reported success while doing nothing.** The `security` job
  ended with `echo "Using bandit for security scanning instead"` — bandit is a
  static analyser of our own source and says nothing whatsoever about
  dependencies, so the job's name promised coverage its own output disclaimed.
  Deleted rather than reworded: a build step whose output is a claim about what
  it is not doing is worse than silence. Real dependency scanning is #234.

  The Codecov upload was worse, because it looked like it worked. Every run, on
  all three matrix legs, `Commit creating failed: {"message":"Token required -
  not valid tokenless upload"}` twice — and the step concluded **success**. Six
  errors per run, invisible, since at least 2026-08-02. The repository is not
  registered with Codecov and holds no secrets, so this was never an expired
  token; it had never uploaded anything. Removed rather than repaired: the
  coverage bar that bites is `fail_under = 82.5`, enforced in-process since
  #237. Re-adding it is one block plus a token if the reporting is wanted
  (#249).

  Neither was found by CI going red. Both were found by reading a log that had
  been green for days.


- **`testing/projects/` is gone: 4.4 MB of vendored Flask, Express and Gin that
  no test has ever opened, exempted by name in nine places, costing 35 standing
  Dependabot alerts.** It was described everywhere as the scan corpus — pinned
  old on purpose so the tests would exercise version drift, advisory matching
  and staleness. Nothing referenced it. Not a test, not a fixture loader, not a
  script, not a workflow. The one documented way to use it,
  `testing/projects/README.md`, gave commands against `test-projects/`, a path
  that stopped existing when the testing tree was consolidated. The real corpus
  is `testing/manifests/`, `testing/fixtures/`, and manifest text written to a
  temp file by `testing/conftest.py`; none of it moved, and the suite reports
  the same 1644 passed / 7 skipped at the same 83.64% before and after.

  Being unread did not make it free. It was excluded by name in
  `pyproject.toml` twice (mypy, ruff), in `.flake8`, and in six
  `.pre-commit-config.yaml` hooks — nine exemptions whose only job was to hold
  back a directory nobody read. None of them reached the one place that
  mattered: GitHub's dependency graph, which took the fixtures at face value
  and produced 35 of this repository's 65 noise alerts, plus a Dependabot PR
  every few weeks.

  The claim that its pins were deliberate does not survive the log either.
  Seven merged Dependabot PRs — #8, #10, #12, #13, #14, #15, #16 — already
  bumped these files through 2025 and 2026. The corpus that was too precious to
  update had been updated seven times, silently, by a bot. That it made no
  difference to any test is the whole point: nothing was watching, because
  nothing was reading.

  `git log -- testing/projects` if it is ever wanted back. Cloning upstream at a
  pinned tag would be the better way to want it.

- **`Analyze (go)` was a required merge gate reporting SUCCESS while analysing
  zero lines of Go.** Removed from the CodeQL matrix and from `gate.sh`.

  Every `.go` file this repository has ever contained lived under
  `testing/projects/gin/`, and `paths-ignore: **/testing/**` in
  `.github/codeql/codeql-config.yml` excluded all of them. So the job built a
  database from nothing, found nothing, and passed — for months, as one of the
  seven checks `gate.sh` asserts must be present and green before a merge.

  Deleting the vendored checkout is what surfaced it. With no `.go` file left,
  autobuild reached for the only `go.mod` remaining and found
  `testing/manifests/gin/go.mod`, a two-line parser input:

  ```
  go: error reading go.mod: missing module declaration
  CodeQL could not process any code written in Go
  ```

  That is the same fatal error that got `javascript-typescript` removed from
  this matrix earlier, and the same underlying condition — no first-party source
  in that language — was already true for Go. The difference is only that Go had
  something to trip over and JavaScript did not.

  Predicted before the push and confirmed by the run rather than asserted:
  [actions/runs/30941393388](https://github.com/williamzujkowski/dependency-risk-profiler/actions/runs/30941393388/job/92100361643).
  Add a language back when the repository contains one, and confirm the job
  reports a nonzero line count rather than merely passing.

### Changed

- **`examples/manifests/package-lock.json` declared four versions and hashed
  four different ones.** The `packages` half said express 4.18.2, lodash
  4.17.21, react 18.2.0, axios 1.6.5. The legacy `dependencies` half repeated
  those version strings and then pointed `resolved` and `integrity` at
  express-4.17.1, lodash-4.17.20, react-17.0.2 and axios-0.21.1 — genuine
  tarballs, genuine hashes, wrong releases. `npm ci` against that file installs
  the downgrades and the integrity check passes, because the hashes are correct
  for what they actually name. The fifth hash, `packages/node_modules/axios`,
  matched no tarball at all. A lockfile exists to make exactly this impossible,
  and this one had been shipping as the worked example since 2025.

  Now current — express 5.2.1, lodash 4.18.1, react 19.2.8, axios 1.19.0 — with
  both halves in agreement and all eight integrity values verified by
  downloading the tarball and computing the digest, not by copying them from a
  registry response. That clears the 30 open alerts (27 axios, 3 lodash) this
  file was carrying.

  The directory's stated policy went with them. `examples/manifests/README.md`
  said its manifests were "intentionally outdated" so the profiler would have
  something to find; that was true of one file out of three, by neglect rather
  than design — `requirements.txt` carried current pins and `go.mod` declares no
  dependencies at all. These are documentation. A reader copies them. A tool
  that scores other projects on dependency risk does not get to hand out a
  worked example with 30 open advisories in it, and the profiler has plenty to
  say about a current manifest anyway: staleness, maintainer count, deprecation
  and repository health are scored whether or not an advisory happens to be open
  today.

- **`.github/dependabot.yml` told its reader the trap was disarmed while four
  PRs were sitting in the queue proving otherwise.** The header claimed
  `directory: "/"` enrolled only root manifests and therefore kept the scan
  fixtures out of scope. `directory:` does not scope security updates at all —
  those are a repository setting (`automated-security-fixes` -> `enabled`) that
  reads the entire dependency graph, and no key in this file can subtract a path
  from it. #17, #18 and #19 were opened against the fixtures while this file was
  syntactically invalid and no version update could run; they never needed it.

  Both halves are now written down as observations rather than readings of the
  documentation. `directory: "/"` does not recurse: #195 bumped the aiohttp
  range in the root `pyproject.toml` and left every pip manifest under
  `examples/` and `testing/` alone. Security updates do reach everything: #241
  targeted `testing/projects/flask/requirements`, which no entry in this file
  comes near. The same false exclusion claim was repeated in `SECURITY.md`,
  `docs/security/SECURITY.md` and `docs/security/DEPENDENCY_SECURITY.md` — the
  last of which also named a `/dependabot_check/` directory that has not existed
  for the life of the document — and all four now say what is true: nothing here
  is excluded from Dependabot, and the only way to keep a file out of its way is
  to keep it out of the dependency graph.

  The `npm` and `gomod` entries are removed. There is no `package.json` and no
  `go.mod` at the repository root, so both enrolled nothing and had never once
  produced a PR. They were coverage-shaped and empty. Two more exclusions in
  the same condition went with them: `**/test_projects/**` and
  `**/test-projects/**` in the CodeQL path filter, naming a directory renamed
  years ago, and `dependabot_check/` in six pre-commit hooks, naming one that
  has never existed in this repository at all. Nothing mechanically checks that
  an exclusion points at something real; #252 proposes that it should.
- **A counted advisory now puts a floor under the verdict, because the verdict
  could not otherwise reach the evidence.** The tool printed
  `risk_level: LOW` on the same record where it printed
  `known_vulnerable: true`, and that pairing was not a mis-tuned weight — it
  was arithmetically unreachable. `exploit` carries the largest single weight,
  0.5, but there are sixteen signals whose weights sum to 3.5, so the exploit
  signal's maximum share of the normalized score is `0.5 / 3.5 = 0.143` against
  a LOW/MEDIUM boundary of `0.25`. **A package with a maximal exploit signal
  and a perfect, zero-risk record on all fifteen other signals normalized to
  0.143 and reported LOW.** No advisory load, however severe, could cross the
  first boundary on its own.

  axios 1.6.5 is the case that surfaced it, found by running the tool
  against `examples/manifests/package-lock.json` rather than by reading the
  code: 44 advisories found, **29** confirmed to affect the installed version,
  maximum counted severity HIGH at CVSS 8.0 — and `LOW`. It reached LOW *because it is healthy
  on everything else*: maintained, released last week, no deprecation. Every
  one of those zeros is correct. The verdict built from them was not.

  What this cost a user is specific. The tool spent the requests, counted the
  29, wrote `known_vulnerable: true`, and then guaranteed by construction that
  none of it could matter to the number a CI gate reads. Every other defect
  fixed in this repository made the tool report *less* than it knew; this one
  made it report a reassuring verdict over evidence it was displaying on the
  same line.

  The fix is a floor, not a re-weighting, and the distinction is load-bearing.
  A weighted mean is a **compensatory** model — signals are exchangeable
  evidence about one latent variable, so a good answer anywhere pays for a bad
  answer anywhere else. Known exploitation of the installed version is
  **non-compensatory**: a fact about the present, not a forecast about the
  future. Your lockfile holds 1.6.5, and upstream velocity does not patch it.
  So: **facts set floors; forecasts move within them. Leading indicators may
  raise a verdict above the lagging floor. They may never lower it below.** The
  rule is written into `docs/signals.md` as a general rule rather than as this
  special case, so the next non-linearity has a principle to be tested against
  instead of a precedent to be copied.

  The floor is one rung under the maximum counted severity — `CRITICAL` → at
  least `HIGH`, `HIGH` → at least `MEDIUM` — and the single rung of slack is
  argued rather than assumed: advisory severity is a CVSS base tier assigned
  without environmental context, while the verdict is about the package in
  *this* tree, and reachability of the vulnerable path is something this tool
  does not measure. One rung is what that unmeasured context is worth. Two
  rungs is the verdict ignoring the fact.

  It keys on `counted_vulnerability_count` — the same field `known_vulnerable`
  is computed from, since the whole defect is that those two could contradict
  each other. Advisories the annotator filtered floor nothing: fixed before
  your version (#61), withdrawn, informational, or below
  `--vuln-min-severity`. Inflating a verdict off advisories that do not affect
  the installed version would be the same defect pointing the other way.

  `risk_score` is untouched. axios still scores 1.1364 of 5, still 0.2273
  normalized, still inside LOW's boundary; only the verdict moves. Every
  component score is asserted at its pre-change value in
  `testing/unit/test_verdict_floor.py`, which is what distinguishes this from a
  re-weighting from the outside. **Corpus movement is zero: 805 scored records
  across nine ecosystems in the test corpus, and eleven across the example
  manifests, all unchanged in verdict and in score.** The per-ecosystem
  measured-signal floors in #131 do not move, and neither does anything #239
  re-baselined.

  Zero, rather than the one movement this started out with, because #253
  upgraded the example manifests to current releases hours before this landed.
  axios 1.19.0 finds the same 44 advisories and counts **none** of them, which
  is the negative case holding on live data. The recording in
  `testing/fixtures/axios_1_6_5.json` is now the only place the defect
  reproduces, and it is captured rather than authored for exactly that reason:
  a regression whose only witness is a manifest somebody upgrades is a
  regression that comes back.

  Re-weighting was considered and rejected on arithmetic: crossing 0.25 alone
  needs `w >= 1.0`, tripling the largest weight, which moves every score in the
  corpus and *still* leaves a compensatory model that dilutes at higher
  thresholds. Maximum blast radius, and it does not fix the mechanism.

  Note for CI gates: `--fail-on medium` and above can now trip on a package
  whose leading indicators are clean. That is the intended behaviour.
  `UNKNOWN` verdicts are deliberately left alone — an abstention is not a
  reassuring verdict, and the contract states that `insufficient_data: true`
  implies `risk_level: UNKNOWN`, so moving it would be a schema-semantics
  break rather than an additive change. #248 tracks that gap.
- **`test_scoring_performance_sla` measured the machine, not the scorer, and
  now measures the scorer.** It timed 100 unwarmed calls and asserted on the
  single worst sample against a 5ms bar. Adding an unrelated 70 KB fixture
  elsewhere in the suite flipped it between pass and fail — four failures in
  eight full-suite runs, at 23-27ms — while the *average* over the same 100
  samples stayed under 1ms and a microbenchmark showed the scoring path
  unchanged at 17.9 µs per dependency against 18.5 µs on the parent commit. A
  two-order-of-magnitude single sample is a GC pause or a scheduler
  preemption, not scoring work.

  Repaired the way its sibling `test_project_profile_performance_sla` already
  was, and for the same stated reason: warm up, then take the median of three
  batches. A real algorithmic regression shows in every batch; a hiccup shows
  in one. Verified to still bite — 2.5ms of real work added to
  `score_dependency` fails it at `Average scoring time 2.825ms exceeds SLA of
  1ms`. The thresholds are unchanged; what changed is what the number means.
  AGENTS.md says a check that fires on legitimate work is a bug in the check.
- **The `aiohttp` cap in the dev extra was tested instead of trusted, and it
  survived.** `"aiohttp>=3.8.6,<3.14",  # Keep aioresponses mocks compatible in
  tests` is holding 14 open advisories — 1 high, 8 medium, 5 low — in this
  project's own committed lockfile, and after #239 it is the only thing left in
  there. Dependabot PR #195 proposed raising the ceiling to `<3.15`, which
  admits the patched 3.14.3 and clears all fourteen. #240 asked the prior
  question: is the comment still true, or merely inherited?

  It is true. Cap lifted, `uv lock --upgrade-package aiohttp` (3.13.5 ->
  3.14.3), `uv sync --extra dev`, full suite: **8 failures.** aiohttp 3.14.0
  made `stream_writer` a required keyword-only argument of
  `ClientResponse.__init__`, and `aioresponses` builds every mock response by
  calling that constructor directly with a hardcoded kwarg set. The client under
  test catches `Exception` and returns `None`, so the breakage arrives as
  `assert None == {'message': 'success'}` and never as the `TypeError` it
  actually is. The boundary is exact — 3.13.5 green, 3.14.0 fails — so `<3.14`
  is precisely right rather than defensively round. #195 is closed: `<3.15`
  admits exactly the versions that break.

  The near-miss worth recording is the shape of the partial pass. Nine of the
  seventeen tests in `test_async_http.py` pass under aiohttp 3.14, and all of
  `test_aggregator_async.py` does, because injected exceptions and 4xx paths
  return before that constructor is ever reached. Check a subset, or check that
  the import works, and the evidence says the cap can go.

  `aioresponses` 0.7.9 is the latest release, postdates aiohttp 3.14.0 by three
  weeks, and declares `aiohttp<4.0,>=3.8` — it advertises support for a version
  it cannot run against, and the upstream fix is open and unreleased
  (pnuckowski/aioresponses#288). The resolver will assemble that broken
  environment on request. This cap is the only thing that stops it.

  So the cap stays and the comment stops asking the next reader to take it on
  faith: it now names the constructor, the version boundary, the date, the
  `aioresponses` version it was measured against, the fourteen advisories it
  costs, and #244 — which removes the *coupling* rather than the cap, and is
  the only thing that can get this lockfile to zero. Nothing about the runtime
  dependency changed; `aiohttp>=3.8.6` in `[project] dependencies` has no
  ceiling, so no consumer of the published package was ever held back. What is
  held back is every contributor's `uv sync` and every CI run.

  Recorded plainly: a comment that turns out to be accurate is the *unusual*
  outcome in this repository, and it is only known to be accurate because
  someone lifted the cap and watched eight tests fail. The next person to
  suspect this line should do the same rather than believe this paragraph.
- **BREAKING CHANGE: Python 3.9 is no longer supported; `requires-python` is
  now `>=3.10`.** The floor was not a style preference. It was putting 47 known
  advisories — 20 high, 23 medium, 4 low — into this project's own committed
  lockfile, and `uv lock --upgrade` could not remove a single one of them.

  The mechanism is worth stating exactly, because the symptom pointed nowhere
  near the cause. `requires-python = ">=3.9"` makes uv *fork* the resolution and
  carry a second, older pin for the 3.9 leg:

  ```
  { name = "cryptography", version = "47.0.0", marker = "python_full_version <= '3.9'" }
  { name = "cryptography", version = "50.0.0", marker = "python_full_version >  '3.9'" }
  ```

  Everyone on 3.10 or newer was already getting the patched version. The
  vulnerable pins existed solely to serve an interpreter that has received no
  security patches of its own since October 2025, and that no upstream still
  supports: urllib3 2.7.0, pillow 12.3.0 and requests 2.33.0 all declare
  `>=3.10`, and cryptography 50.0.0 excludes 3.9.0 and 3.9.1 outright. The
  project could not have obtained patched versions on 3.9 even in principle.

  Changing that one line and relocking: cryptography 47.0.0 -> 50.0.0, pillow
  11.3.0 -> 12.3.0, requests 2.32.5 -> 2.34.2, urllib3 2.6.3 -> 2.7.0, filelock
  3.19.1 -> 3.32.2. The lockfile drops from **153 resolved packages to 114** —
  39 existed only to serve the fork — and no `python_full_version <= '3.9'`
  marker remains. The `test (3.9)` CI job, which installed the vulnerable set on
  every run, is gone with it.

  Decided by consensus vote, 7-0, and the download data was gathered rather than
  assumed: of 223 sampled PyPI downloads, **zero** were Python 3.9 (88.8%
  reported no version, the remainder 3.11, 3.12 and 3.14). The panel's stated
  threshold for keeping the floor was 5%.

  Two things deliberately not done. `[tool.uv.environments]` would have
  collapsed the fork without touching `requires-python`, and was rejected on
  purpose: it removes the 3.9 lock and the 3.9 test job while leaving the
  package metadata still *advertising* 3.9. Untested-but-advertised support for
  an EOL interpreter is worse than honest removal. And `aiohttp` stays at
  3.13.5 with 14 open advisories, because the `<3.14` cap in the dev extra is a
  separate cause with a separate fix (#195) — one relock diff, one reason.

  Consumers still on 3.9 keep every release published to date; pip resolves them
  to the last compatible version. That is the ordinary Python deprecation path.

  Noted without flinching: a tool whose thesis is that an end-of-life runtime
  floor is a *leading* indicator of dependency risk had one, and it produced 47
  lagging advisories. The thesis held. The repository was the counterexample.

### Added

- **`verdict_floor` on every `ScoredDependency`, saying whether a fact or a
  forecast set `risk_level`.** Additive to schema 2 — no key renamed, none
  removed, so no consumer breaks — and required rather than decorative: a
  verdict alone cannot tell a reader which of two mechanisms produced it, and a
  test that can only assert the outcome cannot catch an expectation that starts
  passing for the wrong reason. The block carries `applied`, the
  `max_counted_severity` and the `advisory_id` that carried it, the `floor`
  itself, and the `from` / `to` transition. Every key is always present, so a
  consumer reads `applied` instead of inferring state from which key is null —
  the same shape `signals` uses. `applied: false` with a non-null `floor` is
  the informative middle case: the floor was computed and the leading
  indicators had already carried the verdict past it (#242).
- **NuGet collects `<GlobalPackageReference>` packages, which appear in no
  project file at all.** Central Package Management lets a
  `Directory.Packages.props` apply a package to *every* project under it
  without any `<PackageReference>` in the `.csproj`. Dapper does this with
  ReferenceTrimmer; the convention is analyzers, source-link and versioning
  tools. They run during the build, which is exactly the supply-chain position
  this tool exists to examine, and they were invisible to the scanner while
  every count stayed green.

  Each is marked `build_dependency` in `DependencyMetadata.additional_info` —
  the same key `parsers/toml.py` already writes for pyproject's
  `build-system.requires`, rather than a new spelling for one ecosystem. The
  marker stops at the Python API: the unified `ScoredDependency` has no field
  for a dependency's kind or scope, and `additional_info` reaches neither
  reporter, so nothing here changes the JSON contract. Adding such a field
  concerns all nine ecosystems and belongs in its own issue.

  One #129 property is gone deliberately: a fully inline-pinned project used to
  read no file but its own manifest. A global package is a dependency of the
  pinned projects too, and there is no way to know one is there without
  reading the props file, so the lookup now always runs. Resolved versions for
  pinned and centrally-managed projects are unchanged.
- **A bar and its violation shipped in the same commit, and now they cannot.**
  AGENTS.md rule 7 said "Never commit `uv.lock`". The commit that introduced
  that rule committed `uv.lock`. Nothing noticed, because nothing was looking —
  the rule was a sentence in a file, and this repository has now produced four
  of those: the `Any` ban that `disallow_any_explicit` never enforced, a 90%
  coverage bar spelled with a pytest option that does not exist, this, and the
  one below.

  Put to a consensus vote rather than settled by preference, because the
  library-versus-application question is genuinely contested. It came back 7-0
  the other way, on a point that survives scrutiny: `uv.lock` is not packaged
  into the wheel or the sdist, so it constrains no consumer of this library and
  the entire lockfiles-in-libraries argument is about consumers. What it
  constrains is a contributor's `uv sync`. A tool whose thesis is that unpinned
  dependencies are a leading risk indicator does not get to except itself.

  The rule now says commit it, and says the opposite of what would be
  convenient: **the lockfile is not load-bearing in CI.** CI installs with
  `pip install -e ".[dev]"` and does not invoke `uv` anywhere, so the committed
  lockfile pins the contributor environment and nothing else. Six of the seven
  voters cited reproducible CI as a reason to keep it; that reason is not true
  today, and writing it down as though it were would have made this the fifth
  instance instead of the fix for the third. The contrarian voter flagged the
  install flag as a condition rather than an assumption, which is the only
  reason it was checked.

  What landed is the half that is completely correct: `uv lock --check` now runs
  in CI, so the lockfile cannot drift out of agreement with `pyproject.toml` —
  the case where someone edits a dependency and never relocks. Making the
  install itself consume the lockfile is #232, split out rather than stubbed
  because CI installs across a 3.9–3.12 matrix and a single locked resolution is
  not automatically installable on all four. Replacing a decorative lockfile
  with a red matrix is a worse trade than the status quo.

  Both gates were verified by observing them fail. Untracking `uv.lock` fails
  the new check in `test_repository_rules.py`; adding a dependency to
  `pyproject.toml` without relocking exits `uv lock --check` with status 2.

- **Four more ecosystems measure transitive dependencies, and the fifth says
  why it cannot.** nodejs, python, cargo and rubygems never populated
  `transitive_dependencies` at all. Since the fail-closed read landed, that
  read as *unmeasured* rather than as a fabricated `0.0` — honest, but blind on
  a signal three ecosystems already measured, so a Java artifact and an npm
  package with identical risk profiles scored differently purely because one
  adapter read a field.

  Each now reads its registry's own statement of what installing the package
  pulls in, and each draws the runtime line the way its registry draws it:
  nodejs from `versions[<latest>].dependencies` (not `devDependencies`,
  `peerDependencies` or `optionalDependencies`), python from
  `info.requires_dist` (not the `extra ==` entries), rubygems from
  `dependencies.runtime` (not `development`), and cargo from the per-version
  dependencies endpoint filtered to `kind: "normal"` (not `dev` or `build`).
  Three of the four cost no extra request — the data was already in a payload
  the adapter fetched. cargo costs one: the crate document carries only a
  pointer, so its request count per crate goes from two to three, taken for the
  same reason the adapter already spends a request on the owner count.

  golang abstains, and records UNMEASURED positively rather than staying
  silent. `go.mod` states no dependency scope: `go mod tidy` writes a module's
  test-only requirements into the same direct `require` block as its runtime
  ones — logrus requires `testify` beside `golang.org/x/sys` — so counting the
  block would over-report Go modules systematically, which is the opposite of
  the like-for-like comparison this change exists to restore.

  Two absences are kept distinguishable throughout: a payload that declares no
  dependencies is a measured zero, a payload that declares nothing readable is
  not. PyPI's `requires_dist: null` is the sharp case and is read as unmeasured
  — `carbon` and `graphite-web` both report null and both declare real
  `install_requires`, so null means "PyPI cannot tell you" rather than "none".

- **Schema v2 carries `field_sources`: which acquisition path wrote each field
  that has more than one.** `star_count` is written from a regex over
  unauthenticated github.com HTML *and* from `stargazers_count` on the
  authenticated REST API — in an org scan both run, for the same dependency, in
  that order — into one unlabelled integer, so two very different trust levels
  arrived indistinguishable. Seven fields collapse two or more paths this way:
  `star_count`, `contributor_count`, `maintainer_count`, `commit_frequency`,
  `has_tests`, `has_ci` and `last_updated`.

  Sources are sanitized logical locators from a closed vocabulary —
  `registry:release`, `clone:git-history`, `github:api/repository`,
  `github:html` — and never carry a host, a URL, a query string, a token or a
  filesystem path. A key is absent when nobody recorded a source, which is not
  the same as a source of "unknown".

  Additive: v2 gains a key and `--schema v1` output is unchanged, verified byte
  for byte against the previous release rather than assumed. Scope is derived
  rather than declared — `testing/unit/test_field_provenance.py` walks `src/`
  for write sites and fails when the source tree and the enumerated set
  disagree — and the cost was benchmarked against a budget stated first, with
  the numbers and the two budget lines that were mis-set written up in
  `docs/signals.md`.

### Changed

- **Risk scores move for npm, PyPI, RubyGems and crates.io packages.** A signal
  going from unmeasured to measured re-enters both the numerator and the
  denominator, so every dependency in those four ecosystems is rescored. Some
  cross a verdict boundary in the process: `express` and `request` were UNKNOWN
  purely because npm sat one signal short of the insufficient-data bar and are
  now LOW and MEDIUM, `flask` moves UNKNOWN -> LOW, and `hpricot` moves MEDIUM
  -> LOW on a measured zero.

  The per-ecosystem measured-signal floors are re-baselined upward to the new
  measured value: cargo 8 -> 9, nodejs 7 -> 8, python 8 -> 9, rubygems 8 -> 9.
  maven, gradle, nuget, composer and golang are unchanged. `nodejs` is the last
  entry to leave `SCORES_FROM_REGISTRY_ALONE = False`: npm still publishes no
  cheap maintainer count, and it clears the bar by exactly nothing — eight
  measured against eight unmeasured — so losing any one signal returns every
  npm package to UNKNOWN. golang is now the only ecosystem that cannot reach a
  verdict from registry metadata alone.

- **BREAKING CHANGE: `analyze --output json` and `scan-org` now emit one
  `ScoredDependency` shape (schema v2).** Both commands described the same
  concept and agreed on 5 keys out of ~21; the rest were silent renames of
  identical data — `installed_version`/`version`, `scores`/`component_scores`,
  `has_known_exploits`/`known_vulnerable`, `vulnerabilities`/`advisories`,
  `advisories`/`details` — so a consumer of the documented agent workflow had
  to write two parsers for one concept. Both paths now serialize from
  `dependency_risk_profiler.contract.scored_dependency`, and every document
  declares `schema_version` on its envelope.

  Org-only concepts (`blast_radius`, `usage`, `version_specs`, `remediation`)
  moved under a declared `extensions.org_scan` block. An extension may add
  keys; it may never rename or shadow a shared field.

  **`--schema v1` selects the previous pair of shapes, byte for byte**, on
  `analyze`, `scan-org` and `scan-user`. It is deprecated and **removed in
  1.0.0**. The deprecation notice goes to stderr, so stdout stays parseable.
  The v1 writers are frozen in `cli/json_v1.py` and `org_scan/report_v1.py`
  and are self-contained; they are not kept in sync with v2.

  Fixed in the process, because a mechanical rename would have preserved them:

  - **`analyze -o json` computed licence and community data on every run and
    never serialized it.** It emitted `scores.license_score` while withholding
    which licence produced it. Schema v2 emits `license` and `community` blocks
    on both paths.
  - **The advisory list was emitted twice** in `analyze`, under
    `vulnerability_summary.advisories` and again under `vulnerabilities`. It
    now appears exactly once, at `advisories.details`.
  - **`scan-org` dropped `applicability_unknown_count` /
    `applicability_unknown_reasons`**, collapsing "no applicable advisories"
    into "we could not tell whether these apply". Both survive on both paths.

- **BREAKING CHANGE: an unmeasured signal is now structurally distinct from a
  measured zero in the output.** The two-state `Measurement` stopped at the
  scorer; both writers flattened it to a bare `null`, which a consumer cannot
  tell from "measured, and the answer happens to be null". Schema v2 replaces
  `scores` / `component_scores` with `signals`, where each entry is
  `{"state": "measured", "value": …}` or `{"state": "unmeasured", "reason": …}`
  — so a consumer can tell not only *that* a signal is missing but *why*.

- **BREAKING CHANGE: `remediation` is a structured block, not a sentence.**
  `{action, fix_versions, target_version, detail}` with an enumerated action
  (`upgrade_to_fixed_version`, `upgrade_to_latest`, `replace`, `no_action`,
  `unclassified`) so an agent branches on a value instead of regexing prose.
  `unclassified` is the escape variant: an unclassifiable case is reported as
  such rather than force-fitted into a neighbouring action. `fix_versions` and
  `target_version` are treated as untrusted registry data — anything that could
  not be a version is refused rather than published.

  The CSV report's `remediation` column is now that same block rendered as one
  sentence, rather than a second precedence chain over the same facts. Two
  independent descriptions of one dependency can disagree, and this pair did
  worse than drift: the prose path printed raw registry version strings that
  the structured path had already refused as unsafe to publish. The wording of
  the column changes as a result — it names the action and the version facts
  the structure carries, and is blank for `no_action`.

### Fixed

- **The tool told you a package with known malware in it was clean.** An
  advisory the range matcher had itself decided applied to the installed
  version — `version_match: "affected"` — was then discarded from the score for
  carrying no severity label, under the silent filter reason `unknown severity`.
  A malicious-package advisory will never carry a CVSS, because CVSS scores a
  vulnerability *in* software and there is nothing to score when the software
  **is** the attack, so `MAL-*` records were dropped every time. So were whole
  databases: `GO-*` (0 of 42 records sampled publish a severity) and `RUSTSEC-*`
  (0 of 14). Two ecosystems' native advisory sources were therefore silent.

  `golang.org/x/net v0.55.0` reported `known_vulnerable: false`,
  `counted_in_score: 0` and `0 scored` in the terminal while holding
  GO-2026-5942 matched as affected. `anyhow 1.0.75` likewise, with
  RUSTSEC-2026-0190. No flag recovered them:
  `--minimum-vulnerability-severity INFO` changed nothing, because the filter
  reason was not the threshold.

  **An advisory with no published severity is now counted, and says so.** It is
  neither an advisory of severity zero nor an advisory of unknown
  applicability — applicability was decided, and the answer was *affected*. It
  gets the two-state treatment `applicability_unknown` already had one field
  over: `advisories.severity_unknown` and `severity_unknown_reasons`, which
  distinguish "the source published no severity" from "the value in this record
  is not a severity". `UNKNOWN` is deliberately **absent** from `SEVERITY_ORDER`,
  so nothing can order it against a real tier — that is the by-construction half
  of "unmeasured is not measured-zero", and `max_counted_severity` stays null
  rather than holding a word that looks like a tier.

  **`--minimum-vulnerability-severity` cannot reach these advisories at any
  threshold**, and that is now documented rather than incidental. The threshold
  compares against a severity an advisory *states*; filtering the ones that
  state none would be this bug behind a flag.

  **Malicious-package advisories get their own tier, `MALICIOUS`, ranked above
  `CRITICAL`.** Their missing severity is categorical, not a gap, so folding
  them into the unknown bucket would say the tool could not tell how bad it was
  — the one thing it can tell. `MALICIOUS` floors the verdict at `CRITICAL`
  with no one-rung discount: that rung of slack is paid for by reachability,
  which this tool does not measure and malware does not depend on. It does not
  invent a CVSS to go with the tier; `max_counted_cvss_score` stays null unless
  a real one was published.

  **A counted advisory of unknown severity floors nothing, and that is argued
  rather than left to fall out.** The honest floor would be `LOW`, and `LOW`
  floors at `LOW` — the bottom of the scale — so it would forbid nothing.
  Returning no floor keeps `verdict_floor.applied` meaning what it says. The
  protection is that the advisory is counted: `known_vulnerable` is true, the
  `N scored` column is non-zero, and the `exploit` signal carries a non-zero
  floor instead of the `0.0` a package with no advisories at all scores — at
  the tool's highest-weighted signal, that zero was the last place the silence
  could hide.

- **One vulnerability was counted once per advisory record describing it, so
  `lodash 4.17.15` reported six advisories for four vulnerabilities.**
  Advisories were deduplicated by exact `id`. OSV re-scopes an advisory by
  publishing a *second* record with narrower wording and listing each in the
  other's `aliases` — `GHSA-35jh-r3h4-6jhm` and `GHSA-r5fr-rjxr-66jc` are both
  CVE-2021-23337, `GHSA-f23m-r3pf-42rh` and `GHSA-xxjr-mmjv-4gpg` are both
  CVE-2025-13465 — and the `aliases` field was never read, so both halves of
  each pair survived filtering and both were counted. Everything downstream
  inherited the inflation: `counted_in_score`, the `N scored` column, the
  `Known security issues (N counted, ...)` risk factor, and the #242 verdict
  floor. `npm-user-validate 0.1.5` counted CVE-2020-7754 **twice, at two
  different severities**, HIGH and LOW.

  Records are now grouped by the transitive closure of `id` and `aliases`, so
  two records that both name one CVE and never name each other still collapse —
  which is exactly lodash's shape. `related` is deliberately not part of the
  closure: OSV defines it as connected-but-distinct, and merging on it would
  drop real findings.

  Every field that can filter an advisory out is merged in the direction that
  keeps it in, because collapsing two records must never lose what either
  carried. The severity, CVSS and raw severity string come as a set from the
  record stating the worst of them, so `npm-user-validate` keeps HIGH rather
  than whichever of HIGH and LOW sorts first. `withdrawn` is true only if
  *every* record is withdrawn. Ranges are unioned, and a group in which any
  record carries no range data at all collapses to no range data, so the
  advisory stays counted with `applicability_unknown` rather than being filtered
  by a sibling's ranges. The surviving record is the lexicographically first ID
  in its group — matching `_worst_counted_advisory_id`'s existing tie-break, so
  the ID a report names does not depend on which source answered first — and it
  carries every collapsed ID in its own `aliases`, so nothing disappears
  unfindably.

  The advisory cache schema goes to **5**. A version-4 entry has no `aliases` to
  group on and still holds one record per advisory, so without the bump every
  inflated count already on disk would go on being served, as a measurement,
  for the rest of its 24-hour TTL.

- **`overall_risk_score` averaged in the dependencies it could not measure as
  `0.0`, so a manifest scored better the less the tool managed to learn about
  it.** One manifest, `PyYAML==5.1`, scored **2.46**. The same manifest with
  four names that do not exist on PyPI appended scored **0.49** — an 80%
  improvement bought entirely with ignorance, on the first line of the terminal
  report and the sort key of `Manifest files by risk score`.

  An unresolvable dependency carries `total_score = 0.0` and
  `insufficient_data: true`. The project mean divided by every dependency
  including those, so each package the scan failed to resolve pulled the
  headline number one notch toward "safe". The report *disclosed* the ignorance
  — `4 dependencies had insufficient data to score` sat two lines below — but
  disclosure next to a number the same fact has already improved is worse than
  silence: anyone gating on a threshold, sorting manifests, or watching the
  score over time was reading a number whose gradient points the wrong way. The
  realistic trigger is not fake package names. It is a private index, a
  rate-limited token, or an offline run: the score collapses toward zero
  exactly when the scan is least trustworthy.

  This is #74's rule one layer up. Inside a single dependency's score an
  unmeasured signal already leaves **both** the numerator and the denominator,
  which is why `measured_signal_count` / `total_signal_count` exist. The mean
  across dependencies now does the same, and `null` — not `0.0` — is what a
  manifest reports when nothing in it could be scored. That state was already
  in the contract for a manifest with no dependencies at all; a manifest of
  five unresolvable packages simply never reached it. `0.0` keeps its one
  honest meaning: dependencies were scored, and their mean was zero.

  **A mean over part of a set is published with its denominator, additively.**
  `scored_dependency_count` is new on the analyze envelope and on each entry of
  `manifests[]` and `riskiest_repositories[]`, beside the `dependency_count`
  that gives it a population. The terminal line says it too: `overall 2.5 / 5.0
  across 1 of 5 scored`, or `overall not scored · 0 of 5 dependencies could be
  scored`. It is derivable — `dependency_count` minus
  `insufficient_data_dependencies` — and published anyway, on the precedent of
  `measured_signal_count` one layer down, because the denominator of a
  published mean is part of the measurement rather than a convenience.

  **Every sibling aggregate was checked, and three more had it.** A directory
  run's merged mean weighted each manifest by its *dependency* count while the
  per-manifest means were over *scored* dependencies, which would have let one
  measured package in a manifest of five out-vote a fully-measured manifest
  beside it. `scan-org`'s per-repository `average_risk_score` averaged
  unscorable dependencies in the same way, and is now `null` when a repository
  yielded none — it is also the fourth sort key of `riskiest_repositories`, so
  an unmeasured repository was being ranked as a quiet one. The historical
  trend mean now drops scans that scored nothing rather than averaging them in
  as zeros, which is the one place a failed scan would read as an improvement.
  `risk_points`, the high-risk counts and `known_vulnerable_dependency_count`
  were checked and are sound: they are sums and counts, and an unmeasured
  dependency contributing nothing to a sum cannot lower it.

  `ProjectRiskProfile.overall_risk_score` is now derived from `dependencies`
  rather than stored beside them, so the mean cannot be set independently of
  what it is a mean of. It could be before, and was — by a test that computed
  the average itself, passed it to the constructor, and asserted it came back
  out.

  **`--schema v1` inherits the corrected number.** The frozen writers guarantee
  a *shape*, which is what a v1 parser is written against, and this key was
  already `number | null` there. The freeze is not a licence to keep
  publishing, under a still-selectable flag, a project score that improves
  every time the scan fails to resolve a package. v1 does not gain
  `scored_dependency_count`; that is a shape change and belongs to v2.

  Across the existing manifest corpus, every score that moved moved by exactly
  `total / scored` and no dependency's own score moved at all: `large` 0.0086 →
  1.7230 (1 of 200 scorable), `maven/parent-managed` 0.4604 → 1.3813 (2 of 6),
  `nuget/central-managed` 1.3124 → 1.4317 (11 of 12), `maven/bom-import` 0.0 →
  `null` (0 of 6). The seven fully-measured manifests are unchanged to the last
  digit.

- **A git tree GitHub truncated was reported as `coverage: read`, which claims
  the scan saw all of it.** GitHub caps the recursive tree response and sets
  `"truncated": true` when it does. `GitHubOrgClient.list_manifest_paths`
  noticed, wrote a `logger.warning`, and returned the partial listing as though
  it were complete. Nothing downstream knew: whatever manifests happened to
  fall inside the returned prefix were read, scored, and reported under a state
  #262 defines as "every recognized manifest was fetched and parsed, so a zero
  here is a real zero".

  Reproduced on `torvalds/linux`, which returns 71,798 entries with
  `truncated: true`. Before: `coverage: read`, three dependencies, and
  `"warnings": []` — the truncation existed only in a log line nobody reads
  after a scan. After: `coverage: partially_listed`, the reason in `warnings`,
  a `partially_listed_repository_count` key in the JSON, and a headline that
  says `1 repo listed only in part`.

  `RepositoryManifestListing` now carries `truncated` as a required,
  undefaulted field, so a client cannot answer "here is what I found" without
  answering "did I see all of it".

  **`partially_listed` is a new state rather than a reuse of
  `partially_read`,** and the difference is what a consumer can do next.
  `partially_read` names every manifest it did not read, in
  `unreadable_manifests[]`, each with a remedy — generate the lock file and the
  gap closes. A truncated tree's unread manifests have no names, because they
  were never listed, and no command produces them. It is not even the same
  shape: a truncated repository may have read every manifest it was shown, so
  "at least one read and at least one not" is not true of it.

  It outranks every state but `discovery_failed`, so "this repository's
  dependency list is a prefix" is one comparison for a consumer rather than a
  conjunction. Nothing is lost to that ranking: `unreadable_manifests[]` and
  `parse_failures[]` still carry every per-manifest fact the prefix contained.
  `discovery_failed` still wins, because knowing nothing is worse than knowing
  part.

  **Paginating the tree was considered and not built.** GitHub's Contents API
  lists one directory per request, so walking a repository that truncates at
  ~100k entries costs thousands of requests against a 5000/hour budget — for a
  repository whose manifests are, in the observed case, two files. Reporting
  the truncation honestly is the right stopping point, and it is one the
  operator can act on with `--manifest-glob` or a targeted `analyze`. Building
  the pagination would need its own measurement, which is why this change does
  not guess at it.

- **`scan-org` never fetched a `.csproj`, so every .NET repository in an
  account was reported as holding no dependency manifests at all.** The org
  scanner decided what to fetch from `SUPPORTED_MANIFEST_NAMES`, a tuple of
  thirteen exact file names kept beside the parser registry it was meant to
  mirror. The registry expresses NuGet's primary manifest as an *extension*
  matcher, `*.csproj`, and an exact-name tuple has no way to hold one. So the
  file was never matched, never fetched, and never scored, while `analyze` read
  the same file without complaint.

  After #262 gave every repository a coverage state, that silence acquired a
  name — the wrong one. A .NET project came back as `no_manifests`, which
  #262 defines as "the tree listed and holds no manifest this tool recognizes".
  That is a stronger and falser claim than the `unreadable` state the same
  release added: `unreadable` says "I saw something I could not read";
  `no_manifests` says there was nothing there.

  Measured before and after on real public accounts, counting every GitHub
  request the discovery pass made:

  | account | tree listings | manifest fetches | coverage |
  |---|---|---|---|
  | `ghostvectoracademy` before | 1 | 0 | `no_manifests` |
  | `ghostvectoracademy` after | 1 | 1 | `read` (5 dependencies) |
  | `virtualglobebook` before | 2 | 0 | `unreadable` |
  | `virtualglobebook` after | 2 | 42 | `partially_read` |

  Tree listings are unchanged, which is the claim worth checking: matching is
  done over the recursive tree the scan already paid for, so the only new
  requests are fetches of manifests that are really there.
  `virtualglobebook/OpenGlobe` is a 42-project solution that also carries three
  `.vbproj` files the tool does not read, so `partially_read` is the honest
  answer for it and `unreadable` — its state before, when the only NuGet files
  the scan could see were the three it cannot read — was not.

  **The fix is not a second list, and not a test asserting two lists agree.**
  `SUPPORTED_MANIFEST_NAMES` is deleted. `GitHubOrgClient.list_manifest_paths`
  now asks `EcosystemRegistry.match_ecosystem_by_path()`, which runs the same
  matchers `detect_ecosystem` runs for a local file, minus the ones that need
  bytes. Two lists is what produced this defect, and a test that they agree
  would still leave two lists.

  Deriving a glob list from the registry's published `get_ecosystem_details()`
  labels would have been worse than the tuple. That API renders npm's second
  matcher as `File extension: .json` and Python's as `File extension: .txt`,
  and drops the qualifying function that restricts them to `package-lock` and
  `requirements` — so a scan built from those labels would fetch every JSON and
  text file in every repository in the account. The registry has to *decide*;
  it cannot be asked for a list to copy.

  No cap on a large solution. A cap that stops after N projects reports a
  prefix while claiming `coverage: read`, which is #262 rebuilt; `OpenGlobe`'s
  42 fetches are 42 requests out of an authenticated hourly budget of 5000, and
  an operator who wants less can say so with `--manifest-glob`. That option now
  defaults to no narrowing at all rather than to the deleted tuple, so it only
  ever subtracts from what the registry recognizes.

- **`scan-org` counted a repository it could not read as a repository with
  nothing in it.** The tree listing was filtered against the manifest names the
  parsers accept *before* anything was fetched, so a repository whose only
  manifests were `package.json` and `pnpm-lock.yaml` matched nothing, was never
  fetched, and never reached `parse_failures` — which only records manifests
  that were fetched and then refused. It still appeared in the report, with
  `dependency_count: 0`, zero risk points and `worst: none`, which is
  byte-for-byte what a repository that genuinely declares no dependencies looks
  like. On a real account: two of four repositories read that way, and nothing
  in the output distinguished them from the one that holds no manifests at all.

  This is the #243 defect on the org path, and the blast radius is larger. An
  org scan is exactly where nobody is watching any individual repository, so a
  repository missing from the numbers is a repository nobody notices is
  missing.

  Four outcomes now have four names instead of one shared zero. Every
  repository carries a `coverage` state: `read` (a zero here is a real zero),
  `partially_read` (one ecosystem read, another not, so the count is a floor),
  `unreadable` (dependency manifests found, none readable), `no_manifests` (the
  tree listed and holds nothing this tool knows), and `discovery_failed` (the
  tree never came back, so nothing at all is known). `unreadable_manifests[]`
  carries every recognized-and-unread manifest with its repository, ecosystem
  and next step, using the same field names `analyze` emits so one consumer
  parses both paths. Both are required, undefaulted arguments to the models, so
  the reassuring shape cannot be produced by forgetting to fill them in. The
  headline states the repository count beside `unscored_dependency_count`,
  in the same register: "2 repos could not be read".

  **Discovery failures were being built and then dropped on the floor.** Found
  while fixing the above: `_discover_manifests` appended each failed tree
  listing to a local list, logged a count, and returned only the manifests, so
  `OrgScanReport.warnings` was empty on every scan the scanner ever produced. A
  repository GitHub refused left no trace in the report at all. It now reaches
  `warnings` and gets its own coverage state, because "I could not fetch it" is
  a third fact and must not be folded into "I could not read it".

  **It costs no additional requests.** Recognition is by file name against the
  recursive tree listing the scan already paid for; the unreadable half is
  never fetched. Measured on a four-repository account, before and after: seven
  discovery requests either way, four tree listings and three manifest fetches,
  the same three paths.

  An account whose repositories are all unreadable now exits 1, the same rule
  `analyze` got in #264. An account that genuinely declares no dependencies
  still exits 0 — that is a measurement. `--fail-on` is deliberately untouched:
  it answers "is the risk you found above my threshold", which is a different
  question from "did you find anything at all", and wiring coverage into it
  would make a threshold gate fire on a scan that never got far enough to have
  a risk level.

  Nothing changed about which manifests the parsers accept, which files get
  fetched, or which dependencies get scored. Detection, reporting and exit
  semantics only.

- **`analyze <dir>` over a project it could not read reported zero dependencies
  and exited 0.** Point it at an npm project — a `package.json`, no lock file —
  and it printed "No supported manifest files found", a catalogue of the ten
  ecosystems it does support, a JSON document with `dependency_count: 0` and
  `dependencies: []`, and exit code 0. A CI job branching on that exit code
  recorded a clean scan. A person reading it concluded there was nothing to
  worry about. Both were reading a reassuring answer produced from an absence
  of measurement, which is the same defect as scoring an unmeasured signal
  `0.0` — one level up, on the input rather than the signal (#243).

  A scan that read nothing is now structurally distinct from a scan that found
  nothing, in three places at once. `unreadable_manifests[]` is a new v2 key
  carrying every recognized manifest the run could not read, with its ecosystem
  and what to do about it; empty means everything recognized *was* read, so a
  consumer can branch on it rather than inferring from a count that reads the
  same either way. The terminal summary names the files and the next step. And
  a directory whose only manifests were unreadable now exits 1, joining the
  "every file you named was refused" case from #125 — the two are the same
  outcome and had two different exit codes.

  Two cases deliberately stay at exit 0, because they are genuinely "nothing to
  do" rather than a refusal (#20, #68): a directory with no manifests at all,
  and a manifest that parsed and declares nothing. A scan that reads one
  ecosystem and cannot read another also stays at 0 — it produced a real
  answer — but `unreadable_manifests` says which half is missing, because a
  Python count presented as the whole project is its own quiet lie.

  The rejection message also stopped being a dead end. It used to name one
  companion file or nothing at all; it now names what *is* read for the
  ecosystem it identified — "npm projects are read from package-lock.json", and
  whether that file is sitting right there or how to generate it. For the
  ecosystems with no parser here at all (sbt, CocoaPods, Swift PM, pub, Hex) it
  says so outright instead of implying a supported format was almost found.

  **The sweep is the point, not the npm fix.** `package.json` was one instance
  of a shape that recurs in every ecosystem, and the table covers all of it:
  `Gemfile` and `*.gemspec` against `Gemfile.lock`, `composer.json` against
  `composer.lock`, `Pipfile`/`poetry.lock`/`uv.lock`/`setup.py`/`setup.cfg`
  against the three Python inputs, `go.sum` against `go.mod`, `Cargo.lock`
  against `Cargo.toml`, `packages.config`/`*.vbproj`/`*.fsproj`/
  `Directory.Packages.props` against `packages.lock.json` and `*.csproj`, and
  `settings.gradle` plus `gradle/libs.versions.toml` against the build files.
  A unit test asserts the table is disjoint from what the registry actually
  reads, so a parser added for one of these fails the build instead of leaving
  the tool telling users to go find a file it no longer needs.

  **There is no lockfile rule, and the issue was right that there never was
  one** — `docs/signals.md` now says so with the argument. Fifteen of the
  sixteen signals need only a package name; they are properties of the package,
  read from the registry and its source repository, which is the whole thesis
  of a leading-indicator tool. Only `version` needs a resolved version, and
  `exploit` degrades to `applicability_unknown` without one rather than going
  silent. What each ecosystem is chosen on is which file names the dependencies
  at all: npm's lock file names the resolved tree and `package.json` names only
  the direct set, while Cargo is the same choice made in the opposite
  direction. Accepting `package.json` with `unmanaged` versions is not refused
  on principle; it changes what gets parsed, its cost is a coverage question,
  and it is filed separately rather than folded in.

  One behaviour is deliberately scoped narrower than it could be: vendored
  directories (`node_modules`, `vendor`, `.venv`, and nine more) are pruned
  from the unreadable sweep only, not from manifest discovery. Without the
  pruning, a recursive scan of any real npm project reports one warning per
  installed package, which is a different way of telling the user nothing.
  Narrowing discovery itself would change which files get *scored*, and that
  needs its own evidence.

- **Six scorecard handlers answered from records they could not interpret, and
  one unreadable directory threw away every signal that was readable.** The
  narrower residue of #218, split out because it is a different root cause:
  #218 asked what a read that *failed* means, and these ask what a record we
  cannot *interpret* means. The answer had been the same in every case, and it
  was the one that lowers the score.

  `git tag -v` ran without `check=`-equivalent handling and its trailing `else`
  counted anything the parser did not recognise as an unsigned tag — the
  comment said "If we can't determine the status, assume no signature" out
  loud. A missing `gpg`, a keyring that could not be opened and a genuinely
  unsigned tag were one answer. Measured on a repository with one unsigned
  annotated tag and one signed tag whose `gpg.program` does not exist: before,
  `total_tags=2, no_signature_tags=2`; after, `total_tags=1,
  no_signature_tags=1, uninterpretable_tags=1`, and the one tag nobody could
  verify is excluded from both sides of the signing rate rather than counted
  against the project. `check=True` is deliberately *not* what it got: `git tag
  -v` exits 1 for a genuinely unsigned tag, so `check=True` would raise on the
  commonest honest outcome and unmeasure every unsigned repository.

  A `renovate.json` that did not parse left `package_managers` empty, and the
  report then said "Renovate configuration exists but package managers not
  clearly defined" — a finding about a file's contents, from a file whose
  contents were never read. `package_managers` is now `Optional`: `[]` means it
  parsed and named none, `None` means nobody established what it says, and the
  output names `source_lookup_failed` instead of inventing a finding. The
  confirmed "this project runs Renovate" is kept, because `exists()` measured
  that and the parse failure says nothing about it — the
  `AdvisoryLookupState.PARTIAL` position, that an incomplete measurement is
  still a measurement and is reported as incomplete.

  `analyze_commit_frequency` turned an unparseable `git rev-list --count` into a
  month with zero commits, which then fed the average, the trend and the
  stability figure as though someone had observed a quiet month; the series is
  positional, so a hole can be neither dropped nor filled, and it now
  unmeasures. `analyze_release_cadence` swallowed a `git` failure and fell
  through to a fallback that, absent — which is every call from
  `analyze_repository`, which passes `None` — returned the same empty result a
  project that has never tagged a release produces. And every tag date git
  emitted in an unexpected format was silently dropped from a series that is
  sorted and then differenced between adjacent entries, so one dropped date
  merges two release intervals into one that never happened, and a project all
  of whose dates fail to parse reads as never having released.

  A genuine absence is still a finding, and this was tested in both directions.
  A lightweight tag really cannot carry a signature, and `git tag -v` says so in
  words of its own (`cannot verify a non-tag object`); that is a measured
  negative, and treating it as uninterpretable would have unmeasured every
  repository that tags without `-a` — most of them. So is an unsigned annotated
  tag, an unsigned commit, a genuinely quiet month, and a repository that has
  never tagged anything. Laundering real findings into unknowns is the same
  defect pointing the other way.

  Separately, `analyze_repository` wrapped nine independent reads in a single
  `try`. A `PermissionError` from one directory with its execute bit off took
  everything after it down: measured on a repository with `docs/` at `chmod
  000`, `security_metrics` came back `None` **entirely** — all five scorecard
  checks skipped, never run — with one line at ERROR as the only trace. After,
  each read is isolated to the signal it answers: `has_dependency_update_tools`
  and `has_signed_commits` report their measured `False`, the four signals that
  genuinely read `docs/` report unmeasured with a reason, and the contributor
  count is still `1`. That failure was honest but maximally lossy, and worse, it
  was indistinguishable from a repository that was wholly unreadable — which is
  the distinction #218 exists to make. The #218 evidence run hit exactly this
  and read as the fix working.

- **A repository the scorecard checks could not read reported as a repository
  with nothing in it.** All five OpenSSF-style checks — security policy,
  dependency update tooling, signed commits, branch protection, maintained
  status — opened with `has_X = False` and returned that initial value on the
  broad `except` around the read and on the no-repository path alike. `False`
  is also the correct answer for a project that genuinely ships no
  `SECURITY.md`, so an unreadable file, a `git` subprocess that exited
  non-zero, or a type error part-way through came back as a confident negative
  finding that nothing in the output distinguished from a measured one. Unlike
  the advisory case this failed *closed*, inventing risk rather than hiding it,
  which is the more embarrassing direction to be wrong in: it accuses a project
  of neglect on the evidence of a permission bit.

  The readers underneath were the larger half of it. Each of the sixteen
  file-and-git readers caught its own exceptions and returned an all-`False`
  result dictionary, so the failure never reached the check function's own
  handler — an unreadable `.github/settings.yml`, the issue's own example, was
  swallowed a layer below where anyone was looking. Changing only the five
  return types would have produced a fix that never fired. The readers now let
  the failure propagate to their single caller, which is the one place that
  decides what it means.

  The five checks return `Optional[bool]`, answer `None` on both unmeasured
  paths, and say which one it was using the existing `UnmeasuredReason`
  vocabulary rather than a parallel one: `source_repository_unreadable` when
  there was no repository, `source_lookup_failed` when the read was attempted
  and raised. The paired score follows the same treatment — the initial `0.0`
  was the same lie with a decimal point. `analysis_helpers` guards each write on
  `is not None`, the way it already guards the contributor count and the commit
  cadence, so an unmeasured signal reaches the model as absent rather than as
  zero. Per #74 the scorer then drops it from both the numerator and the
  denominator; that arithmetic was already correct and is now pinned by a test.

  A genuine absence is still a finding. "We read the repository and there is no
  `SECURITY.md`" remains `False`, and is still scored, still reported.

  Measured on a real clone of this repository with `chmod 000` on `.git/`, which
  is what a clone owned by another account looks like in CI: before, the tool
  reported `is_maintained: false`, `has_signed_commits: false` and
  `has_branch_protection: false`, raised the total score from 0.865 to 1.341,
  moved the verdict from LOW to MEDIUM, and printed "Project does not appear to
  be actively maintained" about a repository committed to that week. After, the
  three signals report unmeasured and the verdict is UNKNOWN. The two checks
  that read only files are unaffected in both runs, and the readable control
  run is byte-identical before and after.
- **The 90% coverage bar was never enforced, by anything, at any point.**
  `pyproject.toml` carried `cov_fail_under = 90` under
  `[tool.pytest.ini_options]`. That is not a pytest option, not a pytest-cov
  option, and not a coverage option — pytest printed
  `PytestConfigWarning: Unknown config option: cov_fail_under` on every single
  run for a year while the number sat there looking like a policy. There was no
  `[tool.coverage.report]` section for coverage itself to read, and CI ran
  `pytest --cov=src` with no `--cov-fail-under`, so the run that would have
  failed the bar exited 0 and uploaded the shortfall to Codecov.

  Real coverage is **82.81%**, not 90: 1958 of 11388 statements missed on
  Python 3.11, and 82.86 / 82.89 / 82.82 on 3.9 / 3.10 / 3.12.

  The floor is now `fail_under = 82.5` in `[tool.coverage.report]`, which
  pytest-cov reads and enforces on the CI command with no workflow change — the
  measured minimum with ~0.3pt of headroom against a 0.07pt cross-version
  spread. `precision = 2` is set so the comparison means what it says: at the
  default precision of 0, a floor written as "83" is really a floor of 82.5 via
  rounding, which is how a bar ends up looser than anyone wrote down. Verified
  by raising it to 95 and confirming the CI command exits 1 with all 1594 tests
  passing.

  **The number was not moved to fit; it was measured and written down.** 90
  remains the target and is now tracked with acceptance criteria in #235, where
  the missing 820 statements are broken out by module. The floor is a ratchet:
  it only tightens.

  The pytest warning is gone, which is the smaller half of the fix and the half
  that had been visible on every run since 2025-04.

- **An advisory source that failed read exactly like one that found nothing.**
  `get_vulnerabilities` returned the empty list for a connection failure, a
  4xx, a GraphQL `errors` block, an unreadable body, an ecosystem the source
  does not cover, and a genuinely clean package. Six facts, one answer, and the
  answer was the reassuring one — at the tool's highest-weighted signal.

  It was also cached. An OSV outage during a scan did not merely report every
  package advisory-clean; it wrote that verdict to disk, where it was served
  back as a measurement until the TTL expired. A transient network failure
  became a persistent wrong answer, and nothing in the output told the two
  apart.

  Every source now answers with a result record rather than a list, so the
  three outcomes are distinguishable: advisories found, measured and none
  found, and lookup failed. The third leaves `exploit` **unmeasured** with the
  new `source_lookup_failed` reason, writes no advisory counts at all, adds a
  risk factor naming the sources that did not answer, and is **not written to
  the cache**. The cache schema version is bumped to 4 so that clean verdicts
  written by the old code are discarded rather than served past the fix.

  Partial failures are decided rather than lumped together. OSV and the GitHub
  Advisory Database are asked about a package by identity in an ecosystem, so
  their silence is an answer and their failure unmeasures the absence claim.
  NVD is reached by keyword search over CPE strings and can only ever add, so
  its failure degrades completeness — the result is not cached — without
  unmeasuring anything. A finding survives any failure and is reported as a
  floor: no outage elsewhere un-finds an advisory. A package is therefore never
  called clean because two sources of three answered, and a scan is never made
  unmeasured because NVD was slow.

  An ecosystem a source does not cover is an abstention, not a failure and not
  an answer. Per #164, no `NOT_APPLICABLE` is invented for it: if nobody could
  be asked at all, the signal is unmeasured with `lookup_not_attempted`.

  Measured on a seven-package Python manifest with OSV forced offline: before,
  all seven scored `exploit: 0.0`, `known_vulnerable: false`, and seven cache
  entries were written. After, all seven report `exploit: unmeasured
  (source_lookup_failed)` and nothing is cached. With OSV reachable, four of
  those seven are in fact known-vulnerable.

  One shape note for whoever edits `RiskScorer.score_dependency` next. Its
  50ms-per-100-dependencies SLA is enforced *with coverage instrumentation
  active*, and under instrumentation that method sits on a cliff: adding as few
  as five physical lines to it — comments included, which generate no bytecode
  at all — costs about 30% of the budget, while the same lines in a helper or at
  the end of the file cost nothing measurable. So the second fact travels to
  `_measure` as one tuple rather than as two arguments (a two-argument tail puts
  fifteen call sites onto four lines apiece), and the new risk-factor branches
  live in a module-level `advisory_risk_factors` with their explanation. Scoring
  ends up 5% slower than before under instrumentation and 4% slower without it,
  against an unchanged threshold.
- **NuGet resolves version properties defined in `Directory.Build.props`.** A
  `.csproj` that declares `Version="$(SomethingPackageVersion)"` and defines the
  property one directory up resolved to `unmanaged` — honest under the #141
  contract, and a total loss of the version-drift signal for a repository shape
  that is not rare. Newtonsoft.Json's own project is exactly it: seven package
  references, seven properties, none of them defined in the file that uses
  them, all seven unmeasured.

  Precedence follows MSBuild's evaluation order rather than convenience.
  `Directory.Build.props` is imported first, so anything the project defines
  wins over what it inherits, and so does anything the
  `Directory.Packages.props` defines. `ManagePackageVersionsCentrally` is read
  from it too — Dapper sets the switch there — because reading a file for
  versions and not for the property that decides whether those versions apply
  is how a confident wrong answer gets produced. Only `<PropertyGroup>` content
  is taken; `<Import>` chains and `<PackageReference>` items in that file are
  still not followed, and anything unresolved stays `unmanaged` rather than
  becoming a guess.

  Both walks share one traversal, both files are read through the XXE-safe
  reader, and an unparseable or missing one leaves the versions that needed it
  unmeasured instead of taking the parse down.

- **A package npm removed for malware read as current and undeprecated.** npm's
  security team does not delete a package it pulls; it republishes the name as
  a placeholder described `security holding package` at a version carrying a
  `-security` prerelease tag, and repoints `dist-tags.latest` at it. `crossenv`,
  pulled for stealing environment variables, answers `0.0.2-security`.

  Read as a release, that inverts the finding: an installed `6.1.1` scores as
  *ahead* of the registry, so the drift signal reports no drift, and the
  placeholder carries no `deprecated` notice, so nothing else in the payload
  flags it either. It is cargo's `"0.0.0"` in npm's dialect — a parseable semver
  of exactly the right type that is not a release of the package at all.

  The placeholder is now recognized (both markers required: the description and
  the `-security` suffix, so a legitimate out-of-band security release is not
  caught) and nothing downstream reads it as a release. `latest_version` stays
  unmeasured, its empty manifest is not read as a measured zero dependency
  count, and the dependency is marked deprecated, which is where the finding
  belongs. `additional_info.npm_security_holding_package` records why.

- **GitHub answers `cvss.score: 0` for an advisory it never scored.** The
  GraphQL `cvss` block is non-nullable, so an advisory with no CVSS vector
  still returns a score, and the score it returns is `0.0` — lodash's
  `GHSA-p6mc-m468-83gg` is severity HIGH with `{"score": 0, "vectorString":
  null}`. Copied out verbatim, a high-severity advisory claimed the bottom of
  the scale in every payload that carried the record. `vectorString` is the
  tell — null exactly when no vector was assigned — so a zero without one is
  now unmeasured, and a zero *with* one is kept as the real (if unusual) score
  it is.

- **A measured maximum CVSS of 0.0 was published as "no CVSS measured".** #216
  fixed the per-advisory falsy read (`if cvss_score:` → `is not None`) and left
  the accumulator one line down, which started at `0.0` and emitted
  `max_cvss if max_cvss > 0 else None`. It now starts unmeasured and takes a
  maximum over the advisories that actually stated a severity, so `null` in
  `max_counted_cvss_score` means nobody scored them and `0.0` means somebody
  did. An advisory whose severity is UNKNOWN contributes nothing rather than
  fabricating a measured zero.

- **A contributor count of zero was thrown away as though nobody had looked.**
  `count_contributors` answers `None` for a count it could not take (a shallow
  clone, a git failure) and an int for one it did, and the analyze path guarded
  it with `if contributor_count:` — so a measured zero left
  `maintainer_count` unset and unattributed, in the one field where "none" and
  "unknown" point opposite ways for the maintainer-concentration score. The
  same falsy read in the community pass dropped a zero on the way to
  `contributor_count`. Both guard on `None` now, as the commit-cadence read
  beside them already did.

- **A shape error in an advisory payload could still be reported as "this
  package has no advisories".** #216 hardened what the OSV and GitHub Advisory
  normalizers do with a wrong-typed field, but left them running *inside* the
  `except Exception` that wraps the fetch, so any residual parse failure was
  still caught by a handler whose answer is an empty advisory list — the
  fail-open that turned `severity.upper()` on a boolean into a clean bill of
  health. Both sources now decode the body inside the handler and normalize
  outside it, so a fetch failure still degrades quietly and a parse failure
  surfaces instead of masquerading as a clean package.

- **The advisory cache served one package's advisories for another.** Cache
  filenames were built by sanitizing the package name, and sanitizing loses
  information, so two distinct packages could land on one entry — in either
  direction: a clean package inheriting advisories, or a vulnerable one reading
  as clean. `/` was rewritten to `__`, so composer's `foo/bar` and a literal
  `foo__bar` were one file; and the key kept the source casing, so npm's
  grandfathered `Foo` and a separate `foo` were one file on macOS and Windows,
  which are case-insensitive by default. The second was the worse of the two
  because it depended on the developer's filesystem: it reproduced for some
  people and not others, on the platforms most people run locally.

  Both keys are now a SHA-256 digest of `f"{ecosystem}\x00{package_name}"`. The
  NUL separator cannot appear in either input, so no two `(ecosystem, package)`
  pairs can produce the same joined string — `("a", "b/c")` and `("a/b", "c")`
  stay distinct. Hashing rather than extending the replacement list also
  retires three problems that were queued behind the same design: a
  300-character package name exceeded `NAME_MAX` and failed to write, a NUL
  byte in a name raised `ValueError` out of `open()`, and traversal-shaped
  names stop being a question anyone has to re-answer. (They were never a
  vulnerability — `"../../etc/passwd"` produced the literal filename
  `python_..__..__etc__passwd.json` — but the digest closes it structurally.)

  The in-memory cache in `aggregator.get_cache_key` collided the same two ways
  and one more. It lowercased unconditionally, so `Foo` and `foo` shared an
  entry on *every* platform, and its `:` separator could not split maven
  coordinates back apart, where the package name is itself `group:artifact`.
  The OSV batch pre-warm folded case in its dedupe set for the same reason.
  Both are case-exact now. The cost is that `Flask` and `flask` occupy two
  entries on registries that fold case: a lookup, where the collision cost
  correctness.

  Cache filenames stop being human-readable; the `package` and `ecosystem`
  fields inside each record carry that, and nothing reads a filename for
  meaning any more — `clear(ecosystem=...)` reads the recorded ecosystem
  instead of matching a filename prefix, which is also exact where the prefix
  match was not. `CACHE_SCHEMA_VERSION` goes to 3, so a record written under
  the old layout into a shared cache directory is discarded on read rather than
  scored against. (#212)

- **A JSON `true` in a CVSS field scored as a real severity.** `bool` is a
  subclass of `int`, so `true` satisfied a numeric guard and was returned as
  `True`, behaving as `1.0` downstream: a malformed or hostile registry payload
  produced a valid-looking LOW severity finding instead of an honest refusal.
  The return path was fixed in the previous release; this is the sweep of
  everywhere else the shape survived.

  The NVD and GitHub Advisory normalizers copied `cvssData.baseScore` and
  `advisory.cvss.score` into the record verbatim, so the boolean reached the
  cache and every consumer that did not re-normalize. Both now normalize at the
  point of extraction, as OSV already did. The same pass fixes the mirror-image
  bug beside it: NVD's confidence read `severity or cvss_score`, so a *measured*
  `0.0` — a score NVD published — was treated as a missing one.

  Withdrawal got the same treatment in the other direction. `withdrawn` is an
  RFC 3339 timestamp in both OSV's and GitHub's schemas, but `bool(...)`
  accepted any truthy JSON value, so a payload carrying `"withdrawn": true`
  suppressed a real advisory from the score without ever naming a withdrawal
  date. A withdrawal now requires the timestamp its schema promises.

  Adjacent string fields that arrived as something else were doing damage of
  two kinds. `vuln.get("severity", "").upper()` and `status.lower()` raised
  `AttributeError` on a boolean or null, and the caller's broad `except
  Exception` turned that crash into "this package has no advisories" — a
  fail-open on the whole lookup. Elsewhere the wrong-typed value was simply
  copied through, putting a JSON `true` in `published`, in a `fixed_versions`
  list nothing can version-order, and in reference URLs. All of these are read
  through type-checked accessors now.

  `None` from `normalize_cvss_score` means **unmeasured**, not "no severity",
  and downstream honors that: the advisory falls to `UNKNOWN` severity and is
  filtered with the reason `unknown severity` recorded, rather than scored as
  `INFO`. A severity string NVD states independently still scores — an advisory
  rated CRITICAL with a junk `baseScore` stays CRITICAL. (#213)

- **`scan-org` produced a different risk figure for identical input across
  runs.** The org repository summary averaged a float over the dependencies in
  a repository, and read those dependencies out of a `set`. Set iteration order
  for strings varies with `PYTHONHASHSEED`, which CPython randomises per
  process, and float addition is not associative — so `average_risk_score`
  moved in its last bit from one run to the next, with nothing about the input
  changed. A last-bit difference, but a real one, in a number the tool
  publishes: it defeats byte-comparison of two reports (exactly the wall the
  schema-v2 work hit while proving its `--schema v1` guarantee, which it could
  only get by pinning `PYTHONHASHSEED=0`) and it breaks scan-to-scan diffing,
  since "what changed since last week" is worthless if a number moves when
  nothing did. The summary now accumulates in sorted identity order.

  Worth recording, since it explains why CI did not catch this: CPython 3.12
  gave `sum()` Neumaier compensation, which hides the symptom on 3.12 for
  values in this range. It was live on the 3.9-3.11 jobs. A published number's
  stability should not rest on the interpreter's summation algorithm. A test
  now asserts the property the honest way — two `scan-org` runs under different
  `PYTHONHASHSEED` values in child processes, compared byte for byte — with a
  second test pinning the fixture's order-sensitivity so the sweep cannot
  quietly become decorative. A sweep of every other `sum()` and float aggregate
  in `src/` found no second instance: the rest sum over lists, or sum integers.

### Removed

- **The `tests` symlink, which pointed at one developer's home directory and,
  inside a git worktree, ran the wrong checkout's tests.** It was committed as
  `tests -> /home/william/git/dependency-risk-profiler/testing`, an absolute
  path. On every other machine it dangles, so anything that followed it did
  nothing and said nothing. In a worktree it is worse than broken: it resolves,
  to the *main* checkout, so `pytest tests/unit` from a feature worktree runs a
  different tree's test files than the ones you are editing and reports them
  green.

  Measured before deleting it, from a worktree with a marker test added to that
  worktree's `testing/unit/`: `pytest tests/unit` collected 1546 tests and the
  marker was not among them; `pytest testing/unit` collected 1578 and it was.
  The two trees had already drifted by 32 tests without either run complaining.

  Every reference that pointed through it now names `testing/` directly:
  `.pre-commit-config.yaml`'s bandit exclusion, two `tests/` entries in the
  CodeQL config, `PROJECT_STRUCTURE.md`, both copies of `CONTRIBUTING.md`,
  `testing/integration/README.md`, and `TESTING_IMPLEMENTATION.md`.

  This is the same defect as the `uv run`-without-`uv sync` trap in AGENTS.md
  rule 7, one layer down: the environment substitutes a different source than
  the one under test, and the substitution is silent and green.

- **The inert `[tool.flake8]` section in `pyproject.toml`, and the two tests
  that made it look alive.** flake8 has no pyproject.toml support; without the
  flake8-pyproject plugin, which is not installed, the section was read by
  nothing. Confirmed empirically rather than assumed: with `.flake8` moved
  aside, flake8 fell back to its built-in default of 79 columns rather than the
  88 the section specifies. Every line of it was dead, including six exclusions
  that pointed through the `tests` symlink at files that have lived in
  `testing/unit/` since the migration. `.flake8` is and always was the live
  config — CI runs `flake8 --config=.flake8` — and it already carries every
  setting the dead section named, so nothing needed porting.

  `test_flake8_config_valid` asserted that `flake8 --version` exits 0, under a
  comment reading *"the pyproject.toml path where flake8 config is now stored"*.
  `test_flake8_ignores_are_effective` passed the ignore list on the command line
  and then checked that flake8 honoured it — a test of flake8, not of this
  repository. Neither could fail, and between them they gave the dead section a
  green tick for a year.

  They are replaced by two that bite.
  `test_dot_flake8_is_the_config_flake8_actually_reads` runs the same
  single-fault file twice, once with the repo config and once with
  `--isolated`, and requires opposite verdicts, so a pass cannot come from
  flake8 having nothing to complain about.
  `test_pyproject_carries_no_inert_flake8_section` fails if a `[tool.flake8]`
  section reappears without the plugin that would read it. Both were verified
  to fail before landing, by reintroducing a specimen of the defect: a re-added
  section, and an `extend-ignore` with `F401` removed.

  `docs/enhancement/Improvements.md` — the prompt file whose "configure Flake8
  under `[tool.flake8]`" instruction produced the section in the first place —
  now carries a note saying not to.

- **BREAKING CHANGE: four fields are gone from the JSON output** rather than
  carried into the frozen contract, all still available under `--schema v1`:
  `display_name` and `versions_display` were string formatting over fields
  already in the payload; `key_signals` was a third hand-maintained
  English-string generator over the same scores `risk_factors` already
  describes; the per-dependency `unknown_signal_count` is
  `len(unknown_signals)`. The HTML, terminal and CSV reports now render the
  scorer's own `risk_factors`, so there is one generator instead of three.
  `version_specs` is **kept**: it is the set of raw specifiers different
  manifests declared, and no formatting reconstructs it from one resolved
  version.

- **BREAKING CHANGE: the simulated code-signing subsystem is gone, along with
  the public API it exposed.** `src/dependency_risk_profiler/secure_release/`
  (1784 lines across `code_signing.py`, `release_build.py`,
  `release_management.py`, and a packaged `github_actions_ci_cd.yaml` template)
  is deleted, and with it these names, which were re-exported from the
  top-level package and are therefore importable by anyone who has
  `pip install`ed 0.4.0:

  - `dependency_risk_profiler.sign_artifact`
  - `dependency_risk_profiler.verify_signature`
  - `dependency_risk_profiler.create_release`
  - the `dependency_risk_profiler.secure_release` subpackage in its entirety,
    including `SigningMode`, `BuildMode`, `VersionBumpType`, `scan_for_malware`,
    and `python -m dependency_risk_profiler.secure_release.code_signing`

  None of it was reachable from any CLI command, and none of it did what its
  name said. `retrieve_signing_key` returned `os.urandom(...)` on every call in
  *both* TEST and RELEASE mode, so no key was ever persisted and no signature
  could ever be verified by a second call. `create_signature` was
  `sha256(file_hash || key)`, with the real PSS implementation sitting commented
  out directly above it — no asymmetric key, nothing a third party could check,
  no non-repudiation. `scan_for_malware` set `scan_result = True`
  unconditionally, with the `clamscan` invocation commented out, while its
  docstring advertised a `False` branch that did not exist. A supply-chain risk
  tool was publicly exporting a signature verifier that verified nothing and a
  malware scan that could not fail.

  **Removed rather than deprecated, deliberately.** A deprecation cycle would
  leave a fake signature verifier callable and importable for at least one more
  release, which is precisely backwards for a security fix: the whole problem is
  that the function is reachable and misleading. There is no correct migration
  target to point a deprecation warning at, because the project does not sign
  releases and should not do so from inside the scanner — real signing needs key
  management, timestamping, and revocation, and belongs in CI (sigstore/cosign),
  not in a library function.

  **Version implication:** this is a breaking removal of published public API.
  Under 0.x semantics this warrants a **minor bump to 0.5.0 at minimum**; post-1.0
  it would be a major bump. Maintainer's call, but do not ship it as a patch.

  **If you were calling these:** you were not getting a cryptographic guarantee,
  so there is nothing to preserve. For artifact verification, use the Sigstore
  attestations that PyPI trusted publishing already produces for this project's
  own releases, or `sigstore`/`cosign` directly for your own.

  The release workflow (`.github/workflows/release.yml`) was the one real
  consumer: it called `sign_artifact(..., SigningMode.RELEASE)` on every tagged
  release, attached the resulting `.sig` files and `signing.log` to the GitHub
  Release, and printed release notes claiming the release was "cryptographically
  signed using the project's secure release system." That step is removed, the
  `.sig`/`signing.log` uploads are dropped, and the notes now describe only what
  is actually true: SHA256 checksums plus the PyPI trusted-publishing Sigstore
  attestations (which were already enabled). Past releases carrying `.sig` files
  should be treated as unsigned. (#174)

### Security

- **The `?go-get=1` vanity lookup validated the hostname, not the address it
  resolved to.** A module path in a scanned `go.mod` names a host we then fetch
  from. Every check that fetch made was on the name — https, no credentials, no
  port, public host, no IP literal — and a name an attacker registers is free
  to resolve to `169.254.169.254`. That is DNS rebinding, it defeated all of
  them, and `scan-org` walks every repository in an organization, so one hostile
  repository in scope was enough to aim a request from the scanning host at its
  own metadata service. Fetching now resolves the host itself, refuses the host
  outright if **any** returned address is private, loopback, link-local,
  reserved, multicast or a known cloud-metadata endpoint, and connects to a
  validated address rather than to the name — while still presenting the
  hostname for SNI, the `Host` header and certificate verification, so TLS is
  unweakened. Redirects are followed by us rather than by the HTTP client
  precisely so that every hop is re-resolved and re-validated: a 302 to a
  rebinding host is refused exactly like a first hop would be.

  The control lives in a new `dependency_risk_profiler.secure_http`, not in
  `go_modules`, because #136 consolidates package-to-repository resolution
  across every ecosystem and each one turns a third-party registry string into
  an outbound request. Go is the first caller of this, not the owner of it.
  (#138)

### Fixed

- **`transitive_source` was fail-open: an absent marker read as *measured*, so
  a dependency nobody resolved scored a confident `0.0` for transitive risk.**
  This is #141's fabricated zero surviving in one field. #141 marked the
  unmeasured cases explicitly but never inverted the default, so the guarantee
  held only where someone remembered to annotate — and the places nobody
  annotated were not hypothetical. The org scan (`org_scan.pipeline`) never
  calls the transitive analyzer at all, so *every* dependency it scored arrived
  with an unset marker and got a free `0.0`; a crash part-way through
  resolution did the same to whatever the analyzer had not reached yet. PR #198
  found the near-miss that proves the hazard was live: Maven was writing its
  marker as a bare `"transitive_source"` string literal rather than through the
  recorder, one typo from silently reverting to fabricating zeros, with no test
  failing because `0.0` is a perfectly plausible score. The read now fails
  closed (`signals.transitive_is_measured`), `_calculate_transitive_score`'s
  `measured` argument is keyword-only and defaultless — the #189
  `record_source_repository` shape — and a set carrying no source marker is
  declined rather than credited to an unnamed resolver.

  **Scores move, for real dependencies.** An unmeasured signal leaves both
  numerator and denominator (#74), so removing a fabricated `0.0` *raises* the
  reported risk of everything it was diluting, and costs one measured signal
  against the insufficient-data bar. Verified against the captured registry
  fixtures for all eight ecosystems, scored the way the org scan scores them:
  12 of 25 moved, all of them in the five ecosystems whose adapter reads no
  dependency list (nodejs, python, cargo, rubygems, golang) — express 0.95 →
  1.04 and LOW → UNKNOWN, request MEDIUM → UNKNOWN, flask LOW → UNKNOWN,
  hpricot LOW → MEDIUM, sklearn 2.25 → 2.47. The three ecosystems that
  genuinely measure transitive dependencies are byte-identical: nuget reads the
  `.nuspec` `<dependencies>` (#129), maven the POM's scope-filtered
  `<dependencies>`, composer the p2 entry's `require` block (#180). An audit of
  all eight confirmed those are the only three that populate the field at all.
  `MIN_MEASURED_SIGNALS` is unchanged and correct: no ecosystem measures more
  than it did, and the three that measure transitive were already floored
  including it.

  For npm lockfiles the analyzer now records `manifest` only for packages the
  lockfile actually names. A package absent from the lock resolved to the empty
  set and was stamped as measured, which claimed the manifest said "none" when
  it said nothing. Packages the lock does name are unaffected, including the
  genuine measured zero for a leaf with no dependencies of its own. (#199)

- **The `source_repository` signal has three states, and was recording two of
  them as one.** `record_source_repository` marks whether a registry *declares*
  a source repository, which is what lets the scorer treat "this package
  publishes no repo" as one measured fact rather than eight independent
  unmeasured signals (#146). It only ever wrote DECLARED or UNDECLARED, so
  "declared a repository nobody can read" was indistinguishable from "declared
  none". Maven Central serves the pair that proves the difference:
  `commons-collections:commons-collections:3.1` carries no `<scm>` element at
  all, while `log4j:log4j:1.2.17` declares one and every spelling of it is
  Subversion. PR #175 had already found the discriminator across 25 sampled
  artifacts — 9 declaring nothing, 12 naming SVN or CVS, 4 naming a git forge
  and all 4 resolving — and it was being thrown away. There is now a third
  state, DECLARED-BUT-UNUSABLE, recorded whenever the registry's own
  source field carries something that does not canonicalize to a repository on
  a supported host. **Scores will move**: it scores 0.75 rather than the 1.0
  those packages used to get. The discount is for the declaration itself, which
  is real evidence about a project's publishing hygiene and its era; it is only
  a discount because the operative consequence is unchanged — nobody can read
  the source either way, so the eight repository-derived signals stay dark and
  the #146 collapse still applies to both states. Affected: every ecosystem, and
  Go modules most of all, where a path resolving to `go.googlesource.com` or a
  private vanity host now reads as declared-but-unusable rather than as
  declaring nothing (Go has no separate repository field — the import path *is*
  the declaration, so a Go module is never UNDECLARED). (#176)

- **nuget resolved a source repository and then reported nothing about whether
  one was declared.** `NuGetAnalyzer` read `<repository url>` off the nuspec,
  set `dep.repository_url`, and never called `record_source_repository`, so
  `_calculate_source_repository_score` returned `None` and the signal was
  dropped from `weighted_scores` entirely. nuget was the only ecosystem scoring
  15 signals where the other seven scored 16, and the absence read as though
  nuget.org had said nothing either way — it says plenty, since a nuspec either
  carries `<repository>` or it does not. Worse, a .NET package declaring no
  repository counted eight separate unknowns instead of one explained gap,
  which is the arithmetic that pushed abandoned packages to UNKNOWN in the
  first place. `MIN_MEASURED_SIGNALS["nuget"]` moves 8 → 9 in the same change,
  because a floor below measured coverage is a permission slip (#183, #158).

- **A failed registry lookup was being scored as "this package declares no
  source repository".** `ComposerAnalyzer` called `record_source_repository`
  outside the `if release is not None` guard, and `_get_latest_release`
  swallows a connection error, a non-200 and an unparseable body alike — so a
  404 and a network blip both came out as a confident 1.0, the highest score
  the signal has. Nobody asked Packagist anything. An unmeasured signal is
  excluded from both the numerator and the denominator, never defaulted (#74),
  and this is #141's fabricated zero in a different field. Sweeping the other
  seven adapters found the same ordering in maven (an artifact whose POM could
  not be fetched was recorded as declaring nothing) and in the Go vanity-import
  resolver (a host that never answered was indistinguishable from one that
  answered with nothing). All three now leave the key unset, which is the
  unmeasured branch the scorer already handled. (#182)

- **maven now follows `<parent>`, which is where Java keeps its licence.**
  Maven's convention is to declare `<licenses>` and `<scm>` once in a parent POM
  and inherit them, and the adapter read the artifact's own POM and stopped. So
  `com.google.guava:guava` reported no licence at all, and neither did any
  Apache Commons artifact — commons-lang3's licence is two hops up, in
  `org.apache:apache`. The parent chain is walked through the same bounded
  client #141 built for version resolution: `repo1.maven.org` over https only,
  redirects refused, coordinates matched against a strict grammar, a 2 MiB
  streamed cap, XXE-safe parsing, a bounded depth and the per-manifest fetch
  budget, with failures and successes memoized so twelve Spring starters sharing
  a parent cost one fetch between them. **Precedence is
  nearest-declaration-wins**, matching Maven (a child's own `<licenses>` block
  replaces the parent's rather than merging with it) and matching what #141
  already chose for properties and dependency management. The walk is lazy and
  stops once a licence and an SCM URL are known, so an artifact that declares
  both itself — jackson-databind, every modern Spring module — costs no extra
  request. Two deliberate divergences from Maven's own model builder, both
  documented in `pom_model.inherit_metadata`: the child `artifactId` is not
  appended to an inherited `<scm><url>`, because the consumer trims URLs back to
  the repository root anyway; and `<dependencies>` is not inherited, because an
  artifact's own dependency list is what it ships and a parent's is what its
  siblings ship. The `declared` argument #176 added to
  `record_source_repository` is fed the **inherited** `<scm>` rather than the
  artifact's own, so an artifact that inherits a Subversion or gitbox `<scm>`
  from its parent records UNUSABLE rather than UNDECLARED — recording it off the
  leaf POM would be #182's fabricated negative arrived at from a third
  direction, and it is not a rare shape: `org.apache.ant:ant` and
  `org.apache.velocity:velocity-engine-core` are both built that way.
  **Maven licence and source-repository scores will move for real
  dependencies**: guava and slf4j-api both go from below the measured-signal
  floor to at it (slf4j-api's `source_repository` moves 1.0 → 0.0, because it
  inherits `github.com/qos-ch/slf4j` two hops up and reading it as silence was
  the adapter's blindness rather than the artifact's), and commons-lang3 moves
  from MEDIUM to LOW on registry metadata alone. log4j and commons-collections,
  #176's three-state pair, both declare no `<parent>` and are unaffected. (#178)

- **composer now reads the Packagist `require` block.** Every p2 release entry
  names the package's own dependencies — the same fact nuget reads out of its
  `.nuspec` and maven out of its POM's `<dependencies>` — and composer marked
  the transitive signal unmeasured anyway, for every PHP package. Two judgement
  calls, both asserted by value against captured fixtures rather than described
  in a comment. **Platform constraints are not dependencies**: `php`, `php-*`,
  `ext-*`, `lib-*`, `hhvm` and `composer-*` describe the runtime a package needs,
  not something a consumer is exposed to through the dependency graph, and they
  are dropped. psr/log, whose entire `require` block is `{"php": ">=8.0.0"}`, is
  the proof — it measures zero dependencies rather than one. The filter tests
  the *vendor prefix*, not the name, because several real vendors start with
  exactly the prefixes a platform constraint does: `php-http/discovery`,
  `php-di/php-di`, `composer/semver`. mailgun/mailgun-php was captured for that
  edge — three of its six runtime dependencies are `php-http/*`, and a
  name-first filter would report three. **`require-dev` is
  not counted**: it is what building the package needs, not what installing it
  pulls in, so it is out for the same reason maven excludes `test` and
  `provided` scopes. swiftmailer is the proof — four runtime packages score
  0.1, and the six that fold in the dev block would score 0.25. **Composer risk
  levels will move**: `symfony/console` goes from UNKNOWN (insufficient data) to
  LOW, because the ninth measured signal is what carries it over the bar.
  `MIN_MEASURED_SIGNALS["composer"]` moves 8 -> 9, the highest floor of the eight
  ecosystems. (#180)

- **`community_score` measures development cadence, which it never has.**
  The score advertised a composite of popularity and development activity.
  `CommunityMetrics.commit_frequency` was read in six places and assigned in
  none, and its producer `calculate_commit_frequency` had zero callers, so the
  score was the star-count bucket verbatim — and star count is the weakest
  signal in this tool's own thesis, because it measures attention rather than
  maintenance. It was not even an honest unknown: the star half *was*
  populated, so the composite returned a confident number while silently
  dropping the half that mattered. **Community scores will move for real
  dependencies.** Cadence now comes from the GitHub commits API in both the
  analyze path and org scans; the git implementation is retained but skipped on
  the `--depth 1` clones the tool makes, because one reachable commit reads as
  a confidently dead project for every repository on earth (the split
  `count_contributors` already makes). Two consequences that had never fired in
  the tool's history now can: the "Low development activity" risk factor, and
  the matching line in the terminal report. (#166)

- **A half-measured community signal no longer reports as a whole one.**
  Popularity and cadence are now weighted independently rather than averaged
  into one entry, so an unmeasurable half leaves both the numerator and the
  denominator instead of being carried by the other half at full weight — #74's
  rule, applied one layer down. When cadence cannot be measured, output names
  `community_activity` in `unknown_signals` rather than implying it was
  considered. When *neither* half is measurable the pair still counts as one
  gap, not two, so this does not re-introduce the over-counting #146 fixed. The
  risk factors and terminal signals gate on their own half rather than on the
  average, which for a well-starred package with a dead commit log lands on
  exactly 0.5 and cleared no `> 0.5` threshold. (#166)

- **Five fields were computed, stored, and never read.** `fork_count`,
  `releases_count`, `downloads_count`, `SecurityMetrics.fixed_vulnerability_count`
  and `has_recent_security_update` reached no output, no score, and no risk
  factor. All five are deleted along with the code that produced them. This
  removes a per-dependency HTTP call to pypistats.org — an unaffiliated
  third-party service the scan contacted for a number nobody consumed. (#166)

### Added

- **A two-state measurement, enforced at construction, and a published signal
  vocabulary pinned to a Scorecard version.** (#164, steps 3 and 4)

  `signals.Measurement` is `MEASURED` with a value or `UNMEASURED` with a
  reason, and it refuses every other combination in `__init__`. Instances are
  frozen afterwards, so a value cannot be edited onto an unmeasured signal.
  That makes #141's confident `0.0` for a signal nobody measured, and #166's
  composite that degraded to its weakest component while still reporting as
  measured, unrepresentable rather than merely discouraged. The scorer now
  carries one per signal per dependency.

  Classification is centralized in `signals.unmeasured_reason_for()`, the only
  place that decides *why* a signal is unmeasured, from the catalog plus one
  keyword-only fact the scorer observed — never adapter-local judgment across
  eight adapters. `NOT_APPLICABLE` is **not** here: it is deferred behind a
  schema version until a consumer branches on it, because no conformance check
  can tell a wrong `NOT_APPLICABLE` from a right one. The reason enum is
  guarded by a test against it coming back under another name.

  `docs/signals.md` publishes the mapping from our stable signal names to
  OpenSSF Scorecard `v5.5.0`, with every approximate row marked approximate,
  and `testing/unit/test_signal_catalog.py` fails when the page and the code
  disagree. Our names are **not** renamed to Scorecard's: `signed_commits` maps
  to no Scorecard check at all at that tag — the nearest historical one,
  `Signed-Tags`, was removed after v2.0.0, and the stable `Signed-Releases`
  inspects release assets rather than git history — so adopting an upstream
  vocabulary would have traded the stability guarantee this work exists to make
  for the appearance of interop.

  Two stringly-typed measurement states move out of `additional_info` and onto
  typed fields: `DependencyMetadata.source_repository_state` (a
  `SourceRepositoryState`, written only by `record_source_repository`) and
  `.transitive_source` (written only by `record_transitive_source`, whose
  `source` argument is keyword-only with no default so the unmeasured state
  cannot be reached by omission). Maven had been writing the transitive marker
  as a bare string literal, which is the one spelling a typo would have turned
  into a permanent "unmeasured". `release_date_source` and `version_source`
  stay where they are: both record which write path won rather than whether a
  signal was measured, which is #164's provenance item, gated on its own
  benchmark and sequenced last.

  No change to the JSON output contract — verified byte-identical against
  `origin/main` on a fixed population. Cost measured rather than assumed:
  about +7.6 µs per dependency (11.91 → 19.52 µs), no additional retained
  memory, numbers and method in `docs/signals.md`.

- **A test that fails when a model field the code reads has no writer.** The
  generalized form of the sweep that found the above: any `models.py` field
  declared `= None`, read somewhere in `src/`, and assigned nowhere is a
  constant wearing a signal's name. Verified to fail when an assignment is
  removed. (#166)

- **The org-scan headline no longer reports the reassuring number on its own.**
  A scan of a 25-repo org led with "2 high-risk dependencies exposed across 1
  repositories" while 198 of its 1135 dependencies carried live advisories and
  812 could not be scored at all. Neither number means anything without the
  other, and the high-risk count is systematically depressed exactly when
  coverage is poor — a dependency that cannot be scored cannot score HIGH, while
  the advisory path keeps working — so the old headline got quieter as the tool
  measured less. The headline now reads
  `198 known-vulnerable · 2 high-risk · 812 could not be scored · 1135
  dependencies across 25 repos`, ordered by what demands action: known-vulnerable
  first (there is a fix and a version to move to), then the leading-indicator
  count, then the coverage caveat. Terminal, HTML, and JSON all carry all three;
  the JSON report gains `unscored_dependency_count`, and the HTML masthead gains
  an Unscored readout plus a sentence stating that the high-risk count is a
  floor, not a total. (#133)

- **A successful `analyze --output json` run can no longer emit zero bytes.**
  Pointing the tool at a directory with no manifests exited 0 and wrote nothing,
  so a consumer doing the obvious `run → json.load(stdout) → act` crashed on a
  run that succeeded — and walking an org means hitting manifest-free
  repositories constantly. Every path that can end a run early now emits the
  documented shape with empty collections and a `warnings` entry saying what
  happened: no manifests found, unsupported manifest, parse failure, and a
  manifest that declares no dependencies. A directory of several manifests emits
  one merged document rather than several concatenated ones, which `json.load()`
  rejected. The invariant is now enforced by a test that sweeps every one of
  those paths: **if the process exits 0 in JSON mode, stdout is parseable
  JSON.** (#147)

- **`Unsupported manifest file` now names the next step, and refusing everything
  is no longer a success.** Pointing `analyze` at `package.json` printed a bare
  error, then `Successfully analyzed: 0`, then exited 0. Requiring resolved
  versions is the right design — a range like `^4.13.4` has no version to score
  drift against — but the message said nothing about what to run instead. A
  small companion table now redirects `package.json` → `package-lock.json`,
  `Gemfile` → `Gemfile.lock`, `composer.json` → `composer.lock`, `Pipfile` →
  `Pipfile.lock`, and says whether that companion actually exists next to the
  input; `build.gradle` is told that Gradle lock file support is not implemented
  yet (#101) rather than pointed at nothing. Separately, because the parser
  registry matches manifest filenames exactly, a valid manifest saved under
  another name (`railsgoat-Gemfile.lock`) was rejected identically to an
  unsupported ecosystem — the message now names the parser that would have
  accepted the same bytes and what to rename the file to. No parser was added
  and no dispatch changed. A run that scored nothing because it refused every
  input exits 1; a directory with no manifests, and a manifest that parsed fine
  and declares nothing, both still exit 0. (#125)

- **NuGet projects using Central Package Management now resolve their versions.**
  Modern .NET solutions declare each version once in a
  `Directory.Packages.props` and leave the `PackageReference` bare — it is
  Microsoft's recommended layout for a multi-project solution, and eShopOnWeb,
  Microsoft's own reference application, uses it for all 18 of its packages. The
  parser read only the inline `Version` attribute, so every one of them parsed
  with an empty installed version, there was no drift to score, and the VERSION
  column rendered as a bare arrow. Resolution now walks up from the project
  directory to the nearest `Directory.Packages.props`, expands `$(Property)`
  references against that file's own `<PropertyGroup>` elements, honours
  `<ManagePackageVersionsCentrally>`, and lets a `VersionOverride` on the
  reference win over the central declaration. Nothing is guessed: MSBuild
  conditions are not evaluated, `<Import>` chains out of the props file are not
  followed, and a floating `1.2.*` or an open-ended range names a version only a
  restore could produce. Anything unresolved — including the common case of a
  single `.csproj` fetched without its props file — is reported as `unmanaged`
  and its version-drift signal is excluded from both numerator and denominator
  rather than scored as zero drift.

- **The NuGet analyzer now collects the signals every other ecosystem does.**
  It read a latest version and stopped, so it never set a repository URL and
  every repository-derived signal — staleness, health indicators, the five
  OpenSSF-style checks, community, license — was permanently unmeasured for
  every .NET dependency. Each package's own published `.nuspec` is now read for
  `<repository>`, the license expression, the declared authors, and the
  package's own dependencies, and the registration catalog is read for the
  publication date and the deprecation / unlisted markers. `<repository>` is
  preferred over `<projectUrl>` because a project URL is routinely a
  documentation site rather than a repository. **.NET scans will now report risk
  levels and scores where they previously reported `UNKNOWN`**, so a scan diff
  across this version can show large movement without anything having changed
  upstream. Measured against eShopOnWeb's `src/Web/Web.csproj`: 18 of 18
  `UNKNOWN` at 2.0 of 14 measured signals becomes 18 scored (7 MEDIUM, 11 LOW)
  at 13.9 of 14, with 18 of 18 versions resolved. The same manifest scanned
  alone, without its props file, still scores 18 of 18 at 10.2 of 14 with every
  version honestly reported as `unmanaged`.

  Every nuget.org read is fenced the way #128's Maven Central reads are: https
  and `api.nuget.org` only, redirects refused, ids and versions validated
  against NuGet's grammar before they become a URL path, bodies streamed and
  abandoned past 4 MiB, and a hard per-manifest fetch budget. The one URL that
  arrives inside a payload — a registration index's overflow page — is
  re-validated against the same host before it is fetched.
  `DEPENDENCY_RISK_NO_REMOTE_POMS=1` disables remote reads for NuGet too.

- **Maintenance cadence is now read from the registry first, and abandoned
  packages are scored instead of shrugged at.** Staleness was derived from the
  package's *repository*, which fails on exactly the packages the signal exists
  to catch: the more abandoned a package is, the more likely its repository is
  archived, renamed, deleted, or was never declared, so the more likely the
  lookup returned nothing and the dependency fell through to `UNKNOWN` with no
  cadence at all. `nose`, `pycrypto` and `distribute` each reported
  `staleness=None` — `pycrypto` while carrying two counted CRITICAL advisories.
  Every registry publishes when the package last shipped, and that answer
  cannot be broken by a repository rename, so it now wins and repository
  activity fills in only where the registry published no date. PyPI's per-file
  upload timestamps and `yanked` flag are read for the first time; npm's
  release date comes from the latest-tagged version rather than `time.modified`
  (which moves whenever any metadata changes, and reads July 2026 for a package
  last published in February 2020); Packagist, crates.io and RubyGems keep the
  dates they already read but stop having them overwritten by a clone. **Scores
  change for any dependency whose repository was unreachable, and shift
  slightly for the rest**, since release cadence and last-commit date are not
  the same number. Where a registry genuinely publishes no date the signal
  stays unmeasured (#74) rather than defaulting.

  Two supporting changes. PyPI's repository lookup now prefers a labelled
  `Source`/`Repository` project URL, trims it to its `owner/repo` root, ignores
  funding and issue-tracker links, and treats `home_page` — `None` on every
  modern package — as a genuine last resort instead of a way to mask a missing
  source URL. And "declares no source repository" is now a measured signal in
  its own right rather than a silent cause of `UNKNOWN`: a package that no
  longer says where its source lives is a leading indicator, and because that
  one fact explains why the seven repository-derived signals are quiet, it is
  no longer counted as seven separate gaps in the evidence. Packages with no
  declared repository — `phpstan/phpstan` on Packagist, all three abandoned
  PyPI packages above — now receive a risk level.

  The description-substring deprecation heuristic is gone. On a modern package
  `info.description` is the whole rendered README, so any project documenting a
  deprecated API of its own tripped it, and it still caught only one of five
  known-deprecated packages. It is replaced by `info.yanked` plus a strictly
  additive check of the one-line `info.summary`, which keeps the one true
  positive without the README's false-positive surface.

- **Maven dependencies that inherit their version now resolve it.** Java
  projects overwhelmingly declare a dependency without an inline `<version>`
  and inherit it from `<dependencyManagement>` — the project's own block, a
  parent POM's, or an imported BOM. WebGoat pins 4 of 46 inline. The parser
  read only the inline form, so the installed version was blank for the rest,
  the VERSION column rendered as a bare arrow, and there was no drift to score.
  Resolution now follows Maven's rules across the project's own block, the
  parent POM chain, and `<scope>import</scope>` BOMs (each resolved in its own
  property scope), fetching parent POMs and BOMs from Maven Central. Every
  remote read is fenced: https and `repo1.maven.org` only, redirects refused,
  coordinates validated before they become a URL path, bodies streamed and
  abandoned past 2 MiB, bounded parent and import depth, a per-manifest fetch
  budget, and a per-import allowance so one sprawling vendor BOM cannot spend
  it all. Set `DEPENDENCY_RISK_NO_REMOTE_POMS=1` to keep resolution offline;
  anything still unresolved is reported as `unmanaged` and its version-drift
  signal is excluded from both numerator and denominator rather than scored as
  zero drift.

- **The Maven analyzer now collects the signals every other ecosystem does.**
  It read a latest version and stopped, so it never set a repository URL and
  every repository-derived signal — staleness, health indicators, the five
  OpenSSF-style checks, community, license — was permanently unmeasured for
  every Java dependency. Each artifact's own published POM is now read from
  Maven Central for `<scm>`, `<licenses>`, and the artifact's shipped
  dependencies, and repositories are cloned once each rather than once per
  artifact (twelve Spring Boot starters share one repo). **Java scans will now
  report risk levels and scores where they previously reported `UNKNOWN`**, so
  a scan diff across this version can show large movement without anything
  having changed upstream. Measured against WebGoat's `pom.xml`: 46 of 46
  `UNKNOWN` with 502 unmeasured signals becomes 29 scored (2 HIGH, 14 MEDIUM,
  13 LOW) with 172 unmeasured; against OWASP wrongsecrets, 43 of 43 `UNKNOWN`
  with 444 unmeasured becomes 33 scored (2 HIGH, 19 MEDIUM, 12 LOW) with 103
  unmeasured.

- **An unresolved transitive dependency set is no longer scored as zero risk.**
  Transitive resolution only understands npm lockfiles and Python requirement
  sets; for every other manifest it logged `Could not extract dependency map`
  and left an empty set, which the scorer read as "no transitive dependencies,
  therefore no transitive risk". Unresolved sets are now marked unmeasured and
  excluded from the score (#74). **Scores can move in either direction for
  Maven, NuGet, RubyGems, Composer and Cargo manifests**, since one fabricated
  zero leaves the average and, for Maven, a real measurement replaces it. Two
  latent crashes on the same theme are fixed: the terminal report compared
  `deprecation_score` and `transitive_score` against a number without a `None`
  guard.

- **npm dependencies now report version drift.** `latest_version` was `None`
  for every npm dependency — 804 of 804 on OWASP NodeGoat's
  `package-lock.json` — so the version-drift signal, the one the tool leads
  with, was never computed for the largest ecosystem it supports. The registry
  data was fetched and then dropped on a shape mismatch: the packument at
  `registry.npmjs.org/<package>` has no top-level `version` key, because npm
  publishes the current release as `dist-tags.latest`. The adapter now reads
  `dist-tags.latest`, falls back to the `/<package>/latest` document for
  mirrors that omit dist-tags, percent-encodes scoped names
  (`@cypress/xvfb` -> `@cypress%2Fxvfb`), and **logs a warning when a lookup
  fails** — the failure was previously silent, which is why it survived. Two
  neighbouring reads of the same payload are fixed alongside it: deprecation is
  read from the version manifest where npm actually records it (the top-level
  `deprecated` key never existed), and repository URLs go through
  `canonical_repository_url`, so a `.git` substring inside a repository name no
  longer mangles the URL (`jekyll.github.io` -> `jekyllhub.io`). **npm scans
  will now show a version signal, and therefore different scores, for
  dependencies that previously had none.** Packages with no resolvable latest
  version keep the signal honestly unmeasured rather than scored at zero.

- **Go module paths now resolve to their source repository.** A module path is
  an import path, not a repository URL, and the resolver only understood the
  plain `github.com/owner/repo` form. Everything else — a `/vN` major-version
  suffix, a subdirectory module, a vanity import path — failed to resolve, so
  the dependency got *no* repository-derived signals at all. Measured against
  `gohugoio/hugo`'s `go.mod`, that was 93 of 180 dependencies (52%) with zero
  of ten signals, including `golang.org/x/net`, `golang.org/x/text` and the
  whole AWS SDK. One normalizer now applies the documented rules before any
  repository lookup: strip a trailing `/vN` (N >= 2); treat host plus the first
  two path segments as the repository on github.com / gitlab.com /
  bitbucket.org, with the remainder as a subdirectory; rewrite
  `golang.org/x/<name>` to its `github.com/golang/<name>` mirror without a
  network call; and resolve remaining vanity hosts from their `go-import` meta
  tag under strict bounds (hard timeout, response-size cap, redirect limit,
  public hosts only, prefix-cached so one lookup serves many modules).
  **Go scans will now report signals, and therefore risk levels and scores, for
  dependencies that previously came back `UNKNOWN`**, so a scan diff across
  this version can show large movement without anything having changed
  upstream. Modules that still do not resolve keep their signals honestly
  unmeasured rather than scored at a confident zero. As a side effect, each
  repository is cloned once per scan instead of once per module, so projects
  with many subdirectory modules from one repository do far less network work.

- **cargo and composer dependencies are scored instead of returning UNKNOWN.**
  Both adapters read a couple of fields off their registry and stopped, so the
  eight repository-derived signals — staleness, health indicators, license, and
  the five OpenSSF Scorecard-inspired checks — were never collected and every
  dependency tripped the `unmeasured > measured` bar. crates.io's `repository`
  and Packagist's `source.url` now resolve the source repository (trimmed to its
  `owner/repo` root, so workspace subdirectories and `.git` suffixes stop
  dropping it), release timestamps populate staleness, yanked/abandoned releases
  mark deprecation, and licence and maintainer counts come off the registry
  payload. **Manifests that previously reported nothing but UNKNOWN will now
  produce real risk levels**, so a scan diff across this version can show new
  findings without anything having changed upstream. Packages that genuinely
  publish no repository keep their repository-derived signals unmeasured rather
  than scored as zero. On real manifests: BurntSushi/ripgrep 0 of 13 scored →
  13 of 13 and tokio-rs/tokio 0 of 13 → 13 of 13, both going from ~5 of 14
  signals measured to 13; drupal/drupal 0 of 151 → 150 of 151, unmeasured
  signals down from 1371 to 158. The one package still `UNKNOWN`
  (`phpstan/phpstan`) publishes no source repository on Packagist at all, and
  the residual unmeasured signal on every dependency is `transitive`, which
  composer and cargo manifests have never resolved.

### Changed

- **More ecosystem spellings are now analyzed.** Analyzer dispatch is driven by
  the canonical ecosystem registry instead of a hand-maintained `if`/`elif`
  chain, so registry aliases the chain silently dropped — `java`, `dotnet`,
  `gems`, `node`, `py`, `pypi`, `go`, `ruby`, `php` — now route to the correct
  analyzer. **Scans that previously skipped dependencies under those spellings
  will now report findings for them**, so a scan diff across this version can
  show new results without anything having changed upstream. Every spelling the
  old chain accepted maps to the same analyzer as before, and unrecognized input
  is still skipped rather than raising.

### Fixed

- **Advisories are now matched against the installed version.** OSV is queried
  by package name, and every advisory it returned was counted toward
  `known_vulnerable` and scoring regardless of whether the installed version
  was in its affected range — the `affected` block was fetched and then
  discarded, so `affected_versions` was `None` on every advisory and no
  version filtering existed at all. A pin of Django 4.2 was counted for 153
  advisories including ones fixed in 1.3.4, 1.4.14, 2.0.3 and 4.0.4, and the
  CRITICAL driving its `max_counted_severity` and `has_known_exploits` flag had
  been fixed in 4.0.4, two minor releases earlier. Upgrading a package did not
  change its reading, which inverted the point of the tool.

  Affected ranges are now read from OSV's `affected[].ranges` event stream and
  `affected[].versions` enumeration and from GitHub Advisory's
  `vulnerableVersionRange`, and evaluated with **ecosystem-correct version
  ordering** — PEP 440, SemVer, RubyGems, Maven and NuGet each get their own
  comparator, because they order differently and a string or tuple comparison
  would quietly reintroduce the bug (`"1.10" < "1.9"` lexically; Maven sorts
  `1.0-alpha` below `1.0` but `1.0-foo` above it). Advisories ruled out carry
  the new `does not affect installed version` filter reason. Entries belonging
  to other packages in a multi-package advisory no longer bound this package's
  version.

  **Advisory counts drop sharply and `known_vulnerable` totals fall with
  them**, so a scan diff across this version will show large reductions
  without anything having changed upstream. On OWASP PyGoat: Django 4.2
  153 → 43 counted, Pillow 9.4.0 76 → 18, urllib3 1.26.9 19 → 8 (max severity
  CRITICAL → HIGH), cryptography 39.0.1 24 → 13. A fully patched pin now
  reports `has_known_exploits: false` instead of CRITICAL.

  Where applicability cannot be decided — no range in the advisory, no
  installed version, or a pin the ecosystem cannot parse — the advisory is
  still **counted**, and the reason is reported in the new
  `applicability_unknown` / `applicability_unknown_reasons` fields rather than
  being resolved by assumption in either direction (#74). The advisory disk
  cache carries a schema version, so entries written before this change are
  discarded on read instead of being scored for another day.
- **Calendar-versioned packages are no longer scored as SemVer.** A leading
  four-digit year in a date shape (`certifi 2022.12.7`, `pytz 2020.1`,
  `tzdata`, Go `vYYYY.MM.DD` tags) is now detected before version distance is
  computed, and drift is measured as elapsed time between the installed release
  and the latest release rather than as component distance. `certifi 2022.12.7`
  previously reported "4 major versions behind" and `pytz 2020.1` "6 major
  versions behind", warning about breaking upgrades that do not exist; they now
  read "3 years behind (calendar versioning)" and "6 years behind (calendar
  versioning)". **Version-difference scores drop for calendar-versioned
  dependencies**, most sharply for ones that are only months behind (previously
  a full major-version penalty, now scored on elapsed time), so a scan diff
  across this version can show lower scores without anything having changed
  upstream. When release timestamps are unavailable the drift signal is marked
  unmeasured and excluded from both the numerator and the denominator instead
  of being guessed at. SemVer packages and Go pseudo-versions
  (`v0.0.0-20210428235338-…`) are unaffected: detection requires the calendar
  *shape*, not merely a large leading number.

- **Unknown ecosystems no longer silently default to PyPI.** `infer_ecosystem`
  returned `"python"` for any URL it could not classify, so non-Python packages
  were queried against the wrong advisory source and came back clean. It now
  returns no ecosystem and the aggregators skip the dependency with a warning.

## [0.4.0] - 2026-08-01

### Changed

- **Scoring: the `maintained` signal now has its own tunable weight**
  (`maintained_weight`, default `0.20`). It previously reused
  `branch_protection_weight`, so the two OpenSSF Scorecard-inspired signals
  could not be tuned independently. Because this is a behavior-changing scoring
  default, **risk scores may shift for packages that expose both a
  branch-protection signal and a maintained signal.** The weight is wired
  through the config layer symmetrically with the other weights
  (`scoring_weights.maintained`).

### Fixed

- **Version-difference scoring no longer misclassifies hyphenated prereleases.**
  Installed versions containing `-` (for example `1.2.3-rc1` or Go pseudo-versions)
  were short-circuited to a flat `0.25` "version range" score. They are now parsed
  by real version distance, so a `2.0.0-beta` that is two majors behind scores as
  the major-version risk it actually is.
- **Staleness is now computed in UTC.** The last-updated timestamp is normalized
  to UTC (naive timestamps are assumed to be UTC) and compared against
  `datetime.now(timezone.utc)`, so staleness no longer varies with the host's
  local time zone.

[0.4.0]: https://github.com/williamzujkowski/dependency-risk-profiler/releases/tag/v0.4.0
