# The adapter-conformance harness

**What it is:** per-signal *value* assertions for each ecosystem adapter,
checked against payloads captured from the live registry and replayed offline.

**What it is for:** catching the dead-read class — an adapter that fetches the
registry successfully and then reads a key the registry has never sent.

Issues: [#73][73] (harness), [#145][145] (dead-read audit), [#160][160]
(ratified sequencing).

[73]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/73
[145]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/145
[160]: https://github.com/williamzujkowski/dependency-risk-profiler/issues/160

## The gap it closes

Five confirmed dead reads shipped in one session, each found by measuring an
ecosystem by hand. `testing/unit/signal_floors.py` already floors how many
signals an ecosystem measures, and since #158 names which ones. That catches a
signal going to `None`.

It cannot catch this one:

> npm read a top-level `deprecated` key that npm has never sent. The
> deprecation flag defaulted to `False`. `False` is not `None`, so the signal
> always read as **measured** — just always measured **wrong**. No npm package
> could ever be flagged deprecated, and every count stayed green (#142).

A count-based floor is structurally blind to it. What is not blind to it is an
assertion on the signal's **value**, against a fixture whose ground truth is
the branch the buggy code can never reach.

## The rule

> **Every signal whose read collapses to a fixed default when its key is absent
> needs at least one captured fixture where the correct answer is the
> non-default value, asserted by value.**

Those are the *polarized* signals: booleans and two-state enums.
`adapter_conformance.POLARIZED_SIGNALS` declares them per ecosystem with the
default value, the non-default value, and why the signal is polarized.
`test_every_polarized_signal_has_a_non_default_fixture` enforces it.

A branch the harness cannot prove is recorded as a waiver with a reason and
printed by `unproven_branches()`. A waiver is a gap someone has looked at, not
a gap that has been closed.

## Fixtures are captured, never authored

`test_nodejs_adapter` used to describe its payloads as "trimmed to the keys the
adapter reads". That sentence is the bug: a fixture trimmed to what the adapter
reads cannot, by construction, contain the key the adapter *should* read and
doesn't — the literal mechanism behind four of the five dead reads.

So: `scripts/capture_registry_fixtures.py` fetches from the live registry, and
reducers may drop **volume** but never **key diversity**. See
`testing/fixtures/registry/README.md` for the rule, the refresh cadence, the
ownership, and the security handling of captured payloads.

CI never touches the network. Capture is manual or run from the
`registry-fixtures` dispatch workflow; the suite replays recordings only, and
the replay fetcher raises on any URL it has no recording for.

## Verified to fail

A gate never observed failing is unverified (#153). This one was checked by
reintroducing #142 — making `NodeJSAnalyzer._is_deprecated` read a top-level
`deprecated` again — and running the suite:

| Gate | With #142 reintroduced |
|---|---|
| `test_signal_floors.py` (counts) | **passed** |
| `test_nodejs_adapter.py` floor + named-signal assertions | **passed** |
| `test_adapter_conformance.py` value assertions | **FAILED** on `nodejs/request` |

That is the claim, demonstrated rather than asserted.

## Status: 2 of 8 converted

| Ecosystem | State | Notes |
|---|---|---|
| **nodejs** | converted | 3 captured packuments. Proves the mechanism against #142's phantom top-level `deprecated`. |
| **rubygems** | converted | 2 gem payloads + owners docs. A *different* dead-read shape (#134: registry sends a `licenses` list, adapter read a `license` string), on the other side of `SCORES_FROM_REGISTRY_ALONE` from npm, and small enough to capture whole. |
| python | pending | Highest-value next one. #145 names PyPI as the ecosystem never audited against a live payload. |
| cargo | pending | Carried #139 (a *wrong-value* dead read — the third distinct shape). The one ecosystem where the deprecation non-default branch looks capturable. |
| composer | pending | Never closely audited. Packagist's p2 document needs a reducer like `npm-packument`'s. |
| nuget | pending | Multi-document; its catalog `deprecation` block is a real enum. |
| maven | pending | #141 left 10 of 11 signals structurally unreachable. Needs a `signal_floors` entry before it can have a value gate. |
| golang | pending | Uses `proxy.golang.org`, so both the reducer and the replay seam differ. Converting it first is what makes #160's narrowed-B migration verifiable. |

`adapter_conformance.CONVERSION_STATUS` carries the same table in code, and
`test_the_conversion_ledger_is_honest` stops it claiming more than it has.

## Converting the seventh ecosystem

1. Add its packages to `testing/fixtures/registry/manifest.json`. Pick at least
   a healthy one (the coverage-floor case) plus one per polarized signal whose
   ground truth is the **non-default** branch.
2. Add a reducer to the capture script if the document is version-keyed and
   large. Volume only.
3. `python scripts/capture_registry_fixtures.py --ecosystem <name>`, then read
   the captured payload. Compare every key it contains against what the adapter
   parses; a key the registry sends and the adapter ignores is a candidate dead
   read, and a key the adapter reads and the registry never sends is a
   confirmed one.
4. Add a driver to `adapter_conformance.DRIVERS` — the adapter's fetch seam
   stubbed with `replay_fetcher`, then license → community → scoring, cloning
   off and no token.
5. Declare `POLARIZED_SIGNALS[<name>]` and write the `FixtureCase`s.
6. Flip `CONVERSION_STATUS[<name>].converted` to `True`.
7. Reintroduce a dead read by hand and watch it fail before you believe it.

## Known limits

- The community signal is scraped off a GitHub repository page, not a registry
  document, so it is stubbed rather than captured. Out of scope for a
  *registry* fixture.
- The exploit signal is set by the vulnerability aggregator from OSV, so no
  registry payload can flip its non-default branch. #73's "known-CVE package →
  more than zero advisories, per ecosystem" regression test is the piece that
  would bring it under this harness.
- A reduced fixture cannot exercise a fallback path that depends on the dropped
  volume. Those keep their synthetic tests next to the adapter.
