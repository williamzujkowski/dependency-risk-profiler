# Maintainer handover — stages 1 and 2

**Status:** executed. Protocol: `docs/handover-outcome-protocol.md`, §10 steps 1
and 2 only. **Stopped at the stage-2 gate by instruction**, not by a stop rule —
all three gates passed. No negative control, no baselines, no model, no AUC.
**Date run:** 2026-08-11. **T = 2024-08-01**, the single T the protocol fixes.

Artifacts: `research/data/handover-2026-08-11/`
(`maintainers-current.jsonl`, `MANIFEST.json`, `stage2.json`).
Code: `research/handover_study/`.

---

## Cohort

Reproduced exactly from the pinned snapshot `research/data/npm-2026-08-06`
(digests verified on load) via `build_cohort(snap.packages, T, 2,
snap.harvested_at)`: **2,906 members**, matching the count §3 quotes. 1,877 of
them (64.6%) are scoped names, so the URL-encoding clause is not a formality.

Exclusions, for the record: `already_dormant_at_T` 2,251,
`younger_than_one_year_at_T` 751, `too_few_releases_before_T` 221,
`no_release_before_T` 11.

## Stage 1 — harvest

`registry.npmjs.org` only, no mirror. 8 threads behind a single global pacer at
one request start per 0.09s; the run held **11.1 req/s** end to end and drew
**zero 429s**. Descriptive User-Agent carrying `grenlan@gmail.com`. Each record
archives the extracted `maintainers` array plus a SHA-256 of the raw response
body, per amendment 1 — 617 KB rather than the several gigabytes the pre-
amendment text would have committed.

| | n | share |
|---|---:|---:|
| HTTP 200, usable `maintainers` array | 2,905 | **99.966%** |
| HTTP 200, `maintainers` present but empty | 1 | 0.034% |
| any other failure category | 0 | 0 |

**Gate — resolution ≥ 90%: PASSED**, at 99.97% on the strict reading. There
were no 404s, no timeouts, no throttles, no unparseable bodies. Every category
that failure could have taken is empty.

The one exception is `@liskhq/lisk-bft`: the registry answers 200 with a
well-formed packument whose top-level `maintainers` is `[]`. That is a state,
not a fetch failure — every maintainer has been removed. It is recorded under
its own disposition and **excluded from the denominator** rather than counted
as a positive, which is the conservative choice: an empty set is trivially
disjoint from any frozen set, so admitting it would add 1 to `any change`, 1 to
`lost`, and 1 to `complete turnover`, and the last of those is the definition
the protocol already calls underpowered. It moves no number that matters.

## Stage 2 — base rate, sub-definitions, effective n

Positive = the maintainer set frozen into the release in force at T
(`maintainers_at(record, member.index_at_t)`, carried on `CohortMember`)
differs from the harvested current top-level set. Both sides are normalised
identically — sorted, deduplicated usernames, emails dropped — by a function
written to mirror `abandonment_pilot.harvest._maintainer_names`, so a
reordering by the registry cannot read as an ownership change.

Denominator 2,905.

| definition | count | rate | clusters spanned |
|---|---:|---:|---:|
| **any change** (primary) | **662** | **0.2279** | **473** |
| gained | 505 | 0.1738 | 380 |
| lost | 465 | 0.1601 | 318 |
| both gained and lost | 308 | 0.1060 | 225 |
| complete turnover | 39 | 0.0134 | 36 |

Directional split of the 662: 197 gained only, 157 lost only, 308 both.

### Nominal positives against effective n

| | n |
|---|---:|
| nominal positives | **662** |
| **effective maintainer clusters spanned** | **473** |
| (contrast) clusters recomputed over positives alone | 475 |
| clusters in the whole resolved cohort | 2,176 |

Clusters are the connected components of the **whole cohort's** shared-
maintainer graph at T, as `maintainer_clusters` builds them and as the
abandonment pilot's bootstrap resamples them. Recomputing components over the
positive subset alone drops the non-positive packages that bridge two positive
components, which can only split components and inflate the effective n; it is
reported (475) purely to show the gap is 2, not an order of magnitude.

The collapse ratio is **1.40 positives per cluster**. This is the number the
compromise backtest failed on, where 2,074 nominal cases collapsed to 43 — a
ratio of 48. Nothing of that kind happens here.

### Gates

| gate | threshold | observed | verdict |
|---|---:|---:|---|
| resolution rate | > 90% | 99.97% | **PASSED** |
| nominal positives | ≥ 200 | 662 | **PASSED** |
| **positive maintainer clusters** | **≥ 150** | **473** | **PASSED** |

All three passed. Execution stopped here by instruction.

## Check 1 — is the rate consistent with ~14.5%, or are these renames?

The censored version-document rate from #342 is 14.5%. The uncensored rate is
**22.8%**, a ratio of **1.57×**. That is the direction and roughly the
magnitude §3 predicts: removing the publishing-activity censor should expose
changes in the quiet 40% of the cohort that a version-document comparison
cannot see. It is nowhere near the >40% that §9 says should trigger suspicion
before belief.

Three further checks, none of which the protocol required but each of which
could have caught a rename artefact masquerading as a result:

1. **The classic rename signature** — a solo-maintained package whose single
   account is replaced by a single different account — occurs **18 times**,
   2.7% of positives. Reading them individually, they are a genuine mix:
   `phphe` → `php_he` and `vilic` → `vilicvane` are plainly the same person
   renaming, while `vinaysd17` → `dhan-oss` and `blueking` →
   `blueking-magicbox` are individual-to-organisation transfers, which is
   precisely the event the study wants to count.
2. **The generalised signature** — exactly one account out, exactly one in, at
   any set size — occurs **66 times**, 10.0% of positives. This is a hard
   **upper bound** on the rename contribution, and the hand-inspection above
   suggests the true figure is roughly half of it.
3. **No systematic artefact.** The most frequent gained account,
   `microsoft-oss-releases`, appears in 16 of 662 positives (2.4%) and is a
   real org migration. No npm infrastructure or bot account
   (`npm`, `types`, `npm-cli-ops`, `google-wombot`) moves anywhere in the
   cohort. Exactly one positive touches a `~`-prefixed deleted-account marker.

The 10% upper bound sits right at the §7 ceiling, which is worth flagging now:
§7 requires a hand-audit of ~50 positives before any *absence* claim, and if
misclassification exceeds 10% a null is reported as uninformative. That audit
is stage 7 and was not run. What stages 1-2 establish is that the ceiling is
about 10% and the likely value is materially below it — not that the audit can
be skipped.

**Verdict: the rate is believable. Renames are present, bounded, and cannot
account for the result.**

## Check 2 — maintainer-set size distribution

| | at T | now |
|---|---:|---:|
| solo (exactly 1) | 1,701 (58.6%) | 1,682 (57.9%) |
| 2-4 | 724 (24.9%) | 769 (26.5%) |
| 5+ | 480 (16.5%) | 454 (15.6%) |
| median | 1 | 1 |
| p90 | 7 | 6 |
| max | 106 | 116 |
| mean | 3.39 | 3.13 |

**This cohort is majority solo-maintained** — 58.6% have exactly one account at
T, and the median package has one at both ends. It is not a cohort of teams,
and the distribution is heavily right-skewed: a long tail out to 106 accounts
does most of the work in the mean while the median stays at 1.

Two consequences worth carrying into stage 3 and beyond. First, for a solo
package `gained`, `lost`, and `complete turnover` are close to the same event,
so the sub-definitions are far less independent of each other here than the
five-way split implies. Second, the distribution barely moved in two years
(mean 3.39 → 3.13, the 5+ band shrinking slightly), so the aggregate is nearly
static while 22.8% of individual packages changed. Net size change is zero for
2,336 of 2,905 packages: churn is happening inside a stable size profile, not
as growth.

## Deviations from the protocol as written

**None on anything the protocol specifies.** Two judgement calls the protocol
does not cover are recorded here rather than left implicit:

1. **Empty current `maintainers` array.** Not anticipated by the outcome
   definition, which contrasts two sets and does not say what an empty one
   means. Handled as described above: excluded, not folded into "no change",
   and its effect on every reported number stated (±1 on three definitions).
2. **Which graph defines a cluster.** §5 says "clustered on maintainer, as the
   abandonment pilot is", which fixes the method but not whether the graph is
   built over the cohort or the positives. Both are reported; the gate is read
   against the full-cohort graph because that is the pilot's convention and the
   conservative of the two.

`bandit` is not installed in this worktree's venv and was not run; a missing
tool prints nothing, which reads exactly like a pass. `ruff` and `mypy` were
run and both are clean over `research/handover_study/`.
