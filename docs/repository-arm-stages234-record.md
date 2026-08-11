# Repository arm — stages 2, 3 and 4

**Registers against:** `repository-arm-protocol.md`.
**Run:** 2026-08-11. **All gates passed.**
Stages 5–7 were not run: no model AUC, no registry-only baseline, no ablations
were computed anywhere.

---

## Gates

| gate | threshold | observed | result |
|---|---|---:|---|
| stage 2 resolution | ≥ 60% | **90.8%** | **pass** |
| stage 3 per-signal measurement | ≥ 50% of the arm | five at **99.7%**, `community_popularity` at **0%** | five pass; one reported unmeasured |
| stage 4 primary control (within-download-bin) | mean in [0.47, 0.53] | **0.5013** | **pass** |
| stage 4 secondary control (global permutation) | same | **0.4992** | **pass** |

`community_popularity` at 0% is the §4b rule working rather than a gate firing:
the signal is reported unmeasured because it could not be reconstructed
honestly, not imputed to keep a count up.

## Stage 2 — resolution

2,066 of 2,906 cohort packages declare a parseable GitHub repository at T,
across 1,749 distinct repositories. The coverage split reproduces §6 exactly:
73.4% GitHub, 24.1% none, 2.4% another host.

- repositories: **1,587 / 1,749 = 90.74%**
- packages: **1,875 / 2,066 = 90.76%** of GitHub-declaring, 64.5% of the cohort

**Every failure was one category:** `not_found`, 162 repositories / 191
packages. GitHub reports deleted and private identically, so the two cannot be
separated. Zero timeouts, zero size-cap trips, zero blocked.

### A parser defect found by reconciliation

The shipped `extract_github_repo_info` anchors on end-of-URL, so a fragment
survives `.git` stripping: `git+https://github.com/foo/bar.git#main` returns
`bar.git#main` as the repository *name*, which is a string GitHub cannot have.

Using it directly gives 2,109 packages / 1,785 repositories. Rejecting names
that violate GitHub's own charset rules gives exactly **2,066 / 1,749** — the
protocol's numbers.

Those 43 packages are counted as **unparseable**, which is a different fact
from **deleted**. Folding them together would have inflated the deletion rate
and, through §6, the estimate of survivor bias. Filed separately as a defect in
shipped code, because every downstream GitHub call built from such a pair 404s
and the repository signals silently report unmeasured.

Against the handover stage-7 artifact there is a one-repository difference each
way: that artifact contains `GIT_USER_ID/GIT_REPO_ID`, an unsubstituted
template placeholder that 404s, and omits the real `LiskHQ/lisk-sdk`. Hence 191
unresolvable here against §6's 192 — reconciled, not drift.

## Stage 3 — signal reconstruction

Five signals at **1,869 / 1,875 = 99.68%** of the arm: `health_indicators`,
`security_policy`, `dependency_update`, `community_activity`, `maintained`.
Read failures: 5 `no_commit_before_T`, 1 `git_read_failed`.

**`community_popularity` is unmeasured and was not proxied.** §5 requires
cumulative GH Archive `WatchEvent` to T from 2015 — about 84,000 hourly files,
~6.6 TB. The one queryable public mirror begins **2023-01-13**, covering 566 of
3,500 days (16.2%), and a truncated window understates precisely the
long-established repositories the 100/1000/5000-star thresholds separate. That
is a proxy, and §4b forbids one. No current star count was substituted, which
is the leak the rule exists to prevent.

## Stage 4 — the negative control, before any model result

| control | rounds | mean | min | max | label preservation |
|---|---:|---:|---:|---:|---:|
| within-download-bin (primary) | 200 | **0.5013** | 0.4411 | 0.5656 | **0.561** |
| global (secondary) | 200 | **0.4992** | 0.4556 | 0.5325 | — |

Preservation 0.561 against the handover control's degenerate 0.966, and
matching §0's 0.566 — it genuinely permutes.

The primary statistic is the **unweighted mean of the five within-bin AUCs**,
which is how the 0.539 bar was computed. A pooled AUC under within-bin
permutation would not collapse to 0.5, because the preserved popularity–outcome
association holds it up; the two are not interchangeable.

## §6 — post-outcome conditioning, measured rather than admitted

| subset | n | clusters | abandoned | rate |
|---|---:|---:|---:|---:|
| resolvable (studied) | 1,875 | 1,352 | 744 | **39.68%** |
| unresolvable, declared GitHub | 191 | 150 | 84 | **43.98%** |
| not studied, any reason | 1,031 | 879 | 432 | 41.90% |

The difference runs in the predicted direction — survivors are less abandoned —
at **−0.043, maintainer-clustered 95% interval [−0.185, +0.096]**.

**The interval spans zero on 191 packages across 150 clusters.** So this is
directionally as §6 predicted and *not resolvable at this size*. It is
emphatically not "no bias": the study is still conditional on survival, and the
measurement bounds how large the effect could be rather than showing it absent.

## Sizes

Arm: **1,869 nominal, 1,348 maintainer clusters** (largest 127), base rate
39.70%. Within-download-bin support: **979 nominal, 849 clusters**, 401
positives, roughly 195 per bin.

## Two things stage 5 must carry

1. **The within-stratum endpoint's support is 979 packages, not 1,869.** npm
   answers download counts for about half the cohort, and the bins can only be
   cut on those. That is **below §4c's 1,000-package line**, which words its
   trigger as "the achieved cohort" — 1,869, which clears it — while the
   endpoint's actual support does not. This needs an explicit amendment before
   stage 5, not a judgement call during it.
2. **`maintained` is `commit*0.5 + release*0.3 + issue*0.2`.** §4b names commit
   activity as its only source, so release and issue were left at the shipped
   neutral 0.5, making `is_maintained` exactly `commit_score > 0.7` — about
   seven commits a month — which is True for 23% of repositories. Both other
   components *are* reconstructable at T, but §4b does not name them and adding
   release cadence would import exactly the autocorrelation §10 flags. Followed
   the text literally; flagging the consequence rather than deciding it.

## Verification

Suite **2,682 passed, 7 skipped**, coverage 85.63% against an 82.5% floor.
`mypy src research` clean over 114 files. `bandit` 1.8.6 via the system binary,
version printed so it is not a silent missing-tool pass.

**§10 hardening was verified rather than assumed.** The `RLIMIT_FSIZE` cap was
tested to actually fire (SIGXFSZ → `too_large`), and the test module asserts
`--` precedes the URL, plus `--bare`, `--no-recurse-submodules` and
`--filter=blob:none`, and that git is executed by the shell that took the
limit.

Stages 3 and 4 re-ran bit-identically after lint fixes.

## Clone storage

6.3 GB of bare blobless clones were written to `~/.cache/drp-repo-arm/clones`,
deliberately on the root filesystem rather than `/tmp`, which is a 32 GB tmpfs
with 12 GB free. Nothing downstream needs them: `signals.json` carries every
per-repository read.
