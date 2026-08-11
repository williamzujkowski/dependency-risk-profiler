# Handover study — stage 7, the misclassification audit

**Registers against:** `handover-outcome-protocol.md` §7 and §10 stage 7.
**Run:** 2026-08-11, before stages 3–6 reported.
**Result: both error rates are under the 10% ceiling. §7's condition is satisfied.**

§7 withholds any "evidence of absence" claim until two unmeasured error rates
are bounded, and fixes a **10% ceiling** above which a null is reported as
uninformative rather than as absence. This is that measurement.

It was run *before* the model results existed, deliberately. An audit that
decides how much error is tolerable after seeing whether the result was
positive is not an audit.

---

## 1. False positives — npm account renames

A rename makes the same human appear as a different maintainer, so the outcome
records a change that did not happen.

Stage 2 measured the *signature* — one account out, one account in — at
**10.0% of positives**, sitting exactly on the ceiling. A signature is an upper
bound on renames, not a count of them, so it had to be resolved.

**Method.** The 66 signature cases give 59 distinct account pairs. For each,
ask whether the old account still maintains anything:
`registry.npmjs.org/-/v1/search?text=maintainer:<user>`. The direct user
endpoints are anti-bot blocked — `/-/user/org.couchdb.user:<name>` returns 401
and `npmjs.com/~<user>` returns 403 for every name, including ones that plainly
exist — so the search API is the available instrument.

The discriminator works: `alcalzone` → `mcm1957` shows both accounts alive with
305 and 318 packages. Two real people, one handover, no rename.

| | n |
|---|---:|
| distinct account pairs | 59 |
| old account still maintains packages → **transfer** | 29 |
| old account maintains nothing | 30 |

"Maintains nothing" is not "renamed". It conflates a rename with someone who
left npm and handed everything over — which is a real event and exactly what
this study wants to detect. Separating the 30 by handle similarity:

| pair | reading |
|---|---|
| `phphe` → `php_he` | rename |
| `vilic` → `vilicvane` | rename |
| `haajutran` → `hautranit` | rename |
| `shibanet0` → `~shibanet0` | npm's **deleted-user marker**, not a rename |
| `emannuell_instacarro` → `gabrielgomesinstacarro` | shares a company suffix, personal names differ — probably two employees |

The other 25 are unambiguous departures: `dabeeeenster` →
`flagsmithengineering`, `sosa-vaadin` → `sissbruecker`, `charlie.wilson` →
`ishitaprakash`.

**False-positive rate: 5 / 662 = 0.76%** of positives — and that is an upper
bound, since two of the five are not renames. The true figure is nearer 0.45%.

**The 10.0% signature overstated the problem by more than an order of
magnitude**, because most one-out-one-in changes are genuine handovers.

---

## 2. False negatives — GitHub transfers with no npm change

A project can change hands on GitHub while the npm owner list stays put. The
outcome cannot see it.

**Method.** The GitHub API resolves transfers and renames transparently:
`GET repos/<owner>/<repo>` returns the *current* `full_name` however the
repository moved. Comparing the owner declared at T against the owner the API
returns today detects a transfer directly.

All 1,749 distinct repositories declared by the 2,066 cohort packages that
named one (monorepos share repositories). 1,586 resolved, 163 gone.

| | npm UNCHANGED | npm changed |
|---|---:|---:|
| GitHub owner unchanged | 1,429 | 340 |
| **GitHub owner CHANGED** | **76** | 29 |

**False-negative rate: 76 / 1,874 = 4.06% [95% CI 3.25%, 5.05%].**

A finding in its own right: a GitHub owner change occurs for only **5.60%** of
packages, and only 29 of those 105 coincide with an npm maintainer change.
**Repository custody and publishing rights move largely independently.** Anyone
treating one as a proxy for the other — including a future study — should not.

---

## 3. The gate

| error | rate | denominator |
|---|---:|---|
| false positives (renames) | **0.76%** | of 662 positives |
| false negatives (GitHub transfer, npm unchanged) | **4.06%** | of 1,874 with a resolvable repo |

Both under 10%. **§7's condition is satisfied**, and a null from this study may
be reported as evidence of absence — scoped, as §7 requires, to the
operationalisation rather than the construct.

**The two rates are deliberately not summed.** They sit on different
denominators: one is a fraction of the positive class, the other a fraction of
a cohort subset. A combined figure would look precise and mean nothing.

---

## 4. Limitations

- **192 packages had unresolvable repositories** — 9.3% of those declaring one,
  mostly deleted or private. A deleted repository plausibly correlates with
  abandonment, so this subset is **not missing at random and the false-negative
  rate may be understated.**
- Only the **71% of the cohort declaring a GitHub repository at T** can be
  checked at all. The rest have no repository side to compare against.
- A repository transferred and then renamed back to its original owner would be
  missed. Implausible, but the method cannot see it.
- Non-GitHub forges are out of scope, as they are for the tool generally.
- Handle similarity is a judgement, not a measurement. The five rename
  candidates are listed individually so the judgement can be checked rather
  than taken on trust.
