# Repository ownership transfer — pre-registration

**Status:** pre-registered and revised twice, before any package outside the
existing snapshot has been fetched. Design review (7-0 approve with conditions)
in §11; detection-procedure review (**7-0 reject**, with the defect and its fix)
in §14; the pilot that must clear before any harvest in §15.
**Registers:** #368. Fifth protocol, after abandonment (ran), compromise
(halted stage 1), handover (halted stage 3) and the repository arm (ran, no
claim licensed).
**Date fixed:** 2026-08-11, against `main` at 4c9c78b.

---

## 0. Why this outcome, when four others failed

`outcome-landscape.md` records that coupling — requirement 3 — is the
requirement that actually bites. Its closing line asks that any fifth outcome
be tested for independence from project activity **before** being tested for
anything else.

That test has been run, on data collected for another study:

| | release cadence at T scores against it |
|---|---:|
| abandonment | **0.7346** |
| **ownership transfer** | **0.5104** |

Release cadence is the construct the abandonment protocol ablated as circular,
and it predicts abandonment at 0.73. Against transfer it is a coin.

It escapes the other two structural failures by construction rather than luck:

- a **positive event**, not the absence of one, so there is no "absence of X
  predicted by the rate of X" — the flaw that turns out to bound attempt 1
- a **binary transfer**, not a set difference, so no cardinality confound
  (attempt 3) and no censoring by publishing activity

## 1. The cohort must be fresh, and this is not negotiable

**The existing snapshot cannot be used.** Its transfer answers were computed
during the handover study's stage 7 and have been looked at: the composite
scores 0.4955 and commit cadence 0.5455 on it. A protocol written after seeing
that, run against the same data, would be pre-registration in name only.

So this runs on a **new sample from the same frame** — `all-the-package-names`,
4,314,619 npm names, the frame the 2026-08-06 snapshot drew from — **excluding
every package in that snapshot**.

## 2. The claim under test

> Signals measured at T identify packages whose GitHub repository changes owner
> by the harvest, better than trivial baselines do.

Narrow, and deliberately not "predicts risk". A transfer is not an attack and
not an abandonment; #312's reading was that the score measures the
*precondition for a handover*, and this is the closest measurable form of it.

## 3. Outcome

**Positive** = the owner in the GitHub URL declared by the release in force at
T differs from the owner the GitHub API returns today, which resolves transfers
and renames transparently.

Fixed now, because each has already bitten something:

- **A name GitHub cannot have is UNPARSEABLE, not a transfer and not a
  deletion.** #360 fixed a parser that returned `bar.git#main` as a repository
  name; conflating those categories inflated a survivor-bias estimate once
  already.
- **A 404 is unresolvable, not "no transfer".** GitHub reports deleted and
  private identically, so both are excluded and counted, never folded into a
  negative.
- **One T only.** The comparison is against current state, so it says *changed
  by the harvest*. Same limitation as the handover redesign, stated in every
  table.

## 4. Power, fixed before the harvest

Measured on the existing cohort: base rate **5.6%**, clustered bootstrap SE of
a single-arm AUC **0.0299** at 104 positives.

SE scales roughly as 1/sqrt(positives), so the **target is 400 positives**,
giving SE ≈ 0.0152:

| | MDE at 400 positives |
|---|---:|
| against chance | 0.0427 |
| paired arm difference, ρ = 0.8 | 0.0270 |
| paired arm difference, independent | 0.0604 |

**That target requires roughly 10,000 sampled packages** — 5.6% base rate,
~73% declaring a GitHub repository, ~91% of those resolvable.

**Stop rule: if the assembled cohort yields fewer than 250 positives, the MDE
is recomputed and published before any model is scored**, and a null below it
is reported as uninformative rather than as absence. The trigger is the
**support of the analysis producing the primary endpoint**, not the sampled
count — the wording amendment 1 of the repository-arm protocol had to make
after getting it wrong.

## 5. Control validity — stage 0, on the assembled cohort

`validation-protocol.md` requires a negative control shown non-degenerate on
the actual cohort before the protocol is accepted. This cohort does not exist
yet, so the requirement is discharged in two parts:

1. **The control is specified now**: a global label permutation, 200 rounds.
   Not a within-cluster shuffle — the handover study's cohort averaged 1.33
   members per maintainer component and its within-cluster control preserved
   96.6% of labels, returning the observed model AUC and firing backwards.
2. **It is validated on the assembled cohort before any outcome is read**, and
   the run halts if the mean falls outside [0.47, 0.53] or label preservation
   exceeds 0.75.

**No stratified control is specified, because no stratified endpoint is.** See
§6.

## 6. The primary endpoint is unstratified, deliberately

The repository arm's primary was within-download-stratum, and that choice cost
it: npm answers download counts for every unscoped package and about a fifth of
scoped ones, so the stratified endpoint described a population 73% unscoped
where the cohort was 65% scoped, and **the effect reversed sign** on the
excluded half.

Here the confound that justified stratifying is absent — popularity is not
known to drive ownership transfer, and release cadence, the activity proxy,
scores 0.5104. **So the primary is the whole cohort, unstratified**, and
download count enters as a trivial baseline rather than a stratifier.

If popularity turns out to predict transfer, that is a finding and it is
reported; it is not a reason to restratify after the fact.

## 7. Signals and baselines

**Signals**: the shipped composite as it stands, plus each of the five
repository-derived signals the repository arm reconstructed, individually.
`community_popularity` remains unmeasured — GH Archive is ~6.6 TB and the one
queryable mirror starts 2023-01-13, so a truncated window is a proxy and §4b of
the repository-arm protocol forbids one.

**Trivial baselines**: downloads at T, package age, dependency count,
maintainer count, and **release cadence at T** — included precisely because it
is the activity proxy, and its 0.5104 here is the claim that this outcome is
independent. If it beats the composite, the independence claim is wrong and
that is the finding.

## 8. Falsification lines — fixed now

1. **If the composite does not exceed the best trivial baseline by ≥0.05**, on
   a maintainer-clustered paired bootstrap with the interval excluding zero,
   the claim in §2 is not made.
2. **If the negative control is not clean**, nothing from the run is reported.
3. **If one signal carries the whole effect**, that is the finding, reported
   per-signal rather than folded into a composite claim.
4. **If the composite does not exceed chance by more than the MDE**, it is
   reported as not discriminating this outcome — which, given §0, is the
   result this study most plausibly produces.
5. **Beating chance is not sufficient to license anything.** The composite must
   exceed **both** downloads at T **and** release cadence at T by the paired
   MDE. Clearing chance while losing to a free number is exactly how the
   abandonment result went, and a success path that does not exclude it
   repeats it.

## 9. What a null means — fixed now

**A null means the signals do not predict ownership transfer at this cohort
size**, and — because this is the only outcome measured to be independent of
project activity — it is the strongest available evidence for the reading that
**the signals detect activity rather than risk**.

That reading would then be supported by: signals scoring at chance here, and
scoring above chance only against outcomes that release cadence alone predicts
at 0.73.

**It would not establish it.** One ecosystem, one T, one outcome, and "detects
activity" is an inference from a pattern across studies rather than a measured
quantity. The write-up says that.

The withdrawn README claim (#330) stays withdrawn under every branch.

## 10. Named hazards

- **Transfer is rare.** 5.6% means the positive class is small and every
  interval will be wide. That is why §4 fixes a target rather than hoping.
- **Org migrations cluster.** `elmsln → haxtheweb` moved 4 packages at once.
  Intervals cluster on maintainer, and the count of distinct (source,
  destination) pairs is reported beside the nominal positive count.
- **Detection is one-directional.** A repository transferred and then
  transferred back reads as no change.
- **The GitHub API is the instrument.** Rate limits, and a 404 that means
  private rather than deleted. Both are counted, not inferred.
- **Vanity-org moves are not handovers.** `antfu → antfu-collective` is the
  same person reorganising. The outcome cannot distinguish that from a genuine
  handover, and no attempt is made to; the write-up says the outcome is
  *ownership transfer*, not *change of responsible party*.

---

## 11. What the review changed, before any harvest

Approved 7-0 with binding conditions. All adopted. The three that change what
the study can conclude are first.

### The success path was under-specified because I expect a null

Falsification line 4 pre-commits to publishing "no discrimination", and I said
plainly that is the likely result. Review pointed out the consequence: **the
positive branch was the loosely-specified one**, which is the garden of forking
paths a contaminated analyst leaves open without noticing.

**Line 5 now requires beating both trivial baselines**, not chance. Clearing
chance while losing to download count is precisely how the abandonment result
went; a success path that does not exclude it repeats it.

### Construct validity — the gap the three requirements do not cover

"Ownership transfer" is statistically clean and **semantically heterogeneous**.
A handover to an unknown individual and adoption by a foundation are
opposite-valence events pooled under one label; `antfu → antfu-collective` is
one person reorganising.

**So a positive result licenses "predicts ownership transfers" and not
"predicts risk", and that wording is fixed now rather than negotiated later.**
Requirement 3 is cleared syntactically; semantically the label is a mixture,
and no attempt is made here to unmix it.

### Detection and dating are unspecified, and that is the handover failure's shape

GitHub redirects conflate user renames, org renames, and true transfers.
Worse: **detection probability may itself correlate with activity**, which
would re-couple the outcome to the activity proxy *through the measurement
channel* even though the construct is clean.

Fixed: the detection procedure is written and tested on synthetic fixtures
**before** harvest, distinguishing rename from transfer where the API allows
and counting the residue as its own category. If that residue exceeds 20% of
positives, the outcome is reported as unmixable at this precision.

### The remaining conditions

1. **Freeze and hash the protocol and the composite specification** before
   fetching. Temporal ordering must be provable from git, not asserted.
2. **Exclusion is at repository and maintainer-cluster level, not package
   name.** A fresh package name mapping to a repository already in the old
   snapshot is not fresh.
3. **Re-verify cadence ≈ chance on the fresh cohort as a stage gate.** The
   0.5104 that motivated this whole design was measured on seen data; if it
   does not reproduce, the rationale is gone and the study halts.
4. **Recompute effective clusters on the fresh cohort.** The 1.05 ratio is
   inherited from the old one and the stop rule keys on the new count.
5. **Scoped/unscoped sensitivity split**, reported and explicitly
   non-claim-licensing — sign reversal by population is this project's
   demonstrated failure mode and the point is to detect it, not to let it
   define the endpoint.
6. **This is the capstone, not episode five of a series.** Either branch
   completes `outcome-landscape.md` and no protocol six follows from a null
   here.

### What did not change

The fresh-cohort requirement, the unstratified primary, and cadence as an
adversarial baseline. On contamination the review's position was that I am
contaminated as a *designer* — the 0.5104 that motivated this outcome came from
seen data — but not as an *estimator*, which is what a frozen protocol on fresh
data prevents. That distinction is recorded rather than assumed, and condition
3 is what makes it checkable.

---

## 12. The freeze, made checkable rather than asserted

Condition 1 says the protocol and the composite specification are frozen before
harvest. Written down, that is another bar with nothing checking it — the defect
this repository keeps finding in itself. So it is discharged with an artifact.

`research/frozen/transfer-outcome/risk_scorer.py.frozen` is a byte copy of
`src/dependency_risk_profiler/scoring/risk_scorer.py` taken at freeze time. The
`.frozen` suffix is load-bearing: under a `.py` name mypy type-checks the copy
as first-party source and fails on its now-unrooted relative imports. A frozen
artifact is data, and naming it as data is a smaller lie than adding a tool
exclusion that says the repository does not check one of its own Python files.

```
sha256  b836582833fa7cd4838e2cec7aa6b413f46bcb9849c602bb1e6f48dc2dca0973
```

`test_the_frozen_composite_spec_still_matches_its_recorded_hash` recomputes it
on every run. If the frozen copy is edited the test fails, so the freeze is
tamper-evident rather than promised.

**Drift in the shipped scorer is deliberately not a failure.** The frozen copy
is the thing under test; ordinary maintenance of the shipped module must stay
possible. What the freeze buys is that at harvest time it is checkable, from
git alone, whether the scorer being scored is the scorer that was pre-specified
— and if it is not, that fact is recorded in the write-up instead of discovered
afterwards.

---

## 13. Where the detection procedure lives

Condition 3 of §11 requires the detection procedure to be written and
fixture-tested before harvest. It is `research/transfer_study/detect.py`, with
`testing/unit/test_transfer_detection.py` as its fixtures.

**This section adds no specification and moves no threshold.** The categories
and the 20% ceiling were fixed in §11 before the code existed; this records
where they are implemented so the freeze is checkable against something. The
one thing worth reading twice is the discriminator, because the obvious
procedure is wrong:

`GET /repos/{owner}/{repo}` follows renames, org migrations and true transfers
identically and returns the current `full_name` in all three cases, so comparing
owner *logins* counts a maintainer who renamed their account as having handed
the project to a stranger. Logins are mutable and reusable; numeric account ids
are neither. The procedure compares ids, and where the login declared at T no
longer resolves to any account it returns AMBIGUOUS rather than guessing — that
is the residue the ceiling caps.

Verified by mutation: replacing the id comparison with a login comparison fails
four fixtures, so the fixtures test the thing the module exists to prevent
rather than merely covering its lines.

---

## 14. The procedure was rejected 7-0, and what replaced it

The detection procedure of §13 went to review as a pre-harvest artifact and
came back **rejected, unanimously**. The defect is worth recording in full,
because it is the same defect this repository keeps producing in new clothes.

### The id at T was never observed

The procedure discriminates rename from transfer by comparing account **ids**,
on the sound reasoning that logins are mutable and ids are not. But a registry
URL carries a **login**, not an id, and nothing in the snapshot records the id
the declaring account had at T. Every id-at-T in the procedure therefore came
from resolving that login *today* — and GitHub does not redirect user profiles
after a rename. The old login either 404s, or **someone else has registered
it**.

That second case resolves cleanly to a live account with a different id, and
the procedure called it a transfer. A false positive, sitting inside the
positive class, where the ambiguity gate cannot see it: the gate counts cases
the procedure *admits* it could not resolve, never cases it resolved wrongly.
And freed logins are claimed on popular projects, so the contamination is
**activity-correlated** — the coupling the id discriminator exists to prevent,
re-entering through its own resolution step.

The fixtures did not catch it because they fed ids straight to the classifier.
They verified the decision table; they could not verify that the table's inputs
are obtainable. **A value that satisfies its declared type and lies about the
fact** — this project's signature defect, arrived at from a new direction.

### What changed

- **A creation-date guard.** An account created after T cannot be the account
  that declared the repository at T, so a resolved-today id whose account
  postdates T is AMBIGUOUS, not a transfer. Missing creation dates fail the
  guard rather than pass it.
- **Necessary, not sufficient, and reported as such.** An account older than T
  can also claim a freed login. Positives resolved this way carry their
  provenance and are reported as their own stratum.
- **Ids known as of T skip the guard.** An event archive records actor id
  beside login at event time; that id needs no caveat, and the procedure
  distinguishes the two sources instead of treating them as equal.
- **The same-login branch checks the id too.** A deleted login, re-registered,
  with the repository recreated under it, previously read UNCHANGED — the most
  security-relevant ownership change there is, filed as the negative class.
- **Attrition is published beside the ambiguity gate.** Deletion is not random:
  a repository goes away more often when the project was let go, so the
  exclusion rate is reported whatever it is.
- **Owner type change is counted.** A user account converting to an
  organisation keeps its id and reads UNCHANGED. The outcome cannot see it;
  `type` rides along in a response already fetched, so the limitation is
  quantified rather than asserted.

Two of these are mutation-verified: disabling the creation-date guard fails two
fixtures, disabling the same-login id check fails one.

## 15. The mechanics pilot, and its decision rule — fixed before it runs

The 20% ceiling was chosen with no data on the true ambiguity rate. Every
reviewer said the same thing: measure the channel before spending the harvest,
or the halt condition is first evaluated after paying for it in full.

**The pilot runs on the burned cohort.** Resolution rates, 404 rates and
re-registration rates are properties of GitHub's API, not of any particular
sample, and the 2026-08-06 snapshot is already exploratory — its transfer
answers were computed and read during the handover study. §1 excludes every
package in it from the fresh frame, so a pilot there **cannot** contaminate
the confirmatory cohort. That is not an argument that the leakage is small; it
is that the two populations are disjoint by construction.

**The pilot reads bucket counts only.** No score is joined to a pilot row, at
any point, for any purpose. What it estimates is a nuisance parameter of the
instrument.

**The decision rule, fixed now:**

1. Estimate the ambiguity share with a 95% Wilson interval on the observed
   owner changes.
2. **Upper bound ≤ 0.20** — the resolved-today channel is adequate. Proceed
   with the registered gate.
3. **Point estimate > 0.20** — the channel cannot support the outcome. The
   study proceeds only with ids known as of T, or is declined and reported as
   unmeasurable at this precision. It does not proceed by lowering the gate.
4. **Interval straddles 0.20** — enlarge the pilot within the burned cohort
   until it does not, up to that cohort's supply of owner changes. If the
   supply is exhausted with the interval still straddling, treat it as case 3.

Case 3 is the one worth naming out loud: it ends five attempts with the
instrument, not the hypothesis, as the thing that failed. That is a publishable
result and it is written down here **before** the number exists, which is the
only time such a sentence is worth anything.
