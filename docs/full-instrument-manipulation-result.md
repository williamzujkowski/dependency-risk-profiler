# How much of the composite is attacker-controlled? — result

**Protocol:** `full-instrument-manipulation-protocol.md`, approved 6-1.
**Registers:** #386.

---

## First, the framing the review made binding

**This is how repository-health scoring works, generally.** OpenSSF Scorecard,
deps.dev and Libraries.io all read a repository link the package declares, and
none of them verifies that the repository belongs to the package either. Nothing
below is a claim that this tool is uniquely defective.

What is specific to this tool is the **concentration**, and that is what was
measured.

## The load-bearing number

**48.33% of the composite's declared weight is computed from a URL the package
chooses and nobody verifies.**

| block | weight |
|---|---:|
| repository-derived (8 signals) | **1.45** |
| registry-derived (6 signals) | 1.55 |
| total | 3.00 |

Read from the scorer's constructor rather than retyped, so a re-weighting
changes this figure instead of leaving it stale. The partition is complete —
zero unaccounted signals.

Eight of fourteen signals, and nearly half the weight, come from whatever
`repository` names.

## Criterion 3 ran first, and did not narrow the claim

The review asked that the verification audit precede any scoring, since a
positive result would shrink the claim before it was made.

**No package-to-repository binding check exists anywhere in the codebase.**
`record_source_repository` assigns `DECLARED` when a URL canonicalizes to an
`owner/repo` root on a supported host. Nothing downstream compares the
repository's owner against the package's maintainers, looks for a reciprocal
reference, or consults provenance. All eight signals stay in scope.

## The arithmetic ceiling — an upper bound, not an attack

| arm | normalised score | verdict issued? |
|---|---:|---|
| one maintainer, **no repository declared** | **1.0000** | no — `insufficient_data` |
| same package, **declaring an unrelated healthy repository** | **0.1290** | **yes** |

**Normalised drop: 0.8710.** Eighty-seven percent of the scale, for one URL
string.

**This is deliverable (b) and it is a ceiling.** It asserts that a substituted
healthy repository reads healthy on all eight signals rather than cloning one
and observing it, so it measures the scorer's arithmetic under maximally
favourable inputs. Its value is narrow but real: it shows the aggregation
composes linearly rather than clamping the repository-derived channel, which
the weight share alone cannot establish.

Falsification line 2 asked for a drop of at least 0.3. It is reported for
completeness and **it is not an independent test** — given a 48% weight share
the bar was very nearly arithmetically guaranteed, and treating its passage as
confirmation would be theatre.

## The finding I did not expect

Look at the verdict column.

**Declaring an unrelated repository flips the tool from abstaining to
answering.** The package with no repository is `insufficient_data` — the tool
correctly says it cannot tell. Add one unverified URL and it issues a confident
near-floor score.

So the URL does not merely lower the number. **It manufactures the confidence to
report one.** That compounds the earlier finding that two constant signals
decide the abstention rate from 100% to 73.9%: the sufficiency bar counts
measured signals, and eight signals sourced from an attacker's chosen URL count
exactly as much as eight observed independently.

## What this licenses

*Nearly half this composite's weight is computed from a URL the package
controls and nobody verifies, and supplying one can move the score most of the
scale while converting an abstention into a verdict.*

It does **not** license "the tool is being gamed" — no evidence of exploitation
was offered or sought. It does not say the eight signals are badly built: read
against a repository that genuinely belongs to the package, they may measure
exactly what they claim. **The finding is about who chooses the input.**

## The causal step, now measured — and the premise was wrong

The reviewer who voted to reject said the middle step was assumed: *does a real
substituted repository actually read uniformly healthy?* It was, and it does
not. Running three production collectors against `ossf/scorecard` — the
OpenSSF's own security-scoring project, about as healthy as a repository gets:

| collector | measured | risk score |
|---|---|---:|
| security policy | present | **0.79** |
| branch protection | present | **0.30** |
| signed commits | **unmeasured** | — |

Not one of the three reads clean. **The 0.8710 ceiling above is not reachable
by pointing at a good repository**, and it should be read as the arithmetic
bound it was labelled as, nothing more.

**Realised drop from those three collectors alone: 0.7333.** And that is the
finding worth having, because it survives the premise being wrong:

> **An attacker does not need a healthy repository. They need any repository.**

A substituted repo scoring 0.79 on security policy is still an enormous
improvement over declaring none, because "no repository" scores 1.0 — the top
of the scale. Substitution pays even when the substitute is mediocre.

**Correction to the section above.** The abstention flip reported there came
from the constructed arm, where eight signals were asserted measured. With
three collectors actually run, the package **remains `insufficient_data`**. The
flip therefore requires enough of the suite to clear the sufficiency bar, which
a real run would do and this partial one does not. The claim as originally
written was broader than what has now been measured.

## Limits
- **Detection is unmodelled.** A package pointing at `facebook/react` is
  trivially spotted by a human and by nothing in the tool.
- **The fix is not obvious.** npm provenance and a reciprocal reference in the
  repository are both partial and neither is universal. This is a statement of
  the trust boundary, not a demand that it be closed tomorrow.
