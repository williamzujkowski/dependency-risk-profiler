# Can the score lead? — pre-registration

**Status:** **rejected 5-2 on review and restructured.** Claim A runs as
registered. Claim B is split: its analytic half is settled below and comes out
**false**, and its empirical half is deferred to #378 because the pinned
snapshot cannot falsify it. No trajectory was ever computed.
**Registers:** #379.
**Date fixed:** 2026-08-11, against `main` at 52ddcdf.

---

## 0. The question the project is named after, asked directly

`dependency-risk-profiler` argues that **leading** indicators beat lagging
ones. Five outcome studies asked whether the score *predicts*, and the
programme closed without an answer that survived (`outcome-landscape.md`). A
composition study then asked what the score *is* and found it is not an
activity proxy (`composition-result.md`).

Neither asked the prior question. **A leading indicator has to move before the
thing it indicates.** A number that never changes, or that changes only
simultaneously with the event, cannot lead anything regardless of how well it
correlates with anything.

That is a property of the score's *dynamics*, it needs no outcome, and it is
exactly computable from the pinned snapshot. If the answer is no, every
prediction study in this repository was asking a question the instrument could
not answer, and the five failures have a common cause rather than five causes.

## 1. The two claims under test

**Claim A — the score is a finite lookup table.** The registry-only composite
is a deterministic function of a small number of categorical inputs, so "what
it measures" is enumerable in full rather than estimable.

**Claim B — the score cannot move for a package that has gone quiet.** Its
inputs are read from the version document in force, which changes only when the
package publishes. So between publishes the score is frozen, and after a final
publish it is frozen forever.

B is the one that matters. If it holds, then for the population a risk tool
most needs to warn about — packages going silent — **the score is a constant**,
and no amount of signal improvement changes that.

## 2. Method — exact, not statistical

Everything runs offline against `research/data/npm-2026-08-06`.

**For claim A**, enumerate. Score every cohort member and record the tuple of
inputs the scorer actually read. If the map from input tuple to score is a
function — every tuple always yielding one score — the table is published whole
and the claim is settled by exhibition rather than by a statistic.

**For claim B**, build a trajectory. Score every package at **annual T from
2018-08-01 to 2024-08-01**, using the release in force at each T, and record:

- how many packages ever change score across the seven observations
- for those that do, whether each change coincides with a publish between the
  two dates
- the fraction of packages whose score is constant over the entire window
- the same, restricted to packages that published nothing after 2022 — the
  going-quiet population the tool exists to flag

## 3. Falsification lines — fixed now

1. **If any input tuple maps to more than one score**, claim A is false and the
   table is not published; the composite depends on something not enumerated
   and the study says so.
2. **If more than 20% of packages change score without an intervening
   publish**, claim B is false: something moves the score other than
   publishing, and that something is identified before anything else is
   reported.
3. **If fewer than 20% of packages ever change score across seven years**, that
   is reported as the headline whatever else is found, because a score that is
   constant for most packages over most of their lives cannot lead.
4. **If the going-quiet subset changes score at a rate indistinguishable from
   the rest**, claim B is false in the way that matters and the write-up says
   so plainly.

## 4. What a confirmation licenses

It licenses: *the registry-only score is a lookup table over slow-moving
categorical inputs, and it is frozen for exactly the packages a risk tool most
needs to speak about.*

It does **not** license any statement about the repository-derived signals,
which this arm cannot reconstruct, or about live runs where `staleness` moves
with wall-clock time (#376). Both limits are load-bearing and are stated in
every table.

**The `staleness` caveat is the interesting one and it is not a rescue.** In a
live run `staleness` does move for a silent package — it is the one signal that
does. But `staleness` is *time since last release*, which is the definition of
going quiet rather than a leading indicator of it. If the only thing that moves
is the restatement of the event, the tool reports the present in a risk score's
clothing.

## 5. Named hazards

- **One ecosystem, one snapshot.** npm, and the same 2,906-package cohort as
  every other study here.
- **Seven annual observations is coarse.** A score that oscillates within a
  year reads as constant. This biases *toward* claim B, so a confirmation is
  weaker than it looks and a refutation is stronger; both are stated.
- **The cohort is alive at T.** Packages that never existed before 2018 enter
  the trajectory late, and their pre-existence observations are excluded rather
  than filled with a score nobody could have computed.

---

## 6. What the review changed: claim B was unfalsifiable, and is also false

Rejected **5-2**, and the panel's objection is the one §5 invited under attack
point 3. It is worth stating in full because it is the fourth appearance of
this repository's oldest defect.

### The registered method tested itself

Falsification line 2 says B is false if more than 20% of packages change score
without an intervening publish. **That line can never fire.** The
reconstruction reads the version document *in force at T*, so a reconstructed
score changes only at publish events **by construction of the method**. Line 2
does not test the tool; it tests the reconstruction against its own definition.

Line 4 fails the same way. The going-quiet subset is *defined* as publishing
nothing after 2022, so under the reconstruction its post-2022 score is constant
by definition. The comparison was rigged toward confirming B before any data
was read.

**Two of four pre-registered falsifiers were vacuous.** That is exactly the
mechanical coupling that killed four of the five outcome studies, re-imported
into a study whose entire premise was that it had escaped the outcome
programme's traps by not having an outcome.

### And the claim is false anyway, which the code settles without a sweep

The panel asked for the analytic half to be discharged by reading the scorer
rather than by seven years of scoring. Doing that answers the question outright:

- **The reconstruction** reads `maintainers` from the **version document**,
  which is frozen at publish.
- **The live tool** reads `npm_data["maintainers"]` — the packument's
  **top-level** array, which is npm's *current* state and which
  `npm owner add/rm` mutates **with no publish at all**.

So for the shipped tool, `maintainer_count` **can** move for a package that has
gone completely quiet. Claim B is false, and it is false on the one signal that
matters: `maintainer` is the only member of the composite carrying
discrimination against abandonment, and the only member with a meaningful
activity association (ρ = +0.268).

**That inverts the study's expected finding into a more useful one.** The
tool's single load-bearing signal is also its single genuinely lead-capable
one — it can change before anything is published, or after publishing has
stopped forever. Everything else is frozen at last publish except `staleness`,
which moves only by restating the event.

### What that costs the reconstruction, stated plainly

If the live tool reads current top-level maintainers, then **every historical
maintainer count this repository has reconstructed is a different quantity from
the one the shipped tool computes**. The research arm reads a frozen per-version
array; the product reads a mutable current one. They agree only for packages
whose ownership never changed. That does not invalidate the abandonment result
— which was always explicit about reading version documents — but it does mean
the two are not the same signal, and no document said so until now.

### What runs, and what does not

**Claim A runs as registered.** Every reviewer approved it: exact, offline,
cheap, with a crisp falsifier, and it settles "what the composite measures" by
exhibition. Result in `lookup-table-result.md`.

**Claim B's empirical half is deferred to #378.** Making it falsifiable needs
data the pinned snapshot does not carry: the packument's `time.modified`
(snapshot-visible evidence of a non-publish mutation, which the reduction
dropped) and current top-level maintainer sets to compare against the frozen
per-version ones. That is a bounded ~2,906-request harvest, and it is not run
here because a protocol whose refuter cannot fire should not be executed while
it is being repaired.
