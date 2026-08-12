# What the shipped composite is made of, measured on the full instrument

**Status:** pre-registered. Committed before any figure below the falsification
lines was computed.

## 0. Why this can be asked now and could not be before

`docs/composition-result.md` measured what the composite is made of and found
the activity loading small (rank-R² ≈ 0.099). `docs/lookup-table-result.md`
enumerated it and found a **twelve-cell lookup table** on maintainer band ×
repository state, with eleven distinct scores across 2,906 packages.

Both ran on signals **reconstructable at a past date**. At that date
`staleness` was 1.0 for every package, `version` 0.0 for every package, and the
six repository-derived signals were never computed at all. So both described a
three-signal object, and the lookup table was plausibly a property of the
*reconstruction* rather than of the tool.

The #385 cohort removes that limitation: 2,000 packages drawn uniformly, scored
**at a live T with the production collectors**, 928 of them with the repository
block actually computed. Nothing is reconstructed and nothing saturates.

A composition study has **no outcome**, so none of the four requirements that
closed the outcome landscape apply. It runs offline on the frozen record.

## 1. The claim under test

> The repository-derived block — 41.51% of the composite's declared weight, six
> of thirteen scored signals — materially changes the score, rather than adding
> weight that moves nothing.

This is the question the lookup table raised and could not answer. `license`
was already found to move the score in **zero of twelve cells** despite
carrying weight; a block can be declared and still be inert.

## 2. What is measured

On the frozen record `research/data/prospective-cohort/scored-at-T.json`:

1. **Resolution.** Distinct composite values, whole cohort and full-instrument
   subset.
2. **Enumeration.** Whether the composite is still a small lookup on maintainer
   band × repository state, and how many cells the full instrument occupies.
3. **Explained rank variance.** How much of the composite's rank ordering the
   registry-only inputs alone recover — maintainer count, release count,
   staleness band, deprecation, downloads.
4. **Cell occupancy.** The largest single cell's share, against the prior
   finding that one cell held 39% of the cohort.
5. **Movability.** Whether the manipulation result survives: the share of
   packages whose score can be lowered with no publish, recomputed with the
   repository block present.

## 3. Falsification lines — fixed before computing

1. **If the full-instrument subset has fewer than 30 distinct composite
   values**, the lookup-table finding survives contact with the real
   instrument, and §1's claim is refuted: the repository block adds weight and
   not resolution.
2. **If registry-only inputs recover the composite's rank ordering at
   rank-R² ≥ 0.90** on the full-instrument subset, the repository block is
   decorative — it moves the number without moving the order, and §1's claim is
   not made.
3. **If the largest cell still holds ≥ 30% of the full-instrument subset**, the
   enumeration finding stands in substance even if the value count rose.
4. **If the full-instrument subset is smaller than 500 packages**, no claim is
   made about the block, because the subset is the thing under test.

## 4. What either result licenses

**Refuting §1** would mean the repository block — the larger share of declared
weight, six signals, and the entire reason the tool clones anything — is
inert or near-inert. That would make the clone step, its cost, and the
manipulation surface it opens (#388: an unverified self-declared URL) very hard
to justify.

**Supporting §1** licenses only this: *the block changes the score.* It says
nothing about whether the change is an improvement, because this study has no
outcome. A block can add resolution and predict nothing — that is precisely
what the abandonment result found for the composite as a whole.

## 5. Named hazards

- **The full-instrument subset is not a random half.** Clone failure correlates
  with abandonment, so this subset is enriched for still-alive packages. Every
  figure here is conditional on being computable, and says so.
- **Resolution is not information.** A score with 212 distinct values and a
  score with 11 can order packages equally badly. §1 is deliberately narrow.
- **One ecosystem, one T.**
