# Withdrawn claims

**Status:** authoritative registry. `testing/unit/test_withdrawn_claims.py` reads
this file and fails the build if a withdrawn figure appears anywhere in `docs/`
or `README.md` without a withdrawal marker beside it.

## Why this exists

Three separate times, a claim corrected in one place has survived in another:

1. The lookup-table result **scoped itself correctly** — title, first line and
   limits section all said *registry-only* — and the headline still travelled
   into the README and into working notes without the qualifier.
2. The 928/928 abstention flip was withdrawn in a new section of the same
   document while the original table kept asserting it.
3. The 53.6% abstention figure was corrected in the protocol's §14 and left
   standing in §12, four hundred lines earlier.

The pattern is not carelessness about the correction; it is that **a correction
is written where the author is looking, and the claim lives wherever it was
cited.** Vigilance has now failed three times, so this is a mechanism instead.

## How to use it

When a claim is withdrawn, add a row. The `figure` is a distinctive literal
string — a number with its formatting, not a word — that appears in the
withdrawn claim and would not appear innocently elsewhere. Then either delete
every occurrence or annotate each one with a marker word: **withdrawn**,
**artifact**, **refuted**, **corrected**, or **superseded**.

Deleting is usually wrong. Leaving the original text in place with a marker is
what makes a correction legible to someone reading later.

## The registry

| figure | claim | withdrawn by | why |
|---|---|---|---|
| `928 / 928` | every cloned package abstains without the repository block | PR #420 | the harvest performed 8 of 13 registered signals; the omissions caused the abstentions, not the block |
| `53.6%` | the tool declines to issue a verdict for over half a uniform draw | PR #420 | same cause; measured as registered, **no package abstains** |
| `0.5360` | as above, in decimal | PR #420 | same |

<!-- Rows are read by the test; keep the figure in the first column and inside
     backticks. A row whose figure never appears anywhere is fine — it means
     the claim was fully removed. -->
