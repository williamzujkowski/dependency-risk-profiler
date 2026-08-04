# Agent & Contributor Instructions

**Status:** Authoritative. These rules bind humans and AI agents equally.
**Scope:** Everything in this repository.

`CLAUDE.md` covers build commands and code style. This file covers what may *land*.

---

## Why this file exists

A hardening pass found roughly twenty defects of one kind, and none of them were caught by review, by tests, or by CI:

- A code-signing subsystem whose docstrings said *"In a real implementation, this would…"* — a fresh random key per call, `sha256(hash + key)` in place of a signature, a malware scan hardcoded to return clean — **called by `release.yml` on every tagged release**, publishing `.sig` files and notes claiming the release was "cryptographically signed".
- A scoring branch that could never execute, with **four passing tests** supplying data the pipeline never produces.
- `commit_frequency` read in six places, its producer never called once.
- Unmeasured signals scored as a confident `0.0`.
- Five cases of an adapter reading a key its registry never sends — silently `None` forever.

None of these were incompetence. Each was a reasonable local decision that nothing forbade. This file is what forbids them.

---

## The rules

### 1. No simulated implementations

**A function does what its name says, or it does not exist.**

`sign_artifact` signs. `scan_for_malware` scans. If you cannot build the real thing right now, **file an issue and land nothing.** A placeholder that returns a plausible value is worse than an absent function, because callers will trust it — and in this repo, one did, for every release.

*"In a real implementation…"*, *"Simulate…"*, and *"For now, return…"* are never acceptable in merged code.

### 2. Rescope, don't stub

Scope being too large is normal and fine. The correct response is to **split it, land a smaller piece that is completely correct, and file the remainder with concrete acceptance criteria.**

The incorrect response is to land the whole shape with the hard parts hollowed out. Never leave a placeholder hoping someone catches it later — nobody catches it, and the hollow version acquires callers.

A partial feature that is honest about its boundary beats a complete-looking one that isn't.

### 3. Landed code must be reachable

A new function needs a caller. A new field needs a writer *and* a reader. A new signal needs an adapter that records it.

**Unreached code does not land.** Dead code is worse than absent code: every future reader has to re-derive that it is dead, and tests written against it give false confidence. This repo carried a 189-line module with zero callers and a scoring branch whose only "coverage" came from tests supplying data production never sends.

Before merging, ask: *what calls this, and what breaks if I delete it?* If the answer is "nothing", delete it.

### 4. Silence is not an answer

"We could not measure this" must be **structurally distinct** from "we measured it and it was zero". Not by convention — by construction.

- A measurement that is unmeasured cannot carry a value.
- Recorders take **required** arguments, so a state cannot be set by omission.
- An absent marker reads as *unmeasured*, never as a default.

Scores exclude unmeasured signals from both numerator and denominator. That is what keeps the tool honest — and it is also why a silently-missing signal produces no visible symptom. Assume nothing will alert you.

### 5. Conformance fixtures are captured, never authored

**Scope: conformance fixtures only** — the ones asserting we read a registry correctly. **Adversarial fixtures must be authored**: malformed payloads, hostile values, and error paths cannot be captured from a cooperating registry. Keep them in a clearly labelled separate set; this rule does not apply to them.

For conformance fixtures: capture from the live registry. Reducers may drop **volume** (190 of 200 release entries), never **key diversity** — the keys the adapter does *not* read are exactly the ones that reveal the next dead read.

A hand-written fixture encodes the same wrong assumption the parser makes, so the test passes and proves nothing. A test here named `test_an_explicit_deprecation_block_is_honoured` passed for months while no package in that ecosystem could ever be flagged deprecated: the fixture carried the key *because the parser looked for it*.

Provenance-date every fixture. Capture is a dispatch job; the suite replays recordings and never touches the network.

### 6. Verify that a gate bites

Reintroduce the defect and confirm the gate fails. Then revert.

**A gate never observed to fail is unverified.** This repo has had: a mypy configuration exempting eleven modules, with a test *asserting the exemptions stay in place*; a test that ran an absent binary and therefore always passed; a Dependabot config rejected wholesale so nothing ran, including security updates; and a conformance harness that marked a signal on the adapter's behalf.

Prefer assertions on **values** over assertions on **counts**. A count cannot distinguish "always measured correctly" from "always measured wrong".

### 7. The bar

- No `# type: ignore`, no `# noqa`, no new `# nosec`. `src/` is at zero of the first two; keep it there.
- No **new** `Any`. The repository carries 82 across eight modules — stated as banned, never enforced, because mypy's `disallow_any_explicit` was never set. They are frozen by a ratchet and the honest number is written down rather than wished away.
- `mypy` clean, and the first-party exemption list stays **empty**.
- Ratchets only move **down**.
- No new dependencies without an explicit, argued exception.
  - **Never hand-roll cryptography.** Signing, verification, and key handling go through an audited primitive (sigstore, minisign, age) via the exception path — which exists for exactly this and is meant to be used. Hand-rolled parsing is fine; hand-rolled crypto is how the fake signer gets rebuilt "for real" and badly.
  - The bar is *argued exception*, not *never*. A rule that makes the honest answer unavailable produces a dishonest one.
- Never commit `uv.lock`.
- Run `uv sync --extra dev` before testing — without it, `uv run` can silently import the package from another checkout and your tests pass against someone else's source.

---

## These rules have teeth

Rule 6 says a gate never observed to fail is unverified. A file of prose is exactly that, so the mechanically checkable rules are enforced in CI by `testing/unit/test_repository_rules.py`:

| Rule | Check |
|---|---|
| 1 — no simulated implementations | Fails on stub markers in `src/` (`in a real implementation`, `for simulation purposes`, `simulate ...ing`, `always clean in this example`) |
| 3 — landed code must be reachable | Fails on a module-level function or class in `src/` with no reference outside its own definition |
| 7 — the bar | Fails on `# type: ignore` or `# noqa`; fails on a first-party `ignore_errors` entry; **ratchets `Any` down** |

Each check was verified to fail before it was committed, by reintroducing a specimen of the defect it catches. Rules 2, 4 and 5 are review-time judgment and are honestly marked as such — not every rule can be mechanised, but a rule that *can* be and isn't is just a wish.

**On `Any`: the bar said "no `Any`" and nothing enforced it.** mypy's `disallow_any_explicit` was never set, so 82 uses accumulated across eight modules. Rather than weaken the rule or claim a zero that isn't real, the current count is recorded as a ratchet that only moves down. The first run of these checks also found a 40-line function with no reference anywhere in `src/` or `testing/` — deleted in the same change.

**A check that fires on legitimate work is a bug in the check.** Fix the check or argue the rule; do not silence it.

---

## On ponytail

We use [ponytail](https://github.com/DietrichGebert/ponytail) minimization: prefer the reuse rung, fix root causes, delete rather than accumulate, and add no abstraction that was not requested.

**Read "minimum" as minimum *mechanism*, never minimum *finish*.**

Choose the smallest design that **fully solves** the problem. Never choose a partial solution in order to build less. "Deletion over addition" governs code that is **not reached** — it is not licence to under-build code that is.

Ponytail did not cause the defects above; it is what removed them. But it can be misread as permission to do less, so this is stated explicitly.

**The no-new-dependencies rule did not cause them either, and this was checked rather than assumed.** A reviewer argued the simulated signer was exactly what an agent produces when it must ship signing but may not import a signature library — Python's stdlib has no asymmetric crypto, so the fake would have been dep-avoidance. The dates falsify it: `secure_release/code_signing.py` was created **2025-04-16**, and no dependency policy has ever existed in this repository — neither `CONTRIBUTING.md` nor `CLAUDE.md` contains one. The rule postdates the fake by fifteen months and was never written down at all.

The concern remains valid *forward*, which is why the crypto carve-out above exists.

---

## When you disagree

If a rule here blocks work that should happen, **say so and argue it** — in the PR, in the issue, or by putting it to a consensus vote. Several decisions in this repo were improved by an agent refuting the brief it was given: a proposed fix disproved with endpoint evidence, a design reframed after finding only two of nine bugs were what it claimed to address, a budget reported as badly set rather than quietly moved.

Refuting the task is a valid and valuable outcome. Silently doing a lesser version of it is not.
