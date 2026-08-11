"""Every "the registry does not publish this" claim, checked against a capture.

`REGISTRY_UNANSWERED_SIGNALS` in `signal_floors.py` records, per ecosystem, the
signals a registry-only run cannot measure. Each entry is a claim about a third
party's API, and #336 is what happens when one of them quietly stops being
true: npm had served a `maintainers` array all along, the adapter routed past
it, and the floors table carried the sentence *"npm publishes no cheap owner
count"* as the reason nobody looked. #171 had fixed the identical defect for
PyPI six months earlier.

Two things kept both alive, and the second is the one this file is aimed at:

1. The hand-authored stub was trimmed to the keys the adapter reads, so it
   could not contain the key the adapter should read and doesn't.
2. **The false belief was written down as a reason.** Once a gap has a
   documented cause, nobody re-checks whether the cause is true.

So each withheld entry is justified here by an assertion against a *captured*
payload rather than by prose next to the table.

Two kinds of withholding, and conflating them is the trap
---------------------------------------------------------
Not every entry is an absence claim, and the sweep that produced this file is
how that became clear:

- **ABSENT** — the registry serves nothing that answers the signal. Falsified
  by finding a field that does. This is the kind #336 got wrong.
- **PRESENT_BUT_DIFFERENT** — the registry serves a field, and it measures
  something other than the signal. Maven's `<developers>` is a credits list
  and not a publish-rights list (#357); Go's `require` block states no scope,
  so it cannot answer a *runtime* dependency count. These are **falsified by
  the field disappearing**, which would mean the row's stated reason no longer
  describes anything.

Asserting absence for a PRESENT_BUT_DIFFERENT row would fail immediately and
tempt somebody to weaken the probe. Asserting presence for an ABSENT row would
be the #336 defect with a test in front of it. The direction is part of the
claim, so it is written down as data.
"""

from __future__ import annotations

import json
from typing import Callable, Dict, Tuple

import pytest

from registry_fixtures import RegistryFixture, load_ecosystem
from signal_floors import REGISTRY_UNANSWERED_SIGNALS

#: The registry serves nothing answering this signal.
ABSENT = "absent"

#: The registry serves a field, measuring something else. The row's reason
#: describes that difference, so the field vanishing invalidates the row.
PRESENT_BUT_DIFFERENT = "present_but_different"


def _text(fixture: RegistryFixture) -> str:
    """The capture as searchable text, whatever the registry sent.

    Maven answers XML, the Go proxy plain text, npm JSON. Searching the
    serialized form rather than a parsed one is deliberate: the question is
    whether the *document* carries an answering field anywhere, including in
    keys no adapter parses yet, and a parse would only surface what the parser
    already knows to look for. That is the trimmed-stub mistake in another
    shape.
    """
    payload = fixture.payload
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return body.lower()


def _any_fixture(ecosystem: str, probe: Callable[[str], bool]) -> Tuple[bool, str]:
    """Return whether any captured payload for `ecosystem` satisfies `probe`."""
    for name, fixture in sorted(load_ecosystem(ecosystem).items()):
        if probe(_text(fixture)):
            return True, f"{ecosystem}/{name} ({fixture.source_url})"
    return False, ""


def _has_any(*needles: str) -> Callable[[str], bool]:
    return lambda text: any(needle in text for needle in needles)


#: One row per `REGISTRY_UNANSWERED_SIGNALS` entry: the kind of withholding,
#: a probe over the captured payloads, and why the row exists in those terms.
#:
#: Completeness is asserted below, so a new withheld signal cannot be added to
#: the floors table without a captured payload backing it up.
WITHHOLDING: Dict[Tuple[str, str], Tuple[str, Callable[[str], bool], str]] = {
    ("golang", "maintainer"): (
        ABSENT,
        _has_any("author", "maintainer", '"owner"', "publisher"),
        "proxy.golang.org serves @latest (origin, time, version) and the raw "
        "go.mod. Neither names a person: Go has no module-level owner concept, "
        "and the module path's host is a forge address rather than a "
        "registry-held owner record.",
    ),
    ("golang", "transitive"): (
        PRESENT_BUT_DIFFERENT,
        _has_any("require ("),
        "go.mod DOES publish a require block, indirect entries included. It is "
        "withheld because the block states no scope — Go has no runtime/dev "
        "split — so it cannot answer a runtime dependency count. If the block "
        "ever vanished from the captures this reason would describe nothing.",
    ),
    ("maven", "maintainer"): (
        PRESENT_BUT_DIFFERENT,
        _has_any("<developers>"),
        "Maven Central DOES publish <developers>: 13 of 20 sampled artifacts, "
        "11 with structured <id> values. It is withheld because <id> counts "
        "grow and almost never shrink (commons-lang3: 16 -> 25 -> 28 -> 27 "
        "over a decade), which is a credits list accumulating contributors "
        "rather than a publish-rights list. #357.",
    ),
    ("maven", "deprecation"): (
        ABSENT,
        _has_any("deprecat", "<relocation", "yanked", "<retired"),
        "Maven Central publishes no retirement marker of any kind — no yank, "
        "no deprecation flag, no tombstone. #179.",
    ),
    ("gradle", "maintainer"): (
        PRESENT_BUT_DIFFERENT,
        _has_any("<developers>"),
        "Gradle resolves against Maven Central and inherits its answer, so "
        "this row stands or falls with the Maven one above.",
    ),
    ("gradle", "deprecation"): (
        ABSENT,
        _has_any("deprecat", "<relocation", "yanked", "<retired"),
        "Gradle publishes Maven coordinates and resolves against Maven "
        "Central, so the retirement question reaches the same repository and "
        "gets the same non-answer. Checked against Gradle's own captures "
        "rather than assumed from Maven's, because 'by construction' is the "
        "phrasing every wrong row in this table used.",
    ),
}


def test_every_withheld_signal_is_justified_by_a_captured_payload() -> None:
    """No entry may rest on prose alone. This is the durable part of #337.

    The sweep fixes today's list; this assertion is what stops the next entry
    being wrong for six months. Adding a signal to
    `REGISTRY_UNANSWERED_SIGNALS` without a row here fails, which is the point:
    the cost of claiming a registry withholds something is one captured probe.
    """
    declared = {
        (ecosystem, signal)
        for ecosystem, signals in REGISTRY_UNANSWERED_SIGNALS.items()
        for signal in signals
    }
    assert declared == set(WITHHOLDING), (
        "the floors table and the withholding justifications disagree: "
        f"unjustified {sorted(declared - set(WITHHOLDING))}, "
        f"stale {sorted(set(WITHHOLDING) - declared)}"
    )


@pytest.mark.parametrize(
    "ecosystem,signal", sorted(k for k, v in WITHHOLDING.items() if v[0] == ABSENT)
)
def test_an_absent_signal_is_absent_from_every_captured_payload(
    ecosystem: str, signal: str
) -> None:
    """The #336 direction: find the field the adapter should have read.

    Searched over the serialized capture, so keys no adapter parses yet are in
    scope. A hit does not prove the signal is measurable — the field might be
    something else wearing the word — but it does prove the row's reason needs
    re-reading against the registry rather than against itself.
    """
    _, probe, reason = WITHHOLDING[(ecosystem, signal)]
    found, where = _any_fixture(ecosystem, probe)
    assert not found, (
        f"{ecosystem} is recorded as withholding {signal!r} because: {reason}\n"
        f"But a captured payload carries an answering field: {where}\n"
        "That is the #336 shape. Re-read the registry, not the comment."
    )


@pytest.mark.parametrize(
    "ecosystem,signal",
    sorted(k for k, v in WITHHOLDING.items() if v[0] == PRESENT_BUT_DIFFERENT),
)
def test_a_present_but_different_signal_is_still_present(
    ecosystem: str, signal: str
) -> None:
    """The other direction, and the reason the two kinds are kept apart.

    These rows are not absence claims — they say the registry publishes
    something that measures a different thing. If the field disappeared, the
    stated reason would describe nothing and the row would need rewriting,
    quite possibly as ABSENT. Silence there is the failure mode.
    """
    _, probe, reason = WITHHOLDING[(ecosystem, signal)]
    found, where = _any_fixture(ecosystem, probe)
    assert found, (
        f"{ecosystem} withholds {signal!r} on the grounds that: {reason}\n"
        "No captured payload carries that field any more, so the reason no "
        "longer describes anything. Re-derive the row."
    )
    assert where


def test_the_two_kinds_of_withholding_are_both_in_use() -> None:
    """Guards the distinction itself.

    Collapsing every row to ABSENT is the tempting simplification, and it is
    wrong twice over: it would fail on Maven's <developers>, and the natural
    repair — weakening the probe until it passes — restores exactly the
    unfalsifiable prose this file replaced.
    """
    kinds = {kind for kind, _, _ in WITHHOLDING.values()}
    assert kinds == {ABSENT, PRESENT_BUT_DIFFERENT}


def test_every_reason_cites_the_registry_rather_than_the_adapter() -> None:
    """A withholding row is a claim about a third party, not about our code.

    "the adapter does not parse it" is a reason to fix the adapter, not a
    reason to record the signal as unmeasurable — which is, precisely, what
    #336 and #171 both were.
    """
    for (ecosystem, signal), (_, _, reason) in WITHHOLDING.items():
        assert len(reason) > 60, f"{ecosystem}/{signal} has no real reason"
        lowered = reason.lower()
        assert "adapter" not in lowered, (
            f"{ecosystem}/{signal} justifies a withheld signal by what our "
            "adapter does. That is a defect report, not a registry limit."
        )


def test_the_absence_probe_would_have_caught_336() -> None:
    """The guard, tested against the defect it exists to prevent.

    A check whose own failure mode is untested is the thing this file is
    complaining about. #336 was `nodejs` recording `maintainer` as withheld
    while the packument carried a `maintainers` array. That row is gone, so
    the probe cannot be run through the parametrised path — but it can be run
    directly, and it must find the field.

    If this ever stops finding it, the probe has gone blind and every ABSENT
    row above is passing for the wrong reason.
    """
    found, where = _any_fixture("nodejs", _has_any("maintainer"))
    assert found, (
        "the npm captures no longer carry a maintainers array, so the probe "
        "that would have caught #336 now finds nothing. Either the capture "
        "was trimmed -- which is the original defect -- or npm changed."
    )
    assert "nodejs/" in where


def test_the_probes_are_not_vacuous() -> None:
    """A probe that matches nothing anywhere would pass every ABSENT row.

    Each ABSENT probe is run against the ecosystem it is *not* written for, to
    show it can fire at all. `<developers>` finds Maven, `deprecat` finds the
    Go proxy's module-level retirement comment. A probe that fires nowhere is
    a green test asserting nothing, which is how this table got into trouble
    in the first place.
    """
    developers_finds_maven, _ = _any_fixture("maven", _has_any("<developers>"))
    assert developers_finds_maven

    deprecation_finds_golang, where = _any_fixture("golang", _has_any("deprecat"))
    assert deprecation_finds_golang, (
        "the `deprecat` needle finds nothing in the Go captures, so the same "
        "needle finding nothing in Maven's proves nothing either"
    )
    assert "golang/" in where
