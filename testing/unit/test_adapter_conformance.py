"""The adapter-conformance gate: per-signal value assertions (#73, #145).

Three layers, each failing on a different kind of regression:

1. **Value conformance.** Every captured payload is scored offline and every
   signal it can answer is asserted *by value*. This is the layer that catches
   a signal which is always measured and always wrong — #142's phantom npm
   ``deprecated`` key, the case ``signal_floors`` documents itself as unable to
   reach.
2. **The non-default-branch rule.** Every polarized signal (boolean or
   two-state enum) must have at least one fixture whose ground truth is the
   branch a dead read can never produce. A polarized signal without one is
   reported as a gap, not assumed to work.
3. **Fixture hygiene.** Provenance is present, captures are fresh, payloads
   carry no credentials, sizes are bounded, and no test reaches the network.

Deliberately not here: the ecosystems still pending. ``CONVERSION_STATUS``
carries all eight with a note on what each still needs, and
``test_the_conversion_ledger_is_honest`` keeps that list from quietly claiming
more than it has.
"""

from datetime import date, timedelta
from typing import Mapping, Tuple

import pytest
from adapter_conformance import (
    CASES,
    CONVERSION_STATUS,
    DRIVERS,
    POLARIZED_SIGNALS,
    FixtureCase,
    assert_case_conforms,
    assert_non_default_branches_are_proven,
    assert_polarized_signals_are_registered,
    converted_ecosystems,
    score_case,
    unproven_branches,
)
from registry_fixtures import (
    MANIFEST,
    FixtureError,
    declared_fixtures,
    load_fixture,
    replay_fetcher,
)
from signal_floors import MIN_MEASURED_SIGNALS

CASE_IDS = [case.slug for case in CASES]


# --- 1. Value conformance --------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_captured_payload_produces_the_signal_values_it_should(
    case: FixtureCase,
) -> None:
    """Each captured payload scores to the values its ground truth demands."""
    assert_case_conforms(case)


def test_the_deprecated_npm_package_is_flagged_deprecated() -> None:
    """#142, pinned by value against the payload npm actually serves.

    The adapter used to read ``npm_data["deprecated"]``. The live ``request``
    packument has no such key — the notice lives in
    ``versions["2.88.2"].deprecated`` — so the flag defaulted to False for
    every package in the registry. ``False`` is not ``None``, so the signal
    counted as measured and every floor stayed green.

    Both halves are asserted here: the fixture's shape (there is no top-level
    key to read) and the resulting value (the signal is 1.0 anyway). Reinstate
    the top-level read and this is the test that goes red.
    """
    fixture = load_fixture("nodejs", "request")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    assert "deprecated" not in payload, (
        "the captured packument grew a top-level 'deprecated' key; if npm "
        "really started sending one, #142's premise changed and this test "
        "needs rewriting rather than deleting"
    )
    latest = payload["dist-tags"]["latest"]
    assert isinstance(payload["versions"][latest]["deprecated"], str)

    score = score_case(next(c for c in CASES if c.slug == "nodejs/request"))

    assert score.dependency.is_deprecated is True
    assert score.deprecation_score == 1.0


def test_the_gem_license_is_read_from_the_list_shape() -> None:
    """#134, pinned by value: RubyGems publishes 'licenses', never 'license'."""
    fixture = load_fixture("rubygems", "tzinfo")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    assert "license" not in payload
    assert payload["licenses"] == ["MIT"]

    score = score_case(next(c for c in CASES if c.slug == "rubygems/tzinfo"))

    assert score.dependency.license_info is not None
    assert score.dependency.license_info.license_id == "MIT"
    assert score.license_score == 0.0


# --- 2. The non-default-branch rule ----------------------------------------


@pytest.mark.parametrize("ecosystem", converted_ecosystems())
def test_every_polarized_signal_has_a_non_default_fixture(ecosystem: str) -> None:
    """A signal that defaults to False needs a fixture where the answer is True."""
    assert_non_default_branches_are_proven(ecosystem)


@pytest.mark.parametrize("ecosystem", converted_ecosystems())
def test_polarity_is_declared_only_for_signals_the_ecosystem_measures(
    ecosystem: str,
) -> None:
    """The polarity table and the measured-signal table describe one thing."""
    assert_polarized_signals_are_registered(ecosystem)


def test_unproven_branches_are_named_rather_than_assumed_closed() -> None:
    """Every waived branch carries a reason, and the reasons stay legible.

    A waiver is a gap that has been looked at, not a gap that has been fixed.
    The rubygems ``yanked`` entry is the one this harness produced on its own:
    no live gem payload was found reporting ``yanked: true``, which makes it a
    candidate for the same dead read as #142 in a second adapter.
    """
    waived = unproven_branches()

    assert waived, "the waiver list is the visible-gap mechanism; do not empty it"
    for line in waived:
        assert len(line) > 80, f"a waiver needs a reason, not a shrug: {line}"
    assert any(line.startswith("rubygems.deprecation") for line in waived)


# --- 3. Fixture hygiene ----------------------------------------------------


@pytest.mark.parametrize("fixture_id", declared_fixtures(), ids=str)
def test_every_declared_fixture_loads_with_provenance(
    fixture_id: Tuple[str, str],
) -> None:
    """Each fixture records where it came from and when it was taken."""
    ecosystem, name = fixture_id
    fixture = load_fixture(ecosystem, name)

    assert fixture.source_url.startswith("https://")
    assert fixture.captured_at <= date.today()
    assert fixture.payload not in (None, {}, [])


def test_fixtures_are_within_the_refresh_cadence() -> None:
    """Ageing fixtures warn; stale ones fail, so the refresh has a trigger.

    A fixture that is never re-captured freezes the registry's shape as it was
    the day it was taken and then defends that shape forever, which is #145 in
    slow motion. Thresholds live in the manifest next to the fixtures.
    """
    from registry_fixtures import assert_fixtures_are_fresh

    assert MANIFEST["warn_after_days"] < MANIFEST["fail_after_days"]
    assert_fixtures_are_fresh()


def test_an_ageing_capture_warns_and_a_stale_one_fails() -> None:
    """Both staleness branches are observed, not merely believed to work.

    A gate nobody has watched fail is a gate nobody has tested (#153). Time is
    injected rather than waited for.
    """
    from registry_fixtures import assert_fixtures_are_fresh

    oldest = min(load_fixture(e, n).captured_at for e, n in declared_fixtures())
    newest = max(load_fixture(e, n).captured_at for e, n in declared_fixtures())

    ageing = oldest + timedelta(days=MANIFEST["warn_after_days"] + 1)
    with pytest.warns(UserWarning, match="past the .* refresh cadence"):
        warnings = assert_fixtures_are_fresh(today=ageing)
    assert warnings, "an ageing fixture must name itself"

    stale = newest + timedelta(days=MANIFEST["fail_after_days"] + 1)
    with pytest.raises(FixtureError, match="no longer describe the live registries"):
        assert_fixtures_are_fresh(today=stale)


def test_fixture_ids_cannot_escape_the_fixture_directory() -> None:
    """Captured payloads are untrusted data; their ids never become free paths."""
    for hostile in ("../secrets", "/etc/passwd", "a/b", "Express", ""):
        with pytest.raises(FixtureError):
            load_fixture("nodejs", hostile)
        with pytest.raises(FixtureError):
            load_fixture(hostile, "express")


def test_the_replay_fetcher_refuses_any_url_it_has_no_recording_for() -> None:
    """CI never reaches a registry: an unrecorded URL raises instead of fetching."""
    fixture = load_fixture("nodejs", "express")
    fetch = replay_fetcher({"express": fixture})

    assert fetch(fixture.source_url) is fixture.payload
    with pytest.raises(AssertionError, match="do not let this fall through"):
        fetch("https://registry.npmjs.org/lodash")


def test_fixtures_stay_within_the_size_bound() -> None:
    """A bounded recording is a bounded parse; the loader refuses anything over.

    ``load_fixture`` enforces the bound itself, so a fixture that grew past it
    raises here rather than at whatever test happens to load it first.
    """
    bound = MANIFEST["max_fixture_bytes"]
    assert 0 < bound <= 1024 * 1024

    for ecosystem, name in declared_fixtures():
        assert load_fixture(ecosystem, name).name == name


def test_no_fixture_carries_a_credential_shaped_value() -> None:
    """Recorded registry documents are scanned before they are trusted.

    Public registries have no business serving a token, which is exactly why a
    token appearing in one would matter. The scan runs on load, so it also
    covers a fixture captured from a private or proxying registry.
    """
    for ecosystem, name in declared_fixtures():
        load_fixture(ecosystem, name)  # raises FixtureError on a match


def test_trimming_removed_volume_and_never_a_schema_key() -> None:
    """The capture may drop 285 release manifests; it may not drop a key.

    "Trimmed to the keys the adapter reads" is the sentence that made four of
    #145's five dead reads undetectable. Every note a reducer leaves behind has
    to be about volume.
    """
    for ecosystem, name in declared_fixtures():
        fixture = load_fixture(ecosystem, name)
        for note in fixture.trimming:
            assert any(
                token in note
                for token in ("volume only", "no longer present", "truncated")
            ), f"{fixture.slug}: trimming note does not describe volume: {note}"


# --- The ledger ------------------------------------------------------------


def test_the_conversion_ledger_is_honest() -> None:
    """Every ecosystem is listed, converted ones have a driver, pending say why."""
    assert set(CONVERSION_STATUS) >= set(MIN_MEASURED_SIGNALS)
    assert set(CONVERSION_STATUS) >= set(DRIVERS)

    converted = converted_ecosystems()
    assert set(converted) == set(DRIVERS), (
        "an ecosystem marked converted with no driver is a claim with nothing "
        "behind it"
    )
    for ecosystem in converted:
        assert ecosystem in POLARIZED_SIGNALS
        assert any(case.ecosystem == ecosystem for case in CASES)
        assert any(
            case.ecosystem == ecosystem and case.meets_signal_floor for case in CASES
        ), f"{ecosystem} has no coverage-floor case"

    pending = [k for k, v in CONVERSION_STATUS.items() if not v.converted]
    assert pending, "six ecosystems remain; #73 is Refs, not Closes"
    for ecosystem in pending:
        assert "PENDING" in CONVERSION_STATUS[ecosystem].note
