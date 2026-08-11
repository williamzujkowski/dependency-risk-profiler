"""The signal catalog, the published mapping, and the two-state measurement (#164).

Three properties, and they are the reason the catalog is a table rather than a
paragraph:

1. **The catalog names every signal the scorer weighs, and no others.** A
   signal added to the scorer without a catalog row would have no reason to
   record when it comes back unmeasured, and ``unmeasured_reason_for`` would
   raise on it in production rather than here.
2. **``docs/signals.md`` matches the catalog exactly.** A published mapping
   that drifts from the code is worse than none: it looks authoritative. The
   only thing that keeps a hand-written table honest is a test that reads it.
3. **A measurement cannot carry a value nobody measured.** Enforced at
   construction, which is what makes the #141 shape unrepresentable rather
   than merely discouraged.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    LicenseCategory,
    LicenseInfo,
    RiskLevel,
    SecurityMetrics,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    REPOSITORY_DERIVED_SIGNALS,
    AdvisoryLookupState,
    SCORECARD_CHECKS,
    SCORECARD_VERSION,
    SCORED_SIGNALS,
    SIGNAL_CATALOG,
    SIGNAL_LICENSE,
    SIGNAL_SIGNED_COMMITS,
    Measurement,
    MeasurementState,
    ScorecardFidelity,
    SourceRepositoryState,
    UnmeasuredReason,
    unmeasured_reason_for,
)

DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "signals.md"

# `| `name` | scored | Check | fidelity | note |` — the mapping table's row
# shape. The note is matched loosely because it is prose; the first four cells
# are the contract.
_ROW = re.compile(
    r"^\| `(?P<signal>[a-z_]+)` \| (?P<scored>yes|no) \| (?P<check>[^|]+?) \| "
    r"(?P<fidelity>[a-z_]+) \| (?P<note>.+) \|$"
)


def _documented_rows() -> Dict[str, Tuple[bool, Optional[str], str, str]]:
    """Parse the mapping table out of ``docs/signals.md``.

    Returns:
        Mapping of signal name to ``(scored, scorecard check or None,
        fidelity, note)``.
    """
    rows: Dict[str, Tuple[bool, Optional[str], str, str]] = {}
    for line in DOC_PATH.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line.strip())
        if match is None:
            continue
        check = match.group("check").strip()
        rows[match.group("signal")] = (
            match.group("scored") == "yes",
            None if check == "—" else check,
            match.group("fidelity"),
            match.group("note").strip(),
        )
    return rows


def _fully_measured_dependency() -> DependencyMetadata:
    """Return a dependency every signal can be measured on.

    Returns:
        Metadata populated well enough that the scorer reports no unknown
        signals, which is how the scorer's signal set is discovered without
        restating it.
    """
    dependency = DependencyMetadata(
        name="example",
        installed_version="1.0.0",
        latest_version="1.0.1",
        last_updated=datetime(2026, 1, 1, tzinfo=timezone.utc),
        maintainer_count=4,
        repository_url="https://github.com/owner/repo",
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=True,
    )
    dependency.license_info = LicenseInfo(
        license_id="MIT",
        category=LicenseCategory.PERMISSIVE,
        is_approved=True,
        risk_level=RiskLevel.LOW,
    )
    dependency.community_metrics = CommunityMetrics(
        star_count=1200, contributor_count=40, commit_frequency=6.0
    )
    dependency.security_metrics = SecurityMetrics(
        has_security_policy=True,
        has_dependency_update_tools=True,
        has_signed_commits=True,
        has_branch_protection=True,
        is_maintained=True,
        vulnerability_count=0,
        counted_vulnerability_count=0,
    )
    dependency.transitive_dependencies = {"a", "b"}
    dependency.source_repository_state = SourceRepositoryState.DECLARED
    dependency.transitive_source = "manifest"
    # The two signals that carry a recorded state rather than a value: an
    # advisory lookup that answered, and a registry that said the package is
    # live. Both have to be asked for, which is what stops either reading as
    # measured on a dependency nobody looked at (#320, #321).
    dependency.record_advisory_lookup(
        AdvisoryLookupState.COMPLETE, sources_unavailable=()
    )
    dependency.record_deprecation(deprecated=False)
    return dependency


def _scored_signal_names() -> List[str]:
    """Return every signal name the scorer weighs, read off a real scoring run.

    Returns:
        The names, discovered by scoring a dependency nothing can be measured
        on — every signal then names itself in ``unknown_signals`` — plus
        ``source_repository``, which is only weighed when the registry
        answered and so cannot appear on a bare one.
    """
    bare = RiskScorer().score_dependency(
        DependencyMetadata(name="bare", installed_version="1.0.0")
    )
    return sorted(set(bare.unknown_signals) | {"source_repository"})


def test_catalog_covers_every_signal_the_scorer_weighs() -> None:
    """A signal with no catalog row has no reason to record when it goes quiet."""
    scorer = RiskScorer()
    fully_measured = scorer.score_dependency(_fully_measured_dependency())

    # A fully-measured dependency measures everything, so the catalog must have
    # exactly as many scored rows as the scorer has weighted signals.
    assert fully_measured.unknown_signals == []
    assert fully_measured.total_signal_count == len(SCORED_SIGNALS), (
        "the scorer weighs a different number of signals than the catalog "
        f"marks scored: {fully_measured.total_signal_count} vs "
        f"{len(SCORED_SIGNALS)}"
    )

    for name in _scored_signal_names():
        assert name in SIGNAL_CATALOG, f"scorer emits {name!r} with no catalog row"


def test_the_scorer_weighs_exactly_the_signals_the_catalog_marks_scored() -> None:
    """The catalog's ``scored`` flag is the rule, not a description of it.

    A row that says ``scored=False`` while the scorer still weighs the signal
    would be a published claim nothing enforces, which is this repository's
    most-repeated defect. Read off a real scoring run rather than from the
    scorer's source, so the check cannot be satisfied by a matching literal.
    """
    weighed = set(_scored_signal_names())

    assert weighed == set(SCORED_SIGNALS), (
        "the scorer and the catalog disagree about what is scored; "
        f"weighed but not marked: {sorted(weighed - SCORED_SIGNALS)}, "
        f"marked but not weighed: {sorted(SCORED_SIGNALS - weighed)}"
    )
    assert set(SIGNAL_CATALOG) - SCORED_SIGNALS == {SIGNAL_LICENSE}, (
        "license is the one measured signal published beside the verdict "
        "rather than inside it (#340); a second one needs its own argument"
    )


def test_a_reported_only_signal_is_still_published_with_its_state() -> None:
    """Not scoring a signal is not a licence to withhold it.

    ``license`` leaves the weighted set and the counts that describe it, and
    stays in ``signals`` with the same two-state shape as everything else. A
    consumer that stopped seeing the key could not tell "not scored" from "not
    measured", which is the #164 distinction pointed at a new target.
    """
    scorer = RiskScorer()
    measured = scorer.score_dependency(_fully_measured_dependency())
    unmeasured = scorer.score_dependency(
        DependencyMetadata(name="bare", installed_version="1.0.0")
    )

    assert measured.measurements[SIGNAL_LICENSE].is_measured
    assert SIGNAL_LICENSE not in measured.unknown_signals

    absent = unmeasured.measurements[SIGNAL_LICENSE]
    assert not absent.is_measured
    assert absent.reason is UnmeasuredReason.NO_DATA_FROM_SOURCE
    assert SIGNAL_LICENSE not in unmeasured.unknown_signals


def test_every_mapped_check_exists_at_the_pinned_scorecard_version() -> None:
    """A mapping to a check that is not there is the defect this pin prevents."""
    for spec in SIGNAL_CATALOG.values():
        if spec.scorecard_check is None:
            continue
        assert spec.scorecard_check in SCORECARD_CHECKS, (
            f"{spec.name} maps to {spec.scorecard_check!r}, which Scorecard "
            f"{SCORECARD_VERSION} does not define"
        )


def test_signed_commits_is_recorded_as_having_no_upstream_check() -> None:
    """The row the design was amended over stays honest.

    Scorecard v5.5.0 defines no commit-signing check. ``Signed-Releases``
    inspects release assets and never reads git history, so mapping this signal
    to it would be the papering-over the amendment forbids.
    """
    spec = SIGNAL_CATALOG[SIGNAL_SIGNED_COMMITS]

    assert spec.scorecard_check is None
    assert spec.scorecard_fidelity is ScorecardFidelity.REMOVED_UPSTREAM
    assert "Signed-Releases" in spec.scorecard_note
    assert "Signed-Commits" not in SCORECARD_CHECKS
    assert "Signed-Tags" not in SCORECARD_CHECKS


def test_every_row_states_what_differs() -> None:
    """An unexplained mapping is a mapping nobody can check."""
    for spec in SIGNAL_CATALOG.values():
        assert spec.scorecard_note.strip(), f"{spec.name} has no mapping note"
        if spec.scorecard_fidelity is ScorecardFidelity.NONE:
            assert spec.scorecard_check is None
        if spec.scorecard_check is not None:
            assert spec.scorecard_fidelity in (
                ScorecardFidelity.CLOSE,
                ScorecardFidelity.APPROXIMATE,
            )


def test_published_mapping_matches_the_catalog() -> None:
    """``docs/signals.md`` is the contract; the catalog is the implementation."""
    documented = _documented_rows()

    assert set(documented) == set(SIGNAL_CATALOG), (
        "docs/signals.md and the catalog name different signals; "
        f"only in docs: {sorted(set(documented) - set(SIGNAL_CATALOG))}, "
        f"only in code: {sorted(set(SIGNAL_CATALOG) - set(documented))}"
    )

    for name, spec in SIGNAL_CATALOG.items():
        scored, check, fidelity, note = documented[name]
        assert scored == spec.scored, f"{name}: doc disagrees about being scored"
        assert check == spec.scorecard_check, f"{name}: doc check disagrees"
        assert fidelity == spec.scorecard_fidelity.value, f"{name}: doc fidelity"
        assert note == " ".join(spec.scorecard_note.split()), f"{name}: doc note"


def test_the_document_pins_the_version_the_code_pins() -> None:
    """A mapping without a version is a rumour."""
    assert f"`{SCORECARD_VERSION}`" in DOC_PATH.read_text(encoding="utf-8")


def test_no_reason_means_not_applicable() -> None:
    """The deferred third state must not come back as a reason.

    ``NOT_APPLICABLE`` was deferred because no harness check can tell a wrong
    one from a right one. A reason meaning "this signal does not apply here"
    would be the same unverifiable judgment in a different field.
    """
    names = {reason.name for reason in UnmeasuredReason}
    assert "NOT_APPLICABLE" not in names
    for name in names:
        assert "APPLICABLE" not in name, f"{name} smuggles the deferred state back"


def test_measured_requires_a_value() -> None:
    """A measurement with no value is not a measurement."""
    with pytest.raises(ValueError):
        Measurement(MeasurementState.MEASURED, None, None)
    with pytest.raises(ValueError):
        Measurement(
            MeasurementState.MEASURED, 0.5, UnmeasuredReason.NO_DATA_FROM_SOURCE
        )


def test_unmeasured_cannot_carry_a_value() -> None:
    """REGRESSION #141: a number nobody measured must be unrepresentable."""
    with pytest.raises(ValueError):
        Measurement(
            MeasurementState.UNMEASURED, 0.0, UnmeasuredReason.NO_DATA_FROM_SOURCE
        )
    with pytest.raises(ValueError):
        Measurement(MeasurementState.UNMEASURED, None, None)


def test_a_measurement_cannot_be_edited_into_the_other_state() -> None:
    """Construction-time validation is worthless if the object is then mutable."""
    unmeasured = Measurement.unmeasured(UnmeasuredReason.NO_DATA_FROM_SOURCE)

    with pytest.raises(AttributeError):
        unmeasured.value = 0.0
    with pytest.raises(AttributeError):
        del unmeasured.reason

    assert unmeasured.value is None
    assert not unmeasured.is_measured


def test_unmeasured_instances_are_shared_per_reason() -> None:
    """Interning is what pays for the immutability; it must actually happen."""
    first = Measurement.unmeasured(UnmeasuredReason.LOOKUP_NOT_ATTEMPTED)
    second = Measurement.unmeasured(UnmeasuredReason.LOOKUP_NOT_ATTEMPTED)

    assert first is second
    assert first is not Measurement.unmeasured(UnmeasuredReason.NO_DATA_FROM_SOURCE)


def test_repository_derived_signals_get_the_repository_reason() -> None:
    """One measured fact explains several silent signals, not several gaps (#146)."""
    for name in REPOSITORY_DERIVED_SIGNALS:
        assert (
            unmeasured_reason_for(
                name,
                source_repository_unreadable=True,
                advisory_lookup=AdvisoryLookupState.COMPLETE,
                registry_lookup=None,
            )
            is UnmeasuredReason.SOURCE_REPOSITORY_UNREADABLE
        )

    for name in set(SIGNAL_CATALOG) - REPOSITORY_DERIVED_SIGNALS:
        assert (
            unmeasured_reason_for(
                name,
                source_repository_unreadable=True,
                advisory_lookup=AdvisoryLookupState.COMPLETE,
                registry_lookup=None,
            )
            is not UnmeasuredReason.SOURCE_REPOSITORY_UNREADABLE
        )


def test_an_unnamed_signal_raises_rather_than_defaulting() -> None:
    """Drift between the scorer and the catalog is a bug, not a fallback."""
    with pytest.raises(KeyError):
        unmeasured_reason_for(
            "not_a_signal",
            source_repository_unreadable=False,
            advisory_lookup=AdvisoryLookupState.COMPLETE,
            registry_lookup=None,
        )
