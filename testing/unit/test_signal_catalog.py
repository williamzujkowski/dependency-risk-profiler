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
    SCORECARD_CHECKS,
    SCORECARD_VERSION,
    SIGNAL_CATALOG,
    SIGNAL_SIGNED_COMMITS,
    Measurement,
    MeasurementState,
    ScorecardFidelity,
    SourceRepositoryState,
    UnmeasuredReason,
    unmeasured_reason_for,
)

DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "signals.md"

# `| `name` | Check | fidelity | note |` — the mapping table's row shape. The
# note is matched loosely because it is prose; the first three cells are the
# contract.
_ROW = re.compile(
    r"^\| `(?P<signal>[a-z_]+)` \| (?P<check>[^|]+?) \| (?P<fidelity>[a-z_]+) \| "
    r"(?P<note>.+) \|$"
)


def _documented_rows() -> Dict[str, Tuple[Optional[str], str, str]]:
    """Parse the mapping table out of ``docs/signals.md``.

    Returns:
        Mapping of signal name to ``(scorecard check or None, fidelity, note)``.
    """
    rows: Dict[str, Tuple[Optional[str], str, str]] = {}
    for line in DOC_PATH.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line.strip())
        if match is None:
            continue
        check = match.group("check").strip()
        rows[match.group("signal")] = (
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
    # exactly as many rows as the scorer has signals.
    assert fully_measured.unknown_signals == []
    assert fully_measured.total_signal_count == len(SIGNAL_CATALOG), (
        "the scorer weighs a different number of signals than the catalog "
        f"names: {fully_measured.total_signal_count} vs {len(SIGNAL_CATALOG)}"
    )

    for name in _scored_signal_names():
        assert name in SIGNAL_CATALOG, f"scorer emits {name!r} with no catalog row"


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
        check, fidelity, note = documented[name]
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
                advisory_lookup=None,
                registry_lookup=None,
            )
            is UnmeasuredReason.SOURCE_REPOSITORY_UNREADABLE
        )

    for name in set(SIGNAL_CATALOG) - REPOSITORY_DERIVED_SIGNALS:
        assert (
            unmeasured_reason_for(
                name,
                source_repository_unreadable=True,
                advisory_lookup=None,
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
            advisory_lookup=None,
            registry_lookup=None,
        )
