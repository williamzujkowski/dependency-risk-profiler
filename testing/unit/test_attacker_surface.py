"""Guards for the attacker-controlled weight share.

`docs/full-instrument-manipulation-result.md`. The share is read from the
scorer's constructor, so the guard that matters is the partition: every weight
the scorer declares must be classified as repository-derived or
registry-derived. A signal added to neither list would silently shrink the
denominator and quietly change a published figure.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))

from composition.attacker_surface import (  # noqa: E402
    REGISTRY_DERIVED,
    REPOSITORY_DERIVED,
    attacker_surface,
    declared_weights,
)


def test_every_declared_weight_is_classified() -> None:
    """The partition must be total, or the published share is wrong.

    A new signal that lands in neither tuple would shrink the denominator and
    move `attacker_controlled_share` without anyone editing the document that
    quotes it.
    """
    surface = attacker_surface()
    assert surface["unaccounted_signals"] == [], (
        "a scorer weight is classified as neither repository- nor "
        "registry-derived, so the published attacker-controlled share no "
        "longer describes the scorer"
    )
    assert set(REPOSITORY_DERIVED) & set(REGISTRY_DERIVED) == set()


def test_the_weight_share_still_matches_the_published_figure() -> None:
    """48.33%, the load-bearing number in the write-up."""
    surface = attacker_surface()
    # 1.10 of 2.65 since #339 retired signed_commits (0.20) and
    # branch_protection (0.15). Both were repository-derived, so the share fell
    # from 0.4833 -- the attacker-controlled surface shrank because two of the
    # signals reading a self-declared URL stopped being weighed at all.
    assert surface["repository_derived_weight"] == pytest.approx(1.10)
    assert surface["total_declared_weight"] == pytest.approx(2.65)
    assert surface["attacker_controlled_share"] == pytest.approx(0.4151, abs=5e-4)


def test_the_weights_are_read_from_the_scorer_not_retyped() -> None:
    """A re-weighted scorer must change this answer, not leave it stale."""
    weights = declared_weights()
    assert weights, "no weights were discovered on the scorer's constructor"
    assert set(weights) == set(REPOSITORY_DERIVED) | set(REGISTRY_DERIVED)


def test_no_signal_verifies_the_repository_against_the_package() -> None:
    """Criterion 3, which the review asked to run before any scoring.

    Not a code search for a phrase -- a behavioural check: a package declaring
    a repository it has no relationship to must still be recorded DECLARED. If
    a binding check is ever added, this fails and the claim in the write-up
    narrows, which is exactly what should happen.
    """
    from dependency_risk_profiler.models import (
        AdvisoryLookupState,
        DependencyMetadata,
    )
    from dependency_risk_profiler.models import SourceRepositoryState
    from dependency_risk_profiler.release_dates import (
        record_source_repository,
        resolve_repository,
    )

    dependency = DependencyMetadata(name="totally-unrelated", installed_version="1.0.0")
    dependency.record_advisory_lookup(
        AdvisoryLookupState.NOT_ATTEMPTED, sources_unavailable=()
    )
    record_source_repository(
        dependency, resolve_repository(["https://github.com/facebook/react"])
    )
    assert dependency.source_repository_state is SourceRepositoryState.DECLARED, (
        "a binding check may have been added -- if so this is good news and "
        "docs/full-instrument-manipulation-result.md needs narrowing"
    )
