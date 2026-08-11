"""Fixtures for the transfer-detection procedure, written before the harvest.

`docs/transfer-outcome-protocol.md` §11 requires the detection procedure to be
"written and tested on synthetic fixtures **before** harvest". This is that
test. It exists so the procedure's failure modes are found against cases
someone chose deliberately, rather than discovered as a puzzling residue in a
run that has already cost 10,000 fetches.

Every fixture below is a real GitHub shape, and each one has bitten a study in
this repository or is the direct analogue of one that did.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "research"))

from transfer_study.detect import (  # noqa: E402
    AMBIGUITY_CEILING,
    ANALYSED,
    Account,
    Classification,
    Observation,
    Outcome,
    ambiguity_share,
    classify,
)


def observe(
    package: str = "pkg",
    declared_owner: str | None = "alice",
    declared_repo: str | None = "widget",
    current: Account | None = Account("alice", 1),
    declared_account: Account | None = Account("alice", 1),
) -> Observation:
    """One observation, defaulting to the boring case."""
    return Observation(
        package=package,
        declared_owner=declared_owner,
        declared_repo=declared_repo,
        current=current,
        declared_account=declared_account,
    )


def test_same_owner_is_the_negative() -> None:
    """The common case: nothing moved."""
    assert classify(observe()).outcome is Outcome.UNCHANGED


def test_owner_case_change_is_not_a_transfer() -> None:
    """GitHub logins are case-insensitive; `Alice` and `alice` are one account.

    A registry URL frequently disagrees with GitHub about case, so a
    case-sensitive comparison would manufacture positives out of typography.
    """
    result = classify(
        observe(declared_owner="Alice", current=Account("alice", 1))
    )
    assert result.outcome is Outcome.UNCHANGED


def test_a_move_between_two_live_accounts_is_a_transfer() -> None:
    """The outcome under test: different account today, both resolvable."""
    result = classify(
        observe(
            current=Account("acme-corp", 77),
            declared_account=Account("alice", 1),
        )
    )
    assert result.outcome is Outcome.TRANSFERRED
    assert "1 -> 77" in result.detail


def test_an_account_rename_is_not_a_transfer() -> None:
    """The case the naive procedure gets wrong.

    `alice` renames to `alice-dev`. `GET /repos/alice/widget` follows the
    redirect and reports `alice-dev/widget`, so login comparison says the
    project changed hands. The account id says one person changed their name.
    """
    result = classify(
        observe(
            current=Account("alice-dev", 1),
            declared_account=Account("alice-dev", 1),
        )
    )
    assert result.outcome is Outcome.OWNER_RENAMED
    assert result.outcome not in ANALYSED


def test_a_vanished_declared_login_is_ambiguous_not_a_transfer() -> None:
    """No id comparison is possible, so no answer is asserted.

    This is the residue the protocol caps. Recording it as a transfer would
    inflate the positive class with account deletions; recording it as
    unchanged would hide real handovers. It is neither.
    """
    result = classify(
        observe(current=Account("newowner", 42), declared_account=None)
    )
    assert result.outcome is Outcome.AMBIGUOUS
    assert result.outcome not in ANALYSED


def test_a_404_is_never_read_as_no_transfer() -> None:
    """Deleted and private are the same response; both leave the cohort."""
    result = classify(observe(current=None))
    assert result.outcome is Outcome.UNRESOLVABLE
    assert result.outcome not in ANALYSED


@pytest.mark.parametrize("owner,repo", [(None, "widget"), ("alice", None)])
def test_an_unparseable_declaration_is_its_own_category(
    owner: str | None, repo: str | None
) -> None:
    """#360's lesson: `repo.git#main` is not a deleted repository."""
    result = classify(observe(declared_owner=owner, declared_repo=repo))
    assert result.outcome is Outcome.UNPARSEABLE


def test_unparseable_is_decided_before_the_repository_is_consulted() -> None:
    """Ordering, not just categories.

    A declaration that never named a repository must not be reported as a
    deletion just because the fetch of a nonsense path also 404'd. The
    procedure's branch order is the protocol's exclusion order and this pins
    it.
    """
    result = classify(observe(declared_owner=None, current=None))
    assert result.outcome is Outcome.UNPARSEABLE


def test_a_transfer_into_an_account_that_reused_a_freed_login() -> None:
    """The nastiest real shape, and the reason ids are the discriminator.

    `alice` deletes their account; someone else registers the login `alice`
    and the repository has meanwhile moved to `bob`. The declared login
    resolves — to a stranger — so a login-existence check would call this
    unambiguous. The ids differ from both sides, and it is a transfer.
    """
    result = classify(
        observe(
            current=Account("bob", 500),
            declared_account=Account("alice", 999),
        )
    )
    assert result.outcome is Outcome.TRANSFERRED


def test_the_ambiguity_gate_measures_the_mixture_not_the_cohort() -> None:
    """A large negative class must not flatter the gate.

    30 transfers and 20 ambiguous in a cohort of 10,000 is 0.2% of rows and
    40% of the owner changes. The protocol gates on the second number, because
    the first says nothing about whether the positives are a mixture.
    """
    counts = {
        Outcome.UNCHANGED: 9_950,
        Outcome.TRANSFERRED: 30,
        Outcome.AMBIGUOUS: 20,
    }
    assert ambiguity_share(counts) == pytest.approx(0.4)
    assert ambiguity_share(counts) > AMBIGUITY_CEILING


def test_the_ambiguity_gate_passes_a_clean_run() -> None:
    counts = {Outcome.TRANSFERRED: 400, Outcome.AMBIGUOUS: 40}
    assert ambiguity_share(counts) == pytest.approx(0.0909, abs=1e-4)
    assert ambiguity_share(counts) <= AMBIGUITY_CEILING


def test_the_ambiguity_gate_says_zero_when_nothing_moved() -> None:
    """No owner change observed is the one reading under which the gate is mute.

    Not an error and not a failure: a cohort with no positives fails the power
    stop rule long before the mixture gate has anything to weigh in on.
    """
    assert ambiguity_share({Outcome.UNCHANGED: 100}) == 0.0


def test_only_two_outcomes_reach_the_analysis() -> None:
    """Everything else is attrition, counted and reported.

    Guards against a later edit quietly folding OWNER_RENAMED into the
    negative class to recover cohort size. That trade — precision of the
    outcome for power — is exactly the one the handover arm made and had to
    withdraw.
    """
    assert ANALYSED == {Outcome.UNCHANGED, Outcome.TRANSFERRED}
    assert len(set(Outcome)) == 6


def test_every_classification_carries_a_reason() -> None:
    """A bare label cannot be audited after the fact."""
    cases = [
        observe(),
        observe(current=None),
        observe(declared_owner=None),
        observe(current=Account("x", 9), declared_account=None),
        observe(current=Account("x", 1), declared_account=Account("x", 1)),
        observe(current=Account("x", 9), declared_account=Account("a", 1)),
    ]
    seen = set()
    for case in cases:
        result: Classification = classify(case)
        assert result.detail.strip(), f"{result.outcome} gave no reason"
        seen.add(result.outcome)
    assert seen == set(Outcome), "a fixture is missing for some outcome"
