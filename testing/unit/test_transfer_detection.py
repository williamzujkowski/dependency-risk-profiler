"""Fixtures for the transfer-detection procedure, written before the harvest.

`docs/transfer-outcome-protocol.md` §11 requires the detection procedure to be
"written and tested on synthetic fixtures **before** harvest". This is that
test. It exists so the procedure's failure modes are found against cases
someone chose deliberately, rather than discovered as a puzzling residue in a
run that has already cost 10,000 fetches.

Every fixture below is a real GitHub shape. The ones that matter most are the
squatted-login cases: a 7-0 review rejected the first version of this procedure
for admitting them to the positive class, where the ambiguity gate cannot see
them.
"""

from __future__ import annotations

import sys
from datetime import date
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
    Provenance,
    ambiguity_share,
    attrition_share,
    classify,
)

T = date(2024, 8, 1)
BEFORE_T = date(2015, 3, 9)
AFTER_T = date(2025, 6, 2)


def observe(
    package: str = "pkg",
    declared_owner: str | None = "alice",
    declared_repo: str | None = "widget",
    current: Account | None = Account("alice", 1),
    declared_account: Account | None = Account("alice", 1, BEFORE_T),
    provenance: Provenance = Provenance.RESOLVED_TODAY,
) -> Observation:
    """One observation, defaulting to the boring case."""
    return Observation(
        package=package,
        t=T,
        declared_owner=declared_owner,
        declared_repo=declared_repo,
        current=current,
        declared_account=declared_account,
        provenance=provenance,
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
            declared_account=Account("alice", 1, BEFORE_T),
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
            declared_account=Account("alice-dev", 1, BEFORE_T),
        )
    )
    assert result.outcome is Outcome.OWNER_RENAMED
    assert result.outcome not in ANALYSED


def test_a_vanished_declared_login_is_ambiguous_not_a_transfer() -> None:
    """No id comparison is possible, so no answer is asserted.

    Recording it as a transfer would inflate the positive class with account
    deletions; recording it as unchanged would hide real handovers. It is
    neither.
    """
    result = classify(
        observe(current=Account("newowner", 42), declared_account=None)
    )
    assert result.outcome is Outcome.AMBIGUOUS
    assert result.outcome not in ANALYSED


def test_a_squatted_login_is_ambiguous_not_a_transfer() -> None:
    """The defect that got version one rejected 7-0.

    `alice` renames; GitHub frees the login; a stranger registers it in 2025.
    Resolving `alice` today returns a live account with a different id, which
    the naive id rule calls a transfer — a false positive *inside the positive
    class*, invisible to a gate that only counts admitted non-resolutions. An
    account created after T cannot be the account that declared the repository
    at T, and that is decidable from the account document.
    """
    result = classify(
        observe(
            current=Account("acme-corp", 77),
            declared_account=Account("alice", 909, AFTER_T),
        )
    )
    assert result.outcome is Outcome.AMBIGUOUS
    assert "after T" in result.detail


def test_a_resolved_account_without_a_creation_date_cannot_clear_the_guard(
) -> None:
    """Missing evidence is not passing evidence.

    A `created_at` the document did not carry leaves the squatting question
    open, and an open question is AMBIGUOUS. Defaulting the other way would
    make the guard vanish exactly where the data is worst.
    """
    result = classify(
        observe(
            current=Account("acme-corp", 77),
            declared_account=Account("alice", 909, None),
        )
    )
    assert result.outcome is Outcome.AMBIGUOUS
    assert "no creation date" in result.detail


def test_an_older_squatter_still_passes_the_guard_and_is_stratified() -> None:
    """created_at <= T is necessary, not sufficient, and the report says so.

    An account that predates T can also have claimed a freed login. Nothing
    decidable separates that from a genuine transfer, so the case is a
    positive — carrying its provenance, so a run whose positives are mostly
    resolved-today is read as the weaker measurement it is.
    """
    result = classify(
        observe(
            current=Account("acme-corp", 77),
            declared_account=Account("alice", 909, BEFORE_T),
        )
    )
    assert result.outcome is Outcome.TRANSFERRED
    assert result.provenance is Provenance.RESOLVED_TODAY


def test_an_id_known_as_of_t_skips_the_squatting_guard_entirely() -> None:
    """An event archive records actor id beside login at event time.

    That id is the declaring account's id, so no re-registration can have
    intervened and the creation-date question does not arise. The procedure
    accepts it as the stronger evidence it is rather than treating both
    sources as equal.
    """
    result = classify(
        observe(
            current=Account("acme-corp", 77),
            declared_account=Account("alice", 909, None),
            provenance=Provenance.AS_OF_T,
        )
    )
    assert result.outcome is Outcome.TRANSFERRED
    assert result.provenance is Provenance.AS_OF_T


def test_a_recreated_repo_under_a_re_registered_login_is_not_unchanged() -> None:
    """The same-login branch needs the id check too.

    Account deleted, login re-registered by someone else, repository recreated
    under the same path. The login matches at both ends, so a login comparison
    reports the negative — for the most security-relevant ownership change
    there is.
    """
    result = classify(
        observe(
            current=Account("alice", 5150),
            declared_account=Account("alice", 1, BEFORE_T),
            provenance=Provenance.AS_OF_T,
        )
    )
    assert result.outcome is Outcome.AMBIGUOUS
    assert "re-registered" in result.detail


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
    deletion just because the fetch of a nonsense path also 404'd.
    """
    result = classify(observe(declared_owner=None, current=None))
    assert result.outcome is Outcome.UNPARSEABLE


def test_a_user_to_org_conversion_is_recorded_even_though_it_is_unchanged(
) -> None:
    """Conversion keeps the id, so the outcome cannot see it — but it is real.

    `type` rides along in the response already fetched, so counting these
    costs nothing and keeps the limitation quantified instead of asserted.
    """
    result = classify(
        observe(
            current=Account("alice", 1, BEFORE_T, "Organization"),
            declared_account=Account("alice", 1, BEFORE_T, "User"),
        )
    )
    assert result.outcome is Outcome.UNCHANGED
    assert result.owner_type_changed is True


def test_the_ambiguity_gate_measures_the_mixture_not_the_cohort() -> None:
    """A large negative class must not flatter the gate.

    30 transfers and 20 ambiguous in a cohort of 10,000 is 0.2% of rows and
    40% of the owner changes. The protocol gates on the second number.
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


def test_attrition_is_reported_because_deletion_is_not_random() -> None:
    """A repository is deleted more often when the project was let go.

    Each exclusion is individually correct and the set of them is still
    selection, so the rate is published whatever it is.
    """
    counts = {
        Outcome.UNCHANGED: 800,
        Outcome.TRANSFERRED: 40,
        Outcome.UNRESOLVABLE: 120,
        Outcome.AMBIGUOUS: 20,
        Outcome.UNPARSEABLE: 20,
    }
    assert attrition_share(counts) == pytest.approx(0.16)
    assert attrition_share({}) == 0.0


def test_only_two_outcomes_reach_the_analysis() -> None:
    """Everything else is attrition, counted and reported.

    Guards against a later edit quietly folding OWNER_RENAMED into the
    negative class to recover cohort size. That trade — precision of the
    outcome for power — is exactly the one the handover arm made and withdrew.
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
        observe(
            current=Account("x", 1),
            declared_account=Account("x", 1, BEFORE_T),
        ),
        observe(
            current=Account("x", 9),
            declared_account=Account("a", 1, BEFORE_T),
        ),
    ]
    seen = set()
    for case in cases:
        result: Classification = classify(case)
        assert result.detail.strip(), f"{result.outcome} gave no reason"
        seen.add(result.outcome)
    assert seen == set(Outcome), "a fixture is missing for some outcome"


def test_the_wilson_interval_is_used_because_wald_is_wrong_here() -> None:
    """The pilot's decision rule keys on an upper bound at small counts.

    A Wald interval on 2/10 runs to 0.448; Wilson gives 0.481. The rule fires
    on that difference, and at these counts Wald can also run below zero.
    """
    from transfer_study.pilot import wilson

    low, high = wilson(2, 10)
    assert low == pytest.approx(0.0567, abs=1e-3)
    assert high == pytest.approx(0.5098, abs=1e-3)
    assert wilson(0, 0) == (0.0, 1.0)
    assert wilson(0, 40)[0] == 0.0


@pytest.mark.parametrize(
    "ambiguous,transferred,expected",
    [
        (0, 0, "inconclusive"),
        (4, 200, "proceed"),
        (40, 60, "channel-inadequate"),
        (2, 10, "enlarge"),
    ],
)
def test_the_pilot_decision_rule_matches_the_protocol(
    ambiguous: int, transferred: int, expected: str
) -> None:
    """§15's four branches, pinned to the words fixed before any number existed.

    `enlarge` is the interesting one: 2 of 12 is a point estimate of 0.167,
    under the ceiling, but the interval reaches 0.51 — so the rule enlarges
    rather than reading a small sample as a pass.
    """
    from transfer_study.pilot import verdict

    decision, reason = verdict(ambiguous, transferred)
    assert decision == expected
    assert reason.strip()


def test_the_pilot_never_imports_anything_that_could_join_a_score() -> None:
    """The no-contamination claim, checked rather than promised.

    §15 says the pilot reads classification buckets only. A later edit that
    imported the scorer or the cohort's labels would make that sentence false
    while every other test still passed.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "research"
        / "transfer_study"
        / "pilot.py"
    ).read_text()
    for forbidden in (
        "dependency_risk_profiler",
        "abandonment_pilot",
        "repo_arm",
        "handover_study",
    ):
        assert forbidden not in source, (
            f"pilot.py references {forbidden}; §15 promises it reads buckets "
            "only, and that promise has to be enforced by something"
        )
