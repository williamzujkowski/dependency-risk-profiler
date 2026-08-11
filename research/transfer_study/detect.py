"""Did this repository change owner, and is that change a transfer or a rename?

`docs/transfer-outcome-protocol.md` §11 records the condition this module
discharges. The protocol's outcome is "the owner declared at T differs from the
owner GitHub reports today", and GitHub answers that question through a
redirect that is *deliberately* transparent: `GET /repos/old/name` follows a
rename, an organisation migration and a genuine transfer identically, and
returns the current `full_name` in all three cases. Reading owner inequality
straight off that response would therefore count a user who renamed their
account as having handed their project to someone else.

That matters beyond tidiness. The review's sharpest point was that **detection
probability may itself correlate with activity** — if the procedure is more
likely to notice a change on a busy project, the outcome re-couples to the
activity proxy through the measurement channel even though the construct is
clean. A procedure that cannot separate rename from transfer has exactly that
shape, because account renames are not distributed like handovers.

The discriminator is the account **id**, not the login. GitHub logins are
mutable and reusable; numeric account ids are neither. So:

- old login resolves to the **same id** as the current owner: the account was
  renamed. Not a transfer.
- old login resolves to a **different id**: the repository moved between two
  accounts that both exist. A transfer.
- old login does not resolve at all: the account is gone or the login was
  freed, and no id comparison is possible. **Ambiguous**, counted as its own
  category and never folded into either answer.

The last category is the honest one and the protocol gates on its size: over
20% of positives and the outcome is reported unmixable at this precision.

Everything here is pure. `classify` takes documents someone else fetched, which
is what lets the procedure be tested on fixtures before the harvest exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional


class Outcome(str, Enum):
    """What the comparison of declared-at-T against today can establish."""

    #: Same account id today as at T. The protocol's negative.
    UNCHANGED = "unchanged"

    #: The repository is held by a different account than it was at T, and both
    #: accounts are distinguishable. The protocol's positive.
    TRANSFERRED = "transferred"

    #: The owner login changed but the account id did not. A rename, which is
    #: not the outcome under test and is not a negative either: it is excluded
    #: and counted, the same way a 404 is.
    OWNER_RENAMED = "owner_renamed"

    #: The owner login differs and the id comparison could not be made, because
    #: the login declared at T no longer resolves to any account. This is the
    #: residue the protocol caps at 20% of positives.
    AMBIGUOUS = "ambiguous"

    #: GitHub answered 404 for the repository. Deleted and private are reported
    #: identically, so this is never read as "no transfer".
    UNRESOLVABLE = "unresolvable"

    #: The declaration at T did not yield an owner/repo pair GitHub could name.
    #: A different fact from deletion; #360 exists because the two were once
    #: conflated.
    UNPARSEABLE = "unparseable"


#: Outcomes that contribute to the analysed cohort. Everything else is reported
#: as attrition with its own count, never silently dropped and never recoded to
#: a negative — the failure mode the handover arm hit twice.
ANALYSED = frozenset({Outcome.UNCHANGED, Outcome.TRANSFERRED})


@dataclass(frozen=True)
class Account:
    """A GitHub account as two facts, of which only one is stable."""

    login: str
    account_id: int


@dataclass(frozen=True)
class Observation:
    """One package's declaration at T set against what GitHub says today.

    `declared_owner` is a login because a login is all a `package.json` URL
    ever carries. `current` is None when the repository 404s, and
    `declared_account` is None when the login no longer resolves — those two
    absences mean different things and are kept apart.
    """

    package: str
    declared_owner: Optional[str]
    declared_repo: Optional[str]
    current: Optional[Account]
    declared_account: Optional[Account]


@dataclass(frozen=True)
class Classification:
    """The outcome, and the reason in the words the write-up will use."""

    package: str
    outcome: Outcome
    detail: str


def classify(observation: Observation) -> Classification:
    """Apply the pre-registered decision procedure to one observation.

    The order of the branches is the order of the protocol's exclusions:
    unparseable before unresolvable before any comparison, so a declaration
    that was never a GitHub reference cannot be reported as a deleted
    repository, and a repository that 404s cannot be reported as unchanged.
    """
    obs = observation

    if not obs.declared_owner or not obs.declared_repo:
        return Classification(
            obs.package, Outcome.UNPARSEABLE, "no owner/repo pair at T"
        )

    if obs.current is None:
        return Classification(
            obs.package,
            Outcome.UNRESOLVABLE,
            "GitHub returned 404; deleted and private are indistinguishable",
        )

    if obs.current.login.lower() == obs.declared_owner.lower():
        return Classification(
            obs.package, Outcome.UNCHANGED, "same owner login as at T"
        )

    if obs.declared_account is None:
        return Classification(
            obs.package,
            Outcome.AMBIGUOUS,
            f"owner login changed to {obs.current.login} but "
            f"{obs.declared_owner} no longer resolves, so no id comparison",
        )

    if obs.declared_account.account_id == obs.current.account_id:
        return Classification(
            obs.package,
            Outcome.OWNER_RENAMED,
            f"{obs.declared_owner} -> {obs.current.login} is account "
            f"{obs.current.account_id} under a new login",
        )

    return Classification(
        obs.package,
        Outcome.TRANSFERRED,
        f"account {obs.declared_account.account_id} -> "
        f"{obs.current.account_id}",
    )


def ambiguity_share(counts: Mapping[Outcome, int]) -> float:
    """Ambiguous cases as a share of ambiguous plus confirmed transfers.

    The protocol's gate. The denominator deliberately excludes UNCHANGED: the
    question is not "how much of the cohort was ambiguous" — which a large
    negative class would flatter to nothing — but "of the owner changes seen,
    how many could not be told apart from a rename". A run where every third
    apparent transfer is unresolvable is reporting a mixture whatever the
    cohort size.

    Returns 0.0 when no owner change was observed at all, which is the only
    reading under which a gate on the mixture has nothing to say.
    """
    ambiguous = counts.get(Outcome.AMBIGUOUS, 0)
    transferred = counts.get(Outcome.TRANSFERRED, 0)
    denominator = ambiguous + transferred
    if denominator == 0:
        return 0.0
    return ambiguous / denominator


#: The share above which §11 says the outcome is reported unmixable rather than
#: analysed. Fixed here, in code, so the harvest cannot negotiate with it.
AMBIGUITY_CEILING = 0.20
