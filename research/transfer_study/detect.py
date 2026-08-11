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
mutable and reusable; numeric account ids are neither.

## What the first version of this module got wrong

It assumed the id declared at T was available. **It is not.** A registry URL
carries a login string and nothing else, so every id-at-T in this procedure
comes from resolving that login *today* — and GitHub does not redirect user
profiles after a rename. The old login either 404s, or it has been
**re-registered by somebody else**, in which case it resolves cleanly to a
different id and the naive rule calls that a transfer.

That false positive lands inside the positive class, where the ambiguity gate
cannot see it: the gate counts cases the procedure *admits* it could not
resolve, not cases it resolved wrongly. And login re-registration targets
popular projects, so the contamination is activity-correlated — the coupling
the id discriminator exists to prevent, re-entering through its own resolution
step. With perhaps 400 positives in 10,000 rows, a handful of squatted logins
is a material share of the class carrying the entire inference.

So resolution carries a **provenance**, and a resolved-today id is treated as
the weaker evidence it is:

- `created_at` of the resolving account must predate T. An account created
  after T cannot be the account that declared the repository at T, so a later
  creation date *proves* the resolution is somebody else and the case is
  AMBIGUOUS rather than a transfer.
- That test is **necessary, not sufficient**: an account older than T can also
  have claimed a freed login. So every positive resolved this way is reported
  as its own stratum, and a run whose positives are mostly of this provenance
  is reporting a weaker measurement than one where ids were read as of T.
- `AS_OF_T` provenance — an id recorded at T by an event archive, which stores
  actor id and login together — carries no such caveat. The procedure accepts
  it and says so, rather than pretending both sources are equal.

The same-login branch is checked too. A login deleted and re-registered, with
a repository recreated under it, would otherwise read UNCHANGED: the most
security-relevant ownership change there is, classified as the negative class.

Everything here is pure. `classify` takes documents someone else fetched, which
is what lets the procedure be tested on fixtures before the harvest exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import Enum
from typing import Mapping, Optional


class Outcome(str, Enum):
    """What the comparison of declared-at-T against today can establish."""

    #: Same account today as at T. The protocol's negative.
    UNCHANGED = "unchanged"

    #: The repository is held by a different account than it was at T, and both
    #: accounts are distinguishable. The protocol's positive.
    TRANSFERRED = "transferred"

    #: The owner login changed but the account id did not. A rename, which is
    #: not the outcome under test and is not a negative either: it is excluded
    #: and counted, the same way a 404 is.
    OWNER_RENAMED = "owner_renamed"

    #: The owner login differs and the id comparison could not be made or could
    #: not be trusted. This is the residue the protocol caps at 20% of owner
    #: changes.
    AMBIGUOUS = "ambiguous"

    #: GitHub answered 404 for the repository. Deleted and private are reported
    #: identically, so this is never read as "no transfer".
    UNRESOLVABLE = "unresolvable"

    #: The declaration at T did not yield an owner/repo pair GitHub could name.
    #: A different fact from deletion; #360 exists because the two were once
    #: conflated.
    UNPARSEABLE = "unparseable"


class Provenance(str, Enum):
    """Where an account id came from, because the two sources differ in kind."""

    #: Recorded at T by an event archive that stores actor id beside login.
    #: The id is the id the declaring account had at T. No caveat.
    AS_OF_T = "as_of_t"

    #: Obtained by resolving the T-era login today. Whoever holds that login
    #: now may not be who held it at T, so this evidence is conditional and
    #: every positive built on it is reported as its own stratum.
    RESOLVED_TODAY = "resolved_today"


#: Outcomes that contribute to the analysed cohort. Everything else is reported
#: as attrition with its own count, never silently dropped and never recoded to
#: a negative — the failure mode the handover arm hit twice.
ANALYSED = frozenset({Outcome.UNCHANGED, Outcome.TRANSFERRED})


@dataclass(frozen=True)
class Account:
    """A GitHub account. Only one of these three fields is stable.

    `created_at` is None when the account document did not carry one, which is
    treated as *unable to clear the guard* rather than as clearing it.
    `account_type` is GitHub's `type`: "User" or "Organization".
    """

    login: str
    account_id: int
    created_at: Optional[date] = None
    account_type: Optional[str] = None


@dataclass(frozen=True)
class Observation:
    """One package's declaration at T set against what GitHub says today.

    `declared_owner` is a login because a login is all a `package.json` URL
    ever carries. `current` is None when the repository 404s, and
    `declared_account` is None when the T-era login no longer resolves — those
    two absences mean different things and are kept apart.
    """

    package: str
    t: date
    declared_owner: Optional[str]
    declared_repo: Optional[str]
    current: Optional[Account]
    declared_account: Optional[Account]
    #: Where `declared_account` came from. Ignored when it is None.
    provenance: Provenance = Provenance.RESOLVED_TODAY


@dataclass(frozen=True)
class Classification:
    """The outcome, its evidential strength, and the reason in plain words."""

    package: str
    outcome: Outcome
    detail: str
    #: Set on TRANSFERRED only. None means the id was known as of T; otherwise
    #: the positive rests on a login resolved today and is reported separately.
    provenance: Optional[Provenance] = None
    #: True when the owner changed from a user account to an organisation, or
    #: back. Read off `type` in the same response, so it costs nothing.
    owner_type_changed: bool = False


def _same_login(left: str, right: str) -> bool:
    """GitHub logins are case-insensitive; registry URLs disagree about case."""
    return left.lower() == right.lower()


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

    declared, current = obs.declared_account, obs.current
    type_changed = bool(
        declared
        and declared.account_type
        and current.account_type
        and declared.account_type != current.account_type
    )

    if _same_login(current.login, obs.declared_owner):
        # An id is not always available here, and its absence is the ordinary
        # case rather than a problem: same login and no contrary evidence is
        # the protocol's negative.
        if declared is not None and declared.account_id != current.account_id:
            return Classification(
                obs.package,
                Outcome.AMBIGUOUS,
                f"login {obs.declared_owner} is held by account "
                f"{current.account_id} today but was account "
                f"{declared.account_id} at T; the login was re-registered",
                owner_type_changed=type_changed,
            )
        return Classification(
            obs.package,
            Outcome.UNCHANGED,
            "same owner login as at T",
            owner_type_changed=type_changed,
        )

    if declared is None:
        return Classification(
            obs.package,
            Outcome.AMBIGUOUS,
            f"owner login changed to {current.login} but "
            f"{obs.declared_owner} no longer resolves, so no id comparison",
        )

    if declared.account_id == current.account_id:
        return Classification(
            obs.package,
            Outcome.OWNER_RENAMED,
            f"{obs.declared_owner} -> {current.login} is account "
            f"{current.account_id} under a new login",
            owner_type_changed=type_changed,
        )

    if obs.provenance is Provenance.RESOLVED_TODAY:
        # The id came from whoever holds the T-era login now, who need not be
        # whoever held it at T. An account younger than T provably is not.
        if declared.created_at is None or declared.created_at > obs.t:
            when = (
                "carries no creation date"
                if declared.created_at is None
                else f"was created {declared.created_at}, after T"
            )
            return Classification(
                obs.package,
                Outcome.AMBIGUOUS,
                f"{obs.declared_owner} resolves today to account "
                f"{declared.account_id}, which {when}, so it cannot be the "
                "account that declared the repository at T",
                owner_type_changed=type_changed,
            )

    return Classification(
        obs.package,
        Outcome.TRANSFERRED,
        f"account {declared.account_id} -> {current.account_id}",
        provenance=obs.provenance,
        owner_type_changed=type_changed,
    )


def ambiguity_share(counts: Mapping[Outcome, int]) -> float:
    """Ambiguous cases as a share of ambiguous plus confirmed transfers.

    The protocol's gate. The denominator deliberately excludes UNCHANGED: the
    question is not "how much of the cohort was ambiguous" — which a large
    negative class would flatter to nothing — but "of the owner changes seen,
    how many could not be told apart from a rename or a re-registration". A run
    where every third apparent transfer is unresolvable is reporting a mixture
    whatever the cohort size.

    Returns 0.0 when no owner change was observed at all, which is the only
    reading under which a gate on the mixture has nothing to say.
    """
    ambiguous = counts.get(Outcome.AMBIGUOUS, 0)
    transferred = counts.get(Outcome.TRANSFERRED, 0)
    denominator = ambiguous + transferred
    if denominator == 0:
        return 0.0
    return ambiguous / denominator


def attrition_share(counts: Mapping[Outcome, int]) -> float:
    """Everything excluded, as a share of everything observed.

    Reported beside the ambiguity gate because UNRESOLVABLE is missingness that
    is plausibly correlated with abandonment: a repository is deleted or taken
    private more often when a project has been let go. Dropping those rows
    silently is undisclosed selection even when each individual exclusion is
    correct, so the rate is published whatever it is.
    """
    total = sum(counts.values())
    if total == 0:
        return 0.0
    analysed = sum(counts.get(outcome, 0) for outcome in ANALYSED)
    return (total - analysed) / total


#: The share above which §11 says the outcome is reported unmixable rather than
#: analysed. Fixed here, in code, so the harvest cannot negotiate with it.
AMBIGUITY_CEILING = 0.20
