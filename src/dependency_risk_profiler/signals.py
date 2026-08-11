"""Stable signal names, the two-state measurement, and the reason table (#164).

Four things live here, and they are one idea:

**1. The signal names are ours and they are stable.** The ratified design
originally proposed renaming our signals to OpenSSF Scorecard's check names.
That was rejected, and the reason generalizes: this whole effort is justified on
*API stability*, and Scorecard's vocabulary is not ours to keep stable. Our
``signed_commits`` is the sharp case — see :data:`SIGNAL_CATALOG` and
``docs/signals.md`` — because at the pinned Scorecard version there is no
commit-signing check at all. Adopting an upstream name we cannot hold still
would have traded our stability guarantee for the appearance of interop.

So: our names stay, and the correspondence to Scorecard is published as a
*mapping table pinned to a version*, with every approximate row marked as
approximate. A mapping a consumer can read is worth more than a rename a
consumer cannot rely on.

**2. A signal is MEASURED with a value or UNMEASURED with a reason, enforced at
construction.** #141 shipped a confident ``0.0`` for a signal nobody measured;
#166 shipped a composite that silently degraded to its weakest component while
still reporting as measured. Both are the same defect: the type allowed a value
to exist without a measurement behind it. :class:`Measurement` does not. There
is no way to build one carrying a value without ``MEASURED``, or one carrying
``UNMEASURED`` without a reason, and instances are frozen after construction so
a value cannot be grafted on afterwards.

**3. Classification is centralized, never adapter-local.** :func:`
unmeasured_reason_for` is the only place that decides *why* a signal came back
unmeasured, and it decides from the catalog plus the keyword-only facts the
scorer already knows — whether the source repository was readable, and what the
advisory lookup established. Eight adapters making that judgment independently
is how a table of eight right answers becomes a table of eight opinions.

**``NOT_APPLICABLE`` is deliberately absent.** The design deferred it behind a
schema version until a consumer demonstrably branches on it, on an argument
that applies just as forcefully here: *no conformance harness check can tell a
wrong NOT_APPLICABLE from a right one*. It is the one piece of the design that
cannot be machine-verified, and a confidently-wrong classification is worse
than an honest unknown. Note that this also rules out smuggling it back in as a
*reason*: :class:`UnmeasuredReason` carries no "this signal does not apply to
this ecosystem" member, and must not grow one. Every reason below is decided
from a fact the scorer observed, not from a judgment about the package.

**4. A field written by more than one acquisition path records which one wrote
it.** ``star_count`` was written from an unauthenticated github.com HTML regex
scrape *and* from the authenticated REST API, into the same unlabelled integer,
so two very different trust levels arrived indistinguishable. :class:`FieldSource`
names the path; :class:`ProvenancedField` names the seven fields that have more
than one, which is the whole of the scope — the design amendment restricted
provenance to exactly those, and ``testing/unit/test_field_provenance.py``
re-derives the set from the source tree so it cannot quietly grow or rot.

:class:`FieldSource` is an enum whose values *are* the sanitized logical
locators the design's binding security condition requires. That is the point of
making it an enum rather than a string: there is no code path that can put an
authenticated URL, a clone directory, a query string or a header into a field
whose only inhabitants are these ten members.
"""

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Mapping, Optional

# --- Signal names ----------------------------------------------------------
#
# These strings are the public vocabulary: they appear in ``unknown_signals`` in
# the JSON report and in the conformance harness's per-ecosystem tables. They
# are stable. Renaming one is a breaking change to the output contract, not a
# refactor.

SIGNAL_STALENESS = "staleness"
SIGNAL_MAINTAINER = "maintainer"
SIGNAL_DEPRECATION = "deprecation"
SIGNAL_EXPLOIT = "exploit"
SIGNAL_VERSION = "version"
SIGNAL_HEALTH_INDICATORS = "health_indicators"
SIGNAL_LICENSE = "license"
SIGNAL_COMMUNITY_POPULARITY = "community_popularity"
SIGNAL_COMMUNITY_ACTIVITY = "community_activity"
SIGNAL_TRANSITIVE = "transitive"
SIGNAL_SECURITY_POLICY = "security_policy"
SIGNAL_DEPENDENCY_UPDATE = "dependency_update"
SIGNAL_SIGNED_COMMITS = "signed_commits"
SIGNAL_BRANCH_PROTECTION = "branch_protection"
SIGNAL_MAINTAINED = "maintained"
SIGNAL_SOURCE_REPOSITORY = "source_repository"


# --- The two-state measurement ---------------------------------------------


class MeasurementState(Enum):
    """Whether a signal was measured at all.

    Two states, not three. See the module docstring for why
    ``NOT_APPLICABLE`` is not here and must not be added without a consumer
    that demonstrably branches on it.
    """

    MEASURED = "measured"
    UNMEASURED = "unmeasured"


class UnmeasuredReason(Enum):
    """Why a signal could not be measured.

    Each member is decided from something the scorer *observed*, so each one is
    checkable by the conformance harness. None of them is a judgment about
    whether the signal ought to apply to the package — that is the deferred
    ``NOT_APPLICABLE`` wearing a different hat, and it does not belong here.
    """

    #: The registry answered, and no readable source repository came out of it,
    #: so the repository-derived signals had nothing to read. One measured fact
    #: standing behind several silent signals (#146).
    SOURCE_REPOSITORY_UNREADABLE = "source_repository_unreadable"

    #: The input this signal reads was absent from whatever answered: the
    #: registry published no such field, or the lookup returned nothing. The
    #: default, and the one to pick when uncertain.
    NO_DATA_FROM_SOURCE = "no_data_from_source"

    #: The pipeline step that answers this signal never ran for this manifest.
    #: Distinct from "it ran and found nothing", which is a measured zero.
    LOOKUP_NOT_ATTEMPTED = "lookup_not_attempted"

    #: The lookup ran and the source did not answer: it was unreachable, the
    #: retries were exhausted, it returned an error status, or it sent a body
    #: this code cannot read. Distinct from :attr:`NO_DATA_FROM_SOURCE`, which
    #: is a source that *answered* and had nothing to say.
    #:
    #: Collapsing those two is the #219 defect: every advisory source returned
    #: the empty list for a connection failure, a 4xx, a GraphQL error block, a
    #: junk body and a genuinely clean package alike, so an OSV outage reported
    #: every package in a scan as advisory-clean — and cached the verdict.
    #: Decided from an observed fact (the request did not produce a readable
    #: answer), never from a judgment about the package.
    SOURCE_LOOKUP_FAILED = "source_lookup_failed"


class Measurement:
    """One signal's value, or the reason there isn't one.

    Construction is the gate. ``MEASURED`` requires a value and forbids a
    reason; ``UNMEASURED`` requires a reason and forbids a value. Instances are
    frozen afterwards, so neither state can be edited into the other. A
    fabricated ``0.0`` is therefore not discouraged — it is unrepresentable.

    ``__slots__`` rather than a dataclass because the org scan builds one of
    these per signal per dependency across thousands of dependencies in a
    thread pool, and the design review asked for that cost to be measured
    rather than assumed. See ``docs/signals.md`` for the numbers.
    """

    __slots__ = ("state", "value", "reason")

    state: MeasurementState
    value: Optional[float]
    reason: Optional[UnmeasuredReason]

    def __init__(
        self,
        state: MeasurementState,
        value: Optional[float],
        reason: Optional[UnmeasuredReason],
    ) -> None:
        """Build a measurement, rejecting every inconsistent combination.

        Prefer :meth:`measured`, :meth:`unmeasured`, or :meth:`from_optional`;
        this signature exists so the invariant has exactly one enforcement
        point rather than three.

        Args:
            state: Whether the signal was measured.
            value: The measured value. Required for ``MEASURED``, forbidden
                for ``UNMEASURED``.
            reason: Why it was not measured. Required for ``UNMEASURED``,
                forbidden for ``MEASURED``.

        Raises:
            ValueError: If the arguments describe a signal that carries a value
                nobody measured, or a measurement with no value.
        """
        if state is MeasurementState.MEASURED:
            if value is None:
                raise ValueError("a MEASURED signal must carry a value")
            if reason is not None:
                raise ValueError("a MEASURED signal must not carry a reason")
        else:
            if reason is None:
                raise ValueError("an UNMEASURED signal must carry a reason")
            if value is not None:
                raise ValueError(
                    "an UNMEASURED signal must not carry a value: a number "
                    "nobody measured is the #141 defect this type exists to "
                    "make unrepresentable"
                )
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "reason", reason)

    def __setattr__(self, name: str, value: object) -> None:
        """Refuse post-construction edits.

        Args:
            name: Attribute being assigned.
            value: Value being assigned.

        Raises:
            AttributeError: Always. Validation happens once, at construction;
                an editable measurement is one ``m.value = 0.0`` away from
                being the bug this type prevents.
        """
        raise AttributeError(f"Measurement is immutable; cannot set {name!r}")

    def __delattr__(self, name: str) -> None:
        """Refuse post-construction deletes.

        Args:
            name: Attribute being deleted.

        Raises:
            AttributeError: Always, for the same reason as :meth:`__setattr__`.
        """
        raise AttributeError(f"Measurement is immutable; cannot delete {name!r}")

    def __repr__(self) -> str:
        """Return a debugger-friendly rendering.

        Returns:
            The state plus whichever of value or reason it carries.
        """
        if self.state is MeasurementState.MEASURED:
            return f"Measurement.measured({self.value!r})"
        return f"Measurement.unmeasured({self.reason})"

    def __eq__(self, other: object) -> bool:
        """Compare by state, value and reason.

        Args:
            other: Object to compare against.

        Returns:
            True when ``other`` is a measurement with the same three fields.
        """
        if not isinstance(other, Measurement):
            return NotImplemented
        return (
            self.state is other.state
            and self.value == other.value
            and self.reason is other.reason
        )

    def __hash__(self) -> int:
        """Hash by state, value and reason.

        Returns:
            A hash consistent with :meth:`__eq__`.
        """
        return hash((self.state, self.value, self.reason))

    @property
    def is_measured(self) -> bool:
        """Whether this signal contributed a value.

        Returns:
            True when the state is ``MEASURED``.
        """
        return self.state is MeasurementState.MEASURED

    @classmethod
    def measured(cls, value: float) -> "Measurement":
        """Record a value somebody actually measured.

        Args:
            value: The measured value.

        Returns:
            A ``MEASURED`` measurement.
        """
        return cls(MeasurementState.MEASURED, value, None)

    @classmethod
    def unmeasured(cls, reason: UnmeasuredReason) -> "Measurement":
        """Record that a signal has no value, and why.

        Returns a shared instance per reason. That is only safe because these
        objects are immutable, which makes the frozen-ness pay for part of its
        own cost: an unmeasured signal allocates nothing, and unmeasured
        signals are the common case on exactly the sparsely-covered packages an
        org scan has most of.

        Args:
            reason: Why the signal could not be measured.

        Returns:
            An ``UNMEASURED`` measurement.
        """
        return _UNMEASURED[reason]


#: One shared instance per reason, built once. Safe because :class:`Measurement`
#: is immutable; see :meth:`Measurement.unmeasured`.
_UNMEASURED: Mapping[UnmeasuredReason, Measurement] = {
    reason: Measurement(MeasurementState.UNMEASURED, None, reason)
    for reason in UnmeasuredReason
}


# --- Adapter-facing measurement states -------------------------------------


class SourceRepositoryState(Enum):
    """What the registry said about the package's source repository.

    Three answers, and the absence of this state entirely is a fourth thing:
    the lookup did not happen or did not answer, which is unmeasured and must
    never be written as a negative finding (#182). ``record_source_repository``
    is the only writer, and it takes the evidence for the middle state as a
    required keyword-only argument so the state cannot be set by omission.
    """

    #: A usable ``owner/repo`` root on a supported host. Readable.
    DECLARED = "true"
    #: The registry named a source that is not a reachable git forge — a
    #: Subversion connection string, a decommissioned vanity host (#176).
    UNUSABLE = "unusable"
    #: The registry answered and names no source at all.
    UNDECLARED = "false"


#: The states in which no repository can be read, whatever the registry said.
#: Both silence the same repository-derived signals, so both explain that
#: silence as one measured fact rather than several independent gaps (#146).
SOURCE_REPOSITORY_UNREADABLE: FrozenSet[SourceRepositoryState] = frozenset(
    {SourceRepositoryState.UNUSABLE, SourceRepositoryState.UNDECLARED}
)

#: Marker meaning "transitive resolution never ran for this dependency", as
#: opposed to "it ran and the package has none", which is a measured zero.
TRANSITIVE_SOURCE_UNMEASURED = "unmeasured"


def transitive_is_measured(source: Optional[str]) -> bool:
    """Decide whether a dependency's transitive set was actually resolved.

    The one place that reads the marker, and it fails **closed**: an absent
    marker means nobody resolved this tree, not that someone resolved it and
    found nothing. That default is the whole point of #199. It used to be the
    other way around — ``source != TRANSITIVE_SOURCE_UNMEASURED``, which is
    True for ``None`` — so a dependency no adapter and no analyzer ever touched
    scored a confident ``0.0``, the #141 fabricated zero surviving in one
    field. Every other measurement state in this package is unreachable by
    omission (``Measurement``, ``record_source_repository``); this one now is
    too.

    Args:
        source: The dependency's ``transitive_source`` marker, as written by
            ``transitive.analyzer_enhanced.record_transitive_source``.

    Returns:
        True only when something positively claimed to have resolved the tree.
    """
    return source is not None and source != TRANSITIVE_SOURCE_UNMEASURED


class AdvisoryLookupState(Enum):
    """What the advisory sources established about one package.

    The advisory path used to have exactly one way to say "nothing" — the empty
    list — and it used it for a connection failure, a 4xx, a GraphQL error, an
    unreadable body, a source that does not cover the ecosystem, and a
    genuinely clean package. Six facts, one answer, and the answer was the
    reassuring one, cached to disk so it outlived the outage (#219).

    These four members are the distinction that was missing. ``COMPLETE`` and
    ``PARTIAL`` are measurements; ``FAILED`` and ``NOT_ATTEMPTED`` are not, and
    :data:`ADVISORY_LOOKUP_UNMEASURED` is what reads them that way.

    There is deliberately no "this ecosystem is not covered" member. A source
    that does not cover an ecosystem *abstains*, which is a fact about the
    source rather than about the package: the aggregate is ``COMPLETE`` when
    somebody else answered and ``NOT_ATTEMPTED`` when nobody could be asked at
    all. That is #164's ratified position — an honest unknown with a reason
    beats a ``NOT_APPLICABLE`` no gate can check.
    """

    #: Every source that was asked answered. The only cacheable state: a cache
    #: entry means "this is the whole answer", and nothing weaker.
    COMPLETE = "complete"

    #: At least one source did not answer, but what came back is still a
    #: measurement — either the sources that failed cannot establish absence
    #: anyway (see ``VulnerabilitySource.establishes_absence``), or advisories
    #: were found, and a found advisory is not un-found by an outage elsewhere.
    #: The advisory set is a floor rather than a total, so it is not cached.
    PARTIAL = "partial"

    #: A source that establishes absence did not answer and nothing was found.
    #: "No advisories" is exactly the claim that cannot be made here.
    FAILED = "failed"

    #: No source could be asked: every one was disabled, unauthenticated, or
    #: does not cover the ecosystem. Nothing was measured and nothing failed.
    NOT_ATTEMPTED = "not_attempted"


#: The states in which the advisory lookup established nothing. Read through
#: :func:`advisory_lookup_is_measured`.
ADVISORY_LOOKUP_UNMEASURED: FrozenSet[AdvisoryLookupState] = frozenset(
    {AdvisoryLookupState.FAILED, AdvisoryLookupState.NOT_ATTEMPTED}
)

#: The states in which at least one source was asked and did not answer, so the
#: report owes the reader a line about it. Deliberately not the same set as
#: :data:`ADVISORY_LOOKUP_UNMEASURED`: a ``PARTIAL`` lookup is a measurement and
#: still an incomplete one, and a ``NOT_ATTEMPTED`` one had nothing to fail.
ADVISORY_LOOKUP_DEGRADED: FrozenSet[AdvisoryLookupState] = frozenset(
    {AdvisoryLookupState.FAILED, AdvisoryLookupState.PARTIAL}
)


def advisory_lookup_is_measured(state: AdvisoryLookupState) -> bool:
    """Decide whether the advisory lookup produced a measurement.

    Fails **closed**, exactly like :func:`transitive_is_measured`: only a state
    that positively claims an answer counts as one. A dependency nobody asked
    any advisory source about carries :attr:`AdvisoryLookupState.NOT_ATTEMPTED`
    — the field's own default, and the honest description of a registry-only
    scan — so the exploit signal leaves both the numerator and the denominator
    rather than being handed ``has_known_exploits``'s ``False``. A confident
    ``0.0`` at the tool's largest single weight is exactly the reassurance
    nobody measured (#321).

    The argument takes no ``None``, which is the other half of the same
    property. Two spellings for "nobody looked" is how the reading here and the
    reading in :func:`transitive_is_measured` came to disagree; there is one
    spelling now, and the type refuses the other.

    Args:
        state: The dependency's ``advisory_lookup_state``, as written by
            ``DependencyMetadata.record_advisory_lookup`` or left at the
            unmeasured default.

    Returns:
        True only when a lookup ran and established something.
    """
    return state not in ADVISORY_LOOKUP_UNMEASURED


class RegistryLookupState(Enum):
    """What the package registries jointly established about one package.

    The same shape as :class:`AdvisoryLookupState` and for the same reason. An
    ecosystem whose registry is a set of repositories rather than one API can
    fail in a way one endpoint cannot: it can be asked *incompletely*. Until
    #278 the Maven side asked exactly one repository, Maven Central, and every
    ``androidx.*`` artifact — none of which is published there — came back
    indistinguishable from an artifact that does not exist. Sixty-two of
    Signal-Android's ninety-four dependencies were in that state.

    So "we asked every repository we know and none of them publishes this" is
    :attr:`ABSENT_EVERYWHERE`, and it is deliberately not the same member as
    :attr:`NOT_ATTEMPTED`, which covers a lookup that stopped part-way — a
    spent fetch budget, a coordinate the grammar refuses, remote resolution
    switched off. The distinction is not a convention: the state is derived
    from the recorded per-repository outcomes by
    ``parsers.maven_repositories.RepositoryLookup.state``, so absence is
    unreachable unless the outcomes actually cover the configured set
    (AGENTS.md rule 4).

    ``None`` on a dependency means no registry-lookup state was recorded at
    all, which is what every ecosystem other than Maven does today. It reads as
    "do not branch", exactly like ``None`` for the advisory state, and never as
    a failure.
    """

    #: At least one repository produced the document. Anything still missing is
    #: missing from a document we actually read.
    ANSWERED = "answered"

    #: Every configured repository was asked, every one of them answered, and
    #: none of them publishes this artifact. A measurement.
    ABSENT_EVERYWHERE = "absent_everywhere"

    #: At least one repository was asked and did not answer — a timeout, a 5xx,
    #: a refused redirect, an unreadable body — and none of the others had it.
    #: "Not published anywhere" is exactly the claim that cannot be made here,
    #: which is #219's rule at repository scope.
    FAILED = "failed"

    #: The lookup did not finish: no repository was asked, or some answered
    #: "no" and the rest were never reached.
    NOT_ATTEMPTED = "not_attempted"


# --- Field provenance ------------------------------------------------------


class FieldSource(Enum):
    """Which acquisition path wrote a field that has more than one.

    The member values are **sanitized logical locators**: a closed vocabulary of
    short, lowercase, host-free, credential-free strings naming *what kind of
    thing answered*, never *the request that asked it*. An enum rather than a
    string because the design's binding security condition — no absolute clone
    paths, no authenticated URLs, no query strings, no headers — is then
    structural rather than a rule someone has to remember at twenty-odd call
    sites. ``testing/unit/test_field_provenance.py`` additionally holds every
    value to a locator grammar, so a future member cannot smuggle one in.

    The distinctions drawn here are the ones that change how much a value is
    worth. A star count regex-scraped out of a web page and a star count read
    from ``stargazers_count`` are not the same number with different latency;
    one is parsed out of markup that GitHub may restyle at any time. A commit
    cadence counted in a ``--depth 1`` clone is ~0.17/month for every repository
    on earth (#166), which is why the clone and the API are separate members
    rather than one ``repository`` bucket.
    """

    #: The ecosystem registry's own package document — PyPI's JSON, an npm
    #: packument, crates.io, Packagist, a nuspec, RubyGems, a Maven POM.
    REGISTRY_METADATA = "registry:metadata"
    #: The registry's release or version table specifically, which is where a
    #: publication timestamp comes from.
    REGISTRY_RELEASE = "registry:release"
    #: Git history in a clone of the package's source repository: ``git log``,
    #: ``git shortlog``, ``git rev-list``. Worth much less when the clone is
    #: shallow, which is why the callers that can be shallow abstain instead.
    REPOSITORY_CLONE_HISTORY = "clone:git-history"
    #: Files present in a clone's working tree.
    REPOSITORY_CLONE_WORKTREE = "clone:worktree"
    #: GitHub's REST repository object.
    GITHUB_API_REPOSITORY = "github:api/repository"
    #: GitHub's REST contributors listing.
    GITHUB_API_CONTRIBUTORS = "github:api/contributors"
    #: GitHub's REST commits listing.
    GITHUB_API_COMMITS = "github:api/commits"
    #: GitHub's REST git-tree listing.
    GITHUB_API_TREE = "github:api/tree"
    #: A regex over unauthenticated github.com HTML. The weakest source here,
    #: and the one the design amendment was argued over.
    GITHUB_HTML_SCRAPE = "github:html"


class ProvenancedField(Enum):
    """The model fields that more than one acquisition path writes.

    This enum *is* the scope of the provenance work, and it is deliberately
    seven members rather than the seventeen the original proposal wrapped. Four
    voters rejected that as over-broad and the amendment restricted provenance
    to "fields with more than one real write path"; these are those fields, and
    :mod:`testing.unit.test_field_provenance` re-derives the set from a walk of
    ``src/`` so the enum cannot drift from the code it describes.

    Two fields qualify on write-path count and are deliberately *not* here:

    * ``repository_url`` — an identity locator rather than a measured value,
      and what a consumer actually needs to know about it (did the registry
      declare a usable source, or is this a synthesized registry landing page)
      is already answered by the typed ``source_repository_state`` from #189.
    * ``transitive_dependencies`` — already carries ``transitive_source``
      from #199, which is provenance under an older name.

    The member values are the model attribute names, so the serialized block
    reads as the fields it describes.
    """

    STAR_COUNT = "star_count"
    CONTRIBUTOR_COUNT = "contributor_count"
    COMMIT_FREQUENCY = "commit_frequency"
    MAINTAINER_COUNT = "maintainer_count"
    HAS_TESTS = "has_tests"
    HAS_CI = "has_ci"
    LAST_UPDATED = "last_updated"


# --- The catalog -----------------------------------------------------------


class ScorecardFidelity(Enum):
    """How much a Scorecard check and one of our signals actually agree.

    The grades are deliberately blunt. A consumer joining our output to a
    Scorecard report needs to know when a row is safe to join and when it is
    a resemblance, and a five-point scale would only invite splitting hairs.
    """

    #: Same question, same class of evidence. The numbers are still not
    #: comparable — ours is a 0..1 risk score, Scorecard's a 0..10 quality
    #: score, and they run in opposite directions — but the row is joinable.
    CLOSE = "close"
    #: Related question, different evidence. Do not treat as interchangeable.
    APPROXIMATE = "approximate"
    #: Scorecard has no check that asks this question at the pinned version.
    NONE = "none"
    #: The nearest Scorecard check existed once and is gone at the pinned
    #: version. Exactly the case the design amendment was argued over.
    REMOVED_UPSTREAM = "removed_upstream"


@dataclass(frozen=True)
class SignalSpec:
    """One row of the signal catalog.

    Attributes:
        name: Our stable signal name, as it appears in ``unknown_signals``.
        summary: What the signal measures, in one line.
        repository_derived: Whether the signal can only be answered by reading
            the package's source repository. Drives the #146 collapse.
        scored: Whether the signal enters the weighted composite. A signal with
            ``scored=False`` is measured and published on its own axis and
            carries no weight in ``risk_level``; :data:`SCORED_SIGNALS` is the
            set the scorer is allowed to weigh.
        unmeasured_reason: The reason to record when this signal's input is
            absent and nothing more specific applies.
        scorecard_check: The nearest OpenSSF Scorecard check at
            :data:`SCORECARD_VERSION`, or None when there is none.
        scorecard_fidelity: How much that correspondence is worth.
        scorecard_note: What differs, stated plainly. Never empty.
    """

    name: str
    summary: str
    repository_derived: bool
    scored: bool
    unmeasured_reason: UnmeasuredReason
    scorecard_check: Optional[str]
    scorecard_fidelity: ScorecardFidelity
    scorecard_note: str


#: The Scorecard release this mapping was checked against. A mapping without a
#: version is a rumour: Scorecard adds, renames and removes checks, and the
#: ``signed_commits`` row below is what that looks like when it happens to you.
SCORECARD_VERSION = "v5.5.0"

#: When someone last read Scorecard's ``docs/checks.md`` and ``checks/`` at
#: that tag and confirmed every row.
SCORECARD_CHECKED_ON = "2026-08-04"

#: Every check Scorecard defines at :data:`SCORECARD_VERSION`, read from
#: ``checks/`` and ``docs/checks.md`` at that tag. The catalog may only name a
#: check from this set; that is what keeps the mapping pinned rather than
#: remembered, and it is what forces the ``signed_commits`` row to be honest.
SCORECARD_CHECKS: FrozenSet[str] = frozenset(
    {
        "Binary-Artifacts",
        "Branch-Protection",
        "CI-Tests",
        "CII-Best-Practices",
        "Code-Review",
        "Contributors",
        "Dangerous-Workflow",
        "Dependency-Update-Tool",
        "Fuzzing",
        "License",
        "Maintained",
        "Packaging",
        "Pinned-Dependencies",
        "SAST",
        "SBOM",
        "Security-Policy",
        "Signed-Releases",
        "Token-Permissions",
        "Vulnerabilities",
        "Webhooks",
    }
)


def _spec(
    name: str,
    summary: str,
    *,
    repository_derived: bool = False,
    scored: bool = True,
    unmeasured_reason: UnmeasuredReason = UnmeasuredReason.NO_DATA_FROM_SOURCE,
    scorecard_check: Optional[str] = None,
    scorecard_fidelity: ScorecardFidelity = ScorecardFidelity.NONE,
    scorecard_note: str = "",
) -> SignalSpec:
    """Build one catalog row.

    Args:
        name: Our stable signal name.
        summary: What the signal measures.
        repository_derived: Whether it needs the source repository.
        scored: Whether it enters the weighted composite.
        unmeasured_reason: Default reason when its input is absent.
        scorecard_check: Nearest Scorecard check, or None.
        scorecard_fidelity: How much that correspondence is worth.
        scorecard_note: What differs.

    Returns:
        The populated :class:`SignalSpec`.
    """
    return SignalSpec(
        name=name,
        summary=summary,
        repository_derived=repository_derived,
        scored=scored,
        unmeasured_reason=unmeasured_reason,
        scorecard_check=scorecard_check,
        scorecard_fidelity=scorecard_fidelity,
        scorecard_note=scorecard_note,
    )


#: Every signal the tool measures and publishes, with its Scorecard
#: correspondence. ``scored`` says which of them the composite weighs;
#: :data:`SCORED_SIGNALS` is that subset and is what the scorer is checked
#: against.
#:
#: The table is the source of truth: ``docs/signals.md`` is checked against it
#: by ``testing/unit/test_signal_catalog.py``, so the published mapping cannot
#: drift from the code that implements it.
#:
#: Three of our signals point at Scorecard's ``Maintained``. That is not a
#: mistake and it is not invertible: Scorecard answers "is anyone home" once,
#: from repository activity, where we answer it three times from three
#: different sources — when the registry last shipped, how often the repository
#: is committed to, and the repository's own activity heuristics — because a
#: package can be stale on one and healthy on another and we would rather
#: report the disagreement than average it away (#166).
SIGNAL_CATALOG: Mapping[str, SignalSpec] = {
    spec.name: spec
    for spec in (
        _spec(
            SIGNAL_STALENESS,
            "How long since the package last shipped a release.",
            scorecard_check="Maintained",
            scorecard_fidelity=ScorecardFidelity.APPROXIMATE,
            scorecard_note=(
                "Ours reads the registry's own release timestamp, which cannot "
                "be broken by a repository rename (#146). Scorecard reads "
                "repository commit and issue activity over the trailing 90 "
                "days. A package with a live repository and no releases for "
                "three years scores well upstream and badly here, on purpose."
            ),
        ),
        _spec(
            SIGNAL_MAINTAINER,
            "How many people the registry names as owning the package.",
            scorecard_check="Contributors",
            scorecard_fidelity=ScorecardFidelity.APPROXIMATE,
            scorecard_note=(
                "Ours is a bus-factor count from the registry's owner or "
                "author list. Scorecard counts repository contributors from "
                "at least two organizations, which is a diversity-of-"
                "affiliation question, not a bus-factor one."
            ),
        ),
        _spec(
            SIGNAL_DEPRECATION,
            "Whether the registry marks the package as deprecated or yanked.",
            scorecard_note="Scorecard has no deprecation check.",
        ),
        _spec(
            SIGNAL_EXPLOIT,
            "Severity of advisories that apply to the installed version.",
            scorecard_check="Vulnerabilities",
            scorecard_fidelity=ScorecardFidelity.APPROXIMATE,
            scorecard_note=(
                "Both read OSV. Scorecard reports a count of open advisories "
                "for the repository. Ours is severity-weighted, scoped to the "
                "installed version's affected ranges, and reports advisories "
                "whose applicability could not be decided rather than "
                "assuming them away (#61)."
            ),
        ),
        _spec(
            SIGNAL_VERSION,
            "How far the installed version trails the latest published one.",
            scorecard_note=(
                "Scorecard scores repositories, not installed versions, so it "
                "has no equivalent. The nearest thing is Pinned-Dependencies, "
                "which asks whether *this* project pins its own dependencies."
            ),
        ),
        _spec(
            SIGNAL_HEALTH_INDICATORS,
            "Whether the repository carries tests, CI, and contribution docs.",
            repository_derived=True,
            scorecard_check="CI-Tests",
            scorecard_fidelity=ScorecardFidelity.APPROXIMATE,
            scorecard_note=(
                "A composite of three presence checks, only one of which "
                "(CI) Scorecard asks about, and Scorecard asks it of pull "
                "requests rather than of the repository's configuration."
            ),
        ),
        # Reported on its own axis, never weighed. What a licence carries is a
        # legal and compliance obligation the consumer takes on, which is a
        # different kind of fact from a forecast of how the package will be
        # maintained — the category error #242 separated for advisories.
        # Blending it also measured worse: removing it raised the composite's
        # discrimination in all seven abandonment ablations, every clustered
        # interval excluding zero (#340).
        _spec(
            SIGNAL_LICENSE,
            "What obligation the declared license places on a consumer.",
            scored=False,
            scorecard_check="License",
            scorecard_fidelity=ScorecardFidelity.APPROXIMATE,
            scorecard_note=(
                "Scorecard asks whether a license file exists and is "
                "SPDX-recognized. We categorize the license — permissive, "
                "copyleft, network copyleft, commercial — and report the "
                "obligation it creates. A clean Apache-2.0 and a clean AGPL "
                "are identical upstream and far apart here."
            ),
        ),
        _spec(
            SIGNAL_COMMUNITY_POPULARITY,
            "How much attention the project has (star count).",
            repository_derived=True,
            scorecard_note=(
                "Scorecard deliberately excludes popularity: stars are not a "
                "security property. We keep it as a dampener on abandonment "
                "scoring, never as a finding in itself."
            ),
        ),
        _spec(
            SIGNAL_COMMUNITY_ACTIVITY,
            "Development cadence, in commits per month.",
            repository_derived=True,
            scorecard_check="Maintained",
            scorecard_fidelity=ScorecardFidelity.APPROXIMATE,
            scorecard_note=(
                "Both read commit activity. Scorecard folds issue activity in "
                "and thresholds at 90 days; ours is a rate over six months and "
                "is weighed apart from popularity so a well-starred package "
                "with a dead commit log cannot pass as healthy (#166)."
            ),
        ),
        _spec(
            SIGNAL_TRANSITIVE,
            "Size of the package's own dependency tree.",
            unmeasured_reason=UnmeasuredReason.LOOKUP_NOT_ATTEMPTED,
            scorecard_note=(
                "Scorecard has no dependency-tree-size check. Its "
                "Pinned-Dependencies check asks a different question, about "
                "how dependencies are referenced rather than how many exist."
            ),
        ),
        _spec(
            SIGNAL_SECURITY_POLICY,
            "Whether the repository publishes a security policy.",
            repository_derived=True,
            scorecard_check="Security-Policy",
            scorecard_fidelity=ScorecardFidelity.CLOSE,
            scorecard_note=(
                "Same question, same evidence (a SECURITY.md in a well-known "
                "location). Scorecard grades the policy's contents out of ten; "
                "ours is presence or absence."
            ),
        ),
        _spec(
            SIGNAL_DEPENDENCY_UPDATE,
            "Whether the repository runs an automated dependency updater.",
            repository_derived=True,
            scorecard_check="Dependency-Update-Tool",
            scorecard_fidelity=ScorecardFidelity.CLOSE,
            scorecard_note=(
                "Same question, same evidence (Dependabot or Renovate "
                "configuration in the repository)."
            ),
        ),
        _spec(
            SIGNAL_SIGNED_COMMITS,
            "Whether the project signs its commits, tags, or enforces signing.",
            repository_derived=True,
            # Retired from the composite (#339). Audited across eight real
            # repositories: it abstained on six, and the two findings tracked
            # merge tooling rather than signing practice -- the signatures it
            # does see are GitHub's web-flow key, applied to merge-button
            # merges. Still measured and published on its own axis, because
            # "these commits carry signature objects" remains a fact worth
            # reporting; it is not a forecast and no longer weighs on one.
            scored=False,
            scorecard_fidelity=ScorecardFidelity.REMOVED_UPSTREAM,
            scorecard_note=(
                "No Scorecard check asks this at v5.5.0, and this row is why "
                "the design was amended to keep our own names. We read git "
                "history directly: commit signature status (git log %G?), tag "
                "signature status, and workflow- or settings-enforced signing. "
                "Scorecard's nearest historical check was Signed-Tags, which "
                "existed at v2.0.0 and was gone by v3.2.1. The nearest live "
                "check, Signed-Releases, inspects the last release's *assets* "
                "for detached signature files and never reads git history, so "
                "it answers a different question and must not be joined to "
                "this signal. Do not rename this signal to either name."
            ),
        ),
        _spec(
            SIGNAL_BRANCH_PROTECTION,
            "Whether the default branch is protected.",
            repository_derived=True,
            # Retired from the composite (#339). Returned an identical 0.10
            # for five of eight audited repositories: real branch protection
            # is a GitHub API property and a clone cannot observe it, so what
            # was scored were file-based hints standing in for it. Re-specify
            # it against the API and it can come back.
            scored=False,
            scorecard_check="Branch-Protection",
            scorecard_fidelity=ScorecardFidelity.CLOSE,
            scorecard_note=(
                "Same question, same evidence. Scorecard needs an admin token "
                "to see the full settings and degrades without one; ours reads "
                "what an unauthenticated or read-scoped view exposes, so a "
                "disagreement here is usually a permissions difference rather "
                "than a finding."
            ),
        ),
        _spec(
            SIGNAL_MAINTAINED,
            "Whether the project shows signs of active maintenance.",
            repository_derived=True,
            scorecard_check="Maintained",
            scorecard_fidelity=ScorecardFidelity.CLOSE,
            scorecard_note=(
                "Same question and the closest of our three Maintained rows. "
                "Scorecard thresholds on activity in the trailing 90 days and "
                "treats an archived repository as unmaintained outright."
            ),
        ),
        _spec(
            SIGNAL_SOURCE_REPOSITORY,
            "Whether the registry declares a usable source repository at all.",
            scorecard_note=(
                "Scorecard starts from a repository URL, so it cannot ask "
                "this question: a package that declares no source is one it "
                "cannot score. That is precisely why we measure it — the "
                "packages Scorecard cannot reach are not thereby safe (#146)."
            ),
        ),
    )
}

#: Signals that can only be answered by reading the package's source
#: repository. Derived from the catalog rather than restated, so a new
#: repository-derived signal joins the #146 collapse by declaring itself once.
REPOSITORY_DERIVED_SIGNALS: FrozenSet[str] = frozenset(
    name for name, spec in SIGNAL_CATALOG.items() if spec.repository_derived
)

#: The signals the weighted composite is allowed to weigh. Derived from the
#: catalog for the same reason :data:`REPOSITORY_DERIVED_SIGNALS` is: a signal
#: declares its own membership once, in its row, rather than in a second list
#: that can disagree with it.
#:
#: The complement is not "signals we do not measure". It is signals measured
#: and published beside the verdict instead of inside it, because what they
#: state is a fact rather than a forecast.
SCORED_SIGNALS: FrozenSet[str] = frozenset(
    name for name, spec in SIGNAL_CATALOG.items() if spec.scored
)


def unmeasured_reason_for(
    signal: str,
    *,
    source_repository_unreadable: bool,
    advisory_lookup: AdvisoryLookupState,
    registry_lookup: Optional[RegistryLookupState],
) -> UnmeasuredReason:
    """Decide why a signal came back unmeasured. The only place that decides.

    The design's binding condition: classification lives in a centralized
    table, never in adapter-local judgment across eight adapters. This is that
    table's read side, and it takes facts rather than opinions — both arguments
    are states the pipeline *recorded*, not inferences about the package.

    All three are keyword-only and none has a default, so a caller cannot reach
    a fallback by forgetting one. ``registry_lookup`` may be ``None``; that is
    itself the recorded fact that no such lookup ran.

    Args:
        signal: A stable signal name from :data:`SIGNAL_CATALOG`.
        source_repository_unreadable: Whether the registry answered and no
            readable source repository came out of it.
        advisory_lookup: What the advisory sources established.
            ``NOT_ATTEMPTED`` is the answer for a scan that asked none.
        registry_lookup: What the package registries established, or None when
            no registry-lookup state was recorded — which is every ecosystem
            but Maven today (#278).

    Returns:
        The reason to record. Defaults to the signal's own catalog reason,
        which for all but ``transitive`` is ``NO_DATA_FROM_SOURCE`` — the
        honest fallback when nothing more specific is known.

    Raises:
        KeyError: If ``signal`` is not in the catalog. An unnamed signal is a
            drift bug, not a caller error to swallow.
    """
    spec = SIGNAL_CATALOG[signal]
    if source_repository_unreadable and spec.repository_derived:
        return UnmeasuredReason.SOURCE_REPOSITORY_UNREADABLE
    if signal == SIGNAL_EXPLOIT:
        # The two ways an advisory lookup produces no measurement are different
        # facts and get different reasons. "The sources were asked and did not
        # answer" is not "the sources answered and had nothing" — reporting the
        # second for the first is the whole of #219.
        if advisory_lookup is AdvisoryLookupState.FAILED:
            return UnmeasuredReason.SOURCE_LOOKUP_FAILED
        if advisory_lookup is AdvisoryLookupState.NOT_ATTEMPTED:
            return UnmeasuredReason.LOOKUP_NOT_ATTEMPTED
    # And the two ways a *registry* lookup produces no measurement, last,
    # because both of the facts above are more specific. An artifact nobody
    # could look up has no source repository to be unreadable and no advisory
    # verdict to explain, so in practice this branch is what remains.
    # ABSENT_EVERYWHERE falls through on purpose: every repository was asked
    # and answered, so the input really was absent from the source, which is
    # what the catalog's own reason already says.
    if registry_lookup is RegistryLookupState.FAILED:
        return UnmeasuredReason.SOURCE_LOOKUP_FAILED
    if registry_lookup is RegistryLookupState.NOT_ATTEMPTED:
        return UnmeasuredReason.LOOKUP_NOT_ATTEMPTED
    return spec.unmeasured_reason
