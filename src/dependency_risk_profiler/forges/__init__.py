"""Which forge hosts a repository, and what that forge can be asked (#292).

All but one of this tool's signals never reach a forge API. The eight
repository-derived ones are read from a shallow ``git clone`` — ``pathlib``
existence checks against :mod:`~dependency_risk_profiler.forge_paths` and
``git`` subprocesses — and that is what makes them portable: a host nobody
wrote an adapter for still answers seven of the eight, because ``git clone``
does not care who is serving it.

So this module is deliberately small. It covers the facts a clone *cannot*
carry, which is a short list:

* ``star_count`` — a forge-native social metric with no representation in git,
  and the only signal (``community_popularity``) that has no clone-based
  reading at all.
* ``contributor_count`` and ``commit_frequency`` — countable from git history,
  but not from the ``--depth 1`` clone this tool takes. One reachable commit
  reads as a single maintainer who last worked today, for every repository on
  earth, so the shallow-clone answer is refused and the API is asked instead.

**Coverage differs per forge, and the difference is the output.** The whole
point of routing through a table is that a host with no adapter produces
``UNMEASURED`` naming that fact, rather than a signal that quietly never
appears. ``docs/forge-coverage.md`` publishes the table, and
``testing/unit/test_forge_contract.py`` regenerates it from
:meth:`ForgeRegistry.coverage` so the document cannot drift from the adapters.

**Two states, never three.** :class:`ForgeAnswer` reuses
:class:`~dependency_risk_profiler.signals.MeasurementState` and
:class:`~dependency_risk_profiler.signals.UnmeasuredReason` rather than
defining a second vocabulary next to them (#164, #225). A capability an
adapter does not declare is not a ``False`` and not a zero; it is an
``UNMEASURED`` carrying ``LOOKUP_NOT_ATTEMPTED``, which is the existing member
for "the step that answers this never ran".

**Declaring a capability is not promising an answer.** ``capabilities``
describes the API surface — what this forge can ever be asked. A single call
may still come back ``UNMEASURED``: GitHub's contributor endpoint needs a
token, and without one the answer is unmeasured while the capability remains
declared. The router uses the declaration to decide whether to *ask*; the
answer describes the call.

**Routing is by host, and never by probe.** ``match_forge_by_host`` reads a
registered table and opens no socket. Self-hosted instances are not
identifiable from a hostname — ``git.autistici.org`` is GitLab and
``git.9pm.me`` is Forgejo, so a ``git.`` prefix discriminates nothing — and
probing means an outbound request to a host named by third-party registry
metadata. That is filed as #294 and defaults off; known-host routing covers
99.55% of packages that declare a forge. Nothing here makes a request to a
host in order to find out what it is.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Tuple, Type
from urllib.parse import urlparse

from ..signals import FieldSource, MeasurementState, UnmeasuredReason
from ..utils import canonical_repository_url


class ForgeSoftware(Enum):
    """The forge software an adapter speaks to.

    The software, not the deployment: one adapter serves every instance of it.
    Members arrive with the adapter that implements them, so this enum never
    names a forge nothing can talk to.
    """

    GITHUB = "github"


class ForgeCapability(Enum):
    """A fact a forge API can be asked for that a shallow clone cannot supply.

    Every member here is asked for by
    :func:`~dependency_risk_profiler.community.analyzer.analyze_forge_community_metrics`
    and served by at least one adapter. Facts read from the clone — file
    existence, tags, branch protection as expressed in-tree — are absent on
    purpose: they are answered on every host without an adapter, and a
    capability nothing routes to would be a declaration with no reader.
    """

    #: Stars, or the forge's equivalent social count. The one fact behind
    #: ``community_popularity``, which has no clone-based reading at all.
    STAR_COUNT = "star_count"
    #: Distinct contributors. Countable from full git history; a ``--depth 1``
    #: clone always answers one, which is why the API is asked.
    CONTRIBUTOR_COUNT = "contributor_count"
    #: Commits per month over the trailing window, for the same reason.
    COMMIT_FREQUENCY = "commit_frequency"


@dataclass(frozen=True)
class CanonicalRepo:
    """A repository's identity on a forge, parsed once for every reader.

    Built only by :meth:`from_url`, which delegates the parsing to
    :func:`~dependency_risk_profiler.utils.canonical_repository_url`. That
    function is the tool's single normaliser: it upgrades ``http://``, strips
    ``www.``, refuses embedded credentials and lookalike hosts, and trims a
    deep path such as ``/tree/v2.0.6`` back to the repository root. Re-deriving
    any of that here would be a second implementation to disagree with the
    first.

    Attributes:
        host: Lowercased host, with no userinfo and no ``www.`` prefix.
        owner: First path segment. SourceHut's leading ``~`` is part of the
            owner and is preserved.
        name: Second path segment, with any ``.git`` suffix removed.
        clone_url: The ``https://host/owner/name`` root.
    """

    host: str
    owner: str
    name: str
    clone_url: str

    @classmethod
    def from_url(cls, repo_url: Optional[str]) -> Optional["CanonicalRepo"]:
        """Parse a published repository URL into a forge identity.

        Args:
            repo_url: A repository URL as a registry, lockfile or manifest
                published it, or an already-canonical one. The normaliser is
                idempotent, so a URL that has been through it already is
                unchanged.

        Returns:
            The identity, or ``None`` when the URL names no usable repository
            on a host this tool clones from. ``None`` is not a failure to
            report — it is the same answer the clone path already reached.
        """
        canonical = canonical_repository_url(repo_url)
        if canonical is None:
            return None
        parsed = urlparse(canonical)
        owner, _, name = parsed.path.lstrip("/").partition("/")
        return cls(
            host=parsed.netloc,
            owner=owner,
            name=name,
            clone_url=canonical,
        )


class ForgeAnswer:
    """One forge fact, or the reason there isn't one.

    The same gate as
    :class:`~dependency_risk_profiler.signals.Measurement`, and the same two
    states: ``MEASURED`` requires a value and forbids a reason, ``UNMEASURED``
    requires a reason and forbids a value. A separate type rather than a reuse
    because a forge answer additionally carries *which* acquisition path
    produced it, and ``Measurement`` is built once per scored signal per
    dependency across an org scan's thousands — a field only this path reads
    does not belong on it.

    ``field_source`` travels with the value for the reason
    :class:`~dependency_risk_profiler.signals.FieldSource` exists: a star count
    scraped from HTML and one read from ``stargazers_count`` are not the same
    number with different latency, and a consumer holding one of them needs to
    know which. It is required on a measured answer and forbidden on an
    unmeasured one, so an answer nobody measured cannot claim a source.
    """

    __slots__ = ("state", "value", "reason", "field_source")

    state: MeasurementState
    value: Optional[float]
    reason: Optional[UnmeasuredReason]
    field_source: Optional[FieldSource]

    def __init__(
        self,
        state: MeasurementState,
        value: Optional[float],
        reason: Optional[UnmeasuredReason],
        field_source: Optional[FieldSource],
    ) -> None:
        """Build an answer, rejecting every inconsistent combination.

        Prefer :meth:`measured` or :meth:`unmeasured`; this signature exists so
        the invariant has one enforcement point rather than two.

        Args:
            state: Whether the forge answered.
            value: The measured value. Required for ``MEASURED``, forbidden
                for ``UNMEASURED``.
            reason: Why there is no value. Required for ``UNMEASURED``,
                forbidden for ``MEASURED``.
            field_source: Which acquisition path produced the value. Required
                for ``MEASURED``, forbidden for ``UNMEASURED``.

        Raises:
            ValueError: If the arguments describe an answer carrying a value
                nobody measured, a measurement with no value, or a value with
                no provenance.
        """
        if state is MeasurementState.MEASURED:
            if value is None:
                raise ValueError("a MEASURED forge answer must carry a value")
            if reason is not None:
                raise ValueError("a MEASURED forge answer must not carry a reason")
            if field_source is None:
                raise ValueError("a MEASURED forge answer must carry a field source")
        else:
            if reason is None:
                raise ValueError("an UNMEASURED forge answer must carry a reason")
            if value is not None:
                raise ValueError(
                    "an UNMEASURED forge answer must not carry a value: a "
                    "number nobody measured is what this type exists to make "
                    "unrepresentable"
                )
            if field_source is not None:
                raise ValueError(
                    "an UNMEASURED forge answer must not carry a field source: "
                    "nothing produced a value for it to describe"
                )
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "field_source", field_source)

    def __setattr__(self, name: str, value: object) -> None:
        """Refuse post-construction edits.

        Args:
            name: Attribute being assigned.
            value: Value being assigned.

        Raises:
            AttributeError: Always. Validation happens once, at construction;
                an editable answer is one assignment away from carrying the
                combination the constructor rejects.
        """
        raise AttributeError(f"ForgeAnswer is immutable; cannot set {name!r}")

    def __delattr__(self, name: str) -> None:
        """Refuse post-construction deletes.

        Args:
            name: Attribute being deleted.

        Raises:
            AttributeError: Always, for the same reason as :meth:`__setattr__`.
        """
        raise AttributeError(f"ForgeAnswer is immutable; cannot delete {name!r}")

    @classmethod
    def measured(cls, value: float, field_source: FieldSource) -> "ForgeAnswer":
        """Record a value a forge actually answered.

        Args:
            value: The measured value.
            field_source: Which acquisition path produced it.

        Returns:
            A ``MEASURED`` answer.
        """
        return cls(MeasurementState.MEASURED, value, None, field_source)

    @classmethod
    def unmeasured(cls, reason: UnmeasuredReason) -> "ForgeAnswer":
        """Record that there is no value, and why.

        Args:
            reason: Why the fact could not be measured.

        Returns:
            An ``UNMEASURED`` answer.
        """
        return cls(MeasurementState.UNMEASURED, None, reason, None)

    @property
    def is_measured(self) -> bool:
        """Whether this answer carries a value.

        Returns:
            ``True`` for a ``MEASURED`` answer.
        """
        return self.state is MeasurementState.MEASURED


class ForgeAdapter:
    """What one forge software can be asked, and how to ask it.

    Subclasses declare two class attributes and implement one method.
    ``__init_subclass__`` refuses a subclass that omits either attribute, so an
    adapter with no declared coverage fails at class-definition time rather
    than at the call site that trusted it. That is the structural half of
    "silence is not an answer": there is no default to fall back to, because
    there is no default.

    The router never calls :meth:`fetch` for a capability outside
    :attr:`capabilities`, which is what makes the declaration binding. An
    adapter therefore has no code path in which it could return a plausible
    stand-in for something its API does not serve — nobody asks it.
    """

    #: The forge software this adapter speaks to.
    software: ForgeSoftware
    #: Every capability this adapter can ever answer. Required: an adapter
    #: that declares nothing is asked nothing.
    capabilities: FrozenSet[ForgeCapability]

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Refuse an adapter that does not declare its own coverage.

        Args:
            **kwargs: Passed through to :class:`object`.

        Raises:
            TypeError: If ``software`` or ``capabilities`` is missing. Both are
                annotations on this class rather than values, so a subclass
                inherits no usable default and cannot reach one by omission.
        """
        super().__init_subclass__(**kwargs)
        for attribute in ("software", "capabilities"):
            if getattr(cls, attribute, None) is None:
                raise TypeError(
                    f"{cls.__name__} must declare {attribute!r}: a forge "
                    "adapter states its own coverage, and one that declares "
                    "none would be asked for facts it cannot serve"
                )

    def fetch(
        self,
        repo: CanonicalRepo,
        capability: ForgeCapability,
        token: Optional[str],
    ) -> ForgeAnswer:
        """Ask this forge for one fact about one repository.

        Called only for a capability in :attr:`capabilities`; the router
        answers the rest without reaching an adapter.

        Args:
            repo: The repository to ask about.
            capability: Which fact to fetch.
            token: A credential for this forge, when the caller resolved one.
                ``None`` is ordinary: an endpoint that needs one answers
                ``UNMEASURED`` rather than guessing.

        Returns:
            The fact, or the reason the forge did not supply it.

        Raises:
            NotImplementedError: If a subclass does not implement it.
        """
        raise NotImplementedError


class ForgeRegistry:
    """Routes a repository host to the adapter that speaks its forge.

    Mirrors :class:`~dependency_risk_profiler.parsers.registry.EcosystemRegistry`
    deliberately, including the lazy first-use registration: one table, so the
    set of hosts that route somewhere cannot drift from the set of adapters
    that exist. #265 is the cautionary tale — a second hand-written list beside
    the ecosystem registry's disagreed with it, and every .NET repository in
    every org scan was reported as holding no manifests.

    ``match_forge_by_host`` is the name-only tier and opens no socket. The
    probing tier that would identify a self-hosted instance is #294 and is not
    here; when it arrives it adds a second entry point beside this one, against
    the same table, exactly as ``detect_ecosystem`` sits beside
    ``match_ecosystem_by_path``.
    """

    #: Adapter instance per forge software. One instance: adapters hold no
    #: per-repository state, and the router passes everything they need.
    _adapters: Dict[ForgeSoftware, ForgeAdapter] = {}

    #: Host matchers per forge software, in registration order. A matcher is a
    #: ``(type, pattern)`` pair where type is ``"host"`` (exact) or
    #: ``"suffix"`` (a dot-anchored parent domain).
    _host_matchers: Dict[ForgeSoftware, List[Tuple[str, str]]] = {}

    @classmethod
    def register_adapter(
        cls,
        adapter_class: Type[ForgeAdapter],
        host_matchers: List[Dict[str, str]],
    ) -> None:
        """Register an adapter and the hosts it speaks for.

        Args:
            adapter_class: The adapter. Instantiated once here.
            host_matchers: Which hosts route to it. Each entry is a dict with
                ``type`` — ``"host"`` for an exact match or ``"suffix"`` for a
                parent domain matched on a dot boundary — and ``pattern``, a
                lowercase hostname.

        Raises:
            ValueError: If a matcher names an unknown type. An unroutable
                matcher would silently widen nothing, which is the kind of
                quiet no-op a registry exists to prevent.
        """
        adapter = adapter_class()
        compiled: List[Tuple[str, str]] = []
        for matcher in host_matchers:
            matcher_type = matcher["type"]
            if matcher_type not in {"host", "suffix"}:
                raise ValueError(
                    f"unknown forge host matcher type {matcher_type!r}: "
                    "expected 'host' or 'suffix'"
                )
            compiled.append((matcher_type, matcher["pattern"].lower()))
        cls._adapters[adapter.software] = adapter
        cls._host_matchers[adapter.software] = compiled

    @classmethod
    def match_forge_by_host(cls, host: str) -> Optional[ForgeSoftware]:
        """Identify the forge serving a host, from the host alone.

        Opens no socket and makes no request. A host this returns a forge for
        is one :meth:`adapter_for` also serves, because both read this table.

        Args:
            host: A hostname, as
                :attr:`CanonicalRepo.host` supplies it — already lowercased and
                stripped of userinfo and any ``www.`` prefix.

        Returns:
            The forge software, or ``None`` when no registered adapter claims
            the host. ``None`` is a first-class answer: the repository is still
            cloneable and still answers every clone-derived signal.
        """
        cls._ensure_adapters_registered()
        normalized = host.lower()
        for software, matchers in cls._host_matchers.items():
            for matcher_type, pattern in matchers:
                if matcher_type == "host" and normalized == pattern:
                    return software
                if matcher_type == "suffix" and normalized.endswith("." + pattern):
                    return software
        return None

    @classmethod
    def adapter_for(cls, repo: CanonicalRepo) -> Optional[ForgeAdapter]:
        """Return the adapter serving a repository's host.

        Args:
            repo: The repository whose host to route on.

        Returns:
            The adapter, or ``None`` when no registered adapter claims the
            host.
        """
        software = cls.match_forge_by_host(repo.host)
        if software is None:
            return None
        return cls._adapters[software]

    @classmethod
    def ask(
        cls,
        repo: CanonicalRepo,
        capability: ForgeCapability,
        token: Optional[str],
    ) -> ForgeAnswer:
        """Ask whichever forge serves this repository for one fact.

        The single entry point, and the place the declaration is enforced:
        :meth:`ForgeAdapter.fetch` is reached only when the adapter declared
        the capability. Both refusals name why, so a signal missing because
        nothing serves the host is distinguishable in the output from one the
        forge was asked for and did not supply.

        Args:
            repo: The repository to ask about.
            capability: Which fact to ask for.
            token: A credential for the forge, when the caller resolved one.

        Returns:
            The fact, or the reason there is none:

            * no adapter serves the host, or the adapter does not declare the
              capability -> ``LOOKUP_NOT_ATTEMPTED``, because nothing ran.
            * the adapter ran -> whatever it answered.
        """
        adapter = cls.adapter_for(repo)
        if adapter is None or capability not in adapter.capabilities:
            return ForgeAnswer.unmeasured(UnmeasuredReason.LOOKUP_NOT_ATTEMPTED)
        return adapter.fetch(repo, capability, token)

    @classmethod
    def coverage(cls) -> Dict[ForgeCapability, Dict[ForgeSoftware, bool]]:
        """Return which forge serves which capability.

        Derived from the registered adapters' own ``capabilities`` sets, the
        way ``REPOSITORY_DERIVED_SIGNALS`` is derived from ``SIGNAL_CATALOG``,
        so the published table is a view of the code rather than a second
        statement of it.

        Returns:
            Capability to forge to whether that forge declares it, covering
            every registered forge and every capability.
        """
        cls._ensure_adapters_registered()
        return {
            capability: {
                software: capability in adapter.capabilities
                for software, adapter in cls._adapters.items()
            }
            for capability in ForgeCapability
        }

    @classmethod
    def registered_forges(cls) -> List[ForgeSoftware]:
        """Return every forge software with a registered adapter.

        Returns:
            The forges, in registration order.
        """
        cls._ensure_adapters_registered()
        return list(cls._adapters)

    @classmethod
    def hosts_for(cls, software: ForgeSoftware) -> List[str]:
        """Return the host patterns routing to one forge.

        Production never needs this direction. Every production path goes
        host -> forge through :meth:`match_forge_by_host`; this is the inverse,
        and it exists so the mapping can be shown **total** rather than merely
        working on the hosts anyone happened to try. The round-trip assertion
        in ``test_forge_contract.py`` walks every registered forge, asks for its
        patterns, and checks each one routes back — which catches a forge
        registered with no route, and a pattern that routes to a different
        adapter than the one that declared it. Neither is reachable by testing
        the forward direction alone.

        So its only caller being a test is the design, not neglect. Recorded
        here because a dead-code sweep flagged it (#343), and a reason living
        only in a reviewer's head is the shape of defect this repository keeps
        removing.

        Args:
            software: Which forge.

        Returns:
            The patterns, suffix matchers rendered with their leading dot so
            the published table reads as the match it describes.
        """
        cls._ensure_adapters_registered()
        return [
            pattern if matcher_type == "host" else f".{pattern}"
            for matcher_type, pattern in cls._host_matchers.get(software, [])
        ]

    @classmethod
    def _ensure_adapters_registered(cls) -> None:
        """Register the built-in adapters if nothing has yet.

        Without this an early caller gets a confident "no forge serves this
        host" from an empty registry, which is the reassuring answer and the
        wrong one. Imported here rather than at module scope because the
        adapters import this module's contract types.
        """
        if cls._adapters:
            return
        from . import github

        github.register()
