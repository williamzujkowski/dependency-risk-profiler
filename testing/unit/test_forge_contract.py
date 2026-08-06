"""The forge adapter contract, the router, and the published coverage table (#292).

Four properties, and they are why the layer is a contract rather than a helper:

1. **An adapter states its own coverage, or it does not exist.** A subclass that
   omits ``capabilities`` fails at class-definition time. Rule 4 by
   construction: there is no default to reach by forgetting.
2. **The router never asks an adapter for a capability it did not declare.** So
   an adapter has no code path in which it could return a plausible stand-in for
   something its API does not serve — nobody asks it. Asserted on the *call*,
   not on the return value: a return-value assertion cannot tell a refusal from
   an adapter that answered unmeasured on its own.
3. **A forge answer cannot carry a value nobody measured.** Same gate as
   ``Measurement``, plus provenance: a measured answer must say which
   acquisition path produced it, and an unmeasured one must not claim any.
4. **``docs/forge-coverage.md`` matches the registered adapters exactly.** A
   published coverage table that drifts from the code is worse than none,
   because it looks authoritative.
"""

import re
from pathlib import Path
from typing import List, Optional
from unittest import mock

import pytest

from dependency_risk_profiler.community.analyzer import analyze_forge_community_metrics
from dependency_risk_profiler.contract import forge_to_dict
from dependency_risk_profiler.forges import (
    CanonicalRepo,
    ForgeAdapter,
    ForgeAnswer,
    ForgeCapability,
    ForgeRegistry,
    ForgeSoftware,
)
from dependency_risk_profiler.forges import github as github_forge
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.signals import (
    FieldSource,
    MeasurementState,
    ProvenancedField,
    UnmeasuredReason,
)
from dependency_risk_profiler.utils import _CLONEABLE_HOSTS

DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "forge-coverage.md"

#: Enough of a GitHub repository page for the star scrape.
GITHUB_REPO_HTML = '<span class="Counter js-social-count">4,321</span>'


def _repo(url: str = "https://github.com/pallets/jinja") -> CanonicalRepo:
    """Build a canonical repository for a URL that must parse.

    Args:
        url: The repository URL.

    Returns:
        The parsed identity.
    """
    repo = CanonicalRepo.from_url(url)
    assert repo is not None, url
    return repo


# ---------------------------------------------------------------------------
# 1. An adapter states its own coverage, or it does not exist
# ---------------------------------------------------------------------------


def test_an_adapter_that_declares_no_capabilities_cannot_be_defined() -> None:
    """Rule 4 by construction: coverage cannot be reached by omission."""
    with pytest.raises(TypeError, match="must declare 'capabilities'"):

        class Uncapable(ForgeAdapter):
            """An adapter that says nothing about what it can answer."""

            software = ForgeSoftware.GITHUB


def test_an_adapter_that_names_no_forge_cannot_be_defined() -> None:
    """The other half of the same declaration."""
    with pytest.raises(TypeError, match="must declare 'software'"):

        class Anonymous(ForgeAdapter):
            """An adapter that does not say whose API it speaks."""

            capabilities = frozenset({ForgeCapability.STAR_COUNT})


def test_the_github_adapter_declares_every_capability_its_fetch_serves() -> None:
    """The declaration and the implementation are one claim, checked both ways.

    Every declared capability must produce an answer rather than raising, and
    the adapter must declare every capability its ``fetch`` knows how to serve.
    A declaration wider than the implementation is what the rule-6 exercise for
    this change reintroduces.
    """
    adapter = github_forge.GitHubAdapter()
    repo = _repo()
    with (
        mock.patch.object(github_forge, "github_contributor_count", return_value=None),
        mock.patch.object(github_forge, "github_commit_frequency", return_value=None),
        mock.patch.object(github_forge, "fetch_url", return_value=None),
    ):
        for capability in adapter.capabilities:
            answer = adapter.fetch(repo, capability, token=None)
            assert not answer.is_measured
            assert answer.reason is not None


# ---------------------------------------------------------------------------
# 2. The router never asks for an undeclared capability
# ---------------------------------------------------------------------------


class _RecordingAdapter(ForgeAdapter):
    """An adapter that records every capability it was actually asked for."""

    software = ForgeSoftware.GITHUB
    capabilities = frozenset({ForgeCapability.STAR_COUNT})

    def __init__(self) -> None:
        """Start with an empty call log."""
        self.asked: List[ForgeCapability] = []

    def fetch(
        self,
        repo: CanonicalRepo,
        capability: ForgeCapability,
        token: Optional[str],
    ) -> ForgeAnswer:
        """Record the call and answer with a fixed star count.

        Args:
            repo: Ignored; this adapter answers the same way for every repo.
            capability: Recorded, so the test can assert on the call.
            token: Ignored.

        Returns:
            A measured star count.
        """
        self.asked.append(capability)
        return ForgeAnswer.measured(1.0, FieldSource.GITHUB_HTML_SCRAPE)


def test_the_router_does_not_call_fetch_for_an_undeclared_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The binding condition, asserted on the call rather than the answer.

    An adapter cannot return a plausible default for something its API does not
    serve, because it is never reached. Checking only the returned answer would
    pass just as well against an adapter that decided to answer unmeasured by
    itself, which is the discipline this replaces.
    """
    adapter = _RecordingAdapter()
    monkeypatch.setattr(
        ForgeRegistry, "_adapters", {ForgeSoftware.GITHUB: adapter}, raising=True
    )
    monkeypatch.setattr(
        ForgeRegistry,
        "_host_matchers",
        {ForgeSoftware.GITHUB: [("host", "github.com")]},
        raising=True,
    )
    repo = _repo()

    served = ForgeRegistry.ask(repo, ForgeCapability.STAR_COUNT, token=None)
    refused = ForgeRegistry.ask(repo, ForgeCapability.CONTRIBUTOR_COUNT, token=None)

    assert adapter.asked == [ForgeCapability.STAR_COUNT]
    assert served.is_measured
    assert not refused.is_measured
    assert refused.reason is UnmeasuredReason.LOOKUP_NOT_ATTEMPTED


def test_a_host_no_adapter_serves_is_unmeasured_rather_than_absent() -> None:
    """Different coverage per forge, visible rather than silent."""
    repo = _repo("https://codeberg.org/allauth/django-allauth")

    assert ForgeRegistry.match_forge_by_host(repo.host) is None
    for capability in ForgeCapability:
        answer = ForgeRegistry.ask(repo, capability, token=None)
        assert not answer.is_measured
        assert answer.reason is UnmeasuredReason.LOOKUP_NOT_ATTEMPTED
        assert answer.field_source is None


# ---------------------------------------------------------------------------
# 3. A forge answer cannot carry a value nobody measured
# ---------------------------------------------------------------------------


def test_measured_requires_a_value_and_a_source() -> None:
    """A number with no provenance is the thing FieldSource exists to prevent."""
    with pytest.raises(ValueError, match="must carry a value"):
        ForgeAnswer(MeasurementState.MEASURED, None, None, FieldSource.GITHUB_HTML_SCRAPE)
    with pytest.raises(ValueError, match="must carry a field source"):
        ForgeAnswer(MeasurementState.MEASURED, 1.0, None, None)


def test_measured_cannot_also_carry_a_reason() -> None:
    """Neither state, and never both."""
    with pytest.raises(ValueError, match="must not carry a reason"):
        ForgeAnswer(
            MeasurementState.MEASURED,
            1.0,
            UnmeasuredReason.NO_DATA_FROM_SOURCE,
            FieldSource.GITHUB_HTML_SCRAPE,
        )


def test_unmeasured_cannot_carry_a_value_or_a_source() -> None:
    """The #141 shape, unrepresentable rather than discouraged."""
    with pytest.raises(ValueError, match="must carry a reason"):
        ForgeAnswer(MeasurementState.UNMEASURED, None, None, None)
    with pytest.raises(ValueError, match="must not carry a value"):
        ForgeAnswer(
            MeasurementState.UNMEASURED,
            1.0,
            UnmeasuredReason.NO_DATA_FROM_SOURCE,
            None,
        )
    with pytest.raises(ValueError, match="must not carry a field source"):
        ForgeAnswer(
            MeasurementState.UNMEASURED,
            None,
            UnmeasuredReason.NO_DATA_FROM_SOURCE,
            FieldSource.GITHUB_HTML_SCRAPE,
        )


def test_an_answer_cannot_be_edited_into_the_other_state() -> None:
    """Validation happens once, at construction, so it cannot be bypassed."""
    answer = ForgeAnswer.unmeasured(UnmeasuredReason.NO_DATA_FROM_SOURCE)

    with pytest.raises(AttributeError):
        answer.value = 0.0
    with pytest.raises(AttributeError):
        del answer.reason

    assert answer.value is None
    assert not answer.is_measured


# ---------------------------------------------------------------------------
# Routing is by host, and by the whole host
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/pallets/jinja", ForgeSoftware.GITHUB),
        ("git+https://github.com/pallets/jinja.git", ForgeSoftware.GITHUB),
        ("http://github.com/necaris/python3-openid", ForgeSoftware.GITHUB),
        ("https://www.github.com/pallets/jinja", ForgeSoftware.GITHUB),
        ("https://gitlab.com/gitlab-org/gitlab", None),
        ("https://codeberg.org/allauth/django-allauth", None),
        ("https://bitbucket.org/atlassian/atlaskit", None),
        ("https://git.sr.ht/~sircmpwn/hare", None),
    ],
)
def test_routing_reads_the_host_and_nothing_else(
    url: str, expected: Optional[ForgeSoftware]
) -> None:
    """A URL routes on its host, after the one normaliser has parsed it."""
    repo = _repo(url)
    assert ForgeRegistry.match_forge_by_host(repo.host) is expected


def test_a_lookalike_host_does_not_route_to_github() -> None:
    """``github.com.evil.example`` is not a subdomain of github.com.

    The normaliser refuses it outright, so it never reaches routing at all; the
    suffix matcher is dot-anchored for the same reason, and this asserts both
    ends rather than trusting either.
    """
    assert CanonicalRepo.from_url("https://github.com.evil.example/x/y") is None
    assert ForgeRegistry.match_forge_by_host("github.com.evil.example") is None


def test_a_github_enterprise_subdomain_routes_to_github() -> None:
    """The suffix matcher's reason for existing."""
    assert (
        ForgeRegistry.match_forge_by_host("acme.github.com") is ForgeSoftware.GITHUB
    )


def test_canonicalisation_is_idempotent() -> None:
    """The pipeline stores an already-canonical URL, and parsing it must not move it.

    ``resolve_repository`` writes ``canonical_repository_url``'s output into
    ``repository_url``, so this layer re-parses a URL that has already been
    through the normaliser. If that were not a fixed point, routing would send
    the adapter a different repository than the clone used.
    """
    once = _repo("git+https://WWW.github.com/pallets/jinja.git/")
    twice = _repo(once.clone_url)
    assert once == twice
    assert once.host == "github.com"
    assert once.owner == "pallets"
    assert once.name == "jinja"


def test_a_url_naming_no_repository_yields_no_identity() -> None:
    """An owner with no repository is not a repository."""
    assert CanonicalRepo.from_url("https://github.com/rails") is None
    assert CanonicalRepo.from_url(None) is None


# ---------------------------------------------------------------------------
# 4. The published coverage table matches the registered adapters
# ---------------------------------------------------------------------------


def _generated_block(marker: str) -> List[str]:
    """Return the lines of one generated block in the published document.

    Args:
        marker: The block's name, as it appears in the BEGIN/END comments.

    Returns:
        The block's lines, comments excluded.

    Raises:
        AssertionError: If the block is absent or unterminated.
    """
    text = DOC_PATH.read_text(encoding="utf-8")
    match = re.search(
        rf"<!-- BEGIN GENERATED: {re.escape(marker)} -->\n(.*?)\n"
        rf"<!-- END GENERATED: {re.escape(marker)} -->",
        text,
        re.DOTALL,
    )
    assert match is not None, f"no generated block named {marker!r} in {DOC_PATH}"
    return match.group(1).splitlines()


def _rendered_capability_table() -> List[str]:
    """Render the capability table from the registered adapters.

    Returns:
        The markdown table's lines.
    """
    coverage = ForgeRegistry.coverage()
    forges = ForgeRegistry.registered_forges()
    header = "| Capability | " + " | ".join(f"`{f.value}`" for f in forges) + " |"
    divider = "| --- | " + " | ".join("---" for _ in forges) + " |"
    rows = [
        f"| `{capability.value}` | "
        + " | ".join("yes" if coverage[capability][f] else "no" for f in forges)
        + " |"
        for capability in ForgeCapability
    ]
    return [header, divider, *rows]


def _rendered_host_table() -> List[str]:
    """Render the host-routing table from the cloneable hosts and the registry.

    Returns:
        The markdown table's lines.
    """
    rows = []
    for host in _CLONEABLE_HOSTS:
        software = ForgeRegistry.match_forge_by_host(host)
        adapter = f"`{software.value}`" if software else "none"
        facts = "measured" if software else "unmeasured"
        rows.append(f"| `{host}` | {adapter} | {facts} |")
    return ["| Host | Adapter | Forge-only facts |", "| --- | --- | --- |", *rows]


def test_the_published_capability_table_matches_the_adapters() -> None:
    """A coverage table that drifts from the code looks authoritative and lies."""
    assert _generated_block("capability coverage") == _rendered_capability_table()


def test_the_published_host_table_covers_every_cloneable_host() -> None:
    """Every host the tool clones from appears, adapter or not.

    A host missing from this table is the case a reader cannot look up: it is
    cloned, it scores on fewer signals than a GitHub package, and the document
    does not say why.
    """
    assert _generated_block("host routing") == _rendered_host_table()


def test_every_registered_forge_is_routable_and_every_route_has_an_adapter() -> None:
    """One table: the hosts that route somewhere are the adapters that exist."""
    for software in ForgeRegistry.registered_forges():
        patterns = ForgeRegistry.hosts_for(software)
        assert patterns, software
        for pattern in patterns:
            host = f"acme{pattern}" if pattern.startswith(".") else pattern
            assert ForgeRegistry.match_forge_by_host(host) is software


# ---------------------------------------------------------------------------
# The production path: provenance and the serialized block
# ---------------------------------------------------------------------------


def test_a_scraped_star_count_names_the_path_that_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``field_sources`` names the acquisition path the adapter used."""
    monkeypatch.setattr(github_forge, "github_contributor_count", lambda *_: None)
    monkeypatch.setattr(github_forge, "github_commit_frequency", lambda *_: None)
    monkeypatch.setattr(github_forge, "fetch_url", lambda _: GITHUB_REPO_HTML)
    dependency = DependencyMetadata(
        name="jinja2",
        installed_version="3.1.6",
        repository_url="https://github.com/pallets/jinja",
    )

    analyze_forge_community_metrics(dependency)

    assert dependency.forge is ForgeSoftware.GITHUB
    assert dependency.community_metrics is not None
    assert dependency.community_metrics.star_count == 4321
    assert (
        dependency.field_sources[ProvenancedField.STAR_COUNT]
        is FieldSource.GITHUB_HTML_SCRAPE
    )


def test_a_codeberg_package_reports_why_it_scores_on_fewer_signals() -> None:
    """The output says the host was never asked, not that it had nothing to say."""
    dependency = DependencyMetadata(
        name="django-allauth",
        installed_version="64.2.1",
        repository_url="https://codeberg.org/allauth/django-allauth",
    )

    analyze_forge_community_metrics(dependency)
    block = forge_to_dict(dependency)

    assert dependency.forge is None
    assert block["software"] is None
    assert block["capabilities"] == {
        "star_count": {"state": "unmeasured", "reason": "lookup_not_attempted"},
        "contributor_count": {"state": "unmeasured", "reason": "lookup_not_attempted"},
        "commit_frequency": {"state": "unmeasured", "reason": "lookup_not_attempted"},
    }
    assert dependency.community_metrics is not None
    assert dependency.community_metrics.star_count is None


def test_a_github_package_the_api_could_not_answer_is_not_the_same_silence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``no_data_from_source`` is a forge that answered; the other is one nobody asked.

    Collapsing the two is what makes a coverage gap invisible: a Codeberg
    package and a GitHub package whose token was absent would otherwise produce
    the same empty star count with the same explanation.
    """
    monkeypatch.setattr(github_forge, "github_contributor_count", lambda *_: None)
    monkeypatch.setattr(github_forge, "github_commit_frequency", lambda *_: None)
    monkeypatch.setattr(github_forge, "fetch_url", lambda _: GITHUB_REPO_HTML)
    dependency = DependencyMetadata(
        name="jinja2",
        installed_version="3.1.6",
        repository_url="https://github.com/pallets/jinja",
    )

    analyze_forge_community_metrics(dependency)
    block = forge_to_dict(dependency)

    assert block["software"] == "github"
    assert block["capabilities"] == {
        "contributor_count": {
            "state": "unmeasured",
            "reason": "no_data_from_source",
        },
        "commit_frequency": {"state": "unmeasured", "reason": "no_data_from_source"},
        "star_count": {"state": "measured", "field_source": "github:html"},
    }


def test_a_page_that_did_not_load_is_a_failed_lookup_not_an_absent_star(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fetch that produced no page did not establish that the repo has no stars."""
    monkeypatch.setattr(github_forge, "github_contributor_count", lambda *_: None)
    monkeypatch.setattr(github_forge, "github_commit_frequency", lambda *_: None)
    monkeypatch.setattr(github_forge, "fetch_url", lambda _: None)
    dependency = DependencyMetadata(
        name="jinja2",
        installed_version="3.1.6",
        repository_url="https://github.com/pallets/jinja",
    )

    analyze_forge_community_metrics(dependency)

    stars = dependency.forge_answers[ForgeCapability.STAR_COUNT]
    assert stars.reason is UnmeasuredReason.SOURCE_LOOKUP_FAILED


def test_a_dependency_with_no_usable_repository_asks_no_forge() -> None:
    """Nothing to route on means nothing was asked, and the block says so."""
    dependency = DependencyMetadata(
        name="mystery",
        installed_version="1.0.0",
        repository_url="https://example.invalid/not-a-forge",
    )

    analyze_forge_community_metrics(dependency)

    assert dependency.forge_answers == {}
    assert forge_to_dict(dependency) == {"software": None, "capabilities": {}}
