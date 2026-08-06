"""Resolving Maven artifacts across more than one repository (#278).

Java is the only ecosystem here whose registry is a *set of repositories*, and
until #278 the tool knew one of them. Every ``androidx.*`` artifact is published
to Google's Maven repository and to no other, so on Signal-Android 62 of 94
dependencies 404'd on the only repository that was ever asked and every signal
for them came back unmeasured.

Two things are under test, and they are different in kind:

* **The resolution.** A Google-published artifact resolves; a Central-published
  one still resolves, from Central, and costs no Google request for its POM.
  These run against **captured** documents (AGENTS.md rule 5) replayed through
  the real :class:`MavenRepositoryClient`, so URL construction, status
  classification, byte bounds and the fetch budget all execute.

* **The record of who was asked.** "Every repository was asked and none of them
  publishes this" has to be structurally distinct from "one repository was
  asked" and from "one 404'd while another timed out" — rule 4, and #219's
  rule at repository scope. Those tests are **authored** on purpose: a
  cooperating repository cannot be made to time out, and the whole point is the
  error path.
"""

from typing import Dict, List, Optional, Tuple
from unittest import mock

import pytest
import requests
from registry_fixtures import RecordedResponse, load_ecosystem

from dependency_risk_profiler.analyzers.maven import MavenAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.maven_repositories import (
    CENTRAL,
    DEFAULT_REPOSITORIES,
    GOOGLE,
    ArtifactVersioning,
    MavenRepository,
    MavenRepositoryClient,
    RepositoryLookup,
    RepositoryOutcome,
)
from dependency_risk_profiler.parsers.pom_model import PomCoordinate
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    SIGNAL_LICENSE,
    SIGNAL_STALENESS,
    SIGNAL_TRANSITIVE,
    SIGNAL_VERSION,
    RegistryLookupState,
    UnmeasuredReason,
)

APPCOMPAT = PomCoordinate("androidx.appcompat", "appcompat", "1.7.1")
GUAVA = PomCoordinate("com.google.guava", "guava", "33.6.0-jre")


def _captured() -> Dict[str, bytes]:
    """Return every captured Maven document, keyed by the URL it came from."""
    bodies: Dict[str, bytes] = {}
    for ecosystem in ("maven", "gradle"):
        for fixture in load_ecosystem(ecosystem).values():
            bodies[fixture.source_url] = fixture.body
    return bodies


class RecordingTransport:
    """A ``requests.get`` stub that serves captured bytes and records the asks.

    Anything it has no recording for answers 404, which is what a repository
    that does not publish an artifact actually answers — verified by hand
    against both hosts for every coordinate used here. Nothing reaches a
    socket, and the client's own status handling, streaming and parse all run.
    """

    def __init__(
        self,
        bodies: Optional[Dict[str, bytes]] = None,
        statuses: Optional[Dict[str, int]] = None,
        raises: Tuple[str, ...] = (),
    ) -> None:
        """Initialize the transport.

        Args:
            bodies: URL to recorded body. Defaults to every captured document.
            statuses: URL to a status to answer instead of serving a body.
            raises: URLs whose request raises a transport error.
        """
        self.bodies = _captured() if bodies is None else bodies
        self.statuses = statuses or {}
        self.raises = raises
        self.requested: List[str] = []

    def __call__(self, url: str, **_kwargs: object) -> RecordedResponse:
        """Answer one request from the recording.

        Args:
            url: The URL the client built.

        Returns:
            The recorded response.

        Raises:
            requests.RequestException: For a URL listed in ``raises``.
        """
        self.requested.append(url)
        if url in self.raises:
            raise requests.RequestException("no route to host")
        status = self.statuses.get(url)
        if status is not None:
            return RecordedResponse(url, b"", status_code=status)
        body = self.bodies.get(url)
        if body is None:
            return RecordedResponse(url, b"", status_code=404)
        return RecordedResponse(url, body)

    def patch(self) -> "mock._patch[mock.MagicMock]":
        """Return the unentered patch of the repository transport."""
        return mock.patch(
            "dependency_risk_profiler.parsers.maven_repositories.requests.get",
            side_effect=self,
        )


# --- Resolution, against captured documents --------------------------------


def test_a_google_published_artifact_resolves_after_central_says_404() -> None:
    """REGRESSION #278: androidx is unreadable while only Central is asked.

    The whole issue in one assertion. Central genuinely 404s for
    androidx.appcompat:appcompat — that is not a fixture choice, it is what
    ``repo1.maven.org`` answers — so a resolver that stops at the first repository
    returns nothing and reports thirteen unmeasured signals for an artifact on
    essentially every Android application.
    """
    transport = RecordingTransport()
    client = MavenRepositoryClient(enabled=True)

    with transport.patch():
        lookup = client.fetch_pom(APPCOMPAT)

    assert lookup.document is not None
    assert lookup.document.artifact_id == "appcompat"
    # Both were asked, in order, and the record says which one had it.
    assert lookup.lookup.outcomes == (
        (CENTRAL, RepositoryOutcome.ABSENT),
        (GOOGLE, RepositoryOutcome.FOUND),
    )
    assert lookup.lookup.state is RegistryLookupState.ANSWERED


def test_a_central_published_artifact_still_resolves_from_central() -> None:
    """#278 must not move where an artifact that already worked comes from."""
    transport = RecordingTransport()
    client = MavenRepositoryClient(enabled=True)

    with transport.patch():
        lookup = client.fetch_pom(GUAVA)

    assert lookup.document is not None
    assert lookup.lookup.outcomes == ((CENTRAL, RepositoryOutcome.FOUND),)
    # The cost assertion: a Central hit never reaches Google, so a non-Android
    # project pays nothing at all for the second repository on its POM reads.
    assert not any("dl.google.com" in url for url in transport.requested)


def test_a_pom_read_prefers_the_repository_that_published_the_artifact() -> None:
    """The metadata lookup already established who has it; do not re-pay the 404."""
    transport = RecordingTransport()
    client = MavenRepositoryClient(enabled=True)

    with transport.patch():
        versioning = client.fetch_versioning("androidx.appcompat", "appcompat")
        transport.requested.clear()
        lookup = client.fetch_pom(APPCOMPAT, prefer=versioning.lookup.found_in)

    assert lookup.document is not None
    assert lookup.lookup.outcomes == ((GOOGLE, RepositoryOutcome.FOUND),)
    assert transport.requested == [GOOGLE.pom_url(APPCOMPAT)]


def test_a_stale_preference_costs_a_request_and_never_an_answer() -> None:
    """The hint is ordering only: a wrong one must not lose the artifact."""
    transport = RecordingTransport()
    client = MavenRepositoryClient(enabled=True)

    with transport.patch():
        lookup = client.fetch_pom(GUAVA, prefer=(GOOGLE,))

    assert lookup.document is not None
    assert lookup.lookup.outcomes == (
        (GOOGLE, RepositoryOutcome.ABSENT),
        (CENTRAL, RepositoryOutcome.FOUND),
    )


def test_the_release_history_is_merged_rather_than_taken_from_the_first() -> None:
    """REGRESSION #278: an abandoned mirror must not decide the latest version.

    ``com.android.tools.build:gradle`` is published to both repositories, and
    the two disagree by nine years: Central's copy stops at 2.3.0 with
    ``lastUpdated`` 2017-03-06, the day Google moved the Android toolchain to
    its own repository, while Google's is current. Both captures are real, and
    both are in the fixture set precisely so this disagreement is a recorded
    fact rather than an anecdote.

    First-hit-wins on Central would report a live artifact as nine years stale
    and a project on a current AGP as ahead of the latest release. That is a
    confident wrong number, which is worse than the unmeasured one #278 exists
    to remove.
    """
    transport = RecordingTransport()
    client = MavenRepositoryClient(enabled=True)

    with transport.patch():
        versioning = client.fetch_versioning("com.android.tools.build", "gradle")

    assert versioning.lookup.outcomes == (
        (CENTRAL, RepositoryOutcome.FOUND),
        (GOOGLE, RepositoryOutcome.FOUND),
    )
    assert versioning.latest is not None
    assert not versioning.latest.startswith("2.3"), (
        "Central's copy of the Android Gradle Plugin froze on 2017-03-06; "
        "taking it is the defect this test exists for"
    )
    assert versioning.last_updated is not None
    assert versioning.last_updated.year >= 2020


# --- The record of who was asked (authored: these are the error paths) ------


@pytest.mark.parametrize(
    "outcomes,expected",
    [
        pytest.param(
            ((CENTRAL, RepositoryOutcome.ABSENT),),
            RegistryLookupState.NOT_ATTEMPTED,
            id="one-of-two-answered-no",
        ),
        pytest.param(
            (
                (CENTRAL, RepositoryOutcome.ABSENT),
                (GOOGLE, RepositoryOutcome.ABSENT),
            ),
            RegistryLookupState.ABSENT_EVERYWHERE,
            id="both-answered-no",
        ),
        pytest.param(
            (
                (CENTRAL, RepositoryOutcome.ABSENT),
                (GOOGLE, RepositoryOutcome.UNANSWERED),
            ),
            RegistryLookupState.FAILED,
            id="one-no-one-outage",
        ),
        pytest.param(
            (
                (CENTRAL, RepositoryOutcome.UNANSWERED),
                (GOOGLE, RepositoryOutcome.FOUND),
            ),
            RegistryLookupState.ANSWERED,
            id="one-outage-one-hit",
        ),
        pytest.param((), RegistryLookupState.NOT_ATTEMPTED, id="nobody-asked"),
    ],
)
def test_absence_is_only_claimable_once_every_repository_has_answered(
    outcomes: Tuple[Tuple[MavenRepository, RepositoryOutcome], ...],
    expected: RegistryLookupState,
) -> None:
    """AGENTS.md rule 4, by construction rather than by convention.

    The state is derived from the outcomes and cannot be passed in, so a lookup
    that asked one of two repositories has no way to spell ``ABSENT_EVERYWHERE``
    — the row above it in this table is exactly the #278 defect, and the row
    below it is the #219 defect at repository scope.
    """
    lookup = RepositoryLookup(outcomes=outcomes, configured=DEFAULT_REPOSITORIES)
    assert lookup.state is expected


def test_a_spent_budget_leaves_the_artifact_unread_not_unpublished() -> None:
    """A walk that stops early cannot report the artifact as absent."""
    transport = RecordingTransport(bodies={})
    client = MavenRepositoryClient(enabled=True, fetch_budget=1)

    with transport.patch():
        lookup = client.fetch_pom(APPCOMPAT)

    assert lookup.document is None
    # Central answered "no"; Google was never reached, so absence is not a claim
    # this lookup is allowed to make.
    assert lookup.lookup.outcomes == ((CENTRAL, RepositoryOutcome.ABSENT),)
    assert lookup.lookup.state is RegistryLookupState.NOT_ATTEMPTED


@pytest.mark.parametrize(
    "status,expected",
    [
        pytest.param(404, RepositoryOutcome.ABSENT, id="404-not-published"),
        pytest.param(410, RepositoryOutcome.ABSENT, id="410-gone"),
        pytest.param(301, RepositoryOutcome.UNANSWERED, id="301-refused-redirect"),
        pytest.param(403, RepositoryOutcome.UNANSWERED, id="403-needs-credentials"),
        pytest.param(500, RepositoryOutcome.UNANSWERED, id="500-outage"),
        pytest.param(429, RepositoryOutcome.UNANSWERED, id="429-throttled"),
    ],
)
def test_only_a_negative_answer_counts_as_a_negative_answer(
    status: int, expected: RepositoryOutcome
) -> None:
    """AUTHORED, adversarial: statuses no cooperating repository would send.

    A redirect matters here beyond the general rule. Gradle's plugin portal
    303-redirects a miss to Central, and ``repo.spring.io/release`` answers 401
    to an anonymous request — so "a repository answered something that is not
    the document" is a real shape, not a hypothetical, and reading either as
    "not published" would be the #219 defect with a new cause.
    """
    url = CENTRAL.pom_url(APPCOMPAT)
    transport = RecordingTransport(bodies={}, statuses={url: status})
    client = MavenRepositoryClient(enabled=True, repositories=(CENTRAL,))

    with transport.patch():
        lookup = client.fetch_pom(APPCOMPAT)

    assert lookup.lookup.outcomes == ((CENTRAL, expected),)


def test_a_body_that_does_not_parse_is_not_an_absence() -> None:
    """AUTHORED, adversarial: 200 with junk is a source that did not answer."""
    url = CENTRAL.pom_url(APPCOMPAT)
    transport = RecordingTransport(bodies={url: b"<project><unclosed>"})
    client = MavenRepositoryClient(enabled=True, repositories=(CENTRAL,))

    with transport.patch():
        lookup = client.fetch_pom(APPCOMPAT)

    assert lookup.document is None
    assert lookup.lookup.outcomes == ((CENTRAL, RepositoryOutcome.UNANSWERED),)
    assert lookup.lookup.state is RegistryLookupState.FAILED


def test_a_transport_error_is_not_an_absence() -> None:
    """AUTHORED, adversarial: a dead network is not a fact about the artifact."""
    url = CENTRAL.pom_url(APPCOMPAT)
    transport = RecordingTransport(bodies={}, raises=(url,))
    client = MavenRepositoryClient(enabled=True, repositories=(CENTRAL,))

    with transport.patch():
        lookup = client.fetch_pom(APPCOMPAT)

    assert lookup.lookup.state is RegistryLookupState.FAILED
    assert lookup.lookup.unanswered == ("central",)


# --- What the report says about it -----------------------------------------


def _analyze(transport: RecordingTransport, name: str, version: str) -> DependencyMetadata:
    """Run the real analyzer over one coordinate against a recorded transport."""
    analyzer = MavenAnalyzer(client=MavenRepositoryClient(enabled=True))
    analyzer.clone_repos = False
    dep = DependencyMetadata(name=name, installed_version=version)
    with transport.patch():
        return analyzer.analyze({name: dep})[name]


def test_an_artifact_no_repository_publishes_is_absent_not_unread() -> None:
    """Both repositories answered, neither has it: a measured absence."""
    dep = _analyze(
        RecordingTransport(bodies={}), "com.nowhere:ghost", "1.0.0"
    )

    assert dep.registry_lookup_state is RegistryLookupState.ABSENT_EVERYWHERE
    assert dep.registry_sources_unavailable == ()

    score = RiskScorer().score_dependency(dep)
    assert (
        score.measurements[SIGNAL_LICENSE].reason
        is UnmeasuredReason.NO_DATA_FROM_SOURCE
    )
    assert any("No configured package repository" in f for f in score.factors)


def test_an_artifact_a_repository_could_not_answer_for_is_unread() -> None:
    """REGRESSION #219 at repository scope: an outage is not an absence.

    Central is unreachable and Google says it does not publish the artifact.
    Reading that pair as "not published anywhere" is the defect: the artifact
    may well be on Central, and nobody looked.
    """
    coordinate = PomCoordinate("com.nowhere", "ghost", "1.0.0")
    transport = RecordingTransport(
        bodies={},
        statuses={
            CENTRAL.metadata_url("com.nowhere", "ghost"): 503,
            CENTRAL.pom_url(coordinate): 503,
        },
    )
    dep = _analyze(transport, "com.nowhere:ghost", "1.0.0")

    assert dep.registry_lookup_state is RegistryLookupState.FAILED
    assert dep.registry_sources_unavailable == ("central",)

    score = RiskScorer().score_dependency(dep)
    assert (
        score.measurements[SIGNAL_LICENSE].reason
        is UnmeasuredReason.SOURCE_LOOKUP_FAILED
    )
    assert any(
        "registry lookup did not answer (central)" in factor
        for factor in score.factors
    ), score.factors


def test_the_androidx_case_reports_measured_signals_end_to_end() -> None:
    """#278's acceptance criterion 1, through the analyzer and the scorer."""
    dep = _analyze(RecordingTransport(), "androidx.appcompat:appcompat", "1.7.1")

    assert dep.registry_lookup_state is RegistryLookupState.ANSWERED
    assert dep.latest_version == "1.8.0-rc01"
    assert dep.last_updated is not None
    assert dep.transitive_source is not None
    score = RiskScorer().score_dependency(dep)
    assert score.insufficient_data is False
    # The three registry-derived signals #278 unlocks: what shipped last, how
    # far behind the pin is, and what the artifact itself pulls in.
    for signal in (SIGNAL_STALENESS, SIGNAL_VERSION, SIGNAL_TRANSITIVE):
        assert score.measurements[signal].is_measured, signal


# --- Security: the host set is closed --------------------------------------


def test_the_repository_host_set_is_a_compile_time_constant() -> None:
    """SECURITY: nothing a manifest or a response says can add a host.

    #278 adds one outbound host. What it does *not* add is a way for the file
    under analysis to choose one: Gradle's ``repositories { }`` and Maven's
    ``<repositories>`` name arbitrary URLs — Signal's own settings script names
    two under ``raw.githubusercontent.com`` — and they are not read. Every URL
    this client can build comes from a constant base plus a coordinate that
    passed the grammar.
    """
    for repository in DEFAULT_REPOSITORIES:
        assert repository.base_url.startswith("https://")
        assert "?" not in repository.base_url and "@" not in repository.base_url

    transport = RecordingTransport()
    _analyze(transport, "androidx.appcompat:appcompat", "1.7.1")

    allowed = {"repo1.maven.org", "dl.google.com"}
    hosts = {url.split("/")[2] for url in transport.requested}
    assert hosts <= allowed, hosts
    assert hosts == allowed, "both repositories should have been asked"


def test_the_offline_switch_covers_every_repository_question() -> None:
    """DEPENDENCY_RISK_NO_REMOTE_POMS means offline, including metadata."""
    transport = RecordingTransport()
    client = MavenRepositoryClient(enabled=False)

    with transport.patch():
        assert client.fetch_pom(APPCOMPAT).document is None
        versioning = client.fetch_versioning("androidx.appcompat", "appcompat")

    assert versioning == ArtifactVersioning(
        latest=None,
        last_updated=None,
        lookup=RepositoryLookup(outcomes=(), configured=DEFAULT_REPOSITORIES),
    )
    assert transport.requested == []
