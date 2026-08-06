"""Maven version resolution across parent POMs and imported BOMs (issue #128).

Every test here runs offline. ``testing/manifests/maven/repository`` is a small
on-disk mirror laid out exactly like Maven Central, and :class:`MirrorClient`
serves it through the real :class:`MavenRepositoryClient` code path — so URL
construction, coordinate validation, and the fetch budget are all exercised
without a socket.
"""

import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple
from unittest import mock

import pytest
import requests

from dependency_risk_profiler.parsers import maven_versions
from dependency_risk_profiler.parsers.maven import (
    VERSION_SOURCE_DECLARED,
    VERSION_SOURCE_KEY,
    VERSION_SOURCE_MANAGED,
    VERSION_SOURCE_UNMANAGED,
    MavenPomParser,
)
from dependency_risk_profiler.parsers.maven_repositories import (
    CENTRAL,
    NO_REMOTE_POMS_ENV,
    MavenRepositoryClient,
    RepositoryOutcome,
    is_valid_coordinate,
)
from dependency_risk_profiler.parsers.pom_model import PomCoordinate
from dependency_risk_profiler.parsers.xml_utils import parse_xml_bytes

MANIFESTS = Path(__file__).resolve().parents[1] / "manifests" / "maven"
MIRROR = MANIFESTS / "repository"


class MirrorClient(MavenRepositoryClient):
    """Serves POMs from the on-disk Maven Central mirror instead of the network.

    Narrowed to Central on purpose. Every test in this module is about the
    parent/BOM walk and its budget, and asking a second repository would change
    the fetch counts those tests assert without changing what they are testing.
    Multi-repository behaviour has its own file (#278).
    """

    def __init__(self, root: Path = MIRROR, fetch_budget: int = 48) -> None:
        """Initialize the mirror-backed client."""
        super().__init__(
            fetch_budget=fetch_budget, enabled=True, repositories=(CENTRAL,)
        )
        self.root = root
        self.requested: List[str] = []

    def _fetch_document(
        self, url: str
    ) -> Tuple[Optional[ElementTree.Element], RepositoryOutcome]:
        """Resolve a Maven Central URL against the local mirror tree."""
        self.requested.append(url)
        prefix = CENTRAL.base_url + "/"
        assert url.startswith(prefix), url
        path = self.root.joinpath(*url[len(prefix) :].split("/"))
        if not path.is_file():
            return None, RepositoryOutcome.ABSENT
        root = parse_xml_bytes(path.read_bytes(), url)
        if root is None:
            return None, RepositoryOutcome.UNANSWERED
        return root, RepositoryOutcome.FOUND


def _versions(path: Path, client: MavenRepositoryClient) -> Dict[str, str]:
    """Parse a POM and return name -> installed version."""
    deps = MavenPomParser(str(path), client=client).parse()
    return {name: dep.installed_version for name, dep in deps.items()}


def test_parent_managed_versions_resolve_through_the_chain() -> None:
    """REGRESSION #128: versions in a parent POM's <dependencyManagement> resolve.

    WebGoat's shape: a project whose dependencies carry no inline <version> and
    inherit them from a starter parent, which inherits them from a BOM.
    """
    client = MirrorClient()
    versions = _versions(MANIFESTS / "parent-managed" / "pom.xml", client)

    # The project's own <dependencyManagement> wins over the grandparent's.
    assert versions["com.google.guava:guava"] == "33.0.0-jre"
    # Two levels up, literal version.
    assert versions["com.example.platform:platform-starter-web"] == "3.4.0"
    # Two levels up, via a property declared two levels up.
    assert versions["org.jsoup:jsoup"] == "1.17.2"
    # Two levels up, via a property the leaf project overrides: leaf wins.
    assert versions["com.example.override:overridden"] == "9.9.9"
    # Pinned inline, untouched.
    assert versions["org.pinned:pinned-lib"] == "1.2.3"


def test_unreachable_managed_version_is_reported_unresolved_not_blank() -> None:
    """A version nobody manages is labelled, not silently blanked."""
    deps = MavenPomParser(
        str(MANIFESTS / "parent-managed" / "pom.xml"), client=MirrorClient()
    ).parse()

    ghost = deps["com.nowhere:ghost"]
    assert ghost.installed_version == ""
    assert ghost.additional_info[VERSION_SOURCE_KEY] == VERSION_SOURCE_UNMANAGED
    assert (
        deps["org.pinned:pinned-lib"].additional_info[VERSION_SOURCE_KEY]
        == VERSION_SOURCE_DECLARED
    )
    assert (
        deps["org.jsoup:jsoup"].additional_info[VERSION_SOURCE_KEY]
        == VERSION_SOURCE_MANAGED
    )


def test_imported_bom_versions_resolve_in_the_bom_s_own_scope() -> None:
    """REGRESSION #128: <scope>import</scope> BOMs supply versions.

    An imported BOM is resolved as its own effective POM: it inherits from its
    own parent and sees its own properties, not the importing project's.
    """
    client = MirrorClient()
    versions = _versions(MANIFESTS / "bom-import" / "pom.xml", client)

    # The importing project's own pin beats the BOM's.
    assert versions["com.example.cloud:cloud-config"] == "9.9.9"
    # Straight out of the imported BOM.
    assert versions["com.example.cloud:cloud-gateway"] == "4.1.2"
    # ${project.version} inside the BOM means the BOM's version, not the app's.
    assert versions["com.example.cloud:cloud-sibling"] == "2024.0.1"
    # The imported BOM's own parent is followed too.
    assert versions["com.example.nested:nested-lib"] == "7.7.7"
    # So is a BOM imported by an imported BOM.
    assert versions["com.example.deep:deep-lib"] == "5.5.5"
    # The importing project's property must not leak into the BOM's scope.
    assert versions["com.example.cloud:cloud-leaky"] == ""


def test_one_sprawling_bom_cannot_starve_the_imports_after_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REGRESSION #128: each import gets its own slice of the fetch budget.

    Google's cloud libraries BOM imports well over a hundred BOMs of its own.
    Walking it depth-first spent the whole client budget before the next import
    was looked at, which left OWASP wrongsecrets with six unresolvable versions
    that a fair share recovers.
    """
    monkeypatch.setattr(maven_versions, "MAX_FETCHES_PER_IMPORT", 1)
    client = MirrorClient()

    versions = _versions(MANIFESTS / "bom-import" / "pom.xml", client)

    # The first import spent its allowance on itself, so its nested BOM is lost.
    assert versions["com.example.deep:deep-lib"] == ""
    # The import declared after it is still reached, and still resolves.
    assert versions["com.example.cloud:cloud-gateway"] == "4.1.2"
    assert versions["com.example.nested:nested-lib"] == "7.7.7"


def test_a_fully_pinned_pom_never_touches_the_network(tmp_path: Path) -> None:
    """Resolution is lazy: nothing inherited means nothing fetched."""
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """<?xml version="1.0"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <groupId>com.example</groupId>
          <artifactId>pinned</artifactId>
          <version>1.0.0</version>
          <dependencies>
            <dependency>
              <groupId>org.jsoup</groupId>
              <artifactId>jsoup</artifactId>
              <version>1.17.2</version>
            </dependency>
          </dependencies>
        </project>
        """,
        encoding="utf-8",
    )
    client = MirrorClient()

    assert _versions(pom, client) == {"org.jsoup:jsoup": "1.17.2"}
    assert client.fetch_count == 0


def test_env_opt_out_degrades_to_locally_provable_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEPENDENCY_RISK_NO_REMOTE_POMS keeps resolution entirely offline."""
    monkeypatch.setenv(NO_REMOTE_POMS_ENV, "1")

    deps = MavenPomParser(str(MANIFESTS / "parent-managed" / "pom.xml")).parse()

    # Whatever the file itself proves still resolves.
    assert deps["com.google.guava:guava"].installed_version == "33.0.0-jre"
    assert deps["org.pinned:pinned-lib"].installed_version == "1.2.3"
    # Everything inherited is reported unresolved rather than guessed.
    assert deps["org.jsoup:jsoup"].installed_version == ""
    assert (
        deps["org.jsoup:jsoup"].additional_info[VERSION_SOURCE_KEY]
        == VERSION_SOURCE_UNMANAGED
    )


@pytest.mark.parametrize(
    "group_id,artifact_id,version",
    [
        ("../../etc", "passwd", "1.0"),  # traversal via group path segments
        ("com.example", "../evil", "1.0"),  # traversal via artifactId
        ("com.example", "art", "../1.0"),  # traversal via version
        ("com..example", "art", "1.0"),  # empty group segment
        ("com.example", "art", "${undefined}"),  # unresolved property
        ("com.example", "art/slash", "1.0"),  # path separator
        ("com.example", "art", "1.0 2.0"),  # whitespace
        ("com.example", "art", ""),  # empty version
        ("", "art", "1.0"),  # empty group
        ("com.example", "art", "[1.0,2.0)"),  # version range, not a coordinate
    ],
)
def test_malformed_coordinates_never_become_urls(
    group_id: str, artifact_id: str, version: str
) -> None:
    """SECURITY: a coordinate is validated before it is pasted into a path."""
    coordinate = PomCoordinate(group_id, artifact_id, version)

    assert is_valid_coordinate(coordinate) is False

    client = MirrorClient()
    assert client.fetch_pom(coordinate).document is None
    assert client.requested == []  # never reached the transport at all


def test_pom_url_pins_host_scheme_and_layout() -> None:
    """SECURITY: URLs are built for one host under one scheme."""
    url = CENTRAL.pom_url(PomCoordinate("com.example.platform", "platform-bom", "3.4.0"))

    assert url == (
        "https://repo1.maven.org/maven2/com/example/platform/platform-bom/"
        "3.4.0/platform-bom-3.4.0.pom"
    )


def test_fetch_budget_bounds_how_far_a_pom_chain_can_go() -> None:
    """SECURITY: a hostile chain cannot turn one scan into unbounded requests."""
    client = MirrorClient(fetch_budget=1)

    versions = _versions(MANIFESTS / "parent-managed" / "pom.xml", client)

    assert client.fetch_count == 1
    # The first parent was read; the grandparent that holds jsoup was not.
    assert versions["com.example.platform:platform-starter-web"] == ""
    assert versions["org.jsoup:jsoup"] == ""
    # Locally provable versions are unaffected.
    assert versions["com.google.guava:guava"] == "33.0.0-jre"


def test_remote_fetch_refuses_redirects_and_non_200() -> None:
    """SECURITY: a redirect cannot steer the fetch off Maven Central."""
    client = MavenRepositoryClient(enabled=True, repositories=(CENTRAL,))
    response = mock.MagicMock()
    response.status_code = 302
    response.__enter__.return_value = response
    response.__exit__.return_value = False

    with mock.patch(
        "dependency_risk_profiler.parsers.maven_repositories.requests.get",
        return_value=response,
    ) as get:
        lookup = client.fetch_pom(PomCoordinate("com.example", "art", "1.0"))
    assert lookup.document is None

    assert get.call_args.kwargs["allow_redirects"] is False
    assert get.call_args.kwargs["stream"] is True


def test_oversized_pom_response_is_abandoned_mid_stream() -> None:
    """SECURITY: the body is streamed and dropped once it passes the cap."""
    chunks_served = 0

    def _chunks(chunk_size: int) -> Iterator[bytes]:
        nonlocal chunks_served
        while True:
            chunks_served += 1
            yield b"\x00" * chunk_size

    response = mock.MagicMock()
    response.status_code = 200
    response.iter_content.side_effect = _chunks
    response.__enter__.return_value = response
    response.__exit__.return_value = False

    client = MavenRepositoryClient(enabled=True, repositories=(CENTRAL,))
    with mock.patch(
        "dependency_risk_profiler.parsers.maven_repositories.requests.get",
        return_value=response,
    ):
        lookup = client.fetch_pom(PomCoordinate("com.example", "art", "1.0"))
    assert lookup.document is None

    # It stopped; it did not read an infinite stream into memory.
    assert 0 < chunks_served < 64


def test_transport_failures_are_absorbed() -> None:
    """A dead network degrades to unresolved versions, never to a crash."""
    client = MavenRepositoryClient(enabled=True, repositories=(CENTRAL,))

    with mock.patch(
        "dependency_risk_profiler.parsers.maven_repositories.requests.get",
        side_effect=requests.RequestException("no route to host"),
    ):
        lookup = client.fetch_pom(PomCoordinate("com.example", "art", "1.0"))
    assert lookup.document is None


def test_external_entities_are_never_resolved() -> None:
    """SECURITY: no XXE — a SYSTEM entity fails the parse, it does not read."""
    document = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE p [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
        b"<project><version>&xxe;</version></project>\n"
    )

    assert parse_xml_bytes(document, "test://xxe") is None


def test_entity_amplification_is_refused() -> None:
    """SECURITY: a billion-laughs POM is rejected, not expanded."""
    # The classic nested-entity bomb: ten references per level, nine levels.
    entities = [b'<!ENTITY lol "lol">']
    for level in range(1, 10):
        previous = b"lol" if level == 1 else f"lol{level - 1}".encode()
        body = (b"&" + previous + b";") * 10
        entities.append(f'<!ENTITY lol{level} "'.encode() + body + b'">')
    document = (
        b'<?xml version="1.0"?>\n<!DOCTYPE lolz [\n'
        + b"\n".join(entities)
        + b"\n]>\n<project>&lol9;</project>\n"
    )

    assert len(document) < 2048  # tiny input...
    assert parse_xml_bytes(document, "test://bomb") is None  # ...refused anyway
