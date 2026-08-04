"""SSRF controls on outbound fetches of attacker-influenceable URLs (#138).

The property under test is that validation happens on the *destination*, not on
the name: a hostname that looks public but resolves to a loopback, private,
link-local or cloud-metadata address must never be connected to, on the first
hop or on any redirect after it. No test here opens a socket — the resolver and
the single-request transport are both injected.
"""

import ssl
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import pytest

from dependency_risk_profiler.go_modules import (
    GO_IMPORT_MAX_BYTES,
    GO_IMPORT_MAX_REDIRECTS,
    GoModuleResolver,
    ModuleRepository,
)
from dependency_risk_profiler.secure_http import (
    HttpResponse,
    PinnedRequest,
    SafeFetcher,
    _PinnedHTTPSConnection,
    is_public_address,
    is_public_host,
    resolve_public_addresses,
)

# A public-looking hostname whose owner controls what it resolves to.
HOSTILE = "vanity.example"
FRIENDLY = "go.example"

PUBLIC_ADDRESS = "93.184.216.34"


class RecordingTransport:
    """A transport that serves canned responses and records what it was asked.

    Every request that reaches it is one that passed validation, so an empty
    ``requests`` list is the proof that a destination was refused *before* any
    connection was attempted.
    """

    def __init__(self, responses: Optional[Dict[str, HttpResponse]] = None) -> None:
        """Initialize the transport with a URL -> response map."""
        self.responses = responses or {}
        self.requests: List[PinnedRequest] = []

    def __call__(self, request: PinnedRequest) -> Optional[HttpResponse]:
        """Record the request and return its canned response, if any."""
        self.requests.append(request)
        return self.responses.get(request.url)

    @property
    def urls(self) -> List[str]:
        """Return the URLs a connection was actually attempted for."""
        return [request.url for request in self.requests]

    @property
    def addresses(self) -> List[str]:
        """Return the addresses each request was pinned to."""
        return [request.address for request in self.requests]


def _resolver(mapping: Dict[str, Sequence[str]]) -> Callable[[str, int], Sequence[str]]:
    """Return an AddressResolver backed by a fixed hostname -> addresses map."""

    def resolve(host: str, port: int) -> Sequence[str]:
        if host not in mapping:
            raise OSError(f"no such host: {host}")
        return mapping[host]

    return resolve


# --------------------------------------------------------------------------
# Address classification
# --------------------------------------------------------------------------

BLOCKED_ADDRESSES = [
    ("loopback v4", "127.0.0.1"),
    ("loopback v6", "::1"),
    ("private 10/8", "10.0.0.1"),
    ("private 172.16/12", "172.16.5.4"),
    ("private 192.168/16", "192.168.1.1"),
    ("link-local", "169.254.1.1"),
    ("aws/gcp/azure metadata", "169.254.169.254"),
    ("aws ecs metadata", "169.254.170.2"),
    ("alibaba metadata", "100.100.100.200"),
    ("oracle metadata", "192.0.0.192"),
    ("aws metadata over v6", "fd00:ec2::254"),
    ("unique local v6", "fc00::1"),
    ("link-local v6", "fe80::1"),
    ("multicast", "224.0.0.1"),
    ("reserved", "240.0.0.1"),
    ("unspecified", "0.0.0.0"),
    ("cgnat", "100.64.0.1"),
    ("v4-mapped metadata", "::ffff:169.254.169.254"),
    ("v4-mapped loopback", "::ffff:127.0.0.1"),
    ("6to4 metadata", "2002:a9fe:a9fe::1"),
    ("not an address", "not-an-address"),
    ("empty", ""),
]

ALLOWED_ADDRESSES = ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"]


@pytest.mark.parametrize(
    "address",
    [address for _, address in BLOCKED_ADDRESSES],
    ids=[name for name, _ in BLOCKED_ADDRESSES],
)
def test_non_public_addresses_are_refused(address: str) -> None:
    """Every non-routable or metadata address is rejected by classification."""
    assert not is_public_address(address)


@pytest.mark.parametrize("address", ALLOWED_ADDRESSES)
def test_public_addresses_are_allowed(address: str) -> None:
    """Ordinary public addresses stay usable."""
    assert is_public_address(address)


def test_public_host_still_screens_names() -> None:
    """Name-level screening is unchanged by the move into secure_http."""
    assert is_public_host("github.com")
    assert is_public_host("go.uber.org")
    assert not is_public_host("localhost")
    assert not is_public_host("nodots")
    assert not is_public_host("10.0.0.1")
    assert not is_public_host("::1")
    assert not is_public_host("169.254.169.254")
    assert not is_public_host(None)


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def test_resolution_refuses_the_host_when_any_address_is_private() -> None:
    """One bad address disqualifies the name, not just that answer.

    Taking the public address and connecting anyway would only make a rebinding
    attacker try twice.
    """
    resolve = _resolver({HOSTILE: [PUBLIC_ADDRESS, "127.0.0.1"]})
    assert resolve_public_addresses(HOSTILE, 443, resolve) == []


def test_resolution_returns_every_public_address() -> None:
    """A wholly public answer is returned in resolution order, deduplicated."""
    resolve = _resolver({FRIENDLY: [PUBLIC_ADDRESS, "1.1.1.1", PUBLIC_ADDRESS]})
    assert resolve_public_addresses(FRIENDLY, 443, resolve) == [
        PUBLIC_ADDRESS,
        "1.1.1.1",
    ]


def test_resolution_failure_is_not_an_exception() -> None:
    """A name that does not resolve yields no addresses rather than raising."""
    assert resolve_public_addresses("nx.example", 443, _resolver({})) == []


def test_scoped_and_bracketed_literals_are_normalized() -> None:
    """A zone-scoped link-local answer is still recognized as link-local."""
    resolve = _resolver({HOSTILE: ["fe80::1%eth0"]})
    assert resolve_public_addresses(HOSTILE, 443, resolve) == []


# --------------------------------------------------------------------------
# The rebinding case itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    ["169.254.169.254", "127.0.0.1", "10.1.2.3", "192.168.0.5", "fe80::1"],
)
def test_public_name_resolving_to_a_blocked_address_is_never_fetched(
    address: str,
) -> None:
    """The gap #138 names: the hostname passes, the destination must not.

    The transport recording nothing is the assertion — no connection is even
    attempted once resolution comes back with a blocked address.
    """
    transport = RecordingTransport()
    fetcher = SafeFetcher(
        resolve=_resolver({HOSTILE: [address]}),
        transport=transport,
    )
    assert fetcher.fetch_text(f"https://{HOSTILE}/pkg?go-get=1") is None
    assert transport.requests == []


def test_connection_is_pinned_to_the_validated_address() -> None:
    """The request carries the validated IP, with the hostname kept for TLS."""
    url = f"https://{FRIENDLY}/pkg?go-get=1"
    transport = RecordingTransport({url: HttpResponse(200, None, "<html></html>")})
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    assert fetcher.fetch_text(url) == "<html></html>"
    (request,) = transport.requests
    assert request.address == PUBLIC_ADDRESS
    assert request.host == FRIENDLY
    assert request.target == "/pkg?go-get=1"
    assert request.port == 443


# --------------------------------------------------------------------------
# Redirects — every hop re-validated, not just the first
# --------------------------------------------------------------------------


def test_redirect_to_a_rebinding_host_is_refused() -> None:
    """A 302 is a fresh destination and gets the full check again.

    This is the trap in a naive fix: validate the first hop, hand the rest to a
    redirect-following client, and the attacker just answers the first request
    with a Location pointing at the metadata service.
    """
    first = f"https://{FRIENDLY}/pkg?go-get=1"
    transport = RecordingTransport(
        {first: HttpResponse(302, f"https://{HOSTILE}/latest/meta-data/")}
    )
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS], HOSTILE: ["169.254.169.254"]}),
        transport=transport,
    )
    assert fetcher.fetch_text(first) is None
    # The first hop was fetched; the redirect target never was.
    assert transport.urls == [first]


@pytest.mark.parametrize(
    "location",
    [
        "http://go.example/plain",  # scheme downgrade
        "https://go.example:8443/pkg",  # non-443 port
        "https://user:pass@go.example/pkg",  # credentials
        "https://localhost/pkg",  # name-level block
        "https://127.0.0.1/pkg",  # IP literal
        "https://169.254.169.254/latest/meta-data/",  # metadata literal
        "gopher://go.example/pkg",  # non-HTTP scheme
    ],
)
def test_redirect_targets_are_screened_like_first_hops(location: str) -> None:
    """Redirect targets go through the identical URL validation."""
    first = f"https://{FRIENDLY}/pkg?go-get=1"
    transport = RecordingTransport({first: HttpResponse(302, location)})
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS], "go.example": [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    assert fetcher.fetch_text(first) is None
    assert transport.urls == [first]


def test_a_legitimate_redirect_chain_is_followed_and_re_resolved() -> None:
    """Redirects still work; each hop is resolved and pinned on its own."""
    first = f"https://{FRIENDLY}/pkg?go-get=1"
    second = "https://docs.example/pkg?go-get=1"
    transport = RecordingTransport(
        {
            first: HttpResponse(301, second),
            second: HttpResponse(200, None, "<html>ok</html>"),
        }
    )
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS], "docs.example": ["1.1.1.1"]}),
        transport=transport,
    )
    assert fetcher.fetch_text(first) == "<html>ok</html>"
    assert transport.urls == [first, second]
    assert transport.addresses == [PUBLIC_ADDRESS, "1.1.1.1"]


def test_relative_redirects_resolve_against_the_current_hop() -> None:
    """A relative Location is joined to the hop it came from, then re-checked."""
    first = f"https://{FRIENDLY}/pkg?go-get=1"
    second = f"https://{FRIENDLY}/moved?go-get=1"
    transport = RecordingTransport(
        {
            first: HttpResponse(302, "/moved?go-get=1"),
            second: HttpResponse(200, None, "<html>ok</html>"),
        }
    )
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    assert fetcher.fetch_text(first) == "<html>ok</html>"
    assert transport.urls == [first, second]


def test_redirect_budget_is_bounded() -> None:
    """A redirect chain longer than the budget yields nothing."""
    urls = [f"https://{FRIENDLY}/hop{index}" for index in range(8)]
    transport = RecordingTransport(
        {url: HttpResponse(302, urls[index + 1]) for index, url in enumerate(urls[:-1])}
    )
    fetcher = SafeFetcher(
        max_redirects=2,
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    assert fetcher.fetch_text(urls[0]) is None
    assert len(transport.requests) == 3


def test_redirect_loops_terminate() -> None:
    """A Location pointing back at an already-visited hop is not followed."""
    first = f"https://{FRIENDLY}/a"
    second = f"https://{FRIENDLY}/b"
    transport = RecordingTransport(
        {first: HttpResponse(302, second), second: HttpResponse(302, first)}
    )
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    assert fetcher.fetch_text(first) is None
    assert transport.urls == [first, second]


def test_redirect_without_a_location_stops() -> None:
    """A 302 with no Location is a dead end, not a crash."""
    first = f"https://{FRIENDLY}/pkg"
    transport = RecordingTransport({first: HttpResponse(302, None)})
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    assert fetcher.fetch_text(first) is None


# --------------------------------------------------------------------------
# First-hop URL screening
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://go.example/pkg",
        "https://go.example:8443/pkg",
        "https://user:pass@go.example/pkg",
        "https://localhost/pkg",
        "https://127.0.0.1/pkg",
        "file:///etc/passwd",
        "https:///pkg",
    ],
)
def test_refused_urls_never_reach_the_transport(url: str) -> None:
    """Scheme, credential, port and host rules apply before any resolution."""
    transport = RecordingTransport()
    fetcher = SafeFetcher(
        resolve=_resolver({"go.example": [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    assert fetcher.fetch_text(url) is None
    assert transport.requests == []


def test_explicit_port_443_is_accepted() -> None:
    """The default port written out is still the default port."""
    url = f"https://{FRIENDLY}:443/pkg"
    transport = RecordingTransport({url: HttpResponse(200, None, "ok")})
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    assert fetcher.fetch_text(url) == "ok"


def test_non_200_and_transport_failure_look_identical() -> None:
    """Every failure mode reports None, so none of them is a probe oracle."""
    url = f"https://{FRIENDLY}/pkg"
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS]}),
        transport=RecordingTransport({url: HttpResponse(404)}),
    )
    assert fetcher.fetch_text(url) is None
    fetcher = SafeFetcher(
        resolve=_resolver({FRIENDLY: [PUBLIC_ADDRESS]}),
        transport=RecordingTransport(),
    )
    assert fetcher.fetch_text(url) is None


# --------------------------------------------------------------------------
# The connection itself
# --------------------------------------------------------------------------


class _FakeSocket:
    """Stand-in for a connected socket."""


def test_connection_dials_the_pinned_address_but_speaks_the_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The socket goes to the validated IP; TLS and Host still say the name.

    Without this split there is no pinning: ``http.client`` would re-resolve
    ``self.host`` at connect time, which is exactly the window a rebinding
    resolver aims at.
    """
    import socket as socket_module

    dialed: List[Tuple[str, int]] = []
    recorded: Dict[str, Optional[str]] = {}

    def fake_create_connection(
        address: Tuple[str, int], timeout: object = None, *args: object
    ) -> object:
        dialed.append(address)
        return _FakeSocket()

    def recording_wrap_socket(
        sock: object,
        *args: object,
        server_hostname: Optional[str] = None,
        **kwargs: object,
    ) -> object:
        """Record the SNI hostname and hand the socket straight back."""
        recorded["hostname"] = server_hostname
        return sock

    monkeypatch.setattr(socket_module, "create_connection", fake_create_connection)

    # Recorded by patching the instance rather than by subclassing SSLContext:
    # a subclass whose `wrap_socket` takes and returns a stand-in violates the
    # signature it inherits, and there is no honest way to annotate that.
    # The context stays a real one, which is what the assertions below check.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    monkeypatch.setattr(context, "wrap_socket", recording_wrap_socket)

    connection = _PinnedHTTPSConnection(FRIENDLY, PUBLIC_ADDRESS, 443, 10.0, context)
    connection.connect()

    assert dialed == [(PUBLIC_ADDRESS, 443)]
    assert recorded["hostname"] == FRIENDLY
    assert connection.host == FRIENDLY
    # Verification is not weakened to make pinning work.
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED


# --------------------------------------------------------------------------
# The Go vanity path, end to end, through the hardened fetcher
# --------------------------------------------------------------------------


def _vanity_page(prefix: str, repo_root: str) -> str:
    """Return a minimal vanity page carrying one go-import meta tag."""
    return (
        "<html><head>"
        f'<meta name="go-import" content="{prefix} git {repo_root}">'
        "</head><body></body></html>"
    )


# The real vanity hosts #137 won coverage on. They must keep resolving.
LEGITIMATE_VANITY = [
    (
        "go.opentelemetry.io/otel/trace",
        "go.opentelemetry.io/otel",
        "https://github.com/open-telemetry/opentelemetry-go",
        "https://github.com/open-telemetry/opentelemetry-go",
        "trace",
    ),
    (
        "cloud.google.com/go/storage",
        "cloud.google.com/go",
        "https://github.com/googleapis/google-cloud-go",
        "https://github.com/googleapis/google-cloud-go",
        "storage",
    ),
    (
        "google.golang.org/grpc",
        "google.golang.org/grpc",
        "https://github.com/grpc/grpc-go",
        "https://github.com/grpc/grpc-go",
        "",
    ),
]


@pytest.mark.parametrize(
    "module_path,prefix,repo_root,expected_url,expected_subdir",
    LEGITIMATE_VANITY,
    ids=[case[0] for case in LEGITIMATE_VANITY],
)
def test_legitimate_vanity_hosts_still_resolve(
    module_path: str,
    prefix: str,
    repo_root: str,
    expected_url: str,
    expected_subdir: str,
) -> None:
    """Pinning must not cost the coverage the dynamic lookup was added for."""
    host = module_path.split("/", 1)[0]
    url = f"https://{module_path}?go-get=1"
    transport = RecordingTransport(
        {url: HttpResponse(200, None, _vanity_page(prefix, repo_root))}
    )
    fetcher = SafeFetcher(
        resolve=_resolver({host: [PUBLIC_ADDRESS]}),
        transport=transport,
    )
    resolver = GoModuleResolver(fetch=fetcher.fetch_text)
    assert resolver.resolve(module_path) == ModuleRepository(
        expected_url, expected_subdir
    )


def test_go_resolver_refuses_a_rebinding_vanity_host() -> None:
    """A hostile vanity domain gets no request out of the Go resolver at all."""
    transport = RecordingTransport()
    fetcher = SafeFetcher(
        resolve=_resolver({HOSTILE: ["169.254.169.254"]}),
        transport=transport,
    )
    resolver = GoModuleResolver(fetch=fetcher.fetch_text)
    resolution = resolver.resolve_module(f"{HOSTILE}/pkg")
    assert resolution.repository is None
    assert resolution.lookup_failed is True
    assert transport.requests == []


def test_go_resolver_bounds_are_carried_into_the_fetcher() -> None:
    """The Go-specific caps still apply once the fetch moved into secure_http."""
    resolver = GoModuleResolver(timeout=7)
    fetcher = resolver._fetcher
    assert fetcher.timeout == 7.0
    assert fetcher.max_bytes == GO_IMPORT_MAX_BYTES
    assert fetcher.max_redirects == GO_IMPORT_MAX_REDIRECTS
