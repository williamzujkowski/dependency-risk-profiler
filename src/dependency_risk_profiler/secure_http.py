"""SSRF-hardened HTTP for URLs that untrusted input can influence (#138).

Validating a hostname is not validating a destination. ``evil.example`` is
syntactically fine, publicly registered, and free to resolve to
``169.254.169.254``; every name-based check passes and the request still lands
on the cloud metadata service. That is DNS rebinding, and no amount of string
inspection catches it.

So this module does the resolution itself. For every request, and for every
redirect hop:

1. The URL must be ``https``, carry no credentials, and name no port but 443.
2. The hostname must be syntactically valid, public, and not ``localhost``.
3. The hostname is resolved, and **every** address it returns is checked
   against :func:`is_public_address`. One private, loopback, link-local,
   reserved, multicast, or known-metadata address disqualifies the whole host,
   because a resolver that returns a bad address once will return it again.
4. The connection is opened to a *validated address*, not to the name, so the
   name cannot resolve differently between the check and the connect. The
   original hostname is still what goes into SNI, the ``Host`` header, and
   certificate verification, so TLS is unweakened.

Redirects are followed by this module, never by the transport, precisely so
that steps 1-4 run again on each hop. A 302 to a rebinding host is refused the
same way the first hop would have been.

Why this lives at the package root rather than inside ``go_modules``: #136
consolidates package-to-repository resolution behind one shared resolver, and
every ecosystem it covers turns a third-party registry string into an outbound
request. That is the same SSRF sink the Go vanity-path lookup is, so the
control belongs somewhere all of them can import. ``go_modules`` is the first
caller, not the owner.

Nothing here follows redirects into ``http``, forwards headers across hosts, or
trusts a response body beyond the bytes the caller asked for.
"""

import http.client
import ipaddress
import logging
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urljoin, urlsplit

import certifi

logger = logging.getLogger(__name__)

#: Default cap on a response body, applied while reading rather than after.
DEFAULT_MAX_BYTES = 256 * 1024
#: Default redirect budget. Each hop is re-validated from scratch.
DEFAULT_MAX_REDIRECTS = 3
#: Default hard timeout, in seconds, for one request.
DEFAULT_TIMEOUT = 10.0
#: The only port we will connect to. An explicit port in a URL is refused.
HTTPS_PORT = 443

DEFAULT_USER_AGENT = "dependency-risk-profiler"

_HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)

_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Cloud metadata endpoints. Most are already caught by the link-local or
# private checks below; these are named anyway because the ones that are not
# (Oracle's 192.0.0.192 sits in an IETF assignment block that ``ipaddress``
# considers globally routable) are exactly the ones worth being explicit about.
_METADATA_ADDRESSES = frozenset(
    ipaddress.ip_address(value)
    for value in (
        "169.254.169.254",  # AWS, GCP, Azure, DigitalOcean, OpenStack
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud
        "fd00:ec2::254",  # AWS IMDS over IPv6
    )
)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

#: Resolves a hostname to a list of address literals. Injected in tests so the
#: suite can exercise rebinding without a resolver that actually rebinds.
AddressResolver = Callable[[str, int], Sequence[str]]


@dataclass(frozen=True)
class PinnedRequest:
    """One validated GET, addressed by IP and named by hostname.

    Attributes:
        url: The absolute URL this request came from, for logging only.
        host: Hostname for SNI, the ``Host`` header, and certificate checks.
        port: TCP port, always :data:`HTTPS_PORT`.
        address: The validated IP literal to actually connect to.
        target: Origin-form request target, ``/path?query``.
        headers: Request headers. Never carries credentials.
        timeout: Hard timeout in seconds.
        max_bytes: Cap on the body read from the response.
    """

    url: str
    host: str
    port: int
    address: str
    target: str
    headers: Mapping[str, str]
    timeout: float
    max_bytes: int


@dataclass(frozen=True)
class HttpResponse:
    """The little of a response this module is willing to carry.

    Attributes:
        status: HTTP status code.
        location: ``Location`` header, when the server sent one.
        body: Decoded body, empty for any non-200 status.
    """

    status: int
    location: Optional[str] = None
    body: str = ""


#: Performs one request against an already-validated address, following no
#: redirects. Injected in tests so no test opens a socket.
Transport = Callable[[PinnedRequest], Optional[HttpResponse]]


def is_public_address(address: str) -> bool:
    """Return True when an address literal is safe to connect to.

    Rejects private, loopback, link-local, reserved, multicast, unspecified and
    non-global addresses, the known cloud metadata endpoints, and any IPv6
    address that tunnels a rejected IPv4 address (mapped, 6to4 or Teredo).

    Args:
        address: An IP address literal, without brackets or a zone suffix.

    Returns:
        True when the address is publicly routable and not a metadata endpoint.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not _is_blocked_address(parsed)


def _is_blocked_address(address: _IPAddress) -> bool:
    """Return True when an address must not be connected to."""
    if address in _METADATA_ADDRESSES:
        return True
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        return True
    if isinstance(address, ipaddress.IPv6Address):
        # An IPv6 address can carry an IPv4 one inside it. Judge the payload.
        embedded: List[ipaddress.IPv4Address] = []
        if address.ipv4_mapped is not None:
            embedded.append(address.ipv4_mapped)
        if address.sixtofour is not None:
            embedded.append(address.sixtofour)
        teredo = address.teredo
        if teredo is not None:
            embedded.extend(teredo)
        return any(_is_blocked_address(item) for item in embedded)
    return False


def is_public_host(host: Optional[str]) -> bool:
    """Return True for a syntactically valid, publicly routable hostname.

    A name that passes here has still only passed a *name* check; the address
    it resolves to is validated separately by :func:`resolve_public_addresses`.

    Args:
        host: Hostname or IP literal, or None.

    Returns:
        True when the host is a well-formed public name or a public IP literal.
    """
    if not host:
        return False
    lowered = host.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return False
    stripped = lowered.strip("[]")
    try:
        ipaddress.ip_address(stripped)
    except ValueError:
        return _HOSTNAME.match(lowered) is not None
    return is_public_address(stripped)


def _system_addresses(host: str, port: int) -> Sequence[str]:
    """Resolve a hostname through the system resolver."""
    addresses: List[str] = []
    for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    return addresses


def resolve_public_addresses(
    host: str,
    port: int = HTTPS_PORT,
    resolve: Optional[AddressResolver] = None,
) -> List[str]:
    """Resolve a hostname and return its addresses only if all of them are safe.

    All-or-nothing on purpose. A name that answers with one public and one
    loopback address is a name being used to rebind; taking the public answer
    and connecting anyway would just make the attack take two tries.

    Args:
        host: Hostname to resolve.
        port: Port to resolve for.
        resolve: Optional replacement resolver, for tests.

    Returns:
        The validated addresses in resolution order, or an empty list when
        resolution failed or any returned address was not publicly routable.
    """
    lookup = resolve if resolve is not None else _system_addresses
    try:
        candidates = list(lookup(host, port))
    except OSError as exc:
        logger.debug("DNS resolution failed for %s: %s", host, exc)
        return []
    validated: List[str] = []
    for candidate in candidates:
        # getaddrinfo can hand back a scoped or bracketed literal.
        address = candidate.partition("%")[0].strip("[]")
        if not is_public_address(address):
            logger.warning(
                "Refusing %s: it resolves to the non-public address %s",
                host,
                address,
            )
            return []
        if address not in validated:
            validated.append(address)
    return validated


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection opened to a validated address, named by its host.

    ``http.client`` normally resolves ``self.host`` at connect time, which is
    the window a rebinding resolver aims at. Overriding :meth:`connect` closes
    it: the socket goes to the address we already validated, while SNI, the
    ``Host`` header and certificate verification all still use the hostname.
    """

    def __init__(
        self,
        host: str,
        address: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        """Initialize the connection.

        Args:
            host: Hostname, used for TLS and the ``Host`` header.
            address: Validated IP literal to connect to.
            port: TCP port.
            timeout: Socket timeout in seconds.
            context: TLS context; must verify hostnames and certificates.
        """
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._address = address
        self._ssl_context = context

    def connect(self) -> None:
        """Open the socket to the pinned address and wrap it for the hostname."""
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host)


def _pinned_https_request(request: PinnedRequest) -> Optional[HttpResponse]:
    """Perform one GET against a validated address, following no redirects.

    Args:
        request: The validated request.

    Returns:
        The response, or None when the request could not be completed.
    """
    context = ssl.create_default_context(cafile=certifi.where())
    connection = _PinnedHTTPSConnection(
        request.host,
        request.address,
        request.port,
        request.timeout,
        context,
    )
    try:
        connection.request("GET", request.target, headers=dict(request.headers))
        response = connection.getresponse()
        location = response.getheader("Location")
        if response.status != 200:
            return HttpResponse(response.status, location)
        payload = response.read(request.max_bytes)
        return HttpResponse(
            response.status,
            location,
            payload.decode("utf-8", errors="replace"),
        )
    except (OSError, http.client.HTTPException) as exc:
        logger.debug("Fetch failed for %s: %s", request.url, exc)
        return None
    finally:
        connection.close()


class SafeFetcher:
    """Fetches text from URLs an attacker may have chosen, or returns None.

    Every failure mode — refused URL, refused address, timeout, non-200,
    redirect budget exhausted — is reported the same way, as ``None``. The
    caller cannot distinguish them, and neither can an attacker probing through
    one.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        user_agent: str = DEFAULT_USER_AGENT,
        resolve: Optional[AddressResolver] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        """Initialize the fetcher.

        Args:
            timeout: Hard timeout, in seconds, per request.
            max_bytes: Cap on the body read from each response.
            max_redirects: How many hops to follow. Each is fully re-validated.
            user_agent: ``User-Agent`` to send.
            resolve: Optional replacement resolver, for tests.
            transport: Optional replacement single-request transport, for tests.
        """
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self._resolve = resolve
        self._transport: Transport = (
            transport if transport is not None else _pinned_https_request
        )

    def fetch_text(self, url: str, accept: str = "text/html") -> Optional[str]:
        """Fetch a URL as text, or return None if anything at all is wrong.

        Args:
            url: Absolute https URL. Anything else is refused.
            accept: ``Accept`` header to send.

        Returns:
            The decoded body, capped at ``max_bytes``, or None.
        """
        headers = {"Accept": accept, "User-Agent": self.user_agent}
        current = url
        seen = {current}
        for _ in range(self.max_redirects + 1):
            request = self._pin(current, headers)
            if request is None:
                return None
            response = self._transport(request)
            if response is None:
                return None
            if response.status not in _REDIRECT_STATUSES:
                return response.body if response.status == 200 else None
            if not response.location:
                return None
            # Resolve relative Locations against the hop we are on, then loop:
            # the next pass re-runs every scheme, host and address check.
            following = _next_url(current, response.location)
            if following is None or following in seen:
                return None
            seen.add(following)
            current = following
        logger.debug("Redirect limit reached fetching %s", url)
        return None

    def _pin(self, url: str, headers: Mapping[str, str]) -> Optional[PinnedRequest]:
        """Validate one URL and bind it to an address, or return None."""
        parsed = _parse_https_url(url)
        if parsed is None:
            return None
        host, target = parsed
        addresses = resolve_public_addresses(host, HTTPS_PORT, self._resolve)
        if not addresses:
            return None
        return PinnedRequest(
            url=url,
            host=host,
            port=HTTPS_PORT,
            address=addresses[0],
            target=target,
            headers=dict(headers),
            timeout=self.timeout,
            max_bytes=self.max_bytes,
        )


def _next_url(current: str, location: str) -> Optional[str]:
    """Resolve a ``Location`` header against the URL it was returned from."""
    candidate = urljoin(current, location.strip())
    if not candidate or candidate == current:
        return None
    return candidate


def _parse_https_url(url: str) -> Optional[Tuple[str, str]]:
    """Split an https URL into (hostname, origin-form target), or return None.

    Enforces the scheme, refuses embedded credentials and any explicit port
    other than 443, and rebuilds the request target from the parsed parts so
    nothing in the original string survives unexamined.
    """
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        return None
    if "@" in parsed.netloc:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None and port != HTTPS_PORT:
        return None
    host = parsed.hostname
    if host is None or not is_public_host(host):
        return None
    target = parsed.path or "/"
    if not target.startswith("/"):
        return None
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return host, target
