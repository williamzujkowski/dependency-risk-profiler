"""Resolution of Go module paths to the repositories that host their source.

A Go module path is an import path, not a repository URL, and three documented
rules stand between the two. Until all three are applied, most of a real Go
project's dependencies never resolve to a repository at all, so every
repository-derived signal stays unmeasured (#130):

* **Major-version suffixes.** ``/v2`` and up are part of the module path but
  not of the repository path — ``github.com/cespare/xxhash/v2`` lives in
  ``cespare/xxhash``.
* **Subdirectory modules.** One repository hosts many modules, each rooted in
  its own directory — ``github.com/aws/aws-sdk-go-v2/service/cloudfront`` is a
  subdirectory of ``aws/aws-sdk-go-v2``.
* **Vanity import paths.** ``go.uber.org/automaxprocs`` names a host that only
  serves an HTML ``go-import`` meta tag pointing at the real repository.

All three are handled by one normalizer, :meth:`GoModuleResolver.resolve`,
applied before any repository lookup. ``golang.org/x/<name>`` is rewritten to
its documented ``github.com/golang/<name>`` mirror by a static rule rather than
a network call: the class is near-universal in Go projects, and the module's
own ``go-import`` tag points at a Gerrit host that exposes none of the signals
we collect.

Resolution failure is not an error. It returns ``None``, the caller leaves the
repository unknown, and the affected signals stay honestly unmeasured — #74
already excludes unmeasured signals from both the numerator and the denominator
of the risk score, so nothing is fabricated.

Security note: the ``?go-get=1`` lookup fetches HTML from a host named by the
manifest under analysis, which an attacker may influence. The fetch is bounded
(hard timeout, response-size cap, small redirect limit, public hosts only), and
only the ``content`` attribute of ``go-import`` meta tags is read. The repository
root it yields is re-validated as an https URL on a public host before use;
scheme, credentials, port, query and fragment from the response are discarded.
The fetch itself is performed by :mod:`dependency_risk_profiler.secure_http`,
which resolves the host and pins the connection to a validated address on every
hop, so a public-looking vanity domain cannot rebind onto a private or
cloud-metadata address (#138).
"""

import logging
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

from .secure_http import SafeFetcher
from .secure_http import is_public_host as _is_public_host

logger = logging.getLogger(__name__)

# Hosts whose first two path segments identify a repository, and which we can
# actually collect signals from. Anything else is a vanity path until proven
# otherwise.
_CODE_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

# Go's major-version suffix rule: v2 and up appear in the module path, v0 and
# v1 never do (https://go.dev/ref/mod#major-version-suffixes).
_MAJOR_VERSION_SUFFIX = re.compile(r"^v(?:[2-9]|[1-9][0-9]+)$")

# Documented, stable mirrors resolved without a network call.
_STATIC_MIRRORS: Tuple[Tuple[str, str], ...] = (
    ("golang.org/x/", "github.com/golang/"),
)

# Bounds on the untrusted ?go-get=1 fetch. The document we want is a handful of
# meta tags; anything larger is not a Go vanity page.
GO_IMPORT_MAX_BYTES = 256 * 1024
GO_IMPORT_MAX_REDIRECTS = 3
GO_IMPORT_USER_AGENT = "dependency-risk-profiler (go-import lookup)"

# A callable that returns the body of a ?go-get=1 URL, or None. Injected so the
# test suite can exercise vanity resolution without touching the network.
MetaFetcher = Callable[[str], Optional[str]]


@dataclass(frozen=True)
class ModuleRepository:
    """The repository hosting a Go module.

    Attributes:
        url: https URL of the repository itself, never of the module within it.
        subdirectory: Path of the module inside the repository, empty when the
            module is the repository root.
    """

    url: str
    subdirectory: str = ""


@dataclass(frozen=True)
class ModuleResolution:
    """What resolving a module path found, and whether it could look at all.

    ``repository`` None with ``lookup_failed`` False is an answer: the module
    path names no repository this tool can read. ``lookup_failed`` True is the
    absence of an answer — the vanity host did not respond — and a caller must
    not record it as a finding about the module (#182).

    Attributes:
        repository: The repository hosting the module, when one was found.
        lookup_failed: Whether a ``?go-get=1`` lookup was attempted and could
            not be completed.
    """

    repository: Optional[ModuleRepository] = None
    lookup_failed: bool = False


class _GoImportParser(HTMLParser):
    """Collects the ``content`` of ``go-import`` meta tags and nothing else.

    Everything in the fetched document is untrusted, so this reads one attribute
    of one tag name and ignores the rest of the markup entirely.
    """

    def __init__(self) -> None:
        """Initialize the parser with an empty result list."""
        super().__init__(convert_charrefs=True)
        self.contents: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        """Record the content attribute of a ``go-import`` meta tag."""
        if tag.lower() != "meta":
            return
        attributes = {key.lower(): value for key, value in attrs}
        if (attributes.get("name") or "").strip().lower() != "go-import":
            return
        content = attributes.get("content")
        if content:
            self.contents.append(content)


class GoModuleResolver:
    """Resolves Go module paths to repositories, caching by import prefix.

    One vanity lookup serves every module under the same import prefix, so a
    project depending on twenty ``cloud.google.com/go/*`` modules makes one
    request, not twenty.
    """

    def __init__(
        self,
        timeout: int = 10,
        fetch: Optional[MetaFetcher] = None,
    ) -> None:
        """Initialize the resolver.

        Args:
            timeout: Hard timeout, in seconds, for a ``?go-get=1`` request.
            fetch: Optional replacement for the bounded HTTP fetch. Pass
                ``lambda url: None`` to disable vanity resolution entirely.
        """
        self.timeout = timeout
        self._fetcher = SafeFetcher(
            timeout=float(timeout),
            max_bytes=GO_IMPORT_MAX_BYTES,
            max_redirects=GO_IMPORT_MAX_REDIRECTS,
            user_agent=GO_IMPORT_USER_AGENT,
        )
        self._fetch: MetaFetcher = fetch if fetch is not None else self._fetch_go_import
        # Keyed by import prefix; the value is the resolution for that prefix
        # itself, including whether its lookup could be performed at all.
        self._cache: Dict[str, ModuleResolution] = {}

    def resolve(self, module_path: str) -> Optional[ModuleRepository]:
        """Return the repository hosting a module path, or ``None``.

        Args:
            module_path: Go module path, e.g. ``golang.org/x/net``.

        Returns:
            The resolved :class:`ModuleRepository`, or ``None`` when the module
            path does not resolve to a repository we can inspect.
        """
        return self.resolve_module(module_path).repository

    def resolve_module(self, module_path: str) -> ModuleResolution:
        """Resolve a module path, distinguishing "no repository" from "no answer".

        Args:
            module_path: Go module path, e.g. ``golang.org/x/net``.

        Returns:
            The resolution, whose ``lookup_failed`` flag separates a vanity host
            that did not respond from one that answered with nothing usable.
        """
        path = module_path.strip().strip("/")
        if not path:
            return ModuleResolution()
        direct = _repository_from_path(path)
        if direct is not None:
            return ModuleResolution(direct)
        if path.split("/", 1)[0].lower() in _CODE_HOSTS:
            # A code host is never a vanity path. If the rule above could not
            # find a repository in it, there is not one to find.
            return ModuleResolution()
        return self._resolve_vanity(path)

    def _resolve_vanity(self, path: str) -> ModuleResolution:
        """Resolve a vanity import path through its ``go-import`` meta tag."""
        prefix, resolution = self._cached_prefix(path)
        if prefix is None or resolution is None:
            prefix, resolution = self._lookup_go_import(path)
            self._cache[prefix] = resolution
        repository = resolution.repository
        if repository is None:
            return resolution
        relative = path[len(prefix) :].strip("/")
        subdirectory = "/".join(
            part for part in (repository.subdirectory, relative) if part
        )
        return ModuleResolution(ModuleRepository(repository.url, subdirectory))

    def _cached_prefix(
        self, path: str
    ) -> Tuple[Optional[str], Optional[ModuleResolution]]:
        """Return the longest cached import prefix covering ``path``."""
        best: Optional[str] = None
        for prefix in self._cache:
            if path == prefix or path.startswith(prefix + "/"):
                if best is None or len(prefix) > len(best):
                    best = prefix
        if best is None:
            return None, None
        return best, self._cache[best]

    def _lookup_go_import(self, path: str) -> Tuple[str, ModuleResolution]:
        """Fetch and parse the ``go-import`` meta tag for a module path.

        Returns:
            The import prefix to cache the result under (the module path itself
            when resolution failed) and the resolution.
        """
        host = path.split("/", 1)[0]
        if not _is_public_host(host) or ".." in path.split("/"):
            logger.debug("Refusing go-import lookup for module path: %s", path)
            return path, ModuleResolution()
        # The host is already constrained to hostname characters; percent-encode
        # the rest so a module path cannot smuggle a query, fragment or
        # authority into the URL we are about to request.
        body = self._fetch(f"https://{quote(path, safe='/')}?go-get=1")
        if not body:
            # The host did not answer. That is the absence of a measurement, not
            # a statement that the module names no source (#182).
            return path, ModuleResolution(lookup_failed=True)
        match = _select_go_import(body, path)
        if match is None:
            logger.debug("No usable go-import meta tag for %s", path)
            return path, ModuleResolution()
        prefix, repo_root = match
        repository = _repository_from_path(repo_root)
        if repository is None:
            # A real repository on a host we cannot collect signals from. Record
            # it anyway so the report names the right source, and let the
            # signals stay unmeasured.
            repository = ModuleRepository(f"https://{repo_root}")
        return prefix, ModuleResolution(repository)

    def _fetch_go_import(self, url: str) -> Optional[str]:
        """Fetch a ``?go-get=1`` document under strict bounds, or return None.

        The response is attacker-influenceable, so ``SafeFetcher`` size-caps it
        while reading, bounds the redirect budget, and re-validates and re-pins
        the destination address on every hop. Nothing beyond the meta tags the
        caller extracts is trusted.
        """
        return self._fetcher.fetch_text(url)


def _repository_from_path(path: str) -> Optional[ModuleRepository]:
    """Split a host-qualified path into repository and subdirectory.

    This is the whole normalizer: static mirror rewrite, major-version suffix
    strip, then "host plus two segments is the repository, the rest is a
    subdirectory". It is applied both to module paths and to the repository
    roots that vanity lookups return, so both arrive at the same shape.

    Args:
        path: Host-qualified path such as ``github.com/cespare/xxhash/v2``.

    Returns:
        The repository and the module's subdirectory within it, or ``None``
        when the path names a host we cannot map to a repository.
    """
    for module_prefix, repo_prefix in _STATIC_MIRRORS:
        if path.startswith(module_prefix):
            path = repo_prefix + path[len(module_prefix) :]
            break

    segments = [segment for segment in path.split("/") if segment]
    # Strip the major-version suffix only when a repository still remains
    # underneath it, so a repository legitimately named "v2" survives.
    if len(segments) >= 4 and _MAJOR_VERSION_SUFFIX.match(segments[-1]):
        segments.pop()
    if len(segments) < 3:
        return None
    host = segments[0].lower()
    if host not in _CODE_HOSTS:
        return None
    owner, repo = segments[1], segments[2].removesuffix(".git")
    if not owner or not repo:
        return None
    return ModuleRepository(
        url=f"https://{host}/{owner}/{repo}",
        subdirectory="/".join(segments[3:]),
    )


def _select_go_import(body: str, module_path: str) -> Optional[Tuple[str, str]]:
    """Return the (import prefix, repository root path) for a module path.

    Reads only ``go-import`` meta tags, keeps only entries whose declared import
    prefix actually covers the module path we asked about, and prefers the most
    specific one. The repository root is re-validated before it is returned.
    """
    parser = _GoImportParser()
    try:
        parser.feed(body)
        parser.close()
    except (AssertionError, ValueError) as exc:
        logger.debug("Malformed go-import document for %s: %s", module_path, exc)
        return None

    best: Optional[Tuple[str, str]] = None
    for content in parser.contents:
        fields = content.split()
        if len(fields) != 3:
            continue
        prefix, vcs, repo_root = fields
        if vcs != "git":
            continue
        prefix = prefix.strip("/")
        if module_path != prefix and not module_path.startswith(prefix + "/"):
            continue
        validated = _validated_repo_root(repo_root)
        if validated is None:
            continue
        if best is None or len(prefix) > len(best[0]):
            best = (prefix, validated)
    return best


def _validated_repo_root(value: str) -> Optional[str]:
    """Return an untrusted repository root as a bare ``host/path``, or None.

    Enforces https, rejects credentials, explicit ports and non-public hosts,
    and drops the query and fragment, so nothing an attacker adds to the URL
    survives into a later request.
    """
    parsed = urlparse(value.strip())
    if parsed.scheme != "https":
        return None
    if "@" in parsed.netloc:
        return None
    try:
        if parsed.port is not None:
            return None
    except ValueError:
        return None
    host = parsed.hostname
    if not _is_public_host(host):
        return None
    path = parsed.path.strip("/")
    if not path:
        return None
    return f"{host}/{path}"
