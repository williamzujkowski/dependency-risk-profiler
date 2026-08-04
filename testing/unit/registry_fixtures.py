"""Loader for the provenance-dated, live-captured registry fixtures (#73, #145).

Every payload under ``testing/fixtures/registry/`` was fetched from the live
registry by ``scripts/capture_registry_fixtures.py`` and carries the URL it came
from and the date it was taken. Nothing here touches the network: this module
reads files, and the replay fetchers it builds raise on any URL they have no
recording for, so a test that reaches for the internet fails loudly instead of
passing on a live answer.

Why captured and not authored
-----------------------------
``test_nodejs_adapter`` used to describe its fixtures as "trimmed to the keys
the adapter reads". That sentence is the bug. A fixture trimmed to what the
adapter reads cannot, by construction, contain the key the adapter *should*
read and doesn't — and that is the literal mechanism behind four of the five
dead reads catalogued in #145. The captured payloads keep every key the
registry sends, including the ones no adapter parses yet, because those are the
ones that reveal the next dead read.

Trimming may remove **volume** and never **key diversity**. The capture script
samples version-keyed collections (285 of express's 288 release manifests are
dropped) and caps long string values; it never deletes a schema key. Retained
release manifests keep all of their own keys. One honest limit follows from
that: a fixture cannot exercise a fallback path that depends on the dropped
volume — npm's "newest per-version timestamp" fallback, for instance, sees only
the sampled releases. Those paths keep their synthetic tests in
``test_nodejs_adapter``, which is what synthetic fixtures are legitimately for.

Untrusted data
--------------
A captured payload is untrusted input (#160's security conditions), so this
loader treats it as such: fixture and ecosystem ids are validated against a
strict pattern and the resolved path is checked for containment before any file
is opened, each file is refused above the manifest's size bound, and every
document is scanned for credential-shaped values on load. Nothing in a payload
is ever used to build a filesystem path or a URL — the replay map is keyed by
the ``source_url`` recorded in the manifest, and the harness compares against
it rather than dereferencing it.

Staleness
---------
A frozen fixture recreates #145 in slow motion: it pins today's registry
assumptions and defends them forever. ``assert_fixtures_are_fresh`` warns once a
fixture passes ``warn_after_days`` and fails past ``fail_after_days``, both from
the manifest, so the refresh has a trigger rather than depending on somebody
remembering.

Ownership and refresh cadence
-----------------------------
Owner: whoever is on the adapter rotation for the release; the repository
maintainer by default. Refresh every release cycle, and always after an
ecosystem's adapter changes what it reads:

    python scripts/capture_registry_fixtures.py --check     # ages, no network
    python scripts/capture_registry_fixtures.py             # re-capture all

Review the diff before committing. A changed key shape in the diff is the
signal this whole harness exists to surface; do not squash it.
"""

import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple
from warnings import warn

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "registry"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"

# Mirrors scripts/capture_registry_fixtures.SAFE_ID. Ids become path segments,
# so they are validated here too rather than trusted because the capture script
# validated them once.
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# Credential shapes that must never reach the repository through a fixture.
_SECRET_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"://[^/\s:@]+:[^/\s@]+@"),
)


class FixtureError(AssertionError):
    """Raised when a fixture is missing, malformed, oversized, or unsafe."""


@dataclass(frozen=True)
class RegistryFixture:
    """One captured registry document and the provenance recorded with it."""

    ecosystem: str
    name: str
    source_url: str
    captured_at: date
    reducer: str
    trimming: Tuple[str, ...]
    payload: object
    fmt: str = "json"

    @property
    def slug(self) -> str:
        """Return the ``ecosystem/name`` id used in assertion messages."""
        return f"{self.ecosystem}/{self.name}"

    @property
    def body(self) -> bytes:
        """Return the recorded document as the bytes the registry sent.

        Four ecosystems answer with something other than JSON — Maven Central
        with XML, nuget.org with a nuspec, the Go module proxy with a plain-text
        ``go.mod`` — and their adapters parse bytes rather than a decoded
        object. Serving those adapters the recorded bytes keeps the parse under
        test instead of stubbing it out.

        Returns:
            The payload encoded as UTF-8: verbatim for a text capture, and
            compactly re-serialized for a JSON one.
        """
        if isinstance(self.payload, str):
            return self.payload.encode("utf-8")
        return json.dumps(self.payload).encode("utf-8")

    def age_days(self, today: Optional[date] = None) -> int:
        """Return how many days old the capture is.

        Args:
            today: Reference date; defaults to the current date.

        Returns:
            Age of the capture in days.
        """
        return ((today or date.today()) - self.captured_at).days


def load_manifest() -> Dict[str, object]:
    """Return the shared fixture manifest.

    Both this loader and the capture script read it, so what CI replays and
    what a refresh fetches cannot drift apart.

    Returns:
        The parsed ``manifest.json``.
    """
    with MANIFEST_PATH.open(encoding="utf-8") as handle:
        manifest: Dict[str, object] = json.load(handle)
    return manifest


MANIFEST = load_manifest()


def declared_fixtures() -> List[Tuple[str, str]]:
    """Return every ``(ecosystem, name)`` pair the manifest declares.

    Returns:
        Sorted list of fixture ids.
    """
    return sorted(
        (ecosystem, name)
        for ecosystem, entry in MANIFEST["ecosystems"].items()
        for name in entry["fixtures"]
    )


def _fixture_path(ecosystem: str, name: str) -> Path:
    """Resolve a fixture path, refusing ids that could escape the fixture root.

    Args:
        ecosystem: Ecosystem key.
        name: Fixture id.

    Returns:
        The resolved path.

    Raises:
        FixtureError: If an id fails validation or the path leaves the root.
    """
    for segment in (ecosystem, name):
        if not _SAFE_ID.match(segment):
            raise FixtureError(f"unsafe fixture id: {segment!r}")
    root = FIXTURE_ROOT.resolve()
    path = (root / ecosystem / f"{name}.json").resolve()
    if root not in path.parents:
        raise FixtureError(f"fixture path escapes the fixture root: {path}")
    return path


def _assert_no_credentials(slug: str, raw: str) -> None:
    """Fail if a captured document carries anything credential-shaped.

    Args:
        slug: Fixture id, for the message.
        raw: The fixture's raw text.

    Raises:
        FixtureError: If a credential pattern matches.
    """
    for pattern in _SECRET_PATTERNS:
        if pattern.search(raw):
            raise FixtureError(
                f"{slug} contains a credential-shaped value matching "
                f"{pattern.pattern!r}; re-capture it and check the redaction "
                f"list in scripts/capture_registry_fixtures.py"
            )


def load_fixture(ecosystem: str, name: str) -> RegistryFixture:
    """Load one captured registry document.

    Args:
        ecosystem: Ecosystem key declared in the manifest.
        name: Fixture id declared in the manifest.

    Returns:
        The fixture with its provenance.

    Raises:
        FixtureError: If the fixture is undeclared, missing, oversized,
            malformed, or carries a credential-shaped value.
    """
    entry = MANIFEST["ecosystems"].get(ecosystem, {}).get("fixtures", {}).get(name)
    if entry is None:
        raise FixtureError(f"{ecosystem}/{name} is not declared in the manifest")

    path = _fixture_path(ecosystem, name)
    slug = f"{ecosystem}/{name}"
    if not path.exists():
        raise FixtureError(
            f"{slug} is declared but not captured; run "
            f"`python scripts/capture_registry_fixtures.py --ecosystem {ecosystem}`"
        )

    size = path.stat().st_size
    bound = MANIFEST["max_fixture_bytes"]
    if size > bound:
        raise FixtureError(f"{slug} is {size} bytes, over the {bound}-byte bound")

    raw = path.read_text(encoding="utf-8")
    _assert_no_credentials(slug, raw)
    document = json.loads(raw)

    try:
        provenance = document["provenance"]
        captured_at = date.fromisoformat(provenance["captured_at"])
        source_url = provenance["source_url"]
        payload = document["payload"]
    except (KeyError, TypeError, ValueError) as exc:
        raise FixtureError(f"{slug} has no usable provenance block: {exc}") from exc

    if source_url != entry["url"]:
        raise FixtureError(
            f"{slug} was captured from {source_url} but the manifest now "
            f"declares {entry['url']}; re-capture it"
        )

    return RegistryFixture(
        ecosystem=ecosystem,
        name=name,
        source_url=source_url,
        captured_at=captured_at,
        reducer=provenance.get("reducer", "none"),
        trimming=tuple(provenance.get("trimming", ())),
        payload=payload,
        fmt=provenance.get("format", "json"),
    )


def load_ecosystem(ecosystem: str) -> Dict[str, RegistryFixture]:
    """Load every fixture declared for one ecosystem.

    Args:
        ecosystem: Ecosystem key declared in the manifest.

    Returns:
        Mapping of fixture id to fixture.
    """
    entry = MANIFEST["ecosystems"].get(ecosystem)
    if entry is None:
        raise FixtureError(f"{ecosystem} is not declared in the manifest")
    return {name: load_fixture(ecosystem, name) for name in entry["fixtures"]}


def assert_fixtures_are_fresh(today: Optional[date] = None) -> List[str]:
    """Warn on ageing fixtures and fail on stale ones.

    A fixture that is never refreshed freezes the registry's shape as it was on
    the day it was taken, which is #145 with extra steps. The manifest carries
    both thresholds so the trigger is a test failure rather than somebody's
    memory.

    Args:
        today: Reference date; defaults to the current date.

    Returns:
        The list of warning messages emitted, for tests that want to inspect
        them.

    Raises:
        FixtureError: If any fixture is older than ``fail_after_days``.
    """
    warn_after = MANIFEST["warn_after_days"]
    fail_after = MANIFEST["fail_after_days"]
    warnings: List[str] = []
    stale: List[str] = []

    for ecosystem, name in declared_fixtures():
        fixture = load_fixture(ecosystem, name)
        age = fixture.age_days(today)
        if age > fail_after:
            stale.append(f"{fixture.slug} ({age} days)")
        elif age > warn_after:
            message = (
                f"{fixture.slug} was captured {age} days ago, past the "
                f"{warn_after}-day refresh cadence; run "
                f"scripts/capture_registry_fixtures.py"
            )
            warnings.append(message)
            warn(message, stacklevel=2)

    if stale:
        raise FixtureError(
            "registry fixtures are older than the "
            f"{fail_after}-day limit and no longer describe the live "
            f"registries: {', '.join(stale)}. Re-capture with "
            "scripts/capture_registry_fixtures.py and review the diff — a "
            "changed key shape in that diff is the finding, not the noise."
        )
    return warnings


def replay_fetcher(
    fixtures: Mapping[str, RegistryFixture],
    missing: Optional[Mapping[str, None]] = None,
) -> Callable[..., object]:
    """Build a stub that answers only from recorded payloads.

    The map is keyed by the URL each fixture was *captured from*, so a replay
    also checks that the adapter still requests the URL the capture was taken
    from. Any other URL raises: no test in this suite may reach the network,
    and a silent live answer is exactly how a fixture stops describing reality.

    Args:
        fixtures: Fixtures to serve, keyed however the caller likes.
        missing: URLs that must answer as a failed lookup (``None``).

    Returns:
        A callable with the ``(url, timeout=...)`` shape the adapters' fetchers
        use.
    """
    responses: Dict[str, object] = {
        fixture.source_url: fixture.payload for fixture in fixtures.values()
    }
    for url in missing or {}:
        responses[url] = None

    def fetch(url: str, timeout: int = 30) -> object:
        if url not in responses:
            raise AssertionError(_no_recording(url))
        return responses[url]

    return fetch


def _no_recording(url: str) -> str:
    """Return the message a replay seam raises for an unrecorded URL.

    Args:
        url: The URL the adapter asked for.

    Returns:
        The failure message.
    """
    return (
        f"the adapter requested {url}, which no fixture records. Either the "
        f"adapter changed which endpoint it reads, or the manifest needs a new "
        f"entry — do not let this fall through to the network."
    )


class RecordedResponse:
    """The slice of ``requests.Response`` the byte-oriented adapters touch.

    Maven Central, nuget.org and Packagist are read through ``requests.get``
    rather than through a JSON helper, and each reads the body differently: the
    Maven and NuGet clients stream it with :meth:`iter_content` under a byte
    cap, and the Composer adapter calls :meth:`json`. All three check
    ``status_code`` first, and two of them use the response as a context
    manager. Recreating those four surfaces is what lets the real parse run
    against a captured payload instead of being stubbed past.
    """

    def __init__(self, url: str, body: bytes, status_code: int = 200) -> None:
        """Initialize the recorded response.

        Args:
            url: The URL this body was captured from.
            body: The recorded bytes.
            status_code: The status to report; 404 for a recorded absence.
        """
        self.url = url
        self.status_code = status_code
        self.content = body
        self.headers: Dict[str, str] = {}

    def iter_content(self, chunk_size: int = 65536) -> Iterator[bytes]:
        """Yield the recorded body in chunks, as a streamed response would."""
        for start in range(0, len(self.content), max(chunk_size, 1)):
            yield self.content[start : start + chunk_size]

    def json(self) -> object:
        """Decode the recorded body as JSON."""
        return json.loads(self.content.decode("utf-8"))

    @property
    def text(self) -> str:
        """Return the recorded body decoded as UTF-8."""
        return self.content.decode("utf-8")

    def __enter__(self) -> "RecordedResponse":
        """Return self, so ``with requests.get(...) as response`` works."""
        return self

    def __exit__(self, *exc_info: object) -> bool:
        """Do nothing; there is no socket to release."""
        return False


def replay_requests_get(
    fixtures: Mapping[str, RegistryFixture],
    absent: Sequence[str] = (),
) -> Callable[..., RecordedResponse]:
    """Build a ``requests.get`` stub that answers only from recorded bytes.

    The same rule as :func:`replay_fetcher`, one layer lower: keyed by the URL
    each fixture was captured from, and raising on anything else so a test can
    never fall through to a live registry.

    Args:
        fixtures: Fixtures to serve, keyed however the caller likes.
        absent: URLs that must answer 404 — a recorded absence is a fact about
            the registry too, and the adapters have real branches for it.

    Returns:
        A callable with the ``requests.get`` signature the clients use.
    """
    bodies = {fixture.source_url: fixture.body for fixture in fixtures.values()}
    missing = set(absent)

    def get(url: str, **_kwargs: object) -> RecordedResponse:
        if url in missing:
            return RecordedResponse(url, b"", status_code=404)
        if url not in bodies:
            raise AssertionError(_no_recording(url))
        return RecordedResponse(url, bodies[url])

    return get
