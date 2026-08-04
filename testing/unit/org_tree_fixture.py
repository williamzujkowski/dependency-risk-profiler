"""A real ``GitHubOrgClient`` wired to canned git trees, for offline tests.

Org-scan tests used to hand the runner a fixture client that classified its own
trees — it reimplemented the supported/unreadable split with the same
predicates the production client used. That is a fixture reimplementing the
code under test, and it hides exactly the defect #265 was: the fixture matched
manifest names the way the scanner's hand-written tuple did, so a `.csproj` was
invisible in the tests for the same reason it was invisible in production, and
every test agreed with the bug.

Here the client is the production :class:`GitHubOrgClient`. Only the HTTP
session is canned, so ``list_manifest_paths`` runs the real classifier over a
real tree document. Delete the classifier and these tests stop passing.
"""

from __future__ import annotations

from typing import Dict, Iterable, Iterator, List, Mapping, Optional

from dependency_risk_profiler.org_scan.github import GitHubOrgClient


class CannedTreeResponse:
    """A canned git-tree response satisfying ``github.HttpResponse``."""

    def __init__(self, payload: Dict[str, object]) -> None:
        """Store the tree document this response serves."""
        self.status_code = 200
        self.headers: Dict[str, str] = {}
        self.encoding: Optional[str] = "utf-8"
        self._payload = payload
        self.closed = False

    def iter_content(self, chunk_size: int) -> Iterator[bytes]:
        """Part of the protocol; these fixtures only drive the JSON path."""
        raise NotImplementedError("this fake serves a git tree, not a body")

    def json(self) -> object:
        """Return the canned git tree."""
        return self._payload

    def raise_for_status(self) -> None:
        """Never fail: the canned response is always a 200."""

    def close(self) -> None:
        """Record that the response was closed."""
        self.closed = True


class CannedTreeSession:
    """Session serving one canned git tree per repository.

    Keyed on the ``owner/name`` embedded in the request URL, so one session
    backs a whole fixture account and a request for a repository it was never
    given raises rather than quietly serving somebody else's tree.
    """

    def __init__(self, trees: Mapping[str, Iterable[str]]) -> None:
        """Build one tree document per repository from its blob paths."""
        self._responses = {
            full_name: CannedTreeResponse(
                {"truncated": False, "tree": _tree_entries(paths)}
            )
            for full_name, paths in trees.items()
        }
        self.requested_urls: List[str] = []

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str],
        timeout: int,
        stream: bool,
    ) -> CannedTreeResponse:
        """Serve the canned tree for the repository named in the URL."""
        self.requested_urls.append(url)
        return self._responses[_repository_from_tree_url(url)]


def _tree_entries(paths: Iterable[str]) -> List[Dict[str, str]]:
    """Render blob paths as a git-tree listing, directories included.

    GitHub returns a ``tree`` entry for every directory alongside the blobs,
    and the classifier has to skip them; a fixture that omitted them would
    never exercise that.
    """
    directories: List[str] = []
    entries: List[Dict[str, str]] = []
    for path in paths:
        components = path.split("/")[:-1]
        for depth in range(1, len(components) + 1):
            directory = "/".join(components[:depth])
            if directory not in directories:
                directories.append(directory)
                entries.append({"type": "tree", "path": directory})
        entries.append({"type": "blob", "path": path})
    return entries


def _repository_from_tree_url(url: str) -> str:
    """Extract ``owner/name`` from a git-tree request URL."""
    _, _, tail = url.partition("/repos/")
    owner, _, rest = tail.partition("/")
    name, _, _ = rest.partition("/")
    return f"{owner}/{name}"


def tree_client(trees: Mapping[str, Iterable[str]]) -> GitHubOrgClient:
    """Return a production client whose git trees come from ``trees``.

    Args:
        trees: Repository full name to the repository-relative blob paths its
            git tree contains.

    Returns:
        A :class:`GitHubOrgClient` that reaches no network.
    """
    return GitHubOrgClient(token="fixture-token", session=CannedTreeSession(trees))
