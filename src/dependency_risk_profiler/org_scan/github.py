"""GitHub REST API client for organization dependency discovery."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Mapping, Optional
from urllib.parse import parse_qs, urlparse

import requests

from .models import RepositoryRef

logger = logging.getLogger(__name__)


class GitHubRateLimitError(RuntimeError):
    """Raised when GitHub rate limiting prevents scan progress."""


@dataclass(frozen=True)
class GitHubRepository:
    """GitHub repository returned by the organization listing endpoint."""

    full_name: str
    name: str
    default_branch: str
    html_url: str
    archived: bool
    fork: bool

    def to_ref(self) -> RepositoryRef:
        """Convert the GitHub repository into a scanner repository ref."""
        return RepositoryRef(
            full_name=self.full_name,
            name=self.name,
            default_branch=self.default_branch,
            html_url=self.html_url,
            archived=self.archived,
            fork=self.fork,
        )


@dataclass(frozen=True)
class RepoSignals:
    """Authenticated GitHub repository signals fetched without cloning."""

    star_count: Optional[int] = None
    contributor_count: Optional[int] = None
    archived: Optional[bool] = None
    # `pushed_at` is the server-asserted last push (more trustworthy than a
    # shallow clone's author-controlled commit date). None = unknown.
    pushed_at: Optional[datetime] = None
    # Derived from the repo's root tree; None when the branch is unknown or the
    # tree request fails, so an unknown is reported honestly rather than guessed.
    has_tests: Optional[bool] = None
    has_ci: Optional[bool] = None


class GitHubOrgClient:
    """Small GitHub REST client with pagination and rate-limit backoff."""

    api_base_url = "https://api.github.com"

    def __init__(
        self,
        token: str,
        timeout: int = 30,
        max_retries: int = 3,
        session: Optional[requests.Session] = None,
    ) -> None:
        """Initialize the GitHub client."""
        self.token = token
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = session or requests.Session()

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """List organization repos, skipping forks and archived repos by default."""
        return self._list_repositories(
            f"/orgs/{org}/repos",
            {"per_page": "100", "type": "all"},
            include_archived=include_archived,
            max_repos=max_repos,
        )

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
        include_collaborations: bool = False,
    ) -> List[RepositoryRef]:
        """List a user's repos, skipping forks and archived repos by default.

        Defaults to repositories the user *owns* (``type=owner``). GitHub's
        ``type=all`` also returns repos the user only collaborates on in other
        orgs, which mis-attributes other people's dependencies to the user; set
        ``include_collaborations`` to opt back into that broader set.
        """
        repo_type = "all" if include_collaborations else "owner"
        return self._list_repositories(
            f"/users/{user}/repos",
            {"per_page": "100", "type": repo_type},
            include_archived=include_archived,
            max_repos=max_repos,
        )

    def _list_repositories(
        self,
        path: str,
        base_params: Mapping[str, str],
        include_archived: bool,
        max_repos: Optional[int],
    ) -> List[RepositoryRef]:
        """List repositories from a paginated GitHub repository endpoint."""
        repos: List[RepositoryRef] = []
        page = 1
        while True:
            params = dict(base_params)
            params["page"] = str(page)
            payload = self._get_json(
                path,
                params,
            )
            if not isinstance(payload, list):
                raise RuntimeError("GitHub repository listing returned invalid JSON")
            if not payload:
                break

            for item in payload:
                if not isinstance(item, Mapping):
                    continue
                repo = self._repository_from_mapping(item)
                if repo is None:
                    continue
                if repo.fork:
                    continue
                if repo.archived and not include_archived:
                    continue
                repos.append(repo.to_ref())
                if max_repos is not None and len(repos) >= max_repos:
                    return repos

            page += 1

        return repos

    def list_manifest_paths(
        self,
        repo: RepositoryRef,
        supported_names: Iterable[str],
    ) -> List[str]:
        """List supported manifest paths from a repository git tree."""
        tree = self._get_json(
            f"/repos/{repo.full_name}/git/trees/{repo.default_branch}",
            {"recursive": "1"},
        )
        if not isinstance(tree, Mapping):
            raise RuntimeError(f"Git tree for {repo.full_name} returned invalid JSON")

        truncated = tree.get("truncated")
        if truncated is True:
            logger.warning(
                "Git tree for %s is truncated; scanning returned manifests only",
                repo.full_name,
            )

        raw_items = tree.get("tree")
        if not isinstance(raw_items, list):
            return []

        supported = {name.lower() for name in supported_names}
        paths: List[str] = []
        for item in raw_items:
            if not isinstance(item, Mapping):
                continue
            item_type = item.get("type")
            path = item.get("path")
            if item_type == "blob" and isinstance(path, str):
                leaf = path.rsplit("/", 1)[-1].lower()
                if leaf in supported:
                    paths.append(path)

        return sorted(paths)

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Fetch a manifest file as raw text."""
        response = self._request(
            f"/repos/{repo.full_name}/contents/{path}",
            {},
            accept="application/vnd.github.raw",
        )
        return str(response.text)

    def get_repository_signals(self, owner_repo: str) -> RepoSignals:
        """Fetch cheap authenticated popularity signals for a GitHub repository."""
        normalized = owner_repo.strip().strip("/")
        if normalized.count("/") != 1:
            return RepoSignals()

        try:
            repository_payload = self._get_json(f"/repos/{normalized}", {})
            star_count: Optional[int] = None
            archived: Optional[bool] = None
            pushed_at: Optional[datetime] = None
            default_branch: Optional[str] = None
            if isinstance(repository_payload, Mapping):
                star_count = self._optional_int(
                    repository_payload.get("stargazers_count")
                )
                archived_value = repository_payload.get("archived")
                if isinstance(archived_value, bool):
                    archived = archived_value
                pushed_at = self._parse_github_datetime(
                    repository_payload.get("pushed_at")
                )
                branch_value = repository_payload.get("default_branch")
                if isinstance(branch_value, str) and branch_value:
                    default_branch = branch_value

            contributors_response = self._request(
                f"/repos/{normalized}/contributors",
                {"per_page": "1", "anon": "true"},
                accept="application/vnd.github+json",
            )
            contributor_payload = contributors_response.json()
            contributor_count = self._contributor_count(
                contributor_payload,
                contributors_response.headers.get("Link"),
            )

            has_tests, has_ci = self._repo_health_from_tree(normalized, default_branch)
            return RepoSignals(
                star_count=star_count,
                contributor_count=contributor_count,
                archived=archived,
                pushed_at=pushed_at,
                has_tests=has_tests,
                has_ci=has_ci,
            )
        except (
            GitHubRateLimitError,
            requests.RequestException,
            RuntimeError,
            ValueError,
        ) as exc:
            logger.warning(
                "GitHub repository signal enrichment failed for %s: %s",
                normalized,
                exc,
            )
            return RepoSignals()

    def _get_json(self, path: str, params: Mapping[str, str]) -> object:
        """GET a GitHub endpoint and parse JSON."""
        response = self._request(path, params, accept="application/vnd.github+json")
        parsed: object = response.json()
        return parsed

    def _request(
        self, path: str, params: Mapping[str, str], accept: str
    ) -> requests.Response:
        """GET a GitHub endpoint with bounded retry/backoff."""
        url = f"{self.api_base_url}{path}"
        headers = {
            "Accept": accept,
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dependency-risk-profiler org-scan",
        }

        for attempt in range(self.max_retries + 1):
            response = self.session.get(
                url,
                headers=headers,
                params=dict(params),
                timeout=self.timeout,
            )
            if response.status_code in {403, 429} and self._should_backoff(response):
                if attempt >= self.max_retries:
                    raise GitHubRateLimitError(
                        "GitHub rate limit prevented progress; retry after reset or "
                        "use a token with more remaining quota."
                    )
                delay = self._backoff_seconds(response, attempt)
                logger.warning("GitHub rate limit/backoff: sleeping %.1fs", delay)
                time.sleep(delay)
                continue

            response.raise_for_status()
            return response

        raise GitHubRateLimitError("GitHub request retry loop exhausted")

    def _should_backoff(self, response: requests.Response) -> bool:
        """Return whether a response should trigger rate-limit backoff."""
        remaining = response.headers.get("X-RateLimit-Remaining")
        retry_after = response.headers.get("Retry-After")
        return retry_after is not None or remaining == "0"

    def _backoff_seconds(self, response: requests.Response, attempt: int) -> float:
        """Compute backoff delay from GitHub headers."""
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                return max(float(retry_after), 1.0)
            except ValueError:
                return 2.0

        reset = response.headers.get("X-RateLimit-Reset")
        if reset is not None:
            try:
                reset_at = int(reset)
                return max(float(reset_at - int(time.time())), 1.0)
            except ValueError:
                pass

        return float(2**attempt)

    def _contributor_count(
        self, payload: object, link_header: Optional[str]
    ) -> Optional[int]:
        """Return contributor count from GitHub pagination."""
        if link_header is not None:
            last_page = self._last_page_from_link_header(link_header)
            if last_page is not None:
                return last_page

        if isinstance(payload, list):
            return len(payload)
        return None

    def _last_page_from_link_header(self, link_header: str) -> Optional[int]:
        """Extract the rel=last page number from a GitHub Link header."""
        for link_part in link_header.split(","):
            sections = [section.strip() for section in link_part.split(";")]
            if len(sections) < 2:
                continue
            url_section = sections[0]
            rel_sections = sections[1:]
            if not (url_section.startswith("<") and url_section.endswith(">")):
                continue
            if 'rel="last"' not in rel_sections:
                continue
            parsed_url = urlparse(url_section[1:-1])
            page_values = parse_qs(parsed_url.query).get("page")
            if page_values is None:
                continue
            page = self._optional_int(page_values[-1])
            if page is not None:
                return page
        return None

    def _optional_int(self, value: object) -> Optional[int]:
        """Return an integer only when GitHub returned a real integer value."""
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return None
        return None

    def _parse_github_datetime(self, value: object) -> Optional[datetime]:
        """Parse a GitHub ISO-8601 timestamp (e.g. pushed_at) as tz-aware UTC."""
        if not isinstance(value, str) or not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    # Top-level entry names that indicate CI config or a test layout. Matched
    # against the repo's ROOT tree only (non-recursive), which stays tiny and
    # fast even for huge monorepos — a recursive tree of e.g. TypeScript took
    # ~1.7s/repo and dominated large scans (#46). A ".github" dir at root
    # implies workflows without descending into it.
    _CI_TOP_LEVEL_MARKERS = (
        ".github",
        ".circleci",
        ".gitlab-ci.yml",
        ".travis.yml",
        "azure-pipelines.yml",
        "jenkinsfile",
        ".drone.yml",
        "appveyor.yml",
    )
    _TEST_DIR_MARKERS = ("test", "tests", "spec", "__tests__")
    _TEST_FILE_SUFFIXES = ("_test.go", ".test.js", ".test.ts", ".spec.js")

    def _repo_health_from_tree(
        self, owner_repo: str, default_branch: Optional[str]
    ) -> tuple[Optional[bool], Optional[bool]]:
        """Detect (has_tests, has_ci) from the repo's root tree without cloning.

        Uses a NON-recursive tree (top-level entries only) so the request is
        cheap regardless of repository size. Returns ``(None, None)`` when the
        branch is unknown or the request fails — an honest unknown, not a guess.
        """
        if not default_branch:
            return None, None
        try:
            payload = self._get_json(
                f"/repos/{owner_repo}/git/trees/{default_branch}", {}
            )
        except (
            GitHubRateLimitError,
            requests.RequestException,
            RuntimeError,
            ValueError,
        ) as exc:
            logger.debug("Tree fetch failed for %s: %s", owner_repo, exc)
            return None, None
        if not isinstance(payload, Mapping):
            return None, None
        entries = payload.get("tree")
        if not isinstance(entries, list):
            return None, None

        top_level = {
            entry["path"].lower()
            for entry in entries
            if isinstance(entry, Mapping) and isinstance(entry.get("path"), str)
        }
        has_ci = any(marker in top_level for marker in self._CI_TOP_LEVEL_MARKERS)
        has_tests = any(name in top_level for name in self._TEST_DIR_MARKERS) or any(
            name.endswith(self._TEST_FILE_SUFFIXES) or name.startswith("test_")
            for name in top_level
        )
        return has_tests, has_ci

    def _repository_from_mapping(
        self, item: Mapping[object, object]
    ) -> Optional[GitHubRepository]:
        """Parse a GitHub repository object safely."""
        full_name = item.get("full_name")
        name = item.get("name")
        default_branch = item.get("default_branch")
        html_url = item.get("html_url")
        archived = item.get("archived")
        fork = item.get("fork")

        if not (
            isinstance(full_name, str)
            and isinstance(name, str)
            and isinstance(default_branch, str)
            and isinstance(html_url, str)
            and isinstance(archived, bool)
            and isinstance(fork, bool)
        ):
            return None

        return GitHubRepository(
            full_name=full_name,
            name=name,
            default_branch=default_branch,
            html_url=html_url,
            archived=archived,
            fork=fork,
        )
