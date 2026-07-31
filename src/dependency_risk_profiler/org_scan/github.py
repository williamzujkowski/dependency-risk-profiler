"""GitHub REST API client for organization dependency discovery."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional

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
        repos: List[RepositoryRef] = []
        page = 1
        while True:
            payload = self._get_json(
                f"/orgs/{org}/repos",
                {"per_page": "100", "page": str(page), "type": "all"},
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
