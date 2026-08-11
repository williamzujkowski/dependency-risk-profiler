"""Utility functions used across multiple modules."""

import json
import logging
import os
import re
import shutil
import subprocess  # nosec B404
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

import requests

from .forge_paths import CI_CONFIG_PATHS, CONTRIBUTING_PATHS, any_exists

# Bounded retry for transient HTTP failures (notably 429 rate limiting from
# registry/community APIs on large org scans).
_FETCH_MAX_RETRIES = 3
_FETCH_MAX_BACKOFF_SECONDS = 60.0

# The gh CLI is fast when authenticated; cap it so a hung/misconfigured CLI
# never stalls a scan.
_GH_CLI_TIMEOUT_SECONDS = 5.0
_GITHUB_API_BASE = "https://api.github.com"
# Env vars checked, in order, before falling back to the gh CLI.
_GITHUB_TOKEN_ENV_VARS = ("GITHUB_TOKEN", "GH_TOKEN", "DRP_GITHUB_TOKEN")


def resolve_github_token(explicit: Optional[str] = None) -> Optional[str]:
    """Resolve a GitHub token from the first source that has one.

    Order: an explicit value (CLI flag / config), then the common environment
    variables, then the authenticated gh CLI (``gh auth token``) — so a user
    who has run ``gh auth login`` doesn't have to pass a token at all. Returns
    ``None`` when no source yields one.
    """
    if explicit:
        return explicit
    for env_var in _GITHUB_TOKEN_ENV_VARS:
        value = os.getenv(env_var)
        if value:
            return value
    return _gh_cli_token()


def _gh_cli_token() -> Optional[str]:
    """Return a token from the authenticated gh CLI, or ``None`` if unavailable.

    Never raises: a missing gh binary, an unauthenticated CLI, or a timeout all
    resolve to ``None`` so token discovery degrades quietly.
    """
    gh_path = shutil.which("gh")
    if gh_path is None:
        return None
    try:
        result = subprocess.run(
            [gh_path, "auth", "token"],
            check=False,
            capture_output=True,
            text=True,
            timeout=_GH_CLI_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("gh CLI token lookup failed: %s", exc)
        return None
    if result.returncode != 0:
        return None
    token = result.stdout.strip()
    return token or None


def github_contributor_count(
    repository_url: Optional[str],
    token: Optional[str],
    timeout: int = 30,
) -> Optional[int]:
    """Return a repository's contributor count from the GitHub API, or ``None``.

    Uses the standard pagination trick — request one contributor per page and
    read the last-page number from the ``Link`` header — so a single request
    yields the total without walking every page. Returns ``None`` (unknown)
    when there is no token, the URL isn't a resolvable GitHub repo, or the API
    call fails, so a missing signal stays honestly unknown rather than guessed.
    """
    if not token or not repository_url:
        return None
    repo_info = extract_github_repo_info(repository_url)
    if not repo_info:
        return None
    owner, repo = repo_info
    url = f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/contributors"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "dependency-risk-profiler",
    }
    try:
        response = requests.get(
            url,
            headers=headers,
            params={"per_page": "1", "anon": "true"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        logger.debug("GitHub contributor lookup failed for %s: %s", repository_url, exc)
        return None
    if response.status_code != 200:
        logger.debug(
            "GitHub contributor lookup for %s returned HTTP %s",
            repository_url,
            response.status_code,
        )
        return None
    last_page = _last_page_from_link_header(response.headers.get("Link"))
    if last_page is not None:
        return last_page
    # No Link header means a single page: count the returned contributors.
    try:
        payload = response.json()
    except ValueError:
        return None
    if isinstance(payload, list):
        return len(payload)
    return None


def github_commit_frequency(
    repository_url: Optional[str],
    token: Optional[str],
    months: int = 6,
    timeout: int = 30,
) -> Optional[float]:
    """Return commits per month from the GitHub API, or ``None``.

    The analyze path clones ``--depth 1``, and one reachable commit cannot
    answer "how often is this maintained?" any better than it can answer "how
    many people maintain it?" — so cadence comes from the API for the same
    reason the contributor count does. Same single-request pagination trick:
    one commit per page, and the last-page number is the total.

    Args:
        repository_url: Repository URL published by the registry.
        token: GitHub token; without one the signal stays unknown.
        months: Trailing window, matching ``calculate_commit_frequency``.
        timeout: Per-request timeout in seconds.

    Returns:
        Average commits per month, or None when there is no token, the URL is
        not a resolvable GitHub repo, or the API does not answer.
    """
    if not token or not repository_url:
        return None
    repo_info = extract_github_repo_info(repository_url)
    if not repo_info:
        return None
    owner, repo = repo_info
    since = (datetime.now(timezone.utc) - timedelta(days=30 * months)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "dependency-risk-profiler",
    }
    try:
        response = requests.get(
            f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/commits",
            headers=headers,
            params={"since": since, "per_page": "1"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        logger.debug("GitHub commit lookup failed for %s: %s", repository_url, exc)
        return None
    if response.status_code != 200:
        logger.debug(
            "GitHub commit lookup for %s returned HTTP %s",
            repository_url,
            response.status_code,
        )
        return None

    last_page = _last_page_from_link_header(response.headers.get("Link"))
    if last_page is not None:
        return last_page / months
    # No Link header means a single page: count what came back.
    try:
        payload = response.json()
    except ValueError:
        return None
    if isinstance(payload, list):
        return len(payload) / months
    return None


def _last_page_from_link_header(link_header: Optional[str]) -> Optional[int]:
    """Return the ``rel="last"`` page number from a GitHub ``Link`` header."""
    if not link_header:
        return None
    for part in link_header.split(","):
        segments = part.split(";")
        if len(segments) < 2:
            continue
        url_segment = segments[0].strip().strip("<>")
        if not any('rel="last"' in seg for seg in segments[1:]):
            continue
        match = re.search(r"[?&]page=(\d+)", url_segment)
        if match:
            return int(match.group(1))
    return None


def _retry_after_seconds(response: requests.Response, attempt: int) -> float:
    """Return how long to wait before retrying, honoring Retry-After if sent."""
    header = response.headers.get("Retry-After")
    if header:
        try:
            return min(float(header), _FETCH_MAX_BACKOFF_SECONDS)
        except ValueError:
            pass  # HTTP-date form: fall back to exponential backoff
    return min(2.0**attempt, _FETCH_MAX_BACKOFF_SECONDS)


logger = logging.getLogger(__name__)


def fetch_url(url: str, timeout: int = 30) -> Optional[str]:
    """Fetch content from a URL.

    Args:
        url: URL to fetch.
        timeout: Timeout in seconds.

    Returns:
        Content of the URL or None if fetching fails.
    """
    for attempt in range(_FETCH_MAX_RETRIES + 1):
        try:
            response = requests.get(url, timeout=timeout)
            # Back off and retry on rate limiting / transient server errors.
            if (
                response.status_code == 429 or response.status_code >= 500
            ) and attempt < _FETCH_MAX_RETRIES:
                wait = _retry_after_seconds(response, attempt)
                logger.debug(
                    "Transient %s from %s; retrying in %.1fs (attempt %d/%d)",
                    response.status_code,
                    url,
                    wait,
                    attempt + 1,
                    _FETCH_MAX_RETRIES,
                )
                time.sleep(wait)
                continue
            response.raise_for_status()
            # Explicitly cast response.text to str to help mypy
            return str(response.text)
        except requests.HTTPError as e:
            # Non-transient (4xx other than 429); 429/5xx that reach here are on
            # the final attempt. Either way, don't retry further.
            logger.debug("HTTP error fetching %s: %s", url, e)
            return None
        except requests.RequestException as e:
            # Connection/timeout errors are transient — back off and retry.
            if attempt >= _FETCH_MAX_RETRIES:
                logger.debug("Giving up fetching %s: %s", url, e)
                return None
            time.sleep(min(2.0**attempt, _FETCH_MAX_BACKOFF_SECONDS))
    return None


def fetch_json(url: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
    """Fetch JSON from a URL.

    Args:
        url: URL to fetch.
        timeout: Timeout in seconds.

    Returns:
        JSON content or None if fetching fails.
    """
    content = fetch_url(url, timeout)
    if not content:
        return None

    try:
        # Properly type the result to avoid mypy errors
        result: Dict[str, Any] = json.loads(content)
        return result
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {url}: {e}")
        return None


# A shallow clone of a normal repo finishes in a few seconds; a large cap
# only exists to bound pathological cases without letting one repo stall a
# whole scan (git:// / auth-required URLs used to hang for minutes).
CLONE_TIMEOUT_SECONDS = 60

#: Hosts this tool is willing to ``git clone`` from, and the only hosts any
#: repository-derived signal can come from. Widened from three by #290: each
#: of the four additions was verified cloneable with
#: ``git clone --depth 1 --no-tags`` before it was added, and the three that
#: were already here are unchanged.
#:
#: What widening this does *not* widen: nothing here reaches
#: :mod:`~dependency_risk_profiler.secure_http`, which validates its own
#: destinations and is not consulted for clones; no host is probed; and no
#: request is made to a host a package's own metadata did not name. What it
#: does widen is the set of hosts ``git clone`` may be pointed at, from
#: registry-supplied strings — always over https, never over cleartext, and
#: always with ``GIT_TERMINAL_PROMPT=0`` so a host that demands credentials
#: fails rather than prompts.
_CLONEABLE_HOSTS = (
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "gitea.com",
    "git.sr.ht",
    "gitee.com",
)

#: Placeholder written over any userinfo before a URL reaches a log record.
_REDACTED_USERINFO = "[redacted]"


def redact_credentials(repo_url: Optional[str]) -> str:
    """Return a repository URL safe to put in a log line.

    A registry string, a lockfile entry or a manifest can carry
    ``https://user:token@host/owner/repo``. :func:`normalize_clone_url` refuses
    those, and the refusal is logged — so without this the rejection itself is
    what writes the token to disk. Everything between the scheme and the first
    ``@`` of the authority is replaced; nothing is parsed out of it, because a
    malformed credential is still a credential.

    Args:
        repo_url: A repository URL, including one that did not parse.

    Returns:
        The URL with any embedded userinfo replaced, or ``"<none>"`` for an
        absent URL.
    """
    if not repo_url:
        return "<none>"
    scheme, separator, rest = repo_url.partition("://")
    if not separator:
        # scp-style ``user@host:owner/repo``: the authority is the whole string.
        userinfo, at_sign, remainder = repo_url.partition("@")
        if not at_sign:
            return repo_url
        return f"{_REDACTED_USERINFO}@{remainder}"
    authority, slash, path = rest.partition("/")
    userinfo, at_sign, host = authority.rpartition("@")
    if not at_sign:
        return repo_url
    return f"{scheme}://{_REDACTED_USERINFO}@{host}{slash}{path}"


def normalize_clone_url(repo_url: str) -> Optional[str]:
    """Return a plain https clone URL for a supported host, or None to skip.

    Package metadata spells repository URLs many ways (``git+https://``,
    ``git://``, ``git@host:owner/repo``, ``ssh://``, ``.git`` suffixes). This
    normalizes them to https and rejects anything that would make ``git clone``
    hang or fail — notably ``git://`` (GitHub disabled it in 2022) and
    ssh/auth URLs — so a single bad URL can't stall a scan for minutes.

    Three normalisations beyond that, all of them #290:

    * **Plain ``http://`` is upgraded to https**, for the same reason ``git://``
      already is: registries carry URLs written before the host had TLS and
      nobody rewrote them. It is 15.35% of RubyGems, and 114 of the 233
      ``http://`` declarations in an 8,870-package survey are on ``github.com``
      — repositories this tool already supported, discarded over a scheme.
      The upgrade is to https and the clone happens over https; a cleartext
      clone is never attempted, because fetching an artifact over a channel an
      attacker can rewrite, in order to score that artifact's supply-chain
      risk, measures the attacker rather than the artifact.
    * **A leading ``www.`` is stripped from the host.** It is not cosmetic:
      ``golang.py`` de-duplicates clones by URL, so two spellings of one
      repository clone it twice, and every ``owner/repo`` identity derived from
      the host forks in two.
    * **Embedded credentials are rejected outright** rather than dropped. The
      old code did ``netloc.split("@")[-1]``, which silently turned
      ``https://user:token@github.com/x/y`` into a clone of ``x/y`` — the URL
      was accepted, the secret was discarded, and nothing said either happened.
      A URL carrying a credential is hostile input, not input to sanitise. The
      ssh/scp spellings are the deliberate exception: their userinfo is an SSH
      login name (``git@``), it is dropped as part of rewriting the scheme, and
      a *password* in one (``ssh://user:pass@host/x``) is refused like any
      other credential.

    Args:
        repo_url: Repository URL as some registry, lockfile or manifest
            published it.

    Returns:
        An https URL on a host in :data:`_CLONEABLE_HOSTS`, or None.
    """
    url = repo_url.strip()
    if url.startswith("git+"):
        url = url[4:]
    scp_match = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", url)
    if scp_match:
        url = f"https://{scp_match.group(1)}/{scp_match.group(2)}"
    elif url.startswith("git://"):
        url = "https://" + url[len("git://") :]
    elif url.startswith("ssh://"):
        authority, _, _ = url[len("ssh://") :].partition("/")
        userinfo, at_sign, _ = authority.rpartition("@")
        if at_sign and ":" in userinfo:
            logger.debug(
                "Rejecting repository URL carrying a credential: %s",
                redact_credentials(repo_url),
            )
            return None
        url = "https://" + url[len("ssh://") :].split("@", 1)[-1]
    elif url.startswith("http://"):
        url = "https://" + url[len("http://") :]
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    if "@" in parsed.netloc:
        logger.debug(
            "Rejecting repository URL carrying a credential: %s",
            redact_credentials(repo_url),
        )
        return None
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[len("www.") :]
    if not any(host == h or host.endswith("." + h) for h in _CLONEABLE_HOSTS):
        return None
    return urlunparse(parsed._replace(netloc=host))


def canonical_repository_url(repo_url: Optional[str]) -> Optional[str]:
    """Return the ``https://host/owner/repo`` root of a hosted repository URL.

    Registry metadata routinely points *inside* a repository rather than at it:
    RubyGems gems publish ``source_code_uri`` as
    ``https://github.com/tzinfo/tzinfo/tree/v2.0.6``, and monorepo packages
    point at a subdirectory. Both ``git clone`` and the GitHub API reject those
    deeper paths, which silently drops every repository-derived signal for the
    dependency. Trimming to the repository root restores them.

    The first two path segments are the ``owner/repo`` pair on every host in
    :data:`_CLONEABLE_HOSTS`, and everything after them is a view of the
    repository rather than another repository: GitHub's ``/tree/v2.0.6``,
    GitLab's ``/-/tree/main``, Forgejo's and Gitea's ``/src/branch/main/x``,
    SourceHut's ``/tree/main/item/x``. So the trim needs no per-forge table —
    one rule covers all of them, and a table with one row in it would be a
    second place for the rule to be wrong. SourceHut's owner carries a leading
    ``~``; it is part of the path and is preserved verbatim.

    Returns ``None`` when the URL is not a repository on a supported host or
    carries no ``owner/repo`` pair.
    """
    if not repo_url:
        return None
    normalized = normalize_clone_url(repo_url)
    if normalized is None:
        return None
    parsed = urlparse(normalized)
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) < 2:
        return None
    owner, repo = path_parts[0], path_parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not repo:
        return None
    # ``normalize_clone_url`` has already lowercased the host, stripped any
    # ``www.`` and refused anything carrying userinfo, so this is the one
    # spelling of the host and there is nothing left to strip off it.
    return f"https://{parsed.netloc}/{owner}/{repo}"


def is_cloneable_repo_url(repo_url: Optional[str]) -> bool:
    """Return True if the URL is a cloneable https repo on a supported host.

    Uses full URL parsing (not a substring host check) so lookalike hosts such
    as ``https://github.com.evil.example/x/y`` are correctly rejected.
    """
    if not repo_url:
        return False
    return normalize_clone_url(repo_url) is not None


#: Normalized clone URLs whose clone already failed in this process.
#:
#: A repository that cannot be cloned costs ``CLONE_TIMEOUT_SECONDS`` per
#: attempt, and eight of the eighteen NuGet packages in one eShopOnWeb
#: manifest resolve to ``github.com/dotnet/dotnet``: 480 of that run's 582
#: seconds were the same doomed clone, attempted once per package, into eight
#: separate temp directories. Nothing about the seventh attempt differed from
#: the first (#282).
#:
#: **Keyed on the normalized clone URL**, which is the exact argument handed to
#: ``git clone`` and therefore the thing that decides the outcome. Not on the
#: package: the eight packages are eight names for one repository, so a
#: per-package key would cache nothing. Not on the raw registry string either,
#: since registries spell one repository several ways (``git+https://…``,
#: ``git@host:owner/repo``) and each spelling would buy its own timeout.
#:
#: **Scope is the process, so the TTL is the run.** That is a different answer
#: from the advisory cache's 24 hours on disk, not a smaller one:
#:
#: * A cached clone failure silences eight signals. Persisting one means a
#:   network blip during today's run goes on reporting a repository as
#:   unreadable tomorrow, after the condition has cleared. A stale negative
#:   served past the fix is the exact shape of #219. Bounding the entry to the
#:   process bounds it to the run in which the failure was actually observed.
#: * Nothing is written anywhere, so a URL built from package metadata —
#:   attacker-influenceable input — never reaches a filename. The advisory
#:   cache has to hash its key so one package's record cannot be served for
#:   another or escape the cache directory (#212, #216); here there is no
#:   directory to escape and no key to collide.
#: * Separating a timeout from a repository that no longer exists only buys
#:   something if the two deserve different expiries. Inside one process they
#:   do not, so the classifier that would decide it is not built: it would
#:   have no reader, and classifying git's stderr by substring is exactly the
#:   kind of guess that fails quietly.
#:
#: Only failures are recorded. Reusing a *successful* worktree across the
#: dependencies that share it is the same win in the healthier direction, and
#: it is a separate change with its own lifetime and cleanup questions (#301).
_failed_clone_urls: Set[str] = set()

#: Guards :data:`_failed_clone_urls`. No threaded caller reaches ``clone_repo``
#: today — org scans set ``clone_repos`` False and read the GitHub API instead
#: — but module-level mutable state behind a public function should not depend
#: on which callers happen to exist right now. ``org_scan.pipeline`` guards its
#: own shared caches the same way.
_failed_clone_lock = threading.Lock()


def reset_failed_clone_cache() -> None:
    """Forget every clone failure recorded in this process.

    There is no expiry inside a run — that is the design — so anything wanting
    a second opinion has to ask for one. The test suite is a single process for
    the whole run and empties the cache around every test
    (``testing/conftest.py``); without that, the first test to record a failure
    for a URL would answer for every later test that touches it, and an
    assertion about whether a clone was attempted would turn on collection
    order.
    """
    with _failed_clone_lock:
        _failed_clone_urls.clear()


def clone_repo(repo_url: str) -> Optional[Tuple[str, str]]:
    """Clone a git repository to a temporary directory.

    A repository whose clone already failed in this process is not attempted
    again; see :data:`_failed_clone_urls` for what the cache is keyed on and
    why it does not outlive the run. The cached answer is the same ``None``
    the failing path returns, so a caller cannot tell the two apart and there
    is one downstream code path rather than two — which is what keeps a cached
    failure an unmeasured signal instead of a measured zero (AGENTS.md rule 4).

    Args:
        repo_url: URL of the repository.

    Returns:
        Tuple of (repo_dir, repo_name) or None if cloning fails or the URL is
        not a cloneable https URL for a supported host.
    """
    normalized_url = normalize_clone_url(repo_url)
    if normalized_url is None:
        logger.debug(
            "Skipping non-cloneable repository URL: %s",
            redact_credentials(repo_url),
        )
        return None
    with _failed_clone_lock:
        already_failed = normalized_url in _failed_clone_urls
    if already_failed:
        logger.debug(
            "Skipping clone of %s: an earlier clone in this run failed",
            redact_credentials(repo_url),
        )
        return None
    temp_dir: Optional[str] = None
    try:
        parsed_url = urlparse(normalized_url)
        path_parts = parsed_url.path.strip("/").split("/")
        if len(path_parts) < 2:
            logger.error("Invalid repository URL: %s", redact_credentials(repo_url))
            return None

        repo_name = path_parts[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        # Create a temporary directory
        temp_dir = tempfile.mkdtemp(prefix="dep-profiler-")
        repo_dir = f"{temp_dir}/{repo_name}"

        # Never let git block on a credential/host prompt — fail fast instead.
        clone_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}

        # Clone the repository (shallow, no tags, non-interactive). A non-zero
        # exit raises rather than returning, so the handler below is the only
        # way out of a failed clone — there is no second exit for the cache to
        # miss. The `returncode == 0` branch that used to follow this call was
        # unreachable under `check=True` and is gone.
        subprocess.run(
            [  # nosec B603, B607
                "git",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                normalized_url,
                repo_dir,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            env=clone_env,
        )
        return repo_dir, repo_name
    except Exception as e:
        logger.error("Error cloning %s: %s", redact_credentials(repo_url), e)
        with _failed_clone_lock:
            _failed_clone_urls.add(normalized_url)
        # Remove the destination this attempt created. git writes into it as it
        # goes, so a clone killed at the timeout leaves a partial checkout that
        # nothing else will ever clean up: a single eShopOnWeb run left eight of
        # them at roughly 390 MB each, and `cloned_repo` only removes the tree
        # when the clone succeeded.
        if temp_dir is not None:
            shutil.rmtree(temp_dir, ignore_errors=True)
        return None


@contextmanager
def cloned_repo(repo_url: str) -> Iterator[Optional[Tuple[str, str]]]:
    """Clone a repository into a temp dir and always remove it afterward.

    Yields the ``(repo_dir, repo_name)`` tuple from :func:`clone_repo`, or
    ``None`` if the clone failed. The temporary clone directory is deleted on
    exit regardless of how the ``with`` block terminates, so short-lived repo
    inspection never leaks ``dep-profiler-*`` directories into the temp dir.
    """
    result = clone_repo(repo_url)
    temp_root: Optional[str] = None
    if result is not None:
        repo_dir, _ = result
        temp_root = os.path.dirname(repo_dir)
    try:
        yield result
    finally:
        if temp_root is not None and os.path.isdir(temp_root):
            shutil.rmtree(temp_root, ignore_errors=True)


def get_last_commit_date(repo_dir: str) -> Optional[str]:
    """Get the date of the last commit in a repository.

    Args:
        repo_dir: Path to the repository.

    Returns:
        Date of the last commit in ISO format or None if fetching fails.
    """
    try:
        # Execute git command to get the last commit date
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cI"],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )

        commit_date = result.stdout.strip()
        if commit_date:
            return commit_date
        else:
            logger.error(f"No commit date found in {repo_dir}")
            return None
    except Exception as e:
        logger.error(f"Error getting last commit date: {e}")
        return None


def count_contributors(repo_dir: str) -> Optional[int]:
    """Count contributors to a repository.

    Args:
        repo_dir: Path to the repository.

    Returns:
        Number of contributors or None if counting fails.
    """
    try:
        # A shallow clone (we clone --depth 1) has only one reachable commit, so
        # `git shortlog --all` would report exactly one contributor for every
        # repository — a false "single maintainer" signal. Report unknown (None)
        # in that case rather than a misleading count; the real contributor count
        # comes from the GitHub API (see github_contributor_count).
        if is_shallow_clone(repo_dir):
            logger.debug(
                "Skipping contributor count in %s: shallow clone has no history",
                repo_dir,
            )
            return None

        # Execute git command to count contributors
        result = subprocess.run(
            [
                "git",
                "shortlog",
                "-s",
                "-n",
                "--all",
                "--no-merges",
            ],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )

        contributors = result.stdout.strip().split("\n")
        if contributors and contributors[0]:
            return len(contributors)
        else:
            logger.warning(f"No contributors found in {repo_dir}")
            return 0
    except Exception as e:
        logger.error(f"Error counting contributors: {e}")
        return None


def is_shallow_clone(repo_dir: str) -> bool:
    """Return whether ``repo_dir`` is a shallow git clone.

    A shallow clone cannot answer history questions (contributor count, commit
    cadence, full log) accurately, so callers should treat those signals as
    unknown rather than reading a confident wrong number out of one commit.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],  # nosec B603, B607
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Could not determine shallow status for %s: %s", repo_dir, exc)
        return False
    return result.stdout.strip() == "true"


def check_health_indicators(repo_dir: str) -> Tuple[bool, bool, bool]:
    """Check for health indicators in a repository.

    Args:
        repo_dir: Path to the repository.

    Returns:
        Tuple of (has_tests, has_ci, has_contribution_guidelines).
    """
    repo_path = Path(repo_dir)

    # Check for tests directory or test files
    test_patterns = [
        "test/",
        "tests/",
        "spec/",
        "specs/",
        "*_test.py",
        "*_spec.js",
        "test_*.py",
    ]
    has_tests = False
    for pattern in test_patterns:
        if "*" in pattern:
            # Handle filename patterns
            for file_path in repo_path.glob(pattern):
                if file_path.exists():
                    has_tests = True
                    break
        else:
            # Handle directory patterns
            if repo_path.joinpath(pattern).exists():
                has_tests = True
                break

    # Check for CI configuration. The forge-native workflow directories and
    # Woodpecker join the list here (#291): the Codeberg clone of
    # ``django-allauth`` runs Woodpecker and, with ``.github/`` removed,
    # reported ``has_ci=False`` while ``.woodpecker.yaml`` sat in its root.
    has_ci = any_exists(repo_path, CI_CONFIG_PATHS)

    # Check for contribution guidelines, in each forge's own folder as well as
    # the root and ``docs/``.
    has_contribution_guidelines = any_exists(repo_path, CONTRIBUTING_PATHS)

    return has_tests, has_ci, has_contribution_guidelines


#: What GitHub actually permits in a repository name: alphanumerics, hyphen,
#: underscore and dot. Anything else means the URL was not parsed, not that the
#: repository is missing.
_GITHUB_NAME = re.compile(r"[A-Za-z0-9._-]+")


def extract_github_repo_info(repo_url: str) -> Optional[Tuple[str, str]]:
    """Extract owner and repo name from a GitHub URL.

    Args:
        repo_url: GitHub repository URL.

    Returns:
        Tuple of (owner, repo) or None if not a GitHub URL.
    """
    if not repo_url:
        return None

    repo_url = repo_url.strip()

    # Drop a fragment or query before matching, not after.
    #
    # The patterns below anchor on end-of-string, so anything trailing the
    # repository name became part of it: `github.com/foo/bar.git#main` yielded
    # a repo named `bar.git#main`, because `.git` stripping only fires when
    # `.git` is last. A `#` cannot appear in a GitHub repository name, so every
    # such pair 404s and the forge lookup fails silently -- the repository
    # signals then report unmeasured for a repository that exists.
    #
    # npm and Go both put a committish after `#`, so this is not a rare shape:
    # it hit 43 of 2,109 GitHub-declaring packages in the abandonment cohort.
    repo_url = repo_url.split("#", 1)[0].split("?", 1)[0]

    github_patterns = [
        r"github\.com[/:]([^/]+)/([^/]+)(\.git)?/?$",
        r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git|/)?$",
    ]

    for pattern in github_patterns:
        match = re.search(pattern, repo_url)
        if match:
            owner = match.group(1)
            repo = match.group(2)
            if repo.endswith(".git"):
                repo = repo[:-4]
            # A name GitHub cannot have is not a name. Returning one sends a
            # request that is certain to 404 and reports the answer as though
            # the repository were missing rather than the URL unparsed.
            if not owner or not repo or not _GITHUB_NAME.fullmatch(repo):
                return None
            return owner, repo

    return None
