"""Tests for GitHub token resolution and API-based contributor counting.

These cover the fix for the flagship "maintainer concentration" signal: the
analyze path used to run ``git shortlog`` on a shallow clone and always report
one contributor, so every dependency read as "single maintainer". The real
count now comes from the GitHub API, and the token is discovered from the
flag, the environment, or the authenticated gh CLI.
"""

import subprocess
from typing import Optional
from unittest import mock

import pytest
import requests

from dependency_risk_profiler import analysis_helpers, utils
from dependency_risk_profiler.community import analyzer as community_analyzer
from dependency_risk_profiler.forges import github as github_forge
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.signals import FieldSource, ProvenancedField


class _FakeResponse:
    """Minimal stand-in for ``requests.Response``."""

    def __init__(
        self,
        status_code: int = 200,
        headers: Optional[dict] = None,
        payload: object = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._payload = payload

    def json(self) -> object:
        if isinstance(self._payload, ValueError):
            raise self._payload
        return self._payload


def test_resolve_token_prefers_explicit() -> None:
    """An explicit token wins over env and gh CLI."""
    with mock.patch.object(utils.os, "getenv", return_value="env-token"):
        assert utils.resolve_github_token("explicit") == "explicit"


def test_resolve_token_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Env vars are checked in order when no explicit token is given."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("DRP_GITHUB_TOKEN", "drp-token")
    assert utils.resolve_github_token() == "drp-token"


def test_resolve_token_falls_back_to_gh_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no explicit/env token, an authenticated gh CLI supplies one."""
    for var in ("GITHUB_TOKEN", "GH_TOKEN", "DRP_GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    with mock.patch.object(utils.shutil, "which", return_value="/usr/bin/gh"):
        completed = subprocess.CompletedProcess(
            args=["gh", "auth", "token"], returncode=0, stdout="gho_fromcli\n"
        )
        with mock.patch.object(utils.subprocess, "run", return_value=completed):
            assert utils.resolve_github_token() == "gho_fromcli"


def test_resolve_token_none_when_gh_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """No token anywhere resolves to None (not a guess)."""
    for var in ("GITHUB_TOKEN", "GH_TOKEN", "DRP_GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    with mock.patch.object(utils.shutil, "which", return_value=None):
        assert utils.resolve_github_token() is None


def test_gh_cli_token_none_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unauthenticated gh CLI (non-zero exit) yields no token."""
    for var in ("GITHUB_TOKEN", "GH_TOKEN", "DRP_GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    with mock.patch.object(utils.shutil, "which", return_value="/usr/bin/gh"):
        completed = subprocess.CompletedProcess(
            args=["gh", "auth", "token"], returncode=1, stdout=""
        )
        with mock.patch.object(utils.subprocess, "run", return_value=completed):
            assert utils.resolve_github_token() is None


def test_gh_cli_token_none_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung gh CLI degrades quietly to None rather than raising."""
    for var in ("GITHUB_TOKEN", "GH_TOKEN", "DRP_GITHUB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    with mock.patch.object(utils.shutil, "which", return_value="/usr/bin/gh"):
        boom = subprocess.TimeoutExpired(cmd="gh", timeout=5.0)
        with mock.patch.object(utils.subprocess, "run", side_effect=boom):
            assert utils.resolve_github_token() is None


def test_last_page_from_link_header() -> None:
    """The last-page number is parsed from a GitHub Link header."""
    header = (
        "<https://api.github.com/repos/o/r/contributors?per_page=1&page=2>; "
        'rel="next", '
        "<https://api.github.com/repos/o/r/contributors?per_page=1&page=317>; "
        'rel="last"'
    )
    assert utils._last_page_from_link_header(header) == 317


def test_last_page_none_without_header() -> None:
    """No Link header means a single page (None)."""
    assert utils._last_page_from_link_header(None) is None


def test_contributor_count_none_without_token() -> None:
    """No token → unknown, and no network call is attempted."""
    with mock.patch.object(utils.requests, "get") as get:
        assert utils.github_contributor_count("https://github.com/o/r", None) is None
        get.assert_not_called()


def test_contributor_count_uses_link_header() -> None:
    """A large contributor count comes from the Link header's last page."""
    header = (
        "<https://api.github.com/repos/pallets/flask/contributors"
        '?per_page=1&page=780>; rel="last"'
    )
    response = _FakeResponse(status_code=200, headers={"Link": header})
    with mock.patch.object(utils.requests, "get", return_value=response):
        count = utils.github_contributor_count(
            "https://github.com/pallets/flask", "tok"
        )
    assert count == 780


def test_contributor_count_single_page_counts_payload() -> None:
    """Without a Link header, the returned list length is the count."""
    response = _FakeResponse(status_code=200, headers={}, payload=[{"id": 1}])
    with mock.patch.object(utils.requests, "get", return_value=response):
        count = utils.github_contributor_count("https://github.com/o/solo", "tok")
    assert count == 1


def test_contributor_count_none_on_http_error() -> None:
    """A non-200 response resolves to unknown."""
    response = _FakeResponse(status_code=404, headers={})
    with mock.patch.object(utils.requests, "get", return_value=response):
        assert (
            utils.github_contributor_count("https://github.com/o/gone", "tok") is None
        )


def test_contributor_count_none_on_request_exception() -> None:
    """A network failure resolves to unknown, not a crash."""
    with mock.patch.object(
        utils.requests, "get", side_effect=requests.RequestException("boom")
    ):
        assert utils.github_contributor_count("https://github.com/o/r", "tok") is None


def test_contributor_count_none_for_non_github_url() -> None:
    """A non-GitHub repository URL is not resolvable to a count."""
    assert utils.github_contributor_count("https://gitlab.com/o/r", "tok") is None


class TestAMeasuredZeroIsAnAnswer:
    """``count_contributors`` separates "none" from "could not count".

    It returns None for a count it could not take and an int for one it did,
    and the analyze path threw the zero away with ``if contributor_count:`` —
    the falsy-vs-absent read, in the field where absent and zero have opposite
    meanings for the maintainer-concentration score (#217).
    """

    def test_a_zero_count_reaches_the_dependency(self) -> None:
        """A repository with no contributors measured zero of them."""
        dependency = DependencyMetadata(name="pkg", installed_version="1.0.0")

        with (
            mock.patch.object(
                analysis_helpers, "get_last_commit_date", return_value=None
            ),
            mock.patch.object(analysis_helpers, "count_contributors", return_value=0),
            mock.patch.object(
                analysis_helpers, "calculate_commit_frequency", return_value=None
            ),
            mock.patch.object(
                analysis_helpers,
                "check_health_indicators",
                return_value=(False, False, False),
            ),
        ):
            analysis_helpers.analyze_repository(dependency, "/nonexistent")

        assert dependency.maintainer_count == 0
        assert (
            dependency.field_sources.get(ProvenancedField.MAINTAINER_COUNT)
            is FieldSource.REPOSITORY_CLONE_HISTORY
        )

    def test_an_uncountable_repository_stays_unmeasured(self) -> None:
        """A shallow clone or a git failure is still nobody having looked."""
        dependency = DependencyMetadata(name="pkg", installed_version="1.0.0")

        with (
            mock.patch.object(
                analysis_helpers, "get_last_commit_date", return_value=None
            ),
            mock.patch.object(
                analysis_helpers, "count_contributors", return_value=None
            ),
            mock.patch.object(
                analysis_helpers, "calculate_commit_frequency", return_value=None
            ),
            mock.patch.object(
                analysis_helpers,
                "check_health_indicators",
                return_value=(False, False, False),
            ),
        ):
            analysis_helpers.analyze_repository(dependency, "/nonexistent")

        assert dependency.maintainer_count is None
        assert ProvenancedField.MAINTAINER_COUNT not in dependency.field_sources

    def test_a_zero_maintainer_count_is_copied_to_contributor_count(self) -> None:
        """The same read, in the community pass that copies the count across."""
        dependency = DependencyMetadata(
            name="pkg",
            installed_version="1.0.0",
            repository_url="https://github.com/o/r",
        )
        dependency.maintainer_count = 0
        dependency.record_field_source(
            ProvenancedField.MAINTAINER_COUNT, FieldSource.REPOSITORY_CLONE_HISTORY
        )

        with (
            mock.patch.object(
                github_forge, "github_contributor_count", return_value=None
            ),
            mock.patch.object(
                github_forge, "github_commit_frequency", return_value=None
            ),
            mock.patch.object(github_forge, "fetch_url", return_value=None),
        ):
            community_analyzer.analyze_forge_community_metrics(dependency)

        assert dependency.community_metrics is not None
        assert dependency.community_metrics.contributor_count == 0
