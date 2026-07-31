"""Unit tests for the self-cleaning ``cloned_repo`` context manager."""

import os
import tempfile
from typing import Optional, Tuple
from unittest import mock

import pytest

from dependency_risk_profiler import utils


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("git://github.com/debug-js/debug", "https://github.com/debug-js/debug"),
        ("git+https://github.com/foo/bar.git", "https://github.com/foo/bar.git"),
        ("git@github.com:owner/repo.git", "https://github.com/owner/repo.git"),
        ("ssh://git@github.com/owner/repo", "https://github.com/owner/repo"),
        ("https://github.com/a/b", "https://github.com/a/b"),
        ("https://gitlab.com/a/b", "https://gitlab.com/a/b"),
        # Rejected: unsupported host, non-https scheme, and local paths.
        ("https://evil.example.com/a/b", None),
        ("file:///etc/passwd", None),
        ("git://internal.host/secret", None),
    ],
)
def test_normalize_clone_url(raw: str, expected: Optional[str]) -> None:
    """Normalize to https for supported hosts; skip everything else."""
    assert utils.normalize_clone_url(raw) == expected


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://github.com/a/b", True),
        ("git+https://github.com/a/b.git", True),
        ("https://gitlab.com/a/b", True),
        # Lookalike / embedded host must NOT pass a real host check.
        ("https://github.com.evil.example/a/b", False),
        ("https://evil.example/github.com/a/b", False),
        ("git://internal.host/secret", False),
        (None, False),
        ("", False),
    ],
)
def test_is_cloneable_repo_url(url: Optional[str], expected: bool) -> None:
    """Only real supported-host https URLs are cloneable; lookalikes are not."""
    assert utils.is_cloneable_repo_url(url) is expected


def test_clone_repo_skips_uncloneable_url_without_running_git() -> None:
    """A non-cloneable URL returns None and never shells out to git."""
    with mock.patch.object(utils.subprocess, "run") as run:
        assert utils.clone_repo("git://internal.host/secret") is None
        run.assert_not_called()


def _fake_clone(_repo_url: str) -> Optional[Tuple[str, str]]:
    """Create a real temp clone dir like ``clone_repo`` would, without git."""
    temp_dir = tempfile.mkdtemp(prefix="dep-profiler-")
    repo_dir = os.path.join(temp_dir, "repo")
    os.makedirs(repo_dir)
    return repo_dir, "repo"


def test_cloned_repo_removes_temp_dir_on_normal_exit() -> None:
    """The clone temp dir is deleted when the with-block completes."""
    with mock.patch.object(utils, "clone_repo", side_effect=_fake_clone):
        with utils.cloned_repo("https://github.com/acme/widget") as result:
            assert result is not None
            repo_dir, name = result
            assert name == "repo"
            temp_root = os.path.dirname(repo_dir)
            assert os.path.isdir(temp_root)
        assert not os.path.exists(temp_root)


def test_cloned_repo_removes_temp_dir_on_exception() -> None:
    """The clone temp dir is deleted even if the with-block raises."""
    captured_root: Optional[str] = None
    with mock.patch.object(utils, "clone_repo", side_effect=_fake_clone):
        with pytest.raises(RuntimeError):
            with utils.cloned_repo("https://github.com/acme/widget") as result:
                assert result is not None
                captured_root = os.path.dirname(result[0])
                assert os.path.isdir(captured_root)
                raise RuntimeError("boom")
    assert captured_root is not None
    assert not os.path.exists(captured_root)


def test_cloned_repo_yields_none_when_clone_fails() -> None:
    """A failed clone yields None and never raises on cleanup."""

    def _fail(_repo_url: str) -> Optional[Tuple[str, str]]:
        return None

    with mock.patch.object(utils, "clone_repo", side_effect=_fail):
        with utils.cloned_repo("https://github.com/acme/widget") as result:
            assert result is None
