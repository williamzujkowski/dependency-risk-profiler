"""Unit tests for the self-cleaning ``cloned_repo`` context manager."""

import os
import tempfile
from typing import Optional, Tuple
from unittest import mock

import pytest

from dependency_risk_profiler import utils


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
