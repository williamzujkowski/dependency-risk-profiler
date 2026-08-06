"""The clone-failure cache: one doomed repository costs one attempt, not N.

#282. Eight of the eighteen NuGet packages in eShopOnWeb's ``Web.csproj``
resolve to ``github.com/dotnet/dotnet``, the .NET unified-source monorepo. A
shallow clone of it does not finish inside ``CLONE_TIMEOUT_SECONDS``, and
before this cache it did not finish eight separate times: 480 of the run's 582
seconds spent re-learning a fact that was known after the first attempt.

The hazard this change carries is the AGENTS.md rule 4 one, and it is the
reason these tests assert what they assert. A cache that *answered* for a
failed clone could easily start answering with something other than the honest
unmeasured state a fresh failure produces — that is the #218 / #219 defect
wearing a new hat. It cannot happen here by construction rather than by
convention: the cache short-circuits :func:`~...utils.clone_repo` to the same
``None`` its failing path returns, so there is one downstream code path and not
two. ``test_a_cached_failure_leaves_the_same_state_a_fresh_failure_does``
asserts that as values on the record, and
``test_a_successful_clone_that_found_nothing_is_not_the_unmeasured_state``
asserts the other half: measured-and-absent is still ``False``, never ``None``.

Every count assertion here is on ``subprocess.run.call_count`` — the
production call, not a fixture's idea of one. Deleting the cache lookup from
``clone_repo`` turns the 1s into 2s and fails the suite; the paired
``test_a_second_repository_is_still_cloned`` is what stops a broken cache from
passing by never attempting anything at all.
"""

import subprocess
from pathlib import Path
from typing import Iterator, Tuple
from unittest import mock

import pytest

from dependency_risk_profiler import utils
from dependency_risk_profiler.analyzers.common import collect_repository_signals
from dependency_risk_profiler.models import DependencyMetadata

#: The repository the eight eShopOnWeb packages share.
DOTNET_MONOREPO = "https://github.com/dotnet/dotnet"

#: A second, unrelated repository, used to prove the cache is keyed rather than
#: global — a "clone once per run" bug would pass every single-URL assertion.
DOTNET_RUNTIME = "https://github.com/dotnet/runtime"

#: Every field ``analyze_repository`` writes out of a clone. All ``None`` means
#: nothing was read, which is the unmeasured state rule 4 requires a failed
#: clone to leave.
REPOSITORY_DERIVED_FIELDS = (
    "last_updated",
    "maintainer_count",
    "has_tests",
    "has_ci",
    "has_contribution_guidelines",
)


@pytest.fixture
def contained_temp_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[None]:
    """Keep the temp dirs ``clone_repo`` creates inside the test's own tmp_path.

    ``clone_repo`` calls ``tempfile.mkdtemp`` before it shells out to git, so a
    test that drives it leaves directories in the real temp dir otherwise.
    """
    monkeypatch.setattr(utils.tempfile, "tempdir", str(tmp_path))
    yield


def _timing_out_git() -> mock.MagicMock:
    """Return a ``subprocess.run`` double that fails the way dotnet/dotnet does.

    Not a stand-in for some other failure: ``TimeoutExpired`` after
    ``CLONE_TIMEOUT_SECONDS`` is verbatim what #282 measured eight times.
    """
    return mock.MagicMock(
        side_effect=subprocess.TimeoutExpired(
            cmd=["git", "clone", "--depth", "1", "--no-tags", DOTNET_MONOREPO],
            timeout=utils.CLONE_TIMEOUT_SECONDS,
        )
    )


def _succeeding_git() -> mock.MagicMock:
    """Return a ``subprocess.run`` double that reports a clean clone."""
    return mock.MagicMock(
        return_value=subprocess.CompletedProcess(
            args=["git", "clone"], returncode=0, stdout="", stderr=""
        )
    )


def _package(name: str, repository_url: str) -> DependencyMetadata:
    """Build one dependency pointing at a repository."""
    return DependencyMetadata(
        name=name, installed_version="1.0.0", repository_url=repository_url
    )


def test_two_packages_sharing_an_unreachable_repository_clone_it_once(
    contained_temp_root: None,
) -> None:
    """The second package resolving to dotnet/dotnet does not pay the timeout.

    Driven through ``collect_repository_signals``, which is the production
    entry point every ecosystem adapter uses, so the assertion is on the real
    call chain rather than on ``clone_repo`` in isolation.
    """
    first = _package("Microsoft.EntityFrameworkCore.SqlServer", DOTNET_MONOREPO)
    second = _package("Microsoft.AspNetCore.Identity.UI", DOTNET_MONOREPO)
    run = _timing_out_git()

    with mock.patch.object(utils.subprocess, "run", run):
        collect_repository_signals(first, DOTNET_MONOREPO, clone_repos=True)
        collect_repository_signals(second, DOTNET_MONOREPO, clone_repos=True)

    assert run.call_count == 1


def test_a_second_repository_is_still_cloned(contained_temp_root: None) -> None:
    """A failure against one repository does not suppress another.

    The paired assertion to the test above. Without it, a cache that answered
    "already failed" for every URL — or a harness that never reached git at
    all — would look identical to a correct one.
    """
    run = _timing_out_git()

    with mock.patch.object(utils.subprocess, "run", run):
        collect_repository_signals(
            _package("Microsoft.EntityFrameworkCore.SqlServer", DOTNET_MONOREPO),
            DOTNET_MONOREPO,
            clone_repos=True,
        )
        collect_repository_signals(
            _package("System.Text.Json", DOTNET_RUNTIME),
            DOTNET_RUNTIME,
            clone_repos=True,
        )

    assert run.call_count == 2


def test_a_cached_failure_leaves_the_same_state_a_fresh_failure_does(
    contained_temp_root: None,
) -> None:
    """AGENTS.md rule 4: the cached answer is unmeasured, never a measured zero.

    The first package's clone genuinely runs and fails; the second's is served
    from the cache. Both records must be the same record, field for field —
    every repository-derived signal absent, no security metrics invented, and
    no field source claimed for a read that never happened.
    """
    fresh = _package("Microsoft.EntityFrameworkCore.SqlServer", DOTNET_MONOREPO)
    cached = _package("Microsoft.AspNetCore.Identity.UI", DOTNET_MONOREPO)

    with mock.patch.object(utils.subprocess, "run", _timing_out_git()):
        collect_repository_signals(fresh, DOTNET_MONOREPO, clone_repos=True)
        collect_repository_signals(cached, DOTNET_MONOREPO, clone_repos=True)

    for field_name in REPOSITORY_DERIVED_FIELDS:
        assert getattr(fresh, field_name) is None, field_name
        assert getattr(cached, field_name) is None, field_name
    assert fresh.security_metrics is None
    assert cached.security_metrics is None
    assert fresh.field_sources == {}
    assert cached.field_sources == {}


def test_a_successful_clone_that_found_nothing_is_not_the_unmeasured_state(
    tmp_path: Path,
) -> None:
    """The other half of rule 4: measured-and-absent stays ``False``.

    An empty tree has no tests and no CI, and that is a finding. If this came
    back ``None`` it would be indistinguishable from the failed clone above,
    which is exactly the collapse #218 fixed.
    """
    repo_dir = tmp_path / "clone-root" / "repo"
    repo_dir.mkdir(parents=True)

    def _succeed(_repo_url: str) -> Tuple[str, str]:
        return str(repo_dir), "repo"

    found_nothing = _package("empty-repo-package", DOTNET_MONOREPO)
    with mock.patch.object(utils, "clone_repo", side_effect=_succeed):
        collect_repository_signals(found_nothing, DOTNET_MONOREPO, clone_repos=True)

    assert found_nothing.has_tests is False
    assert found_nothing.has_ci is False
    assert found_nothing.has_contribution_guidelines is False
    assert found_nothing.security_metrics is not None


def test_two_spellings_of_one_repository_share_one_attempt(
    contained_temp_root: None,
) -> None:
    """The key is the URL git is handed, not the string a registry published.

    Registries spell the same repository several ways — npm publishes the scp
    form, others prefix ``git+``. Keying on the raw string would let one
    repository occupy several cache entries and pay the timeout once per
    spelling.
    """
    scp_form = "git@github.com:dotnet/dotnet.git"
    git_plus_form = "git+https://github.com/dotnet/dotnet.git"
    assert utils.normalize_clone_url(scp_form) == utils.normalize_clone_url(
        git_plus_form
    )
    run = _timing_out_git()

    with mock.patch.object(utils.subprocess, "run", run):
        assert utils.clone_repo(scp_form) is None
        assert utils.clone_repo(git_plus_form) is None

    assert run.call_count == 1


def test_a_successful_clone_is_not_remembered_as_a_failure(
    contained_temp_root: None,
) -> None:
    """Only failures are recorded. A repository that clones stays cloneable."""
    run = _succeeding_git()

    with mock.patch.object(utils.subprocess, "run", run):
        assert utils.clone_repo(DOTNET_MONOREPO) is not None
        assert utils.clone_repo(DOTNET_MONOREPO) is not None

    assert run.call_count == 2


def test_resetting_forgets_recorded_failures(contained_temp_root: None) -> None:
    """The cache is process-scoped state, and it can be emptied on demand.

    ``testing/conftest.py`` empties it around every test; without that, the
    first test to reach a URL would decide the answer for every later one.
    """
    run = _timing_out_git()

    with mock.patch.object(utils.subprocess, "run", run):
        assert utils.clone_repo(DOTNET_MONOREPO) is None
        utils.reset_failed_clone_cache()
        assert utils.clone_repo(DOTNET_MONOREPO) is None

    assert run.call_count == 2


def test_a_failed_clone_leaves_no_temp_directory_behind(
    contained_temp_root: None, tmp_path: Path
) -> None:
    """A clone that times out cleans up its own partial tree.

    ``clone_repo`` creates the destination before it shells out, and a timeout
    against a repository the size of dotnet/dotnet can leave gigabytes of
    partial checkout in the temp dir for the rest of the run. The failure cache
    reduces that from once per package to once per repository; removing the
    tree reduces it to nothing.
    """
    with mock.patch.object(utils.subprocess, "run", _timing_out_git()):
        assert utils.clone_repo(DOTNET_MONOREPO) is None

    assert list(tmp_path.glob("dep-profiler-*")) == []
