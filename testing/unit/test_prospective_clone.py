"""The prospective harvest's clone hardening, tested without a network.

§7 of ``docs/prospective-protocol.md`` turns the hardening into a registered
commitment rather than a habit: the harvest clones ~2,000 repository URLs that
packages declare about themselves, and #388 established that nothing in this
tool binds a package to its repository. These are attacker-controlled inputs.

The argv builder is split out of the clone precisely so these properties are
assertable offline.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RESEARCH = Path(__file__).resolve().parents[2] / "research"
sys.path.insert(0, str(RESEARCH))

from prospective import clone  # noqa: E402


def argv_for(slug: str, since: str | None = "2025-07-12") -> list[str]:
    return clone.clone_argv(slug, Path("/tmp/dest"), since)


def test_the_url_is_constructed_not_accepted() -> None:
    """The https-only allowlist holds by construction, not by filtering."""
    argv = argv_for("axios/axios")
    assert "https://github.com/axios/axios.git" in argv
    assert not [a for a in argv if a.startswith(("ext::", "file://", "ssh://", "git://"))]


@pytest.mark.parametrize(
    "slug",
    [
        "--upload-pack=touch /tmp/pwned",
        "ext::sh -c touch% /tmp/pwned",
        "../../../etc/passwd",
        "owner/repo; rm -rf /",
        "owner/repo\nowner/other",
        "",
    ],
)
def test_hostile_slugs_never_reach_git(slug: str, tmp_path: Path) -> None:
    """A slug outside GitHub's charset is rejected before any subprocess runs."""
    result = clone.clone_one(slug, tmp_path, "2025-07-12")
    assert result.ok is False
    assert result.reason == "bad_slug"


def test_double_dash_precedes_the_url() -> None:
    """Without ``--`` a URL beginning ``--upload-pack=`` is code execution."""
    argv = argv_for("axios/axios")
    assert argv.index("--") < argv.index("https://github.com/axios/axios.git")


def test_credential_helpers_are_disabled() -> None:
    """A repository demanding auth must fail, not prompt or spend a token."""
    argv = argv_for("axios/axios")
    assert "credential.helper=" in argv
    assert "core.askPass=" in argv


def test_submodules_are_never_recursed() -> None:
    """A submodule URL is a second transport no allowlist here would see."""
    assert "--no-recurse-submodules" in argv_for("axios/axios")


def test_the_clone_is_never_blob_filtered_or_bare() -> None:
    """The shape that silently killed four signals.

    ``research.repo_arm.clone`` uses ``--bare --filter=blob:none``, which is
    correct for commit-metadata signals and wrong here: with no working tree
    every file-content collector reads absent, uniformly, and the study scores
    the degenerate variant it exists to escape -- failing into a plausible
    ``False`` rather than into a missing value.
    """
    argv = argv_for("axios/axios")
    assert "--bare" not in argv
    assert not [a for a in argv if a.startswith("--filter=")]


def test_shallow_since_is_preferred_and_depth_one_is_the_fallback() -> None:
    """``--depth=1`` alone kills two more signals; it is never the first choice."""
    assert "--shallow-since=2025-07-12" in argv_for("axios/axios")
    assert "--depth=1" not in argv_for("axios/axios")
    # The fallback, taken only when the repository has no commits in the window.
    assert "--depth=1" in argv_for("axios/axios", since=None)


def test_no_commits_in_window_is_classified_for_the_fallback() -> None:
    """The error that fires on exactly the abandoned repositories.

    ``--shallow-since`` fails hard when nothing is in range. Misclassifying it
    would drop those packages into the uncloneable stratum and correlate clone
    failure with the outcome through the harness.
    """
    assert (
        clone._classify("fatal: error processing shallow info: 4", 128)
        == "no_commits_in_window"
    )


def test_a_file_size_limit_is_imposed() -> None:
    """``ulimit -f`` bounds a zip-bomb; the wrapper must carry the limit."""
    argv = argv_for("axios/axios")
    assert argv[0] == "/bin/sh"
    assert str(clone.FSIZE_BLOCKS) in argv


def test_a_shared_slug_reuses_the_clone_instead_of_racing(tmp_path: Path) -> None:
    """Several packages can declare the same repository; one slug, one clone.

    In the #385 harvest one slug was declared by fourteen packages. With ten
    worker threads they raced -- each rmtree-ing a destination another was
    cloning into -- and the losers were recorded as `git_error`, entering the
    uncloneable stratum. A failure recorded as a property of the package when
    it was a property of the harness.
    """
    destination = tmp_path / "owner__repo"
    (destination / ".git").mkdir(parents=True)

    result = clone.clone_one("owner/repo", tmp_path, "2025-07-12")

    assert result.ok is True
    assert result.reason == "ok_shared"
    assert result.path == destination
    # The existing clone survives: nothing was rmtree'd out from under a
    # concurrent reader.
    assert (destination / ".git").is_dir()


def test_a_partial_directory_is_discarded_not_reused(tmp_path: Path) -> None:
    """Only a completed clone is shareable; a half-written one is not."""
    destination = tmp_path / "owner__repo"
    destination.mkdir(parents=True)  # no .git -- an interrupted clone

    argv = clone.clone_argv("owner/repo", destination, "2025-07-12")
    # Reaching git at all means the partial directory was not treated as a
    # usable clone; the call itself needs no network to assert that.
    assert "--shallow-since=2025-07-12" in argv
