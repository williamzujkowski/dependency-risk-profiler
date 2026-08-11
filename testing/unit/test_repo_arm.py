"""Tests for the repository arm's stages 2-4.

Three things are worth a test here and the rest is arithmetic the runners
report anyway:

* **The clone hardening**, because §10's ``--`` separator is the difference
  between a clone and remote code execution, and a missing separator looks
  exactly like a working clone until someone points a hostile URL at it.
* **The parse rejection**, because ``repo.git#main`` is the case that
  distinguishes 2,066 packages from 2,109 and *unparseable* from *deleted*.
* **The negative control**, because the previous study died of a control that
  preserved its labels, and a control nobody tests is a control nobody has.
"""

from __future__ import annotations

from pathlib import Path

from repo_arm.clone import clone_argv, clone_directory
from repo_arm.control import download_bins, mean_within_bin_auc, within_bin_permutation
from repo_arm.resolve import GITHUB, OTHER_HOST, UNDECLARED, UNPARSEABLE
from repo_arm.signals_at_t import _has_path, _has_tests


class TestCloneHardening:
    """§10's fixed defences, asserted rather than assumed."""

    def test_url_follows_a_double_dash_separator(self) -> None:
        argv = clone_argv("owner/repo", Path("/tmp/dest"), 1024)
        assert "--" in argv
        url_index = argv.index("https://github.com/owner/repo.git")
        assert argv.index("--") < url_index

    def test_bare_and_no_submodules_and_blobless(self) -> None:
        argv = clone_argv("owner/repo", Path("/tmp/dest"), 1024)
        assert "--bare" in argv
        assert "--no-recurse-submodules" in argv
        assert "--filter=blob:none" in argv

    def test_size_cap_is_applied_before_git_runs(self) -> None:
        argv = clone_argv("owner/repo", Path("/tmp/dest"), 4096)
        assert argv[0] == "/bin/sh"
        assert "ulimit -f" in argv[2]
        assert argv[4] == "4096"
        # git must be exec'd by the shell that took the limit, not beside it.
        assert argv[5] == "git"

    def test_the_url_is_rebuilt_from_the_slug(self) -> None:
        # No byte of registry metadata reaches the command line: the URL is
        # composed from the validated pair.
        argv = clone_argv("owner/repo", Path("/tmp/dest"), 1024)
        assert "https://github.com/owner/repo.git" in argv

    def test_clone_directory_round_trips(self) -> None:
        assert clone_directory(Path("/root"), "own/re_po").name == "own__re_po.git"


class TestDeclarationParsing:
    """The rules that decide who is in the arm."""

    def test_categories(self) -> None:
        from repo_arm.resolve import _mentions_github

        assert _mentions_github("git+https://github.com/a/b.git")
        assert _mentions_github("github:a/b")
        # GitHub Enterprise on someone else's domain is another host.
        assert not _mentions_github("https://github.deutsche-boerse.de/dev/x")

    def test_a_fragment_no_longer_survives_into_the_repository_name(self) -> None:
        """The production parser now drops the committish, so this resolves.

        It used to return ``b.git#main`` — a name GitHub cannot have — and the
        study's own charset rule was what stopped that reaching git. Finding
        that during stage 2 is what surfaced the defect; it is fixed at the
        source now, so the parser resolves the URL rather than the study
        rejecting it.

        The counts in the stage 2-4 record are unaffected: those 43 packages
        were classified UNPARSEABLE, and with the fix they resolve to real
        repositories. That changes future runs, not the recorded one.
        """
        from dependency_risk_profiler.utils import extract_github_repo_info

        from repo_arm.resolve import _REPO

        info = extract_github_repo_info("https://github.com/a/b.git#main")
        assert info == ("a", "b")
        # The study's charset rule is kept as a second line rather than the
        # only one: it now passes what the parser hands it.
        assert _REPO.match(info[1])

    def test_constants_are_distinct(self) -> None:
        assert len({GITHUB, OTHER_HOST, UNDECLARED, UNPARSEABLE}) == 4


class TestTreeMatching:
    """``git ls-tree -r`` flattens directories; the matcher must not."""

    def test_directory_candidate_matches_by_prefix(self) -> None:
        assert _has_path([".github/workflows/ci.yml"], (".github/workflows",))
        assert not _has_path([".github/workflowsX/ci.yml"], (".github/workflows",))

    def test_file_candidate_matches_exactly(self) -> None:
        assert _has_path(["SECURITY.md"], ("SECURITY.md",))
        assert not _has_path(["docs/SECURITY.md"], ("SECURITY.md",))

    def test_tests_are_read_at_the_root_only(self) -> None:
        # Production globs the repository root, so a deep test file is not a
        # root test file and this must score the same signal.
        assert _has_tests(["test/a.js"])
        assert _has_tests(["test_thing.py"])
        assert not _has_tests(["src/pkg/test_thing.py"])
        assert not _has_tests(["README.md"])


class TestNegativeControl:
    """The stage that killed the last study."""

    def test_bins_are_equal_size_and_skip_unmeasured(self) -> None:
        downloads = [None] + list(range(20))
        bins = download_bins(downloads, strata=5)
        assert len(bins) == 5
        assert sum(len(b) for b in bins) == 20
        assert all(index != 0 for b in bins for index in b)

    def test_a_perfect_score_is_destroyed_by_permutation(self) -> None:
        # Labels perfectly ordered by score inside every bin: the observed
        # statistic is 1.0, so a control that does not collapse to ~0.5 is
        # broken.
        n = 200
        scores = [float(i % 40) for i in range(n)]
        labels = [(i % 40) >= 20 for i in range(n)]
        downloads = list(range(n))
        bins = download_bins(downloads, strata=5)
        assert mean_within_bin_auc(scores, labels, bins) == 1.0
        result = within_bin_permutation(scores, labels, bins, rounds=100, seed=7)
        assert 0.47 <= result.mean <= 0.53
        assert result.label_preservation is not None
        # It must genuinely permute: the handover control preserved 0.966.
        assert result.label_preservation < 0.7

    def test_the_control_is_reproducible(self) -> None:
        scores = [float(i) for i in range(100)]
        labels = [i % 3 == 0 for i in range(100)]
        bins = download_bins(list(range(100)), strata=5)
        first = within_bin_permutation(scores, labels, bins, rounds=25, seed=11)
        second = within_bin_permutation(scores, labels, bins, rounds=25, seed=11)
        assert first.mean == second.mean
