"""Tests for the repository arm, stages 2-7.

Six things are worth a test here and the rest is arithmetic the runners report
anyway:

* **The clone hardening**, because §10's ``--`` separator is the difference
  between a clone and remote code execution, and a missing separator looks
  exactly like a working clone until someone points a hostile URL at it.
* **The parse rejection**, because ``repo.git#main`` is the case that
  distinguishes 2,066 packages from 2,109 and *unparseable* from *deleted*.
* **The negative control**, because the previous study died of a control that
  preserved its labels, and a control nobody tests is a control nobody has.
* **That the repository block is five signals**, because the sixth is
  unmeasured and a block that grows back to six has reintroduced a leak.
* **That ablation is absence**, because a neutral value substituted for a
  withheld signal scores something nobody measured.
* **The statistics stages 5-7 decide on** — the within-bin estimand is not the
  pooled AUC, the pairing survives the bootstrap, the realised rho comes from
  resamples, and the falsification lines are rules rather than impressions.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import CohortMember
from abandonment_pilot.snapshot import PackageRecord
from abandonment_pilot.stats import Interval
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    SIGNAL_BRANCH_PROTECTION,
    SIGNAL_COMMUNITY_ACTIVITY,
    SIGNAL_COMMUNITY_POPULARITY,
    SIGNAL_SECURITY_POLICY,
    SIGNAL_SIGNED_COMMITS,
    MeasurementState,
)
from repo_arm.arm import REPO_SIGNALS, build_arm_metadata
from repo_arm.clone import clone_argv, clone_directory
from repo_arm.control import download_bins, mean_within_bin_auc, within_bin_permutation
from repo_arm.endpoint import (
    PREREGISTERED_MDE_TABLE,
    PUBLISHED_TABLE_IMPLIED_SE,
    Paired,
    Support,
    _statistic,
    mde_at,
    mde_row_for,
    paired,
)
from repo_arm.resolve import GITHUB, OTHER_HOST, UNDECLARED, UNPARSEABLE
from repo_arm.signals_at_t import RepoSignals, _has_path, _has_tests
from repo_arm.stage6 import clears_line_1
from repo_arm.stage7 import line_3


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


class TestRepositoryBlockIsFive:
    """``community_popularity`` is unmeasured and must not drift back in."""

    def test_the_block_has_five_signals(self) -> None:
        assert len(REPO_SIGNALS) == 5

    def test_community_popularity_is_not_in_the_block(self) -> None:
        # Stage 3 could not reconstruct it without a proxy §4b forbids, and the
        # other two were unevaluable at any past date before the study began. A
        # block that quietly grows back to six is a leak, not a fix.
        assert SIGNAL_COMMUNITY_POPULARITY not in REPO_SIGNALS
        assert SIGNAL_SIGNED_COMMITS not in REPO_SIGNALS
        assert SIGNAL_BRANCH_PROTECTION not in REPO_SIGNALS


def _repo_signals() -> RepoSignals:
    """Return a reconstruction with every component present."""
    return RepoSignals(
        slug="owner/repo",
        head_at_t="abc123",
        has_tests=True,
        has_ci=True,
        has_contribution_guidelines=False,
        has_security_policy=True,
        has_dependency_update_tools=False,
        commit_frequency=12.0,
        is_maintained=True,
        error=None,
    )


def _member_and_record() -> Tuple[CohortMember, PackageRecord]:
    """Return one cohort member and its snapshot record."""
    moment = datetime(2020, 1, 1, tzinfo=timezone.utc)
    record = PackageRecord(
        name="left-pad",
        releases=(("1.0.0", moment),),
        maintainers=((0, ("someone",)),),
        repository=((0, "https://github.com/owner/repo"),),
        license=((0, "MIT"),),
        dep_count=((0, 0),),
        raw_sha256="0" * 64,
    )
    member = CohortMember(
        name="left-pad",
        index_at_t=0,
        last_release_before_t=moment,
        first_release=moment,
        releases_before_t=1,
        abandoned=False,
        maintainers=("someone",),
    )
    return member, record


class TestAblationIsAbsence:
    """A withheld signal must leave the score, not enter it as a neutral value."""

    def test_withholding_a_signal_leaves_its_input_unset(self) -> None:
        member, record = _member_and_record()
        kept = build_arm_metadata(record, member, _repo_signals())
        assert kept.security_metrics is not None
        assert kept.security_metrics.has_security_policy is True

        dropped = build_arm_metadata(
            record,
            member,
            _repo_signals(),
            enabled=REPO_SIGNALS - {SIGNAL_SECURITY_POLICY},
        )
        assert dropped.security_metrics is not None
        # Absence, not a neutral False: a False here would be a confident
        # measurement nobody made, which is the defect #141 shipped.
        assert dropped.security_metrics.has_security_policy is None

    def test_the_scorer_reports_a_withheld_signal_unmeasured(self) -> None:
        member, record = _member_and_record()
        scorer = RiskScorer()
        full = scorer.score_dependency(
            build_arm_metadata(record, member, _repo_signals())
        )
        ablated = scorer.score_dependency(
            build_arm_metadata(
                record,
                member,
                _repo_signals(),
                enabled=REPO_SIGNALS - {SIGNAL_COMMUNITY_ACTIVITY},
            )
        )
        assert (
            full.measurements[SIGNAL_COMMUNITY_ACTIVITY].state
            is MeasurementState.MEASURED
        )
        assert (
            ablated.measurements[SIGNAL_COMMUNITY_ACTIVITY].state
            is MeasurementState.UNMEASURED
        )

    def test_the_default_still_attaches_the_whole_block(self) -> None:
        # Stages 2-4 called this without the parameter and must be unchanged by
        # its arrival.
        member, record = _member_and_record()
        default = build_arm_metadata(record, member, _repo_signals())
        explicit = build_arm_metadata(
            record, member, _repo_signals(), enabled=REPO_SIGNALS
        )
        scorer = RiskScorer()
        assert (
            scorer.score_dependency(default).total_score
            == scorer.score_dependency(explicit).total_score
        )


class TestMinimumDetectableEffect:
    """§12's table is published; the code reproduces it rather than approximating."""

    def test_the_published_rows_are_reproduced(self) -> None:
        # On the SE as published (0.0157, three significant figures) every row
        # lands within 0.0002; on the SE the table itself
        # implies, all four are exact. Both are asserted, because a rounded
        # constant is the boring explanation for a mismatch against a
        # pre-registered number and it should be pinned rather than assumed.
        for _, assumed, published in PREREGISTERED_MDE_TABLE:
            assert assumed is not None
            assert abs(mde_at(assumed) - published) <= 0.0002
            assert round(mde_at(assumed, PUBLISHED_TABLE_IMPLIED_SE), 4) == published

    def test_a_realised_correlation_selects_the_row_at_or_below_it(self) -> None:
        # Reading a higher row than the data supports would quote a smaller MDE
        # than the study earned.
        assert mde_row_for(0.0) == "independent (worst case)"
        assert mde_row_for(0.49) == "independent (worst case)"
        assert mde_row_for(0.5) == "rho = 0.5"
        assert mde_row_for(0.79) == "rho = 0.5"
        assert mde_row_for(0.95) == "rho = 0.9"


def _support(
    scores_a: Sequence[float],
    scores_b: Sequence[float],
    labels: Sequence[bool],
    clusters: Sequence[int],
    bands: Sequence[Optional[int]],
) -> Support:
    """Return a two-arm support for the statistics tests."""
    return Support(
        scores={"a": tuple(scores_a), "b": tuple(scores_b)},
        labels=tuple(labels),
        clusters=tuple(clusters),
        bands=tuple(bands),
    )


class TestWithinStratumStatistic:
    """The estimand is the within-bin mean, and it is not the pooled AUC."""

    def test_the_two_statistics_differ_on_the_same_rows(self) -> None:
        # Two bins. Inside each the score ranks the labels backwards; across
        # bins it tracks them perfectly. Pooled reads a fair predictor,
        # within-bin reads a useless one. That divergence is the confound
        # falsification line 4 exists for, so a statistic that cannot show it
        # is the wrong statistic.
        scores = [0.80, 0.82, 0.84, 0.86, 0.10, 0.12, 0.14, 0.16]
        labels = [True, True, True, False, True, False, False, False]
        support = _support(
            scores,
            scores,
            labels,
            list(range(8)),
            [0, 0, 0, 0, 1, 1, 1, 1],
        )
        assert _statistic(support, "a", True) == 0.0
        assert _statistic(support, "a", False) == 0.5625

    def test_rows_outside_every_bin_are_ignored_by_the_stratified_statistic(
        self,
    ) -> None:
        scores = [0.1, 0.9, 0.5, 0.5]
        labels = [False, True, True, False]
        support = _support(scores, scores, labels, [0, 1, 2, 3], [0, 0, None, None])
        assert _statistic(support, "a", True) == 1.0


def _rows() -> (
    Tuple[List[float], List[float], List[bool], List[int], List[Optional[int]]]
):
    """Return two arms that disagree, with clusters and bins."""
    scores_a = [(index % 17) / 17.0 for index in range(120)]
    scores_b = [(index % 13) / 13.0 for index in range(120)]
    labels = [index % 3 == 0 for index in range(120)]
    clusters = [index // 2 for index in range(120)]
    bands: List[Optional[int]] = [index // 40 for index in range(120)]
    return scores_a, scores_b, labels, clusters, bands


class TestPairedComparison:
    """The pairing has to survive the bootstrap, and rho has to be measured."""

    def test_an_arm_against_itself_is_exactly_zero_and_perfectly_correlated(
        self,
    ) -> None:
        scores_a, _, labels, clusters, bands = _rows()
        support = _support(scores_a, scores_a, labels, clusters, bands)
        result = paired(support, "a", "b", True)
        assert result.delta == 0.0
        assert result.realised_correlation is not None
        assert round(result.realised_correlation, 9) == 1.0

    def test_the_correlation_comes_from_resamples_not_the_point_estimate(
        self,
    ) -> None:
        scores_a, scores_b, labels, clusters, bands = _rows()
        support = _support(scores_a, scores_b, labels, clusters, bands)
        result = paired(support, "a", "b", True)
        # Two genuinely different score vectors cannot be perfectly correlated
        # across resamples; a rho pinned at 1.0 would mean the point estimate
        # had leaked into the draws.
        assert result.realised_correlation is not None
        assert result.realised_correlation < 1.0
        assert result.se_delta is not None
        assert result.se_delta > 0.0

    def test_the_reported_n_carries_its_clustering(self) -> None:
        scores_a, scores_b, labels, clusters, bands = _rows()
        support = _support(scores_a, scores_b, labels, clusters, bands)
        result = paired(support, "a", "b", True)
        assert result.nominal_n == 120
        assert result.effective_clusters == 60
        assert result.positives == 40

    def test_the_paired_se_agrees_with_the_two_marginal_ses(self) -> None:
        scores_a, scores_b, labels, clusters, bands = _rows()
        support = _support(scores_a, scores_b, labels, clusters, bands)
        result = paired(support, "a", "b", True)
        assert result.se_a is not None
        assert result.se_b is not None
        assert result.se_delta is not None
        assert result.realised_correlation is not None
        # This identity is what makes reading §12's MDE at the realised rho
        # legitimate: the published table is built on exactly this
        # decomposition.
        implied = math.sqrt(
            result.se_a**2
            + result.se_b**2
            - 2 * result.realised_correlation * result.se_a * result.se_b
        )
        assert abs(implied - result.se_delta) < 1e-9


def _fake_paired(delta: float, low: float, high: float) -> Paired:
    """Return a comparison carrying only what the falsification rules read."""
    interval = Interval(
        estimate=delta, low=low, high=high, replicates=10, draws=(delta,)
    )
    return Paired(
        arm_a="a",
        arm_b="b",
        stratified=True,
        auc_a=None,
        auc_b=None,
        delta=delta,
        clustered=interval,
        unclustered=interval,
        p_value=None,
        realised_correlation=None,
        se_a=None,
        se_b=None,
        se_delta=None,
        nominal_n=1,
        effective_clusters=1,
        positives=1,
    )


class TestFalsificationRules:
    """The lines are decided by rules, so the rules get tests."""

    def test_line_1_needs_the_bar_and_an_interval_off_zero(self) -> None:
        assert clears_line_1(_fake_paired(0.06, 0.01, 0.11))
        # The bar without the interval is not a result.
        assert not clears_line_1(_fake_paired(0.06, -0.01, 0.13))
        # The interval without the bar is a precisely-measured irrelevance.
        assert not clears_line_1(_fake_paired(0.02, 0.01, 0.03))

    def test_line_3_is_not_evaluable_where_the_composite_shows_nothing(self) -> None:
        composite = _fake_paired(0.008, -0.12, 0.11)
        rows = {
            "community_activity": (
                _fake_paired(0.05, 0.01, 0.09),
                _fake_paired(0.05, 0.01, 0.09),
            )
        }
        verdict = line_3(composite, rows)
        # Shares of six and minus five are an artefact of a denominator near
        # zero, not a signal carrying an effect that does not exist.
        assert verdict["evaluable"] is False
        assert verdict["fired"] is False
        assert verdict["carriers_ignored_because_not_evaluable"] == [
            "community_activity"
        ]

    def test_line_3_fires_when_one_signal_both_supplies_and_removes_it(self) -> None:
        composite = _fake_paired(0.06, 0.01, 0.11)
        rows = {
            "community_activity": (
                _fake_paired(0.06, 0.01, 0.11),
                _fake_paired(0.06, 0.01, 0.11),
            ),
            "security_policy": (
                _fake_paired(0.0, -0.01, 0.01),
                _fake_paired(0.0, -0.01, 0.01),
            ),
        }
        verdict = line_3(composite, rows)
        assert verdict["evaluable"] is True
        assert verdict["fired"] is True
        assert verdict["carriers"] == ["community_activity"]
