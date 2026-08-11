"""A scorecard read that failed is not a read that found nothing (#218).

**These fixtures are ADVERSARIAL and are authored on purpose.** AGENTS.md rule 5
scopes "captured, never authored" to *conformance* fixtures — the ones asserting
we read a registry correctly. Error paths cannot be captured from a cooperating
source, so the failures below are constructed: a ``SECURITY.md`` that is a
directory rather than a file, a ``.github/settings.yml`` likewise, and a
directory that is not a git repository at all. Each makes a real read raise a
real exception from real code; none of them monkeypatches the check under test.

The defect: each of the five checks opened with ``has_X = False`` and returned
that initial value on the exception path and on the no-repository path alike.
``False`` is also the correct answer for a repository that genuinely ships no
security policy, so an unreadable file came back as a confident negative finding
and the scorer counted it as evidence.

Every assertion below is on a **value**, not a count (rule 6): a count cannot
tell "always measured correctly" from "always measured wrong", and the whole
question here is which of ``None`` and ``False`` came back.
"""

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import pytest

from dependency_risk_profiler.analysis_helpers import analyze_repository
from dependency_risk_profiler.models import DependencyMetadata, SecurityMetrics
from dependency_risk_profiler.scorecard.branch_protection import check_branch_protection
from dependency_risk_profiler.scorecard.dependency_update import (
    check_dependency_update_tools,
)
from dependency_risk_profiler.scorecard.maintained import check_maintained_status
from dependency_risk_profiler.scorecard.security_policy import check_security_policy
from dependency_risk_profiler.scorecard.signed_commits import check_signed_commits
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import (
    SIGNAL_SECURITY_POLICY,
    AdvisoryLookupState,
    UnmeasuredReason,
)

CheckResult = Tuple[Optional[bool], Optional[float], List[str]]
Check = Callable[[DependencyMetadata, Optional[str]], CheckResult]

#: The five checks, by the name their issue lines use.
CHECKS: List[Tuple[str, Check]] = [
    ("Security policy", check_security_policy),
    ("Dependency update tools", check_dependency_update_tools),
    ("Signed commits", check_signed_commits),
    ("Branch protection", check_branch_protection),
    ("Maintained status", check_maintained_status),
]

FAILED = UnmeasuredReason.SOURCE_LOOKUP_FAILED.value
NO_REPOSITORY = UnmeasuredReason.SOURCE_REPOSITORY_UNREADABLE.value


def _dependency() -> DependencyMetadata:
    """Return a bare dependency for the checks to write onto."""
    return DependencyMetadata(name="probe", installed_version="1.0.0")


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A real git repository with one commit and no scorecard evidence in it.

    Real rather than simulated: three of the five checks shell out to git, and a
    fake repository would make them fail for the wrong reason and turn this file
    into a test of the fixture.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "probe@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "probe"], check=True)
    (repo / "README.md").write_text("probe\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
    return repo


# --- The no-repository path -------------------------------------------------


@pytest.mark.parametrize("name,check", CHECKS, ids=[c[0] for c in CHECKS])
def test_no_repository_is_unmeasured_not_a_negative_finding(
    name: str, check: Check
) -> None:
    """Nothing was read, so nothing is reported as absent."""
    verdict, score, issues = check(_dependency(), None)

    assert verdict is None, f"{name} answered {verdict!r} without reading anything"
    assert score is None, f"{name} scored {score!r} without reading anything"
    assert any(NO_REPOSITORY in issue for issue in issues), issues


# --- The read-failed path (adversarial fixtures) ----------------------------


def test_unreadable_security_policy_is_unmeasured(git_repo: Path) -> None:
    """ADVERSARIAL: ``SECURITY.md`` exists but cannot be read as a file.

    ``exists()`` says yes and ``open()`` raises, which is the shape of every
    environmental read failure: a permission bit, a broken symlink, a stale
    network mount. Before #218 this reported "No security policy file found".
    """
    (git_repo / "SECURITY.md").mkdir()

    verdict, score, issues = check_security_policy(_dependency(), str(git_repo))

    assert verdict is None
    assert score is None
    assert any(FAILED in issue for issue in issues), issues
    # ``startswith`` rather than equality: #291 appended the locations that
    # were consulted to this line, and an equality check would then pass
    # because the string changed rather than because the read is unmeasured.
    assert not any(
        issue.startswith("No security policy file found") for issue in issues
    ), issues


def test_unreadable_dependabot_config_is_unmeasured(git_repo: Path) -> None:
    """ADVERSARIAL: ``.github/dependabot.yml`` exists but cannot be read."""
    (git_repo / ".github").mkdir()
    (git_repo / ".github" / "dependabot.yml").mkdir()

    verdict, score, issues = check_dependency_update_tools(_dependency(), str(git_repo))

    assert verdict is None
    assert score is None
    assert any(FAILED in issue for issue in issues), issues


def test_unreadable_settings_yml_is_unmeasured_for_branch_protection(
    git_repo: Path,
) -> None:
    """ADVERSARIAL: the issue's own example — an unreadable settings.yml."""
    (git_repo / ".github").mkdir()
    (git_repo / ".github" / "settings.yml").mkdir()

    verdict, score, issues = check_branch_protection(_dependency(), str(git_repo))

    assert verdict is None
    assert score is None
    assert any(FAILED in issue for issue in issues), issues


def test_unreadable_settings_yml_is_unmeasured_for_signed_commits(
    git_repo: Path,
) -> None:
    """ADVERSARIAL: the same file also feeds the signed-commits check."""
    (git_repo / ".github").mkdir()
    (git_repo / ".github" / "settings.yml").mkdir()

    verdict, score, issues = check_signed_commits(_dependency(), str(git_repo))

    assert verdict is None
    assert score is None
    assert any(FAILED in issue for issue in issues), issues


@pytest.mark.parametrize(
    "name,check",
    [
        c
        for c in CHECKS
        if c[0] in {"Signed commits", "Branch protection", "Maintained status"}
    ],
    ids=["Signed commits", "Branch protection", "Maintained status"],
)
def test_failing_git_subprocess_is_unmeasured(
    name: str, check: Check, tmp_path: Path
) -> None:
    """ADVERSARIAL: a directory that is not a git repository.

    The three git-backed checks run ``git log``, ``git config --local`` and
    ``git rev-list`` against it; git exits non-zero and ``check=True`` raises.
    Before #218 that arrived as "does not sign its commits", "does not protect
    its branches" and "is not maintained".
    """
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()

    verdict, score, issues = check(_dependency(), str(not_a_repo))

    assert verdict is None, f"{name} answered {verdict!r} from a failed git read"
    assert score is None, f"{name} scored {score!r} from a failed git read"
    assert any(FAILED in issue for issue in issues), issues


# --- The two unmeasured reasons stay distinct -------------------------------


def test_the_two_unmeasured_reasons_are_not_collapsed(
    git_repo: Path, tmp_path: Path
) -> None:
    """Both answer None; the output still says which None it is.

    Swallowing this distinction is the thing the issue asks not to do, so it is
    asserted directly rather than left to the reader of two other tests.
    """
    (git_repo / "SECURITY.md").mkdir()

    _, _, read_failed = check_security_policy(_dependency(), str(git_repo))
    _, _, no_repository = check_security_policy(_dependency(), None)

    assert any(FAILED in issue for issue in read_failed), read_failed
    assert not any(NO_REPOSITORY in issue for issue in read_failed), read_failed

    assert any(NO_REPOSITORY in issue for issue in no_repository), no_repository
    assert not any(FAILED in issue for issue in no_repository), no_repository


# --- A genuine absence is still a finding -----------------------------------


@pytest.mark.parametrize("name,check", CHECKS, ids=[c[0] for c in CHECKS])
def test_a_read_repository_with_no_evidence_still_answers_false(
    name: str, check: Check, git_repo: Path
) -> None:
    """The fix must not launder real findings into unknowns.

    "We looked in the repository and there is no SECURITY.md" is a measurement
    and the scorer is supposed to act on it.
    """
    verdict, score, _ = check(_dependency(), str(git_repo))

    assert verdict is False, f"{name} lost a real finding to unmeasured"
    assert score is not None, f"{name} withheld a score it actually computed"


def test_a_present_security_policy_still_answers_true(git_repo: Path) -> None:
    """The positive direction is unaffected too."""
    (git_repo / "SECURITY.md").write_text(
        "# Security Policy\n\n## Reporting a Vulnerability\n\nEmail security@x.invalid.\n"
    )

    verdict, score, _ = check_security_policy(_dependency(), str(git_repo))

    assert verdict is True
    assert score is not None and score > 0.0


# --- The write onto the model -----------------------------------------------


def test_analyze_repository_writes_findings_and_withholds_non_findings(
    tmp_path: Path,
) -> None:
    """ADVERSARIAL: a non-git directory, read end to end through the helper.

    The two file-only checks succeed and record a measured ``False``; the three
    git-backed checks fail and record nothing at all. Both halves are asserted
    in one test because the point is that they sit side by side on the same
    model: the guard has to let findings through, not just block everything.
    """
    plain = tmp_path / "plain"
    plain.mkdir()
    dependency = _dependency()

    analyze_repository(dependency, str(plain))

    metrics = dependency.security_metrics
    assert metrics is not None
    assert metrics.has_security_policy is False
    assert metrics.has_dependency_update_tools is False
    assert metrics.has_signed_commits is None
    assert metrics.has_branch_protection is None
    assert metrics.is_maintained is None


def test_analyze_repository_records_all_five_on_a_readable_repository(
    git_repo: Path,
) -> None:
    """The guard is not a blanket refusal: a readable repository records five."""
    dependency = _dependency()

    analyze_repository(dependency, str(git_repo))

    metrics = dependency.security_metrics
    assert metrics is not None
    assert metrics.has_security_policy is False
    assert metrics.has_dependency_update_tools is False
    assert metrics.has_signed_commits is False
    assert metrics.has_branch_protection is False
    assert metrics.is_maintained is False


# --- The score itself (#74) --------------------------------------------------


def _stale(policy: Optional[bool], *, with_metrics: bool = True) -> DependencyMetadata:
    """A dependency stale enough that the denominator is observable.

    Two risky signals and one clean one. Without the clean one every measured
    signal scores 1.0, the weighted mean is 1.0 whatever is in the
    denominator, and the three cases below come out numerically identical —
    the test would then pass whatever the scorer did. The clean signal is a
    completed advisory lookup that found nothing, which is a measurement
    rather than the fabricated zero an unrecorded lookup used to supply
    (#321).
    """
    dependency = DependencyMetadata(
        name="probe",
        installed_version="1.0.0",
        latest_version="9.9.9",
        last_updated=datetime.now(timezone.utc) - timedelta(days=1500),
    )
    dependency.record_advisory_lookup(
        AdvisoryLookupState.COMPLETE, sources_unavailable=()
    )
    if with_metrics:
        dependency.security_metrics = SecurityMetrics()
        dependency.security_metrics.has_security_policy = policy
    return dependency


def test_an_unmeasured_signal_leaves_both_numerator_and_denominator() -> None:
    """#74: unmeasured is renormalized away, not scored as zero.

    Three-way, on values. If ``None`` were dropped from the numerator alone it
    would score like a repository that *has* a policy; if it were read as a
    negative finding it would score like one that lacks it. It does neither: it
    scores exactly as though the signal were not in the table.
    """
    scorer = RiskScorer()

    unmeasured = scorer.score_dependency(_stale(None))
    absent = scorer.score_dependency(_stale(None, with_metrics=False))
    finding = scorer.score_dependency(_stale(False))
    clean = scorer.score_dependency(_stale(True))

    assert unmeasured.total_score == absent.total_score
    assert unmeasured.total_score != finding.total_score
    assert unmeasured.total_score != clean.total_score
    assert clean.total_score < unmeasured.total_score < finding.total_score

    assert unmeasured.security_policy_score is None
    assert finding.security_policy_score == 1.0
    assert clean.security_policy_score == 0.0

    assert SIGNAL_SECURITY_POLICY in unmeasured.unknown_signals
    assert SIGNAL_SECURITY_POLICY not in finding.unknown_signals
    assert SIGNAL_SECURITY_POLICY not in clean.unknown_signals


def test_an_unmeasured_signal_is_not_reported_as_a_risk_factor() -> None:
    """The last mile: None must not print as a finding.

    A ``None`` that reaches the report and renders as "Missing security policy"
    reproduces the defect at the point the user actually reads.
    """
    scorer = RiskScorer()

    unmeasured = scorer.score_dependency(_stale(None))
    finding = scorer.score_dependency(_stale(False))

    assert not any("security policy" in factor.lower() for factor in unmeasured.factors)
    assert any("Missing security policy" == factor for factor in finding.factors)
