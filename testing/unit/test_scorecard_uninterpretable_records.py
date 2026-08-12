"""A record we could not interpret is not a record that measured zero (#236).

**These fixtures are ADVERSARIAL and are authored on purpose.** AGENTS.md rule 5
scopes "captured, never authored" to *conformance* fixtures. Error paths and
hostile payloads cannot be captured from a cooperating source, so everything
here is constructed: a tag object carrying a signature block that is not a
signature, a repository configured to reach for a ``gpg`` that does not exist, a
``renovate.json`` that is not JSON, a directory with its execute bit removed.

Where real ``git`` can produce the hostile record, it does — no monkeypatching.
Three of these records real ``git`` **cannot** produce, and that is itself a
finding worth writing down:

* ``git log --pretty=format:%H %G?`` always emits ``<40 hex> <one letter>``, and
  every letter it can emit is in ``_COMMIT_STATUS_BUCKETS``. The old
  ``except ValueError: no_signature_commits += 1`` was therefore *latent* rather
  than actively wrong today.
* ``git rev-list --count`` prints a decimal or exits non-zero.
* ``git for-each-ref --format=%(creatordate:iso)`` prints a parseable date even
  for a tag object whose ``tagger`` line has a deliberately corrupt date — git
  falls back to the epoch (checked, with ``hash-object --literally``).

For those three the *binary* is substituted rather than the module: a ``git``
shim earlier on ``PATH``. The code under test is untouched and really runs a
real subprocess against real output it cannot interpret, which is strictly
closer to production than patching ``subprocess.run`` — and a wrapper named
``git`` on ``PATH`` is a thing that exists in the wild, as is a future git
changing a format.

Every assertion is on a **value**, never a count of issues (rule 6): the whole
question is *which* number came back, and a count cannot tell "measured
correctly" from "measured wrong".
"""

import json
import os
import shutil
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import pytest

from dependency_risk_profiler.analysis_helpers import analyze_repository
from dependency_risk_profiler.models import DependencyMetadata, SecurityMetrics
from dependency_risk_profiler.scorecard.dependency_update import (
    check_dependency_update_tools,
    check_renovate_configuration,
    identify_dependency_update_issues,
)
from dependency_risk_profiler.scorecard.maintained import (
    analyze_commit_frequency,
    analyze_release_cadence,
    check_maintained_status,
)
from dependency_risk_profiler.scorecard.signed_commits import (
    check_recent_commit_signature_status,
    check_release_signature_status,
    check_signed_commits,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from dependency_risk_profiler.signals import AdvisoryLookupState, UnmeasuredReason

FAILED = UnmeasuredReason.SOURCE_LOOKUP_FAILED.value

#: A signature block that is not a signature. ``git tag -v`` will hand it to
#: gpg, which is what makes the gpg-absent case below reachable at all.
_FAKE_SIGNATURE = (
    "-----BEGIN PGP SIGNATURE-----\n"
    "\n"
    "notarealsignature\n"
    "-----END PGP SIGNATURE-----\n"
)


def _dependency() -> DependencyMetadata:
    """Return a bare dependency for the checks to write onto."""
    return DependencyMetadata(name="probe", installed_version="1.0.0")


def _git(repo: Path, *args: str) -> str:
    """Run git in ``repo`` and return its stdout."""
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A real git repository with one unsigned commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "probe@example.invalid")
    _git(repo, "config", "user.name", "probe")
    # Pinned, not assumed. A contributor with ``commit.gpgsign = true`` in their
    # global config signs this fixture's commit, and ``%G?`` then answers ``U``
    # rather than ``N`` — which would make the measured-negative assertions
    # below pass or fail depending on whose laptop ran them.
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "tag.gpgsign", "false")
    (repo / "README.md").write_text("probe\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial")
    return repo


def _write_fake_signed_tag(repo: Path, name: str) -> None:
    """Create a tag object whose signature block gpg will be asked to check.

    ADVERSARIAL: authored, because no cooperating repository ships one. The tag
    is a genuine git object written by ``git hash-object``; only its signature
    is nonsense, which is exactly the shape of "a tag we cannot verify".
    """
    commit = _git(repo, "rev-parse", "HEAD").strip()
    payload = (
        f"object {commit}\n"
        "type commit\n"
        f"tag {name}\n"
        "tagger probe <probe@example.invalid> 1700000000 +0000\n"
        "\n"
        "message\n"
        f"{_FAKE_SIGNATURE}"
    )
    oid = subprocess.run(
        ["git", "-C", str(repo), "hash-object", "-t", "tag", "-w", "--stdin"],
        input=payload,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _git(repo, "update-ref", f"refs/tags/{name}", oid)


def _break_gpg(repo: Path) -> None:
    """Point this repository's tag verification at a gpg that does not exist.

    A real, local, reversible failure: ``git tag -v`` really tries to exec the
    program and really fails. This is the issue's "a gpg that is absent".
    """
    _git(repo, "config", "gpg.program", str(repo / "no-such-gpg"))


def _git_shim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **stdout: str) -> None:
    """Put a ``git`` earlier on PATH that answers named subcommands verbatim.

    Args:
        tmp_path: Where to put the shim.
        monkeypatch: Used only to prepend to ``PATH`` — the environment, not the
            code under test.
        stdout: Subcommand (``git``'s first argument, with ``-`` written as
            ``_``) to the stdout it should print. Anything not named is handed
            to the real git.
    """
    real_git = shutil.which("git")
    assert real_git is not None, "these tests need git"

    bin_dir = tmp_path / "shim-bin"
    bin_dir.mkdir()

    lines = ["#!/bin/sh"]
    for index, (subcommand, payload) in enumerate(stdout.items()):
        payload_file = bin_dir / f"payload{index}"
        payload_file.write_text(payload)
        lines.append(f'if [ "$1" = "{subcommand.replace("_", "-")}" ]; then')
        lines.append(f'  cat "{payload_file}"')
        lines.append("  exit 0")
        lines.append("fi")
    lines.append(f'exec "{real_git}" "$@"')

    shim = bin_dir / "git"
    shim.write_text("\n".join(lines) + "\n")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")


# --- Commit signature records ------------------------------------------------


def test_uninterpretable_commit_lines_leave_the_signing_rate_alone(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADVERSARIAL: one readable commit line and two git cannot be read from.

    The old code answered ``no_signature_commits = 3`` here, on the strength of
    a comment reading "If we can't parse the output, assume no signature". The
    two records nobody could interpret are now out of the numerator *and* the
    denominator — #74's rule for whole signals, applied per record — so the rate
    is one signed commit out of the one commit that was actually read.
    """
    _git_shim(
        tmp_path,
        monkeypatch,
        log="a" * 40 + " G\n" + "b" * 40 + " ?\n" + "c" * 40 + "\n",
    )

    result = check_recent_commit_signature_status(str(git_repo))

    assert result["total_commits"] == 1
    assert result["verified_commits"] == 1
    assert result["no_signature_commits"] == 0
    assert result["unverified_commits"] == 0
    assert result["uninterpretable_commits"] == 2


def test_wholly_uninterpretable_commit_output_is_a_failed_read(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADVERSARIAL: nothing left to take a rate over, so nothing is answered."""
    _git_shim(tmp_path, monkeypatch, log="a" * 40 + " ?\n" + "b" * 40 + " ?\n")

    verdict, score, issues = check_signed_commits(_dependency(), str(git_repo))

    assert verdict is None
    assert score is None
    assert any(FAILED in issue for issue in issues), issues


def test_a_genuinely_unsigned_commit_is_still_a_measured_negative(
    git_repo: Path,
) -> None:
    """The opposite direction: a real finding must not become an unknown."""
    result = check_recent_commit_signature_status(str(git_repo))

    assert result["total_commits"] == 1
    assert result["no_signature_commits"] == 1
    assert result["verified_commits"] == 0
    assert result["uninterpretable_commits"] == 0


# --- Release tag signature records (real git throughout) ---------------------


def test_a_gpg_that_cannot_run_is_not_an_unsigned_tag(git_repo: Path) -> None:
    """ADVERSARIAL, and entirely real: git execs a gpg that is not there.

    The issue's example. ``git tag -v`` prints ``fatal: cannot exec ...`` and
    exits 1, which the old trailing ``else`` counted as ``no_signature_tags``:
    an absent gpg, an unopenable keyring and a genuinely unsigned tag were one
    answer, and it was the one that lowers the score.
    """
    _write_fake_signed_tag(git_repo, "v1.0.0")
    _break_gpg(git_repo)

    with pytest.raises(ValueError):
        check_release_signature_status(str(git_repo))


def test_an_unverifiable_tag_is_excluded_and_the_rest_still_measured(
    git_repo: Path,
) -> None:
    """ADVERSARIAL: one unsigned tag git can read, one it cannot verify.

    The partial measurement the ``AdvisoryLookupState.PARTIAL`` precedent
    allows: the signing rate is taken over the tag that was actually verified,
    the other is reported as excluded, and neither is invented.
    """
    _git(git_repo, "tag", "-a", "v1.0.0", "-m", "release")
    _write_fake_signed_tag(git_repo, "v2.0.0")
    _break_gpg(git_repo)

    result = check_release_signature_status(str(git_repo))

    assert result["total_tags"] == 1
    assert result["no_signature_tags"] == 1
    assert result["verified_tags"] == 0
    assert result["unverified_tags"] == 0
    assert result["uninterpretable_tags"] == 1

    _, _, issues = check_signed_commits(_dependency(), str(git_repo))
    assert any("could not be verified either way" in issue for issue in issues), issues


def test_an_unsigned_annotated_tag_is_still_a_measured_negative(
    git_repo: Path,
) -> None:
    """The opposite direction: ``error: no signature found`` is a finding."""
    _git(git_repo, "tag", "-a", "v1.0.0", "-m", "release")

    result = check_release_signature_status(str(git_repo))

    assert result["total_tags"] == 1
    assert result["no_signature_tags"] == 1
    assert result["uninterpretable_tags"] == 0


def test_a_lightweight_tag_is_still_a_measured_negative(git_repo: Path) -> None:
    """A lightweight tag has no object that could carry a signature.

    ``git tag -v`` answers ``cannot verify a non-tag object of type commit``.
    That establishes "this release is not signed" rather than failing to
    establish anything, and treating it as uninterpretable would unmeasure every
    repository that tags without ``-a`` — most of them.
    """
    _git(git_repo, "tag", "v1.0.0")

    result = check_release_signature_status(str(git_repo))

    assert result["total_tags"] == 1
    assert result["no_signature_tags"] == 1
    assert result["uninterpretable_tags"] == 0


# --- Renovate configuration contents -----------------------------------------


def test_an_unparseable_renovate_config_leaves_its_contents_unmeasured(
    git_repo: Path,
) -> None:
    """ADVERSARIAL: a ``renovate.json`` that is not JSON.

    ``has_renovate`` came from ``exists()`` and stands. ``package_managers``
    came from bytes nobody could interpret and is None, not ``[]`` — the two
    used to be the same empty list, which is how a file that never parsed
    produced a finding about its contents.
    """
    (git_repo / "renovate.json").write_text('{"packageRules": [ this is not json')

    result = check_renovate_configuration(str(git_repo))

    assert result["has_renovate"] is True
    assert result["package_managers"] is None


def test_an_unparseable_renovate_config_reports_a_read_failure_not_a_finding(
    git_repo: Path,
) -> None:
    """The finding the issue names, gone; the reason, present."""
    (git_repo / "renovate.json").write_text("not json at all")

    _, _, issues = check_dependency_update_tools(_dependency(), str(git_repo))

    assert not any(
        "package managers not clearly defined" in issue for issue in issues
    ), issues
    assert any(FAILED in issue for issue in issues), issues


def test_an_unparseable_renovate_config_still_measures_the_tool_itself(
    git_repo: Path,
) -> None:
    """A confirmed "this project runs Renovate" is not lost to an unread bonus."""
    (git_repo / "renovate.json").write_text("not json at all")

    verdict, score, _ = check_dependency_update_tools(_dependency(), str(git_repo))

    assert verdict is True
    assert score == pytest.approx(0.7)


def test_a_parsed_renovate_config_with_no_managers_is_still_a_finding(
    git_repo: Path,
) -> None:
    """The opposite direction: ``[]`` is a measurement and keeps its finding."""
    (git_repo / "renovate.json").write_text(json.dumps({"packageRules": []}))

    result = check_renovate_configuration(str(git_repo))
    assert result["package_managers"] == []

    issues = identify_dependency_update_issues(
        {"has_dependabot": False, "configuration_type": None, "ecosystems_covered": []},
        result,
        {"has_pyup": False, "configuration_type": None},
        {"has_update_actions": False, "update_workflows": []},
    )
    assert any(
        "package managers not clearly defined" in issue for issue in issues
    ), issues


def test_a_parsed_renovate_config_reports_the_managers_it_names(
    git_repo: Path,
) -> None:
    """And the positive direction still reads the file it can read."""
    (git_repo / "renovate.json").write_text(
        json.dumps({"packageRules": [{"matchManagers": ["pip", "npm"]}]})
    )

    result = check_renovate_configuration(str(git_repo))

    assert result["package_managers"] == ["npm", "pip"]


# --- Commit cadence and release cadence --------------------------------------


def test_a_month_git_could_not_count_is_not_a_month_with_no_commits(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADVERSARIAL: ``git rev-list --count`` answers with something else.

    The old handler appended a zero, and that zero went into the average, the
    trend and the stability figure as though someone had observed a quiet month.
    """
    _git_shim(tmp_path, monkeypatch, rev_list="not-a-count\n")

    with pytest.raises(ValueError, match="not a commit count"):
        analyze_commit_frequency(str(git_repo))


def test_a_genuinely_quiet_month_still_counts_as_zero(git_repo: Path) -> None:
    """The opposite direction: a real zero is a measurement and stays one."""
    result = analyze_commit_frequency(str(git_repo), months=12)

    # One commit, made today, across twelve monthly buckets.
    assert result["average_monthly_commits"] == pytest.approx(1 / 12)


def test_a_tag_date_git_emitted_in_an_unexpected_format_is_not_dropped(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADVERSARIAL: one readable tag date and one that is not a date.

    Dropping the unreadable one would merge the two intervals either side of it
    into one release interval that never happened; dropping all of them made the
    project read as never having released.
    """
    _git_shim(
        tmp_path,
        monkeypatch,
        for_each_ref="2026-07-30 10:29:33 +0000\nsometime last spring\n",
    )

    with pytest.raises(ValueError, match="not a date this code can read"):
        analyze_release_cadence(str(git_repo))


def test_a_failed_tag_read_with_no_fallback_is_not_an_empty_cadence(
    tmp_path: Path,
) -> None:
    """ADVERSARIAL, and entirely real: a directory that is not a git repository.

    ``git for-each-ref`` exits non-zero, ``check=True`` raises, and the old
    handler logged at DEBUG and returned ``{}`` — the same empty dictionary a
    project that has never tagged a release produces.
    """
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()

    with pytest.raises(subprocess.SubprocessError):
        analyze_release_cadence(str(not_a_repo))


def test_a_repository_that_has_never_tagged_still_reads_as_empty(
    git_repo: Path,
) -> None:
    """The opposite direction: a successful read that found no tags."""
    assert analyze_release_cadence(str(git_repo)) == {}


def test_a_failed_tag_read_unmeasures_the_maintained_signal(tmp_path: Path) -> None:
    """End to end: the failure arrives as unmeasured, with its reason."""
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()

    verdict, score, issues = check_maintained_status(_dependency(), str(not_a_repo))

    assert verdict is None
    assert score is None
    assert any(FAILED in issue for issue in issues), issues


# --- analyze_repository: one failed read does not discard the other eight -----


@pytest.fixture
def unreadable_docs_dir(git_repo: Path) -> Iterator[Path]:
    """ADVERSARIAL, and entirely real: ``docs/`` with its execute bit off.

    ``check_health_indicators`` probes ``docs/CONTRIBUTING.md`` with
    ``Path.exists()``, which re-raises ``EACCES`` rather than answering False —
    ``pathlib`` only swallows ENOENT, ENOTDIR, EBADF, ELOOP and EINVAL, checked
    rather than assumed. So this is a genuine ``PermissionError`` out of real
    code, not a patched one.

    ``docs/`` rather than the issue's ``.github/`` on purpose: every one of the
    five scorecard checks reads ``.github/`` too, so that fixture cannot tell
    "aborted before the checks ran" from "the checks ran and each failed on its
    own" — both come back all-None. ``docs/`` is read by four of the nine
    signals here and by none of the other five, which is the split this test
    needs.
    """
    docs = git_repo / "docs"
    docs.mkdir()
    (docs / "CONTRIBUTING.md").write_text("contribute\n")
    docs.chmod(0o000)
    try:
        yield git_repo
    finally:
        docs.chmod(stat.S_IRWXU)


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores the permission bits this fixture relies on",
)
def test_one_unreadable_path_does_not_discard_the_signals_that_read(
    unreadable_docs_dir: Path,
) -> None:
    """The whole of category 2 of #236, on values.

    Before this change the ``PermissionError`` aborted ``analyze_repository``
    before any scorecard check ran, so ``security_metrics`` came back None
    *entirely* — six signals lost to one directory, and the only trace was a
    line at ERROR. Worse, the result was indistinguishable from a repository
    that was wholly unreadable, which is the distinction #218 exists to make:
    the #218 evidence run hit exactly this and read as the fix working.

    Both halves are asserted together because the point is that they sit side by
    side. Isolation that unmeasured everything would pass half of this test.
    """
    dependency = _dependency()

    analyze_repository(dependency, str(unreadable_docs_dir))

    metrics = dependency.security_metrics
    assert metrics is not None, "one unreadable directory discarded all five checks"

    # The signals that read ``docs/``: unmeasured, by construction.
    assert dependency.has_tests is None
    assert dependency.has_ci is None
    assert dependency.has_contribution_guidelines is None
    assert metrics.has_security_policy is None
    assert metrics.has_branch_protection is None
    assert metrics.is_maintained is None

    # The ones that do not: measured, and still on the model.
    assert dependency.maintainer_count == 1
    assert metrics.has_dependency_update_tools is False
    assert metrics.has_signed_commits is False


# --- #74 for every signal this change can leave unmeasured -------------------

# `has_signed_commits` is deliberately absent since #339 retired the signal
# from the weighted set. Unmeasuring a weightless signal renormalizes nothing
# and the score is identical either way, so parameterising it here would
# assert that a number changes when by construction it cannot.
_SECURITY_METRIC_FIELDS: List[str] = [
    "has_dependency_update_tools",
    "is_maintained",
]


def _with_metric(field: str, value: Optional[bool]) -> DependencyMetadata:
    """A dependency carrying exactly one security-metrics answer.

    Two risky signals and one clean one, so the denominator is observable:
    with every measured signal scoring 1.0 the three cases below come out
    numerically identical and the test passes whatever the scorer does. The
    clean signal is a completed advisory lookup that found nothing, which is a
    measurement rather than the fabricated zero an unrecorded lookup used to
    supply (#321).
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
    dependency.security_metrics = SecurityMetrics()
    setattr(dependency.security_metrics, field, value)
    return dependency


@pytest.mark.parametrize("field", _SECURITY_METRIC_FIELDS)
def test_every_signal_this_change_can_unmeasure_is_renormalized_away(
    field: str,
) -> None:
    """#74, checked for the signals #236 newly routes to unmeasured.

    The #218 suite checks this for the security-policy signal only. Each of the
    handlers fixed here can now leave a *different* signal unmeasured, and a
    renormalization that holds for one signal is not evidence it holds for the
    next, so each is asserted on its own.
    """
    scorer = RiskScorer()

    unmeasured = scorer.score_dependency(_with_metric(field, None))
    finding = scorer.score_dependency(_with_metric(field, False))
    clean = scorer.score_dependency(_with_metric(field, True))

    assert unmeasured.total_score != finding.total_score, field
    assert unmeasured.total_score != clean.total_score, field
    assert clean.total_score < unmeasured.total_score < finding.total_score, field


@pytest.mark.parametrize("field", _SECURITY_METRIC_FIELDS)
def test_an_unmeasured_signal_is_not_reported_as_a_risk_factor(field: str) -> None:
    """And None must not print as a finding at the point the user reads it."""
    scorer = RiskScorer()

    unmeasured = scorer.score_dependency(_with_metric(field, None))
    finding = scorer.score_dependency(_with_metric(field, False))

    assert len(unmeasured.factors) < len(finding.factors), field
    for factor in finding.factors:
        if factor not in unmeasured.factors:
            break
    else:  # pragma: no cover - defensive
        pytest.fail(f"{field}: the measured negative produced no extra factor")


# --- The shim itself is not doing the work -----------------------------------


def test_the_git_shim_delegates_everything_it_does_not_name(
    git_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rule 5's other half: a fixture that quietly answered everything.

    If the shim intercepted more than the one subcommand it names, the tests
    above would be measuring the shim. ``git tag`` is not named, so it must
    still come from real git.
    """
    _git(git_repo, "tag", "-a", "v1.0.0", "-m", "release")
    _git_shim(tmp_path, monkeypatch, log="unused\n")

    result: Dict[str, int] = check_release_signature_status(str(git_repo))

    assert result["total_tags"] == 1
    assert result["no_signature_tags"] == 1
