"""A file the forge keeps somewhere else is not a file the repository lacks (#291).

#218 made a scorecard read that *raised* unmeasured. A read that succeeds
against a path the project never uses still returned a confident ``False``, and
the scorer counted it as evidence. Measured on the real Codeberg clone of
``allauth/django-allauth``, which ships ``.gitea/pull_request_template.md`` and
``.gitea/ISSUE_TEMPLATE/``: with ``.github/`` deleted, production reported
``has_pull_request_template=False`` and ``has_issue_templates=False``.

**Fixture provenance.** The layouts under ``testing/fixtures/repo_layouts/`` are
CONFORMANCE fixtures and are **captured** (AGENTS.md rule 5) by
``scripts/capture_repo_layouts.py``, from real clones, at a recorded commit. The
Forgejo-native case is a *reduction* of the captured Codeberg tree — one
directory removed at the call site — not an authored tree. That matters here
more than usual: an authored layout would put the template wherever the author
believes the check looks, which is the assumption under test, and every test
tree in this repository before now had a ``.github/`` directory for exactly that
reason.

The ADVERSARIAL fixtures are in the clearly-labelled section at the bottom and
are authored on purpose: a repository with no metadata anywhere cannot be
captured from a cooperating project, and it is what proves the fix did not
launder real negatives into unknowns.

**The two directions, and why both are asserted.** Widening a path set fixes a
``False`` that should have been ``True``. The opposite mistake — turning a real
absence into an unknown so the scorer stops counting it — is this same defect
pointing the other way, and it is cheaper to commit. So every "found it now"
assertion below is paired with a "still absent, still ``False``" assertion on
the *same tree*, and the checks that genuinely do not generalise (Dependabot on
a Forgejo repository) are asserted to stay measured.

Every assertion is on a **value**, not a count (rule 6).
"""

import subprocess
from pathlib import Path

import pytest
from repo_layouts import layout_paths, load_layout, materialise

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.scorecard.branch_protection import (
    check_branch_protection,
    check_common_branch_protection_indicators,
    check_pull_request_patterns,
)
from dependency_risk_profiler.scorecard.dependency_update import (
    check_dependabot_configuration,
    check_dependency_update_tools,
    check_github_actions_dependency_updates,
    check_renovate_configuration,
)
from dependency_risk_profiler.scorecard.maintained import analyze_issue_activity
from dependency_risk_profiler.scorecard.security_policy import (
    check_security_file_existence,
)
from dependency_risk_profiler.utils import check_health_indicators

CODEBERG = "codeberg-django-allauth"
GITLAB = "gitlab-runner"


def _dependency() -> DependencyMetadata:
    """Return a bare dependency for the end-to-end checks to write onto."""
    return DependencyMetadata(name="probe", installed_version="1.0.0")


# --- The captured layouts say what they claim to say -------------------------


def test_captured_codeberg_layout_is_forge_native() -> None:
    """The fixture is only meaningful if the real repository is what we say.

    Guards against a recapture silently landing a tree with no ``.gitea/`` in
    it, which would leave every assertion below passing for the wrong reason.
    """
    paths = layout_paths(CODEBERG)

    assert ".gitea/pull_request_template.md" in paths
    assert ".gitea/ISSUE_TEMPLATE/issue.md" in paths
    assert ".woodpecker.yaml" in paths
    # The security policy and the Dependabot config live only under .github/,
    # which is what makes this tree able to prove both directions at once.
    assert ".github/SECURITY.md" in paths
    assert ".github/dependabot.yml" in paths
    assert not any(path.startswith(".gitea/SECURITY") for path in paths)
    assert load_layout(CODEBERG)["source_url"] == (
        "https://codeberg.org/allauth/django-allauth.git"
    )


def test_captured_gitlab_layout_is_forge_native() -> None:
    """The GitLab fixture has no ``.github/`` at all, and GitLab's spellings."""
    paths = layout_paths(GITLAB)

    assert not any(path.startswith(".github/") for path in paths)
    assert ".gitlab/CODEOWNERS" in paths
    assert ".gitlab/merge_request_templates/Default.md" in paths
    assert ".gitlab/issue_templates/Default.md" in paths
    assert "CODEOWNERS" not in paths
    assert "docs/CODEOWNERS" not in paths
    # No security policy file, under any name, in any forge folder. This is a
    # captured real negative, and it is what the fix must leave alone.
    assert not any(
        Path(path).name.upper() in {"SECURITY.MD", "SECURITY.TXT"} for path in paths
    )
    assert "security/README.md" not in paths


# --- CONFORMANCE: a Forgejo-native tree ------------------------------------


@pytest.fixture
def forgejo_native(tmp_path: Path) -> Path:
    """The captured Codeberg tree with ``.github/`` removed.

    A reduction of a capture, not an authored tree: every remaining path was
    chosen by ``allauth``. This is the layout #291 was demonstrated on.
    """
    return materialise(CODEBERG, tmp_path / "allauth", without=[".github"])


@pytest.fixture
def gitlab_native(tmp_path: Path) -> Path:
    """The captured GitLab tree, unreduced — it ships no ``.github/`` to remove."""
    return materialise(GITLAB, tmp_path / "runner")


def test_forgejo_native_pull_request_template_is_found(forgejo_native: Path) -> None:
    """``.gitea/pull_request_template.md`` is a pull request template."""
    patterns = check_pull_request_patterns(str(forgejo_native))

    assert patterns["has_pull_request_template"] is True
    assert patterns["uses_pull_requests"] is True


def test_forgejo_native_issue_templates_are_found(forgejo_native: Path) -> None:
    """``.gitea/ISSUE_TEMPLATE/`` is a directory of issue templates."""
    assert analyze_issue_activity(str(forgejo_native))["has_issue_templates"] is True


def test_forgejo_native_woodpecker_config_is_ci(forgejo_native: Path) -> None:
    """Codeberg's own CI counts as CI.

    ``.woodpecker.yaml`` sat in the root of this tree while ``has_ci`` said
    ``False``, because the CI list knew Travis, CircleCI and Jenkins but not
    the CI the forge in the fixture actually runs.
    """
    _, has_ci, _ = check_health_indicators(str(forgejo_native))

    assert has_ci is True


def test_forgejo_native_contributing_guide_is_found(forgejo_native: Path) -> None:
    """``CONTRIBUTING.rst`` is contribution guidance; the list was ``.md``-only."""
    _, _, has_contribution_guidelines = check_health_indicators(str(forgejo_native))

    assert has_contribution_guidelines is True


def test_gitlab_native_merge_request_template_is_a_pull_request_template(
    gitlab_native: Path,
) -> None:
    """GitLab spells it ``merge_request_templates/`` and it is the same concept."""
    patterns = check_pull_request_patterns(str(gitlab_native))

    assert patterns["has_pull_request_template"] is True
    assert patterns["uses_pull_requests"] is True


def test_gitlab_native_codeowners_is_found(gitlab_native: Path) -> None:
    """``.gitlab/CODEOWNERS`` is a CODEOWNERS file.

    This repository keeps no ``CODEOWNERS`` at the root and none in ``docs/``,
    so before the path table there was nowhere left for the check to look.
    """
    indicators = check_common_branch_protection_indicators(str(gitlab_native))

    assert indicators["has_code_owners"] is True


def test_gitlab_native_branch_protection_reaches_the_public_check(
    gitlab_native: Path,
) -> None:
    """End to end, through the function ``analysis_helpers`` actually calls.

    ``has_branch_protection`` is an OR whose third operand is "CODEOWNERS and
    the project uses pull requests". On this tree both come from ``.gitlab/``,
    so the whole signal flipped from a confident ``False`` to ``True`` — and it
    exercises the production wiring, not the sub-readers in isolation.
    """
    verdict, score, _ = check_branch_protection(_dependency(), str(gitlab_native))

    assert verdict is True
    assert score is not None and score > 0.0


# --- CONFORMANCE: the same trees still report their real absences ------------


def test_forgejo_native_security_policy_absence_stays_a_measured_false(
    forgejo_native: Path,
) -> None:
    """``django-allauth`` keeps its policy only in ``.github/``; removed, it is gone.

    Paired deliberately with the template assertions above: the *same* tree
    that gained two ``True`` values keeps this ``False``. Widening a path set
    must not turn an absence into a maybe.
    """
    existence = check_security_file_existence(str(forgejo_native))

    assert existence["has_security_file"] is False
    assert "security_file_path" not in existence


def test_dependabot_absence_on_a_forgejo_tree_stays_a_measured_false(
    forgejo_native: Path,
) -> None:
    """Dependabot is a GitHub service, so its absence elsewhere is a real absence.

    The distinction this asserts, against the line above and against #218: a
    path set with nowhere else to look is not an unmeasurable signal. Forgejo
    does not run Dependabot, "no dependency-update tooling configured" is the
    true answer, and the check must keep saying it rather than going quiet.
    """
    configuration = check_dependabot_configuration(str(forgejo_native))
    verdict, score, issues = check_dependency_update_tools(
        _dependency(), str(forgejo_native)
    )

    assert configuration["has_dependabot"] is False
    assert verdict is False, "a real absence must stay a finding, not become None"
    assert score == 0.0
    assert not any("unmeasured" in issue for issue in issues), issues


def test_gitlab_native_security_policy_absence_stays_a_measured_false(
    gitlab_native: Path,
) -> None:
    """A captured repository that genuinely ships no policy still says so."""
    assert check_security_file_existence(str(gitlab_native))["has_security_file"] is (
        False
    )


def test_the_unreduced_codeberg_tree_still_reads_its_github_metadata(
    tmp_path: Path,
) -> None:
    """Widening the path sets did not cost the GitHub-shaped answers.

    The as-captured tree carries both layouts, and every signal it answered
    before must still be answered.
    """
    tree = materialise(CODEBERG, tmp_path / "allauth")

    assert check_security_file_existence(str(tree))["has_security_file"] is True
    assert check_dependabot_configuration(str(tree))["has_dependabot"] is True
    assert check_pull_request_patterns(str(tree))["has_pull_request_template"] is True
    assert analyze_issue_activity(str(tree))["has_issue_templates"] is True


# --- ADVERSARIAL (authored, on purpose) --------------------------------------
#
# A repository with no metadata at all cannot be captured from a cooperating
# project; rule 5 scopes "captured, never authored" to conformance fixtures and
# requires the adversarial ones to be authored and labelled. These are the ones
# that prove the fix did not launder real negatives.


@pytest.fixture
def bare_repository(tmp_path: Path) -> Path:
    """ADVERSARIAL: a real git repository with one file and no metadata at all.

    Real rather than simulated: three of the five checks shell out to git.
    """
    repo = tmp_path / "bare"
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


def test_a_repository_with_no_metadata_reports_false_not_unmeasured(
    bare_repository: Path,
) -> None:
    """ADVERSARIAL: nothing anywhere is a measured nothing.

    This is the assertion that stops the fix from being applied in the wrong
    direction. Every one of these could be made to "pass" by returning ``None``;
    ``None`` would be a lie, because we looked in every place any forge uses and
    the evidence was not in any of them.
    """
    assert check_pull_request_patterns(str(bare_repository)) == {
        "uses_pull_requests": False,
        "has_pull_request_template": False,
    }
    assert analyze_issue_activity(str(bare_repository))["has_issue_templates"] is False
    assert (
        check_security_file_existence(str(bare_repository))["has_security_file"]
        is False
    )
    assert check_dependabot_configuration(str(bare_repository))["has_dependabot"] is (
        False
    )
    assert check_renovate_configuration(str(bare_repository))["has_renovate"] is False
    assert (
        check_common_branch_protection_indicators(str(bare_repository))[
            "has_code_owners"
        ]
        is False
    )

    has_tests, has_ci, has_contribution_guidelines = check_health_indicators(
        str(bare_repository)
    )
    assert has_tests is False
    assert has_ci is False
    assert has_contribution_guidelines is False


def test_a_repository_with_no_metadata_keeps_a_measured_verdict(
    bare_repository: Path,
) -> None:
    """ADVERSARIAL: the public checks report findings, not silence.

    ``None`` from these means unmeasured, and the scorer drops the signal from
    both numerator and denominator. A repository that ships nothing must not
    win that way.
    """
    update_verdict, update_score, _ = check_dependency_update_tools(
        _dependency(), str(bare_repository)
    )
    protection_verdict, protection_score, _ = check_branch_protection(
        _dependency(), str(bare_repository)
    )

    assert update_verdict is False
    assert update_score == 0.0
    assert protection_verdict is False
    assert protection_score == 0.0


@pytest.mark.parametrize(
    "relative_path",
    [
        ".gitea/pull_request_template.md",
        ".forgejo/PULL_REQUEST_TEMPLATE.md",
        ".gitlab/merge_request_templates/Default.md",
        ".github/PULL_REQUEST_TEMPLATE.md",
        "PULL_REQUEST_TEMPLATE.md",
        "docs/pull_request_template.md",
    ],
)
def test_each_convention_alone_is_enough(tmp_path: Path, relative_path: str) -> None:
    """ADVERSARIAL: one convention at a time, so no hit can mask another.

    Parameterised over the *forges*, not over the path table's contents: each
    of these is a place a real project keeps its template, and each on its own
    has to be sufficient. A single fixture carrying all of them would pass if
    the code only read one.
    """
    repo = tmp_path / "single"
    target = repo / relative_path
    target.parent.mkdir(parents=True)
    target.write_text("## Checklist\n")

    patterns = check_pull_request_patterns(str(repo))

    assert patterns["has_pull_request_template"] is True
    assert patterns["uses_pull_requests"] is True


@pytest.mark.parametrize(
    "relative_path",
    [
        ".gitea/workflows/renovate.yaml",
        ".forgejo/workflows/renovate.yml",
        ".github/workflows/renovate.yml",
    ],
)
def test_each_actions_directory_is_searched_for_update_workflows(
    tmp_path: Path, relative_path: str
) -> None:
    """ADVERSARIAL: Gitea and Forgejo Actions read the same format, elsewhere.

    Also pins the glob: ``.yaml`` is as valid a workflow extension as ``.yml``,
    and the security-workflow reader used to match only the latter.
    """
    repo = tmp_path / "actions"
    target = repo / relative_path
    target.parent.mkdir(parents=True)
    target.write_text("jobs:\n  bump:\n    steps:\n      - run: renovate\n")

    workflows = check_github_actions_dependency_updates(str(repo))

    assert workflows["has_update_actions"] is True
    assert workflows["update_workflows"] == [relative_path]


@pytest.mark.parametrize(
    "relative_path",
    [
        ".gitlab/renovate.json",
        ".github/renovate.json",
        "renovate.jsonc",
        ".renovaterc.json5",
    ],
)
def test_renovate_is_found_wherever_renovate_looks(
    tmp_path: Path, relative_path: str
) -> None:
    """ADVERSARIAL: Renovate runs on all four forges, so its config generalises.

    Unlike Dependabot, which does not, and is asserted above to stay ``False``.
    """
    repo = tmp_path / "renovate"
    target = repo / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}\n")

    assert check_renovate_configuration(str(repo))["has_renovate"] is True


def test_a_negative_finding_names_where_it_looked(bare_repository: Path) -> None:
    """A ``False`` is only attributable if the report says where we looked.

    Before this, "No pull request template found" meant ``.github/`` and did
    not say so, which is how the wrong reading survived review.
    """
    _, _, issues = check_branch_protection(_dependency(), str(bare_repository))
    template_issues = [
        issue for issue in issues if issue.startswith("No pull request template found")
    ]

    assert len(template_issues) == 1, issues
    for convention in (".gitea/", ".forgejo/", ".gitlab/", ".github/"):
        assert convention in template_issues[0], template_issues[0]
