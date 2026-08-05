"""Where each forge keeps repository metadata, in one table (#291).

Every repository-derived signal in this tool is read from a shallow ``git
clone`` — ``pathlib`` existence checks and ``git`` subprocesses, no forge API.
That is what makes the signals portable across hosts. Until this module the
*paths* were not: each check carried its own inline list of GitHub-shaped
literals, so a repository that keeps its metadata where its own forge looks for
it read as a repository that has none.

That is a rule-4 violation of the exact shape #218 fixed one layer down. #218
made a read that *raised* unmeasured; a read that succeeds against a path the
project never uses still returns a confident ``False``, and the scorer counts it
as evidence. Measured on the real Codeberg clone of ``allauth/django-allauth``,
which ships ``.gitea/pull_request_template.md`` and ``.gitea/ISSUE_TEMPLATE/``:
with ``.github/`` removed, ``has_pull_request_template`` and
``has_issue_templates`` both came back ``False``.

**The rule this module implements.** Absence is only a finding if we looked
where the file would actually be. So a concept ("does this project ship a pull
request template") gets one path set spanning every convention that expresses
it, and a ``False`` means the file was in none of them. The scorecard checks
never see the forge they are reading — ``repo_dir`` is a directory — so the
union is not a fallback, it is the answer: an absence across every convention is
a measured absence, which is the honest reading when the forge is unknown.

**Adding paths cannot launder a negative.** A wider path set only ever turns
``False`` into ``True``, and only when a file genuinely exists on disk. Nothing
here converts a real absence into an unknown; the tests assert that direction
explicitly.

**What is deliberately *not* generalised**, because no equivalent exists:

* ``.github/settings.yml`` is the Probot *Settings app* convention. It is a
  GitHub App, not a forge folder, and neither Gitea, Forgejo nor GitLab has an
  in-tree equivalent — branch protection on those forges is project state
  reachable only through their APIs. Widening this path set would mean
  inventing a convention. See :data:`GITHUB_APP_SETTINGS_PATHS`.
* Dependabot is a GitHub service, not a directory layout. Its absence on
  Forgejo is a real absence of dependency-update tooling, not an unmeasured
  one, and the tests assert that against the previous line. Renovate, which
  *does* run on all four forges, is generalised — see
  :data:`RENOVATE_CONFIG_PATHS`.

**Provenance.** Every path below is taken from the forge's own documentation,
read 2026-08-04:

* Forgejo/Gitea issue and pull request templates — the folders searched are
  ``.forgejo``, ``.gitea``, ``.github`` and ``docs``; issue templates live in an
  ``ISSUE_TEMPLATE``/``issue_template`` subdirectory; a pull request template is
  a single file in the folder itself, in six spellings; ``.gitlab`` is
  explicitly *not* searched.
  https://forgejo.org/docs/latest/user/repository/issue-pull-request-templates/
* GitLab description templates — ``.gitlab/issue_templates/`` and
  ``.gitlab/merge_request_templates/``.
  https://docs.gitlab.com/user/project/description_templates/
* GitLab CODEOWNERS — root, ``docs/``, ``.gitlab/``.
  https://docs.gitlab.com/user/project/codeowners/
* Gitea CODEOWNERS — root, ``docs/``, ``.gitea/``.
  https://docs.gitea.com/usage/code-owners
* Gitea Actions reads ``.gitea/workflows`` and ``.github/workflows``; Forgejo
  Actions reads ``.forgejo/workflows`` and falls back through ``.gitea`` to
  ``.github``. https://forgejo.org/docs/latest/user/actions/
* Renovate configuration file names, in search order.
  https://docs.renovatebot.com/configuration-options/
"""

from pathlib import Path
from typing import Iterable, List, Optional, Tuple

#: The forge folders this tool knows how to read, most-specific forge first.
#: Gitea and Forgejo read each other's and GitHub's; GitLab reads only its own.
FORGE_METADATA_DIRS: Tuple[str, ...] = (".github", ".gitea", ".forgejo", ".gitlab")

#: The three folders Forgejo and Gitea search for templates and workflows.
#: ``.gitlab`` is absent on purpose — the Forgejo documentation excludes it, and
#: GitLab's own spellings differ enough that they are listed separately below.
_ACTIONS_STYLE_DIRS: Tuple[str, ...] = (".github", ".gitea", ".forgejo")

#: Directories a project may put a pull request template in, per Forgejo's
#: documented search order. ``docs`` is searched for templates but cannot hold
#: workflows, so it is not in :data:`_ACTIONS_STYLE_DIRS`.
_TEMPLATE_DIRS: Tuple[str, ...] = _ACTIONS_STYLE_DIRS + ("docs",)


def _spellings(stems: Iterable[str], extensions: Iterable[str]) -> Tuple[str, ...]:
    """Return the documented cross-product of file stems and extensions.

    Generated rather than typed out only where the documentation states a
    cross-product. Where a forge uses a different name for the same concept
    (GitLab's ``merge_request_templates``), the path is written literally, so no
    spelling here is inferred from another forge's.

    Args:
        stems: File name stems, without a dot or extension.
        extensions: Extensions, without the leading dot.

    Returns:
        Every ``stem.extension`` combination, stems varying slowest.
    """
    return tuple(f"{stem}.{ext}" for stem in stems for ext in extensions)


_PR_TEMPLATE_FILES = _spellings(
    ("PULL_REQUEST_TEMPLATE", "pull_request_template"), ("md", "yaml", "yml")
)

#: Where a pull request (or merge request) template lives.
#:
#: GitHub additionally honours a ``PULL_REQUEST_TEMPLATE/`` *directory* of
#: several templates; Forgejo and Gitea permit only one file. GitLab has no
#: single-file form at all — it reads a directory under its own folder, with a
#: different name, which is why this is a table and not a prefix substitution.
PULL_REQUEST_TEMPLATE_PATHS: Tuple[str, ...] = (
    tuple(
        f"{directory}/{name}"
        for directory in _TEMPLATE_DIRS
        for name in _PR_TEMPLATE_FILES
    )
    + tuple(f"{directory}/PULL_REQUEST_TEMPLATE" for directory in _TEMPLATE_DIRS)
    + ("PULL_REQUEST_TEMPLATE.md", "pull_request_template.md", "PULL_REQUEST_TEMPLATE")
    + (".gitlab/merge_request_templates",)
)

#: Where issue templates live. Both capitalisations of the Forgejo/Gitea
#: subdirectory, GitHub's legacy single-file form, and GitLab's own directory.
#:
#: ``docs/issue-templates`` predates this table and is kept: removing a path
#: only ever turns a ``True`` into a ``False``, which is the defect this module
#: exists to remove.
ISSUE_TEMPLATE_PATHS: Tuple[str, ...] = (
    tuple(f"{directory}/ISSUE_TEMPLATE" for directory in _TEMPLATE_DIRS)
    + tuple(f"{directory}/issue_template" for directory in _TEMPLATE_DIRS)
    + tuple(
        f"{directory}/{name}"
        for directory in _TEMPLATE_DIRS
        for name in _spellings(
            ("ISSUE_TEMPLATE", "issue_template"), ("md", "yaml", "yml")
        )
    )
    + (".gitlab/issue_templates", "docs/issue-templates")
)

#: Where a CODEOWNERS file lives. GitHub, GitLab and Gitea all read the root and
#: ``docs/``; each also reads its own folder. Forgejo inherits Gitea's search.
CODEOWNERS_PATHS: Tuple[str, ...] = ("CODEOWNERS", "docs/CODEOWNERS") + tuple(
    f"{directory}/CODEOWNERS" for directory in FORGE_METADATA_DIRS
)

#: Where a project records who maintains it.
#:
#: No forge renders these; there is no convention to generalise and none is
#: invented. The forge folders are included because a repository that moved its
#: metadata into one moved all of it, and a file that exists is evidence
#: whether or not the forge displays it.
MAINTAINERS_PATHS: Tuple[str, ...] = (
    "MAINTAINERS",
    "MAINTAINERS.md",
    "OWNERS",
    "docs/MAINTAINERS.md",
) + tuple(f"{directory}/MAINTAINERS.md" for directory in FORGE_METADATA_DIRS)

_SECURITY_FILE_NAMES = ("SECURITY.md", "security.md", "SECURITY.txt", "security.txt")

#: Where a security policy lives.
#:
#: Only GitHub *renders* one, from the root, ``docs/`` or ``.github/``. The
#: forge folders are included for the same reason as :data:`MAINTAINERS_PATHS`:
#: the question is whether the project publishes a policy, and a policy in
#: ``.gitea/SECURITY.md`` is a published policy.
SECURITY_POLICY_PATHS: Tuple[str, ...] = (
    _SECURITY_FILE_NAMES
    + tuple(f"docs/{name}" for name in _SECURITY_FILE_NAMES)
    + tuple(
        f"{directory}/{name}"
        for directory in FORGE_METADATA_DIRS
        for name in _SECURITY_FILE_NAMES
    )
    + ("security/README.md",)
)

#: Directories holding Actions-compatible workflow files. GitLab is absent
#: because it has no workflow directory: its pipeline is the single
#: ``.gitlab-ci.yml`` named in :data:`CI_CONFIG_PATHS`, which is a different
#: file format and is not searched for workflow content.
WORKFLOW_DIRS: Tuple[str, ...] = tuple(
    f"{directory}/workflows" for directory in _ACTIONS_STYLE_DIRS
)

#: The glob patterns a workflow file matches. ``*.y*ml`` covers ``.yml`` and
#: ``.yaml`` alike, which is what every caller wants.
WORKFLOW_GLOB = "*.y*ml"

#: Where CodeQL's analysis workflow lives. CodeQL's runner is a GitHub Action,
#: so this is GitHub-shaped by nature, but a mirrored repository keeps the same
#: file under its own forge's workflow directory.
CODEQL_WORKFLOW_PATHS: Tuple[str, ...] = tuple(
    f"{directory}/{name}"
    for directory in WORKFLOW_DIRS
    for name in ("codeql-analysis.yml", "codeql.yml")
)

#: Where Renovate's configuration lives, in Renovate's own documented search
#: order. Renovate runs against GitHub, GitLab, Gitea and Forgejo, so this
#: genuinely generalises; the ``.gitlab/`` variants are Renovate's, not a
#: GitLab convention.
RENOVATE_CONFIG_PATHS: Tuple[str, ...] = (
    _spellings(("renovate",), ("json", "jsonc", "json5"))
    + tuple(
        f"{directory}/{name}"
        for directory in (".github", ".gitlab")
        for name in _spellings(("renovate",), ("json", "jsonc", "json5"))
    )
    + (".renovaterc", ".renovaterc.json", ".renovaterc.jsonc", ".renovaterc.json5")
)

#: Where Dependabot's configuration lives.
#:
#: **Not generalised, on purpose.** Dependabot is a GitHub service. Forgejo,
#: Gitea and GitLab do not run it, so there is no other place it could be and
#: its absence there is a real absence of that tooling — a measured ``False``,
#: not an unmeasured signal. Widening this would launder a true negative.
DEPENDABOT_CONFIG_PATHS: Tuple[str, ...] = (
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    ".dependabot/config.yml",
    ".dependabot/config.yaml",
)

#: The Probot *Settings app* configuration.
#:
#: **Not generalised, on purpose.** This is a GitHub App's file, not a forge
#: folder: no Gitea, Forgejo or GitLab equivalent exists, because branch
#: protection on those forges is project state behind their APIs and is not
#: expressed in the tree at all. Its absence is read as "this repository does
#: not declare branch protection in-tree", which is a true statement about any
#: tree. Deciding it is *unmeasurable* on a non-GitHub forge needs the forge
#: identity, which no caller of these checks has; see the follow-up filed
#: against #289.
GITHUB_APP_SETTINGS_PATHS: Tuple[str, ...] = (".github/settings.yml",)

#: Non-workflow configuration files that indicate a security or quality tool is
#: wired up. ``.snyk`` and the coverage services are host-independent already;
#: Dependabot is listed here for the same reason it is above.
SECURITY_TOOL_CONFIG_PATHS: Tuple[str, ...] = (
    ".snyk",
    ".dependabot/config.yml",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "codecov.yml",
    ".codeclimate.yml",
    ".coveralls.yml",
    ".sonarcloud.properties",
)

#: Where a project's continuous integration is configured.
#:
#: ``.woodpecker.yaml`` earns its place from the fixture: the Codeberg clone of
#: ``django-allauth`` runs Woodpecker, Codeberg's CI, and reported ``has_ci``
#: as ``False`` with the file sitting in its root. ``bitbucket-pipelines.yml``
#: earns its place from ``utils._CLONEABLE_HOSTS``, which already clones
#: ``bitbucket.org``; ``.drone.yml`` is Drone, the CI most Gitea installations
#: ran before Gitea Actions existed. All three are file names their own
#: projects document, not names inferred from another forge's.
CI_CONFIG_PATHS: Tuple[str, ...] = WORKFLOW_DIRS + (
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    ".travis.yml",
    ".circleci",
    "azure-pipelines.yml",
    "Jenkinsfile",
    "bitbucket-pipelines.yml",
    ".woodpecker.yml",
    ".woodpecker.yaml",
    ".woodpecker",
    ".drone.yml",
)

_CONTRIBUTING_FILE_NAMES = (
    "CONTRIBUTING.md",
    "CONTRIBUTING.rst",
    "CONTRIBUTE.md",
)

#: Where contribution guidelines live. GitHub, GitLab and Gitea all render one
#: from the root, ``docs/`` or their own folder.
CONTRIBUTING_PATHS: Tuple[str, ...] = (
    _CONTRIBUTING_FILE_NAMES
    + tuple(f"docs/{name}" for name in _CONTRIBUTING_FILE_NAMES)
    + tuple(
        f"{directory}/{name}"
        for directory in FORGE_METADATA_DIRS
        for name in _CONTRIBUTING_FILE_NAMES
    )
)


def first_existing(repo_path: Path, paths: Iterable[str]) -> Optional[Path]:
    """Return the first of ``paths`` that exists under ``repo_path``.

    Args:
        repo_path: Root of the cloned repository.
        paths: Repository-relative paths, in preference order.

    Returns:
        The resolved path of the first hit, or ``None`` if none exists. ``None``
        here means "not in any of the places given" — a measured absence,
        provided the caller passed a path set covering every convention.
    """
    for path in paths:
        candidate = repo_path.joinpath(path)
        if candidate.exists():
            return candidate
    return None


def any_exists(repo_path: Path, paths: Iterable[str]) -> bool:
    """Return whether any of ``paths`` exists under ``repo_path``.

    Args:
        repo_path: Root of the cloned repository.
        paths: Repository-relative paths.

    Returns:
        ``True`` if at least one exists.
    """
    return first_existing(repo_path, paths) is not None


def existing_workflow_dirs(repo_path: Path) -> List[Path]:
    """Return every Actions-compatible workflow directory that exists.

    A repository mirrored between forges can carry more than one, so this
    returns all of them rather than the first: reading only ``.github`` on a
    repository whose live workflows moved to ``.forgejo`` is the defect.

    Args:
        repo_path: Root of the cloned repository.

    Returns:
        The existing workflow directories, in :data:`WORKFLOW_DIRS` order.
        Empty when the repository configures no Actions-style CI, which is a
        measured absence.
    """
    found = []
    for relative in WORKFLOW_DIRS:
        candidate = repo_path.joinpath(relative)
        if candidate.is_dir():
            found.append(candidate)
    return found


def locations_phrase(paths: Iterable[str]) -> str:
    """Render the directories a path set covers, for an issue line.

    A ``False`` is only attributable if the output says where we looked, so the
    checks report "no pull request template found in ..." rather than leaving
    the reader to assume it means ``.github`` alone.

    Args:
        paths: The repository-relative paths that were consulted.

    Returns:
        A comma-separated list of the distinct directories, with the repository
        root named as such. Empty string for an empty path set.
    """
    seen: List[str] = []
    for path in paths:
        parent = path.rsplit("/", 1)[0] + "/" if "/" in path else "the repository root"
        if parent not in seen:
            seen.append(parent)
    return ", ".join(seen)
