"""Tests for CI/CD configuration files.

These tests verify that our CI/CD configuration files are valid and work as expected.
"""

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).parent.parent.parent

# An unused import. F401 is in `.flake8`'s `extend-ignore` and is *not* ignored
# by flake8's defaults, which is what makes it a usable probe for "did the repo
# config apply".
PROBE_SOURCE = "import os\n"


def test_dot_flake8_is_the_config_flake8_actually_reads(tmp_path: Path) -> None:
    """`.flake8` is the config flake8 loads when run from the repo root.

    Asserted on behaviour, not on file contents. The probe is a file whose only
    fault is F401: `.flake8` ignores it, flake8's defaults do not. If the repo
    config is loaded the probe passes; run with `--isolated` — same flake8, same
    file, no config — it must fail. Two runs, opposite verdicts, so a pass here
    cannot come from flake8 simply having nothing to complain about.

    The predecessor of this test asserted that `flake8 --version` exits 0, under
    a comment claiming the config lived in `pyproject.toml`. It could not fail,
    and the config it named was never read (#228).
    """
    assert (ROOT_DIR / ".flake8").exists(), ".flake8 is the live flake8 config"

    probe = tmp_path / "probe.py"
    probe.write_text(PROBE_SOURCE)

    with_repo_config = subprocess.run(
        [sys.executable, "-m", "flake8", str(probe)],
        capture_output=True,
        text=True,
        cwd=ROOT_DIR,
    )
    isolated = subprocess.run(
        [sys.executable, "-m", "flake8", "--isolated", str(probe)],
        capture_output=True,
        text=True,
        cwd=ROOT_DIR,
    )

    assert "F401" in isolated.stdout, (
        "the probe must be a genuine flake8 error without config, otherwise the "
        f"assertion below proves nothing: {isolated.stdout!r}"
    )
    assert with_repo_config.returncode == 0, (
        "flake8 did not load the repo config from the root — it flagged an error "
        f"that .flake8 ignores: {with_repo_config.stdout!r}"
    )


def test_pyproject_carries_no_inert_flake8_section() -> None:
    """A `[tool.flake8]` section may only exist if something can read it.

    flake8 has no pyproject.toml support. Without the flake8-pyproject plugin
    such a section is read by nothing, and it does not announce that: it just
    sits there looking like configuration. This repo carried one for a year,
    including six exclusions that pointed through a dangling `tests` symlink
    (#228). If a future change wants the section, it has to install the plugin
    that makes it real.
    """
    has_section = re.search(
        r"^\[tool\.flake8\]", (ROOT_DIR / "pyproject.toml").read_text(), re.MULTILINE
    )
    plugin_available = importlib.util.find_spec("flake8_pyproject") is not None

    assert not has_section or plugin_available, (
        "pyproject.toml has a [tool.flake8] section but flake8-pyproject is not "
        "installed, so flake8 reads none of it. Put the settings in .flake8, or "
        "add flake8-pyproject to the dev extra so the section is real."
    )


def test_pre_commit_config_valid() -> None:
    """Test that the pre-commit configuration is valid."""
    # Get the pre-commit config path
    root_dir = Path(__file__).parent.parent.parent
    pre_commit_path = root_dir / ".pre-commit-config.yaml"

    # Verify the file exists
    assert pre_commit_path.exists(), "pre-commit configuration file should exist"

    # Verify the YAML is valid
    try:
        with open(pre_commit_path, "r") as f:
            yaml_content = yaml.safe_load(f)

        # Check for required sections
        assert "repos" in yaml_content, "pre-commit config should have repos defined"
        assert isinstance(yaml_content["repos"], list), "repos should be a list"

        # Check that each repo has required fields
        for repo in yaml_content["repos"]:
            assert "repo" in repo, "Each repo should have a 'repo' URL"
            assert "rev" in repo, "Each repo should have a 'rev' revision"
            assert "hooks" in repo, "Each repo should have hooks defined"

    except yaml.YAMLError as e:
        pytest.fail(f"Invalid YAML in pre-commit config file: {e}")


def test_every_codeql_action_step_pins_the_same_version() -> None:
    """CodeQL's sub-actions must not skew, and prose did not stop them.

    `codeql-action/init` and `codeql-action/analyze` fail with "Loaded a
    configuration file for version X, but running version Y" whenever they run
    at different versions. That was diagnosed once and written into a comment
    at `codeql.yml:126` -- and it recurred verbatim on 2026-08-12 as PRs #397
    and #399, because Dependabot tracks each sub-action separately and, before
    the `codeql-action` group was added, opened one PR per sub-action so
    neither could pass alone.

    A hazard recorded in a comment is not a hazard prevented. This is the
    check the comment lacked.
    """
    import re
    from pathlib import Path

    workflows = Path(__file__).resolve().parents[2] / ".github" / "workflows"
    pinned: dict = {}
    for path in workflows.glob("*.yml"):
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = re.search(r"github/codeql-action/\S+@([0-9a-f]{40})", stripped)
            if match:
                pinned.setdefault(match.group(1), []).append(
                    f"{path.name}:{stripped.split('@')[0].split('/')[-1]}"
                )

    assert pinned, "no pinned codeql-action step was found; has the pin format changed?"
    assert len(pinned) == 1, (
        "codeql-action steps are pinned to different commits, which fails at "
        f"run time with a version-mismatch error: {pinned}"
    )
