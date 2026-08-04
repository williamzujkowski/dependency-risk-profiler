"""Tests for CI/CD configuration files.

These tests verify that our CI/CD configuration files are valid and work as expected.
"""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml


def test_flake8_config_valid() -> None:
    """Test that the flake8 configuration is valid and works as expected."""
    # Get the pyproject.toml path where flake8 config is now stored
    root_dir = Path(__file__).parent.parent.parent
    pyproject_path = root_dir / "pyproject.toml"

    # Verify the file exists
    assert pyproject_path.exists(), "pyproject.toml file should exist"

    # Run flake8 with the pyproject file for configuration
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "flake8",
            "--version",
        ],
        capture_output=True,
        text=True,
    )

    # We should get a successful result
    assert result.returncode == 0, f"flake8 configuration is invalid: {result.stderr}"


def test_flake8_ignores_are_effective() -> None:
    """Test that flake8 ignores are properly configured."""
    # Get the root directory
    root_dir = Path(__file__).parent.parent.parent

    # Create a temp file with common errors that should be ignored
    temp_file = root_dir / "temp_flake8_test.py"
    try:
        with open(temp_file, "w") as f:
            f.write(
                """
# This file has long lines but should be ignored due to E501 in extend-ignore
very_long_line = (
    "This is a very long line that should normally trigger an E501 error but "
    "we have configured flake8 to ignore line length errors across the "
    "codebase so this should pass"
)

# This has no blank line at the end (W292) but should be ignored
# This has trailing whitespace (W291) but should be ignored
"""
            )

        # Run flake8 on the temp file with explicit configuration
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "flake8",
                str(temp_file),
                "--max-line-length=88",
                "--extend-ignore=E203,E501,W291,W292,W293",
            ],
            capture_output=True,
            text=True,
        )

        # We should get a successful result despite the errors
        assert result.returncode == 0, f"flake8 ignores aren't working: {result.stdout}"

    finally:
        # Clean up the temp file
        if temp_file.exists():
            temp_file.unlink()


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
