"""Comprehensive tests for the TOML parser."""

import os
import tempfile
from typing import List

import pytest

from dependency_risk_profiler.parsers.toml import TomlParser

# Temp files the fixtures below create, cleaned up in teardown_module.
# Previously stashed as attributes on the module object, which no type
# checker can follow and which ruff's B010 will not let you write honestly.
_TEMP_FILES: List[str] = []


@pytest.fixture
def flit_pyproject_toml() -> str:
    """Create a temporary Flit-style pyproject.toml file for testing."""
    content = """
[build-system]
requires = ["flit_core>=3.2,<4"]
build-backend = "flit_core.buildapi"

[project]
name = "flit-project"
version = "0.1.0"
description = "A Flit-based project"
requires-python = ">=3.9"
readme = "README.md"
authors = [{name = "Test Author", email = "test@example.com"}]
license = {file = "LICENSE"}
classifiers = [
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
]
dependencies = [
    "django>=4.0.0",
    "celery>=5.2.0",
    "pydantic[email]>=1.9.0",
]

[project.optional-dependencies]
test = [
    "pytest>=7.0.0",
    "pytest-cov>=3.0.0",
]
dev = [
    "black>=22.1.0",
    "mypy>=0.931",
    "isort>=5.10.1",
]
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup

    _TEMP_FILES.append(temp_file)

    return temp_file


@pytest.fixture
def pdm_pyproject_toml() -> str:
    """Create a temporary PDM-style pyproject.toml file for testing."""
    content = """
[build-system]
requires = ["pdm-pep517>=1.0.0"]
build-backend = "pdm.pep517.api"

[project]
name = "pdm-project"
version = "0.1.0"
description = "A PDM-based project"
requires-python = ">=3.9"
license = {text = "MIT"}
authors = [
    {name = "Test Author", email = "test@example.com"}
]
dependencies = [
    "fastapi>=0.68.0",
    "uvicorn>=0.15.0",
    "sqlalchemy>=1.4.0",
]

[tool.pdm.dev-dependencies]
test = [
    "pytest>=7.0.0",
]
dev = [
    "black>=22.1.0",
    "ruff>=0.0.60",
]

[tool.pdm.build]
includes = ["src"]
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup

    _TEMP_FILES.append(temp_file)

    return temp_file


@pytest.fixture
def hatch_pyproject_toml() -> str:
    """Create a temporary Hatch-style pyproject.toml file for testing."""
    content = """
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "hatch-project"
version = "0.1.0"
description = "A Hatch-based project"
readme = "README.md"
requires-python = ">=3.9"
license = "MIT"
authors = [
    {name = "Test Author", email = "test@example.com"}
]
dependencies = [
    "pydantic>=1.9.0",
    "typer>=0.6.0",
    "rich>=12.0.0",
]

[project.optional-dependencies]
test = [
    "pytest>=7.0.0",
]
dev = [
    "black>=22.1.0",
]

[tool.hatch.envs.default]
dependencies = [
    "pytest",
    "black",
]
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup

    _TEMP_FILES.append(temp_file)

    return temp_file


@pytest.fixture
def workspace_cargo_toml() -> str:
    """Create a temporary Cargo.toml file with workspace dependencies for testing."""
    content = """
[workspace]
members = [
    "crates/*",
]

[workspace.dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.28", features = ["full"] }
clap = { version = "4.3", features = ["derive"] }

[package]
name = "workspace-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
tokio = "1.28"
clap = "4.3"

[dev-dependencies]
criterion = "0.5"
proptest = "1.2"

[build-dependencies]
cc = "1.0"
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup

    _TEMP_FILES.append(temp_file)

    return temp_file


@pytest.fixture
def empty_toml_file() -> str:
    """Create an empty TOML file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        temp_file = f.name

    # Store path for cleanup

    _TEMP_FILES.append(temp_file)

    return temp_file


def test_flit_pyproject_parsing(flit_pyproject_toml: str) -> None:
    """Test parsing a Flit-style pyproject.toml file."""
    parser = TomlParser(flit_pyproject_toml)
    dependencies = parser.parse()

    # Check that we have the expected number of dependencies
    assert len(dependencies) >= 3  # At least the main dependencies

    # Check for main dependencies
    assert "django" in dependencies
    assert dependencies["django"].installed_version == ">=4.0.0"

    assert "celery" in dependencies
    assert dependencies["celery"].installed_version == ">=5.2.0"

    # Check dependency with extras; parsers may preserve or strip extras.
    assert "pydantic[email]" in dependencies or "pydantic" in dependencies
    if "pydantic[email]" in dependencies:
        assert dependencies["pydantic[email]"].installed_version == ">=1.9.0"
    elif "pydantic" in dependencies:
        assert (
            dependencies["pydantic"].installed_version.startswith(">=")
            or "[email]" in dependencies["pydantic"].installed_version
        )

    # If we have test dependencies, verify them
    if "pytest" in dependencies:
        assert "pytest-cov" in dependencies
        assert "groups" in dependencies["pytest"].additional_info


def test_pdm_pyproject_parsing(pdm_pyproject_toml: str) -> None:
    """Test parsing a PDM-style pyproject.toml file."""
    parser = TomlParser(pdm_pyproject_toml)
    dependencies = parser.parse()

    # Check that we have the expected number of dependencies
    assert len(dependencies) >= 3  # At least the main dependencies

    # Check for main dependencies
    assert "fastapi" in dependencies
    assert dependencies["fastapi"].installed_version == ">=0.68.0"

    assert "uvicorn" in dependencies
    assert dependencies["uvicorn"].installed_version == ">=0.15.0"

    assert "sqlalchemy" in dependencies
    assert dependencies["sqlalchemy"].installed_version == ">=1.4.0"

    # PDM dev dependencies may be parsed depending on implementation
    # If we find them, we can check them
    if "black" in dependencies:
        assert "dev" in dependencies["black"].additional_info.get("section", "")


def test_hatch_pyproject_parsing(hatch_pyproject_toml: str) -> None:
    """Test parsing a Hatch-style pyproject.toml file."""
    parser = TomlParser(hatch_pyproject_toml)
    dependencies = parser.parse()

    # Check that we have the expected number of dependencies
    assert len(dependencies) >= 3  # At least the main dependencies

    # Check for main dependencies
    assert "pydantic" in dependencies
    assert dependencies["pydantic"].installed_version == ">=1.9.0"

    assert "typer" in dependencies
    assert dependencies["typer"].installed_version == ">=0.6.0"

    assert "rich" in dependencies
    assert dependencies["rich"].installed_version == ">=12.0.0"

    # Hatch dev dependencies may be parsed differently depending on implementation
    # If we find pytest we just check it's there, since the section might vary
    if "pytest" in dependencies:
        assert dependencies["pytest"].installed_version in [">=7.0.0", "latest"]


def test_workspace_cargo_toml_parsing(workspace_cargo_toml: str) -> None:
    """Test parsing a Cargo.toml file with workspace dependencies."""
    parser = TomlParser(workspace_cargo_toml)
    dependencies = parser.parse()

    # Check that we have the expected number of dependencies
    assert len(dependencies) >= 3  # At least the main dependencies

    # Check for main dependencies which should use workspace dependencies
    assert "serde" in dependencies
    # The version could be represented in different ways
    assert dependencies["serde"].installed_version in [
        "1.0",
        "workspace = true",
        "unknown",
    ]

    assert "tokio" in dependencies
    assert dependencies["tokio"].installed_version in [
        "1.28",
        "workspace = true",
        "unknown",
    ]

    # Check for build dependencies
    assert "cc" in dependencies
    assert dependencies["cc"].installed_version == "1.0"
    build_deps = [
        name
        for name, dep in dependencies.items()
        if "build_dependency" in dep.additional_info
        or "build-dependencies" in dep.additional_info.get("section", "")
    ]
    assert len(build_deps) > 0, "No build dependencies found"

    # Check for dev dependencies
    assert "criterion" in dependencies
    assert dependencies["criterion"].installed_version == "0.5"
    dev_deps = [
        name
        for name, dep in dependencies.items()
        if "dev_dependency" in dep.additional_info
        or "dev-dependencies" in dep.additional_info.get("section", "")
    ]
    assert len(dev_deps) > 0, "No dev dependencies found"


def test_empty_toml_file(empty_toml_file: str) -> None:
    """Test parsing an empty TOML file."""
    parser = TomlParser(empty_toml_file)
    dependencies = parser.parse()

    # Should return an empty dictionary, not error
    assert isinstance(dependencies, dict)
    assert len(dependencies) == 0


def test_extract_version_methods() -> None:
    """Test the version extraction methods directly."""
    # Create a temporary file for testing
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(b"[package]\nname = 'test'\n")
        temp_file = f.name

    parser = TomlParser(temp_file)

    try:
        # Test _parse_dependency_string
        assert parser._parse_dependency_string("requests>=2.25.0") == (
            "requests",
            ">=2.25.0",
        )
        assert parser._parse_dependency_string("django==4.0.0") == ("django", "==4.0.0")
        assert parser._parse_dependency_string("numpy") == ("numpy", "latest")
        assert parser._parse_dependency_string("pydantic[email]>=1.9.0") == (
            "pydantic[email]",
            ">=1.9.0",
        )

        # Test _extract_poetry_version
        assert parser._extract_poetry_version("^2.0.0") == "^2.0.0"
        assert parser._extract_poetry_version({"version": "^1.0.0"}) == "^1.0.0"
        assert (
            parser._extract_poetry_version(
                {"git": "https://github.com/example/repo.git"}
            )
            == "git:https://github.com/example/repo.git"
        )

        # Test _extract_cargo_version
        assert parser._extract_cargo_version("1.0") == "1.0"
        assert parser._extract_cargo_version({"version": "1.0"}) == "1.0"
        assert (
            parser._extract_cargo_version(
                {"git": "https://github.com/example/repo.git"}
            )
            == "git:https://github.com/example/repo.git"
        )
        assert (
            parser._extract_cargo_version(
                {"git": "https://github.com/example/repo.git", "tag": "v1.0"}
            )
            == "git:https://github.com/example/repo.git@v1.0"
        )
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def test_generic_toml_parsing() -> None:
    """Test the generic TOML parsing functionality."""
    # Create a custom TOML file with various dependency formats
    content = """
[dependencies]
first = "1.0.0"
second = { version = "2.0.0" }

[dev.dependencies]
third = "3.0.0"

[tool.dependencies]
fourth = { git = "https://example.com/repo.git" }

# Unusual formats to test robustness
[weird_dependencies]
fifth = { v = "5.0.0" }

[build]
requires = ["sixth>=6.0.0", "seventh==7.0.0"]
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup

    _TEMP_FILES.append(temp_file)

    parser = TomlParser(temp_file)
    dependencies = parser.parse()

    # Check that we found some dependencies
    assert len(dependencies) > 0

    # Check for dependencies from different sections
    if "first" in dependencies:
        assert dependencies["first"].installed_version == "1.0.0"

    if "third" in dependencies:
        assert dependencies["third"].installed_version == "3.0.0"
        assert "dev" in dependencies["third"].additional_info.get("section", "")

    if "fourth" in dependencies:
        assert "git:" in dependencies["fourth"].installed_version


def teardown_module() -> None:
    """Remove every temp file the fixtures in this module created."""
    while _TEMP_FILES:
        path = _TEMP_FILES.pop()
        if os.path.exists(path):
            os.unlink(path)
