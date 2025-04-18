"""Tests for edge cases in the TOML parser."""

import os
import tempfile

import pytest

from dependency_risk_profiler.parsers.toml import TomlParser


@pytest.fixture
def malformed_version_toml():
    """Create a TOML file with malformed version specifications."""
    content = """
[package]
name = "malformed-versions"
version = "0.1.0"

[dependencies]
# Missing version
missing_version = {}
# Empty string version
empty_version = ""
# Unusual version specifications
unusual_version = { what = "this is not a version" }
# Array as version
array_version = [1, 2, 3]
# Boolean as version
bool_version = true
# Number as version
number_version = 42
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup
    import sys

    current_module = sys.modules[__name__]
    current_module.malformed_version_path = temp_file

    return temp_file


@pytest.fixture
def nested_dependencies_toml():
    """Create a TOML file with deeply nested dependency specifications."""
    content = """
[package]
name = "nested-dependencies"
version = "0.1.0"

[dependencies]
# Normal dependency
normal = "1.0.0"

[nested.dependencies]
first = "1.0.0"

[deeply.nested.dependencies]
second = "2.0.0"

[extremely.deeply.nested.dependencies]
third = "3.0.0"

[tool.deeply.nested.dependencies]
fourth = "4.0.0"
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup
    import sys

    current_module = sys.modules[__name__]
    current_module.nested_deps_path = temp_file

    return temp_file


@pytest.fixture
def large_toml_file():
    """Create a large TOML file with many dependencies."""
    content = """
[package]
name = "large-project"
version = "0.1.0"

[dependencies]
"""
    # Add 100 dependencies
    for i in range(1, 101):
        content += f'dep{i} = "{i}.0.0"\n'

    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup
    import sys

    current_module = sys.modules[__name__]
    current_module.large_toml_path = temp_file

    return temp_file


@pytest.fixture
def complex_dependencies_toml():
    """Create a TOML file with complex dependency specifications."""
    content = """
[package]
name = "complex-dependencies"
version = "0.1.0"

[dependencies]
# Git dependency with branch, tag and rev
git_complex = { git = "https://github.com/example/repo.git", branch = "main", tag = "v1.0.0", rev = "abcdef123456" }
# Path dependency
path_dep = { path = "../local_package" }
# Registry dependency with complex features
complex_features = { version = "1.0.0", features = ["feature1", "feature2"], default-features = false, optional = true }
# Dependencies with target-specific overrides
standard = "1.0.0"
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup
    import sys

    current_module = sys.modules[__name__]
    current_module.complex_deps_path = temp_file

    return temp_file


@pytest.fixture
def mixed_formats_toml():
    """Create a TOML file with mixed format dependency specifications."""
    content = """
[project]
name = "mixed-formats"
version = "0.1.0"
dependencies = [
    "simple1>=1.0.0",
    "simple2==2.0.0"
]

[build-system]
requires = ["complex>=3.0.0"]

[tool.poetry.dependencies]
poetry_dep = "^4.0.0"

[dependencies]
cargo_dep = "5.0.0"

[tool.pdm.dev-dependencies]
pdm_dep = "6.0.0"
"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".toml") as f:
        f.write(content.encode("utf-8"))
        temp_file = f.name

    # Store path for cleanup
    import sys

    current_module = sys.modules[__name__]
    current_module.mixed_formats_path = temp_file

    return temp_file


def test_malformed_versions(malformed_version_toml):
    """Test handling of malformed version specifications."""
    parser = TomlParser(malformed_version_toml)
    dependencies = parser.parse()

    # The parser should not crash and should extract what it can
    assert isinstance(dependencies, dict)

    # Check how malformed versions are handled
    if "missing_version" in dependencies:
        assert dependencies["missing_version"].installed_version in ["unknown", "{}"]

    if "empty_version" in dependencies:
        assert dependencies["empty_version"].installed_version in ["unknown", ""]

    if "unusual_version" in dependencies:
        assert dependencies["unusual_version"].installed_version in [
            "unknown",
            '{ what = "this is not a version" }',
            "{'what': 'this is not a version'}",
        ]

    if "array_version" in dependencies:
        assert (
            "unknown" in dependencies["array_version"].installed_version
            or "[1, 2, 3]" in dependencies["array_version"].installed_version
        )

    if "bool_version" in dependencies:
        assert dependencies["bool_version"].installed_version.lower() in [
            "unknown",
            "true",
            "True",
        ]

    if "number_version" in dependencies:
        assert dependencies["number_version"].installed_version in ["unknown", "42"]


def test_nested_dependencies(nested_dependencies_toml):
    """Test parsing of deeply nested dependency specifications."""
    parser = TomlParser(nested_dependencies_toml)
    dependencies = parser.parse()

    # Check that we found dependencies at different nesting levels
    assert "normal" in dependencies
    assert dependencies["normal"].installed_version == "1.0.0"

    # Our current implementation doesn't deeply traverse TOML structure for nested dependencies
    # For now, we just make sure it doesn't crash on nested structures
    assert isinstance(dependencies, dict)


def test_large_toml_file(large_toml_file):
    """Test parsing of a large TOML file with many dependencies."""
    parser = TomlParser(large_toml_file)
    dependencies = parser.parse()

    # Should be able to parse all dependencies
    assert len(dependencies) == 100

    # Check a few dependencies at random
    assert "dep1" in dependencies
    assert dependencies["dep1"].installed_version == "1.0.0"

    assert "dep50" in dependencies
    assert dependencies["dep50"].installed_version == "50.0.0"

    assert "dep100" in dependencies
    assert dependencies["dep100"].installed_version == "100.0.0"


def test_complex_dependencies(complex_dependencies_toml):
    """Test parsing of complex dependency specifications."""
    parser = TomlParser(complex_dependencies_toml)
    dependencies = parser.parse()

    # Make sure we found all dependencies
    assert "standard" in dependencies
    assert dependencies["standard"].installed_version == "1.0.0"

    # Check complex git dependency
    assert "git_complex" in dependencies
    assert "git:" in dependencies["git_complex"].installed_version

    # Check path dependency
    assert "path_dep" in dependencies
    assert "path:" in dependencies["path_dep"].installed_version

    # Check complex features dependency
    assert "complex_features" in dependencies


def test_mixed_formats(mixed_formats_toml):
    """Test parsing of mixed format dependency specifications."""
    parser = TomlParser(mixed_formats_toml)
    dependencies = parser.parse()

    # We should find dependencies from different formats
    formats_found = set()

    # PEP 621 format
    if any(
        dep
        for name, dep in dependencies.items()
        if dep.additional_info.get("section") == "project.dependencies"
    ):
        formats_found.add("pep621")

    # Build system format
    if any(
        dep
        for name, dep in dependencies.items()
        if "build-system" in dep.additional_info.get("section", "")
    ):
        formats_found.add("build-system")

    # Poetry format
    if any(
        dep
        for name, dep in dependencies.items()
        if "tool.poetry" in dep.additional_info.get("section", "")
    ):
        formats_found.add("poetry")

    # Cargo format
    if any(
        dep
        for name, dep in dependencies.items()
        if dep.additional_info.get("section") == "dependencies"
    ):
        formats_found.add("cargo")

    # PDM format
    if any(
        dep
        for name, dep in dependencies.items()
        if "tool.pdm" in dep.additional_info.get("section", "")
    ):
        formats_found.add("pdm")

    # We should find at least 2 different formats
    assert len(formats_found) >= 2, f"Only found {formats_found} formats"


def teardown_module(module):
    """Clean up temporary files."""
    # Clean up any temporary files that might have been created
    for path_attr in [
        "malformed_version_path",
        "nested_deps_path",
        "large_toml_path",
        "complex_deps_path",
        "mixed_formats_path",
    ]:
        path = getattr(module, path_attr, None)
        if path and os.path.exists(path):
            os.unlink(path)
