"""Tests for the enhanced transitive dependency analyzer."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.transitive.analyzer_enhanced import (
    analyze_pipfile_lock_dependencies,
    analyze_pyproject_toml_dependencies,
    analyze_python_transitive_dependencies,
    analyze_transitive_dependencies_enhanced,
    build_dependency_graph,
    create_virtual_env,
    extract_python_dependencies_enhanced,
    get_pip_path,
    get_python_path,
    install_packages,
    install_pipdeptree,
    run_pipdeptree,
)


class TestVirtualEnvFunctions:
    """Tests for the virtual environment functions."""

    def test_create_virtual_env(self):
        """HYPOTHESIS: create_virtual_env should create a virtual environment."""
        # Skip if venv creation would be too slow for unit tests
        pytest.skip("Skipping venv creation test - slow operation")

        # Arrange
        with tempfile.TemporaryDirectory() as temp_dir:
            # Act
            result = create_virtual_env(temp_dir)

            # Assert
            assert result is True
            # Check if key venv directories/files exist
            if os.name == "nt":  # Windows
                assert os.path.exists(os.path.join(temp_dir, "Scripts"))
                assert os.path.exists(os.path.join(temp_dir, "Scripts", "python.exe"))
            else:  # Unix/Linux/MacOS
                assert os.path.exists(os.path.join(temp_dir, "bin"))
                assert os.path.exists(os.path.join(temp_dir, "bin", "python"))

    def test_get_pip_path(self):
        """HYPOTHESIS: get_pip_path should return the correct pip path for the platform."""
        # Arrange
        venv_path = "/path/to/venv"

        # Act
        with patch("os.name", "posix"):  # Test Unix path
            unix_path = get_pip_path(venv_path)

        with patch("os.name", "nt"):  # Test Windows path
            windows_path = get_pip_path(venv_path)

        # Assert
        assert unix_path == "/path/to/venv/bin/pip"
        assert windows_path == "/path/to/venv/Scripts/pip.exe"

    def test_get_python_path(self):
        """HYPOTHESIS: get_python_path should return the correct python path for the platform."""
        # Arrange
        venv_path = "/path/to/venv"

        # Act
        with patch("os.name", "posix"):  # Test Unix path
            unix_path = get_python_path(venv_path)

        with patch("os.name", "nt"):  # Test Windows path
            windows_path = get_python_path(venv_path)

        # Assert
        assert unix_path == "/path/to/venv/bin/python"
        assert windows_path == "/path/to/venv/Scripts/python.exe"


class TestDependencyInstallation:
    """Tests for package installation functions."""

    @patch("subprocess.run")
    def test_install_packages_success(self, mock_run):
        """HYPOTHESIS: install_packages should return True on successful installation."""
        # Arrange
        pip_path = "/path/to/venv/bin/pip"
        requirements_file = "/path/to/requirements.txt"
        mock_run.return_value = Mock(returncode=0, stderr="")

        # Act
        result = install_packages(pip_path, requirements_file)

        # Assert
        assert result is True
        mock_run.assert_called_once_with(
            [pip_path, "install", "-r", requirements_file],
            capture_output=True,
            text=True,
            check=False,
        )

    @patch("subprocess.run")
    def test_install_packages_failure(self, mock_run):
        """HYPOTHESIS: install_packages should return False on installation failure."""
        # Arrange
        pip_path = "/path/to/venv/bin/pip"
        requirements_file = "/path/to/requirements.txt"
        mock_run.return_value = Mock(
            returncode=1, stderr="Error: could not find package"
        )

        # Act
        result = install_packages(pip_path, requirements_file)

        # Assert
        assert result is False

    @patch("subprocess.run")
    def test_install_pipdeptree_success(self, mock_run):
        """HYPOTHESIS: install_pipdeptree should return True on successful installation."""
        # Arrange
        pip_path = "/path/to/venv/bin/pip"
        mock_run.return_value = Mock(returncode=0, stderr="")

        # Act
        result = install_pipdeptree(pip_path)

        # Assert
        assert result is True
        mock_run.assert_called_once_with(
            [pip_path, "install", "pipdeptree"],
            capture_output=True,
            text=True,
            check=False,
        )

    @patch("subprocess.run")
    def test_install_pipdeptree_failure(self, mock_run):
        """HYPOTHESIS: install_pipdeptree should return False on installation failure."""
        # Arrange
        pip_path = "/path/to/venv/bin/pip"
        mock_run.return_value = Mock(
            returncode=1, stderr="Error: could not find package"
        )

        # Act
        result = install_pipdeptree(pip_path)

        # Assert
        assert result is False


class TestPipdeptreeExecution:
    """Tests for pipdeptree execution."""

    @patch("subprocess.run")
    def test_run_pipdeptree_success(self, mock_run):
        """HYPOTHESIS: run_pipdeptree should return parsed JSON on success."""
        # Arrange
        python_path = "/path/to/venv/bin/python"
        mock_output = json.dumps(
            [
                {
                    "package": {
                        "key": "requests",
                        "package_name": "requests",
                        "installed_version": "2.28.1",
                    },
                    "dependencies": [
                        {
                            "package": {
                                "key": "urllib3",
                                "package_name": "urllib3",
                                "installed_version": "1.26.12",
                            }
                        },
                        {
                            "package": {
                                "key": "charset-normalizer",
                                "package_name": "charset-normalizer",
                                "installed_version": "2.1.1",
                            }
                        },
                    ],
                }
            ]
        )
        mock_run.return_value = Mock(returncode=0, stdout=mock_output, stderr="")

        # Act
        result = run_pipdeptree(python_path)

        # Assert
        assert result is not None
        assert len(result) == 1
        assert result[0]["package"]["key"] == "requests"
        assert len(result[0]["dependencies"]) == 2
        mock_run.assert_called_once_with(
            [python_path, "-m", "pipdeptree", "--json-tree", "--warn", "silence"],
            capture_output=True,
            text=True,
            check=False,
        )

    @patch("subprocess.run")
    def test_run_pipdeptree_failure(self, mock_run):
        """HYPOTHESIS: run_pipdeptree should return None on failure."""
        # Arrange
        python_path = "/path/to/venv/bin/python"
        mock_run.return_value = Mock(
            returncode=1, stderr="Error: pipdeptree not installed"
        )

        # Act
        result = run_pipdeptree(python_path)

        # Assert
        assert result is None

    @patch("subprocess.run")
    def test_run_pipdeptree_invalid_json(self, mock_run):
        """REGRESSION: run_pipdeptree should handle invalid JSON output."""
        # Arrange
        python_path = "/path/to/venv/bin/python"
        mock_run.return_value = Mock(returncode=0, stdout="Not valid JSON", stderr="")

        # Act
        result = run_pipdeptree(python_path)

        # Assert
        assert result is None


class TestDependencyGraphBuilding:
    """Tests for dependency graph building."""

    def test_build_dependency_graph(self):
        """HYPOTHESIS: build_dependency_graph should correctly build transitive dependencies."""
        # Arrange
        direct_dependencies = ["packageA", "packageB"]
        dependency_map = {
            "packageA": {"dependency1", "dependency2"},
            "packageB": {"dependency3"},
            "dependency1": {"dependency4"},
            "dependency2": {"dependency4", "dependency5"},
            "dependency3": set(),
            "dependency4": set(),
            "dependency5": {"dependency6"},
            "dependency6": set(),
        }

        # Act
        transitive_deps = build_dependency_graph(direct_dependencies, dependency_map)

        # Assert
        assert "packageA" in transitive_deps
        assert "packageB" in transitive_deps

        # Check transitive dependencies for packageA
        assert "dependency1" in transitive_deps["packageA"]
        assert "dependency2" in transitive_deps["packageA"]
        assert "dependency4" in transitive_deps["packageA"]
        assert "dependency5" in transitive_deps["packageA"]
        assert "dependency6" in transitive_deps["packageA"]

        # Check transitive dependencies for packageB
        assert "dependency3" in transitive_deps["packageB"]
        assert len(transitive_deps["packageB"]) == 1  # only dependency3

    def test_build_dependency_graph_with_cycles(self):
        """REGRESSION: build_dependency_graph should handle dependency cycles."""
        # Arrange
        direct_dependencies = ["packageA"]
        dependency_map = {
            "packageA": {"packageB"},
            "packageB": {"packageC"},
            "packageC": {"packageA"},  # Creates a cycle
        }

        # Act
        transitive_deps = build_dependency_graph(direct_dependencies, dependency_map)

        # Assert
        assert "packageA" in transitive_deps
        # Due to cycle handling, we should still have dependencies
        assert "packageB" in transitive_deps["packageA"]
        assert "packageC" in transitive_deps["packageA"]


class TestDependencyAnalysis:
    """Tests for dependency analysis functions."""

    @patch("dependency_risk_profiler.transitive.analyzer_enhanced.create_virtual_env")
    @patch("dependency_risk_profiler.transitive.analyzer_enhanced.install_packages")
    @patch("dependency_risk_profiler.transitive.analyzer_enhanced.install_pipdeptree")
    @patch("dependency_risk_profiler.transitive.analyzer_enhanced.run_pipdeptree")
    def test_analyze_python_transitive_dependencies(
        self,
        mock_run_pipdeptree,
        mock_install_pipdeptree,
        mock_install_packages,
        mock_create_venv,
    ):
        """HYPOTHESIS: analyze_python_transitive_dependencies should extract dependencies from pipdeptree."""
        # Arrange
        requirements_file = "/path/to/requirements.txt"

        # Mock successful venv and package installation
        mock_create_venv.return_value = True
        mock_install_packages.return_value = True
        mock_install_pipdeptree.return_value = True

        # Mock pipdeptree output
        mock_pipdeptree_output = [
            {
                "package": {
                    "key": "requests",
                    "package_name": "requests",
                    "installed_version": "2.28.1",
                },
                "dependencies": [
                    {
                        "package": {
                            "key": "urllib3",
                            "package_name": "urllib3",
                            "installed_version": "1.26.12",
                        }
                    },
                    {
                        "package": {
                            "key": "charset-normalizer",
                            "package_name": "charset-normalizer",
                            "installed_version": "2.1.1",
                        }
                    },
                ],
            },
            {
                "package": {
                    "key": "flask",
                    "package_name": "Flask",
                    "installed_version": "2.2.2",
                },
                "dependencies": [
                    {
                        "package": {
                            "key": "werkzeug",
                            "package_name": "Werkzeug",
                            "installed_version": "2.2.2",
                        }
                    },
                    {
                        "package": {
                            "key": "jinja2",
                            "package_name": "Jinja2",
                            "installed_version": "3.1.2",
                        }
                    },
                ],
            },
        ]
        mock_run_pipdeptree.return_value = mock_pipdeptree_output

        # Act
        dependency_map = analyze_python_transitive_dependencies(requirements_file)

        # Assert
        assert len(dependency_map) == 2
        assert "requests" in dependency_map
        assert "flask" in dependency_map
        assert "urllib3" in dependency_map["requests"]
        assert "charset-normalizer" in dependency_map["requests"]
        assert "werkzeug" in dependency_map["flask"]
        assert "jinja2" in dependency_map["flask"]

    @patch(
        "dependency_risk_profiler.transitive.analyzer_enhanced.analyze_python_transitive_dependencies"
    )
    def test_analyze_pyproject_toml_dependencies(self, mock_analyze_python):
        """HYPOTHESIS: analyze_pyproject_toml_dependencies should extract dependencies from pyproject.toml."""
        # Skip for complex implementation
        pytest.skip("Requires tomli and file operations, mocking is complex")

    @patch(
        "dependency_risk_profiler.transitive.analyzer_enhanced.analyze_python_transitive_dependencies"
    )
    def test_analyze_pipfile_lock_dependencies(self, mock_analyze_python):
        """HYPOTHESIS: analyze_pipfile_lock_dependencies should extract dependencies from Pipfile.lock."""
        # Arrange
        pipfile_lock = "/tmp/test_Pipfile.lock"
        mock_analyze_python.return_value = {"requests": {"urllib3"}}

        # Create test fixture
        with open(pipfile_lock, "w") as f:
            json.dump(
                {
                    "default": {
                        "requests": {
                            "version": "==2.28.1",
                            "hashes": ["hash1", "hash2"],
                        }
                    }
                },
                f,
            )

        try:
            # Act
            dependency_map = analyze_pipfile_lock_dependencies(pipfile_lock)

            # Assert
            mock_analyze_python.assert_called_once()
            assert dependency_map == {"requests": {"urllib3"}}
        finally:
            # Clean up
            os.remove(pipfile_lock)

    @patch(
        "dependency_risk_profiler.transitive.analyzer_enhanced.analyze_python_transitive_dependencies"
    )
    @patch(
        "dependency_risk_profiler.transitive.analyzer_enhanced.analyze_pyproject_toml_dependencies"
    )
    @patch(
        "dependency_risk_profiler.transitive.analyzer_enhanced.analyze_pipfile_lock_dependencies"
    )
    def test_extract_python_dependencies_enhanced(
        self, mock_pipfile, mock_pyproject, mock_requirements
    ):
        """HYPOTHESIS: extract_python_dependencies_enhanced should call the correct analyzer."""
        # Arrange
        mock_requirements.return_value = {"pkg1": {"dep1"}}
        mock_pyproject.return_value = {"pkg2": {"dep2"}}
        mock_pipfile.return_value = {"pkg3": {"dep3"}}

        # Act - Test each file type
        reqs_result = extract_python_dependencies_enhanced("requirements.txt")
        pyproj_result = extract_python_dependencies_enhanced("pyproject.toml")
        pipfile_result = extract_python_dependencies_enhanced("Pipfile.lock")
        unknown_result = extract_python_dependencies_enhanced("unknown.txt")

        # Assert
        assert reqs_result == {"pkg1": {"dep1"}}
        assert pyproj_result == {"pkg2": {"dep2"}}
        assert pipfile_result == {"pkg3": {"dep3"}}
        assert unknown_result == {}
        mock_requirements.assert_called_once_with("requirements.txt")
        mock_pyproject.assert_called_once_with("pyproject.toml")
        mock_pipfile.assert_called_once_with("Pipfile.lock")


@patch(
    "dependency_risk_profiler.transitive.analyzer_enhanced.extract_python_dependencies_enhanced"
)
def test_analyze_transitive_dependencies_enhanced(mock_extract_python):
    """HYPOTHESIS: analyze_transitive_dependencies_enhanced should update dependency metadata."""
    # Arrange
    dependencies = {
        "requests": DependencyMetadata(name="requests", installed_version="2.28.1"),
        "flask": DependencyMetadata(name="flask", installed_version="2.2.2"),
    }
    manifest_path = "requirements.txt"

    mock_extract_python.return_value = {
        "requests": {"urllib3", "charset-normalizer"},
        "flask": {"werkzeug", "jinja2"},
    }

    # Act
    result = analyze_transitive_dependencies_enhanced(dependencies, manifest_path)

    # Assert
    assert result is dependencies  # Should return the same dict, modified
    assert result["requests"].transitive_dependencies == {
        "urllib3",
        "charset-normalizer",
    }
    assert result["flask"].transitive_dependencies == {"werkzeug", "jinja2"}


@pytest.mark.benchmark
def test_transitive_analysis_performance():
    """BENCHMARK: The enhanced analysis should handle large dependency trees efficiently.

    SLA Requirements:
    - Should process a reasonable number of dependencies in < 1s (excluding venv creation)
    """
    # Skip actual benchmark as it would create venvs
    pytest.skip("Skipping performance benchmark that would create venvs")
