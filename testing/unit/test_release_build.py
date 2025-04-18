"""Tests for the release_build module."""

import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import ANY, MagicMock, Mock, patch

import pytest

from dependency_risk_profiler.secure_release.code_signing import SigningMode
from dependency_risk_profiler.secure_release.release_build import (
    BuildError,
    BuildMode,
    build_package,
    create_build_manifest,
    fetch_latest_code,
    run_build_process,
    run_tests,
    scan_artifacts,
    setup_build_environment,
    sign_artifacts,
)
from dependency_risk_profiler.secure_release.release_management import VersionBumpType


class TestSetupBuildEnvironment:
    """Tests for the setup_build_environment function."""

    @patch("dependency_risk_profiler.secure_release.release_build.time")
    @patch("dependency_risk_profiler.secure_release.release_build.datetime")
    def test_setup_build_environment(self, mock_datetime: Mock, mock_time: Mock) -> None:
        """Verify that setup_build_environment returns a dictionary with the expected environment variables."""
        # Setup mocks
        mock_time.time.return_value = 1617235200  # Arbitrary timestamp
        
        # Create a mock datetime object
        mock_date = Mock()
        mock_date.isoformat.return_value = "2023-01-15T12:00:00"
        mock_datetime.datetime.utcnow.return_value = mock_date
        
        # Call the function
        result = setup_build_environment()
        
        # Verify the result
        assert isinstance(result, dict)
        assert result["PYTHONHASHSEED"] == "0"
        assert result["SOURCE_DATE_EPOCH"] == "1617235200"
        assert result["BUILD_TIMESTAMP"] == "2023-01-15T12:00:00Z"
        assert result["BUILD_ID"] == "build-1617235200"
        
        # Verify the environment includes system environment variables
        assert len(result) > 4  # Should include system env vars too


class TestFetchLatestCode:
    """Tests for the fetch_latest_code function."""

    @patch("dependency_risk_profiler.secure_release.release_build.subprocess.run")
    def test_fetch_latest_code_success(self, mock_run: Mock) -> None:
        """Verify that fetch_latest_code clones a repository and returns the path."""
        # Setup mocks
        mock_process = Mock()
        mock_process.returncode = 0
        mock_process.stdout = "Cloned successfully"
        mock_run.return_value = mock_process
        
        # Call the function with a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            result = fetch_latest_code("https://github.com/org/repo.git", "main", temp_dir)
            
            # Verify the result
            assert result == Path(temp_dir)
            
            # Verify git clone was called with the correct arguments
            mock_run.assert_called_once_with(
                ["git", "clone", "-b", "main", "https://github.com/org/repo.git", str(temp_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
    
    @patch("dependency_risk_profiler.secure_release.release_build.subprocess.run")
    def test_fetch_latest_code_failure(self, mock_run: Mock) -> None:
        """Verify that fetch_latest_code raises a BuildError when git clone fails."""
        # Setup mocks to simulate a failure
        error = subprocess.CalledProcessError(1, ["git", "clone"])
        error.stdout = ""
        error.stderr = "Error: repository not found"
        mock_run.side_effect = error
        
        # Call the function and verify it raises an exception
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(BuildError, match="Failed to fetch code"):
                fetch_latest_code("https://github.com/org/repo.git", "main", temp_dir)


class TestRunTests:
    """Tests for the run_tests function."""

    @patch("dependency_risk_profiler.secure_release.release_build.os")
    @patch("dependency_risk_profiler.secure_release.release_build.subprocess.run")
    def test_run_tests_success(self, mock_run: Mock, mock_os: Mock) -> None:
        """Verify that run_tests returns True when all tests pass."""
        # Setup mocks
        mock_process = Mock()
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        mock_os.getcwd.return_value = "/original/dir"
        
        # Create a test environment
        build_env = {"PYTHONPATH": "/test/path"}
        
        # Call the function
        result = run_tests("/code/dir", build_env)
        
        # Verify the result
        assert result is True
        
        # Verify directory changes
        mock_os.chdir.assert_any_call(Path("/code/dir"))
        mock_os.chdir.assert_called_with("/original/dir")
        
        # Verify subprocess calls
        assert mock_run.call_count == 5  # pip install, flake8, black, mypy, pytest
    
    @patch("dependency_risk_profiler.secure_release.release_build.os")
    @patch("dependency_risk_profiler.secure_release.release_build.subprocess.run")
    def test_run_tests_failure(self, mock_run: Mock, mock_os: Mock) -> None:
        """Verify that run_tests returns False when tests fail."""
        # Setup mocks to simulate a failure in one of the steps
        mock_os.getcwd.return_value = "/original/dir"
        
        mock_process = Mock()
        mock_process.returncode = 0
        
        # Make the third call (black) fail
        call_count = [0]  # Use a list to maintain state between calls
        
        def mock_run_side_effect(*args: Any, **kwargs: Any) -> Mock:
            call_count[0] += 1
            if call_count[0] == 3:  # Third call (black)
                error = subprocess.CalledProcessError(1, ["black", "--check", "."])
                error.stdout = ""
                error.stderr = "Formatting issues found"
                raise error
            return mock_process
        
        mock_run.side_effect = mock_run_side_effect
        
        # Call the function
        result = run_tests("/code/dir", {})
        
        # Verify the result
        assert result is False
        
        # Verify we changed back to the original directory
        mock_os.chdir.assert_called_with("/original/dir")


class TestBuildPackage:
    """Tests for the build_package function."""

    @patch("dependency_risk_profiler.secure_release.release_build.os")
    @patch("dependency_risk_profiler.secure_release.release_build.shutil")
    @patch("dependency_risk_profiler.secure_release.release_build.subprocess.run")
    def test_build_package_success(self, mock_run: Mock, mock_shutil: Mock, mock_os: Mock) -> None:
        """Verify that build_package builds and copies artifacts correctly."""
        # Setup mocks
        mock_process = Mock()
        mock_process.returncode = 0
        mock_run.return_value = mock_process
        mock_os.getcwd.return_value = "/original/dir"
        
        # Setup temporary directories for testing
        with tempfile.TemporaryDirectory() as code_dir:
            with tempfile.TemporaryDirectory() as output_dir:
                # Create a fake distribution directory structure
                code_path = Path(code_dir)
                dist_path = code_path / "dist"
                dist_path.mkdir()
                
                # Create fake distribution files
                sdist_file = dist_path / "package-1.0.0.tar.gz"
                wheel_file = dist_path / "package-1.0.0-py3-none-any.whl"
                
                with open(sdist_file, "w") as f:
                    f.write("fake sdist")
                with open(wheel_file, "w") as f:
                    f.write("fake wheel")
                
                # Call the function
                result = build_package(code_dir, output_dir, {})
                
                # Verify the result
                assert isinstance(result, tuple)
                assert len(result) == 2
                sdist_dest, wheel_dest = result
                
                # Verify paths
                assert sdist_dest == Path(output_dir) / "package-1.0.0.tar.gz"
                assert wheel_dest == Path(output_dir) / "package-1.0.0-py3-none-any.whl"
                
                # Verify copy operations
                mock_shutil.copy2.assert_any_call(sdist_file, sdist_dest)
                mock_shutil.copy2.assert_any_call(wheel_file, wheel_dest)
                
                # Verify directory changes
                mock_os.chdir.assert_any_call(code_path)
                mock_os.chdir.assert_called_with("/original/dir")

    @patch("dependency_risk_profiler.secure_release.release_build.os")
    @patch("dependency_risk_profiler.secure_release.release_build.subprocess.run")
    def test_build_package_failure(self, mock_run: Mock, mock_os: Mock) -> None:
        """Verify that build_package raises a BuildError when building fails."""
        # Setup mocks to simulate a failure
        mock_os.getcwd.return_value = "/original/dir"
        error = subprocess.CalledProcessError(1, ["build"])
        error.stdout = ""
        error.stderr = "Build error"
        mock_run.side_effect = error
        
        # Call the function and verify it raises an exception
        with tempfile.TemporaryDirectory() as code_dir:
            with tempfile.TemporaryDirectory() as output_dir:
                with pytest.raises(BuildError, match="Failed to build package"):
                    build_package(code_dir, output_dir, {})
                
                # Verify we changed back to the original directory
                mock_os.chdir.assert_called_with("/original/dir")


class TestScanArtifacts:
    """Tests for the scan_artifacts function."""

    @patch("dependency_risk_profiler.secure_release.release_build.time")
    def test_scan_artifacts_success(self, mock_time: Mock) -> None:
        """Verify that scan_artifacts returns True for a successful scan."""
        # Setup temporary files
        with tempfile.NamedTemporaryFile() as temp_file1:
            with tempfile.NamedTemporaryFile() as temp_file2:
                artifacts = [Path(temp_file1.name), Path(temp_file2.name)]
                
                # Call the function
                result = scan_artifacts(artifacts)
                
                # Verify the result
                assert result is True
                
                # Verify time.sleep was called for each artifact (simulated scanning)
                assert mock_time.sleep.call_count == len(artifacts)

    @patch("dependency_risk_profiler.secure_release.release_build.time")
    def test_scan_artifacts_exception(self, mock_time: Mock) -> None:
        """Verify that scan_artifacts returns False when an exception occurs."""
        # Setup mock to raise an exception
        mock_time.sleep.side_effect = Exception("Scan error")
        
        # Call the function with a path that will cause an exception
        result = scan_artifacts([Path("nonexistent/file.txt")])
        
        # Verify the result
        assert result is False


class TestSignArtifacts:
    """Tests for the sign_artifacts function."""

    @patch("dependency_risk_profiler.secure_release.release_build.sign_artifact")
    def test_sign_artifacts_success(self, mock_sign_artifact: Mock) -> None:
        """Verify that sign_artifacts signs each artifact and returns a dictionary of results."""
        # Setup mocks
        mock_sign_artifact.return_value = {"timestamp": "2023-01-15T12:00:00Z", "mode": "TEST"}
        
        # Setup temporary files
        with tempfile.NamedTemporaryFile() as temp_file1:
            with tempfile.NamedTemporaryFile() as temp_file2:
                artifacts = [Path(temp_file1.name), Path(temp_file2.name)]
                
                # Call the function
                result = sign_artifacts(artifacts, "build-123", SigningMode.TEST, "log.txt")
                
                # Verify the result
                assert isinstance(result, dict)
                assert len(result) == 2
                assert Path(temp_file1.name) in result
                assert Path(temp_file2.name) in result
                
                # Verify each artifact was signed
                for artifact in artifacts:
                    assert mock_sign_artifact.call_args_list[artifacts.index(artifact)].args[0] == artifact
                
                # Verify the signature info was returned
                for signature_info in result.values():
                    assert signature_info == {"timestamp": "2023-01-15T12:00:00Z", "mode": "TEST"}

    @patch("dependency_risk_profiler.secure_release.release_build.sign_artifact")
    def test_sign_artifacts_failure(self, mock_sign_artifact: Mock) -> None:
        """Verify that sign_artifacts raises a BuildError when signing fails."""
        # Setup mock to raise an exception
        mock_sign_artifact.side_effect = Exception("Signing error")
        
        # Call the function and verify it raises an exception
        with tempfile.NamedTemporaryFile() as temp_file:
            with pytest.raises(BuildError, match="Failed to sign artifacts"):
                sign_artifacts([Path(temp_file.name)], "build-123", SigningMode.TEST)


class TestCreateBuildManifest:
    """Tests for the create_build_manifest function."""

    @patch("dependency_risk_profiler.secure_release.release_build.subprocess.run")
    def test_create_build_manifest_success(self, mock_run: Mock) -> None:
        """Verify that create_build_manifest creates a manifest with artifact information."""
        # Setup mocks
        mock_process = Mock()
        mock_process.stdout = "abcdef1234567890 filename\n"
        mock_run.return_value = mock_process
        
        # Setup test data
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create a test artifact
            artifact_path = temp_path / "package-1.0.0.tar.gz"
            with open(artifact_path, "w") as f:
                f.write("fake artifact")
            
            # Setup test data
            artifacts = [artifact_path]
            signatures = {artifact_path: {"timestamp": "2023-01-15T12:00:00Z", "mode": "TEST"}}
            build_env = {"BUILD_ID": "build-123", "BUILD_TIMESTAMP": "2023-01-15T12:00:00Z"}
            manifest_path = temp_path / "manifest.json"
            
            # Call the function
            result = create_build_manifest(artifacts, signatures, build_env, manifest_path)
            
            # Verify the result
            assert result == manifest_path
            assert manifest_path.exists()
            
            # Verify manifest contents
            with open(manifest_path, "r") as f:
                manifest = json.load(f)
                
                assert manifest["build_id"] == "build-123"
                assert manifest["build_timestamp"] == "2023-01-15T12:00:00Z"
                assert len(manifest["artifacts"]) == 1
                
                artifact_info = manifest["artifacts"][0]
                assert artifact_info["path"] == str(artifact_path)
                assert artifact_info["name"] == "package-1.0.0.tar.gz"
                assert artifact_info["size"] > 0
                assert "sha256" in artifact_info
                assert "signature" in artifact_info
                assert artifact_info["signature"]["timestamp"] == "2023-01-15T12:00:00Z"

    def test_create_build_manifest_failure(self) -> None:
        """Verify that create_build_manifest raises a BuildError when an exception occurs."""
        # Set up a scenario that will cause an exception
        artifacts = [Path("nonexistent/file.txt")]
        signatures: Dict[Path, Dict[str, str]] = {}
        build_env: Dict[str, str] = {}
        
        # Call the function and verify it raises an exception
        with pytest.raises(BuildError, match="Failed to create build manifest"):
            create_build_manifest(artifacts, signatures, build_env, "manifest.json")


class TestRunBuildProcess:
    """Tests for the run_build_process function."""

    @patch("dependency_risk_profiler.secure_release.release_build.tempfile.TemporaryDirectory")
    @patch("dependency_risk_profiler.secure_release.release_build.setup_build_environment")
    @patch("dependency_risk_profiler.secure_release.release_build.fetch_latest_code")
    @patch("dependency_risk_profiler.secure_release.release_build.run_tests")
    @patch("dependency_risk_profiler.secure_release.release_build.build_package")
    @patch("dependency_risk_profiler.secure_release.release_build.scan_artifacts")
    @patch("dependency_risk_profiler.secure_release.release_build.sign_artifacts")
    @patch("dependency_risk_profiler.secure_release.release_build.create_build_manifest")
    @patch("dependency_risk_profiler.secure_release.release_build.create_release")
    def test_run_build_process_success(
        self, 
        mock_create_release: Mock,
        mock_create_manifest: Mock,
        mock_sign_artifacts: Mock,
        mock_scan_artifacts: Mock,
        mock_build_package: Mock,
        mock_run_tests: Mock,
        mock_fetch_code: Mock,
        mock_setup_env: Mock,
        mock_temp_dir: Mock
    ) -> None:
        """Verify that run_build_process runs the full build process successfully."""
        # Setup mocks
        mock_setup_env.return_value = {
            "BUILD_ID": "build-123",
            "BUILD_TIMESTAMP": "2023-01-15T12:00:00Z"
        }
        
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/build-123"
        mock_fetch_code.return_value = Path("/tmp/build-123/repo")
        mock_run_tests.return_value = True
        
        # Setup artifacts
        sdist_path = Path("/output/package-1.0.0.tar.gz")
        wheel_path = Path("/output/package-1.0.0-py3-none-any.whl")
        mock_build_package.return_value = (sdist_path, wheel_path)
        
        mock_scan_artifacts.return_value = True
        mock_sign_artifacts.return_value = {
            sdist_path: {"timestamp": "2023-01-15T12:00:00Z", "mode": "TEST"},
            wheel_path: {"timestamp": "2023-01-15T12:00:00Z", "mode": "TEST"}
        }
        
        manifest_path = Path("/output/build-manifest-build-123.json")
        mock_create_manifest.return_value = manifest_path
        
        mock_create_release.return_value = {
            "version": "1.0.0",
            "build_id": "build-123",
            "artifact": "/output/release-1.0.0.zip",
            "checksum": "abcdef1234567890",
            "release_notes": "/output/release-notes-1.0.0.md",
            "metadata": "/output/release-1.0.0.json"
        }
        
        # Call the function
        with tempfile.TemporaryDirectory() as output_dir:
            result = run_build_process(
                "https://github.com/org/repo.git",
                "main",
                output_dir,
                BuildMode.DEVELOPMENT,
                VersionBumpType.PATCH,
                False
            )
            
            # Verify the result is a dict with expected keys
            assert isinstance(result, dict)
            assert result["build_id"] == "build-123"
            assert result["build_timestamp"] == "2023-01-15T12:00:00Z"
            assert len(result["artifacts"]) == 2
            assert str(sdist_path) in result["artifacts"]
            assert str(wheel_path) in result["artifacts"]
            
            # The manifest path might be in a temporary directory, so just check the filename
            assert "build-manifest-build-123.json" in result["manifest"]
            
            # Verify the calls to the different functions
            mock_fetch_code.assert_called_once()
            mock_run_tests.assert_called_once()
            mock_build_package.assert_called_once()
            mock_scan_artifacts.assert_called_once()
            mock_sign_artifacts.assert_called_once()
            mock_create_manifest.assert_called_once()
            mock_create_release.assert_called_once()

    @patch("dependency_risk_profiler.secure_release.release_build.tempfile.TemporaryDirectory")
    @patch("dependency_risk_profiler.secure_release.release_build.setup_build_environment")
    @patch("dependency_risk_profiler.secure_release.release_build.fetch_latest_code")
    @patch("dependency_risk_profiler.secure_release.release_build.run_tests")
    def test_run_build_process_test_failure(
        self, 
        mock_run_tests: Mock,
        mock_fetch_code: Mock,
        mock_setup_env: Mock,
        mock_temp_dir: Mock
    ) -> None:
        """Verify that run_build_process raises a BuildError when tests fail."""
        # Setup mocks
        mock_setup_env.return_value = {
            "BUILD_ID": "build-123",
            "BUILD_TIMESTAMP": "2023-01-15T12:00:00Z"
        }
        
        mock_temp_dir.return_value.__enter__.return_value = "/tmp/build-123"
        mock_fetch_code.return_value = Path("/tmp/build-123/repo")
        mock_run_tests.return_value = False  # Tests fail
        
        # Call the function and verify it raises an exception
        with tempfile.TemporaryDirectory() as output_dir:
            with pytest.raises(BuildError, match="Tests failed"):
                run_build_process(
                    "https://github.com/org/repo.git",
                    "main",
                    output_dir,
                    BuildMode.DEVELOPMENT,
                    VersionBumpType.PATCH,
                    False
                )