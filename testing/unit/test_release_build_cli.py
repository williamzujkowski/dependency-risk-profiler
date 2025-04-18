"""Tests for the release_build command-line interface."""

import argparse
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, patch

import pytest

from dependency_risk_profiler.secure_release.release_build import (
    BuildMode,
    BuildError,
    main,
)
from dependency_risk_profiler.secure_release.release_management import VersionBumpType


class TestMain:
    """Tests for the main function."""

    @patch("dependency_risk_profiler.secure_release.release_build.argparse.ArgumentParser.parse_args")
    @patch("dependency_risk_profiler.secure_release.release_build.run_build_process")
    def test_main_success(self, mock_run_build_process: Mock, mock_parse_args: Mock) -> None:
        """Test that the main function successfully processes command line arguments."""
        # Setup mock arguments
        args = Mock()
        args.repo = "https://github.com/org/repo.git"
        args.branch = "main"
        args.output_dir = "./dist"
        args.mode = "development"
        args.version_bump = "patch"
        args.artifacts_only = False
        args.debug = False
        mock_parse_args.return_value = args
        
        # Setup mock build process
        mock_run_build_process.return_value = {
            "build_id": "build-123",
            "build_timestamp": "2023-01-15T12:00:00Z",
            "artifacts": ["/path/to/artifact1.tar.gz", "/path/to/artifact2.whl"],
            "manifest": "/path/to/manifest.json",
            "log": "/path/to/log.txt",
            "signing_log": "/path/to/signing_log.txt",
        }
        
        # Call the function
        with patch("dependency_risk_profiler.secure_release.release_build.print") as mock_print:
            result = main()
        
        # Verify the result
        assert result == 0
        
        # Verify the correct arguments were passed
        mock_run_build_process.assert_called_once_with(
            "https://github.com/org/repo.git",
            "main",
            "./dist",
            BuildMode.DEVELOPMENT,
            VersionBumpType.PATCH,
            False,
        )
        
        # Verify output was printed
        assert mock_print.call_count > 0
        success_message_found = False
        for call in mock_print.call_args_list:
            args, _ = call
            if args and "✅ Build completed successfully!" in args[0]:
                success_message_found = True
                break
        assert success_message_found, "Success message not found in output"

    @patch("dependency_risk_profiler.secure_release.release_build.argparse.ArgumentParser.parse_args")
    @patch("dependency_risk_profiler.secure_release.release_build.run_build_process")
    def test_main_staging_mode(self, mock_run_build_process: Mock, mock_parse_args: Mock) -> None:
        """Test that the main function correctly handles staging mode."""
        # Setup mock arguments
        args = Mock()
        args.repo = "https://github.com/org/repo.git"
        args.branch = "main"
        args.output_dir = "./dist"
        args.mode = "staging"  # Test staging mode
        args.version_bump = "minor"  # Test minor version bump
        args.artifacts_only = False
        args.debug = False
        mock_parse_args.return_value = args
        
        # Setup mock build process
        mock_run_build_process.return_value = {
            "build_id": "build-123",
            "build_timestamp": "2023-01-15T12:00:00Z",
            "artifacts": ["/path/to/artifact.tar.gz"],
            "manifest": "/path/to/manifest.json",
            "log": "/path/to/log.txt",
            "signing_log": "/path/to/signing_log.txt",
        }
        
        # Call the function
        with patch("dependency_risk_profiler.secure_release.release_build.print"):
            result = main()
        
        # Verify the result
        assert result == 0
        
        # Verify the correct mode was passed
        mock_run_build_process.assert_called_once_with(
            "https://github.com/org/repo.git",
            "main",
            "./dist",
            BuildMode.STAGING,  # Should be STAGING mode
            VersionBumpType.MINOR,  # Should be MINOR version bump
            False,
        )

    @patch("dependency_risk_profiler.secure_release.release_build.argparse.ArgumentParser.parse_args")
    @patch("dependency_risk_profiler.secure_release.release_build.run_build_process")
    def test_main_production_mode(self, mock_run_build_process: Mock, mock_parse_args: Mock) -> None:
        """Test that the main function correctly handles production mode."""
        # Setup mock arguments
        args = Mock()
        args.repo = "https://github.com/org/repo.git"
        args.branch = "main"
        args.output_dir = "./dist"
        args.mode = "production"  # Test production mode
        args.version_bump = "major"  # Test major version bump
        args.artifacts_only = True  # Test artifacts_only flag
        args.debug = True  # Test debug flag
        mock_parse_args.return_value = args
        
        # Setup mock build process
        mock_run_build_process.return_value = {
            "build_id": "build-123",
            "build_timestamp": "2023-01-15T12:00:00Z",
            "artifacts": ["/path/to/artifact.tar.gz"],
            "manifest": "/path/to/manifest.json",
            "log": "/path/to/log.txt",
            "signing_log": "/path/to/signing_log.txt",
        }
        
        # Call the function
        with patch("dependency_risk_profiler.secure_release.release_build.print"):
            with patch("dependency_risk_profiler.secure_release.release_build.logging.basicConfig") as mock_logging:
                result = main()
        
        # Verify the result
        assert result == 0
        
        # Verify the correct mode was passed
        mock_run_build_process.assert_called_once_with(
            "https://github.com/org/repo.git",
            "main",
            "./dist",
            BuildMode.PRODUCTION,  # Should be PRODUCTION mode
            VersionBumpType.MAJOR,  # Should be MAJOR version bump
            True,  # Should be artifacts_only True
        )
        
        # Verify logging was set to DEBUG
        mock_logging.assert_called_once()
        _, kwargs = mock_logging.call_args
        assert kwargs.get("level") == pytest.approx(10)  # DEBUG is 10

    @patch("dependency_risk_profiler.secure_release.release_build.argparse.ArgumentParser.parse_args")
    @patch("dependency_risk_profiler.secure_release.release_build.run_build_process")
    def test_main_build_error(self, mock_run_build_process: Mock, mock_parse_args: Mock) -> None:
        """Test that the main function handles BuildError properly."""
        # Setup mock arguments
        args = Mock()
        args.repo = "https://github.com/org/repo.git"
        args.branch = "main"
        args.output_dir = "./dist"
        args.mode = "development"
        args.version_bump = "patch"
        args.artifacts_only = False
        args.debug = False
        mock_parse_args.return_value = args
        
        # Setup mock build process to raise an error
        mock_run_build_process.side_effect = BuildError("Test build error")
        
        # Call the function
        with patch("dependency_risk_profiler.secure_release.release_build.print") as mock_print:
            result = main()
        
        # Verify the result
        assert result == 1
        
        # Verify error message was printed
        error_message_found = False
        for call in mock_print.call_args_list:
            args, _ = call
            if args and "❌ Build failed: Test build error" in args[0]:
                error_message_found = True
                break
        assert error_message_found, "Error message not found in output"

    @patch("dependency_risk_profiler.secure_release.release_build.argparse.ArgumentParser.parse_args")
    @patch("dependency_risk_profiler.secure_release.release_build.run_build_process")
    def test_main_unexpected_error(self, mock_run_build_process: Mock, mock_parse_args: Mock) -> None:
        """Test that the main function handles unexpected errors properly."""
        # Setup mock arguments
        args = Mock()
        args.repo = "https://github.com/org/repo.git"
        args.branch = "main"
        args.output_dir = "./dist"
        args.mode = "development"
        args.version_bump = "patch"
        args.artifacts_only = False
        args.debug = False
        mock_parse_args.return_value = args
        
        # Setup mock build process to raise an unexpected error
        mock_run_build_process.side_effect = ValueError("Unexpected error")
        
        # Call the function
        with patch("dependency_risk_profiler.secure_release.release_build.print") as mock_print:
            result = main()
        
        # Verify the result
        assert result == 1
        
        # Verify error message was printed
        error_message_found = False
        for call in mock_print.call_args_list:
            args, _ = call
            if args and "❌ Build failed: Unexpected error" in args[0]:
                error_message_found = True
                break
        assert error_message_found, "Error message not found in output"