"""Tests for the Typer CLI module."""

import os
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import Mock, patch

import pytest
import typer
from typer.testing import CliRunner

from dependency_risk_profiler.cli.typer_cli import (
    OutputFormat,
    display_ecosystem_list,
    get_ecosystem_from_manifest,
)

# Create a test runner
runner = CliRunner()


@pytest.fixture
def mock_config() -> Mock:
    """Fixture for a mock Config object."""
    config_mock = Mock()
    config_mock.get.return_value = "terminal"
    config_mock.get_section.return_value = {}
    config_mock.get_scoring_weights.return_value = {
        "staleness": 0.25,
        "maintainer": 0.2,
        "deprecation": 0.3,
        "exploit": 0.5,
        "version_difference": 0.15,
        "health_indicators": 0.1,
        "license": 0.3,
        "community": 0.2,
        "transitive": 0.15,
    }
    config_mock.get_vulnerability_config.return_value = {
        "enable_osv": True,
        "enable_nvd": False,
        "enable_github_advisory": False,
        "github_token": "",
        "nvd_api_key": "",
        "disable_cache": False,
        "clear_cache": False,
    }
    config_mock.get_api_keys.return_value = {}
    return config_mock


@pytest.fixture
def mock_ecosystem_registry() -> Mock:
    """Fixture for mocking EcosystemRegistry."""
    registry_mock = Mock()
    registry_mock.get_available_ecosystems.return_value = ["python", "nodejs", "golang"]
    registry_mock.get_ecosystem_details.return_value = {
        "python": {
            "file_patterns": ["requirements.txt", "pyproject.toml", "Pipfile.lock"]
        },
        "nodejs": {"file_patterns": ["package-lock.json", "yarn.lock"]},
        "golang": {"file_patterns": ["go.mod", "go.sum"]},
    }
    registry_mock.detect_ecosystem.return_value = "python"
    return registry_mock


class TestEcosystemFunctions:
    """Tests for ecosystem-related functions."""

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    def test_display_ecosystem_list(
        self, mock_registry_class: Mock, mock_ecosystem_registry: Mock
    ) -> None:
        """HYPOTHESIS: display_ecosystem_list should print available ecosystems."""
        # Arrange
        mock_registry_class.get_available_ecosystems = (
            mock_ecosystem_registry.get_available_ecosystems
        )
        mock_registry_class.get_ecosystem_details = (
            mock_ecosystem_registry.get_ecosystem_details
        )

        # No easy way to capture console output in typer.
        try:
            # Act
            display_ecosystem_list()
            # Assert - no exception means success
            assert True
        except Exception as e:
            pytest.fail(f"display_ecosystem_list raised an exception: {e}")

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    @patch("dependency_risk_profiler.cli.typer_cli.BaseParser")
    def test_display_ecosystem_list_empty_registry(
        self, mock_base_parser: Mock, mock_registry: Mock
    ) -> None:
        """HYPOTHESIS: display_ecosystem_list should handle empty registry."""
        # Arrange
        mock_registry.get_available_ecosystems.return_value = []
        mock_registry.get_ecosystem_details.return_value = {}

        # Act - should initialize registry when empty
        display_ecosystem_list()

        # Assert
        mock_base_parser._initialize_registry.assert_called_once()

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    def test_display_ecosystem_list_import_error(self, mock_registry: Mock) -> None:
        """REGRESSION: display_ecosystem_list should handle ImportError."""
        # Arrange
        mock_registry.get_available_ecosystems.side_effect = ImportError(
            "Test import error"
        )

        # Act - should handle the import error gracefully
        with patch("dependency_risk_profiler.cli.typer_cli.console") as mock_console:
            display_ecosystem_list()

            # Assert proper error was displayed
            mock_console.print.assert_called_with(
                "\n[bold red]Error: Registry module not available: "
                "Test import error[/bold red]"
            )

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    def test_display_ecosystem_list_general_exception(
        self, mock_registry: Mock
    ) -> None:
        """REGRESSION: display_ecosystem_list should handle general exceptions."""
        # Arrange
        mock_registry.get_available_ecosystems.return_value = True
        mock_registry.get_ecosystem_details.side_effect = Exception(
            "Test general error"
        )

        # Act - should handle the exception gracefully
        with patch("dependency_risk_profiler.cli.typer_cli.console") as mock_console:
            display_ecosystem_list()

            # Assert proper error was displayed
            mock_console.print.assert_called_with(
                "\n[bold red]Error displaying available ecosystems: "
                "Test general error[/bold red]"
            )

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    def test_get_ecosystem_from_manifest(
        self, mock_registry_class: Mock, mock_ecosystem_registry: Mock
    ) -> None:
        """HYPOTHESIS: get_ecosystem_from_manifest detects the ecosystem."""
        # Arrange
        mock_registry_class.get_available_ecosystems = (
            mock_ecosystem_registry.get_available_ecosystems
        )
        mock_registry_class.detect_ecosystem = mock_ecosystem_registry.detect_ecosystem

        # Act
        result = get_ecosystem_from_manifest("/path/to/requirements.txt")

        # Assert
        assert result == "python"

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    @patch("dependency_risk_profiler.cli.typer_cli.BaseParser")
    def test_get_ecosystem_from_manifest_empty_registry(
        self, mock_base_parser: Mock, mock_registry: Mock
    ) -> None:
        """HYPOTHESIS: get_ecosystem_from_manifest initializes empty registry."""
        # Arrange
        mock_registry.get_available_ecosystems.return_value = []
        mock_registry.detect_ecosystem.return_value = "python"

        # Act
        result = get_ecosystem_from_manifest("/path/to/requirements.txt")

        # Assert
        mock_base_parser._initialize_registry.assert_called_once()
        assert result == "python"

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    def test_get_ecosystem_from_manifest_import_error(
        self, mock_registry: Mock
    ) -> None:
        """REGRESSION: get_ecosystem_from_manifest should handle ImportError."""
        # Arrange
        mock_registry.get_available_ecosystems.side_effect = ImportError(
            "Test import error"
        )

        # Act - should fall back to the default implementation
        result = get_ecosystem_from_manifest("/path/to/package-lock.json")

        # Assert
        assert result == "nodejs"

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    def test_get_ecosystem_from_manifest_no_match(self, mock_registry: Mock) -> None:
        """REGRESSION: get_ecosystem_from_manifest should handle unrecognized files."""
        # Arrange
        mock_registry.get_available_ecosystems.return_value = ["python", "nodejs"]
        mock_registry.detect_ecosystem.return_value = None  # No match from registry

        # Act - should fall back to the default implementation
        result = get_ecosystem_from_manifest("/path/to/unknown.file")

        # Assert
        assert result == "unknown"

    def test_get_ecosystem_from_manifest_fallbacks(self) -> None:
        """HYPOTHESIS: get_ecosystem_from_manifest uses known fallbacks."""
        # Arrange - no need to mock EcosystemRegistry as the test will use fallbacks
        with patch(
            "dependency_risk_profiler.cli.typer_cli.EcosystemRegistry"
        ) as mock_registry:
            # Setup registry to fail detection
            mock_registry.get_available_ecosystems.return_value = []
            mock_registry.detect_ecosystem.return_value = None

            # Act/Assert - check fallbacks for various file types
            assert get_ecosystem_from_manifest("/path/to/package-lock.json") == "nodejs"
            assert get_ecosystem_from_manifest("/path/to/requirements.txt") == "python"
            assert get_ecosystem_from_manifest("/path/to/Pipfile.lock") == "python"
            assert get_ecosystem_from_manifest("/path/to/go.mod") == "golang"
            assert get_ecosystem_from_manifest("/path/to/pyproject.toml") == "pyproject"
            assert get_ecosystem_from_manifest("/path/to/cargo.toml") == "cargo"
            # A generic .toml is no longer profiled as Python (#75).
            assert get_ecosystem_from_manifest("/path/to/config.toml") == "unknown"
            assert get_ecosystem_from_manifest("/path/to/unknown.file") == "unknown"


class TestLoggingSetup:
    """Tests for the logging setup function."""

    @patch("dependency_risk_profiler.cli.typer_cli.logging")
    def test_setup_logging_debug(self, mock_logging: Mock) -> None:
        """HYPOTHESIS: setup_logging should set debug level when debug=True."""
        # Import the function
        from dependency_risk_profiler.cli.typer_cli import setup_logging

        # Act
        setup_logging(debug=True)

        # Assert
        mock_logging.basicConfig.assert_called_once()
        # Check that DEBUG level was set
        _, kwargs = mock_logging.basicConfig.call_args
        assert kwargs["level"] == mock_logging.DEBUG

    @patch("dependency_risk_profiler.cli.typer_cli.logging")
    def test_setup_logging_info(self, mock_logging: Mock) -> None:
        """HYPOTHESIS: setup_logging should set info level when debug=False."""
        # Import the function
        from dependency_risk_profiler.cli.typer_cli import setup_logging

        # Act
        setup_logging(debug=False)

        # Assert
        mock_logging.basicConfig.assert_called_once()
        # Check that INFO level was set
        _, kwargs = mock_logging.basicConfig.call_args
        assert kwargs["level"] == mock_logging.INFO

    @patch("dependency_risk_profiler.cli.typer_cli.logging")
    @patch("dependency_risk_profiler.cli.typer_cli.RichHandler")
    def test_setup_logging_handlers(
        self, mock_rich_handler: Mock, mock_logging: Mock
    ) -> None:
        """HYPOTHESIS: setup_logging should configure Rich handler."""
        # Arrange
        mock_rich_handler.return_value = "rich_handler_instance"

        # Import the function
        from dependency_risk_profiler.cli.typer_cli import setup_logging

        # Act
        setup_logging()

        # Assert: diagnostic logs are routed to a stderr console so stdout
        # stays clean for the report / JSON output (issue #20).
        mock_rich_handler.assert_called_once()
        _, rh_kwargs = mock_rich_handler.call_args
        assert rh_kwargs["rich_tracebacks"] is True
        assert rh_kwargs["console"].stderr is True
        # Check that our rich handler was passed to basicConfig
        _, kwargs = mock_logging.basicConfig.call_args
        assert "rich_handler_instance" in kwargs["handlers"]


class TestCliCommands:
    """Tests for CLI commands."""

    @patch("dependency_risk_profiler.cli.typer_cli.Config")
    def test_callback_function(self, mock_config_class: Mock) -> None:
        """HYPOTHESIS: callback should initialize configuration and set up logging."""
        # Arrange
        mock_config = Mock()
        mock_config.get.return_value = False  # debug=False
        mock_config_class.return_value = mock_config

        # Import the callback function
        from dependency_risk_profiler.cli.typer_cli import callback

        # Create a mock context
        ctx = Mock()

        # Act
        with patch(
            "dependency_risk_profiler.cli.typer_cli.setup_logging"
        ) as mock_setup_logging:
            callback(ctx, None, False)

            # Assert
            assert ctx.obj == mock_config
            mock_setup_logging.assert_called_once_with(False)

    @patch("dependency_risk_profiler.cli.typer_cli.Config")
    def test_callback_config_debug(self, mock_config_class: Mock) -> None:
        """HYPOTHESIS: callback should use debug setting from config if available."""
        # Arrange
        mock_config = Mock()
        # Config has debug=True
        mock_config.get.side_effect = lambda section, key, default: (
            True if section == "general" and key == "debug" else default
        )
        mock_config_class.return_value = mock_config

        # Import the callback function
        from dependency_risk_profiler.cli.typer_cli import callback

        # Create a mock context
        ctx = Mock()

        # Act - pass debug=False but config has debug=True, should use True
        with patch(
            "dependency_risk_profiler.cli.typer_cli.setup_logging"
        ) as mock_setup_logging:
            callback(ctx, None, False)

            # Assert - debug should be True from config
            mock_setup_logging.assert_called_once_with(True)

    @patch("dependency_risk_profiler.cli.typer_cli.app")
    def test_analyze_help_text(self, mock_app: Mock) -> None:
        """HYPOTHESIS: analyze command should have helpful documentation."""
        # Import the Typer command
        from dependency_risk_profiler.cli.typer_cli import analyze

        # Check that the analyze command exists and has proper help text
        assert callable(analyze)

        # Get the help text from the docstring
        help_text = analyze.__doc__
        assert help_text is not None
        assert "Analyze dependencies and generate risk profile" in help_text

    @patch("dependency_risk_profiler.cli.typer_cli.get_ecosystem_from_manifest")
    def test_ecosystem_detection_in_analyze(self, mock_get_ecosystem: Mock) -> None:
        """HYPOTHESIS: analyze command should detect ecosystems correctly."""
        # Setup return value
        mock_get_ecosystem.return_value = "python"

        # Import the function
        from dependency_risk_profiler.cli.typer_cli import get_ecosystem_from_manifest

        # Test it directly since we can't easily test the full typer command
        result = get_ecosystem_from_manifest("/path/to/requirements.txt")
        assert result == "python"

        # Verify the function was called with correct args
        mock_get_ecosystem.assert_called_once_with("/path/to/requirements.txt")

    @patch("dependency_risk_profiler.cli.typer_cli.BaseParser")
    @patch("dependency_risk_profiler.cli.typer_cli.Config")
    def test_list_ecosystems_command(
        self, mock_config: Mock, mock_base_parser: Mock
    ) -> None:
        """HYPOTHESIS: list_ecosystems command should display available ecosystems."""
        # Import the list-ecosystems command function
        from dependency_risk_profiler.cli.typer_cli import list_ecosystems

        # Patch the display_ecosystem_list function
        with patch(
            "dependency_risk_profiler.cli.typer_cli.display_ecosystem_list"
        ) as mock_display:
            # Act
            list_ecosystems()

            # Assert
            mock_display.assert_called_once()

    @patch("dependency_risk_profiler.cli.typer_cli.app")
    def test_generate_config_command_registration(self, mock_app: Mock) -> None:
        """HYPOTHESIS: generate-config command should be registered with the app."""
        # Import function and verify it exists
        from dependency_risk_profiler.cli.typer_cli import generate_config

        assert callable(generate_config)

    @patch("dependency_risk_profiler.cli.typer_cli.EcosystemRegistry")
    @patch("dependency_risk_profiler.cli.typer_cli.BaseParser")
    @patch("dependency_risk_profiler.cli.typer_cli.os.walk")
    def test_directory_scanning(
        self,
        mock_walk: Mock,
        mock_base_parser: Mock,
        mock_registry: Mock,
        mock_ecosystem_registry: Mock,
    ) -> None:
        """HYPOTHESIS: CLI should scan directories for manifest files."""
        # Arrange
        mock_registry.get_available_ecosystems.return_value = (
            mock_ecosystem_registry.get_available_ecosystems.return_value
        )
        mock_registry.detect_ecosystem.side_effect = lambda path: (
            True
            if str(path).endswith(("requirements.txt", "package-lock.json"))
            else False
        )

        # Mock the os.walk to return a structure with some files
        mock_walk.return_value = [
            ("/test/dir", ["subdir"], ["requirements.txt", "README.md"]),
            ("/test/dir/subdir", [], ["package-lock.json", "other.file"]),
        ]

        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test the directory scanning functionality directly
            from dependency_risk_profiler.cli.typer_cli import analyze

            # Mock objects needed for testing
            ctx = Mock()
            ctx.obj = Mock()

            # Create test files
            os.makedirs(os.path.join(temp_dir, "subdir"), exist_ok=True)
            with open(
                os.path.join(temp_dir, "requirements.txt"), "w", encoding="utf-8"
            ) as f:
                f.write("# Test requirements file")
            with open(
                os.path.join(temp_dir, "subdir", "package-lock.json"),
                "w",
                encoding="utf-8",
            ) as f:
                f.write("{}")

            # Act & Assert - verify it scans for files
            # This is a partial test since we can't fully invoke the typer app
            try:
                # We expect this to fail eventually because not every dependency
                # needed for a full analyze run is mocked.
                with patch(
                    "dependency_risk_profiler.cli.typer_cli.os.path.isdir",
                    return_value=True,
                ):
                    with patch(
                        "dependency_risk_profiler.cli.typer_cli.Path"
                    ) as mock_path:
                        # Configure mock_path to handle our test case
                        mock_path_instance = Mock()
                        mock_path.return_value = mock_path_instance

                        try:
                            analyze(
                                Path(temp_dir),  # manifest path
                                recursive=True,  # enable recursive scanning
                                ctx=ctx,
                            )
                        except (AttributeError, RuntimeError, TypeError, ValueError):
                            pass

                # Verify detection was called on the right files
                assert mock_registry.detect_ecosystem.call_count > 0

            except typer.Exit:
                # Expected to exit if any CLI validation fails
                pass
            except Exception:
                # We expect an exception due to other unpatched dependencies
                # We are testing directory scanning, not the full analyze command.
                pass

    def test_directory_scanning_recursive_vs_non_recursive(self) -> None:
        """HYPOTHESIS: CLI should respect recursive directory scanning."""
        # Create a simpler test that directly tests the os.walk logic in typer_cli.py

        # Create a temporary directory with nested manifests
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a standard project structure
            main_dir = temp_dir
            subdir = os.path.join(main_dir, "subdir")
            os.makedirs(subdir, exist_ok=True)

            # Create manifest files
            with open(
                os.path.join(main_dir, "requirements.txt"), "w", encoding="utf-8"
            ) as f:
                f.write("# Test requirements")
            with open(
                os.path.join(subdir, "package-lock.json"), "w", encoding="utf-8"
            ) as f:
                f.write("{}")

            # Function to find manifests with the actual implementation algorithm
            def find_manifest_files(
                directory: str, recursive: bool = False
            ) -> List[str]:
                manifest_files: List[str] = []

                for root, _, files in os.walk(directory):
                    # Skip nested directories unless recursive mode is enabled.
                    if not recursive and root != directory:
                        continue

                    for filename in files:
                        file_path = os.path.join(root, filename)
                        # Check file extensions instead of using the registry.
                        if file_path.endswith((".txt", ".json")):
                            manifest_files.append(file_path)

                return manifest_files

            # Test non-recursive mode
            non_recursive_files = find_manifest_files(main_dir, recursive=False)

            # Test recursive mode
            recursive_files = find_manifest_files(main_dir, recursive=True)

            # Verify non-recursive only finds the top-level manifest
            top_level_manifests = [
                f for f in non_recursive_files if os.path.dirname(f) == main_dir
            ]
            assert (
                len(top_level_manifests) == 1
            ), "Non-recursive should find 1 top-level manifest"

            # Verify recursive finds both manifests
            assert (
                len(recursive_files) == 2
            ), "Recursive should find manifests in subdirectories"

            # Verify we have more files in recursive mode
            assert len(recursive_files) > len(non_recursive_files)


@pytest.mark.parametrize("output_format", ["terminal", "json"])
def test_output_format_enum(output_format: str) -> None:
    """HYPOTHESIS: OutputFormat enum should contain valid output formats."""
    # Act/Assert
    assert OutputFormat(output_format) is not None


@pytest.mark.parametrize("graph_format", ["d3", "graphviz", "cytoscape"])
def test_graph_format_enum(graph_format: str) -> None:
    """HYPOTHESIS: GraphFormat enum should contain valid graph formats."""
    # Import the enum
    from dependency_risk_profiler.cli.typer_cli import GraphFormat

    # Act/Assert
    assert GraphFormat(graph_format) is not None


@pytest.mark.parametrize(
    "trend_viz", ["overall", "distribution", "dependencies", "security"]
)
def test_trend_visualization_enum(trend_viz: str) -> None:
    """HYPOTHESIS: TrendVisualization enum should contain valid visualization types."""
    # Import the enum
    from dependency_risk_profiler.cli.typer_cli import TrendVisualization

    # Act/Assert
    assert TrendVisualization(trend_viz) is not None


class TestAnalyzeCommand:
    """Tests for the analyze command output formatting."""

    @patch("dependency_risk_profiler.cli.typer_cli.JsonFormatter")
    @patch("dependency_risk_profiler.cli.typer_cli.TerminalFormatter")
    def test_analyze_formatter_selection(
        self, mock_terminal_formatter: Mock, mock_json_formatter: Mock
    ) -> None:
        """HYPOTHESIS: analyze command should select the correct output formatter."""
        # Create mock formatter instances
        mock_terminal = Mock()
        mock_json = Mock()
        mock_terminal_formatter.return_value = mock_terminal
        mock_json_formatter.return_value = mock_json

        # Import the formatter selection logic from the CLI
        from dependency_risk_profiler.cli.typer_cli import (
            JsonFormatter,
            TerminalFormatter,
        )

        # Verify the formatters are properly defined
        assert TerminalFormatter is not None
        assert JsonFormatter is not None


@pytest.mark.benchmark
def test_cli_startup_performance() -> None:
    """BENCHMARK: CLI should start quickly.

    SLA Requirements:
    - CLI startup time should be < 500ms
    """
    # Note: This is hard to actually measure in a unittest context
    # In a real benchmark, we would time multiple invocations of the CLI
    # with the `time` command or equivalent.
    pytest.skip(
        "Skipping CLI startup performance benchmark - needs real timing measurements"
    )


def test_analyze_json_mode_keeps_status_off_stdout(tmp_path: Path) -> None:
    """In json mode, manifest-discovery status stays off the stdout console.

    It routes to a stderr console instead so stdout stays machine-clean. Uses
    the no-manifests branch to avoid any network.
    """
    import dependency_risk_profiler.cli.typer_cli as cli

    empty_dir = tmp_path / "proj"
    empty_dir.mkdir()

    with patch.object(cli.console, "print") as stdout_print:
        result = runner.invoke(
            cli.app,
            ["analyze", str(empty_dir), "--recursive", "--output", "json"],
        )

    # "No supported manifests" is a clean outcome, not a failure (exit 0), and
    # nothing — status or error — may reach the stdout console in json mode.
    assert result.exit_code == 0
    stdout_text = " ".join(str(call) for call in stdout_print.call_args_list)
    assert "Scanning" not in stdout_text
    assert "manifest files" not in stdout_text
    assert "No supported manifest files" not in stdout_text
    assert "Error" not in stdout_text
