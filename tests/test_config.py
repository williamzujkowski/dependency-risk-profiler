"""Tests for the config module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from dependency_risk_profiler.config import Config, get_config


class TestConfig:
    """Tests for the Config class."""

    def test_default_config_values(self):
        """HYPOTHESIS: Config should have default values when initialized without a file."""
        # Act
        config = Config()

        # Assert
        assert config.get("general", "output_format") == "terminal"
        assert config.get("scoring_weights", "staleness") == 0.25
        assert config.get("vulnerability", "enable_osv") is True
        assert config.get("trends", "limit") == 10
        assert config.get("graph", "format") == "d3"

    def test_load_toml_config(self):
        """HYPOTHESIS: Config should load values from TOML file."""
        # Arrange
        with tempfile.NamedTemporaryFile(
            suffix=".toml", mode="w", delete=False
        ) as temp_file:
            temp_file.write(
                """
[general]
output_format = "json"
use_color = false
debug = true

[scoring_weights]
staleness = 0.5
maintainer = 0.3
            """
            )
            temp_file_path = temp_file.name

        try:
            # Act
            config = Config(temp_file_path)

            # Assert
            assert config.config_file_loaded is True
            assert config.get("general", "output_format") == "json"
            assert config.get("general", "use_color") is False
            assert config.get("general", "debug") is True
            assert config.get("scoring_weights", "staleness") == 0.5
            assert config.get("scoring_weights", "maintainer") == 0.3
            # Default values should still be present for unspecified settings
            assert config.get("scoring_weights", "deprecation") == 0.3
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)

    def test_load_yaml_config(self):
        """HYPOTHESIS: Config should load values from YAML file."""
        # Arrange
        with tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="w", delete=False
        ) as temp_file:
            config_data = {
                "general": {"output_format": "json", "use_color": False},
                "vulnerability": {"enable_nvd": True, "cache_expiry": 43200},
                # Add scoring_weights explicitly to avoid values from default config
                "scoring_weights": {"staleness": 0.25},
            }
            yaml.dump(config_data, temp_file)
            temp_file_path = temp_file.name

        try:
            # Act
            config = Config(temp_file_path)

            # Assert
            assert config.config_file_loaded is True
            assert config.get("general", "output_format") == "json"
            assert config.get("general", "use_color") is False
            assert config.get("vulnerability", "enable_nvd") is True
            assert config.get("vulnerability", "cache_expiry") == 43200
            # Default values should still be present for unspecified settings
            assert config.get("scoring_weights", "staleness") == 0.25
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)

    def test_load_from_env_variables(self):
        """HYPOTHESIS: Config should load values from environment variables."""
        # Arrange
        with patch.dict(
            os.environ,
            {
                "DRP_OUTPUT_FORMAT": "json",
                "DRP_USE_COLOR": "false",
                "DRP_DEBUG": "true",
                "DRP_GITHUB_TOKEN": "test_token",
                "DRP_CACHE_EXPIRY": "7200",
            },
        ):
            # Act
            config = Config()

            # Assert
            assert config.get("general", "output_format") == "json"
            assert config.get("general", "use_color") is False
            assert config.get("general", "debug") is True
            assert config.get("vulnerability", "github_token") == "test_token"
            assert config.get("vulnerability", "enable_github_advisory") is True
            assert config.get("vulnerability", "cache_expiry") == 7200

    def test_update_from_args(self):
        """HYPOTHESIS: Config should update values from command line arguments."""
        # Arrange
        config = Config()
        args = {
            "output": "json",
            "no_color": True,
            "debug": True,
            "staleness_weight": 0.4,
            "maintainer_weight": 0.3,
            "github_token": "cli_token",
            "enable_nvd": True,
            "graph_format": "graphviz",
            "trend_limit": 5,
        }

        # Act
        config.update_from_args(args)

        # Assert
        assert config.get("general", "output_format") == "json"
        assert config.get("general", "use_color") is False
        assert config.get("general", "debug") is True
        assert config.get("scoring_weights", "staleness") == 0.4
        assert config.get("scoring_weights", "maintainer") == 0.3
        assert config.get("vulnerability", "github_token") == "cli_token"
        assert config.get("vulnerability", "enable_nvd") is True
        assert config.get("graph", "format") == "graphviz"
        assert config.get("trends", "limit") == 5

    def test_priority_cli_over_env_over_file(self):
        """HYPOTHESIS: CLI args should override env vars which override file config."""
        # Arrange
        with tempfile.NamedTemporaryFile(
            suffix=".toml", mode="w", delete=False
        ) as temp_file:
            temp_file.write(
                """
[general]
output_format = "terminal"
debug = false

[vulnerability]
enable_osv = true
            """
            )
            temp_file_path = temp_file.name

        try:
            # Set environment variables
            with patch.dict(
                os.environ, {"DRP_OUTPUT_FORMAT": "json", "DRP_ENABLE_OSV": "false"}
            ):
                # Create config from file and env
                config = Config(temp_file_path)

                # Verify env overrides file
                assert config.get("general", "output_format") == "json"
                assert config.get("general", "debug") is False

                # Update with CLI args
                cli_args = {"output": "csv", "debug": True}
                config.update_from_args(cli_args)

                # Verify CLI overrides env and file
                assert config.get("general", "output_format") == "csv"
                assert config.get("general", "debug") is True
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)

    def test_get_scoring_weights(self):
        """HYPOTHESIS: get_scoring_weights should return all scoring weights."""
        # Arrange
        config = Config()

        # Act
        weights = config.get_scoring_weights()

        # Assert
        assert isinstance(weights, dict)
        assert "staleness" in weights
        assert "maintainer" in weights
        assert "deprecation" in weights
        assert "exploit" in weights
        assert "version_difference" in weights
        assert "health_indicators" in weights
        assert "license" in weights
        assert "community" in weights
        assert "transitive" in weights

    def test_get_api_keys(self):
        """HYPOTHESIS: get_api_keys should return configured API keys."""
        # Arrange
        config = Config()

        # Update with API keys
        config._config["vulnerability"]["github_token"] = "github_token_value"
        config._config["vulnerability"]["nvd_api_key"] = "nvd_key_value"
        config._config["vulnerability"]["enable_github_advisory"] = True
        config._config["vulnerability"]["enable_nvd"] = True

        # Act
        api_keys = config.get_api_keys()

        # Assert
        assert "github" in api_keys
        assert "nvd" in api_keys
        assert api_keys["github"] == "github_token_value"
        assert api_keys["nvd"] == "nvd_key_value"

    def test_generate_sample_config_toml(self):
        """HYPOTHESIS: generate_sample_config should create a valid TOML config file."""
        # Arrange
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as temp_file:
            temp_file_path = temp_file.name

        try:
            # Remove the file so we can test creation
            os.unlink(temp_file_path)

            config = Config()

            # Act
            result = config.generate_sample_config(temp_file_path, "toml")

            # Assert
            assert result is True
            assert os.path.exists(temp_file_path)

            # Verify it's a valid TOML file
            with open(temp_file_path, "r") as f:
                content = f.read()
                assert "[general]" in content
                assert "[scoring_weights]" in content
                assert "[vulnerability]" in content
                assert "[trends]" in content
                assert "[graph]" in content

            # Verify we can load it
            new_config = Config(temp_file_path)
            assert new_config.config_file_loaded is True
        finally:
            # Clean up
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    def test_generate_sample_config_yaml(self):
        """HYPOTHESIS: generate_sample_config should create a valid YAML config file."""
        # Arrange
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as temp_file:
            temp_file_path = temp_file.name

        try:
            # Remove the file so we can test creation
            os.unlink(temp_file_path)

            config = Config()

            # Act
            result = config.generate_sample_config(temp_file_path, "yaml")

            # Assert
            assert result is True
            assert os.path.exists(temp_file_path)

            # Verify it's a valid YAML file by loading it
            with open(temp_file_path, "r") as f:
                data = yaml.safe_load(f)
                assert "general" in data
                assert "scoring_weights" in data
                assert "vulnerability" in data
                assert "trends" in data
                assert "graph" in data
        finally:
            # Clean up
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)


def test_get_config_singleton():
    """HYPOTHESIS: get_config should return the same config instance when called multiple times."""
    # Act
    config1 = get_config()
    config2 = get_config()

    # Assert
    assert config1 is config2


def test_get_config_new_path():
    """HYPOTHESIS: get_config should return a new instance when a path is provided."""
    # Act
    config1 = get_config()
    config2 = get_config("/tmp/nonexistent_config.toml")  # Path doesn't need to exist

    # Assert
    assert config1 is not config2
