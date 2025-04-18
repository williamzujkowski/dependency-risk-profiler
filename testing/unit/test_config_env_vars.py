"""Tests for configuration and environment variable handling.

These tests verify that environment variables are properly handled in the configuration.
"""

import os
from unittest import mock

import pytest

from dependency_risk_profiler.config import Config, get_config


def test_config_environment_variables():
    """Test that environment variables are properly loaded in the configuration."""
    # Test with all environment variables set
    env_vars = {
        "DRP_OUTPUT_FORMAT": "json",
        "DRP_USE_COLOR": "0",
        "DRP_DEBUG": "1",
        "DRP_GITHUB_TOKEN": "test-token",
        "DRP_NVD_API_KEY": "test-key",
        "DRP_DISABLE_CACHE": "1",
        "DRP_CACHE_EXPIRY": "3600",
    }

    with mock.patch.dict(os.environ, env_vars):
        config = Config()

        # Check that values were loaded from environment
        assert config.get("general", "output_format") == "json"
        assert config.get("general", "use_color") is False
        assert config.get("general", "debug") is True
        assert config.get("vulnerability", "github_token") == "test-token"
        assert config.get("vulnerability", "nvd_api_key") == "test-key"
        assert config.get("vulnerability", "disable_cache") is True
        assert config.get("vulnerability", "cache_expiry") == 3600
        assert config.get("vulnerability", "enable_github_advisory") is True
        assert config.get("vulnerability", "enable_nvd") is True


def test_config_environment_variable_precedence():
    """Test that environment variables take precedence over config file values."""
    # Create a mock config object with predefined values
    config = Config()

    # Override the _config attribute directly for testing
    config._config = {
        "general": {
            "output_format": "terminal",
            "use_color": True,
            "debug": False,
        },
        "vulnerability": {
            "github_token": "old-token",
            "nvd_api_key": "old-key",
            "disable_cache": False,
            "cache_expiry": 86400,
            "enable_github_advisory": False,
            "enable_nvd": False,
        },
    }

    # Set environment variables
    env_vars = {
        "DRP_OUTPUT_FORMAT": "json",
        "DRP_USE_COLOR": "0",
        "DRP_DEBUG": "1",
        "DRP_GITHUB_TOKEN": "new-token",
        "DRP_NVD_API_KEY": "new-key",
        "DRP_DISABLE_CACHE": "1",
        "DRP_CACHE_EXPIRY": "3600",
    }

    with mock.patch.dict(os.environ, env_vars):
        # Call _load_from_env to reload from environment
        config._load_from_env()

        # Check that values were updated from environment
        assert config.get("general", "output_format") == "json"
        assert config.get("general", "use_color") is False
        assert config.get("general", "debug") is True
        assert config.get("vulnerability", "github_token") == "new-token"
        assert config.get("vulnerability", "nvd_api_key") == "new-key"
        assert config.get("vulnerability", "disable_cache") is True
        assert config.get("vulnerability", "cache_expiry") == 3600
        assert config.get("vulnerability", "enable_github_advisory") is True
        assert config.get("vulnerability", "enable_nvd") is True


def test_get_config_singleton():
    """Test that get_config returns a singleton instance."""
    # Clear any existing instance
    import dependency_risk_profiler.config
    from dependency_risk_profiler.config import _config_instance

    dependency_risk_profiler.config._config_instance = None

    # Get a config instance
    config1 = get_config()

    # Get another config instance
    config2 = get_config()

    # They should be the same object
    assert config1 is config2, "get_config should return a singleton instance"

    # Get a config instance with a specific path
    config3 = get_config(config_path="custom_path.toml")

    # It should be a different object
    assert config1 is not config3, "get_config with path should return a new instance"
