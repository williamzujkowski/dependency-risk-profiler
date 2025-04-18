"""Configuration manager for the dependency risk profiler.

This module provides functionality to load and manage configuration from both
configuration files and environment variables. It merges default values with
user-defined settings, with priority given to command-line arguments.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Union

# Import tomllib from the standard library in Python 3.11+ or use tomli as a fallback
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import yaml

logger = logging.getLogger(__name__)

# Default config locations, in order of priority
CONFIG_PATHS = [
    Path.cwd() / ".dependency-risk-profiler.toml",
    Path.cwd() / ".dependency-risk-profiler.yaml",
    Path.cwd() / ".dependency-risk-profiler.yml",
    Path("~/.config/dependency-risk-profiler/config.toml").expanduser(),
    Path("~/.config/dependency-risk-profiler/config.yaml").expanduser(),
    Path("~/.config/dependency-risk-profiler/config.yml").expanduser(),
]

# Default configuration
DEFAULT_CONFIG = {
    "general": {
        "output_format": "terminal",
        "use_color": True,
        "debug": False,
        "timeout": 120,  # Default timeout in seconds
    },
    "scoring_weights": {
        "staleness": 0.25,
        "maintainer": 0.2,
        "deprecation": 0.3,
        "exploit": 0.5,
        "version_difference": 0.15,
        "health_indicators": 0.1,
        "license": 0.3,
        "community": 0.2,
        "transitive": 0.15,
    },
    "vulnerability": {
        "enable_osv": True,
        "enable_nvd": False,
        "enable_github_advisory": False,
        "github_token": "",
        "nvd_api_key": "",
        "disable_cache": False,
        "clear_cache": False,
        "cache_expiry": 86400,  # 24 hours in seconds
    },
    "trends": {
        "limit": 10,
    },
    "graph": {
        "format": "d3",
        "depth": 3,
    },
}


class Config:
    """Configuration manager for dependency risk profiler.

    Loads and merges configuration from files, environment variables,
    and command-line arguments, with CLI arguments having highest priority.
    """

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        """Initialize configuration manager.

        Args:
            config_path: Optional explicit path to config file (overrides default search paths)
        """
        self._config = DEFAULT_CONFIG.copy()

        # Load configuration file
        self.config_file_loaded = False
        self.config_file_path = None

        if config_path:
            # Use explicitly provided config file
            if self._load_config_file(Path(config_path)):
                self.config_file_loaded = True
                self.config_file_path = Path(config_path)
        else:
            # Try default config paths in order
            for path in CONFIG_PATHS:
                if self._load_config_file(path):
                    self.config_file_loaded = True
                    self.config_file_path = path
                    break

        # Load environment variables
        self._load_from_env()

    def _load_config_file(self, file_path: Path) -> bool:
        """Load configuration from file.

        Args:
            file_path: Path to the configuration file

        Returns:
            True if configuration was successfully loaded, False otherwise
        """
        if not file_path.exists():
            return False

        try:
            config_data = None
            if file_path.suffix == ".toml":
                with open(file_path, "rb") as f:
                    # Use tomllib for Python 3.11+ or tomli for older versions
                    if sys.version_info >= (3, 11):
                        config_data = tomllib.load(f)
                    else:
                        import tomli

                        config_data = tomli.load(f)
            elif file_path.suffix in (".yaml", ".yml"):
                with open(file_path, "r") as f:
                    config_data = yaml.safe_load(f)
            else:
                logger.warning(f"Unsupported config file format: {file_path}")
                return False

            if not config_data:
                logger.warning(f"Empty config file: {file_path}")
                return False

            # Update configuration
            self._merge_config(config_data)
            logger.info(f"Loaded configuration from {file_path}")
            return True

        except Exception as e:
            logger.warning(f"Error loading config file {file_path}: {e}")
            return False

    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # General settings
        if "DRP_OUTPUT_FORMAT" in os.environ:
            self._config["general"]["output_format"] = os.environ["DRP_OUTPUT_FORMAT"]

        if "DRP_USE_COLOR" in os.environ:
            self._config["general"]["use_color"] = os.environ[
                "DRP_USE_COLOR"
            ].lower() in ("1", "true", "yes")

        if "DRP_DEBUG" in os.environ:
            self._config["general"]["debug"] = os.environ["DRP_DEBUG"].lower() in (
                "1",
                "true",
                "yes",
            )

        # Vulnerability settings
        if "DRP_GITHUB_TOKEN" in os.environ:
            self._config["vulnerability"]["github_token"] = os.environ[
                "DRP_GITHUB_TOKEN"
            ]
            self._config["vulnerability"]["enable_github_advisory"] = True

        if "DRP_NVD_API_KEY" in os.environ:
            self._config["vulnerability"]["nvd_api_key"] = os.environ["DRP_NVD_API_KEY"]
            self._config["vulnerability"]["enable_nvd"] = True

        if "DRP_DISABLE_CACHE" in os.environ:
            self._config["vulnerability"]["disable_cache"] = os.environ[
                "DRP_DISABLE_CACHE"
            ].lower() in ("1", "true", "yes")

        if "DRP_CACHE_EXPIRY" in os.environ:
            try:
                self._config["vulnerability"]["cache_expiry"] = int(
                    os.environ["DRP_CACHE_EXPIRY"]
                )
            except ValueError:
                pass

    def _merge_config(self, config_data: Dict[str, Any]) -> None:
        """Merge configuration data with current config.

        Args:
            config_data: Configuration data to merge
        """
        # Merge general settings
        if "general" in config_data:
            self._config["general"].update(config_data["general"])

        # Merge scoring weights
        if "scoring_weights" in config_data:
            self._config["scoring_weights"].update(config_data["scoring_weights"])

        # Merge vulnerability settings
        if "vulnerability" in config_data:
            self._config["vulnerability"].update(config_data["vulnerability"])

        # Merge trends settings
        if "trends" in config_data:
            self._config["trends"].update(config_data["trends"])

        # Merge graph settings
        if "graph" in config_data:
            self._config["graph"].update(config_data["graph"])

    def update_from_args(self, args: Dict[str, Any]) -> None:
        """Update configuration with command-line arguments.

        Args:
            args: Command-line arguments
        """
        # General settings
        if "output" in args and args["output"]:
            self._config["general"]["output_format"] = args["output"]

        if "no_color" in args:
            self._config["general"]["use_color"] = not args["no_color"]

        if "debug" in args:
            self._config["general"]["debug"] = args["debug"]

        if "timeout" in args and args["timeout"] is not None:
            self._config["general"]["timeout"] = args["timeout"]

        # Scoring weights
        if "staleness_weight" in args and args["staleness_weight"] is not None:
            self._config["scoring_weights"]["staleness"] = args["staleness_weight"]

        if "maintainer_weight" in args and args["maintainer_weight"] is not None:
            self._config["scoring_weights"]["maintainer"] = args["maintainer_weight"]

        if "deprecation_weight" in args and args["deprecation_weight"] is not None:
            self._config["scoring_weights"]["deprecation"] = args["deprecation_weight"]

        if "exploit_weight" in args and args["exploit_weight"] is not None:
            self._config["scoring_weights"]["exploit"] = args["exploit_weight"]

        if "version_weight" in args and args["version_weight"] is not None:
            self._config["scoring_weights"]["version_difference"] = args[
                "version_weight"
            ]

        if "health_weight" in args and args["health_weight"] is not None:
            self._config["scoring_weights"]["health_indicators"] = args["health_weight"]

        if "license_weight" in args and args["license_weight"] is not None:
            self._config["scoring_weights"]["license"] = args["license_weight"]

        if "community_weight" in args and args["community_weight"] is not None:
            self._config["scoring_weights"]["community"] = args["community_weight"]

        if "transitive_weight" in args and args["transitive_weight"] is not None:
            self._config["scoring_weights"]["transitive"] = args["transitive_weight"]

        # Vulnerability settings
        if "enable_osv" in args:
            self._config["vulnerability"]["enable_osv"] = args["enable_osv"]

        if "enable_nvd" in args:
            self._config["vulnerability"]["enable_nvd"] = args["enable_nvd"]

        if "enable_github_advisory" in args:
            self._config["vulnerability"]["enable_github_advisory"] = args[
                "enable_github_advisory"
            ]

        if "github_token" in args and args["github_token"]:
            self._config["vulnerability"]["github_token"] = args["github_token"]

        if "nvd_api_key" in args and args["nvd_api_key"]:
            self._config["vulnerability"]["nvd_api_key"] = args["nvd_api_key"]

        if "no_cache" in args:
            self._config["vulnerability"]["disable_cache"] = args["no_cache"]

        if "clear_cache" in args:
            self._config["vulnerability"]["clear_cache"] = args["clear_cache"]

        # Trends settings
        if "trend_limit" in args and args["trend_limit"] is not None:
            self._config["trends"]["limit"] = args["trend_limit"]

        # Graph settings
        if "graph_format" in args and args["graph_format"]:
            self._config["graph"]["format"] = args["graph_format"]

        if "graph_depth" in args and args["graph_depth"] is not None:
            self._config["graph"]["depth"] = args["graph_depth"]

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if the key is not found

        Returns:
            Configuration value
        """
        return self._config.get(section, {}).get(key, default)

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get a configuration section.

        Args:
            section: Configuration section

        Returns:
            Configuration section as a dictionary
        """
        return self._config.get(section, {}).copy()

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Get the entire configuration.

        Returns:
            Complete configuration as a dictionary
        """
        return self._config.copy()

    def get_scoring_weights(self) -> Dict[str, float]:
        """Get scoring weights from configuration.

        Returns:
            Dictionary of scoring weights with keys as expected by RiskScorer
        """
        weights = self.get_section("scoring_weights")

        # Map config keys to RiskScorer parameter names
        return {
            "staleness_weight": weights.get("staleness", 0.25),
            "maintainer_weight": weights.get("maintainer", 0.2),
            "deprecation_weight": weights.get("deprecation", 0.3),
            "exploit_weight": weights.get("exploit", 0.5),
            "version_difference_weight": weights.get("version_difference", 0.15),
            "health_indicators_weight": weights.get("health_indicators", 0.1),
            "license_weight": weights.get("license", 0.3),
            "community_weight": weights.get("community", 0.2),
            "transitive_weight": weights.get("transitive", 0.15),
            "security_policy_weight": weights.get("security_policy", 0.25),
            "dependency_update_weight": weights.get("dependency_update", 0.2),
            "signed_commits_weight": weights.get("signed_commits", 0.2),
            "branch_protection_weight": weights.get("branch_protection", 0.15),
        }

    def get_vulnerability_config(self) -> Dict[str, Any]:
        """Get vulnerability configuration.

        Returns:
            Dictionary of vulnerability configuration
        """
        return self.get_section("vulnerability")

    def get_api_keys(self) -> Dict[str, str]:
        """Get API keys from configuration.

        Returns:
            Dictionary of API keys
        """
        vuln_config = self.get_vulnerability_config()
        api_keys = {}

        if vuln_config.get("enable_github_advisory") and vuln_config.get(
            "github_token"
        ):
            api_keys["github"] = vuln_config["github_token"]

        if vuln_config.get("enable_nvd") and vuln_config.get("nvd_api_key"):
            api_keys["nvd"] = vuln_config["nvd_api_key"]

        return api_keys

    def generate_sample_config(
        self, file_path: Union[str, Path], format: str = "toml"
    ) -> bool:
        """Generate a sample configuration file.

        Args:
            file_path: Path to save the sample configuration
            format: Configuration format (toml or yaml)

        Returns:
            True if the file was generated successfully, False otherwise
        """
        file_path = Path(file_path)

        try:
            if format.lower() == "toml":
                # We can't use tomli/tomllib for writing, so we'll create it manually
                with open(file_path, "w") as f:
                    f.write("# Dependency Risk Profiler Configuration\n\n")

                    # General section
                    f.write("[general]\n")
                    f.write(
                        f"output_format = \"{DEFAULT_CONFIG['general']['output_format']}\"\n"
                    )
                    f.write(
                        f"use_color = {str(DEFAULT_CONFIG['general']['use_color']).lower()}\n"
                    )
                    f.write(
                        f"debug = {str(DEFAULT_CONFIG['general']['debug']).lower()}\n\n"
                    )

                    # Scoring weights section
                    f.write("[scoring_weights]\n")
                    for key, value in DEFAULT_CONFIG["scoring_weights"].items():
                        f.write(f"{key} = {value}\n")
                    f.write("\n")

                    # Vulnerability section
                    f.write("[vulnerability]\n")
                    for key, value in DEFAULT_CONFIG["vulnerability"].items():
                        if isinstance(value, bool):
                            f.write(f"{key} = {str(value).lower()}\n")
                        elif isinstance(value, str):
                            f.write(f'{key} = "{value}"\n')
                        else:
                            f.write(f"{key} = {value}\n")
                    f.write("\n")

                    # Trends section
                    f.write("[trends]\n")
                    f.write(f"limit = {DEFAULT_CONFIG['trends']['limit']}\n\n")

                    # Graph section
                    f.write("[graph]\n")
                    f.write(f"format = \"{DEFAULT_CONFIG['graph']['format']}\"\n")
                    f.write(f"depth = {DEFAULT_CONFIG['graph']['depth']}\n")

            elif format.lower() in ("yaml", "yml"):
                with open(file_path, "w") as f:
                    yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
            else:
                logger.warning(f"Unsupported config format: {format}")
                return False

            logger.info(f"Generated sample configuration at {file_path}")
            return True

        except Exception as e:
            logger.error(f"Error generating sample config: {e}")
            return False


# Global configuration instance
_config_instance = None


def get_config(config_path: Optional[Union[str, Path]] = None) -> Config:
    """Get global configuration instance, initializing if necessary.

    Args:
        config_path: Optional explicit path to config file

    Returns:
        Configuration instance
    """
    global _config_instance
    if _config_instance is None or config_path is not None:
        _config_instance = Config(config_path)
    return _config_instance
