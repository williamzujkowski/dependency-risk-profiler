"""Configuration manager for the dependency risk profiler.

This module provides functionality to load and manage configuration from both
configuration files and environment variables. It merges default values with
user-defined settings, with priority given to command-line arguments.
"""

import logging
import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Dict, Optional, Union

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

# Default configuration.
#
# The annotation is load-bearing. Without it mypy joins the section literals
# (one is all floats, the rest are mixed) down to a bare `object`, and every
# `self._config["general"]["debug"] = ...` below is uncheckable.
DEFAULT_CONFIG: Dict[str, Dict[str, object]] = {
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
        "community": 0.2,
        "transitive": 0.15,
        # Mature, widely adopted projects often release less frequently. These
        # calibration knobs dampen only abandonment-style staleness reads when
        # real popularity data is available; bus-factor scoring is unchanged.
        "popularity_high_stars": 2000,
        "popularity_high_contributors": 25,
        "staleness_popularity_dampening": 0.5,
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
        "minimum_severity_for_scoring": "LOW",
    },
    "trends": {
        "save_history": False,
        "analyze": False,
        "limit": 10,
        "visualization": None,
    },
    "graph": {
        "generate": False,
        "format": "d3",
        "depth": 3,
        "output": None,
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
            config_path: Optional explicit path to config file
                (overrides default search paths)
        """
        self._config = deepcopy(DEFAULT_CONFIG)

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

        if "DRP_MINIMUM_VULNERABILITY_SEVERITY" in os.environ:
            self._config["vulnerability"]["minimum_severity_for_scoring"] = os.environ[
                "DRP_MINIMUM_VULNERABILITY_SEVERITY"
            ]

    def _merge_config(self, config_data: Dict[str, object]) -> None:
        """Merge configuration data with current config.

        Args:
            config_data: Configuration data to merge
        """
        # A config file is user-edited text: `general = "yes"` parses fine
        # and reaches here as a string. `dict.update` raises on it, so skip
        # sections that are not tables and say which were skipped.
        for section in (
            "general",
            "scoring_weights",
            "vulnerability",
            "trends",
            "graph",
        ):
            if section not in config_data:
                continue
            values = config_data[section]
            if not isinstance(values, dict):
                logger.warning(
                    f"Ignoring config section '{section}': expected a table, "
                    f"got {type(values).__name__}"
                )
                continue
            self._config[section].update(values)

    def update_from_args(self, args: Dict[str, object]) -> None:
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

        if (
            "minimum_vulnerability_severity" in args
            and args["minimum_vulnerability_severity"]
        ):
            self._config["vulnerability"]["minimum_severity_for_scoring"] = args[
                "minimum_vulnerability_severity"
            ]

        # Trends settings
        if "save_history" in args and args["save_history"] is not None:
            self._config["trends"]["save_history"] = args["save_history"]

        if "analyze_trends" in args and args["analyze_trends"] is not None:
            self._config["trends"]["analyze"] = args["analyze_trends"]

        if "trend_limit" in args and args["trend_limit"] is not None:
            self._config["trends"]["limit"] = args["trend_limit"]

        if "trend_visualization" in args and args["trend_visualization"] is not None:
            self._config["trends"]["visualization"] = args["trend_visualization"]

        # Graph settings
        if "generate_graph" in args and args["generate_graph"] is not None:
            self._config["graph"]["generate"] = args["generate_graph"]

        if "graph_format" in args and args["graph_format"] is not None:
            self._config["graph"]["format"] = args["graph_format"]

        if "graph_depth" in args and args["graph_depth"] is not None:
            self._config["graph"]["depth"] = args["graph_depth"]

        if "graph_output" in args and args["graph_output"] is not None:
            self._config["graph"]["output"] = args["graph_output"]

    def get(self, section: str, key: str, default: object = None) -> object:
        """Get a configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if the key is not found

        Returns:
            Configuration value
        """
        return self._config.get(section, {}).get(key, default)

    def get_section(self, section: str) -> Dict[str, object]:
        """Get a configuration section.

        Args:
            section: Configuration section

        Returns:
            Configuration section as a dictionary
        """
        return self._config.get(section, {}).copy()

    @staticmethod
    def _weight(weights: Dict[str, object], key: str, default: float) -> float:
        """Return a numeric scoring weight, falling back when it is not one.

        Weights come from a user-edited TOML/YAML file, so a key can hold a
        string, a list, or `true`. The declared `Dict[str, float]` return type
        was a promise this method could not keep; keep it by rejecting values
        that are not numbers instead of handing them to the scorer.
        """
        value = weights.get(key, default)
        # `bool` is an `int` subclass; `staleness = true` is a typo, not a 1.0.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            logger.warning(
                f"Ignoring scoring weight '{key}': expected a number, got "
                f"{type(value).__name__}. Using default {default}."
            )
            return default
        return float(value)

    def get_scoring_weights(self) -> Dict[str, float]:
        """Get scoring weights from configuration.

        Returns:
            Dictionary of scoring weights with keys as expected by RiskScorer
        """
        weights = self.get_section("scoring_weights")

        # Map config keys to RiskScorer parameter names
        return {
            "staleness_weight": self._weight(weights, "staleness", 0.25),
            "maintainer_weight": self._weight(weights, "maintainer", 0.2),
            "deprecation_weight": self._weight(weights, "deprecation", 0.3),
            "exploit_weight": self._weight(weights, "exploit", 0.5),
            "version_difference_weight": self._weight(
                weights, "version_difference", 0.15
            ),
            "health_indicators_weight": self._weight(weights, "health_indicators", 0.1),
            "community_weight": self._weight(weights, "community", 0.2),
            "transitive_weight": self._weight(weights, "transitive", 0.15),
            "security_policy_weight": self._weight(weights, "security_policy", 0.25),
            "dependency_update_weight": self._weight(weights, "dependency_update", 0.2),
            "signed_commits_weight": self._weight(weights, "signed_commits", 0.2),
            "branch_protection_weight": self._weight(
                weights, "branch_protection", 0.15
            ),
            "maintained_weight": self._weight(weights, "maintained", 0.20),
            "popularity_high_stars": self._weight(
                weights, "popularity_high_stars", 2000
            ),
            "popularity_high_contributors": self._weight(
                weights,
                "popularity_high_contributors",
                25,
            ),
            "staleness_popularity_dampening": self._weight(
                weights,
                "staleness_popularity_dampening",
                0.5,
            ),
        }

    def get_vulnerability_config(self) -> Dict[str, object]:
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
        api_keys: Dict[str, str] = {}

        # A credential read out of a config file is only a credential if it is
        # a string; a non-string here would have been passed to the HTTP layer
        # as an `Authorization` header and failed somewhere far from the cause.
        github_token = vuln_config.get("github_token")
        if vuln_config.get("enable_github_advisory") and isinstance(github_token, str):
            if github_token:
                api_keys["github"] = github_token

        nvd_api_key = vuln_config.get("nvd_api_key")
        if vuln_config.get("enable_nvd") and isinstance(nvd_api_key, str):
            if nvd_api_key:
                api_keys["nvd"] = nvd_api_key

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
                        "output_format = "
                        f"\"{DEFAULT_CONFIG['general']['output_format']}\"\n"
                    )
                    f.write(
                        "use_color = "
                        f"{str(DEFAULT_CONFIG['general']['use_color']).lower()}\n"
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
                    f.write(
                        "save_history = "
                        f"{str(DEFAULT_CONFIG['trends']['save_history']).lower()}\n"
                    )
                    f.write(
                        "analyze = "
                        f"{str(DEFAULT_CONFIG['trends']['analyze']).lower()}\n"
                    )
                    f.write(f"limit = {DEFAULT_CONFIG['trends']['limit']}\n\n")

                    # Graph section
                    f.write("[graph]\n")
                    f.write(
                        "generate = "
                        f"{str(DEFAULT_CONFIG['graph']['generate']).lower()}\n"
                    )
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
