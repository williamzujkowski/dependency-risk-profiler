"""Base parser interface for dependency manifests."""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional

from ..models import DependencyMetadata

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """Base class for dependency manifest parsers."""

    def __init__(self, manifest_path: str):
        """Initialize parser with path to manifest file.

        Args:
            manifest_path: Path to the manifest file.
        """
        self.manifest_path = Path(manifest_path)
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
        if not self.manifest_path.is_file():
            raise ValueError(f"Manifest path is not a file: {manifest_path}")

    @abstractmethod
    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse the manifest file and extract dependencies.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        pass

    @staticmethod
    def get_parser_for_file(manifest_path: str) -> Optional["BaseParser"]:
        """Get the appropriate parser for a given manifest file.

        Args:
            manifest_path: Path to the manifest file.

        Returns:
            An instance of the appropriate parser, or None if no parser matches.
        """
        # Use the registry to get the appropriate parser
        from .registry import EcosystemRegistry

        # If the registry is empty, initialize it with built-in parsers
        if not EcosystemRegistry.get_available_ecosystems():
            BaseParser._initialize_registry()

        return EcosystemRegistry.get_parser_for_file(manifest_path)

    @staticmethod
    def _initialize_registry() -> None:
        """Initialize the ecosystem registry with built-in parsers."""
        from .golang import GoParser
        from .nodejs import NodeJSParser
        from .python import PythonParser
        from .registry import EcosystemRegistry
        from .ruby import GemfileLockParser
        from .toml import TomlParser

        # Register Node.js parser
        EcosystemRegistry.register_parser(
            "nodejs",
            NodeJSParser,
            [
                {"type": "filename", "pattern": "package-lock.json"},
                {
                    "type": "extension",
                    "pattern": ".json",
                    "matcher_fn": lambda path: "package-lock" in path.lower(),
                },
                {"type": "content", "pattern": r'"lockfileVersion".*"dependencies"'},
            ],
        )

        # Register Python parser
        EcosystemRegistry.register_parser(
            "python",
            PythonParser,
            [
                {"type": "filename", "pattern": "requirements.txt"},
                {"type": "filename", "pattern": "pipfile.lock"},
                {
                    "type": "extension",
                    "pattern": ".txt",
                    "matcher_fn": lambda path: "requirements" in path.lower(),
                },
                {"type": "content", "pattern": r'"_meta".*"pipfile"'},
            ],
        )

        # Register Go parser
        EcosystemRegistry.register_parser(
            "golang",
            GoParser,
            [
                {"type": "filename", "pattern": "go.mod"},
                {
                    "type": "extension",
                    "pattern": ".mod",
                    "matcher_fn": lambda path: "go" in path.lower(),
                },
            ],
        )

        # Register Ruby parser
        EcosystemRegistry.register_parser(
            "rubygems",
            GemfileLockParser,
            [
                {"type": "filename", "pattern": "Gemfile.lock"},
            ],
        )

        # Register TOML parsers with analyzer-specific ecosystems.
        EcosystemRegistry.register_parser(
            "pyproject",
            TomlParser,
            [
                {"type": "filename", "pattern": "pyproject.toml"},
            ],
        )

        EcosystemRegistry.register_parser(
            "cargo",
            TomlParser,
            [
                {"type": "filename", "pattern": "cargo.toml"},
            ],
        )
        # No generic ".toml" catch-all: an arbitrary config.toml has no
        # dependency semantics, and profiling it as Python produced confidently
        # wrong scores. pyproject.toml and Cargo.toml keep their explicit routes.

        logger.debug(
            "Initialized ecosystem registry with built-in parsers: "
            f"{EcosystemRegistry.get_available_ecosystems()}"
        )
