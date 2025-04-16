"""Base parser interface for dependency manifests."""
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional

from ..models import DependencyMetadata


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
        from .nodejs import NodeJSParser
        from .python import PythonParser
        from .golang import GoParser

        file_name = os.path.basename(manifest_path).lower()
        
        if file_name == "package-lock.json":
            return NodeJSParser(manifest_path)
        elif file_name == "requirements.txt":
            return PythonParser(manifest_path)
        elif file_name == "pipfile.lock":
            return PythonParser(manifest_path)
        elif file_name == "go.mod":
            return GoParser(manifest_path)
        else:
            return None