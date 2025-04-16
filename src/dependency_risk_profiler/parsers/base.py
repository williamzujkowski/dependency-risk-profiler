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
        from .toml import TomlParser

        file_name = os.path.basename(manifest_path).lower()
        
        # Check if file exists (important for tests with temporary files)
        if not os.path.exists(manifest_path):
            return None
            
        # Check for matching file patterns
        if "package-lock" in file_name and file_name.endswith(".json"):
            return NodeJSParser(manifest_path)
        elif "requirements" in file_name and file_name.endswith(".txt"):
            return PythonParser(manifest_path)
        elif "pipfile.lock" in file_name.lower():
            return PythonParser(manifest_path)
        elif file_name.endswith(".mod") and ("go" in file_name or "go.mod" in manifest_path.lower()):
            return GoParser(manifest_path)
        elif file_name in ["pyproject.toml", "cargo.toml"] or "pyproject.toml" in file_name.lower() or "cargo.toml" in file_name.lower():
            return TomlParser(manifest_path)
            
        # Check for file extensions as a fallback
        elif file_name.endswith(".json"):
            # Check content for package-lock structure
            try:
                with open(manifest_path, 'r') as f:
                    first_chunk = f.read(1000)  # Read first 1000 chars
                    if '"lockfileVersion"' in first_chunk and ('"dependencies"' in first_chunk or '"packages"' in first_chunk):
                        return NodeJSParser(manifest_path)
            except:
                pass
        elif file_name.endswith(".lock"):
            # Check if it's a Pipfile.lock
            try:
                with open(manifest_path, 'r') as f:
                    first_chunk = f.read(1000)
                    if '"_meta"' in first_chunk and ('"pipfile"' in first_chunk or '"sources"' in first_chunk):
                        return PythonParser(manifest_path)
            except:
                pass
        elif file_name.endswith(".toml"):
            # For other TOML files, try to parse as a generic TOML file
            return TomlParser(manifest_path)
            
        return None