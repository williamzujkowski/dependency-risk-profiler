"""Registry for ecosystem parsers."""

import logging
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple, Type

from .base import BaseParser

logger = logging.getLogger(__name__)


class EcosystemRegistry:
    """Registry for ecosystem parsers and file matchers."""

    # Dictionary mapping ecosystem names to parser classes
    _parsers: Dict[str, Type[BaseParser]] = {}

    # Dictionary mapping ecosystem names to file pattern matchers
    # Each matcher is a tuple of (pattern_type, pattern, matcher_function)
    # pattern_type can be 'filename', 'extension', or 'content'
    _file_matchers: Dict[str, List[Tuple[str, Any, Optional[Callable]]]] = {}

    @classmethod
    def register_parser(
        cls,
        ecosystem_name: str,
        parser_class: Type[BaseParser],
        file_matchers: List[Dict[str, Any]],
    ) -> None:
        """Register a parser for an ecosystem.

        Args:
            ecosystem_name: Unique identifier for the ecosystem.
            parser_class: Parser class to use for this ecosystem.
            file_matchers: List of file matcher configurations.
                Each matcher should be a dict with keys:
                - 'type': One of 'filename', 'extension', or 'content'
                - 'pattern': String or re.Pattern for matching
                - 'matcher_fn': Optional function for custom matching logic

        Examples:
            Register a Python parser:

            ```python
            from dependency_risk_profiler.parsers.registry import EcosystemRegistry

            EcosystemRegistry.register_parser(
                'python',
                PythonParser,
                [
                    {'type': 'filename', 'pattern': 'requirements.txt'},
                    {'type': 'filename', 'pattern': 'pipfile.lock'},
                    {'type': 'extension', 'pattern': '.txt',
                     'matcher_fn': lambda path: 'requirements' in path.lower()},
                ]
            )
            ```
        """
        # Register the parser class
        cls._parsers[ecosystem_name] = parser_class

        # Register the file matchers
        cls._file_matchers.setdefault(ecosystem_name, [])

        for matcher in file_matchers:
            matcher_type = matcher["type"]
            pattern = matcher["pattern"]
            matcher_fn = matcher.get("matcher_fn")

            # Compile regex patterns
            if matcher_type == "content" and isinstance(pattern, str):
                pattern = re.compile(pattern)

            cls._file_matchers[ecosystem_name].append(
                (matcher_type, pattern, matcher_fn)
            )

        logger.debug(f"Registered parser for ecosystem: {ecosystem_name}")

    @classmethod
    def get_parser_for_file(cls, file_path: str) -> Optional[BaseParser]:
        """Get the appropriate parser for a given file path.

        Args:
            file_path: Path to the dependency manifest file.

        Returns:
            An instance of the appropriate parser, or None if no parser matches.
        """
        file_path = Path(file_path)

        # Check if file exists
        if not file_path.exists() or not file_path.is_file():
            logger.warning(f"File not found or not a file: {file_path}")
            return None

        # Try to match the file to an ecosystem
        ecosystem_name = cls.detect_ecosystem(file_path)

        if ecosystem_name:
            parser_class = cls._parsers.get(ecosystem_name)
            if parser_class:
                try:
                    return parser_class(str(file_path))
                except Exception as e:
                    logger.error(f"Error creating parser for {ecosystem_name}: {e}")
                    return None

        logger.warning(f"No parser found for file: {file_path}")
        return None

    @classmethod
    def detect_ecosystem(cls, file_path: Path) -> Optional[str]:
        """Detect the ecosystem for a given file path.

        Args:
            file_path: Path to the dependency manifest file.

        Returns:
            The ecosystem name, or None if no ecosystem matches.
        """
        file_name = file_path.name.lower()
        file_ext = file_path.suffix.lower()

        # Try to match each ecosystem's file patterns
        for ecosystem, matchers in cls._file_matchers.items():
            for matcher_type, pattern, matcher_fn in matchers:
                match = False

                # Match based on file name
                if matcher_type == "filename" and isinstance(pattern, str):
                    match = file_name == pattern.lower()

                # Match based on file extension
                elif matcher_type == "extension" and isinstance(pattern, str):
                    match = file_ext == pattern.lower()

                    # Apply additional matcher function if provided
                    if match and matcher_fn:
                        match = matcher_fn(str(file_path).lower())

                # Match based on file content pattern
                elif matcher_type == "content" and isinstance(pattern, Pattern):
                    # Read a small chunk of the file to check for patterns
                    try:
                        with open(file_path, "r", errors="ignore") as f:
                            content = f.read(2048)  # Read first 2KB
                            match = bool(pattern.search(content))
                    except Exception as e:
                        logger.debug(f"Error reading file for content matching: {e}")
                        match = False

                # If a custom matcher function is provided, use it
                elif matcher_type == "custom" and matcher_fn:
                    try:
                        match = matcher_fn(file_path)
                    except Exception as e:
                        logger.debug(f"Error in custom matcher: {e}")
                        match = False

                if match:
                    return ecosystem

        return None

    @classmethod
    def get_available_ecosystems(cls) -> List[str]:
        """Get a list of available ecosystems.

        Returns:
            List of ecosystem names.
        """
        return sorted(cls._parsers.keys())

    @classmethod
    def get_ecosystem_details(cls) -> Dict[str, Dict[str, Any]]:
        """Get detailed information about registered ecosystems.

        Returns:
            Dictionary with ecosystem details.
        """
        details = {}

        for ecosystem_name, parser_class in cls._parsers.items():
            matchers = cls._file_matchers.get(ecosystem_name, [])

            file_patterns = []
            for matcher_type, pattern, _ in matchers:
                if matcher_type == "filename":
                    file_patterns.append(f"File name: {pattern}")
                elif matcher_type == "extension":
                    file_patterns.append(f"File extension: {pattern}")
                elif matcher_type == "content":
                    file_patterns.append(f"Content pattern: {pattern.pattern}")
                elif matcher_type == "custom":
                    file_patterns.append("Custom matcher function")

            details[ecosystem_name] = {
                "parser_class": parser_class.__name__,
                "file_patterns": file_patterns,
            }

        return details
