"""Registry for ecosystem parsers."""

import logging
import re
from pathlib import Path, PurePath
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
        path = Path(file_path)

        # Check if file exists
        if not path.exists() or not path.is_file():
            logger.warning(f"File not found or not a file: {path}")
            return None

        # Try to match the file to an ecosystem
        ecosystem_name = cls.detect_ecosystem(path)

        if ecosystem_name:
            parser_class = cls._parsers.get(ecosystem_name)
            if parser_class:
                try:
                    return parser_class(str(path))
                except Exception as e:
                    logger.error(f"Error creating parser for {ecosystem_name}: {e}")
                    return None

        logger.warning(f"No parser found for file: {path}")
        return None

    @classmethod
    def detect_ecosystem(cls, file_path: Path) -> Optional[str]:
        """Detect the ecosystem for a given file path.

        Args:
            file_path: Path to the dependency manifest file.

        Returns:
            The ecosystem name, or None if no ecosystem matches.
        """
        # Try to match each ecosystem's file patterns
        for ecosystem, matchers in cls._file_matchers.items():
            for matcher_type, pattern, matcher_fn in matchers:
                match = False

                # Match on the path alone (file name / extension). Shared with
                # `match_ecosystem_by_path` so the two answers cannot diverge.
                if matcher_type in {"filename", "extension"}:
                    match = cls._path_matcher_hits(
                        matcher_type, pattern, matcher_fn, file_path
                    )

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
    def match_ecosystem_by_path(cls, file_path: PurePath) -> Optional[str]:
        """Detect the ecosystem for a path, from the path alone.

        The name-and-extension half of :meth:`detect_ecosystem`, and literally
        the same matchers: both run :meth:`_path_matcher_hits` over
        ``_file_matchers`` in registration order, so a caller that has bytes
        and one that has only a name cannot disagree about what a file is.

        This exists because an org scan holds a *remote* git tree. It has file
        names and no bytes, so the content matchers cannot run and the custom
        matchers must not — a custom matcher is handed a ``Path`` and may go to
        the filesystem, which for a repository-relative name would resolve
        against the operator's working directory. Skipping them here is
        conservative in the safe direction: a path this returns an ecosystem
        for is one ``detect_ecosystem`` also accepts.

        It replaced a hand-written tuple of exact file names in the org
        scanner. That tuple had no ``*.csproj`` entry, because the registry
        expresses NuGet's primary manifest as an extension matcher and a
        second list has no way to know that — so every .NET repository in every
        org scan was reported as holding no manifests at all (#265). A test
        asserting the two lists agree would have caught it, and would still
        have left two lists.

        Args:
            file_path: The path to classify. Never opened, never stat-ed, and
                need not exist.

        Returns:
            The ecosystem name, or None when no name-based matcher accepts it.
        """
        cls._ensure_parsers_registered()
        for ecosystem, matchers in cls._file_matchers.items():
            for matcher_type, pattern, matcher_fn in matchers:
                if matcher_type not in {"filename", "extension"}:
                    continue
                if cls._path_matcher_hits(matcher_type, pattern, matcher_fn, file_path):
                    return ecosystem
        return None

    @classmethod
    def _path_matcher_hits(
        cls,
        matcher_type: str,
        pattern: object,
        matcher_fn: Optional[Callable],
        file_path: PurePath,
    ) -> bool:
        """Return whether one name-or-extension matcher accepts a path.

        Opens nothing. ``matcher_fn`` on an extension matcher is what keeps
        npm's ``.json`` matcher from claiming every JSON file in a repository,
        so it is applied here rather than dropped — dropping it is what makes a
        derived pattern list dangerous.
        """
        if not isinstance(pattern, str):
            return False
        if matcher_type == "filename":
            return file_path.name.lower() == pattern.lower()
        if matcher_type != "extension":
            return False
        if file_path.suffix.lower() != pattern.lower():
            return False
        if matcher_fn is None:
            return True
        return bool(matcher_fn(str(file_path).lower()))

    @classmethod
    def _ensure_parsers_registered(cls) -> None:
        """Register the built-in parsers if nothing has yet.

        Without this an early caller gets a confident "no ecosystem matches"
        from an empty registry, which is the reassuring answer and the wrong
        one. ``BaseParser.get_parser_for_file`` has always done the same thing.
        """
        if not cls._parsers:
            BaseParser._initialize_registry()

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
