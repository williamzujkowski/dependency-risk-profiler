"""Base analyzer interface for dependency metadata collection."""

from abc import ABC, abstractmethod
from typing import Dict, Optional

from ..models import DependencyMetadata


class BaseAnalyzer(ABC):
    """Base class for dependency analyzers."""

    def __init__(self, timeout: int = 30):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout

    @abstractmethod
    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze dependencies and collect metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        pass

    @staticmethod
    def get_analyzer_for_ecosystem(ecosystem: str) -> Optional["BaseAnalyzer"]:
        """Get the appropriate analyzer for a given ecosystem.

        Args:
            ecosystem: The dependency ecosystem (e.g., "nodejs", "python", "golang").

        Returns:
            An instance of the appropriate analyzer, or None if no analyzer matches.
        """
        from .golang import GoAnalyzer
        from .nodejs import NodeJSAnalyzer
        from .python import PythonAnalyzer

        ecosystem = ecosystem.lower()

        if ecosystem == "nodejs":
            return NodeJSAnalyzer()
        elif ecosystem == "python":
            return PythonAnalyzer()
        elif ecosystem == "golang":
            return GoAnalyzer()
        elif ecosystem == "toml":
            # Fallback to Python analyzer for toml files (pyproject.toml)
            return PythonAnalyzer()
        else:
            return None
