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
        # When False, skip cloning each dependency's source repo. Org/user scans
        # set this off and derive the same signals (last update, tests, CI) from
        # the GitHub API instead, which is far faster at scale. The single-project
        # `analyze` command leaves it on, where per-dependency depth is the point.
        self.clone_repos = True

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
        try:
            from .crates import CratesIOAnalyzer
            from .golang import GoAnalyzer
            from .nodejs import NodeJSAnalyzer
            from .python import PythonAnalyzer
            from .ruby import RubyGemsAnalyzer

            if not ecosystem:
                return None

            ecosystem = ecosystem.lower().strip()

            if ecosystem == "nodejs":
                return NodeJSAnalyzer()
            elif ecosystem in ["python", "pyproject"]:
                return PythonAnalyzer()
            elif ecosystem == "golang":
                return GoAnalyzer()
            elif ecosystem in ["cargo", "rust", "crates"]:
                return CratesIOAnalyzer()
            elif ecosystem == "rubygems":
                return RubyGemsAnalyzer()
            elif ecosystem == "toml":
                # Backward-compatible fallback for generic TOML files.
                return PythonAnalyzer()
            else:
                return None

        except ImportError:
            # Handle the case where one of the analyzers can't be imported
            return None
