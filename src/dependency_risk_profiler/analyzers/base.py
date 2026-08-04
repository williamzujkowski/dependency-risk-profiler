"""Base analyzer interface for dependency metadata collection."""

from abc import ABC, abstractmethod
from typing import Dict, Optional, Type

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

        Dispatch is table-driven off the canonical ecosystem registry
        (``vulnerabilities.ecosystems``) rather than a second hand-maintained
        alias chain, so every spelling the registry knows routes here too
        ("rust"/"crates" -> cargo, "php" -> composer, "dotnet" -> nuget) and a
        new ecosystem is one registry entry plus one row below. Unknown input
        stays non-raising (``lookup``, not ``resolve``): callers treat None as
        "skip this dependency".

        Args:
            ecosystem: The dependency ecosystem (e.g., "nodejs", "python", "golang").

        Returns:
            An instance of the appropriate analyzer, or None if no analyzer matches.
        """
        if not ecosystem:
            return None

        try:
            from ..vulnerabilities.ecosystems import lookup
            from .composer import ComposerAnalyzer
            from .crates import CratesIOAnalyzer
            from .golang import GoAnalyzer
            from .maven import MavenAnalyzer
            from .nodejs import NodeJSAnalyzer
            from .nuget import NuGetAnalyzer
            from .python import PythonAnalyzer
            from .ruby import RubyGemsAnalyzer

            # Keyed on canonical Ecosystem.key. "java" is a separate registry
            # entry from "maven" (they diverge in NVD CPE prefix only) and both
            # are served by the same analyzer.
            analyzers: Dict[str, Type[BaseAnalyzer]] = {
                "nodejs": NodeJSAnalyzer,
                "python": PythonAnalyzer,
                "golang": GoAnalyzer,
                "cargo": CratesIOAnalyzer,
                "maven": MavenAnalyzer,
                "java": MavenAnalyzer,
                "nuget": NuGetAnalyzer,
                "ruby": RubyGemsAnalyzer,
                "composer": ComposerAnalyzer,
            }

            resolved = lookup(ecosystem)
            if resolved is None:
                return None

            analyzer_class = analyzers.get(resolved.key)
            return analyzer_class() if analyzer_class is not None else None

        except ImportError:
            # Handle the case where one of the analyzers can't be imported
            return None
