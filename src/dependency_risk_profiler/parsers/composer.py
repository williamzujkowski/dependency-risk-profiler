"""Parser for PHP composer.lock files."""

import json
import logging
from typing import Dict

from ..models import DependencyMetadata
from .base import BaseParser

logger = logging.getLogger(__name__)


class ComposerLockParser(BaseParser):
    """Parser for PHP composer.lock files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse composer.lock and extract the resolved packages.

        Returns:
            Dictionary mapping package names to their pinned metadata.
        """
        dependencies: Dict[str, DependencyMetadata] = {}
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.error("Could not read %s: %s", self.manifest_path, exc)
            return dependencies

        # composer.lock resolves both runtime and dev packages with concrete
        # versions; both sections are relevant to a dependency-risk scan.
        for section in ("packages", "packages-dev"):
            entries = data.get(section)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                version = entry.get("version")
                if not isinstance(name, str) or not isinstance(version, str):
                    continue
                if name in dependencies:
                    continue
                repo_url = None
                source = entry.get("source")
                if isinstance(source, dict):
                    url = source.get("url")
                    if isinstance(url, str):
                        repo_url = url
                dependencies[name] = DependencyMetadata(
                    name=name,
                    installed_version=version.lstrip("v"),
                    repository_url=repo_url,
                )
        return dependencies
