"""Parser for Ruby Gemfile.lock files."""

import logging
import re
from typing import Dict

from ..models import DependencyMetadata
from .base import BaseParser

logger = logging.getLogger(__name__)

# A resolved top-level gem inside a ``specs:`` block is indented exactly four
# spaces: ``    name (version)``. Its own transitive requirements are indented
# six spaces (``      dep (~> 2.0)``) and are intentionally skipped here.
_SPEC_LINE = re.compile(r"^ {4}([A-Za-z0-9._-]+) \(([^()]+)\)\s*$")


class GemfileLockParser(BaseParser):
    """Parser for Ruby Gemfile.lock files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse Gemfile.lock and extract the resolved gems.

        Returns:
            Dictionary mapping gem names to their pinned metadata.
        """
        dependencies: Dict[str, DependencyMetadata] = {}
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            logger.error("Could not read %s: %s", self.manifest_path, exc)
            return dependencies

        in_specs = False
        for line in lines:
            if line.strip() == "specs:":
                in_specs = True
                continue
            if not in_specs:
                continue
            # A new top-level section (PLATFORMS, DEPENDENCIES, ...) starts at
            # column zero and ends the specs block.
            if line and not line.startswith(" "):
                in_specs = False
                continue
            match = _SPEC_LINE.match(line)
            if match:
                name, pinned_version = match.group(1), match.group(2).strip()
                if name not in dependencies:
                    dependencies[name] = DependencyMetadata(
                        name=name, installed_version=pinned_version
                    )
        return dependencies
