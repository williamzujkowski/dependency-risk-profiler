"""Parser for Go go.mod files."""

import re
from typing import Dict

from ..models import DependencyMetadata
from .base import BaseParser


class GoParser(BaseParser):
    """Parser for Go go.mod files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse the go.mod file and extract dependencies.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        dependencies = {}

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract module name and go version (module name could be used for future enhancements)
            # Commented out as it's not currently used in this version
            # module_match = re.search(r'module\s+(.+?)(?:\n|$)', content)
            # module_name = module_match.group(1).strip() if module_match else None

            # Extract dependencies
            # Look for require statements which can be either inline or in a block
            require_block_pattern = r"require\s*\(\s*([\s\S]*?)\s*\)"
            require_inline_pattern = r"require\s+([^\s]+)\s+([^\s]+)"

            # Extract block require statements
            block_matches = re.findall(require_block_pattern, content)
            for block in block_matches:
                for line in block.split("\n"):
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue

                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].strip()

                        if name not in dependencies:
                            dependencies[name] = DependencyMetadata(
                                name=name,
                                installed_version=version,
                                repository_url=f"https://{name}",
                            )

            # Extract inline require statements
            inline_matches = re.findall(require_inline_pattern, content)
            for match in inline_matches:
                name = match[0]
                version = match[1]

                if name not in dependencies:
                    dependencies[name] = DependencyMetadata(
                        name=name,
                        installed_version=version,
                        repository_url=f"https://{name}",
                    )

            return dependencies
        except Exception as e:
            raise ValueError(f"Error parsing go.mod: {e}")
