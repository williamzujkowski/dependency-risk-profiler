"""Parser for Node.js package-lock.json files."""

import json
from typing import Dict

from ..models import DependencyMetadata
from .base import BaseParser


class NodeJSParser(BaseParser):
    """Parser for Node.js package-lock.json files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse the package-lock.json file and extract dependencies.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                lockfile_data = json.load(f)

            dependencies = {}

            # Handle different package-lock.json formats (v1 vs v2+)
            if "dependencies" in lockfile_data:
                # package-lock.json v1 format or v2 with direct dependencies
                self._extract_dependencies(lockfile_data["dependencies"], dependencies)

            # For v2+ format, also check packages
            if "packages" in lockfile_data:
                packages = lockfile_data["packages"]
                for pkg_path, pkg_info in packages.items():
                    # Skip the root package
                    if pkg_path == "":
                        continue

                    # Extract package name (handling scoped packages)
                    if "node_modules/" in pkg_path:
                        pkg_name = pkg_path.split("node_modules/")[-1]
                    else:
                        pkg_name = pkg_path

                    if "version" in pkg_info and pkg_name not in dependencies:
                        dependencies[pkg_name] = DependencyMetadata(
                            name=pkg_name,
                            installed_version=pkg_info["version"],
                            repository_url=(
                                pkg_info.get("repository", {}).get("url")
                                if isinstance(pkg_info.get("repository"), dict)
                                else None
                            ),
                        )

            return dependencies
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in package-lock.json: {e}")

    def _extract_dependencies(
        self, deps_dict: Dict, result: Dict[str, DependencyMetadata]
    ) -> None:
        """Extract dependencies recursively from dependencies dictionary.

        Args:
            deps_dict: Dictionary of dependencies from package-lock.json.
            result: Dictionary to store extracted DependencyMetadata objects.
        """
        for name, info in deps_dict.items():
            if "version" in info and name not in result:
                result[name] = DependencyMetadata(
                    name=name,
                    installed_version=info["version"],
                    repository_url=(
                        info.get("repository", {}).get("url")
                        if isinstance(info.get("repository"), dict)
                        else None
                    ),
                )

            # Recursively process nested dependencies if present
            if "dependencies" in info:
                self._extract_dependencies(info["dependencies"], result)
