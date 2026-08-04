"""Readers for Node.js documents: a package-lock and a registry version manifest."""

import json
import logging
from typing import Dict, Optional, Set

from ..models import DependencyMetadata
from .base import BaseParser

logger = logging.getLogger(__name__)

# The other dependency objects a published package.json can carry. None of them
# is what installing the package pulls in, which is the line nuget's runtime
# ``<dependencies>``, maven's scope filter and composer's ``require`` all draw.
# Named so the exclusion is legible; nothing reads them.
NON_RUNTIME_DEPENDENCY_KEYS = (
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "bundleDependencies",
    "bundledDependencies",
)


def runtime_dependency_names(manifest: object) -> Optional[Set[str]]:
    """Return the packages an npm version manifest declares as runtime deps.

    Two absences that look identical from the outside and are not:

    * **No manifest.** ``versions[<latest>]`` is missing — a mirror that
      answered the packument without the version, a ``latest`` resolved from
      the ``/latest`` document rather than from ``dist-tags``. Nobody read a
      dependency list, so the answer is None and the signal stays unmeasured.
    * **A manifest with no ``dependencies`` key.** That is a *measured zero*.
      The registry stores the published package.json verbatim, and npm's own
      tooling omits the key when the author declares nothing: lodash, ms,
      react, chalk and escape-html all ship without it, while indexof and
      isarray ship ``"dependencies": {}``. Both spellings mean the same thing
      and both are a real answer.

    The distinction matters because the field this feeds fails closed (#199):
    returning an empty set for the first case would be #141's fabricated zero
    arriving through a new door.

    Note also where this does *not* read. The packument has no top-level
    ``dependencies`` key and never has — checked against twelve live packuments
    — so a top-level read would be #142's dead read a second time, in the same
    adapter, against the same document.

    Args:
        manifest: A ``versions[<version>]`` entry from an npm packument, or
            None/anything else when no such entry exists.

    Returns:
        The declared runtime dependency names, or None when no manifest was
        read at all.
    """
    if not isinstance(manifest, dict):
        return None
    dependencies = manifest.get("dependencies")
    if dependencies is None:
        # The author declared none. See the docstring: this is the common
        # spelling for a zero-dependency package, not a missing document.
        return set()
    if not isinstance(dependencies, dict):
        logger.debug(
            "npm version manifest carries a non-object 'dependencies': %r",
            type(dependencies).__name__,
        )
        return set()
    return {
        name.strip() for name in dependencies if isinstance(name, str) and name.strip()
    }


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

            dependencies: Dict[str, DependencyMetadata] = {}

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
            raise ValueError(f"Invalid JSON in package-lock.json: {e}") from e

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
