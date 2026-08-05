"""Parser for TOML dependency files."""

import logging
import sys
from typing import Any, Dict, List, Optional

from ..models import DependencyMetadata
from .base import BaseParser
from .python_requirements import (
    DeclaredRequirement,
    python_dependency,
    read_poetry_requirement,
    read_requirement,
)

logger = logging.getLogger(__name__)


class TomlParser(BaseParser):
    """Parser for TOML dependency files like pyproject.toml, Cargo.toml, etc."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse the TOML file and extract dependencies.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        # Choose the appropriate parsing function based on the file name
        file_name = self.manifest_path.name.lower()

        if file_name == "pyproject.toml":
            return self._parse_pyproject_toml()
        elif file_name == "cargo.toml":
            return self._parse_cargo_toml()
        else:
            # Generic TOML parser that looks for common dependency patterns
            return self._parse_generic_toml()

    def _load_toml(self) -> Dict[str, Any]:
        """Load and parse a TOML file.

        Returns:
            Parsed TOML data as a dictionary.
        """
        try:
            # Handle different versions of Python (tomllib is built-in for Python 3.11+)
            if sys.version_info >= (3, 11):
                import tomllib

                with open(self.manifest_path, "rb") as f:
                    return tomllib.load(f)
            else:
                import tomli

                with open(self.manifest_path, "rb") as f:
                    return tomli.load(f)
        except ImportError as e:
            raise ValueError(
                "TOML parsing requires tomli package for Python < 3.11. "
                "Install with 'pip install tomli'"
            ) from e
        except Exception as e:
            raise ValueError(f"Error parsing TOML file: {e}") from e

    def _parse_pyproject_toml(self) -> Dict[str, DependencyMetadata]:
        """Parse a pyproject.toml file.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        dependencies = {}

        try:
            data = self._load_toml()

            # Handle different formats of pyproject.toml

            # PEP 621 standard format (project.dependencies)
            if "project" in data and "dependencies" in data["project"]:
                deps_list = data["project"]["dependencies"]
                for dep in deps_list:
                    # "requests>=2.25.0" is a bound, not an installed version,
                    # and #275 is that the two do not share a slot.
                    requirement = self._read_pep508(dep)
                    if requirement is None:
                        continue
                    dependencies[requirement.name] = python_dependency(
                        requirement, {"section": "project.dependencies"}
                    )

            # Poetry format (tool.poetry.dependencies)
            if (
                "tool" in data
                and "poetry" in data["tool"]
                and "dependencies" in data["tool"]["poetry"]
            ):
                poetry_deps = data["tool"]["poetry"]["dependencies"]
                for name, version_info in poetry_deps.items():
                    # Skip python dependency which is a requirement not a package
                    if name.lower() == "python":
                        continue

                    # Handle different version formats in Poetry
                    requirement = read_poetry_requirement(name, version_info)
                    if requirement is None:
                        continue

                    dependencies[requirement.name] = python_dependency(
                        requirement, {"section": "tool.poetry.dependencies"}
                    )

            # Handle Poetry dev dependencies
            if (
                "tool" in data
                and "poetry" in data["tool"]
                and "dev-dependencies" in data["tool"]["poetry"]
            ):
                dev_deps = data["tool"]["poetry"]["dev-dependencies"]
                for name, version_info in dev_deps.items():
                    requirement = read_poetry_requirement(name, version_info)
                    if requirement is None:
                        continue

                    # Skip if already in main dependencies
                    if requirement.name in dependencies:
                        # Update existing dependency to mark it as a dev dependency
                        dependencies[requirement.name].additional_info[
                            "dev_dependency"
                        ] = "true"
                    else:
                        dependencies[requirement.name] = python_dependency(
                            requirement,
                            {
                                "dev_dependency": "true",
                                "section": "tool.poetry.dev-dependencies",
                            },
                        )

            # Setuptools format (build-system.requires) - not regular dependencies
            if "build-system" in data and "requires" in data["build-system"]:
                build_deps = data["build-system"]["requires"]
                for dep in build_deps:
                    requirement = self._read_pep508(dep)
                    if requirement is None:
                        continue

                    # Skip if already present as a regular dependency
                    if requirement.name not in dependencies:
                        dependencies[requirement.name] = python_dependency(
                            requirement,
                            {
                                "build_dependency": "true",
                                "section": "build-system.requires",
                            },
                        )

            # Handle optional dependencies/dev dependencies in PEP 621 format
            if "project" in data and "optional-dependencies" in data["project"]:
                for group, deps in data["project"]["optional-dependencies"].items():
                    for dep in deps:
                        requirement = self._read_pep508(dep)
                        if requirement is None:
                            continue
                        name = requirement.name
                        # Only add if not already added or update with additional info
                        if name in dependencies:
                            if "groups" in dependencies[name].additional_info:
                                dependencies[name].additional_info[
                                    "groups"
                                ] += f",{group}"
                            else:
                                dependencies[name].additional_info["groups"] = group

                            # If it's a dev group, mark as dev dependency
                            if group.lower() in [
                                "dev",
                                "development",
                                "test",
                                "testing",
                            ]:
                                dependencies[name].additional_info[
                                    "dev_dependency"
                                ] = "true"
                        else:
                            additional_info = {
                                "groups": group,
                                "section": f"project.optional-dependencies.{group}",
                            }

                            # If it's a dev group, mark as dev dependency
                            if group.lower() in [
                                "dev",
                                "development",
                                "test",
                                "testing",
                            ]:
                                additional_info["dev_dependency"] = "true"

                            dependencies[name] = python_dependency(
                                requirement, additional_info
                            )

            return dependencies
        except Exception as e:
            raise ValueError(f"Error parsing pyproject.toml: {e}") from e

    def _read_pep508(self, dep: object) -> Optional[DeclaredRequirement]:
        """Read one PEP 508 string out of a pyproject table, or report it.

        ``project.dependencies``, ``project.optional-dependencies`` and
        ``build-system.requires`` all hold PEP 508 strings, and all three used
        to go through a separator scan that kept the operator in the version
        (``">=3.12.1"``) while ``parsers/python.py`` stripped it (``"3.12.1"``)
        — two readings of one ecosystem, both wrong in different directions
        (#275). They now share the one reader with requirements.txt.

        Args:
            dep: The entry, which the schema says is a string and a hand-edited
                file may not be.

        Returns:
            The declaration, or None when the entry is not a requirement.
        """
        if not isinstance(dep, str):
            logger.warning(
                "%s: %r is not a requirement string; skipping",
                self.manifest_path,
                dep,
            )
            return None
        requirement = read_requirement(dep)
        if requirement is None:
            logger.warning(
                "%s: cannot read %r as a requirement; skipping",
                self.manifest_path,
                dep,
            )
        return requirement

    def _parse_cargo_toml(self) -> Dict[str, DependencyMetadata]:
        """Parse a Cargo.toml file for Rust dependencies.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        dependencies = {}

        try:
            data = self._load_toml()

            # Process regular dependencies
            if "dependencies" in data:
                for name, version_info in data["dependencies"].items():
                    version = self._extract_cargo_version(version_info)

                    dependencies[name] = DependencyMetadata(
                        name=name,
                        installed_version=version,
                        repository_url=f"https://crates.io/crates/{name}",
                        additional_info={"section": "dependencies"},
                    )

            # Process dev dependencies
            if "dev-dependencies" in data:
                for name, version_info in data["dev-dependencies"].items():
                    version = self._extract_cargo_version(version_info)

                    # Skip if already in main dependencies
                    if name in dependencies:
                        # Mark existing dependency as a dev dependency too
                        dependencies[name].additional_info["dev_dependency"] = "true"
                    else:
                        dependencies[name] = DependencyMetadata(
                            name=name,
                            installed_version=version,
                            repository_url=f"https://crates.io/crates/{name}",
                            additional_info={
                                "dev_dependency": "true",
                                "section": "dev-dependencies",
                            },
                        )

            # Process build dependencies
            if "build-dependencies" in data:
                for name, version_info in data["build-dependencies"].items():
                    version = self._extract_cargo_version(version_info)

                    # Skip if already in dependencies
                    if name in dependencies:
                        dependencies[name].additional_info["build_dependency"] = "true"
                    else:
                        dependencies[name] = DependencyMetadata(
                            name=name,
                            installed_version=version,
                            repository_url=f"https://crates.io/crates/{name}",
                            additional_info={
                                "build_dependency": "true",
                                "section": "build-dependencies",
                            },
                        )

            # Process dependencies in [workspace.dependencies]
            if "workspace" in data and "dependencies" in data["workspace"]:
                for name, version_info in data["workspace"]["dependencies"].items():
                    version = self._extract_cargo_version(version_info)

                    # Skip if already processed
                    if name in dependencies:
                        dependencies[name].additional_info[
                            "workspace_dependency"
                        ] = "true"
                    else:
                        dependencies[name] = DependencyMetadata(
                            name=name,
                            installed_version=version,
                            repository_url=f"https://crates.io/crates/{name}",
                            additional_info={
                                "workspace_dependency": "true",
                                "section": "workspace.dependencies",
                            },
                        )

            return dependencies
        except Exception as e:
            raise ValueError(f"Error parsing Cargo.toml: {e}") from e

    def _parse_generic_toml(self) -> Dict[str, DependencyMetadata]:
        """Parse a generic TOML file looking for common dependency patterns.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        dependencies = {}

        try:
            data = self._load_toml()

            # Look for common dependency sections in TOML files
            dependency_sections = [
                "dependencies",
                "dev-dependencies",
                "build-dependencies",
                "target.dependencies",
                "project.dependencies",
                "tool.dependencies",
                "package.dependencies",
                "requires",
                "tool.poetry.dependencies",
                "tool.poetry.dev-dependencies",
            ]

            # Also look for nested dependency patterns
            nested_sections = self._find_nested_dependency_sections(data)
            dependency_sections.extend(nested_sections)

            for section in dependency_sections:
                # Navigate nested sections (like tool.poetry.dependencies)
                parts = section.split(".")
                current = data
                valid_path = True

                for part in parts:
                    if part in current:
                        current = current[part]
                    else:
                        valid_path = False
                        break

                if not valid_path:
                    continue

                # Process dependencies based on the format
                if isinstance(current, list):
                    # Handle list format [dep1, dep2]
                    for dep in current:
                        if isinstance(dep, str):
                            name, version = self._parse_dependency_string(dep)
                            dependencies[name] = DependencyMetadata(
                                name=name,
                                installed_version=version,
                                repository_url=None,  # Unknown repository
                                additional_info={"section": section},
                            )
                elif isinstance(current, dict):
                    # Handle dict format {dep1: version1, dep2: version2}
                    for name, version_info in current.items():
                        if name.lower() in [
                            "python",
                            "rust",
                        ]:  # Skip language requirements
                            continue

                        version = self._extract_generic_version(version_info)

                        # Add dev/build/etc. flags based on section name
                        additional_info = {"section": section}
                        if "dev" in section:
                            additional_info["dev_dependency"] = "true"
                        if "build" in section:
                            additional_info["build_dependency"] = "true"

                        dependencies[name] = DependencyMetadata(
                            name=name,
                            installed_version=version,
                            repository_url=None,  # Unknown repository
                            additional_info=additional_info,
                        )

            return dependencies
        except Exception as e:
            raise ValueError(f"Error parsing generic TOML file: {e}") from e

    def _find_nested_dependency_sections(
        self, data: Dict, prefix: str = ""
    ) -> List[str]:
        """Find all nested sections that might contain dependencies.

        Args:
            data: The TOML data dictionary
            prefix: Prefix for nested keys

        Returns:
            List of section paths that might contain dependencies
        """
        sections = []

        # Look for sections that are likely to contain dependencies
        for key, value in data.items():
            current_path = f"{prefix}.{key}" if prefix else key

            # If this is a "dependencies" section, add it
            if "dependencies" in key.lower():
                sections.append(current_path)

            # Recursively check nested dictionaries
            if isinstance(value, dict):
                nested_sections = self._find_nested_dependency_sections(
                    value, current_path
                )
                sections.extend(nested_sections)

        return sections

    def _parse_dependency_string(self, dep_string: str) -> tuple:
        """Parse a dependency string into name and version.

        Args:
            dep_string: A dependency string like "package>=1.0.0".

        Returns:
            Tuple of (name, version).
        """
        # Handle different version specifiers
        for separator in ["==", ">=", "<=", "~=", ">", "<"]:
            if separator in dep_string:
                parts = dep_string.split(separator, 1)
                name = parts[0].strip()
                version = (
                    separator + parts[1].strip().split(";")[0].strip()
                )  # Remove environment markers
                return name, version

        # If no version specifier, assume latest
        name = dep_string.split(";")[0].strip()  # Remove environment markers
        return name, "latest"

    def _extract_cargo_version(self, version_info: Any) -> str:
        """Extract version info from Cargo.toml, which can be a string or dict.

        Args:
            version_info: Version info from Cargo.toml (string or dict).

        Returns:
            Version string.
        """
        if isinstance(version_info, str):
            return version_info
        elif isinstance(version_info, dict):
            if "version" in version_info:
                # See _extract_poetry_version: TOML may parse this as a number.
                return str(version_info["version"])
            elif "git" in version_info:
                git_info = version_info["git"]
                if "tag" in version_info:
                    return f"git:{git_info}@{version_info['tag']}"
                return f"git:{git_info}"
            elif "path" in version_info:
                return f"path:{version_info['path']}"

        return "unknown"

    def _extract_generic_version(self, version_info: Any) -> str:
        """Extract version info from a generic TOML format.

        Args:
            version_info: Version info from TOML (can be string, dict, or other).

        Returns:
            Version string.
        """
        if isinstance(version_info, str):
            return version_info
        elif isinstance(version_info, dict):
            # Try common keys for version information
            for key in ["version", "ver", "v"]:
                if key in version_info:
                    return str(version_info[key])

            # Look for common source specifications
            for source_type in ["git", "path", "url"]:
                if source_type in version_info:
                    if "tag" in version_info:
                        source = version_info[source_type]
                        return f"{source_type}:{source}@{version_info['tag']}"
                    elif "branch" in version_info:
                        source = version_info[source_type]
                        return f"{source_type}:{source}#{version_info['branch']}"
                    elif "rev" in version_info:
                        source = version_info[source_type]
                        return f"{source_type}:{source}@{version_info['rev']}"
                    else:
                        return f"{source_type}:{version_info[source_type]}"

            # Workspace dependencies (Cargo)
            if "workspace" in version_info and version_info["workspace"] is True:
                return "workspace = true"

            # If we found a complex dict but no recognized version pattern,
            # serialize it to a simple string representation
            if version_info:
                return str(version_info)
        elif isinstance(version_info, (int, float, bool)):
            # Handle primitive types
            return str(version_info)
        elif isinstance(version_info, list):
            # Handle list values
            return str(version_info)

        return "unknown"
