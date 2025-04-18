"""Parser for Python dependency files."""

import json
import re
from typing import Dict

from ..models import DependencyMetadata
from .base import BaseParser


class PythonParser(BaseParser):
    """Parser for Python requirements.txt files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse the requirements.txt file and extract dependencies.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        # Determine if this is a requirements.txt or Pipfile.lock file
        if self.manifest_path.name.lower() == "pipfile.lock":
            return self._parse_pipfile_lock()
        else:
            return self._parse_requirements_txt()

    def _parse_requirements_txt(self) -> Dict[str, DependencyMetadata]:
        """Parse a requirements.txt file.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        dependencies = {}

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                requirements = f.readlines()

            for line in requirements:
                line = line.strip()

                # Skip empty lines, comments, and non-dependency lines
                if (
                    not line
                    or line.startswith("#")
                    or line.startswith("-e ")
                    or line.startswith("-r ")
                ):
                    continue

                # Handle different formats of dependency specifications
                # Format: package==version
                if "==" in line:
                    parts = line.split("==", 1)
                    name = parts[0].strip()
                    version = (
                        parts[1].strip().split(";")[0].strip()
                    )  # Remove environment markers

                # Format: package>=version
                elif ">=" in line:
                    parts = line.split(">=", 1)
                    name = parts[0].strip()
                    version = (
                        parts[1].strip().split(";")[0].strip()
                    )  # Remove environment markers

                # Format: package<=version
                elif "<=" in line:
                    parts = line.split("<=", 1)
                    name = parts[0].strip()
                    version = (
                        parts[1].strip().split(";")[0].strip()
                    )  # Remove environment markers

                # Format: package~=version
                elif "~=" in line:
                    parts = line.split("~=", 1)
                    name = parts[0].strip()
                    version = (
                        parts[1].strip().split(";")[0].strip()
                    )  # Remove environment markers

                # Format: package>version
                elif ">" in line and "=" not in line:
                    parts = line.split(">", 1)
                    name = parts[0].strip()
                    version = (
                        ">" + parts[1].strip().split(";")[0].strip()
                    )  # Remove environment markers

                # Format: package<version
                elif "<" in line and "=" not in line:
                    parts = line.split("<", 1)
                    name = parts[0].strip()
                    version = (
                        "<" + parts[1].strip().split(";")[0].strip()
                    )  # Remove environment markers

                # Format: package[extras]
                elif "[" in line and "]" in line:
                    name = line.split("[")[0].strip()
                    extras = re.search(r"\[(.*?)\]", line).group(1)
                    version = "with extras [" + extras + "]"

                # Format: package
                else:
                    name = line.split(";")[0].strip()  # Remove environment markers
                    version = "latest"

                # Clean up package name
                name = re.sub(r"[<>=~].*$", "", name).strip()

                # Add to dependencies
                dependencies[name] = DependencyMetadata(
                    name=name,
                    installed_version=version,
                    repository_url=f"https://pypi.org/project/{name}/",
                )

            return dependencies
        except Exception as e:
            raise ValueError(f"Error parsing requirements.txt: {e}")

    def _parse_pipfile_lock(self) -> Dict[str, DependencyMetadata]:
        """Parse a Pipfile.lock file.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        dependencies = {}

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Extract default dependencies
            default_packages = data.get("default", {})
            dev_packages = data.get("develop", {})

            # Process default packages
            for name, info in default_packages.items():
                version = info.get("version", "")
                if version.startswith("=="):
                    version = version[2:]  # Remove == prefix

                dependencies[name] = DependencyMetadata(
                    name=name,
                    installed_version=version,
                    repository_url=f"https://pypi.org/project/{name}/",
                )

            # Process dev packages
            for name, info in dev_packages.items():
                # Skip if already in default packages
                if name in dependencies:
                    continue

                version = info.get("version", "")
                if version.startswith("=="):
                    version = version[2:]  # Remove == prefix

                dependencies[name] = DependencyMetadata(
                    name=name,
                    installed_version=version,
                    repository_url=f"https://pypi.org/project/{name}/",
                    additional_info={"dev_dependency": "true"},
                )

            return dependencies
        except Exception as e:
            raise ValueError(f"Error parsing Pipfile.lock: {e}")
