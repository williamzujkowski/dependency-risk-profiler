"""Transitive dependency analyzer."""

import json
import logging
import os
from typing import Dict, List, Set

from ..models import DependencyMetadata

logger = logging.getLogger(__name__)


def extract_npm_dependencies(package_lock_data: Dict) -> Dict[str, Set[str]]:
    """Extract dependencies from package-lock.json.

    Args:
        package_lock_data: package-lock.json data.

    Returns:
        Dictionary mapping package names to their dependencies.
    """
    dependency_map = {}

    # Extract dependencies from different package-lock.json formats
    if "dependencies" in package_lock_data:
        for pkg_name, pkg_info in package_lock_data["dependencies"].items():
            dependency_map[pkg_name] = set()
            if "requires" in pkg_info:
                for req in pkg_info["requires"]:
                    dependency_map[pkg_name].add(req)
            if "dependencies" in pkg_info:
                for dep_name in pkg_info["dependencies"]:
                    dependency_map[pkg_name].add(dep_name)

    # Handle packages field in newer package-lock.json
    if "packages" in package_lock_data:
        for pkg_path, pkg_info in package_lock_data["packages"].items():
            if not pkg_path:  # Skip the root package
                continue

            # Extract package name
            parts = pkg_path.split("node_modules/")
            if len(parts) > 1:
                pkg_name = parts[-1]
            else:
                pkg_name = pkg_path

            if pkg_name not in dependency_map:
                dependency_map[pkg_name] = set()

            if "dependencies" in pkg_info:
                for dep_name in pkg_info["dependencies"]:
                    dependency_map[pkg_name].add(dep_name)

    return dependency_map


def extract_python_dependencies(requirements_file: str) -> Dict[str, Set[str]]:
    """Extract dependencies from requirements.txt or pip freeze output.

    Args:
        requirements_file: Path to requirements.txt file.

    Returns:
        Dictionary mapping package names to their dependencies.
    """
    # This is a simplified approach
    # For a complete analysis, we would need to install the packages and inspect them

    dependency_map = {}

    try:
        if os.path.exists(requirements_file):
            with open(requirements_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Extract package name
                        parts = line.split("==")
                        if len(parts) > 1:
                            pkg_name = parts[0].strip()
                        else:
                            parts = line.split(">=")
                            if len(parts) > 1:
                                pkg_name = parts[0].strip()
                            else:
                                pkg_name = line.split(";")[0].strip()

                        # Initialize empty dependencies
                        # (would require inspecting the package to find real dependencies)
                        dependency_map[pkg_name] = set()
    except Exception as e:
        logger.error(f"Error extracting Python dependencies: {e}")

    return dependency_map


def build_dependency_graph(
    direct_dependencies: List[str], dependency_map: Dict[str, Set[str]]
) -> Dict[str, Set[str]]:
    """Build a graph of transitive dependencies.

    Args:
        direct_dependencies: List of direct dependency names.
        dependency_map: Dictionary mapping package names to their dependencies.

    Returns:
        Dictionary mapping package names to their transitive dependencies.
    """
    transitive_deps = {}

    def explore_deps(package: str, visited: Set[str]) -> Set[str]:
        """Recursively explore dependencies."""
        if package in visited:
            return set()  # Avoid cycles

        visited.add(package)

        if package not in dependency_map:
            return set()

        all_deps = set(dependency_map[package])

        for dep in list(dependency_map[package]):
            indirect_deps = explore_deps(dep, visited.copy())
            all_deps.update(indirect_deps)

        return all_deps

    # Explore transitive dependencies for each direct dependency
    for pkg in direct_dependencies:
        transitive_deps[pkg] = explore_deps(pkg, set())

    return transitive_deps


def analyze_transitive_dependencies(
    dependencies: Dict[str, DependencyMetadata], manifest_path: str
) -> Dict[str, DependencyMetadata]:
    """Analyze transitive dependencies.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata.
        manifest_path: Path to the manifest file.

    Returns:
        Updated dependencies with transitive dependency information.
    """
    logger.info(f"Analyzing transitive dependencies from {manifest_path}")

    try:
        # Extract dependency map based on manifest type
        dependency_map = {}

        if manifest_path.endswith("package-lock.json"):
            with open(manifest_path, "r") as f:
                package_lock_data = json.load(f)
            dependency_map = extract_npm_dependencies(package_lock_data)

        elif manifest_path.endswith("requirements.txt"):
            dependency_map = extract_python_dependencies(manifest_path)

        # Skip if no dependency map could be extracted
        if not dependency_map:
            logger.warning(f"Could not extract dependency map from {manifest_path}")
            return dependencies

        # Build transitive dependency graph
        direct_dependencies = list(dependencies.keys())
        transitive_deps = build_dependency_graph(direct_dependencies, dependency_map)

        # Update dependency metadata with transitive dependencies
        for pkg_name, deps in transitive_deps.items():
            if pkg_name in dependencies:
                dependencies[pkg_name].transitive_dependencies = deps
                logger.info(f"Found {len(deps)} transitive dependencies for {pkg_name}")

    except Exception as e:
        logger.error(f"Error analyzing transitive dependencies: {e}")

    return dependencies
