"""Enhanced transitive dependency analyzer.

This module provides improved methods for analyzing transitive dependencies,
particularly for Python projects using the pipdeptree library.
"""

import json
import logging
import os
import subprocess  # nosec B404
import tempfile
import venv
from typing import Dict, List, Optional, Set

from ..models import DependencyMetadata

logger = logging.getLogger(__name__)


def create_virtual_env(path: str) -> bool:
    """Create a Python virtual environment.

    Args:
        path: Path to create the virtual environment

    Returns:
        True if the virtual environment was created successfully, False otherwise
    """
    try:
        logger.debug(f"Creating virtual environment at {path}")
        venv.create(path, with_pip=True)
        return True
    except Exception as e:
        logger.error(f"Error creating virtual environment: {e}")
        return False


def get_pip_path(venv_path: str) -> str:
    """Get the path to pip in a virtual environment.

    Args:
        venv_path: Path to the virtual environment

    Returns:
        Path to pip executable
    """
    if os.name == "nt":  # Windows
        return os.path.join(venv_path, "Scripts", "pip.exe")
    else:  # Unix/Linux/MacOS
        return os.path.join(venv_path, "bin", "pip")


def get_python_path(venv_path: str) -> str:
    """Get the path to python in a virtual environment.

    Args:
        venv_path: Path to the virtual environment

    Returns:
        Path to python executable
    """
    if os.name == "nt":  # Windows
        return os.path.join(venv_path, "Scripts", "python.exe")
    else:  # Unix/Linux/MacOS
        return os.path.join(venv_path, "bin", "python")


def install_packages(pip_path: str, requirements_file: str) -> bool:
    """Install packages from a requirements file.

    Args:
        pip_path: Path to pip executable
        requirements_file: Path to requirements file

    Returns:
        True if the packages were installed successfully, False otherwise
    """
    try:
        logger.debug(f"Installing packages from {requirements_file}")
        result = subprocess.run(
            [pip_path, "install", "-r", requirements_file],  # nosec B603
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning(f"Error installing packages: {result.stderr}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error installing packages: {e}")
        return False


def install_pipdeptree(pip_path: str) -> bool:
    """Install pipdeptree.

    Args:
        pip_path: Path to pip executable

    Returns:
        True if pipdeptree was installed successfully, False otherwise
    """
    try:
        logger.debug("Installing pipdeptree")
        result = subprocess.run(
            [pip_path, "install", "pipdeptree"],  # nosec B603
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning(f"Error installing pipdeptree: {result.stderr}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error installing pipdeptree: {e}")
        return False


def run_pipdeptree(python_path: str) -> Optional[List[Dict]]:
    """Run pipdeptree to get dependency tree.

    Args:
        python_path: Path to python executable

    Returns:
        Dependency tree as a list of dictionaries, or None if an error occurred
    """
    try:
        logger.debug("Running pipdeptree")
        result = subprocess.run(
            [
                python_path,
                "-m",
                "pipdeptree",
                "--json-tree",
                "--warn",
                "silence",
            ],  # nosec B603
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logger.warning(f"Error running pipdeptree: {result.stderr}")
            return None

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing pipdeptree output: {e}")
            return None
    except Exception as e:
        logger.error(f"Error running pipdeptree: {e}")
        return None


def analyze_python_transitive_dependencies(
    requirements_file: str,
) -> Dict[str, Set[str]]:
    """Analyze transitive dependencies for a Python project using pipdeptree.

    Args:
        requirements_file: Path to requirements file

    Returns:
        Dictionary mapping package names to their dependencies
    """
    try:
        # Create a temporary directory for the virtual environment
        with tempfile.TemporaryDirectory(
            prefix="dependency-risk-profiler-"
        ) as temp_dir:
            logger.info(f"Using temporary directory: {temp_dir}")

            # Create virtual environment
            if not create_virtual_env(temp_dir):
                logger.error("Failed to create virtual environment")
                return {}

            # Get pip and python paths
            pip_path = get_pip_path(temp_dir)
            python_path = get_python_path(temp_dir)

            # Install packages from requirements file
            if not install_packages(pip_path, requirements_file):
                logger.error("Failed to install packages")
                return {}

            # Install pipdeptree
            if not install_pipdeptree(pip_path):
                logger.error("Failed to install pipdeptree")
                return {}

            # Run pipdeptree
            dependency_tree = run_pipdeptree(python_path)
            if not dependency_tree:
                logger.error("Failed to get dependency tree")
                return {}

            # Parse dependency tree
            dependency_map = {}
            for package in dependency_tree:
                pkg_name = package.get("package", {}).get("key", "").lower()
                if not pkg_name:
                    continue

                dependency_map[pkg_name] = set()

                for dependency in package.get("dependencies", []):
                    dep_name = dependency.get("package", {}).get("key", "").lower()
                    if dep_name:
                        dependency_map[pkg_name].add(dep_name)

            logger.info(f"Found {len(dependency_map)} packages with dependencies")
            return dependency_map
    except Exception as e:
        logger.error(f"Error analyzing Python transitive dependencies: {e}")
        return {}


def analyze_pyproject_toml_dependencies(pyproject_file: str) -> Dict[str, Set[str]]:
    """Analyze dependencies from a pyproject.toml file.

    Args:
        pyproject_file: Path to pyproject.toml file

    Returns:
        Dictionary mapping package names to their dependencies
    """
    try:
        import tomli

        with open(pyproject_file, "rb") as f:
            pyproject_data = tomli.load(f)

        dependency_map = {}

        # Get direct dependencies from pyproject.toml
        dependencies = []

        # Check PEP 621 format
        if "project" in pyproject_data and "dependencies" in pyproject_data["project"]:
            dependencies = pyproject_data["project"]["dependencies"]

        # Check Poetry format
        elif "tool" in pyproject_data and "poetry" in pyproject_data["tool"]:
            if "dependencies" in pyproject_data["tool"]["poetry"]:
                poetry_deps = pyproject_data["tool"]["poetry"]["dependencies"]
                # Convert poetry dependencies to simple list
                for name, spec in poetry_deps.items():
                    if name != "python" and isinstance(spec, str):
                        dependencies.append(f"{name}{spec}")
                    elif (
                        name != "python"
                        and isinstance(spec, dict)
                        and "version" in spec
                    ):
                        dependencies.append(f"{name}{spec['version']}")
                    elif name != "python":
                        dependencies.append(name)

        # Create a temporary requirements file
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            for dep in dependencies:
                temp_file.write(f"{dep}\n")

            temp_file_path = temp_file.name

        try:
            # Use the requirements file to analyze dependencies
            dependency_map = analyze_python_transitive_dependencies(temp_file_path)
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)

        return dependency_map
    except Exception as e:
        logger.error(f"Error analyzing pyproject.toml dependencies: {e}")
        return {}


def analyze_pipfile_lock_dependencies(pipfile_lock: str) -> Dict[str, Set[str]]:
    """Analyze dependencies from a Pipfile.lock file.

    Args:
        pipfile_lock: Path to Pipfile.lock file

    Returns:
        Dictionary mapping package names to their dependencies
    """
    try:
        with open(pipfile_lock, "r") as f:
            pipfile_data = json.load(f)

        dependency_map = {}

        # Create a temporary requirements file
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt"
        ) as temp_file:
            # Extract default dependencies
            if "default" in pipfile_data:
                for name, info in pipfile_data["default"].items():
                    if "version" in info:
                        version = info["version"].replace("==", "").replace("=", "")
                        temp_file.write(f"{name}=={version}\n")
                    else:
                        temp_file.write(f"{name}\n")

            temp_file_path = temp_file.name

        try:
            # Use the requirements file to analyze dependencies
            dependency_map = analyze_python_transitive_dependencies(temp_file_path)
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)

        return dependency_map
    except Exception as e:
        logger.error(f"Error analyzing Pipfile.lock dependencies: {e}")
        return {}


def extract_python_dependencies_enhanced(manifest_path: str) -> Dict[str, Set[str]]:
    """Extract Python dependencies with enhanced transitive dependency analysis.

    Args:
        manifest_path: Path to Python manifest file

    Returns:
        Dictionary mapping package names to their dependencies
    """
    logger.info(f"Extracting Python dependencies from {manifest_path}")

    if manifest_path.endswith("requirements.txt"):
        return analyze_python_transitive_dependencies(manifest_path)
    elif manifest_path.endswith("pyproject.toml"):
        return analyze_pyproject_toml_dependencies(manifest_path)
    elif manifest_path.endswith("Pipfile.lock"):
        return analyze_pipfile_lock_dependencies(manifest_path)
    else:
        logger.warning(f"Unsupported Python manifest file: {manifest_path}")
        return {}


def build_dependency_graph(
    direct_dependencies: List[str], dependency_map: Dict[str, Set[str]]
) -> Dict[str, Set[str]]:
    """Build a graph of transitive dependencies.

    Args:
        direct_dependencies: List of direct dependency names
        dependency_map: Dictionary mapping package names to their dependencies

    Returns:
        Dictionary mapping package names to their transitive dependencies
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


def analyze_transitive_dependencies_enhanced(
    dependencies: Dict[str, DependencyMetadata], manifest_path: str
) -> Dict[str, DependencyMetadata]:
    """Analyze transitive dependencies with enhanced methods.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata
        manifest_path: Path to the manifest file

    Returns:
        Updated dependencies with transitive dependency information
    """
    logger.info(f"Analyzing transitive dependencies from {manifest_path} (enhanced)")

    try:
        # Extract dependency map based on manifest type
        dependency_map = {}

        if manifest_path.endswith("package-lock.json"):
            from ..transitive.analyzer import extract_npm_dependencies

            with open(manifest_path, "r") as f:
                package_lock_data = json.load(f)
            dependency_map = extract_npm_dependencies(package_lock_data)

        elif any(
            manifest_path.endswith(ext)
            for ext in ["requirements.txt", "pyproject.toml", "Pipfile.lock"]
        ):
            dependency_map = extract_python_dependencies_enhanced(manifest_path)

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
