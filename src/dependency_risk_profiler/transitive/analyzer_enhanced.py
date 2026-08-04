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

# Records how a dependency's transitive set was established, so the scorer can
# tell "resolved, and it is empty" from "never resolved".
TRANSITIVE_SOURCE_KEY = "transitive_source"
TRANSITIVE_SOURCE_UNMEASURED = "unmeasured"


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
            tree = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing pipdeptree output: {e}")
            return None

        if not isinstance(tree, list):
            logger.error(
                "Unexpected pipdeptree output: expected a JSON array, got %s",
                type(tree).__name__,
            )
            return None
        return [node for node in tree if isinstance(node, dict)]
    except Exception as e:
        logger.error(f"Error running pipdeptree: {e}")
        return None


def analyze_python_transitive_dependencies(
    requirements_file: str,
    allow_install: bool = False,
) -> Dict[str, Set[str]]:
    """Analyze transitive dependencies for a Python project using pipdeptree.

    Args:
        requirements_file: Path to requirements file
        allow_install: Opt in to installing the manifest to resolve transitive
            deps. This runs ``pip install`` on untrusted input, which executes
            arbitrary package code (setup.py / build backends); off by default.

    Returns:
        Dictionary mapping package names to their dependencies
    """
    if not allow_install:
        logger.warning(
            "Skipping transitive resolution for %s: it requires installing the "
            "manifest, which executes arbitrary package code (setup.py / build "
            "backends). Re-run with --install-transitive to opt in, and only "
            "for manifests you trust.",
            requirements_file,
        )
        return {}
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
            dependency_map: Dict[str, Set[str]] = {}
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


def analyze_pyproject_toml_dependencies(
    pyproject_file: str, allow_install: bool = False
) -> Dict[str, Set[str]]:
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
            dependency_map = analyze_python_transitive_dependencies(
                temp_file_path, allow_install=allow_install
            )
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)

        return dependency_map
    except Exception as e:
        logger.error(f"Error analyzing pyproject.toml dependencies: {e}")
        return {}


def analyze_pipfile_lock_dependencies(
    pipfile_lock: str, allow_install: bool = False
) -> Dict[str, Set[str]]:
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
            dependency_map = analyze_python_transitive_dependencies(
                temp_file_path, allow_install=allow_install
            )
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_path)

        return dependency_map
    except Exception as e:
        logger.error(f"Error analyzing Pipfile.lock dependencies: {e}")
        return {}


def extract_python_dependencies_enhanced(
    manifest_path: str, allow_install: bool = False
) -> Dict[str, Set[str]]:
    """Extract Python dependencies with enhanced transitive dependency analysis.

    Args:
        manifest_path: Path to Python manifest file
        allow_install: Opt in to install-based transitive resolution (off by
            default; executes untrusted package code — see the chokepoint).

    Returns:
        Dictionary mapping package names to their dependencies
    """
    logger.info(f"Extracting Python dependencies from {manifest_path}")

    if manifest_path.endswith("requirements.txt"):
        return analyze_python_transitive_dependencies(
            manifest_path, allow_install=allow_install
        )
    elif manifest_path.endswith("pyproject.toml"):
        return analyze_pyproject_toml_dependencies(
            manifest_path, allow_install=allow_install
        )
    elif manifest_path.endswith("Pipfile.lock"):
        return analyze_pipfile_lock_dependencies(
            manifest_path, allow_install=allow_install
        )
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


def mark_unmeasured_transitive(
    dependencies: Dict[str, DependencyMetadata],
) -> Dict[str, DependencyMetadata]:
    """Flag dependencies whose transitive set was never actually resolved.

    A dependency that an ecosystem analyzer already populated (Maven reads each
    artifact's published POM, for instance) keeps its data and its source
    marker. Everything else gets ``TRANSITIVE_SOURCE_UNMEASURED`` so the scorer
    reports the signal as unavailable rather than as "zero transitive
    dependencies, therefore zero risk".

    Args:
        dependencies: Dictionary mapping dependency names to their metadata.

    Returns:
        The same dictionary, with unmeasured dependencies marked.
    """
    for dependency in dependencies.values():
        if dependency.transitive_dependencies:
            continue
        if dependency.additional_info.get(TRANSITIVE_SOURCE_KEY):
            continue
        dependency.additional_info[TRANSITIVE_SOURCE_KEY] = TRANSITIVE_SOURCE_UNMEASURED
    return dependencies


def analyze_transitive_dependencies_enhanced(
    dependencies: Dict[str, DependencyMetadata],
    manifest_path: str,
    allow_install: bool = False,
) -> Dict[str, DependencyMetadata]:
    """Analyze transitive dependencies with enhanced methods.

    Args:
        dependencies: Dictionary mapping dependency names to their metadata
        manifest_path: Path to the manifest file
        allow_install: Opt in to install-based Python transitive resolution.
            Off by default because it runs ``pip install`` on the untrusted
            manifest, executing arbitrary package code.

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
            dependency_map = extract_python_dependencies_enhanced(
                manifest_path, allow_install=allow_install
            )

        # This module only knows how to walk npm lockfiles and Python
        # requirement sets. For every other manifest there is no map to build,
        # which is not a failure — it is an absent capability, and saying so is
        # the difference between "we looked and found none" and "we never
        # looked". Anything the ecosystem analyzer already collected stands;
        # anything it did not is marked unmeasured so the scorer drops the
        # transitive signal from both numerator and denominator (#74) instead of
        # scoring an unearned zero.
        if not dependency_map:
            logger.debug(
                "No transitive dependency map is available for %s; keeping "
                "whatever the ecosystem analyzer collected",
                manifest_path,
            )
            return mark_unmeasured_transitive(dependencies)

        # Build transitive dependency graph
        direct_dependencies = list(dependencies.keys())
        transitive_deps = build_dependency_graph(direct_dependencies, dependency_map)

        # Update dependency metadata with transitive dependencies
        for pkg_name, deps in transitive_deps.items():
            if pkg_name in dependencies:
                dependencies[pkg_name].transitive_dependencies = deps
                dependencies[pkg_name].additional_info[
                    TRANSITIVE_SOURCE_KEY
                ] = "manifest"
                logger.info(f"Found {len(deps)} transitive dependencies for {pkg_name}")

    except Exception as e:
        logger.error(f"Error analyzing transitive dependencies: {e}")

    return dependencies
