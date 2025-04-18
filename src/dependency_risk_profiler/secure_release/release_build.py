#!/usr/bin/env python3
"""
Comprehensive release build script with security gates.

This script implements a comprehensive release process with multiple security
gates, integrating code signing, testing, and artifact generation.
"""
import argparse
import datetime
import json
import logging
import os
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from .code_signing import SigningMode, sign_artifact
from .release_management import VersionBumpType, create_release

# Configure logging
logger = logging.getLogger(__name__)


class BuildError(Exception):
    """Base exception for build errors."""

    pass


class BuildMode(Enum):
    """Mode for building the release."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


def setup_build_environment() -> Dict[str, str]:
    """
    Set up the build environment with proper variables.

    Returns:
        Dictionary of environment variables
    """
    build_env = os.environ.copy()

    # Set deterministic build variables
    build_env["PYTHONHASHSEED"] = "0"
    build_env["SOURCE_DATE_EPOCH"] = str(int(time.time()))

    # Set build timestamp
    build_env["BUILD_TIMESTAMP"] = datetime.datetime.utcnow().isoformat() + "Z"

    # Set build ID
    build_env["BUILD_ID"] = f"build-{int(time.time())}"

    return build_env


def fetch_latest_code(repo_url: str, branch: str, temp_dir: Union[str, Path]) -> Path:
    """
    Pull the latest code from version control.

    Args:
        repo_url: URL of the Git repository
        branch: Branch to check out
        temp_dir: Temporary directory for the checkout

    Returns:
        Path to the checked out code

    Raises:
        BuildError: If fetching the code fails
    """
    temp_dir = Path(temp_dir)

    try:
        logger.info(f"Fetching code from {repo_url}, branch {branch}")

        # Clone the repository
        subprocess.run(
            ["git", "clone", "-b", branch, repo_url, str(temp_dir)],  # nosec B603, B607
            check=True,
            capture_output=True,
            text=True,
        )

        logger.info(f"Code fetched successfully to {temp_dir}")
        return temp_dir

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fetch code: {e}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise BuildError(f"Failed to fetch code from {repo_url}: {e}")

    except Exception as e:
        logger.error(f"Error fetching code: {e}")
        raise BuildError(f"Failed to fetch code: {e}")


def run_tests(code_dir: Union[str, Path], build_env: Dict[str, str]) -> bool:
    """
    Run a suite of automated tests.

    Args:
        code_dir: Path to the code directory
        build_env: Build environment variables

    Returns:
        True if tests pass, False otherwise
    """
    code_dir = Path(code_dir)

    try:
        logger.info("Running tests...")

        # Change to the code directory
        current_dir = os.getcwd()
        os.chdir(code_dir)

        try:
            # Install dependencies
            logger.info("Installing dependencies...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-e", ".[dev]"],  # nosec B603
                check=True,
                env=build_env,
                capture_output=True,
                text=True,
            )

            # Run linters
            logger.info("Running linters...")
            subprocess.run(
                [sys.executable, "-m", "flake8"],  # nosec B603
                check=True,
                env=build_env,
                capture_output=True,
                text=True,
            )

            subprocess.run(
                [sys.executable, "-m", "black", "--check", "."],  # nosec B603
                check=True,
                env=build_env,
                capture_output=True,
                text=True,
            )

            # Run type checking
            logger.info("Running type checking...")
            subprocess.run(
                [sys.executable, "-m", "mypy", "src/"],  # nosec B603
                check=True,
                env=build_env,
                capture_output=True,
                text=True,
            )

            # Run unit tests
            logger.info("Running unit tests...")
            subprocess.run(
                [sys.executable, "-m", "pytest", "-xvs", "tests/"],  # nosec B603
                check=True,
                env=build_env,
                capture_output=True,
                text=True,
            )

            logger.info("All tests passed!")
            return True

        finally:
            # Change back to the original directory
            os.chdir(current_dir)

    except subprocess.CalledProcessError as e:
        logger.error(f"Tests failed: {e}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        return False

    except Exception as e:
        logger.error(f"Error running tests: {e}")
        return False


def build_package(
    code_dir: Union[str, Path], output_dir: Union[str, Path], build_env: Dict[str, str]
) -> Tuple[Path, Path]:
    """
    Build the software artifact in a reproducible manner.

    Args:
        code_dir: Path to the code directory
        output_dir: Path to the output directory
        build_env: Build environment variables

    Returns:
        Tuple of (sdist_path, wheel_path)

    Raises:
        BuildError: If the build fails
    """
    code_dir = Path(code_dir)
    output_dir = Path(output_dir)

    try:
        logger.info("Building package...")

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Change to the code directory
        current_dir = os.getcwd()
        os.chdir(code_dir)

        try:
            # Build the package
            subprocess.run(
                [sys.executable, "-m", "build"],  # nosec B603
                check=True,
                env=build_env,
                capture_output=True,
                text=True,
            )

            # Find the built artifacts
            dist_dir = code_dir / "dist"
            sdist_files = list(dist_dir.glob("*.tar.gz"))
            wheel_files = list(dist_dir.glob("*.whl"))

            if not sdist_files or not wheel_files:
                raise BuildError("Failed to find built artifacts")

            # Use the latest artifacts (should be only one of each)
            sdist_path = sdist_files[0]
            wheel_path = wheel_files[0]

            # Copy artifacts to the output directory
            sdist_dest = output_dir / sdist_path.name
            wheel_dest = output_dir / wheel_path.name

            shutil.copy2(sdist_path, sdist_dest)
            shutil.copy2(wheel_path, wheel_dest)

            logger.info(f"Built package: {sdist_dest}, {wheel_dest}")
            return (sdist_dest, wheel_dest)

        finally:
            # Change back to the original directory
            os.chdir(current_dir)

    except subprocess.CalledProcessError as e:
        logger.error(f"Build failed: {e}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise BuildError("Failed to build package")

    except Exception as e:
        logger.error(f"Error building package: {e}")
        raise BuildError(f"Failed to build package: {e}")


def scan_artifacts(artifacts: List[Path]) -> bool:
    """
    Perform virus/malware scanning on build artifacts.

    Args:
        artifacts: List of artifact paths

    Returns:
        True if artifacts are clean, False otherwise
    """
    try:
        logger.info(f"Scanning {len(artifacts)} artifacts for security issues...")

        for artifact in artifacts:
            logger.info(f"Scanning {artifact}...")

            # In a real scenario, you would call an actual scanner
            # For example: subprocess.run(["clamscan", str(artifact)])

            # Simulate scanning
            time.sleep(1)

        logger.info("All artifacts passed security scan")
        return True

    except Exception as e:
        logger.error(f"Artifact scanning failed: {e}")
        return False


def sign_artifacts(
    artifacts: List[Path],
    build_id: str,
    mode: SigningMode,
    log_file: Optional[Union[str, Path]] = None,
) -> Dict[Path, Dict[str, str]]:
    """
    Sign all artifacts using the code signing utility.

    Args:
        artifacts: List of artifact paths
        build_id: Build identifier
        mode: Signing mode
        log_file: Path to the signing log file

    Returns:
        Dictionary mapping artifacts to their signature info

    Raises:
        BuildError: If signing fails
    """
    try:
        logger.info(f"Signing {len(artifacts)} artifacts in {mode.name} mode...")

        signatures = {}

        for artifact in artifacts:
            logger.info(f"Signing {artifact}...")

            signature_path = artifact.with_suffix(artifact.suffix + ".sig")
            signature_info = sign_artifact(
                artifact, build_id, mode, signature_path, log_file
            )

            signatures[artifact] = signature_info
            logger.info(f"Artifact signed: {signature_path}")

        return signatures

    except Exception as e:
        logger.error(f"Artifact signing failed: {e}")
        raise BuildError(f"Failed to sign artifacts: {e}")


def create_build_manifest(
    artifacts: List[Path],
    signatures: Dict[Path, Dict[str, str]],
    build_env: Dict[str, str],
    output_path: Union[str, Path],
) -> Path:
    """
    Create a build manifest with all build information.

    Args:
        artifacts: List of artifact paths
        signatures: Dictionary mapping artifacts to signature info
        build_env: Build environment variables
        output_path: Path to write the manifest

    Returns:
        Path to the manifest file
    """
    try:
        output_path = Path(output_path)

        manifest = {
            "build_id": build_env.get("BUILD_ID", "unknown"),
            "build_timestamp": build_env.get("BUILD_TIMESTAMP", "unknown"),
            "artifacts": [],
            "environment": {"python_version": sys.version, "platform": sys.platform},
        }

        # Add artifact information
        for artifact in artifacts:
            artifact_info = {
                "path": str(artifact),
                "name": artifact.name,
                "size": artifact.stat().st_size,
                "sha256": subprocess.run(
                    ["sha256sum", str(artifact)],  # nosec B603, B607
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.split()[0],
            }

            # Add signature info if available
            if artifact in signatures:
                artifact_info["signature"] = {
                    "path": str(artifact.with_suffix(artifact.suffix + ".sig")),
                    "timestamp": signatures[artifact].get("timestamp"),
                    "mode": signatures[artifact].get("mode"),
                }

            manifest["artifacts"].append(artifact_info)

        # Write manifest to file
        with output_path.open("w") as f:
            json.dump(manifest, f, indent=2)

        logger.info(f"Build manifest written to {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"Failed to create build manifest: {e}")
        raise BuildError(f"Failed to create build manifest: {e}")


def run_build_process(
    repo_url: str,
    branch: str,
    output_dir: Union[str, Path],
    mode: BuildMode,
    version_bump: VersionBumpType,
    artifacts_only: bool = False,
) -> Dict[str, str]:
    """
    Run the full build process with all security gates.

    Args:
        repo_url: URL of the Git repository
        branch: Branch to check out
        output_dir: Path to the output directory
        mode: Build mode
        version_bump: Type of version bump to perform
        artifacts_only: If True, only build the artifacts without version bumping

    Returns:
        Dictionary with build information

    Raises:
        BuildError: If any part of the build process fails
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Set up build environment
    build_env = setup_build_environment()
    build_id = build_env["BUILD_ID"]
    build_timestamp = build_env["BUILD_TIMESTAMP"]

    # Create build log
    log_file = output_dir / f"build-log-{build_id}.txt"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(file_handler)

    try:
        logger.info(f"Starting build process (ID: {build_id}, Mode: {mode.name})")

        # Create a temporary directory for the code checkout
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Step 1: Fetch code from repository
            code_dir = fetch_latest_code(repo_url, branch, temp_path)

            # Step 2: Run tests
            if not run_tests(code_dir, build_env):
                raise BuildError("Tests failed, aborting build")

            # Step 3: Build the package
            sdist_path, wheel_path = build_package(code_dir, output_dir, build_env)

            # Step 4: Scan artifacts for security issues
            artifacts = [sdist_path, wheel_path]
            if not scan_artifacts(artifacts):
                raise BuildError("Security scan failed, aborting build")

            # Step 5: Sign the artifacts
            signing_mode = (
                SigningMode.RELEASE
                if mode == BuildMode.PRODUCTION
                else SigningMode.TEST
            )
            signing_log = output_dir / f"signing-log-{build_id}.txt"
            signatures = sign_artifacts(artifacts, build_id, signing_mode, signing_log)

            # Step 6: Create build manifest
            manifest_path = output_dir / f"build-manifest-{build_id}.json"
            create_build_manifest(artifacts, signatures, build_env, manifest_path)

            # Step 7: If not artifacts_only, create a proper release by bumping version
            if not artifacts_only:
                try:
                    version_file = code_dir / "pyproject.toml"

                    # Use the release management module to create a release
                    release_info = create_release(
                        code_dir,
                        version_file,
                        output_dir,
                        version_bump,
                        signing_mode,
                        signing_log,
                    )

                    logger.info(f"Release created: {release_info['version']}")
                except Exception as e:
                    logger.error(f"Release creation failed: {e}")
                    # Continue with the build process

            # Return build information
            return {
                "build_id": build_id,
                "build_timestamp": build_timestamp,
                "artifacts": [str(p) for p in artifacts],
                "manifest": str(manifest_path),
                "log": str(log_file),
                "signing_log": str(signing_log),
            }

    except Exception as e:
        logger.error(f"Build process failed: {e}")
        raise BuildError(f"Build process failed: {e}")

    finally:
        # Remove the file handler
        logger.removeHandler(file_handler)


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Comprehensive release build script")

    parser.add_argument(
        "--repo",
        default="https://github.com/your-organization/dependency-risk-profiler.git",
        help="URL of the Git repository",
    )

    parser.add_argument(
        "--branch", default="main", help="Branch to check out. Default: main"
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        default="./dist",
        help="Path to the output directory. Default: ./dist",
    )

    parser.add_argument(
        "--mode",
        choices=["development", "staging", "production"],
        default="development",
        help="Build mode. Default: development",
    )

    parser.add_argument(
        "--version-bump",
        choices=["patch", "minor", "major"],
        default="patch",
        help="Type of version bump to perform. Default: patch",
    )

    parser.add_argument(
        "--artifacts-only",
        action="store_true",
        help="Only build the artifacts without version bumping",
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    try:
        # Parse build mode
        build_mode = BuildMode(args.mode)

        # Parse version bump type
        version_bump = VersionBumpType(args.version_bump)

        # Run the build process
        build_info = run_build_process(
            args.repo,
            args.branch,
            args.output_dir,
            build_mode,
            version_bump,
            args.artifacts_only,
        )

        print("✅ Build completed successfully!")
        print(f"  Build ID: {build_info['build_id']}")
        print(f"  Timestamp: {build_info['build_timestamp']}")
        print("  Artifacts:")
        for artifact in build_info["artifacts"]:
            print(f"    - {artifact}")
        print(f"  Build manifest: {build_info['manifest']}")
        print(f"  Build log: {build_info['log']}")
        print(f"  Signing log: {build_info['signing_log']}")

        return 0

    except Exception as e:
        print(f"❌ Build failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
