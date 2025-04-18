"""
Release management module for automating the release process.

This module implements functionality for automating software releases,
including version management, artifact packaging, code signing, and
release notes generation.
"""

import argparse
import datetime
import json
import logging
import shutil
import sys
import tempfile
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

from .code_signing import SigningMode, sign_artifact

# Configure logging
logger = logging.getLogger(__name__)


class ReleaseError(Exception):
    """Base exception for release errors."""

    pass


class VersionBumpType(Enum):
    """Type of version bump to perform."""

    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


def read_version(version_file: Union[str, Path]) -> str:
    """
    Read the current version from a configuration file.

    Args:
        version_file: Path to the version file

    Returns:
        Version string

    Raises:
        FileNotFoundError: If the version file doesn't exist
        ValueError: If the version is invalid
    """
    try:
        version_file = Path(version_file)

        if not version_file.exists():
            raise FileNotFoundError(f"Version file not found: {version_file}")

        # Determine file type based on extension
        if version_file.suffix in (".json", ".jsonc"):
            with version_file.open("r") as f:
                data = json.load(f)
                version = data.get("version")
                if not version:
                    raise ValueError(f"No version field found in {version_file}")
                return version

        elif version_file.suffix in (".py", ".pyc"):
            # This is a simple approach; in a real scenario you might use
            # more robust methods like abstract syntax tree parsing
            with version_file.open("r") as f:
                for line in f:
                    if line.startswith("__version__"):
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            # Extract version string and remove quotes
                            version = parts[1].strip().strip("\"'")
                            return version
                raise ValueError(f"No __version__ variable found in {version_file}")

        elif version_file.suffix in (".toml",):
            # Simple TOML parsing - in a real scenario use a proper TOML parser
            with version_file.open("r") as f:
                for line in f:
                    if "version" in line and "=" in line:
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            # Extract version string and remove quotes
                            version = parts[1].strip().strip("\"'")
                            return version
                raise ValueError(f"No version field found in {version_file}")

        else:
            # Default to plain text
            with version_file.open("r") as f:
                version = f.read().strip()
                if not version:
                    raise ValueError(f"Empty version file: {version_file}")
                return version

    except Exception as e:
        logger.error(f"Error reading version from {version_file}: {e}")
        raise


def bump_version(current_version: str, bump_type: VersionBumpType) -> str:
    """
    Increment the version according to Semantic Versioning rules.

    Args:
        current_version: The current version
        bump_type: Type of version bump to perform

    Returns:
        The new version

    Raises:
        ValueError: If the version is invalid
    """
    try:
        # Parse the current version
        if current_version.startswith("v"):
            prefix = "v"
            version = current_version[1:]
        else:
            prefix = ""
            version = current_version

        # Split version into parts
        parts = version.split(".")
        if len(parts) < 3:
            parts.extend(["0"] * (3 - len(parts)))

        major, minor, patch = map(int, parts[:3])

        # Handle pre-release and build metadata
        extra = ""
        if len(parts) > 3 or "-" in parts[2] or "+" in parts[2]:
            # Extract pre-release and build metadata
            if "-" in parts[2]:
                patch_part, pre_release = parts[2].split("-", 1)
                patch = int(patch_part)
                extra = f"-{pre_release}"
            elif "+" in parts[2]:
                patch_part, build_meta = parts[2].split("+", 1)
                patch = int(patch_part)
                extra = f"+{build_meta}"
            elif len(parts) > 3:
                extra = "." + ".".join(parts[3:])

        # Bump the version according to the specified type
        if bump_type == VersionBumpType.MAJOR:
            major += 1
            minor = 0
            patch = 0
            extra = ""  # Reset pre-release and build metadata
        elif bump_type == VersionBumpType.MINOR:
            minor += 1
            patch = 0
            extra = ""  # Reset pre-release and build metadata
        elif bump_type == VersionBumpType.PATCH:
            patch += 1
            # Keep pre-release and build metadata in patch bumps if specified

        # Construct the new version
        new_version = f"{prefix}{major}.{minor}.{patch}{extra}"
        return new_version

    except Exception as e:
        logger.error(f"Error bumping version {current_version}: {e}")
        raise ValueError(f"Invalid version format: {current_version}")


def update_version_file(version_file: Union[str, Path], new_version: str) -> None:
    """
    Update the version in the configuration file.

    Args:
        version_file: Path to the version file
        new_version: The new version to set

    Raises:
        FileNotFoundError: If the version file doesn't exist
        ValueError: If the version update fails
    """
    try:
        version_file = Path(version_file)

        if not version_file.exists():
            raise FileNotFoundError(f"Version file not found: {version_file}")

        # Determine file type based on extension
        if version_file.suffix in (".json", ".jsonc"):
            with version_file.open("r") as f:
                data = json.load(f)

            data["version"] = new_version

            with version_file.open("w") as f:
                json.dump(data, f, indent=2)

        elif version_file.suffix in (".py", ".pyc"):
            with version_file.open("r") as f:
                lines = f.readlines()

            with version_file.open("w") as f:
                for line in lines:
                    if line.startswith("__version__"):
                        f.write(f'__version__ = "{new_version}"\n')
                    else:
                        f.write(line)

        elif version_file.suffix in (".toml",):
            with version_file.open("r") as f:
                lines = f.readlines()

            with version_file.open("w") as f:
                for line in lines:
                    if "version" in line and "=" in line:
                        key = line.split("=")[0].strip()
                        f.write(f'{key} = "{new_version}"\n')
                    else:
                        f.write(line)

        else:
            # Default to plain text
            with version_file.open("w") as f:
                f.write(new_version)

        logger.info(f"Updated version in {version_file} to {new_version}")

    except Exception as e:
        logger.error(f"Error updating version in {version_file}: {e}")
        raise ValueError(f"Failed to update version file: {e}")


def build_artifact(
    source_dir: Union[str, Path],
    output_dir: Union[str, Path],
    version: str,
    build_id: str,
) -> Path:
    """
    Build the artifact for release.

    Args:
        source_dir: Path to the source directory
        output_dir: Path to the output directory
        version: Version string
        build_id: Build identifier

    Returns:
        Path to the built artifact

    Raises:
        ReleaseError: If the build fails
    """
    try:
        source_dir = Path(source_dir)
        output_dir = Path(output_dir)

        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Define artifact file name
        artifact_name = f"dependency-risk-profiler-{version}-{build_id}.zip"
        artifact_path = output_dir / artifact_name

        logger.info(f"Building artifact: {artifact_path}")

        # Create a temporary directory for the build
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Copy source files to temp directory
            # In a real scenario, you would build the package properly
            # For our simulation, we'll just copy files to a temp directory
            for item in source_dir.glob("**/*"):
                if item.is_file() and not any(p.startswith(".") for p in item.parts):
                    # Skip hidden files and directories
                    rel_path = item.relative_to(source_dir)
                    dest_path = temp_path / rel_path
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, dest_path)

            # Create a zip archive from the temp directory
            shutil.make_archive(
                str(artifact_path.with_suffix("")),  # Base name without extension
                "zip",
                temp_path,
            )

        logger.info(f"Built artifact: {artifact_path}")
        return artifact_path

    except Exception as e:
        logger.error(f"Build failed: {e}")
        raise ReleaseError(f"Failed to build artifact: {e}")


def generate_checksum(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
    """
    Generate a checksum for a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal representation of the checksum
    """
    import hashlib

    try:
        file_path = Path(file_path)

        hash_obj = hashlib.new(algorithm)

        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    except Exception as e:
        logger.error(f"Error generating checksum for {file_path}: {e}")
        raise ReleaseError(f"Failed to generate checksum: {e}")


def generate_release_notes(
    version: str,
    build_id: str,
    artifact_path: Path,
    checksum: str,
    signing_info: Optional[Dict[str, str]] = None,
    warnings: Optional[List[str]] = None,
) -> str:
    """
    Generate release notes for the artifact.

    Args:
        version: Version string
        build_id: Build identifier
        artifact_path: Path to the artifact
        checksum: Checksum of the artifact
        signing_info: Signature information
        warnings: List of warnings

    Returns:
        Release notes as a string
    """
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    notes = [
        f"# Release Notes for Version {version}",
        "",
        f"Build ID: {build_id}",
        f"Release Date: {timestamp}",
        f"Artifact: {artifact_path.name}",
        f"Checksum (SHA-256): {checksum}",
        "",
    ]

    if signing_info:
        notes.extend(
            [
                "## Signature Information",
                f"Timestamp: {signing_info.get('timestamp', 'N/A')}",
                f"Signature Mode: {signing_info.get('mode', 'N/A')}",
                "",
            ]
        )

    if warnings:
        notes.extend(["## Warnings", ""])
        for warning in warnings:
            notes.append(f"- {warning}")
        notes.append("")

    notes.extend(
        [
            "## Changes",
            "",
            "- Implemented secure release process",
            "- Added code signing capabilities",
            "- Improved vulnerability aggregation from multiple sources",
            "",
        ]
    )

    return "\n".join(notes)


def create_release(
    source_dir: Union[str, Path],
    version_file: Union[str, Path],
    output_dir: Union[str, Path],
    bump_type: VersionBumpType = VersionBumpType.PATCH,
    signing_mode: SigningMode = SigningMode.TEST,
    signing_log: Optional[Union[str, Path]] = None,
) -> Dict[str, str]:
    """
    Create a release package with proper versioning, building, and signing.

    Args:
        source_dir: Path to the source directory
        version_file: Path to the version file
        output_dir: Path to the output directory
        bump_type: Type of version bump to perform
        signing_mode: Mode for code signing
        signing_log: Path to the signing log file

    Returns:
        Dictionary with release information

    Raises:
        ReleaseError: If the release process fails
    """
    source_dir = Path(source_dir)
    version_file = Path(version_file)
    output_dir = Path(output_dir)

    warnings = []

    try:
        # Step 1: Read current version
        current_version = read_version(version_file)
        logger.info(f"Current version: {current_version}")

        # Step 2: Bump version
        new_version = bump_version(current_version, bump_type)
        logger.info(f"New version: {new_version}")

        # Step 3: Update version file
        update_version_file(version_file, new_version)

        # Step 4: Generate build ID
        build_id = f"build-{int(datetime.datetime.now().timestamp())}"
        logger.info(f"Build ID: {build_id}")

        # Step 5: Build the artifact
        artifact_path = build_artifact(source_dir, output_dir, new_version, build_id)

        # Step 6: Generate checksum
        checksum = generate_checksum(artifact_path)
        logger.info(f"Checksum (SHA-256): {checksum}")

        # Step 7: Sign the artifact
        try:
            signature_path = artifact_path.with_suffix(".sig")
            signing_info = sign_artifact(
                artifact_path, build_id, signing_mode, signature_path, signing_log
            )
            logger.info(f"Artifact signed: {signature_path}")
        except Exception as e:
            logger.warning(f"Signing failed: {e}")
            warnings.append(f"Artifact signing failed: {e}")
            signing_info = None

        # Step 8: Generate release notes
        release_notes_path = output_dir / f"release-notes-{new_version}.md"
        release_notes = generate_release_notes(
            new_version, build_id, artifact_path, checksum, signing_info, warnings
        )

        with release_notes_path.open("w") as f:
            f.write(release_notes)

        logger.info(f"Release notes generated: {release_notes_path}")

        # Step 9: Save release metadata
        metadata_path = output_dir / f"release-{new_version}.json"
        metadata = {
            "version": new_version,
            "build_id": build_id,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "artifact": str(artifact_path),
            "checksum": checksum,
            "release_notes": str(release_notes_path),
        }

        if signing_info:
            metadata["signature"] = str(signature_path)
            metadata["signature_info"] = signing_info

        with metadata_path.open("w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Release metadata saved: {metadata_path}")

        # Return release information
        return {
            "version": new_version,
            "build_id": build_id,
            "artifact": str(artifact_path),
            "checksum": checksum,
            "release_notes": str(release_notes_path),
            "metadata": str(metadata_path),
        }

    except Exception as e:
        logger.error(f"Release process failed: {e}")
        raise ReleaseError(f"Failed to create release: {e}")


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Release management tool")

    parser.add_argument(
        "--source-dir",
        "-s",
        default=".",
        help="Path to the source directory. Default: current directory",
    )

    parser.add_argument(
        "--version-file", "-f", required=True, help="Path to the version file"
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        default="./dist",
        help="Path to the output directory. Default: ./dist",
    )

    parser.add_argument(
        "--bump",
        choices=["patch", "minor", "major"],
        default="patch",
        help="Type of version bump to perform. Default: patch",
    )

    parser.add_argument(
        "--signing-mode",
        choices=["test", "release"],
        default="test",
        help="Mode for code signing. Default: test",
    )

    parser.add_argument("--signing-log", help="Path to the signing log file")

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    try:
        # Parse bump type
        bump_type = VersionBumpType(args.bump)

        # Parse signing mode
        signing_mode = (
            SigningMode.TEST if args.signing_mode == "test" else SigningMode.RELEASE
        )

        # Create release
        release_info = create_release(
            args.source_dir,
            args.version_file,
            args.output_dir,
            bump_type,
            signing_mode,
            args.signing_log,
        )

        print(f"✅ Release {release_info['version']} created successfully!")
        print(f"  Artifact: {release_info['artifact']}")
        print(f"  Checksum: {release_info['checksum']}")
        print(f"  Release notes: {release_info['release_notes']}")

        return 0

    except Exception as e:
        print(f"❌ Release creation failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
