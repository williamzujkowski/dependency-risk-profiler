#!/usr/bin/env python3
"""
Demo script for the secure release capabilities of the dependency-risk-profiler.

This script demonstrates the usage of the secure code signing and release
management functionality provided by the secure_release module.
"""
import argparse
import datetime
import logging
import sys
import tempfile
from pathlib import Path

from dependency_risk_profiler.secure_release.code_signing import (
    SigningMode,
    sign_artifact,
    verify_signature,
)
from dependency_risk_profiler.secure_release.release_management import (
    VersionBumpType,
    create_release,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def demo_code_signing(output_dir: Path) -> None:
    """Demonstrate the code signing functionality."""
    print("\n📝 Demonstrating Code Signing...\n")

    # Create a sample artifact to sign
    artifact_path = output_dir / "sample-artifact.zip"
    with artifact_path.open("wb") as f:
        f.write(b"This is a sample artifact for demonstration purposes.\n")

    print(f"✅ Created sample artifact: {artifact_path}")

    # Create build ID
    build_id = f"demo-{int(datetime.datetime.now().timestamp())}"

    # Sign the artifact in test mode
    print("\n🔑 Signing artifact in TEST mode...")
    test_sig_path = artifact_path.with_suffix(".test.sig")
    test_signature = sign_artifact(
        artifact_path, build_id, SigningMode.TEST, test_sig_path
    )

    print(f"✅ Artifact signed: {test_sig_path}")
    print(f"   Signature mode: {test_signature['mode']}")
    print(f"   Timestamp: {test_signature['timestamp']}")

    # Sign the artifact in release mode
    print("\n🔒 Signing artifact in RELEASE mode...")
    release_sig_path = artifact_path.with_suffix(".release.sig")
    release_signature = sign_artifact(
        artifact_path, build_id, SigningMode.RELEASE, release_sig_path
    )

    print(f"✅ Artifact signed: {release_sig_path}")
    print(f"   Signature mode: {release_signature['mode']}")
    print(f"   Timestamp: {release_signature['timestamp']}")

    # Verify the signatures
    print("\n🔍 Verifying signatures...")

    test_verified = verify_signature(artifact_path, test_sig_path)
    print(
        f"TEST signature verification: {'✅ Success' if test_verified else '❌ Failed'}"
    )

    release_verified = verify_signature(artifact_path, release_sig_path)
    print(
        f"RELEASE signature verification: {'✅ Success' if release_verified else '❌ Failed'}"
    )

    print("\n✅ Code signing demonstration completed!")


def demo_release_management(source_dir: Path, output_dir: Path) -> None:
    """Demonstrate the release management functionality."""
    print("\n📦 Demonstrating Release Management...\n")

    # Create a sample version file
    version_file = source_dir / "version.txt"
    with version_file.open("w") as f:
        f.write("1.0.0")

    print(f"✅ Created sample version file: {version_file} (version 1.0.0)")

    # Create a release with a patch version bump
    print("\n🚀 Creating PATCH release...")
    patch_release = create_release(
        source_dir, version_file, output_dir, VersionBumpType.PATCH, SigningMode.TEST
    )

    print(f"✅ PATCH release created: {patch_release['version']}")
    print(f"   Artifact: {patch_release['artifact']}")
    print(f"   Release notes: {patch_release['release_notes']}")

    # Create a release with a minor version bump
    print("\n🚀 Creating MINOR release...")
    minor_release = create_release(
        source_dir, version_file, output_dir, VersionBumpType.MINOR, SigningMode.TEST
    )

    print(f"✅ MINOR release created: {minor_release['version']}")
    print(f"   Artifact: {minor_release['artifact']}")
    print(f"   Release notes: {minor_release['release_notes']}")

    # Create a release with a major version bump
    print("\n🚀 Creating MAJOR release...")
    major_release = create_release(
        source_dir, version_file, output_dir, VersionBumpType.MAJOR, SigningMode.RELEASE
    )

    print(f"✅ MAJOR release created: {major_release['version']}")
    print(f"   Artifact: {major_release['artifact']}")
    print(f"   Release notes: {major_release['release_notes']}")

    print("\n✅ Release management demonstration completed!")


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Secure release demo")

    parser.add_argument(
        "--output-dir",
        "-o",
        help="Path to the output directory. Default: temporary directory",
    )

    parser.add_argument(
        "--signing-only", action="store_true", help="Only demonstrate code signing"
    )

    parser.add_argument(
        "--release-only",
        action="store_true",
        help="Only demonstrate release management",
    )

    args = parser.parse_args()

    try:
        # Use specified output directory or create a temporary one
        if args.output_dir:
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            # Create a source directory if needed for release demo
            source_dir = output_dir / "source"
            source_dir.mkdir(exist_ok=True)

            # Run the demos in the specified output directory
            if not args.release_only:
                demo_code_signing(output_dir)

            if not args.signing_only:
                demo_release_management(source_dir, output_dir)

            print(
                f"\n✅ All demonstrations completed. Output files saved to {output_dir}"
            )

        else:
            # Use temporary directories
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                print(f"\n📂 Using temporary directory: {temp_path}")

                # Create a source directory if needed for release demo
                source_dir = temp_path / "source"
                source_dir.mkdir()

                # Run the demos in the temporary directory
                if not args.release_only:
                    demo_code_signing(temp_path)

                if not args.signing_only:
                    demo_release_management(source_dir, temp_path)

                print(
                    "\n✅ All demonstrations completed. Temporary files will be removed."
                )

        return 0

    except Exception as e:
        logger.error(f"Demo failed: {e}")
        print(f"\n❌ Demo failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
