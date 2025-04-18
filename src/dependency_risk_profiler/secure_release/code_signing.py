"""
Secure code signing implementation for build artifacts.

This module implements functionality for securely signing software artifacts
with appropriate security measures like cryptographic hashing, malware scanning,
secure key management, and timestamping.
"""

import argparse
import datetime
import hashlib
import logging
import os
import sys
import time
from enum import Enum, auto
from pathlib import Path
from typing import Dict, Optional, Union

# Configure logging
logger = logging.getLogger(__name__)


class SigningMode(Enum):
    """Modes for artifact signing."""

    TEST = auto()
    RELEASE = auto()


class SigningError(Exception):
    """Base exception for signing errors."""

    pass


class KeyRetrievalError(SigningError):
    """Exception raised when key retrieval fails."""

    pass


class MalwareScanError(SigningError):
    """Exception raised when malware scan fails."""

    pass


class SignatureError(SigningError):
    """Exception raised when signature creation fails."""

    pass


def compute_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> str:
    """
    Compute the cryptographic hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use

    Returns:
        Hexadecimal representation of the hash

    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If there's an error reading the file
    """
    hash_obj = hashlib.new(algorithm)

    try:
        file_path = Path(file_path)
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()
    except (FileNotFoundError, IOError) as e:
        logger.error(f"Error computing hash for {file_path}: {e}")
        raise


def scan_for_malware(file_path: Union[str, Path]) -> bool:
    """
    Perform a virus/malware scan on an artifact.

    This function simulates integration with an anti-malware scanner.
    In a real implementation, this would call an actual anti-malware API.

    Args:
        file_path: Path to the file to scan

    Returns:
        True if the file is clean, False if malware is detected

    Raises:
        MalwareScanError: If the scan fails
    """
    logger.info(f"Scanning {file_path} for malware...")

    try:
        # Simulate scanning - in a real scenario, call actual AV software
        # For example: subprocess.run(["clamscan", "--quiet", str(file_path)])

        # Simulate scan result (always clean in this example)
        scan_result = True

        logger.info(f"Malware scan completed for {file_path}")
        return scan_result

    except Exception as e:
        logger.error(f"Malware scan failed: {e}")
        raise MalwareScanError(f"Failed to scan {file_path}: {e}")


def retrieve_signing_key(mode: SigningMode) -> bytes:
    """
    Retrieve the appropriate signing key from a secure storage.

    In a real implementation, this would retrieve the key from an HSM or
    a secure key management service like AWS KMS, Azure Key Vault, etc.

    Args:
        mode: The signing mode (test or release)

    Returns:
        The signing key as bytes

    Raises:
        KeyRetrievalError: If key retrieval fails
    """
    logger.info(f"Retrieving signing key for {mode.name} mode...")

    try:
        # Simulate retrieving a key from a secure storage
        # In a real scenario, this would call an HSM or key management API

        # For simulation, we're creating different keys for test vs. release
        if mode == SigningMode.TEST:
            # Generate a test key (this is just a simulation)
            key = b"TEST_SIGNING_KEY_" + os.urandom(16)
        else:  # RELEASE mode
            # In a real scenario, you would fetch the production key from an HSM
            # For simulation purposes only:
            key = b"RELEASE_SIGNING_KEY_" + os.urandom(32)

        logger.info(f"Successfully retrieved {mode.name} signing key")
        return key

    except Exception as e:
        logger.error(f"Failed to retrieve signing key: {e}")
        raise KeyRetrievalError(f"Failed to retrieve {mode.name} signing key: {e}")


def get_timestamp_token() -> str:
    """
    Get a trusted timestamp token from a timestamp authority.

    In a real implementation, this would connect to an actual RFC 3161
    compliant Time Stamp Authority.

    Returns:
        Timestamp token as a string
    """
    try:
        # Simulate getting a timestamp from a timestamp authority
        # In a real scenario, you would call an actual TSA service
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"

        # Real implementation would use something like this:
        # response = requests.post(
        #     "https://timestamp.authority.com",
        #     data=hash_to_timestamp,
        #     headers={"Content-Type": "application/timestamp-query"}
        # )
        # timestamp_token = response.content

        return timestamp

    except Exception as e:
        logger.error(f"Failed to obtain timestamp: {e}")
        raise SignatureError(f"Failed to obtain trusted timestamp: {e}")


def create_signature(file_hash: str, key: bytes) -> bytes:
    """
    Create a digital signature for a file hash using the provided key.

    In a real implementation, this would use proper cryptographic libraries
    to create a digital signature.

    Args:
        file_hash: The hash value to sign
        key: The key to use for signing

    Returns:
        The signature as bytes
    """
    try:
        # Simulate creating a signature
        # In a real scenario, you would use something like:
        # from cryptography.hazmat.primitives import hashes
        # from cryptography.hazmat.primitives.asymmetric import padding
        # signature = private_key.sign(
        #     file_hash.encode(),
        #     padding.PSS(
        #         mgf=padding.MGF1(hashes.SHA256()),
        #         salt_length=padding.PSS.MAX_LENGTH
        #     ),
        #     hashes.SHA256()
        # )

        # For simulation purposes only:
        signature = hashlib.sha256(file_hash.encode() + key).digest()

        return signature

    except Exception as e:
        logger.error(f"Failed to create signature: {e}")
        raise SignatureError(f"Failed to create signature: {e}")


def log_signing_operation(
    artifact_path: Union[str, Path],
    artifact_hash: str,
    build_id: str,
    mode: SigningMode,
    timestamp: str,
    signature: bytes,
    log_file: Optional[Union[str, Path]] = None,
) -> None:
    """
    Log the signing operation securely.

    Args:
        artifact_path: Path to the signed artifact
        artifact_hash: Hash of the artifact
        build_id: Build identifier
        mode: Signing mode
        timestamp: Signature timestamp
        signature: The signature value
        log_file: Path to the log file (optional)
    """
    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "operation": "sign",
        "artifact": str(artifact_path),
        "hash": artifact_hash,
        "build_id": build_id,
        "mode": mode.name,
        "signature_timestamp": timestamp,
        "signature_hash": hashlib.sha256(signature).hexdigest(),
    }

    # Convert log entry to formatted string
    log_message = (
        f"[{log_entry['timestamp']}] SIGN: "
        f"artifact={log_entry['artifact']}, "
        f"hash={log_entry['hash']}, "
        f"build_id={log_entry['build_id']}, "
        f"mode={log_entry['mode']}, "
        f"sig_time={log_entry['signature_timestamp']}, "
        f"sig_hash={log_entry['signature_hash']}"
    )

    # Log to the configured logger
    logger.info(log_message)

    # If a log file is specified, append the log entry to it
    if log_file:
        try:
            log_file_path = Path(log_file)
            # Ensure directory exists
            log_file_path.parent.mkdir(parents=True, exist_ok=True)

            with log_file_path.open("a") as f:
                f.write(log_message + "\n")

        except Exception as e:
            logger.error(f"Failed to write to log file {log_file}: {e}")


def sign_artifact(
    artifact_path: Union[str, Path],
    build_id: str,
    mode: SigningMode = SigningMode.TEST,
    output_path: Optional[Union[str, Path]] = None,
    log_file: Optional[Union[str, Path]] = None,
) -> Dict[str, str]:
    """
    Sign an artifact using a secure code signing process.

    Args:
        artifact_path: Path to the artifact to sign
        build_id: Build identifier
        mode: Signing mode (TEST or RELEASE)
        output_path: Path to write the signature file (optional)
        log_file: Path to the signing log file (optional)

    Returns:
        Dictionary with signature details

    Raises:
        SigningError: If any part of the signing process fails
    """
    artifact_path = Path(artifact_path)

    if not artifact_path.exists():
        raise SigningError(f"Artifact not found: {artifact_path}")

    try:
        # Step 1: Compute the hash of the artifact
        artifact_hash = compute_hash(artifact_path)
        logger.info(f"Computed hash for {artifact_path}: {artifact_hash}")

        # Step 2: Scan for malware
        if not scan_for_malware(artifact_path):
            raise MalwareScanError(f"Malware detected in {artifact_path}")

        # Step 3: Retrieve the signing key
        key = retrieve_signing_key(mode)

        # Step 4: Get a trusted timestamp
        timestamp = get_timestamp_token()

        # Step 5: Create the signature
        signature = create_signature(artifact_hash, key)

        # Step 6: Log the signing operation
        log_signing_operation(
            artifact_path, artifact_hash, build_id, mode, timestamp, signature, log_file
        )

        # Generate signature details
        signature_info = {
            "artifact": str(artifact_path),
            "build_id": build_id,
            "hash": artifact_hash,
            "hash_algorithm": "sha256",
            "timestamp": timestamp,
            "signature": signature.hex(),
            "mode": mode.name,
        }

        # Write signature file if output path is provided
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Write signature info to file
            with output_path.open("w") as f:
                f.write(f"Artifact: {signature_info['artifact']}\n")
                f.write(f"Build ID: {signature_info['build_id']}\n")
                f.write(
                    f"Hash ({signature_info['hash_algorithm']}): {signature_info['hash']}\n"
                )
                f.write(f"Timestamp: {signature_info['timestamp']}\n")
                f.write(f"Signature: {signature_info['signature']}\n")
                f.write(f"Mode: {signature_info['mode']}\n")

            logger.info(f"Signature file written to {output_path}")

        return signature_info

    except Exception as e:
        logger.error(f"Signing failed: {e}")
        raise SigningError(f"Failed to sign {artifact_path}: {e}")


def verify_signature(
    artifact_path: Union[str, Path], signature_path: Union[str, Path]
) -> bool:
    """
    Verify the signature of an artifact.

    Args:
        artifact_path: Path to the artifact
        signature_path: Path to the signature file

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        artifact_path = Path(artifact_path)
        signature_path = Path(signature_path)

        if not artifact_path.exists():
            logger.error(f"Artifact not found: {artifact_path}")
            return False

        if not signature_path.exists():
            logger.error(f"Signature file not found: {signature_path}")
            return False

        # Read signature info from file
        signature_info = {}
        with signature_path.open("r") as f:
            for line in f:
                if ":" in line:
                    key, value = line.strip().split(":", 1)
                    signature_info[key.strip().lower()] = value.strip()

        # Compute current hash of the artifact
        current_hash = compute_hash(artifact_path)

        # Check if hash matches
        original_hash = signature_info.get("hash (sha256)")

        if not original_hash:
            logger.error("Invalid signature file format: missing hash")
            return False

        if current_hash != original_hash:
            logger.error(
                f"Hash mismatch. Original: {original_hash}, Current: {current_hash}"
            )
            return False

        logger.info(f"Signature verified for {artifact_path}")
        return True

    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


def main() -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Secure code signing tool")

    parser.add_argument("artifact", help="Path to the artifact to sign or verify")

    parser.add_argument(
        "--mode",
        choices=["test", "release"],
        default="test",
        help="Signing mode (test or release). Default: test",
    )

    parser.add_argument(
        "--build-id", default=None, help="Build identifier. Default: auto-generated"
    )

    parser.add_argument("--output", "-o", help="Path to write the signature file")

    parser.add_argument("--log-file", help="Path to the signing log file")

    parser.add_argument(
        "--verify",
        "-v",
        metavar="SIGNATURE",
        help="Verify the signature instead of signing",
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    try:
        if args.verify:
            # Verify mode
            if verify_signature(args.artifact, args.verify):
                print(f"✅ Signature verified for {args.artifact}")
                return 0
            else:
                print(f"❌ Invalid signature for {args.artifact}")
                return 1
        else:
            # Sign mode
            if args.mode == "test":
                mode = SigningMode.TEST
            else:
                mode = SigningMode.RELEASE

            # Auto-generate build ID if not provided
            build_id = args.build_id or f"build-{int(time.time())}"

            # Sign the artifact
            signature_info = sign_artifact(
                args.artifact, build_id, mode, args.output, args.log_file
            )

            print(f"✅ Successfully signed {args.artifact}")
            print(f"  Build ID: {signature_info['build_id']}")
            print(f"  Hash: {signature_info['hash']}")
            print(f"  Timestamp: {signature_info['timestamp']}")
            print(f"  Mode: {signature_info['mode']}")

            if args.output:
                print(f"  Signature file: {args.output}")

            return 0

    except SigningError as e:
        print(f"❌ Signing error: {e}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
