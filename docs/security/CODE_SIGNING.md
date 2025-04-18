# Code Signing

The Dependency Risk Profiler project implements a secure code signing system for its releases to ensure the integrity and authenticity of distributed artifacts.

## Overview

Code signing provides several important security benefits:

1. **Authenticity**: Verifies that the package was created by the project's maintainers
2. **Integrity**: Ensures the package hasn't been tampered with since it was signed
3. **Non-repudiation**: Provides evidence of the source of the package
4. **Trust**: Increases user confidence in the software they're installing

## How Code Signing Works

The project's code signing process includes the following steps:

1. **Hash computation**: A cryptographic hash (SHA-256) is calculated for each artifact
2. **Malware scanning**: Artifacts are scanned for potential security issues
3. **Signature creation**: A digital signature is created using a secure signing key
4. **Timestamping**: A trusted timestamp is applied to prove when the signature was created
5. **Signature storage**: The signature is stored alongside the artifact

## Verifying Package Signatures

All official releases include signature files (.sig) that can be used to verify package authenticity:

```bash
# Install the package if you haven't already
pip install dependency-risk-profiler

# Verify a signature
python -m dependency_risk_profiler.secure_release.code_signing package.whl --verify package.whl.sig
```

If the verification is successful, you'll see:
```
✅ Signature verified for package.whl
```

## Implementation Details

The code signing implementation:

- Is written entirely in Python for portability
- Follows industry best practices for security
- Uses strong cryptographic algorithms
- Includes comprehensive logging for audit purposes
- Is integrated into the automated CI/CD pipeline

## Development and Testing

For development purposes, the code signing module supports a `TEST` mode that uses simulated signing keys. In production releases, `RELEASE` mode is used with securely managed keys.

## Using the Code Signing Tool

The code signing module can be used as a standalone tool:

```bash
# Sign an artifact
python -m dependency_risk_profiler.secure_release.code_signing artifact.zip --build-id release-123 --mode release --output artifact.zip.sig

# Verify a signature
python -m dependency_risk_profiler.secure_release.code_signing artifact.zip --verify artifact.zip.sig
```

## Security Considerations

- In a real-world production environment, signing keys would be stored in Hardware Security Modules (HSMs) or secure key management services
- The current implementation uses simulated keys for demonstration purposes
- While the cryptographic operations are implemented correctly, the key management aspect would need to be enhanced for a truly secure production deployment