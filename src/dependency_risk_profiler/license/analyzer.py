"""License analyzer for dependencies."""

import logging
import re
from typing import Dict, Optional, Set

from ..models import DependencyMetadata, LicenseCategory, LicenseInfo, RiskLevel

logger = logging.getLogger(__name__)

# Common licenses and their categories
LICENSE_MAP = {
    # Permissive licenses
    "MIT": LicenseCategory.PERMISSIVE,
    "BSD": LicenseCategory.PERMISSIVE,
    "APACHE": LicenseCategory.PERMISSIVE,
    "APACHE-2.0": LicenseCategory.PERMISSIVE,
    "ISC": LicenseCategory.PERMISSIVE,
    "UNLICENSE": LicenseCategory.PERMISSIVE,
    "CC0": LicenseCategory.PERMISSIVE,
    # Copyleft licenses
    "GPL": LicenseCategory.COPYLEFT,
    "GPL-2.0": LicenseCategory.COPYLEFT,
    "GPL-3.0": LicenseCategory.COPYLEFT,
    "LGPL": LicenseCategory.COPYLEFT,
    "LGPL-2.1": LicenseCategory.COPYLEFT,
    "LGPL-3.0": LicenseCategory.COPYLEFT,
    "MPL": LicenseCategory.COPYLEFT,
    "MPL-2.0": LicenseCategory.COPYLEFT,
    # Network copyleft licenses
    "AGPL": LicenseCategory.NETWORK_COPYLEFT,
    "AGPL-3.0": LicenseCategory.NETWORK_COPYLEFT,
    # Commercial licenses
    "COMMERCIAL": LicenseCategory.COMMERCIAL,
    "PROPRIETARY": LicenseCategory.COMMERCIAL,
}

# Risk levels for license categories
LICENSE_RISK_LEVELS = {
    LicenseCategory.PERMISSIVE: RiskLevel.LOW,
    LicenseCategory.COPYLEFT: RiskLevel.MEDIUM,
    LicenseCategory.NETWORK_COPYLEFT: RiskLevel.HIGH,
    LicenseCategory.COMMERCIAL: RiskLevel.HIGH,
    LicenseCategory.UNKNOWN: RiskLevel.CRITICAL,
}

# Organizational license approval policy (default to allowing permissive licenses)
APPROVED_LICENSES = {
    LicenseCategory.PERMISSIVE,
}


def parse_license_from_string(license_text: str) -> Optional[str]:
    """Parse license ID from a license string.

    Args:
        license_text: License string to parse.

    Returns:
        Normalized license ID or None if not recognized.
    """
    if not license_text:
        return None

    # Clean up license text
    license_text = license_text.upper().strip()

    # Try to match common license patterns
    license_patterns = [
        r"MIT",
        r"BSD[\s-]?(\d-CLAUSE)?",
        r"APACHE[\s-]?(\d\.\d)?",
        r"GPL[\s-]?(\d\.\d)?",
        r"LGPL[\s-]?(\d\.\d)?",
        r"AGPL[\s-]?(\d\.\d)?",
        r"MPL[\s-]?(\d\.\d)?",
        r"ISC",
        r"UNLICENSE[D]?",
        r"CC0[\s-]?(\d\.\d)?",
    ]

    for pattern in license_patterns:
        match = re.search(pattern, license_text)
        if match:
            return match.group(0).strip()

    return None


def categorize_license(license_id: str) -> LicenseCategory:
    """Categorize a license based on its ID.

    Args:
        license_id: SPDX ID or license name.

    Returns:
        License category.
    """
    if not license_id:
        return LicenseCategory.UNKNOWN

    # Normalize license ID
    normalized_id = license_id.upper().strip()

    # Check known licenses
    for known_license, category in LICENSE_MAP.items():
        if known_license in normalized_id:
            return category

    # Default to unknown
    return LicenseCategory.UNKNOWN


def analyze_license_compatibility(licenses: Set[str]) -> RiskLevel:
    """Analyze compatibility between multiple licenses.

    Args:
        licenses: Set of license IDs.

    Returns:
        Risk level based on license compatibility.
    """
    if not licenses:
        return RiskLevel.MEDIUM  # Default to MEDIUM risk when license is unknown

    # Check if any license is unknown
    for license_id in licenses:
        category = categorize_license(license_id)
        if category == LicenseCategory.UNKNOWN:
            return RiskLevel.CRITICAL

    # Check for network copyleft licenses
    for license_id in licenses:
        category = categorize_license(license_id)
        if category == LicenseCategory.NETWORK_COPYLEFT:
            return RiskLevel.HIGH

    # Check for copyleft licenses
    has_copyleft = False
    for license_id in licenses:
        category = categorize_license(license_id)
        if category == LicenseCategory.COPYLEFT:
            has_copyleft = True

    if has_copyleft:
        return RiskLevel.MEDIUM

    # All permissive licenses
    return RiskLevel.LOW


def extract_license_info(metadata: Dict) -> Optional[LicenseInfo]:
    """Extract license information from package metadata.

    Args:
        metadata: Package metadata.

    Returns:
        License information, or None if not available.
    """
    license_text = None

    # Check common metadata fields for license information
    if "license" in metadata:
        license_text = metadata["license"]
    elif "info" in metadata and "license" in metadata["info"]:
        license_text = metadata["info"]["license"]
    elif "info" in metadata and "classifiers" in metadata["info"]:
        # Look for license in PyPI classifiers
        for classifier in metadata["info"]["classifiers"]:
            if "License ::" in classifier:
                license_text = classifier.split("::")[-1].strip()
                break

    if not license_text:
        return None

    # Parse license
    license_id = parse_license_from_string(license_text)
    if not license_id:
        return LicenseInfo(
            license_id=license_text,
            category=LicenseCategory.UNKNOWN,
            is_approved=False,
            risk_level=RiskLevel.CRITICAL,
        )

    # Categorize license
    category = categorize_license(license_id)

    # Determine risk level
    risk_level = LICENSE_RISK_LEVELS.get(category, RiskLevel.CRITICAL)

    # Check if license is approved
    is_approved = category in APPROVED_LICENSES

    return LicenseInfo(
        license_id=license_id,
        category=category,
        is_approved=is_approved,
        risk_level=risk_level,
    )


def analyze_license(
    dependency: DependencyMetadata, metadata: Dict
) -> DependencyMetadata:
    """Analyze license for a dependency.

    Args:
        dependency: Dependency metadata.
        metadata: Package metadata.

    Returns:
        Updated dependency metadata with license information.
    """
    logger.info(f"Analyzing license for {dependency.name}")

    try:
        license_info = extract_license_info(metadata)
        if license_info:
            dependency.license_info = license_info
            logger.info(
                f"Found license {license_info.license_id} ({license_info.category.value}) for {dependency.name}"
            )
        else:
            logger.warning(f"No license information found for {dependency.name}")
    except Exception as e:
        logger.error(f"Error analyzing license for {dependency.name}: {e}")

    return dependency
