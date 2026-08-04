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
def first_license_string(value: object) -> Optional[str]:
    """Return the first non-empty license string in a metadata value.

    Registries disagree on the shape as well as the key: npm and PyPI publish a
    plain string, while RubyGems and Packagist publish a *list* (``["MIT"]``).
    Lists are flattened so a list-valued field is read rather than discarded.

    Args:
        value: Raw value read from package metadata.

    Returns:
        License string, or None when the value carries none.
    """
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, (list, tuple)):
        for item in value:
            text = first_license_string(item)
            if text:
                return text
    return None


def extract_license_text(metadata: Dict) -> Optional[str]:
    """Return the raw license string published in package metadata.

    Both the top level and PyPI's nested ``info`` object are searched under
    every spelling, because the key differs per registry and, on PyPI, per
    metadata version: ``licenses`` (a list) on RubyGems and Packagist,
    ``license`` (free text) on npm and legacy PyPI, and ``license_expression``
    (an SPDX expression) on PyPI packages built to metadata 2.4 / PEP 639.
    ``license_expression`` is tried first because where PyPI publishes it, it
    is the authoritative field and ``license`` is null.

    That last spelling was #145's class of dead read, found by capturing live
    PyPI payloads for the conformance harness: 17 of 30 sampled popular
    packages — flask, pytest, urllib3, cryptography, django, numpy — publish
    ``license_expression`` with ``license: null`` and no ``License ::``
    classifier, so the license signal read as unmeasured for all of them while
    the payload stated the licence in plain sight.

    PyPI's ``License ::`` classifiers are the last resort.

    Args:
        metadata: Package metadata.

    Returns:
        License string, or None when the metadata carries none.
    """
    info = metadata.get("info")
    for source in (metadata, info if isinstance(info, dict) else None):
        if source is None:
            continue
        for key in ("license_expression", "license", "licenses"):
            license_text = first_license_string(source.get(key))
            if license_text:
                return license_text

    if isinstance(info, dict):
        # Look for license in PyPI classifiers
        classifiers = info.get("classifiers")
        if isinstance(classifiers, (list, tuple)):
            for classifier in classifiers:
                if isinstance(classifier, str) and "License ::" in classifier:
                    return classifier.split("::")[-1].strip()

    return None


def extract_license_info(metadata: Dict) -> Optional[LicenseInfo]:
    """Extract license information from package metadata.

    Args:
        metadata: Package metadata.

    Returns:
        License information, or None if not available.
    """
    license_text = extract_license_text(metadata)

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
                f"Found license {license_info.license_id} "
                f"({license_info.category.value}) for {dependency.name}"
            )
        else:
            logger.warning(f"No license information found for {dependency.name}")
    except Exception as e:
        logger.error(f"Error analyzing license for {dependency.name}: {e}")

    return dependency
