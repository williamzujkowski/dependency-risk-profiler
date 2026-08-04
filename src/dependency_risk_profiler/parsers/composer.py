"""Readers for PHP Composer documents: the lock file and a ``require`` block."""

import json
import logging
from typing import Dict, Set

from ..models import DependencyMetadata
from .base import BaseParser

logger = logging.getLogger(__name__)

# What an unvendored Composer requirement actually resolves against: the PHP
# runtime, a compiled extension, a bundled library, or Composer's own plugin
# API. Named for legibility rather than used as the test — the test is the
# vendor prefix, for the reason spelled out in is_platform_requirement.
PLATFORM_REQUIREMENTS = frozenset({"php", "hhvm", "composer"})
PLATFORM_PREFIXES = ("php-", "ext-", "lib-", "composer-")


def is_platform_requirement(name: str) -> bool:
    """Return True when a ``require`` key names a runtime, not a package.

    ``php``, ``php-64bit``, ``ext-json``, ``lib-openssl`` and the
    ``composer-*-api`` constraints all describe the environment the package
    needs; none of them is something a consumer can be exposed to through the
    dependency graph. Counting them would inflate every PHP package's transitive
    footprint by one to five, and psr/log — whose only requirement is ``php`` —
    would report a dependency it does not have.

    The test is the vendor prefix, not the name. Packagist spells every real
    package ``vendor/name``, and several real vendors start with exactly the
    prefixes a platform constraint does — ``php-http/discovery``,
    ``php-di/php-di``, ``php-amqplib/php-amqplib``, ``composer/semver``. A
    prefix check that ran first would silently delete them; mailgun/mailgun-php
    requires three ``php-http/*`` packages and would report three of its six
    dependencies. So a slash settles it, and the named sets above describe the
    unvendored population rather than deciding it.

    Args:
        name: A key from a ``require`` or ``require-dev`` object.

    Returns:
        True when the requirement is a platform constraint.
    """
    lowered = name.strip().lower()
    if "/" in lowered:
        return False
    if lowered not in PLATFORM_REQUIREMENTS and not lowered.startswith(
        PLATFORM_PREFIXES
    ):
        # Unvendored and unrecognized. Still not a package Packagist can serve,
        # so it is dropped rather than counted as a phantom dependency — but it
        # is worth seeing, because it means this list has fallen behind.
        logger.debug("Unvendored Composer requirement outside the known set: %r", name)
    return True


def required_packages(require: object) -> Set[str]:
    """Return the packages a Composer ``require`` block names.

    Runtime requirements only. ``require-dev`` is a separate object and is not
    read here: it is what building the package needs, not what installing it
    pulls in, so it is out for the same reason maven excludes ``test`` and
    ``provided`` scopes and nuget's ``.nuspec`` states only runtime
    ``<dependencies>``. Counting it would make PHP packages look several times
    riskier than the ecosystems they are compared against — monolog declares two
    runtime requirements and nineteen dev ones.

    Args:
        require: The ``require`` value off a Packagist p2 release entry, or a
            ``composer.json``. Anything that is not an object yields an empty
            set, which the caller must not confuse with a measured zero.

    Returns:
        The ``vendor/name`` packages, platform constraints removed.
    """
    if not isinstance(require, dict):
        return set()
    return {
        name.strip()
        for name in require
        if isinstance(name, str) and name.strip() and not is_platform_requirement(name)
    }


class ComposerLockParser(BaseParser):
    """Parser for PHP composer.lock files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse composer.lock and extract the resolved packages.

        Returns:
            Dictionary mapping package names to their pinned metadata.
        """
        dependencies: Dict[str, DependencyMetadata] = {}
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.error("Could not read %s: %s", self.manifest_path, exc)
            return dependencies

        # composer.lock resolves both runtime and dev packages with concrete
        # versions; both sections are relevant to a dependency-risk scan.
        for section in ("packages", "packages-dev"):
            entries = data.get(section)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                version = entry.get("version")
                if not isinstance(name, str) or not isinstance(version, str):
                    continue
                if name in dependencies:
                    continue
                repo_url = None
                source = entry.get("source")
                if isinstance(source, dict):
                    url = source.get("url")
                    if isinstance(url, str):
                        repo_url = url
                dependencies[name] = DependencyMetadata(
                    name=name,
                    installed_version=version.lstrip("v"),
                    repository_url=repo_url,
                )
        return dependencies
