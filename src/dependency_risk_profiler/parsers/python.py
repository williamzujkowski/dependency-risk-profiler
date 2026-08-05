"""Readers for Python documents: requirement files and PyPI's ``requires_dist``."""

import json
import logging
import re
from typing import Dict, List, Optional, Sequence, Set

from ..models import DependencyMetadata
from .base import BaseParser
from .python_requirements import (
    DeclaredRequirement,
    normalized_name,
    python_dependency,
    read_requirement,
    read_version_specifier,
    requirement_lines,
)

logger = logging.getLogger(__name__)

# PEP 508's project-name grammar, anchored at the head of a requirement string.
# Everything after it is a version specifier, an extras list, a URL reference,
# or a marker, and none of those is part of the name.
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")

# ``extra`` used as a PEP 508 *marker variable* — the left or the right side of
# a comparison. Anchored on the word so that it cannot match inside a name, a
# quoted string, or another marker variable. See ``_is_extras_only`` for why
# this is a regex over the marker section rather than a substring test over the
# requirement, which is the trap.
_EXTRA_MARKER = re.compile(r"(?<![A-Za-z0-9._-])extra(?![A-Za-z0-9._-])")


def _requirement_name(requirement: str) -> Optional[str]:
    """Return the project name at the head of a PEP 508 requirement, or None.

    Args:
        requirement: One ``requires_dist`` entry, e.g. ``idna<4,>=2.5`` or
            ``PySocks!=1.5.7,>=1.5.6; extra == "socks"``.

    Returns:
        The project name as written, or None when the entry does not start
        with one.
    """
    match = _REQUIREMENT_NAME.match(requirement)
    return match.group(1) if match is not None else None


def _is_extras_only(requirement: str) -> bool:
    """Return whether a requirement is gated behind an extra.

    ``pip install requests`` does not install ``PySocks``; ``pip install
    requests[socks]`` does. An extras-gated requirement is therefore optional
    tooling — the test suite, the docs build, the async backend — and is out for
    the same reason ``require-dev``, ``devDependencies`` and maven's ``test``
    scope are out.

    **The test is the marker section, not the requirement string.** ``extras``
    is a real, installable PyPI project (testtools depends on it), and so are
    ``pytest-extra`` and ``sphinx-extras``. A substring sweep for ``extra``
    over the whole requirement silently deletes every one of them — the same
    shape as #190, where a Composer platform check that matched on the name
    prefix rather than the vendor slash would have deleted ``php-http/discovery``
    and ``php-di/php-di``. So the name is severed at the semicolon first, and
    only what follows is examined.

    Environment markers that are *not* extras stay: ``importlib-metadata;
    python_version < "3.10"`` and ``tzdata; sys_platform == "win32"`` are
    runtime dependencies on the interpreters and platforms they name, and a
    consumer on one of those does install them.

    Args:
        requirement: One ``requires_dist`` entry.

    Returns:
        True when the entry's marker mentions the ``extra`` variable.
    """
    _, separator, marker = requirement.partition(";")
    if not separator:
        return False
    return _EXTRA_MARKER.search(marker) is not None


def runtime_requirement_names(requires_dist: object) -> Optional[Set[str]]:
    """Return the runtime dependencies a PyPI ``requires_dist`` list names.

    ``null`` is not zero, and that is the whole reason this returns Optional.
    PyPI publishes ``requires_dist: null`` whenever the newest release carries
    no ``Requires-Dist`` metadata at all, and an sdist-only upload predating
    metadata 2.1 has none *whatever its dependencies are*: ``carbon`` and
    ``graphite-web`` both report null and both declare real ``install_requires``
    in their ``setup.py``. Reading that as "resolved, and it is empty" would be
    #141's fabricated zero with a fresh source, so it is returned as None and
    the signal stays honestly unmeasured. The cost is real and accepted —
    ``six``, ``certifi``, ``pytz`` and ``chardet`` genuinely have no
    dependencies and also report null, so they lose a signal they could have
    had. An honest gap beats a confident wrong number (#74).

    A *list* is a measurement, including an empty one and including one whose
    every entry is extras-gated: ``mock`` and ``supervisor`` publish nothing but
    ``extra ==`` entries and have a measured zero runtime dependencies.

    Args:
        requires_dist: The ``info.requires_dist`` value off a
            ``pypi.org/pypi/<name>/json`` payload.

    Returns:
        The runtime project names, or None when PyPI published no requirement
        metadata to read.
    """
    if not isinstance(requires_dist, Sequence) or isinstance(
        requires_dist, (str, bytes)
    ):
        return None

    entries: List[str] = [item for item in requires_dist if isinstance(item, str)]
    names: Set[str] = set()
    for entry in entries:
        if _is_extras_only(entry):
            continue
        head, _, _ = entry.partition(";")
        name = _requirement_name(head)
        if name is None:
            # A direct URL reference with no name, or something PyPI let
            # through that PEP 508 does not describe. Not countable as a
            # package, and worth seeing when it happens.
            logger.debug("Unparseable requires_dist entry: %r", entry)
            continue
        names.add(name)
    return names


class PythonParser(BaseParser):
    """Parser for Python requirements.txt files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse the requirements.txt file and extract dependencies.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        # Determine if this is a requirements.txt or Pipfile.lock file
        if self.manifest_path.name.lower() == "pipfile.lock":
            return self._parse_pipfile_lock()
        else:
            return self._parse_requirements_txt()

    def _parse_requirements_txt(self) -> Dict[str, DependencyMetadata]:
        """Parse a requirements.txt file.

        Every line goes through :func:`~.python_requirements.read_requirement`,
        which is pip's own PEP 508 parser, so a bound stays a bound and only a
        ``==`` to one concrete version becomes an ``installed_version`` (#275).
        The chain of ``if "==" in line / elif ">=" in line`` this replaced had
        seven branches and got four shapes wrong; the specifier grammar has one
        implementation and gets them right for free.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        dependencies: Dict[str, DependencyMetadata] = {}

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                text = f.read()

            for line in requirement_lines(text):
                requirement = read_requirement(line)
                if requirement is None:
                    # Not a requirement pip would accept either. Naming a
                    # package after it is how `requests-toolbelt!` reached a
                    # registry lookup, so it is reported and dropped.
                    logger.warning(
                        "%s: cannot read %r as a requirement; skipping",
                        self.manifest_path,
                        line,
                    )
                    continue
                dependencies[requirement.name] = python_dependency(requirement)

            unpinned = sum(
                1
                for metadata in dependencies.values()
                if not metadata.installed_version
            )
            if unpinned:
                logger.info(
                    "%d of %d requirements in %s state a constraint rather than "
                    "one version; their version-drift signal is reported as "
                    "unmeasured and advisories against them as "
                    "applicability-unknown, not resolved against a bound",
                    unpinned,
                    len(dependencies),
                    self.manifest_path,
                )
            return dependencies
        except OSError as e:
            raise ValueError(f"Error parsing requirements.txt: {e}") from e

    def _parse_pipfile_lock(self) -> Dict[str, DependencyMetadata]:
        """Parse a Pipfile.lock file.

        Returns:
            Dictionary mapping dependency names to their metadata.
        """
        dependencies = {}

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Extract default dependencies
            default_packages = data.get("default", {})
            dev_packages = data.get("develop", {})

            # Process default packages
            for name, info in default_packages.items():
                requirement = self._pipfile_requirement(name, info)
                dependencies[requirement.name] = python_dependency(requirement)

            # Process dev packages
            for name, info in dev_packages.items():
                requirement = self._pipfile_requirement(name, info)
                # Skip if already in default packages
                if requirement.name in dependencies:
                    continue

                dependencies[requirement.name] = python_dependency(
                    requirement, {"dev_dependency": "true"}
                )

            return dependencies
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"Error parsing Pipfile.lock: {e}") from e

    @staticmethod
    def _pipfile_requirement(name: str, info: object) -> DeclaredRequirement:
        """Read one Pipfile.lock entry.

        Entries are usually ``{"version": "==1.2.3", …}`` but can also be a bare
        version string, so both shapes are handled without assuming a dict.

        A lock file is where a pin is expected, and the ``==`` form is one — but
        not every entry carries one. ``"*"`` appears for an entry pinned by
        ``git``/``ref`` rather than by version, and an editable or VCS entry may
        carry no ``version`` key at all. Those name no version, and #275 is that
        such an entry must not be scored as though they did: ``"*"`` is exactly
        the ``latest`` sentinel wearing a different hat.

        Args:
            name: The package name as the lock file wrote it.
            info: The entry value.

        Returns:
            The declaration, pinned when the entry states one version.
        """
        if isinstance(info, dict):
            raw = info.get("version")
        elif isinstance(info, str):
            raw = info
        else:
            raw = None
        if not isinstance(raw, str) or not raw.strip():
            return DeclaredRequirement(
                name=normalized_name(name), pinned_version=None, constraint=None
            )
        return read_version_specifier(name, raw.strip())
