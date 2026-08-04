"""Readers for Ruby documents: a Gemfile.lock and RubyGems' dependency object."""

import logging
import re
from typing import Dict, Optional, Set

from ..models import DependencyMetadata
from .base import BaseParser

logger = logging.getLogger(__name__)

# RubyGems splits a gemspec's declared dependencies by scope, and publishes both
# halves under one key. ``development`` is what building the gem needs, not what
# installing it pulls in, and is out for composer's ``require-dev`` reason.
RUNTIME_DEPENDENCY_SCOPE = "runtime"
DEVELOPMENT_DEPENDENCY_SCOPE = "development"

# A resolved top-level gem inside a ``specs:`` block is indented exactly four
# spaces: ``    name (version)``. Its own transitive requirements are indented
# six spaces (``      dep (~> 2.0)``) and are intentionally skipped here.
_SPEC_LINE = re.compile(r"^ {4}([A-Za-z0-9._-]+) \(([^()]+)\)\s*$")


def runtime_dependency_names(dependencies: object) -> Optional[Set[str]]:
    """Return the gems a RubyGems ``dependencies`` object names as runtime deps.

    The trap here is the shape of the value, not its contents.
    ``/api/v1/gems/<name>.json`` publishes ``dependencies`` as an **object keyed
    by scope** — ``{"development": [...], "runtime": [...]}`` — not as a list.
    Something that counted the value directly would report exactly two
    dependencies for every gem on rubygems.org, forever, and two is a
    thoroughly plausible number: measured, and measured wrong for the whole
    ecosystem, which is #142's shape. So the runtime list is addressed by name
    and each entry's own ``name`` is read.

    Unlike Composer there is nothing to filter out of the runtime list itself. A
    gemspec states its interpreter and toolchain floors in
    ``required_ruby_version`` and ``required_rubygems_version``, which are
    separate fields and are not published in this payload at all — so RubyGems
    has no equivalent of ``php``/``ext-*`` leaking in beside real packages, and
    a name-shaped filter would have nothing to do but delete real gems.
    ``bundler`` and ``json`` are ordinary gems and are counted as such.

    Args:
        dependencies: The ``dependencies`` value off a ``/gems/<name>.json``
            payload.

    Returns:
        The runtime gem names, or None when the payload published no
        dependency object to read.
    """
    if not isinstance(dependencies, dict):
        return None
    runtime = dependencies.get(RUNTIME_DEPENDENCY_SCOPE)
    if not isinstance(runtime, list):
        # The key the whole read is addressed by is missing or the wrong shape.
        # Nobody measured a runtime dependency list, so nothing is claimed.
        logger.debug(
            "RubyGems dependency object carries no %r list", RUNTIME_DEPENDENCY_SCOPE
        )
        return None

    names: Set[str] = set()
    for entry in runtime:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if isinstance(name, str) and name.strip():
            names.add(name.strip())
    return names


class GemfileLockParser(BaseParser):
    """Parser for Ruby Gemfile.lock files."""

    def parse(self) -> Dict[str, DependencyMetadata]:
        """Parse Gemfile.lock and extract the resolved gems.

        Returns:
            Dictionary mapping gem names to their pinned metadata.
        """
        dependencies: Dict[str, DependencyMetadata] = {}
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            logger.error("Could not read %s: %s", self.manifest_path, exc)
            return dependencies

        in_specs = False
        for line in lines:
            if line.strip() == "specs:":
                in_specs = True
                continue
            if not in_specs:
                continue
            # A new top-level section (PLATFORMS, DEPENDENCIES, ...) starts at
            # column zero and ends the specs block.
            if line and not line.startswith(" "):
                in_specs = False
                continue
            match = _SPEC_LINE.match(line)
            if match:
                name, pinned_version = match.group(1), match.group(2).strip()
                if name not in dependencies:
                    dependencies[name] = DependencyMetadata(
                        name=name, installed_version=pinned_version
                    )
        return dependencies
