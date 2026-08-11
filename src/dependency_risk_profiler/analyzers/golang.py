"""Analyzer for Go dependencies."""

import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ..analysis_helpers import analyze_repository
from ..go_modules import GoModuleResolver
from ..models import DependencyMetadata
from ..release_dates import (
    RepositoryResolution,
    apply_registry_release_date,
    parse_registry_timestamp,
    record_source_repository,
)
from ..transitive.analyzer_enhanced import record_transitive_source
from ..utils import cloned_repo, fetch_json, fetch_url
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

# Go states a module's own retirement in its ``go.mod``: a ``// Deprecated:``
# comment attached to the ``module`` directive, which is what ``go list -m -u``
# reports and what pkg.go.dev renders as the retirement banner
# (https://go.dev/ref/mod#go-mod-file-module). The module proxy serves that file
# verbatim at ``@v/<version>.mod``, so it is one cheap read away — and until
# #73's conformance capture, nothing read it. ``is_deprecated`` was therefore
# False for every Go module ever scanned: measured, and measured wrong, which is
# #142's shape exactly.
_DEPRECATED_COMMENT = re.compile(r"^\s*//\s*Deprecated:\s*(?P<notice>.*)$")

# The proxy escapes uppercase letters in a module path — and in a version — as
# "!<lower>", so that its storage is case-insensitive-safe.
_UPPERCASE = re.compile(r"[A-Z]")

# Go's version grammar, tightened. The version is pasted into a URL path, and
# it arrives from a registry response rather than from the manifest, so it is
# validated before it becomes a path segment rather than trusted because the
# proxy sent it.
_MODULE_VERSION = re.compile(r"^v[0-9][A-Za-z0-9.\-+]{0,127}$")

# Go is the one ecosystem of the nine that abstains on the transitive signal,
# and it abstains on purpose rather than by omission (#204).
#
# The data is there: the ``go.mod`` this adapter already fetches for the
# ``// Deprecated:`` marker carries the module's ``require`` block. What it does
# not carry is a **scope**. Every other ecosystem publishes the runtime/test
# line the signal is defined on — nuget's nuspec states runtime
# ``<dependencies>``, maven filters by scope, composer splits ``require`` from
# ``require-dev``, npm from ``devDependencies``, cargo by ``kind`` — and go.mod
# has no such split. ``go mod tidy`` writes the test-only requirements of a
# module's own packages into the same direct ``require`` block as its runtime
# ones, and sirupsen/logrus is the ordinary case rather than a corner: two
# direct requires, of which ``github.com/stretchr/testify`` is test-only. The
# ``// indirect`` marker does not help; it separates depth, not scope.
#
# Counting the block anyway would report roughly double for the large fraction
# of Go modules that test with testify, systematically, and would make Go
# modules look uniformly riskier than the ecosystems they are compared against —
# which is the *opposite* of the like-for-like comparison #204 exists to
# restore. So the signal is recorded as UNMEASURED, positively, with this as
# the reason.
TRANSITIVE_UNMEASURED_REASON = (
    "go.mod states no dependency scope: a module's test-only requirements sit "
    "in the same require block as its runtime ones, so the block cannot answer "
    "'runtime dependencies' without over-counting."
)


def _escape_module_path(value: str) -> str:
    """Return a module path or version in the proxy's escaped spelling."""
    return _UPPERCASE.sub(lambda match: "!" + match.group(0).lower(), value)


def deprecation_notice(go_mod: str) -> Optional[str]:
    """Return the module-level deprecation notice in a ``go.mod``, or None.

    Go attaches the notice to the ``module`` directive as a block of
    ``// Deprecated:`` comment lines immediately above it. Only that block
    counts: a ``// Deprecated:`` comment sitting above a ``require`` line is
    about the *dependency*, not about this module, and reading it would flag
    every consumer of a retired package as retired itself.

    Args:
        go_mod: The contents of a ``go.mod`` file.

    Returns:
        The notice text (possibly empty), or None when the module is not
        deprecated.
    """
    notice: Optional[str] = None
    for line in go_mod.splitlines():
        stripped = line.strip()
        if not stripped:
            # A blank line detaches a comment block from what follows it.
            notice = None
            continue
        match = _DEPRECATED_COMMENT.match(line)
        if match is not None:
            notice = match.group("notice").strip()
            continue
        if stripped.startswith("//"):
            continue
        if stripped.split()[0] == "module":
            return notice
        return None
    return None


class GoAnalyzer(BaseAnalyzer):
    """Analyzer for Go dependencies."""

    def __init__(self, timeout: int = 30):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        # Cache for package metadata
        self.metadata_cache: Dict[str, Dict[str, object]] = {}
        # Module path -> repository. A module path is an import path, not a
        # repository URL: see ..go_modules for the three rules between them.
        self.resolver = GoModuleResolver()

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Go dependencies and collect metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        repositories = self._resolve_repositories(dependencies)
        if self.clone_repos:
            self._analyze_repositories(dependencies, repositories)
        return dependencies

    def _resolve_repositories(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, List[str]]:
        """Collect proxy metadata and map each module to its repository.

        Returns:
            Repository URL -> the dependency names hosted in it. Modules that do
            not resolve are absent, so their repository-derived signals stay
            unmeasured rather than guessed.
        """
        repositories: Dict[str, List[str]] = {}
        for name, dep in dependencies.items():
            logger.info(f"Analyzing Go package: {name}")
            # Set the OSV ecosystem explicitly; the URL heuristic only matches
            # module paths that happen to contain a "go" token, so packages
            # like github.com/sirupsen/logrus would otherwise misroute to PyPI.
            dep.additional_info["ecosystem"] = "golang"

            # Said out loud rather than left to the fail-closed default. The
            # read is the same either way; the difference is that #204's audit
            # of this ecosystem is now recorded at the call site instead of
            # being indistinguishable from an adapter nobody has looked at.
            # See TRANSITIVE_UNMEASURED_REASON.
            record_transitive_source(dep, source=None)

            try:
                # Get latest version from proxy.golang.org. This uses the full
                # module path, major-version suffix included — that is what the
                # module proxy is keyed on.
                latest_version, released = self._get_latest(name)
                if latest_version:
                    dep.latest_version = latest_version
                    # Store minimal metadata in cache
                    self.metadata_cache[name] = {
                        "name": name,
                        "latest_version": latest_version,
                    }
                    deprecated = self._is_deprecated(name, latest_version)
                    if deprecated is not None:
                        dep.record_deprecation(deprecated=deprecated)

                # ``@latest`` dates the release it names. Nothing read that
                # field, so a Go module's cadence was unmeasured unless the
                # scan cloned its repository — and an abandoned module is
                # exactly the one whose repository has been archived or renamed
                # (#146).
                apply_registry_release_date(dep, released)

                # Go is the one ecosystem with no separate repository field: the
                # import path *is* the declaration, so a Go module is never
                # UNDECLARED. Either the path resolves to a forge this tool can
                # read, or it names something it cannot — go.googlesource.com, a
                # private vanity host, a path with no repository in it — which
                # is the declared-but-unusable state (#176, #137).
                resolution = self.resolver.resolve_module(name)
                if resolution.lookup_failed:
                    # The vanity host did not answer. Nobody measured anything,
                    # so nothing is recorded (#182).
                    logger.debug("Source repository lookup failed for %s", name)
                    continue
                repository = resolution.repository
                if repository is None:
                    # Go has no separate repository field: the module path is
                    # the declaration, and one that resolves to no repository
                    # is the declared-but-unusable state (#176, #137). There is
                    # one candidate here, so there is no second key-set for the
                    # declaration to disagree with (#290).
                    logger.debug("No source repository resolved for %s", name)
                    record_source_repository(
                        dep, RepositoryResolution(url=None, declared=name)
                    )
                    continue
                dep.repository_url = repository.url
                record_source_repository(
                    dep,
                    RepositoryResolution(url=repository.url, declared=repository.url),
                )
                if repository.subdirectory:
                    # Many modules can share one repository; record where this
                    # one lives so a shared repository URL is not confusing.
                    dep.additional_info["module_subdirectory"] = repository.subdirectory
                repositories.setdefault(repository.url, []).append(name)
            except Exception as e:
                logger.error(f"Error analyzing {name}: {e}")

        return repositories

    def _analyze_repositories(
        self,
        dependencies: Dict[str, DependencyMetadata],
        repositories: Dict[str, List[str]],
    ) -> None:
        """Clone each repository once and analyze every module it hosts.

        Subdirectory modules mean one repository can back dozens of
        dependencies; cloning per repository rather than per dependency keeps
        that from multiplying the network cost by the same factor.
        """
        for repo_url, names in repositories.items():
            # Clone the repository into a self-cleaning temp dir
            # (skipped for org scans, which use API signals instead).
            with cloned_repo(repo_url) as clone_result:
                if not clone_result:
                    continue
                repo_dir, _ = clone_result
                for name in names:
                    try:
                        # Helper avoids circular imports.
                        dependencies[name] = analyze_repository(
                            dependencies[name], repo_dir
                        )
                    except Exception as e:
                        logger.error(f"Error analyzing repository for {name}: {e}")

    def _get_latest_version(self, package_name: str) -> Optional[str]:
        """Get the latest version of a Go package.

        Args:
            package_name: Name of the Go package.

        Returns:
            The latest version string, or None if fetching failed.
        """
        return self._get_latest(package_name)[0]

    def _get_latest(
        self, package_name: str
    ) -> Tuple[Optional[str], Optional[datetime]]:
        """Return the module's latest version and the date that version shipped.

        Args:
            package_name: Go module path.

        Returns:
            The version string and the parsed publication timestamp, either of
            which is None when the proxy does not answer with it.
        """
        # Query the Go module proxy's JSON endpoint instead of scraping HTML —
        # it is stable and version-correct (pseudo-versions, +incompatible).
        data = fetch_json(
            f"https://proxy.golang.org/{_escape_module_path(package_name)}/@latest",
            self.timeout,
        )
        if not isinstance(data, dict):
            return None, None
        version = data.get("Version")
        if not isinstance(version, str) or not version:
            return None, None
        return version, parse_registry_timestamp(data.get("Time"))

    def _is_deprecated(self, package_name: str, version: str) -> Optional[bool]:
        """Return what the module's own ``go.mod`` says about retirement.

        ``None`` is the answer when no ``go.mod`` was read: a version string
        the grammar refuses, or a proxy that did not send one. A marker nobody
        could read is not a marker saying the module is fine, and the state
        that says so is where that answer goes (#320).

        Args:
            package_name: Go module path.
            version: The version whose ``go.mod`` to read.

        Returns:
            True when a ``// Deprecated:`` comment precedes the ``module``
            directive, False when a ``go.mod`` was read and carries none, None
            when none was read.
        """
        if not _MODULE_VERSION.match(version):
            logger.debug("Refusing malformed Go module version: %r", version)
            return None
        url = (
            f"https://proxy.golang.org/{_escape_module_path(package_name)}"
            f"/@v/{_escape_module_path(version)}.mod"
        )
        body = fetch_url(url, self.timeout)
        if not isinstance(body, str) or not body:
            return None
        return deprecation_notice(body) is not None
