"""Analyzer for Python dependencies."""

import logging
import re
from typing import Dict, Iterator, Mapping, Optional, Sequence

from ..models import DependencyMetadata
from ..release_dates import (
    apply_registry_release_date,
    newest_timestamp,
    record_source_repository,
)
from .base import BaseAnalyzer
from .common import canonical_repository_url, collect_repository_signals, fetch_json

logger = logging.getLogger(__name__)

# project_urls keys that name a source repository, most explicit first. PyPI
# lets a maintainer label the link anything, so the match is on the key, but
# "Code of Conduct" must not read as "Code" — hence exact-ish tokens rather
# than the old substring sweep.
_SOURCE_URL_KEYS: Sequence[str] = (
    "source",
    "source code",
    "repository",
    "repo",
    "code",
    "github",
    "gitlab",
    "bitbucket",
)

# project_urls labels that point at something hosted but not at source.
_NON_SOURCE_URL_KEYS: Sequence[str] = (
    "fund",
    "sponsor",
    "donat",
    "tracker",
    "issue",
    "bug",
    "changelog",
    "release notes",
    "discussion",
    "chat",
    "twitter",
    "mastodon",
)

# Deliberate one-line deprecation notices, checked against info.summary only.
_SUMMARY_DEPRECATION_TERMS: Sequence[str] = (
    "deprecated",
    "unmaintained",
    "abandoned",
)


class PythonAnalyzer(BaseAnalyzer):
    """Analyzer for Python dependencies."""

    def __init__(self, timeout: int = 30):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        # Cache for package metadata
        self.metadata_cache = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Python dependencies and collect metadata.

        Args:
            dependencies: Dictionary mapping dependency names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info(f"Analyzing Python package: {name}")
            # Set the OSV ecosystem explicitly rather than leaning on the
            # aggregator's "default to PyPI" behavior, so routing stays correct
            # regardless of heuristic changes.
            dep.additional_info["ecosystem"] = "python"

            try:
                # Get PyPI package information
                pypi_data = self._get_pypi_package_info(name)
                if not pypi_data:
                    continue

                # Store in cache for other analyzers to use
                self.metadata_cache[name] = pypi_data
                self._apply_registry_metadata(dep, pypi_data)

                # Repository-derived signals refine what the registry already
                # answered; they no longer decide whether the package has a
                # measurable release cadence at all.
                dependencies[name] = collect_repository_signals(
                    dep, dep.repository_url, self.clone_repos
                )
            except Exception as e:
                logger.error(f"Error analyzing {name}: {e}")

        return dependencies

    def _apply_registry_metadata(
        self, dep: DependencyMetadata, pypi_data: Mapping[str, object]
    ) -> None:
        """Copy the PyPI payload onto the fields the scorer reads.

        Args:
            dep: Dependency metadata to update in place.
            pypi_data: ``pypi.org/pypi/<name>/json`` payload.
        """
        info = pypi_data.get("info")
        info_map: Mapping[str, object] = info if isinstance(info, Mapping) else {}

        latest_version = _string_or_none(info_map.get("version"))
        if latest_version:
            dep.latest_version = latest_version

        repository_url = self._repository_url(info_map)
        if repository_url:
            dep.repository_url = repository_url
        # Recorded off the registry answer, not off dep.repository_url: the
        # requirements parser pre-fills that with the package's pypi.org
        # project page, which is a landing page, not a source repository.
        record_source_repository(dep, repository_url)

        # PyPI dates every uploaded file. The newest upload across all releases
        # is when the project last shipped anything — for `distribute` that is
        # a 2016 patch to an older line, three years after its final 0.7.3.
        apply_registry_release_date(dep, newest_timestamp(_upload_times(pypi_data)))

        # A yanked release is PyPI's explicit "do not use this" marker, the
        # same field RubyGems and crates.io publish and this adapter never read.
        if info_map.get("yanked") is True:
            dep.is_deprecated = True

        if self._summary_declares_deprecation(info_map):
            dep.is_deprecated = True

    @staticmethod
    def _summary_declares_deprecation(info_map: Mapping[str, object]) -> bool:
        """Return whether the one-line summary states the package is deprecated.

        This replaces a substring sweep of ``info.description``, which on a
        modern package is the entire rendered README: any project that
        documents a deprecated API of its own tripped it, and against five
        known-deprecated packages it still caught only ``sklearn``. The summary
        is one line the maintainer writes on purpose ("deprecated sklearn
        package, use scikit-learn instead"), so it keeps that one true positive
        without the README's false-positive surface. It is strictly additive:
        it can raise a deprecation verdict, never clear one set by ``yanked``.

        Args:
            info_map: The payload's ``info`` object.

        Returns:
            True when the summary names the package as deprecated.
        """
        summary = _string_or_none(info_map.get("summary"))
        if not summary:
            return False
        lowered = summary.lower()
        return any(term in lowered for term in _SUMMARY_DEPRECATION_TERMS)

    @staticmethod
    def _repository_url(info_map: Mapping[str, object]) -> Optional[str]:
        """Return the package's repository root, or None when it declares none.

        ``project_urls`` is where PyPI records the source repository, and the
        keys are free text, so candidates are tried most-explicit-first:
        ``Source`` before ``Code``, and any hosted URL trimmed to its
        ``owner/repo`` root. ``home_page`` is a genuine last resort — it is
        ``None`` on every modern package, PyPI having superseded it with
        ``project_urls`` — and it is consulted only after every project URL has
        failed, so a documentation homepage can never stand in for a missing
        ``Source`` entry.

        Args:
            info_map: The payload's ``info`` object.

        Returns:
            An ``https://host/owner/repo`` URL, or None.
        """
        project_urls = info_map.get("project_urls")
        urls: Mapping[str, object] = (
            project_urls if isinstance(project_urls, Mapping) else {}
        )

        for wanted in _SOURCE_URL_KEYS:
            for key, value in urls.items():
                if not isinstance(key, str) or wanted not in key.lower():
                    continue
                canonical = canonical_repository_url(_string_or_none(value))
                if canonical:
                    return canonical

        # Plenty of packages publish the repository under a label that names
        # none of the above — most often plain "Homepage" pointing at GitHub. A
        # hosted repo URL is still one, so any remaining project URL counts,
        # except the labels that routinely point at a hosted *non*-repository
        # (``https://github.com/sponsors/<user>`` would otherwise canonicalize
        # to the "sponsors/<user>" repo, which does not exist).
        for key, value in urls.items():
            if isinstance(key, str) and _is_non_source_label(key):
                continue
            canonical = canonical_repository_url(_string_or_none(value))
            if canonical:
                return canonical

        return canonical_repository_url(_string_or_none(info_map.get("home_page")))

    def _get_pypi_package_info(self, package_name: str) -> Optional[dict]:
        """Get package information from PyPI.

        Args:
            package_name: Name of the Python package.

        Returns:
            Dictionary with package information, or None if fetching failed.
        """
        url = f"https://pypi.org/pypi/{package_name}/json"
        return fetch_json(url, self.timeout)

    def _normalize_version(self, version_str: str) -> str:
        """Normalize version string for comparison.

        Args:
            version_str: Version string to normalize.

        Returns:
            Normalized version string.
        """
        if (
            version_str.startswith(">")
            or version_str.startswith("<")
            or version_str.startswith("=")
        ):
            # Extract version without operators
            match = re.search(r"[0-9].*", version_str)
            if match:
                return match.group(0)
        return version_str


def _upload_times(pypi_data: Mapping[str, object]) -> Iterator[object]:
    """Yield every file upload timestamp in a PyPI payload.

    ``urls`` holds the files of the *latest* version and ``releases`` holds
    every version's files. Both are read: a project can ship a patch to an
    older line after its newest version, which ``urls`` alone would miss.

    Args:
        pypi_data: ``pypi.org/pypi/<name>/json`` payload.

    Yields:
        Raw ``upload_time_iso_8601`` values, unparsed.
    """
    files = pypi_data.get("urls")
    if isinstance(files, Sequence) and not isinstance(files, (str, bytes)):
        for entry in files:
            if isinstance(entry, Mapping):
                yield entry.get("upload_time_iso_8601")

    releases = pypi_data.get("releases")
    if not isinstance(releases, Mapping):
        return
    for entries in releases.values():
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
            continue
        for entry in entries:
            if isinstance(entry, Mapping):
                yield entry.get("upload_time_iso_8601")


def _is_non_source_label(key: str) -> bool:
    """Return whether a project_urls label names something other than source."""
    lowered = key.lower()
    return any(token in lowered for token in _NON_SOURCE_URL_KEYS)


def _string_or_none(value: object) -> Optional[str]:
    """Return the value when it is a non-empty string, else None."""
    if isinstance(value, str) and value:
        return value
    return None
