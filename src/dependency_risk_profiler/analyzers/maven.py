"""Analyzer for Java (Maven) dependencies."""

import logging
import xml.etree.ElementTree as ElementTree
from typing import Dict, Optional

import requests

from ..models import DependencyMetadata
from ..parsers.xml_utils import local_name
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)

# maven-metadata.xml is small; cap the download to bound parse cost.
_MAX_METADATA_BYTES = 2 * 1024 * 1024


class MavenAnalyzer(BaseAnalyzer):
    """Analyzer for Java dependencies published to Maven Central."""

    def __init__(self, timeout: int = 10):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        self.metadata_cache: Dict[str, str] = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Java dependencies and collect Maven Central metadata.

        Args:
            dependencies: Dictionary mapping ``groupId:artifactId`` to metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info("Analyzing Maven package: %s", name)
            # Route vulnerability lookups to the Maven OSV ecosystem.
            dep.additional_info["ecosystem"] = "maven"

            try:
                latest = self._get_latest_version(name)
                if latest:
                    dep.latest_version = latest
            except Exception as exc:
                logger.error("Error analyzing Maven package %s: %s", name, exc)

        return dependencies

    def _get_latest_version(self, coordinate: str) -> Optional[str]:
        """Return the release (or latest) version for a groupId:artifactId."""
        if ":" not in coordinate:
            return None
        group, artifact = coordinate.split(":", 1)
        group_path = group.replace(".", "/")
        url = (
            "https://repo1.maven.org/maven2/"
            f"{group_path}/{artifact}/maven-metadata.xml"
        )
        headers = {"User-Agent": "dependency-risk-profiler (metadata lookup)"}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("Maven Central lookup failed for %s: %s", coordinate, exc)
            return None
        if response.status_code != 200:
            return None
        content = response.content
        if len(content) > _MAX_METADATA_BYTES:
            return None
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return None
        return self._latest_from_metadata(root)

    @staticmethod
    def _latest_from_metadata(root: ElementTree.Element) -> Optional[str]:
        """Return <release> (preferred) or <latest> from a maven-metadata root."""
        for versioning in root:
            if local_name(versioning.tag) != "versioning":
                continue
            release: Optional[str] = None
            latest: Optional[str] = None
            for child in versioning:
                text = (child.text or "").strip()
                if not text:
                    continue
                if local_name(child.tag) == "release":
                    release = text
                elif local_name(child.tag) == "latest":
                    latest = text
            return release or latest
        return None
