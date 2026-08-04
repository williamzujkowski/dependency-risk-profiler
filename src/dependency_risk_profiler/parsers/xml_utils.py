"""Bounded XML reading for (untrusted) dependency manifest files.

NuGet ``.csproj`` and Maven ``pom.xml`` are XML, and so are the parent POMs and
BOMs a Maven project inherits from. All of it is attacker-influenceable input to
a risk-scanning tool, so it goes through the helpers here rather than a bare
``ElementTree.parse``. Three things hold the line:

* ``xml.etree.ElementTree`` never resolves an external entity — a ``SYSTEM``
  reference raises ``ParseError`` instead of reading the file or the URL, so
  there is no XXE.
* The underlying expat (>= 2.4) refuses runaway internal-entity amplification,
  so a billion-laughs document raises rather than expanding.
* The byte caps below bound everything else — quadratic blowup, a manifest that
  is simply enormous — before the parser is handed anything.

``testing/unit/test_maven_version_resolution.py`` locks the first two.
"""

import logging
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Real pom.xml / .csproj files are small; cap well above that to reject inputs
# crafted to be expensive to parse.
_MAX_XML_BYTES = 5 * 1024 * 1024


def read_xml_root(path: Path) -> Optional[ElementTree.Element]:
    """Parse an XML manifest into its root element, or None on failure."""
    try:
        if path.stat().st_size > _MAX_XML_BYTES:
            logger.warning("Skipping oversized XML manifest: %s", path)
            return None
        return ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        logger.error("Could not parse %s: %s", path, exc)
        return None


def parse_xml_bytes(data: bytes, origin: str) -> Optional[ElementTree.Element]:
    """Parse an in-memory XML document into its root element, or None.

    Same hardening contract as :func:`read_xml_root`, for XML that arrived over
    the network (a Maven Central POM) rather than off disk: the caller caps the
    byte count before calling, and ``xml.etree`` resolves no external entities.

    Args:
        data: Raw XML bytes.
        origin: Human-readable source (a URL) used only for log messages.

    Returns:
        The root element, or None if the document is oversized or malformed.
    """
    if len(data) > _MAX_XML_BYTES:
        logger.warning("Skipping oversized XML document: %s", origin)
        return None
    try:
        return ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        logger.debug("Could not parse XML from %s: %s", origin, exc)
        return None


def local_name(tag: str) -> str:
    """Return an XML tag's local name, stripping any ``{namespace}`` prefix."""
    return tag.rsplit("}", 1)[-1]


def child_text(element: ElementTree.Element, name: str) -> Optional[str]:
    """Return the trimmed text of a direct child by local tag name, or None."""
    for child in element:
        if local_name(child.tag) == name:
            text = (child.text or "").strip()
            return text or None
    return None


def find_child(
    element: ElementTree.Element, name: str
) -> Optional[ElementTree.Element]:
    """Return the first direct child with the given local tag name, or None."""
    for child in element:
        if local_name(child.tag) == name:
            return child
    return None
