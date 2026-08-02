"""Bounded XML reading for (untrusted) dependency manifest files.

NuGet ``.csproj`` and Maven ``pom.xml`` are XML. These files are attacker-
influenceable input to a risk-scanning tool, so parsing is done through one
helper that caps the input size before handing it to ``xml.etree`` — which does
not resolve external entities (no XXE), while the size cap bounds the cost of
internal-entity-expansion / quadratic-blowup inputs.
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


def local_name(tag: str) -> str:
    """Return an XML tag's local name, stripping any ``{namespace}`` prefix."""
    return tag.rsplit("}", 1)[-1]
