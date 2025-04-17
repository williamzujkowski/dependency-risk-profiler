"""
Disk-based caching system for vulnerability data.

This module provides functions to store and retrieve vulnerability data from a
disk-based cache, reducing the need for frequent network calls to vulnerability APIs.
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default cache directory
DEFAULT_CACHE_DIR = Path.home() / ".dependency_risk_profiler" / "vuln_cache"

# Default cache expiry time in seconds (24 hours)
DEFAULT_CACHE_EXPIRY = 24 * 60 * 60


class VulnerabilityCache:
    """Disk-based cache for vulnerability data."""

    def __init__(
        self, cache_dir: Optional[Path] = None, expiry: int = DEFAULT_CACHE_EXPIRY
    ):
        """Initialize the vulnerability cache.

        Args:
            cache_dir: Directory to store cache files.
                Defaults to ~/.dependency_risk_profiler/vuln_cache
            expiry: Cache expiry time in seconds. Defaults to 24 hours.
        """
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
        self.expiry = expiry
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Ensure the cache directory exists."""
        if not self.cache_dir.exists():
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created vulnerability cache directory: {self.cache_dir}")
            except OSError as e:
                logger.warning(f"Could not create vulnerability cache directory: {e}")

    def _get_cache_path(self, package_name: str, ecosystem: str) -> Path:
        """Get the path to the cache file for a package.

        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem

        Returns:
            Path to the cache file
        """
        # Sanitize the package name and ecosystem for use in a filename
        safe_package = package_name.replace("/", "__").replace("\\", "__")
        safe_ecosystem = ecosystem.replace("/", "_").replace("\\", "_")

        # Generate a cache file name
        return self.cache_dir / f"{safe_ecosystem}_{safe_package}.json"

    def get(
        self, package_name: str, ecosystem: str
    ) -> Optional[Tuple[List[Dict[str, Any]], float]]:
        """Get cached vulnerability data for a package.

        Args:
            package_name: Package name
            ecosystem: Package ecosystem

        Returns:
            Tuple of (vulnerability data, timestamp) or None if not found or expired
        """
        logger.info(
            f"Attempting to retrieve cache data for {package_name} ({ecosystem})"
        )
        cache_path = self._get_cache_path(package_name, ecosystem)

        if not cache_path.exists():
            logger.info(f"No cache file found for {package_name} ({ecosystem})")
            return None

        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            # Check if the cache entry has the required fields
            if not all(k in cache_data for k in ["data", "timestamp"]):
                logger.warning(
                    f"Malformed cache entry for {package_name}: missing required fields"
                )
                return None

            # Check if the cache is still valid
            timestamp = cache_data["timestamp"]
            if time.time() - timestamp > self.expiry:
                logger.info(f"Cache expired for {package_name} ({ecosystem})")
                return None

            logger.info(
                f"Serving vulnerability data for {package_name} from disk cache "
                f"(created: {datetime.fromtimestamp(timestamp).isoformat()})"
            )
            return cache_data["data"], timestamp

        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Error reading cache file for {package_name}: {e}")
            return None

    def set(
        self, package_name: str, ecosystem: str, data: List[Dict[str, Any]]
    ) -> bool:
        """Cache vulnerability data for a package.

        Args:
            package_name: Package name
            ecosystem: Package ecosystem
            data: Vulnerability data to cache

        Returns:
            True if caching succeeded, False otherwise
        """
        if not self.cache_dir.exists():
            self._ensure_cache_dir()
            if not self.cache_dir.exists():
                return False

        cache_path = self._get_cache_path(package_name, ecosystem)

        try:
            cache_data = {
                "data": data,
                "timestamp": time.time(),
                "package": package_name,
                "ecosystem": ecosystem,
            }

            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2)

            logger.debug(f"Cached vulnerability data for {package_name} ({ecosystem})")
            return True

        except OSError as e:
            logger.warning(f"Error writing cache file for {package_name}: {e}")
            return False

    def clear(
        self, package_name: Optional[str] = None, ecosystem: Optional[str] = None
    ) -> int:
        """Clear cached vulnerability data.

        Args:
            package_name: Specific package name to clear (optional)
            ecosystem: Specific ecosystem to clear (optional)

        Returns:
            Number of cache entries cleared
        """
        if not self.cache_dir.exists():
            return 0

        count = 0

        if package_name and ecosystem:
            # Clear a specific package
            cache_path = self._get_cache_path(package_name, ecosystem)
            if cache_path.exists():
                try:
                    cache_path.unlink()
                    count = 1
                    logger.debug(f"Cleared cache for {package_name} ({ecosystem})")
                except OSError as e:
                    logger.warning(f"Error clearing cache for {package_name}: {e}")

        elif ecosystem:
            # Clear all packages in a specific ecosystem
            prefix = f"{ecosystem}_"
            for cache_file in self.cache_dir.glob(f"{prefix}*.json"):
                try:
                    cache_file.unlink()
                    count += 1
                except OSError as e:
                    logger.warning(f"Error clearing cache file {cache_file.name}: {e}")

            logger.debug(f"Cleared {count} cache entries for ecosystem {ecosystem}")

        else:
            # Clear all cache entries
            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    cache_file.unlink()
                    count += 1
                except OSError as e:
                    logger.warning(f"Error clearing cache file {cache_file.name}: {e}")

            logger.debug(f"Cleared all {count} cache entries")

        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the cache.

        Returns:
            Dictionary with cache statistics
        """
        stats = {
            "cache_dir": str(self.cache_dir),
            "entry_count": 0,
            "total_size_bytes": 0,
            "oldest_entry": None,
            "newest_entry": None,
            "ecosystems": set(),
        }

        if not self.cache_dir.exists():
            return stats

        entries = list(self.cache_dir.glob("*.json"))
        stats["entry_count"] = len(entries)

        if not entries:
            return stats

        # Get file sizes and modification times
        sizes = []
        mtimes = []

        for entry in entries:
            try:
                # Get file stats
                file_stat = entry.stat()
                sizes.append(file_stat.st_size)
                mtimes.append(file_stat.st_mtime)

                # Read file to get ecosystem
                with open(entry, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                    ecosystem = cache_data.get("ecosystem")
                    if ecosystem:
                        stats["ecosystems"].add(ecosystem)

            except (OSError, json.JSONDecodeError):
                continue

        if sizes:
            stats["total_size_bytes"] = sum(sizes)

        if mtimes:
            stats["oldest_entry"] = datetime.fromtimestamp(min(mtimes)).isoformat()
            stats["newest_entry"] = datetime.fromtimestamp(max(mtimes)).isoformat()

        stats["ecosystems"] = list(stats["ecosystems"])
        return stats


# Global instance for easy access
default_cache = VulnerabilityCache()
