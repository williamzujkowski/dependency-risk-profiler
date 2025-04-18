#!/usr/bin/env python3
"""
Script to clean up legacy configuration files that have been migrated to pyproject.toml.

This script identifies and removes files that are no longer needed due to the migration
to a pyproject.toml-based configuration. It creates backups before removal.
"""

import os
import shutil
from pathlib import Path

# Files that should be removed after migration to pyproject.toml
LEGACY_FILES = [
    "setup.py",
    "setup.cfg",
    "MANIFEST.in",
    "mypy.ini",
    ".flake8",
    "tox.ini",
    "pytest.ini",
]

def backup_file(file_path):
    """Create a backup of a file before removing it."""
    backup_dir = Path("backup_legacy")
    backup_dir.mkdir(exist_ok=True)
    
    src = Path(file_path)
    if src.exists():
        dest = backup_dir / src.name
        print(f"Creating backup: {src} -> {dest}")
        shutil.copy2(src, dest)
        return True
    return False

def remove_file(file_path):
    """Remove a file if it exists."""
    path = Path(file_path)
    if path.exists():
        print(f"Removing: {path}")
        path.unlink()
        return True
    return False

def main():
    """Main entry point."""
    print("Dependency Risk Profiler Legacy Cleanup")
    print("======================================")
    print("This script will remove legacy configuration files that have been migrated to pyproject.toml.")
    print("Backups will be created in the 'backup_legacy' directory.")
    
    # Check if pyproject.toml exists
    if not Path("pyproject.toml").exists():
        print("\nERROR: pyproject.toml not found. Migration must be completed first.")
        return 1
    
    # Confirm before proceeding
    confirm = input("\nContinue with removal of legacy files? (y/N): ").strip().lower()
    if confirm not in ["y", "yes"]:
        print("Operation cancelled.")
        return 0
    
    # Process each legacy file
    removed_count = 0
    for file in LEGACY_FILES:
        if backup_file(file) and remove_file(file):
            removed_count += 1
    
    # Report results
    if removed_count > 0:
        print(f"\nSuccessfully removed {removed_count} legacy files.")
        print("Backups are stored in the 'backup_legacy' directory.")
    else:
        print("\nNo legacy files found or removed.")
    
    return 0

if __name__ == "__main__":
    exit(main())