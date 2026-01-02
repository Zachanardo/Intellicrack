"""Ghidra Script Manager for Intellicrack

This module provides automatic discovery, management, and execution of Ghidra scripts.
Supports both Java and Python scripts with metadata extraction.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import logging
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from ..resource_helper import get_resource_path

logger = logging.getLogger(__name__)


class GhidraScript:
    """Represents a single Ghidra script with metadata."""

    def __init__(self, path: str):
        """Initialize Ghidra script with metadata extraction.

        Args:
            path: Path to the Ghidra script file

        """
        self.path = os.path.abspath(path)
        self.filename = os.path.basename(path)
        self.name = os.path.splitext(self.filename)[0]
        self.extension = os.path.splitext(self.filename)[1].lower()
        self.type = "java" if self.extension == ".java" else "python"
        self.directory = os.path.dirname(path)

        # Metadata from script
        self.description = "No description available"
        self.author = "Unknown"
        self.category = "User Scripts"
        self.version = "1.0"
        self.min_ghidra_version = None
        self.tags: list[str] = []

        # Runtime info
        self.last_modified = datetime.fromtimestamp(Path(path).stat().st_mtime)
        self.size = os.path.getsize(path)
        self.is_valid = False
        self.validation_errors: list[str] = []

        # Extract metadata
        self._extract_metadata()
        self._validate()

    def _extract_metadata(self) -> None:
        """Extract metadata from script comments."""
        try:
            with open(self.path, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Java-style comments
            if self.type == "java":
                if desc_match := re.search(
                    r"@description\s+(.+?)(?:\n|$)", content
                ):
                    self.description = desc_match[1].strip()

                if author_match := re.search(r"@author\s+(.+?)(?:\n|$)", content):
                    self.author = author_match[1].strip()

                if category_match := re.search(
                    r"@category\s+(.+?)(?:\n|$)", content
                ):
                    self.category = category_match[1].strip()

                # Also check for /* */ style description
                block_match = re.search(r"/\*\s*\n\s*\*\s*(.+?)\n", content)
                if block_match and self.description == "No description available":
                    self.description = block_match[1].strip("* ")

            elif self.type == "python":
                if docstring_match := re.search(
                    r'"""(.+?)"""', content, re.DOTALL
                ):
                    if lines := docstring_match[1].strip().split("\n"):
                        self.description = lines[0].strip()

                # Look for # @metadata comments
                for line in content.split("\n"):
                    if line.strip().startswith("# @author"):
                        self.author = line.split("@author", 1)[1].strip()
                    elif line.strip().startswith("# @category"):
                        self.category = line.split("@category", 1)[1].strip()
                    elif line.strip().startswith("# @version"):
                        self.version = line.split("@version", 1)[1].strip()

            if tag_match := re.search(r"@tags?\s+(.+?)(?:\n|$)", content):
                self.tags = [t.strip() for t in tag_match[1].split(",")]

        except Exception as e:
            logger.warning(f"Failed to extract metadata from {self.filename}: {e}")

    def _validate(self) -> None:
        """Validate the script for basic requirements."""
        self.validation_errors = []

        try:
            with open(self.path, encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if self.type == "java":
                # Check for required imports
                if "ghidra.app.script.GhidraScript" not in content:
                    self.validation_errors.append("Missing GhidraScript import")

                # Check for class extending GhidraScript
                if not re.search(r"class\s+\w+\s+extends\s+GhidraScript", content):
                    self.validation_errors.append("Class must extend GhidraScript")

                # Check for run() method
                if not re.search(r"public\s+void\s+run\s*\(\s*\)", content):
                    self.validation_errors.append("Missing public void run() method")

            elif self.type == "python":
                # Python scripts are more flexible, just check if it's not empty
                if len(content.strip()) < 10:
                    self.validation_errors.append("Script appears to be empty")

            self.is_valid = not self.validation_errors

        except Exception as e:
            logger.error("Exception in ghidra_script_manager: %s", e)
            self.validation_errors.append(f"Failed to validate: {e}")
            self.is_valid = False

    def to_dict(self) -> dict[str, Any]:
        """Convert script info to dictionary.

        Returns:
            dict[str, Any]: Dictionary containing all script metadata
                and properties including path, filename, name, type,
                description, author, category, version, tags,
                last_modified, size, is_valid, validation_errors,
                and directory.

        """
        return {
            "path": self.path,
            "filename": self.filename,
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "author": self.author,
            "category": self.category,
            "version": self.version,
            "tags": self.tags,
            "last_modified": self.last_modified.isoformat(),
            "size": self.size,
            "is_valid": self.is_valid,
            "validation_errors": self.validation_errors,
            "directory": self.directory,
        }


class GhidraScriptManager:
    """Manages Ghidra script discovery, validation, and execution."""

    # Centralized script directory
    DEFAULT_SCRIPT_DIRS = [get_resource_path("scripts/ghidra")]

    # Script metadata cache file
    CACHE_FILE = "ghidra_scripts_cache.json"

    def __init__(self, additional_dirs: list[str] | None = None):
        """Initialize the script manager.

        Args:
            additional_dirs: Extra directories to search for scripts

        """
        self.script_dirs = self.DEFAULT_SCRIPT_DIRS.copy()
        if additional_dirs:
            self.script_dirs.extend(additional_dirs)

        self.scripts: dict[str, GhidraScript] = {}
        self.categories: dict[str, list[str]] = {}
        self.last_scan: datetime | None = None

        # Create default directories if they don't exist
        self._create_default_directories()

        # Load cache if available
        self._load_cache()

    def _create_default_directories(self) -> None:
        """Create default script directories if they don't exist."""
        # Create main directory and subdirectories
        base_dir = get_resource_path("scripts/ghidra")
        subdirs = ["default", "user", "examples", "community"]

        # Create base directory
        if not os.path.exists(base_dir):
            try:
                os.makedirs(base_dir, exist_ok=True)
                logger.info(f"Created script directory: {base_dir}")
            except Exception as e:
                logger.warning(f"Failed to create directory {base_dir}: {e}")

        # Create subdirectories
        for subdir in subdirs:
            dir_path = os.path.join(base_dir, subdir)
            if not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path, exist_ok=True)
                    logger.info(f"Created script subdirectory: {dir_path}")
                except Exception as e:
                    logger.warning(f"Failed to create directory {dir_path}: {e}")

    def scan_scripts(self, force_rescan: bool = False) -> dict[str, GhidraScript]:
        """Scan all directories for Ghidra scripts.

        Args:
            force_rescan: Force rescan even if cache is recent

        Returns:
            Dictionary of script path -> GhidraScript objects

        """
        # Check if we need to rescan
        if not force_rescan and len(self.scripts) > 0 and self.last_scan is not None and (datetime.now() - self.last_scan).seconds < 300:
            return self.scripts

        logger.info("Scanning for Ghidra scripts...")
        self.scripts.clear()
        self.categories.clear()

        for script_dir in self.script_dirs:
            if not os.path.exists(script_dir):
                continue

            # Walk directory tree
            for root, dirs, files in os.walk(script_dir):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith(".")]

                for file in files:
                    if file.endswith((".java", ".py")):
                        # Skip backup files
                        if file.endswith((".bak", ".tmp", "~")):
                            continue

                        script_path = os.path.join(root, file)
                        try:
                            script = GhidraScript(script_path)
                            self.scripts[script_path] = script

                            # Organize by category
                            if script.category not in self.categories:
                                self.categories[script.category] = []
                            self.categories[script.category].append(script_path)

                            logger.debug(f"Found script: {script.name} ({script.category})")

                        except Exception as e:
                            logger.warning(f"Failed to load script {file}: {e}")

        self.last_scan = datetime.now()
        logger.info(f"Found {len(self.scripts)} Ghidra scripts in {len(self.categories)} categories")

        # Save cache
        self._save_cache()

        return self.scripts

    def get_scripts_by_category(self) -> dict[str, list[GhidraScript]]:
        """Get scripts organized by category.

        Returns:
            dict[str, list[GhidraScript]]: Dictionary mapping category
                names to lists of GhidraScript objects. Keys are category
                names and values are lists of GhidraScript instances in
                that category.

        """
        if not self.scripts:
            self.scan_scripts()

        return {
            category: [
                self.scripts[path] for path in paths if path in self.scripts
            ]
            for category, paths in self.categories.items()
        }

    def get_script(self, identifier: str) -> GhidraScript | None:
        """Get a script by path, filename, or name.

        Args:
            identifier: Script path, filename, or name

        Returns:
            GhidraScript object or None

        """
        if not self.scripts:
            self.scan_scripts()

        # Try direct path lookup
        if identifier in self.scripts:
            return self.scripts[identifier]

        return next(
            (
                script
                for _, script in self.scripts.items()
                if script.filename == identifier or script.name == identifier
            ),
            None,
        )

    def validate_script(self, script_path: str) -> tuple[bool, list[str]]:
        """Validate a specific script.

        Args:
            script_path: Path to the script

        Returns:
            Tuple of (is_valid, error_messages)

        """
        try:
            script = GhidraScript(script_path)
            return script.is_valid, script.validation_errors
        except Exception as e:
            logger.error("Exception in ghidra_script_manager: %s", e)
            return False, [str(e)]

    def copy_script_for_execution(self, script: GhidraScript, destination_dir: str) -> str:
        """Copy script to destination directory for execution.

        Args:
            script: GhidraScript object
            destination_dir: Where to copy the script

        Returns:
            Path to the copied script

        """
        os.makedirs(destination_dir, exist_ok=True)
        dest_path = os.path.join(destination_dir, script.filename)

        # Copy the script
        shutil.copy2(script.path, dest_path)

        # If Java script, check for accompanying class files
        if script.type == "java":
            class_file = f"{script.name}.class"
            class_path = os.path.join(script.directory, class_file)
            if os.path.exists(class_path):
                shutil.copy2(class_path, os.path.join(destination_dir, class_file))

        return dest_path

    def search_scripts(self, query: str) -> list[GhidraScript]:
        """Search scripts by name, description, or tags.

        Args:
            query: Search query

        Returns:
            List of matching scripts

        """
        if not self.scripts:
            self.scan_scripts()

        query_lower = query.lower()
        return [
            script
            for script in self.scripts.values()
            if any(
                query_lower in field.lower()
                for field in [
                    script.name,
                    script.description,
                    script.author,
                    script.category,
                    " ".join(script.tags),
                ]
            )
        ]

    def discover_scripts(self, force_rescan: bool = False) -> int:
        """Discover and catalog all Ghidra scripts in configured directories.

        Scans all configured script directories for Java and Python Ghidra scripts,
        extracts their metadata, validates them, and organizes them by category.
        This is an alias for scan_scripts with additional directory checking.

        Args:
            force_rescan: If True, forces a rescan even if scripts were recently scanned

        Returns:
            Number of scripts discovered

        """
        for script_dir in self.script_dirs:
            if not os.path.exists(script_dir):
                try:
                    os.makedirs(script_dir, exist_ok=True)
                    logger.info(f"Created script directory during discovery: {script_dir}")
                except OSError as e:
                    logger.warning(f"Could not create script directory {script_dir}: {e}")

        self.scan_scripts(force_rescan=force_rescan)
        return len(self.scripts)

    def list_scripts(self, category: str | None = None, valid_only: bool = False) -> list[GhidraScript]:
        """List all discovered Ghidra scripts.

        Returns a list of all discovered GhidraScript objects, optionally filtered
        by category or validation status. If scripts haven't been scanned yet,
        triggers a scan first.

        Args:
            category: Optional category name to filter scripts by
            valid_only: If True, only return scripts that passed validation

        Returns:
            List of GhidraScript objects matching the filter criteria

        """
        if not self.scripts:
            self.scan_scripts()

        scripts = list(self.scripts.values())

        if category is not None:
            scripts = [s for s in scripts if s.category.lower() == category.lower()]

        if valid_only:
            scripts = [s for s in scripts if s.is_valid]

        return sorted(scripts, key=lambda s: (s.category, s.name))

    def add_user_script(self, source_path: str, category: str = "User Scripts") -> GhidraScript | None:
        """Add a user script to the user scripts directory.

        Copies the script to the user scripts directory and validates
        it before adding to the collection. If validation fails, the
        copied file is removed and None is returned.

        Args:
            source_path: Path to the script to add
            category: Category for the script

        Returns:
            GhidraScript object if successful, None on failure

        Raises:
            ValueError: If the script fails validation.

        """
        base_dir = get_resource_path("scripts/ghidra")
        user_dir = os.path.join(base_dir, "user")
        os.makedirs(user_dir, exist_ok=True)

        filename = os.path.basename(source_path)
        dest_path = os.path.join(user_dir, filename)

        # Check if already exists
        if os.path.exists(dest_path):
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(dest_path):
                filename = f"{base}_{counter}{ext}"
                dest_path = os.path.join(user_dir, filename)
                counter += 1

        try:
            # Copy the script
            shutil.copy2(source_path, dest_path)

            # Create and validate script object
            script = GhidraScript(dest_path)
            if not script.is_valid:
                os.remove(dest_path)
                raise ValueError(f"Invalid script: {', '.join(script.validation_errors)}")

            # Add to our collection
            self.scripts[dest_path] = script
            if category not in self.categories:
                self.categories[category] = []
            self.categories[category].append(dest_path)

            # Save cache
            self._save_cache()

            logger.info(f"Added user script: {script.name}")
            return script

        except Exception as e:
            logger.error(f"Failed to add user script: {e}")
            if os.path.exists(dest_path):
                os.remove(dest_path)
            return None

    def _load_cache(self) -> None:
        """Load script cache from disk."""
        cache_path = os.path.join("cache", self.CACHE_FILE)
        if not os.path.exists(cache_path):
            return

        try:
            with open(cache_path) as f:
                data = json.load(f)

            # Check cache version
            if data.get("version", 1) != 2:
                return

            # Load scripts
            for script_data in data.get("scripts", []):
                path = script_data["path"]
                if os.path.exists(path):
                    # Check if file hasn't changed
                    mtime = Path(path).stat().st_mtime
                    cached_mtime = datetime.fromisoformat(script_data["last_modified"]).timestamp()

                    if abs(mtime - cached_mtime) < 1:  # Within 1 second
                        # Use cached data
                        script = GhidraScript(path)
                        script.description = script_data.get("description", script.description)
                        script.author = script_data.get("author", script.author)
                        script.category = script_data.get("category", script.category)
                        script.tags = script_data.get("tags", script.tags)

                        self.scripts[path] = script
                        if script.category not in self.categories:
                            self.categories[script.category] = []
                        self.categories[script.category].append(path)

            last_scan_str = data.get("last_scan")
            self.last_scan = datetime.fromisoformat(last_scan_str) if last_scan_str else None
            logger.info(f"Loaded {len(self.scripts)} scripts from cache")

        except Exception as e:
            logger.warning(f"Failed to load script cache: {e}")

    def _save_cache(self) -> None:
        """Save script cache to disk."""
        cache_dir = "cache"
        os.makedirs(cache_dir, exist_ok=True)
        cache_path = os.path.join(cache_dir, self.CACHE_FILE)

        try:
            data = {
                "version": 2,
                "last_scan": self.last_scan.isoformat() if self.last_scan else None,
                "scripts": [script.to_dict() for script in self.scripts.values()],
            }

            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.warning(f"Failed to save script cache: {e}")


# Global instance
_script_manager: GhidraScriptManager | None = None


def get_script_manager() -> GhidraScriptManager:
    """Get or create the global script manager instance.

    Returns a singleton instance of GhidraScriptManager that manages
    all Ghidra script discovery and execution. Creates the instance
    on first call and reuses it on subsequent calls.

    Returns:
        GhidraScriptManager: The global GhidraScriptManager instance
            used for managing script discovery, validation, and
            execution across the application.

    """
    global _script_manager
    if _script_manager is None:
        _script_manager = GhidraScriptManager()
    return _script_manager


def add_script_directory(directory: str) -> None:
    """Add a directory to search for scripts.

    Adds a new directory to the global script manager's search path.
    The directory will be scanned for Ghidra scripts (Java and Python)
    during the next scan operation.

    Args:
        directory: Path to the directory to add for script searching.

    """
    manager = get_script_manager()
    if directory not in manager.script_dirs:
        manager.script_dirs.append(directory)
        logger.info(f"Added script directory: {directory}")
