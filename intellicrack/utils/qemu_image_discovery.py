"""QEMU Image Discovery Utility.

Provides dynamic discovery of QEMU images from configured directories.
Replaces hardcoded image paths with automatic detection.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import logging
from dataclasses import dataclass
from pathlib import Path

from .path_resolver import get_project_root


logger: logging.Logger = logging.getLogger(__name__)


@dataclass
class QEMUImageInfo:
    """Information about a discovered QEMU image."""

    path: Path
    filename: str
    format: str
    os_type: str
    architecture: str
    size_bytes: int


class QEMUImageDiscovery:
    """Discovers and catalogs QEMU images from configured directories."""

    SUPPORTED_FORMATS: list[str] = [
        ".qcow2",
        ".qcow",
        ".img",
        ".vmdk",
        ".vdi",
        ".vhd",
        ".vhdx",
        ".iso",
        ".raw",
        ".qed",
        ".cloop",
        ".dmg",
        ".parallels",
        ".bochs",
    ]
    """Supported QEMU image file formats."""

    def __init__(self) -> None:
        """Initialize QEMU image discovery."""
        self._cache: list[QEMUImageInfo] = []
        self._cache_valid: bool = False

    def get_search_directories(self) -> list[Path]:
        """Get list of directories to search for QEMU images.

        Returns:
            list[Path]: List of directories to search for QEMU images.
        """
        project_root = get_project_root()

        directories = [
            project_root / "intellicrack" / "assets" / "qemu_images",
            Path.home() / ".intellicrack" / "qemu_images",
        ]

        existing_dirs = [d for d in directories if d.exists()]

        if not existing_dirs:
            logger.warning("No QEMU image directories found, creating default location")
            default_dir = project_root / "intellicrack" / "assets" / "qemu_images"
            default_dir.mkdir(parents=True, exist_ok=True)
            existing_dirs.append(default_dir)

        return existing_dirs

    def detect_os_type(self, filename: str) -> str:
        """Detect OS type from filename patterns.

        Args:
            filename: The filename to analyze.

        Returns:
            str: Detected OS type (windows, linux, bsd, macos, or unknown).
        """
        filename_lower = filename.lower()

        patterns = {
            "windows": ["windows", "win10", "win11", "win7", "win8", "winxp", "vista"],
            "linux": ["linux", "ubuntu", "debian", "centos", "fedora", "arch", "kali", "mint"],
            "bsd": ["bsd", "freebsd", "openbsd", "netbsd"],
            "macos": ["macos", "osx", "darwin"],
        }

        return next(
            (os_type for os_type, keywords in patterns.items() if any(keyword in filename_lower for keyword in keywords)),
            "unknown",
        )

    def detect_architecture(self, filename: str) -> str:
        """Detect architecture from filename patterns.

        Args:
            filename: The filename to analyze.

        Returns:
            str: Detected architecture (x86_64, x86, arm64, arm, or x86_64 as default).
        """
        filename_lower = filename.lower()

        patterns = {
            "x86_64": ["x86_64", "amd64", "x64", "64bit"],
            "x86": ["x86", "i386", "i686", "32bit"],
            "arm64": ["arm64", "aarch64"],
            "arm": ["arm", "armv7"],
        }

        return next(
            (arch for arch, keywords in patterns.items() if any(keyword in filename_lower for keyword in keywords)),
            "x86_64",
        )

    def discover_images(self, force_refresh: bool = False) -> list[QEMUImageInfo]:
        """Discover all QEMU images in search directories.

        Args:
            force_refresh: Whether to force a cache refresh.

        Returns:
            list[QEMUImageInfo]: List of discovered QEMU image information objects.
        """
        if self._cache_valid and not force_refresh:
            return self._cache

        discovered_images = []
        search_dirs = self.get_search_directories()

        for directory in search_dirs:
            logger.debug("Searching for QEMU images in: %s", directory)

            for extension in self.SUPPORTED_FORMATS:
                for image_path in directory.glob(f"*{extension}"):
                    if not image_path.is_file():
                        continue

                    try:
                        size = image_path.stat().st_size
                        filename = image_path.name
                        format_type = extension.lstrip(".")

                        os_type = self.detect_os_type(filename)
                        architecture = self.detect_architecture(filename)

                        image_info = QEMUImageInfo(
                            path=image_path,
                            filename=filename,
                            format=format_type,
                            os_type=os_type,
                            architecture=architecture,
                            size_bytes=size,
                        )

                        discovered_images.append(image_info)
                        logger.debug("Found QEMU image: %s (%s/%s, %sMB)", filename, os_type, architecture, size // (1024**2))

                    except OSError as e:
                        logger.warning("Error accessing QEMU image %s: %s", image_path, e, exc_info=True)
                        continue

        self._cache = discovered_images
        self._cache_valid = True

        logger.info("Discovered %s QEMU images", len(discovered_images))
        return discovered_images

    def get_images_by_os(self, os_type: str) -> list[QEMUImageInfo]:
        """Get all images for a specific OS type.

        Args:
            os_type: The OS type to filter by.

        Returns:
            list[QEMUImageInfo]: List of QEMU images matching the specified OS type.
        """
        all_images = self.discover_images()
        return [img for img in all_images if img.os_type.lower() == os_type.lower()]

    def get_images_by_format(self, format_type: str) -> list[QEMUImageInfo]:
        """Get all images of a specific format.

        Args:
            format_type: The format type to filter by.

        Returns:
            list[QEMUImageInfo]: List of QEMU images matching the specified format.
        """
        all_images = self.discover_images()
        return [img for img in all_images if img.format.lower() == format_type.lower()]

    def find_image(self, filename: str) -> QEMUImageInfo | None:
        """Find a specific image by filename.

        Args:
            filename: The filename to search for.

        Returns:
            QEMUImageInfo | None: The QEMU image information if found, otherwise None.
        """
        all_images = self.discover_images()

        for image in all_images:
            if filename in (image.filename, image.path.name):
                return image

        logger.warning("QEMU image not found: %s", filename)
        return None

    def invalidate_cache(self) -> None:
        """Invalidate the image cache to force re-discovery."""
        self._cache_valid = False
        logger.debug("QEMU image cache invalidated")


_discovery_instance: QEMUImageDiscovery | None = None
"""Module-level singleton instance of QEMU image discovery."""


def get_qemu_discovery() -> QEMUImageDiscovery:
    """Get singleton QEMU image discovery instance.

    Returns:
        QEMUImageDiscovery: The singleton QEMU image discovery instance.
    """
    global _discovery_instance
    if _discovery_instance is None:
        _discovery_instance = QEMUImageDiscovery()
    return _discovery_instance
