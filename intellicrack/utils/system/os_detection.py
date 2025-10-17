"""OS detection utilities for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Operating System Detection Utilities

Shared OS detection functions to eliminate code duplication across the codebase.
"""

import logging
import os
import platform
import tempfile
from typing import Any

logger = logging.getLogger(__name__)


def detect_operating_system() -> str:
    """Detect and normalize operating system identifier.

    Returns:
        Normalized OS identifier: 'windows', 'linux', or 'unknown'

    """
    system = platform.system().lower()

    if system == "windows":
        return "windows"
    if system in ["linux", "darwin"]:
        return "linux"
    return "unknown"


def is_windows() -> bool:
    """Check if running on Windows."""
    return detect_operating_system() == "windows"


def is_linux_like() -> bool:
    """Check if running on Linux or macOS."""
    return detect_operating_system() == "linux"


def is_unix_like() -> bool:
    """Check if running on Unix-like system (Linux or macOS)."""
    return is_linux_like()


def get_platform_details() -> dict[str, Any]:
    """Get detailed platform information.

    Returns:
        Dictionary with platform details

    """
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "architecture": platform.architecture(),
        "normalized_os": detect_operating_system(),
    }


def get_default_persistence_method() -> str:
    """Get default persistence method based on operating system.

    Returns:
        Default persistence method for the current OS

    """
    current_os = detect_operating_system()

    if current_os == "windows":
        return "scheduled_task"
    if current_os == "linux":
        return "systemd_service"
    return "cron_job"


def get_platform_specific_paths() -> dict[str, str]:
    """Get platform-specific common paths.

    Returns:
        Dictionary with common paths for the current platform

    """
    current_os = detect_operating_system()

    if current_os == "windows":
        return {
            "temp": os.environ.get("TEMP", "C:\\Windows\\Temp"),
            "appdata": os.environ.get("APPDATA", ""),
            "localappdata": os.environ.get("LOCALAPPDATA", ""),
            "programfiles": os.environ.get("PROGRAMFILES", "C:\\Program Files"),
            "system32": "C:\\Windows\\System32",
            "documents": os.path.join(os.path.expanduser("~"), "Documents"),
        }
    return {
        "temp": tempfile.gettempdir(),
        "home": os.path.expanduser("~"),
        "etc": "/etc",
        "var": "/var",
        "usr": "/usr",
        "bin": "/bin",
    }


def detect_file_type(file_path: str) -> str:
    """Detect the type of a binary file.

    Args:
        file_path: Path to the file to analyze

    Returns:
        File type string: 'pe', 'elf', 'macho', or 'unknown'

    """
    if not os.path.exists(file_path):
        return "unknown"

    try:
        with open(file_path, "rb") as f:
            header = f.read(4)

            # Check for PE (Windows executable)
            if header[:2] == b"MZ":
                return "pe"

            # Check for ELF (Linux executable)
            if header == b"\x7fELF":
                return "elf"

            # Check for Mach-O (macOS executable)
            if header in [b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"]:
                return "macho"

    except Exception as e:
        logger.debug("Error detecting binary format: %s", e)

    return "unknown"


# Export main functions
__all__ = [
    "detect_file_type",
    "detect_operating_system",
    "get_default_persistence_method",
    "get_platform_details",
    "get_platform_specific_paths",
    "is_linux_like",
    "is_unix_like",
    "is_windows",
]
