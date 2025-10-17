"""Windows common utilities for Intellicrack.

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

Common Windows utilities and checks.

This module consolidates Windows-specific functionality to reduce code duplication.
"""

import logging
import sys

logger = logging.getLogger(__name__)

# Global Windows availability check
WINDOWS_AVAILABLE = False
ctypes = None

if sys.platform == "win32":
    try:
        import ctypes
        import ctypes.wintypes

        WINDOWS_AVAILABLE = True
    except ImportError as e:
        logger.error("Import error in windows_common: %s", e)
        WINDOWS_AVAILABLE = False
        ctypes = None


def is_windows_available() -> bool:
    """Check if Windows-specific functionality is available."""
    return WINDOWS_AVAILABLE


def get_windows_kernel32():
    """Get kernel32 library if available."""
    if not WINDOWS_AVAILABLE or ctypes is None:
        return None
    try:
        return ctypes.WinDLL("kernel32", use_last_error=True)
    except Exception as e:
        logger.error("Failed to load kernel32: %s", e)
        return None


def get_windows_ntdll():
    """Get ntdll library if available."""
    if not WINDOWS_AVAILABLE or ctypes is None:
        return None
    try:
        return ctypes.WinDLL("ntdll.dll")
    except Exception as e:
        logger.error("Failed to load ntdll: %s", e)
        return None


# Common Windows constants
class WindowsConstants:
    """Provide Windows constants used across modules."""

    CREATE_SUSPENDED = 0x00000004
    CREATE_NO_WINDOW = 0x08000000
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40


def cleanup_process_handles(kernel32, process_info: dict, logger_instance=None) -> None:
    """Clean up Windows process handles.

    Args:
        kernel32: Windows kernel32 library
        process_info: Dictionary containing process and thread handles
        logger_instance: Optional logger for error reporting

    """
    try:
        if process_info.get("thread_handle"):
            kernel32.CloseHandle(process_info["thread_handle"])
        if process_info.get("process_handle"):
            kernel32.CloseHandle(process_info["process_handle"])
    except Exception as e:
        if logger_instance:
            logger_instance.warning(f"Error cleaning up handles: {e}")
