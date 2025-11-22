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


logger: logging.Logger = logging.getLogger(__name__)

# Global Windows availability check
WINDOWS_AVAILABLE: bool = False
ctypes: object = None

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


def get_windows_kernel32() -> object | None:
    """Get kernel32 library if available.

    Loads the Windows kernel32.dll library if Windows is available and
    ctypes has been successfully imported. Returns None if Windows is not
    available or if the library fails to load.

    Returns:
        The kernel32 WinDLL instance if available, None otherwise.

    """
    if not WINDOWS_AVAILABLE or ctypes is None:
        return None
    try:
        return ctypes.WinDLL("kernel32", use_last_error=True)
    except Exception as e:
        logger.error("Failed to load kernel32: %s", e)
        return None


def get_windows_ntdll() -> object | None:
    """Get ntdll library if available.

    Loads the Windows ntdll.dll library if Windows is available and
    ctypes has been successfully imported. Returns None if Windows is not
    available or if the library fails to load.

    Returns:
        The ntdll WinDLL instance if available, None otherwise.

    """
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


def cleanup_process_handles(
    kernel32: object,
    process_info: dict[str, object],
    logger_instance: logging.Logger | None = None,
) -> None:
    """Clean up Windows process handles.

    Closes process and thread handles stored in the provided dictionary.
    Gracefully handles errors and logs them if a logger instance is provided.

    Args:
        kernel32: Windows kernel32 library WinDLL instance.
        process_info: Dictionary containing 'process_handle' and 'thread_handle' keys
            with their respective handle values.
        logger_instance: Optional logger instance for error reporting. If provided,
            errors during handle cleanup will be logged as warnings.

    Returns:
        None.

    """
    try:
        if process_info.get("thread_handle"):
            kernel32.CloseHandle(process_info["thread_handle"])
        if process_info.get("process_handle"):
            kernel32.CloseHandle(process_info["process_handle"])
    except Exception as e:
        if logger_instance:
            logger_instance.warning(f"Error cleaning up handles: {e}")
