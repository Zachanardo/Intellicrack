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
from types import ModuleType
from typing import Any

logger: logging.Logger = logging.getLogger(__name__)

WINDOWS_AVAILABLE: bool = False
ctypes: ModuleType | None = None

if sys.platform == "win32":
    try:
        import ctypes as ctypes_module
        import ctypes.wintypes

        ctypes = ctypes_module
        WINDOWS_AVAILABLE = True
    except ImportError as e:
        logger.exception("Import error in windows_common: %s", e)
        WINDOWS_AVAILABLE = False
        ctypes = None


def is_windows_available() -> bool:
    """Check if Windows-specific functionality is available."""
    return WINDOWS_AVAILABLE


def get_windows_kernel32() -> Any:
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
        kernel32_dll: Any = ctypes.WinDLL("kernel32", use_last_error=True)
        return kernel32_dll
    except Exception as e:
        logger.exception("Failed to load kernel32: %s", e)
        return None


def get_windows_ntdll() -> Any:
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
        ntdll_dll: Any = ctypes.WinDLL("ntdll.dll")
        return ntdll_dll
    except Exception as e:
        logger.exception("Failed to load ntdll: %s", e)
        return None


# Common Windows constants
class WindowsConstants:
    """Provide Windows constants used across modules."""

    CREATE_SUSPENDED: int = 0x00000004
    CREATE_NO_WINDOW: int = 0x08000000
    MEM_COMMIT: int = 0x1000
    MEM_RESERVE: int = 0x2000
    PAGE_EXECUTE_READWRITE: int = 0x40


def cleanup_process_handles(
    kernel32: Any,
    process_info: dict[str, Any],
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
        thread_handle: Any = process_info.get("thread_handle")
        if thread_handle is not None:
            kernel32.CloseHandle(thread_handle)
        process_handle: Any = process_info.get("process_handle")
        if process_handle is not None:
            kernel32.CloseHandle(process_handle)
    except Exception as e:
        if logger_instance is not None:
            logger_instance.warning("Error cleaning up handles: %s", e)
