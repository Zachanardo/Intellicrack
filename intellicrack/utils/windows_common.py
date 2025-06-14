"""
Common Windows utilities and checks.

This module consolidates Windows-specific functionality to reduce code duplication.
"""

import sys
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Global Windows availability check
WINDOWS_AVAILABLE = False
if sys.platform == 'win32':
    try:
        import ctypes.wintypes
        WINDOWS_AVAILABLE = True
    except ImportError:
        WINDOWS_AVAILABLE = False

def is_windows_available() -> bool:
    """Check if Windows-specific functionality is available."""
    return WINDOWS_AVAILABLE

def get_windows_kernel32():
    """Get kernel32 library if available."""
    if not WINDOWS_AVAILABLE:
        return None
    try:
        import ctypes
        return ctypes.WinDLL('kernel32', use_last_error=True)
    except Exception as e:
        logger.error("Failed to load kernel32: %s", e)
        return None

def get_windows_ntdll():
    """Get ntdll library if available."""
    if not WINDOWS_AVAILABLE:
        return None
    try:
        import ctypes
        return ctypes.WinDLL('ntdll.dll')
    except Exception as e:
        logger.error("Failed to load ntdll: %s", e)
        return None

# Common Windows constants
class WindowsConstants:
    """Common Windows constants used across modules."""
    CREATE_SUSPENDED = 0x00000004
    CREATE_NO_WINDOW = 0x08000000
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40