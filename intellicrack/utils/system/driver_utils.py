"""
Common driver path utilities for Intellicrack.

This module provides utilities for finding Windows driver paths.
"""

import logging
import os

logger = logging.getLogger(__name__)


def get_driver_path(driver_name: str) -> str:
    """
    Get the full path to a Windows driver.

    Args:
        driver_name: Name of the driver file

    Returns:
        Full path to the driver
    """
    # Try to use path discovery if available
    try:
        from .core.path_discovery import get_system_path
        drivers_dir = get_system_path('windows_drivers')
        if drivers_dir:
            return os.path.join(drivers_dir, driver_name)
    except ImportError:
        # Fall back to standard Windows driver paths
        logger.debug("path_discovery module not available for driver location")

    # Fallback to standard Windows location
    system_root = os.environ.get('SystemRoot', r'C:\Windows')
    return os.path.join(system_root, 'System32', 'drivers', driver_name)
