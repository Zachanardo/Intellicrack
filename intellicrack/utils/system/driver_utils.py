"""Driver utilities for Intellicrack.

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

Common driver path utilities for Intellicrack.

This module provides utilities for finding Windows driver paths.
"""

import logging
import os

logger = logging.getLogger(__name__)


def get_driver_path(driver_name: str) -> str:
    """Get the full path to a Windows driver.

    Args:
        driver_name: Name of the driver file

    Returns:
        Full path to the driver

    """
    # Try to use path discovery if available
    try:
        from .core.path_discovery import get_system_path

        drivers_dir = get_system_path("windows_drivers")
        if drivers_dir:
            return os.path.join(drivers_dir, driver_name)
    except ImportError:
        # Fall back to standard Windows driver paths
        logger.debug("path_discovery module not available for driver location")

    # Fallback to standard Windows location
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(system_root, "System32", "drivers", driver_name)
