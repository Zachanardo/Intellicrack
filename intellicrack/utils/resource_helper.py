"""Resource Path Helper

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

import os
import sys


def get_resource_path(resource_path: str) -> str:
    """Get the absolute path to a resource file in the intellicrack package.

    This function replaces pkg_resources.resource_filename() to avoid
    deprecation warnings and improve compatibility.

    Args:
        resource_path: Relative path within the intellicrack package

    Returns:
        Absolute path to the resource file

    """
    # Handle different installation scenarios
    if hasattr(sys, "_MEIPASS"):
        # PyInstaller frozen app
        base_path = sys._MEIPASS
        return os.path.join(base_path, "intellicrack", resource_path.replace("/", os.sep))

    # Normal Python environment
    import intellicrack

    package_dir = os.path.dirname(intellicrack.__file__)

    # If we're in a development environment, go up one level
    if os.path.basename(os.path.dirname(package_dir)) == "intellicrack":
        base_path = os.path.dirname(package_dir)
    else:
        base_path = os.path.dirname(package_dir)

    return os.path.join(base_path, "intellicrack", resource_path.replace("/", os.sep))
