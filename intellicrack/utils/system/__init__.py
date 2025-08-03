"""
System utility modules for Intellicrack.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

# Import system utilities
from .os_detection import (
    detect_operating_system,
    get_default_persistence_method,
    get_platform_details,
    get_platform_specific_paths,
    is_linux_like,
    is_unix_like,
    is_windows,
)
from .os_detection_mixin import OSDetectionMixin

__all__ = [
    "detect_operating_system",
    "is_windows",
    "is_linux_like",
    "is_unix_like",
    "get_platform_details",
    "get_default_persistence_method",
    "get_platform_specific_paths",
    "OSDetectionMixin"
]
