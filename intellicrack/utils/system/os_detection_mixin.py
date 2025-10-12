"""OS detection mixin for Intellicrack.

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

OS Detection Mixin

Shared mixin for classes that need OS detection functionality.
Eliminates code duplication across multiple classes.
"""

from .os_detection import detect_operating_system


class OSDetectionMixin:
    """Mixin class providing OS detection functionality.

    Eliminates duplicate OS detection methods across multiple classes.
    """

    def _detect_os(self) -> str:
        """Detect operating system."""
        return detect_operating_system()

    def _detect_target_os(self) -> str:
        """Detect target operating system."""
        return detect_operating_system()

    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        return self._detect_os() == "windows"

    def _is_linux(self) -> bool:
        """Check if running on Linux."""
        return self._detect_os() == "linux"

    def detect_platform(self) -> str:
        """Detect the current platform (public method for compatibility)."""
        return self._detect_os()
