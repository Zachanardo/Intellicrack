"""
OS Detection Mixin

Shared mixin for classes that need OS detection functionality.
Eliminates code duplication across multiple classes.
"""

from .os_detection import detect_operating_system


class OSDetectionMixin:
    """
    Mixin class providing OS detection functionality.
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
        return self._detect_os() == 'windows'

    def _is_linux(self) -> bool:
        """Check if running on Linux."""
        return self._detect_os() == 'linux'