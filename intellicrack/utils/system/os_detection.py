"""
Operating System Detection Utilities

Shared OS detection functions to eliminate code duplication across the codebase.
"""

import platform
from typing import Any, Dict


def detect_operating_system() -> str:
    """
    Detect and normalize operating system identifier.

    Returns:
        Normalized OS identifier: 'windows', 'linux', or 'unknown'
    """
    system = platform.system().lower()

    if system == 'windows':
        return 'windows'
    elif system in ['linux', 'darwin']:
        return 'linux'
    else:
        return 'unknown'


def is_windows() -> bool:
    """Check if running on Windows."""
    return detect_operating_system() == 'windows'


def is_linux_like() -> bool:
    """Check if running on Linux or macOS."""
    return detect_operating_system() == 'linux'


def is_unix_like() -> bool:
    """Check if running on Unix-like system (Linux or macOS)."""
    return is_linux_like()


def get_platform_details() -> Dict[str, Any]:
    """
    Get detailed platform information.

    Returns:
        Dictionary with platform details
    """
    return {
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'architecture': platform.architecture(),
        'normalized_os': detect_operating_system()
    }


def get_default_persistence_method() -> str:
    """
    Get default persistence method based on operating system.

    Returns:
        Default persistence method for the current OS
    """
    current_os = detect_operating_system()

    if current_os == 'windows':
        return 'scheduled_task'
    elif current_os == 'linux':
        return 'systemd_service'
    else:
        return 'cron_job'


def get_platform_specific_paths() -> Dict[str, str]:
    """
    Get platform-specific common paths.

    Returns:
        Dictionary with common paths for the current platform
    """
    current_os = detect_operating_system()

    if current_os == 'windows':
        import os
        return {
            'temp': os.environ.get('TEMP', 'C:\\Windows\\Temp'),
            'appdata': os.environ.get('APPDATA', ''),
            'localappdata': os.environ.get('LOCALAPPDATA', ''),
            'programfiles': os.environ.get('PROGRAMFILES', 'C:\\Program Files'),
            'system32': 'C:\\Windows\\System32',
            'documents': os.path.join(os.path.expanduser('~'), 'Documents')
        }
    else:
        return {
            'temp': '/tmp',
            'home': os.path.expanduser('~'),
            'etc': '/etc',
            'var': '/var',
            'usr': '/usr',
            'bin': '/bin'
        }


# Export main functions
__all__ = [
    'detect_operating_system',
    'is_windows',
    'is_linux_like',
    'is_unix_like',
    'get_platform_details',
    'get_default_persistence_method',
    'get_platform_specific_paths'
]
