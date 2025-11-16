"""Intellicrack Core Patching Package.

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

import logging
import sys

# Set up package logger
logger = logging.getLogger(__name__)

# Import patching modules with error handling
print("[DEBUG patching/__init__] Importing windows_activator...")
sys.stdout.flush()
try:
    from .windows_activator import (
        ActivationMethod,
        ActivationStatus,
        WindowsActivator,
        activate_windows_hwid,
        activate_windows_kms,
        check_windows_activation,
        create_windows_activator,
    )

    def activate_windows_interactive(output_callback: object = None) -> object:
        """Launch Windows activation interactively.

        Args:
            output_callback: Optional callback function to handle output messages.

        Returns:
            The result of the Windows interactive activation process.

        """
        activator = create_windows_activator()
        return activator.activate_windows_interactive(output_callback)

    def activate_windows_in_terminal() -> object:
        """Activate Windows using embedded terminal (recommended).

        Returns:
            The result of the Windows embedded terminal activation process.

        """
        activator = create_windows_activator()
        return activator.activate_windows_in_terminal()

    print("[DEBUG patching/__init__] windows_activator imported OK")
    sys.stdout.flush()
except ImportError as e:
    logger.warning("Failed to import windows_activator: %s", e)

print("[DEBUG patching/__init__] Importing memory_patcher...")
sys.stdout.flush()
try:
    from .memory_patcher import generate_launcher_script, setup_memory_patching
    print("[DEBUG patching/__init__] memory_patcher imported OK")
    sys.stdout.flush()
except ImportError as e:
    logger.warning("Failed to import memory_patcher: %s", e)

print("[DEBUG patching/__init__] Importing radare2_patch_integration...")
sys.stdout.flush()
try:
    from .radare2_patch_integration import R2PatchIntegrator
    print("[DEBUG patching/__init__] radare2_patch_integration imported OK")
    sys.stdout.flush()
except ImportError as e:
    logger.warning("Failed to import radare2_patch_integration: %s", e)
    R2PatchIntegrator = None

# Define package exports
__all__ = [
    # From windows_activator
    "WindowsActivator",
    "ActivationMethod",
    "ActivationStatus",
    "create_windows_activator",
    "check_windows_activation",
    "activate_windows_hwid",
    "activate_windows_kms",
    "activate_windows_interactive",
    "activate_windows_in_terminal",
    # From memory_patcher
    "generate_launcher_script",
    "setup_memory_patching",
    # From radare2_patch_integration
    "R2PatchIntegrator",
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
