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


logger = logging.getLogger(__name__)

# Import patching modules with error handling
logger.debug("Importing windows_activator...")
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

    logger.debug("windows_activator imported OK")
except ImportError as e:
    logger.warning("Failed to import windows_activator: %s", e, exc_info=True)

logger.debug("Importing memory_patcher...")
try:
    from .memory_patcher import generate_launcher_script, setup_memory_patching

    logger.debug("memory_patcher imported OK")
except ImportError as e:
    logger.warning("Failed to import memory_patcher: %s", e, exc_info=True)

logger.debug("Importing radare2_patch_integration...")
try:
    from .radare2_patch_integration import R2PatchIntegrator

    logger.debug("radare2_patch_integration imported OK")
except ImportError as e:
    logger.warning("Failed to import radare2_patch_integration: %s", e, exc_info=True)
    R2PatchIntegrator = None

# Define package exports
__all__ = [
    "ActivationMethod",
    "ActivationStatus",
    "R2PatchIntegrator",
    "WindowsActivator",
    "activate_windows_hwid",
    "activate_windows_in_terminal",
    "activate_windows_interactive",
    "activate_windows_kms",
    "check_windows_activation",
    "create_windows_activator",
    "generate_launcher_script",
    "setup_memory_patching",
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
