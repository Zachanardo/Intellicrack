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

# Set up package logger
logger = logging.getLogger(__name__)

# Import patching modules with error handling
try:
    from .adobe_injector import (
        AdobeInjector,
        create_adobe_injector,
        inject_running_adobe_processes,
        start_adobe_monitoring,
    )
except ImportError as e:
    logger.warning("Failed to import adobe_injector: %s", e)

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
except ImportError as e:
    logger.warning("Failed to import windows_activator: %s", e)

try:
    from .memory_patcher import generate_launcher_script, setup_memory_patching
except ImportError as e:
    logger.warning("Failed to import memory_patcher: %s", e)

try:
    from .radare2_patch_integration import Radare2PatchIntegration
except ImportError as e:
    logger.warning("Failed to import radare2_patch_integration: %s", e)
    Radare2PatchIntegration = None

# Define package exports
__all__ = [
    # From adobe_injector
    "AdobeInjector",
    "create_adobe_injector",
    "inject_running_adobe_processes",
    "start_adobe_monitoring",
    # From windows_activator
    "WindowsActivator",
    "ActivationMethod",
    "ActivationStatus",
    "create_windows_activator",
    "check_windows_activation",
    "activate_windows_hwid",
    "activate_windows_kms",
    # From memory_patcher
    "generate_launcher_script",
    "setup_memory_patching",
    # From radare2_patch_integration
    "Radare2PatchIntegration",
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
