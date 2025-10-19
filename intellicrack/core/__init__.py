"""Core analysis and processing modules for Intellicrack.

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

from intellicrack.utils.logger import logger

# Import security enforcement early to apply patches
try:
    from . import security_enforcement

    SECURITY_ENFORCEMENT_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).warning(f"Security enforcement not available: {e}")
    security_enforcement = None
    SECURITY_ENFORCEMENT_AVAILABLE = False

# Import all core modules with error handling
try:
    from . import analysis
except ImportError as e:
    logger.warning(f"Analysis module not available: {e}")
    analysis = None

try:
    from . import network
except ImportError as e:
    logger.warning(f"Network module not available: {e}")
    network = None

try:
    from . import patching
except ImportError as e:
    logger.warning(f"Patching module not available: {e}")
    patching = None

try:
    from . import processing
except ImportError as e:
    logger.warning(f"Processing module not available: {e}")
    processing = None

try:
    from . import protection_bypass
except ImportError as e:
    logger.warning(f"Protection bypass module not available: {e}")
    protection_bypass = None

try:
    from . import reporting
except ImportError as e:
    logger.warning(f"Reporting module not available: {e}")
    reporting = None

# Import protection analyzer
try:
    from .protection_analyzer import ProtectionAnalyzer

    PROTECTION_ANALYZER_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Protection analyzer not available: {e}")
    ProtectionAnalyzer = None
    PROTECTION_ANALYZER_AVAILABLE = False

# Import new exploitation modules
try:
    from . import (
        exploitation,
        vulnerability_research,
    )

    EXPLOITATION_MODULES_AVAILABLE = True
except ImportError as e:
    # Exploitation modules are optional - not critical for basic functionality
    logging.getLogger(__name__).warning(f"Exploitation modules not available: {e}")
    exploitation = None
    vulnerability_research = None
    EXPLOITATION_MODULES_AVAILABLE = False

# Import individual core modules for Sphinx documentation
try:
    from . import binary_analyzer
except ImportError as e:
    logger.warning(f"binary_analyzer not available: {e}")
    binary_analyzer = None

try:
    from . import config_migration_handler
except ImportError as e:
    logger.warning(f"config_migration_handler not available: {e}")
    config_migration_handler = None

try:
    from . import debugging_engine
except ImportError as e:
    logger.warning(f"debugging_engine not available: {e}")
    debugging_engine = None

try:
    from . import frida_bypass_wizard
except ImportError as e:
    logger.warning(f"frida_bypass_wizard not available: {e}")
    frida_bypass_wizard = None

try:
    from . import frida_constants
except ImportError as e:
    logger.warning(f"frida_constants not available: {e}")
    frida_constants = None

try:
    from . import frida_manager
except ImportError as e:
    logger.warning(f"frida_manager not available: {e}")
    frida_manager = None

try:
    from . import frida_presets
except ImportError as e:
    logger.warning(f"frida_presets not available: {e}")
    frida_presets = None

try:
    from . import gpu_acceleration
except ImportError as e:
    logger.warning(f"gpu_acceleration not available: {e}")
    gpu_acceleration = None

try:
    from . import hardware_spoofer
except ImportError as e:
    logger.warning(f"hardware_spoofer not available: {e}")
    hardware_spoofer = None

try:
    from . import license_snapshot
except ImportError as e:
    logger.warning(f"license_snapshot not available: {e}")
    license_snapshot = None

try:
    from . import license_validation_bypass
except ImportError as e:
    logger.warning(f"license_validation_bypass not available: {e}")
    license_validation_bypass = None

try:
    from . import network_capture
except ImportError as e:
    logger.warning(f"network_capture not available: {e}")
    network_capture = None

try:
    from . import offline_activation_emulator
except ImportError as e:
    logger.warning(f"offline_activation_emulator not available: {e}")
    offline_activation_emulator = None

try:
    from . import process_manipulation
except ImportError as e:
    logger.warning(f"process_manipulation not available: {e}")
    process_manipulation = None

try:
    from . import protection_analyzer
except ImportError as e:
    logger.warning(f"protection_analyzer not available: {e}")
    protection_analyzer = None

try:
    from . import security_utils
except ImportError as e:
    logger.warning(f"security_utils not available: {e}")
    security_utils = None

try:
    from . import serial_generator
except ImportError as e:
    logger.warning(f"serial_generator not available: {e}")
    serial_generator = None

try:
    from . import startup_checks
except ImportError as e:
    logger.warning(f"startup_checks not available: {e}")
    startup_checks = None

try:
    from . import subscription_validation_bypass
except ImportError as e:
    logger.warning(f"subscription_validation_bypass not available: {e}")
    subscription_validation_bypass = None

try:
    from . import task_manager
except ImportError as e:
    logger.warning(f"task_manager not available: {e}")
    task_manager = None

try:
    from . import tool_discovery
except ImportError as e:
    logger.warning(f"tool_discovery not available: {e}")
    tool_discovery = None

try:
    from . import trial_reset_engine
except ImportError as e:
    logger.warning(f"trial_reset_engine not available: {e}")
    trial_reset_engine = None

# Import shared modules
try:
    from . import shared
except ImportError as e:
    logger.warning(f"shared not available: {e}")
    shared = None

# Import network.protocols
try:
    from .network import protocols
except ImportError as e:
    logger.warning(f"network.protocols not available: {e}")
    protocols = None

# Frida modules - lazy import to avoid cycles
FRIDA_MODULES_AVAILABLE = False
FridaManager = None
FRIDA_PRESETS = None
FridaBypassWizard = None


def get_frida_manager():
    """Get FridaManager with lazy import to avoid circular dependencies.

    This function implements lazy loading for the FridaManager class to prevent
    circular import issues that can occur during module initialization. The
    FridaManager is only imported when first requested, and then cached for
    subsequent calls.

    Returns:
        FridaManager: The FridaManager class if available, None if import fails

    Side Effects:
        - Sets global FridaManager variable on first successful import
        - Sets FRIDA_MODULES_AVAILABLE to True on successful import
        - Logs warning if import fails

    Example:
        >>> FridaManager = get_frida_manager()
        >>> if FridaManager:
        ...     manager = FridaManager()

    """
    global FridaManager, FRIDA_MODULES_AVAILABLE
    if FridaManager is None:
        try:
            from .frida_manager import FridaManager as _FridaManager

            FridaManager = _FridaManager
            FRIDA_MODULES_AVAILABLE = True
        except ImportError as e:
            logging.getLogger(__name__).warning(f"FridaManager not available: {e}")
    return FridaManager


def get_frida_presets():
    """Get FRIDA_PRESETS with lazy import to avoid circular dependencies.

    This function implements lazy loading for the FRIDA_PRESETS dictionary
    to prevent circular import issues. The presets contain pre-configured
    bypass scripts for common protection schemes.

    Returns:
        dict: Dictionary of Frida presets if available, None if import fails

    Side Effects:
        - Sets global FRIDA_PRESETS variable on first successful import
        - Logs error if import fails

    Example:
        >>> presets = get_frida_presets()
        >>> if presets:
        ...     anti_debug_script = presets.get('anti_debug')

    """
    global FRIDA_PRESETS
    if FRIDA_PRESETS is None:
        try:
            from .frida_presets import FRIDA_PRESETS as _PRESETS

            FRIDA_PRESETS = _PRESETS
        except ImportError as e:
            logger.error("Import error in __init__: %s", e)
    return FRIDA_PRESETS


def get_frida_bypass_wizard():
    """Get FridaBypassWizard with lazy import to avoid circular dependencies.

    This function implements lazy loading for the FridaBypassWizard class
    which provides an interactive wizard for generating protection bypass
    scripts based on detected protection schemes.

    Returns:
        FridaBypassWizard: The wizard class if available, None if import fails

    Side Effects:
        - Sets global FridaBypassWizard variable on first successful import
        - Logs error if import fails

    Example:
        >>> Wizard = get_frida_bypass_wizard()
        >>> if Wizard:
        ...     wizard = Wizard()
        ...     wizard.generate_bypass_script(protections)

    """
    global FridaBypassWizard
    if FridaBypassWizard is None:
        try:
            from .frida_bypass_wizard import FridaBypassWizard as _Wizard

            FridaBypassWizard = _Wizard
        except ImportError as e:
            logger.error("Import error in __init__: %s", e)
    return FridaBypassWizard


__all__ = [
    "EXPLOITATION_MODULES_AVAILABLE",
    "FRIDA_MODULES_AVAILABLE",
    "PROTECTION_ANALYZER_AVAILABLE",
    "SECURITY_ENFORCEMENT_AVAILABLE",
    "analysis",
    "binary_analyzer",
    "config_migration_handler",
    "debugging_engine",
    "exploitation",
    "frida_bypass_wizard",
    "frida_constants",
    "frida_manager",
    "frida_presets",
    "get_frida_bypass_wizard",
    "get_frida_manager",
    "get_frida_presets",
    "gpu_acceleration",
    "hardware_spoofer",
    "license_snapshot",
    "license_validation_bypass",
    "network",
    "network_capture",
    "offline_activation_emulator",
    "patching",
    "process_manipulation",
    "processing",
    "protection_analyzer",
    "protection_bypass",
    "ProtectionAnalyzer",
    "protocols",
    "reporting",
    "security_enforcement",
    "security_utils",
    "serial_generator",
    "shared",
    "startup_checks",
    "subscription_validation_bypass",
    "task_manager",
    "tool_discovery",
    "trial_reset_engine",
    "vulnerability_research",
]

# Update __all__ to exclude None modules
__all__ = [
    item
    for item in __all__
    if item
    not in [
        "analysis",
        "network",
        "patching",
        "processing",
        "protection_bypass",
        "reporting",
        "binary_analyzer",
        "config_migration_handler",
        "debugging_engine",
        "frida_bypass_wizard",
        "frida_constants",
        "frida_manager",
        "frida_presets",
        "gpu_acceleration",
        "hardware_spoofer",
        "license_snapshot",
        "license_validation_bypass",
        "network_capture",
        "offline_activation_emulator",
        "process_manipulation",
        "protection_analyzer",
        "security_utils",
        "serial_generator",
        "startup_checks",
        "subscription_validation_bypass",
        "task_manager",
        "tool_discovery",
        "trial_reset_engine",
        "shared",
        "protocols",
    ]
    or locals().get(item) is not None
]
