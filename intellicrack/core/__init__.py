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
# pylint: disable=cyclic-import

import logging
from types import ModuleType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from intellicrack.core import analysis
    from intellicrack.core import binary_analyzer
    from intellicrack.core import config_migration_handler
    from intellicrack.core import debugging_engine
    from intellicrack.core import exploitation
    from intellicrack.core import frida_bypass_wizard
    from intellicrack.core import frida_constants
    from intellicrack.core import frida_manager
    from intellicrack.core import frida_presets
    from intellicrack.core import gpu_acceleration
    from intellicrack.core import hardware_spoofer
    from intellicrack.core import license_snapshot
    from intellicrack.core import license_validation_bypass
    from intellicrack.core import network
    from intellicrack.core import network_capture
    from intellicrack.core import offline_activation_emulator
    from intellicrack.core import patching
    from intellicrack.core import process_manipulation
    from intellicrack.core import processing
    from intellicrack.core import protection_analyzer as protection_analyzer
    from intellicrack.core import protection_bypass
    from intellicrack.core import reporting
    from intellicrack.core import security_utils
    from intellicrack.core import serial_generator
    from intellicrack.core import shared
    from intellicrack.core import startup_checks
    from intellicrack.core import subscription_validation_bypass
    from intellicrack.core import task_manager
    from intellicrack.core import tool_discovery
    from intellicrack.core import trial_reset_engine
    from intellicrack.core import vulnerability_research
    from intellicrack.core.network import protocols
    from intellicrack.core.protection_analyzer import ProtectionAnalyzer


logger = logging.getLogger(__name__)
logger.debug("Core module loaded")

# Import security enforcement early to apply patches
security_enforcement: ModuleType | None = None
SECURITY_ENFORCEMENT_AVAILABLE: bool = False
try:
    from . import security_enforcement

    SECURITY_ENFORCEMENT_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).warning("Security enforcement not available: %s", e)

# All individual core modules are now lazy-loaded through __getattr__ to prevent circular imports
# No eager imports here - modules will be loaded on first access

PROTECTION_ANALYZER_AVAILABLE: bool = False
EXPLOITATION_MODULES_AVAILABLE: bool = False

# Frida modules - lazy import to avoid cycles
FRIDA_MODULES_AVAILABLE: bool = False
FridaManager: type | None = None
FRIDA_PRESETS: dict[str, Any] | None = None
FridaBypassWizard: type | None = None


def get_frida_manager() -> type | None:
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
        >>> FridaManager = (
        ...     get_frida_manager()
        ... )
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
            logging.getLogger(__name__).warning("FridaManager not available: %s", e)
    return FridaManager


def get_frida_presets() -> dict[str, Any] | None:
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
        ...     anti_debug_script = (
        ...         presets.get(
        ...             "anti_debug"
        ...         )
        ...     )

    """
    global FRIDA_PRESETS
    if FRIDA_PRESETS is None:
        try:
            from .frida_presets import FRIDA_PRESETS as _PRESETS

            FRIDA_PRESETS = _PRESETS
        except ImportError as e:
            logger.exception("Import error in __init__: %s", e)
    return FRIDA_PRESETS


def get_frida_bypass_wizard() -> type | None:
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
        >>> Wizard = (
        ...     get_frida_bypass_wizard()
        ... )
        >>> if Wizard:
        ...     wizard = Wizard()
        ...     wizard.generate_bypass_script(
        ...         protections
        ...     )

    """
    global FridaBypassWizard
    if FridaBypassWizard is None:
        try:
            from .frida_bypass_wizard import FridaBypassWizard as _Wizard

            FridaBypassWizard = _Wizard
        except ImportError as e:
            logger.exception("Import error in __init__: %s", e)
    return FridaBypassWizard


_lazy_modules: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    """Lazy load module attributes to prevent circular imports."""
    module_names = [
        "analysis",
        "binary_analyzer",
        "config_migration_handler",
        "debugging_engine",
        "exploitation",
        "frida_bypass_wizard",
        "frida_constants",
        "frida_manager",
        "frida_presets",
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
        "protocols",
        "reporting",
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

    # Special handling for ProtectionAnalyzer class
    if name == "ProtectionAnalyzer":
        if name not in _lazy_modules:
            try:
                from .protection_analyzer import ProtectionAnalyzer as ProtectionAnalyzerAlias

                _lazy_modules[name] = ProtectionAnalyzerAlias
                global PROTECTION_ANALYZER_AVAILABLE
                PROTECTION_ANALYZER_AVAILABLE = True
            except ImportError as e:
                logger.warning("ProtectionAnalyzer not available: %s", e)
                _lazy_modules[name] = None
        return _lazy_modules[name]

    # Special handling for protocols submodule
    if name == "protocols":
        if name not in _lazy_modules:
            try:
                from .network import protocols as proto

                _lazy_modules[name] = proto
            except ImportError as e:
                logger.warning("protocols not available: %s", e)
                _lazy_modules[name] = None
        return _lazy_modules[name]

    if name in module_names:
        if name not in _lazy_modules:
            try:
                _lazy_modules[name] = __import__(f"{__name__}.{name}", fromlist=[name])

                # Set availability flags for exploitation modules
                if name in {"exploitation", "vulnerability_research"}:
                    global EXPLOITATION_MODULES_AVAILABLE
                    EXPLOITATION_MODULES_AVAILABLE = True

            except ImportError as e:
                logger.warning("%s not available: %s", name, e)
                _lazy_modules[name] = None
        return _lazy_modules[name]

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__: list[str] = [
    "EXPLOITATION_MODULES_AVAILABLE",
    "FRIDA_MODULES_AVAILABLE",
    "PROTECTION_ANALYZER_AVAILABLE",
    "ProtectionAnalyzer",
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

# Update __all__ to only include modules that are actually available
_locals: dict[str, Any] = locals()
__all__ = [item for item in __all__ if item in _locals and _locals.get(item) is not None]
