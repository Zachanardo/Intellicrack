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
    from intellicrack.core import (
        analysis,
        binary_analyzer,
        config_migration_handler,
        debugging_engine,
        exploitation,
        frida_bypass_wizard,
        frida_constants,
        frida_manager,
        frida_presets,
        gpu_acceleration,
        hardware_spoofer,
        license_snapshot,
        license_validation_bypass,
        network,
        network_capture,
        offline_activation_emulator,
        patching,
        process_manipulation,
        processing,
        protection_analyzer as protection_analyzer,
        protection_bypass,
        reporting,
        security_utils,
        serial_generator,
        shared,
        startup_checks,
        subscription_validation_bypass,
        task_manager,
        tool_discovery,
        trial_reset_engine,
        vulnerability_research,
    )
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
        The FridaManager class if available, None if import fails. Sets global
        FridaManager variable and FRIDA_MODULES_AVAILABLE flag on successful
        import. Logs warning if import fails.

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
        Dictionary of Frida presets if available, None if import fails. Sets
        global FRIDA_PRESETS variable on first successful import. Logs error
        if import fails.

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
        The wizard class if available, None if import fails. Sets global
        FridaBypassWizard variable on first successful import. Logs error
        if import fails.

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
    """Lazy load module attributes to prevent circular imports.

    Implements lazy loading for core modules to prevent circular import
    issues during module initialization. Modules are loaded on first access
    and cached in _lazy_modules for subsequent calls.

    Args:
        name: The name of the module or class attribute to load. Must
            correspond to a module name in the lazy-loadable modules list
            or to special attributes like 'ProtectionAnalyzer' or
            'protocols'.

    Returns:
        The loaded module, class, or dictionary if the attribute is
        available and successfully imported. Returns None if the import
        fails but the attribute name is valid. Raises AttributeError if
        the requested attribute name is not in the list of available
        lazy-loadable modules.

    Raises:
        AttributeError: If the requested attribute name is not in the list
            of available lazy-loadable modules or recognized special
            attributes.

    """
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
