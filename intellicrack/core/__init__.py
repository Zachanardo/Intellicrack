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

from intellicrack.logger import logger

# Import security enforcement early to apply patches
try:
    from . import security_enforcement

    SECURITY_ENFORCEMENT_AVAILABLE = True
except ImportError as e:
    logging.getLogger(__name__).warning(f"Security enforcement not available: {e}")
    security_enforcement = None
    SECURITY_ENFORCEMENT_AVAILABLE = False

# Import all core modules
from . import analysis, network, patching, processing, protection_bypass, reporting

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
    "exploitation",
    "get_frida_bypass_wizard",
    "get_frida_manager",
    "get_frida_presets",
    "network",
    "patching",
    "processing",
    "protection_analyzer",
    "protection_bypass",
    "ProtectionAnalyzer",
    "reporting",
    "security_enforcement",
    "vulnerability_research",
]
