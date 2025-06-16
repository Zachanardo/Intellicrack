"""
Core analysis and processing modules for Intellicrack. 

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


# Import all core modules
from . import analysis, network, patching, processing, protection_bypass, reporting

# Import new exploitation modules
try:
    from . import (
        exploitation,
        vulnerability_research,
    )
    EXPLOITATION_MODULES_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Exploitation modules not available: {e}")
    exploitation = None
    vulnerability_research = None
    EXPLOITATION_MODULES_AVAILABLE = False

# Import Frida modules
try:
    from .frida_bypass_wizard import FridaBypassWizard
    from .frida_manager import FridaManager
    from .frida_presets import FRIDA_PRESETS
    FRIDA_MODULES_AVAILABLE = True
except ImportError as e:
    import logging
    logging.getLogger(__name__).warning(f"Frida modules not available: {e}")
    FridaManager = None
    FRIDA_PRESETS = None
    FridaBypassWizard = None
    FRIDA_MODULES_AVAILABLE = False

__all__ = [
    'analysis',
    'network',
    'patching',
    'processing',
    'protection_bypass',
    'reporting',
    'exploitation',
    'vulnerability_research',
    'EXPLOITATION_MODULES_AVAILABLE',
    'FridaManager',
    'FRIDA_PRESETS',
    'FridaBypassWizard',
    'FRIDA_MODULES_AVAILABLE'
]
