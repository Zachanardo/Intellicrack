"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from intellicrack.logger import logger

"""
Mitigation Bypass Module - Compatibility Alias

This module provides compatibility aliases for the exploit mitigation bypass components.
"""

# Import from the actual exploit mitigation module
try:
    from ..exploitation.cfi_bypass import CFIBypass
    HAS_CFI_BYPASS = True
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    CFIBypass = None
    HAS_CFI_BYPASS = False


class BypassEngine:
    """Engine for exploit mitigation bypass techniques."""

    def __init__(self):
        """Initialize the bypass engine with available mitigation bypass capabilities."""
        self.cfi_bypass = CFIBypass() if HAS_CFI_BYPASS else None

    def analyze_bypass_capabilities(self, target_info):
        """Analyze available bypass capabilities for a target."""
        bypasses = []

        # Check ASLR bypass
        if target_info.get('aslr_enabled'):
            bypasses.append('aslr_bypass')

        # Check DEP bypass
        if target_info.get('dep_enabled'):
            bypasses.append('dep_bypass')

        # Check CFI bypass
        if target_info.get('cfi_enabled'):
            bypasses.append('cfi_bypass')

        return {
            'bypasses_available': bypasses,
            'target_info': target_info
        }


# Mock bypass classes for compatibility
class ASLRBypass:
    """ASLR bypass implementation."""
    pass

class DEPBypass:
    """DEP bypass implementation."""
    pass

# Export available classes
__all__ = ['BypassEngine', 'ASLRBypass', 'DEPBypass']
if HAS_CFI_BYPASS:
    __all__.append('CFIBypass')
