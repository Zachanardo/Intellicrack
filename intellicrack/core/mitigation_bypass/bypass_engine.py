"""
Bypass Engine Module

Central engine for managing exploit mitigation bypasses.
"""

from ..exploit_mitigation.cfi_bypass import CFIBypass
from ..shared.bypass_config import BypassConfig


class BypassEngine:
    """Engine for exploit mitigation bypass techniques."""

    def __init__(self):
        self.cfi_bypass = CFIBypass()

    def analyze_bypass_capabilities(self, target_info):
        """Analyze available bypass capabilities for a target."""
        # Use shared configuration for consistent bypass analysis
        return BypassConfig.analyze_bypass_capabilities(target_info)

    def get_available_bypasses(self):
        """Get list of all available bypass types."""
        return BypassConfig.get_available_bypasses()

    def get_bypass_info(self, bypass_type):
        """Get detailed information about a specific bypass type."""
        return BypassConfig.get_bypass_info(bypass_type)

    def get_recommended_bypasses(self, target_info, min_reliability=6):
        """Get recommended bypasses based on target and reliability threshold."""
        return BypassConfig.get_recommended_bypasses(target_info, min_reliability)


__all__ = ['BypassEngine']
