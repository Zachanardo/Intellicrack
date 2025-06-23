"""
Models Package

This package provides model management functionality for Intellicrack,
including local file and API-based model repositories.
"""

from .model_manager import ModelManager

# Import severity levels for backwards compatibility
try:
    from ..utils.analysis.severity_levels import SeverityLevel, VulnerabilityLevel
except ImportError:
    # Fallback enum if severity_levels not available
    from enum import Enum
    class VulnerabilityLevel(Enum):
        """Fallback vulnerability severity levels when module unavailable."""
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        INFO = "info"
    SeverityLevel = VulnerabilityLevel

__all__ = ['ModelManager', 'VulnerabilityLevel', 'SeverityLevel']
