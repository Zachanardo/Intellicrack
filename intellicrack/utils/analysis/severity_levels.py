"""
Common Severity Level Enums

Centralized severity level definitions to eliminate code duplication.
"""

from enum import Enum


class SeverityLevel(Enum):
    """Common severity levels used across the application."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Aliases for backwards compatibility
SecurityRelevance = SeverityLevel
VulnerabilityLevel = SeverityLevel
