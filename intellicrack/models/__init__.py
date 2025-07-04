"""
Intellicrack Models Package

This package contains data models and knowledge bases for Intellicrack.
ML models have been replaced with ICP Engine for protection detection.
"""

import logging

from .model_manager import ModelManager

# Create module logger
logger = logging.getLogger(__name__)

# Import model manager for compatibility

# Import protection knowledge base
try:
    from .protection_knowledge_base import get_protection_knowledge_base
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
    get_protection_knowledge_base = None

# Import severity levels for backwards compatibility
try:
    from ..utils.analysis.severity_levels import SeverityLevel, VulnerabilityLevel
except ImportError as e:
    logger.error("Import error in __init__: %s", e)
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

# Export main interface
__all__ = [
    'ModelManager',
    'VulnerabilityLevel',
    'SeverityLevel'
]

if get_protection_knowledge_base is not None:
    __all__.append('get_protection_knowledge_base')

# Log initialization

logger = logging.getLogger(__name__)
logger.info("Models package initialized - Using ICP Engine for protection detection")
