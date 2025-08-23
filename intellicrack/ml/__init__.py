"""Machine Learning components for Intellicrack.

This package provides machine learning capabilities for pattern recognition,
behavior analysis, and intelligent security research automation.
"""

import logging

logger = logging.getLogger(__name__)

# Attempt to import available ML modules
try:
    from .pattern_evolution_tracker import PatternEvolutionTracker
    logger.debug("Pattern evolution tracker loaded successfully")
    HAS_PATTERN_TRACKER = True
except ImportError as e:
    logger.warning("Pattern evolution tracker not available: %s", e)
    PatternEvolutionTracker = None
    HAS_PATTERN_TRACKER = False

def get_ml_capabilities():
    """Get list of available ML capabilities."""
    capabilities = []
    if HAS_PATTERN_TRACKER:
        capabilities.append("pattern_evolution")
    return capabilities

__all__ = []
if PatternEvolutionTracker:
    __all__.append('PatternEvolutionTracker')

__all__.extend(['get_ml_capabilities', 'HAS_PATTERN_TRACKER'])
