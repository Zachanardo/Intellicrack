"""
Protection Detection Module

This module provides comprehensive protection detection capabilities through
a unified engine that seamlessly combines multiple detection methods.
"""

from .intellicrack_protection_core import (
    DetectionResult,
    DIEProtectionDetector,  # Backward compatibility alias
    IntellicrackProtectionCore,
    ProtectionAnalysis,
    ProtectionType,
)
from .protection_detector import (
    ProtectionDetector,
    deep_analyze,
    get_protection_detector,
    quick_analyze,
)
from .unified_protection_engine import (
    UnifiedProtectionEngine,
    UnifiedProtectionResult,
    get_unified_engine,
)

__all__ = [
    'ProtectionDetector',
    'get_protection_detector',
    'quick_analyze',
    'deep_analyze',
    'IntellicrackProtectionCore',
    'DIEProtectionDetector',  # Backward compatibility
    'UnifiedProtectionEngine',
    'UnifiedProtectionResult',
    'get_unified_engine',
    'DetectionResult',
    'ProtectionAnalysis',
    'ProtectionType',
]
