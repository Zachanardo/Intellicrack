"""Protection module initialization for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging

logger = logging.getLogger(__name__)

try:
    from .intellicrack_protection_core import (
        DetectionResult,
        IntellicrackProtectionCore,
        ProtectionAnalysis,
        ProtectionType,
    )
except ImportError as e:
    logger.warning(f"Failed to import intellicrack_protection_core: {e}")
    DetectionResult = None
    IntellicrackProtectionCore = None
    ProtectionAnalysis = None
    ProtectionType = None

try:
    from .protection_detector import (
        ProtectionDetector,
        deep_analyze,
        get_protection_detector,
        quick_analyze,
    )
except ImportError as e:
    logger.warning(f"Failed to import protection_detector: {e}")
    ProtectionDetector = None
    deep_analyze = None
    get_protection_detector = None
    quick_analyze = None

try:
    from .unified_protection_engine import (
        UnifiedProtectionEngine,
        UnifiedProtectionResult,
        get_unified_engine,
    )
except ImportError as e:
    logger.warning(f"Failed to import unified_protection_engine: {e}")
    UnifiedProtectionEngine = None
    UnifiedProtectionResult = None
    get_unified_engine = None

try:
    from .themida_analyzer import (
        ThemidaAnalysisResult,
        ThemidaAnalyzer,
        VMArchitecture,
        ThemidaVersion,
        VMHandler,
        VMContext,
        DevirtualizedCode,
    )
except ImportError as e:
    logger.warning(f"Failed to import themida_analyzer: {e}")
    ThemidaAnalysisResult = None
    ThemidaAnalyzer = None
    VMArchitecture = None
    ThemidaVersion = None
    VMHandler = None
    VMContext = None
    DevirtualizedCode = None

"""
Protection Detection Module

This module provides comprehensive protection detection capabilities through
a unified engine that seamlessly combines multiple detection methods.
"""

__all__ = [
    "DetectionResult",
    "IntellicrackProtectionCore",
    "ProtectionAnalysis",
    "ProtectionDetector",
    "ProtectionType",
    "UnifiedProtectionEngine",
    "UnifiedProtectionResult",
    "deep_analyze",
    "get_protection_detector",
    "get_unified_engine",
    "quick_analyze",
    "ThemidaAnalysisResult",
    "ThemidaAnalyzer",
    "VMArchitecture",
    "ThemidaVersion",
    "VMHandler",
    "VMContext",
    "DevirtualizedCode",
]

__all__ = [item for item in __all__ if item in locals() and locals()[item] is not None]
