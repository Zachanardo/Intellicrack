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


logger: logging.Logger = logging.getLogger(__name__)

DetectionResult: object = None
IntellicrackProtectionCore: object = None
ProtectionAnalysis: object = None
ProtectionType: object = None
ProtectionDetector: object = None
deep_analyze: object = None
get_protection_detector: object = None
quick_analyze: object = None

_lazy_imports: dict[str, dict[str, object]] = {}


def __getattr__(name: str) -> object:
    """Lazy load protection module components to prevent circular imports.

    Implements lazy loading for protection detection and analysis components
    to prevent circular import issues while maintaining backwards compatibility
    with existing code that imports from this module.

    Args:
        name: Name of the module attribute to load.

    Returns:
        Loaded module component or None if import fails.

    Raises:
        AttributeError: If the requested attribute does not exist in any
            lazy-loaded module.

    """
    if name in {
        "DetectionResult",
        "IntellicrackProtectionCore",
        "ProtectionAnalysis",
        "ProtectionType",
    }:
        if "core_module" not in _lazy_imports:
            try:
                from .intellicrack_protection_core import (
                    DetectionResult as DetectionResultAlias,
                    IntellicrackProtectionCore as IntellicrackProtectionCoreAlias,
                    ProtectionAnalysis as ProtectionAnalysisAlias,
                    ProtectionType as ProtectionTypeAlias,
                )

                _lazy_imports["core_module"] = {
                    "DetectionResult": DetectionResultAlias,
                    "IntellicrackProtectionCore": IntellicrackProtectionCoreAlias,
                    "ProtectionAnalysis": ProtectionAnalysisAlias,
                    "ProtectionType": ProtectionTypeAlias,
                }
            except ImportError as e:
                logger.warning(f"Failed to import intellicrack_protection_core: {e}")
                _lazy_imports["core_module"] = {
                    "DetectionResult": None,
                    "IntellicrackProtectionCore": None,
                    "ProtectionAnalysis": None,
                    "ProtectionType": None,
                }
        return _lazy_imports["core_module"].get(name)

    if name in {
        "ProtectionDetector",
        "deep_analyze",
        "get_protection_detector",
        "quick_analyze",
    }:
        if "detector_module" not in _lazy_imports:
            try:
                from .protection_detector import (
                    ProtectionDetector as ProtectionDetectorAlias,
                    deep_analyze as da,
                    get_protection_detector as gpd,
                    quick_analyze as qa,
                )

                _lazy_imports["detector_module"] = {
                    "ProtectionDetector": ProtectionDetectorAlias,
                    "deep_analyze": da,
                    "get_protection_detector": gpd,
                    "quick_analyze": qa,
                }
            except ImportError as e:
                logger.warning(f"Failed to import protection_detector: {e}")
                _lazy_imports["detector_module"] = {
                    "ProtectionDetector": None,
                    "deep_analyze": None,
                    "get_protection_detector": None,
                    "quick_analyze": None,
                }
        return _lazy_imports["detector_module"].get(name)

    error_msg = f"module '{__name__}' has no attribute '{name}'"
    logger.error(error_msg)
    raise AttributeError(error_msg)


try:
    from .unified_protection_engine import UnifiedProtectionEngine, UnifiedProtectionResult, get_unified_engine
except ImportError as e:
    logger.warning(f"Failed to import unified_protection_engine: {e}")
    UnifiedProtectionEngine = None
    UnifiedProtectionResult = None
    get_unified_engine = None

try:
    from .themida_analyzer import (
        DevirtualizedCode,
        ThemidaAnalysisResult,
        ThemidaAnalyzer,
        ThemidaVersion,
        VMArchitecture,
        VMContext,
        VMHandler,
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
    "DevirtualizedCode",
    "IntellicrackProtectionCore",
    "ProtectionAnalysis",
    "ProtectionDetector",
    "ProtectionType",
    "ThemidaAnalysisResult",
    "ThemidaAnalyzer",
    "ThemidaVersion",
    "UnifiedProtectionEngine",
    "UnifiedProtectionResult",
    "VMArchitecture",
    "VMContext",
    "VMHandler",
    "deep_analyze",
    "get_protection_detector",
    "get_unified_engine",
    "quick_analyze",
]

__all__ = [item for item in __all__ if item in locals() and locals()[item] is not None]
