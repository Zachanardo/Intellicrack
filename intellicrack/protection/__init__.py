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

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from .intellicrack_protection_core import (
        DetectionResult as DetectionResultType,
        IntellicrackProtectionCore as IntellicrackProtectionCoreType,
        ProtectionAnalysis as ProtectionAnalysisType,
        ProtectionType as ProtectionTypeType,
    )
    from .protection_detector import ProtectionDetector as ProtectionDetectorType
    from .themida_analyzer import (
        DevirtualizedCode as DevirtualizedCodeType,
        ThemidaAnalysisResult as ThemidaAnalysisResultType,
        ThemidaAnalyzer as ThemidaAnalyzerType,
        ThemidaVersion as ThemidaVersionType,
        VMArchitecture as VMArchitectureType,
        VMContext as VMContextType,
        VMHandler as VMHandlerType,
    )
    from .unified_protection_engine import (
        UnifiedProtectionEngine as UnifiedProtectionEngineType,
        UnifiedProtectionResult as UnifiedProtectionResultType,
    )


logger: logging.Logger = logging.getLogger(__name__)

DetectionResult: type[DetectionResultType] | None = None
IntellicrackProtectionCore: type[IntellicrackProtectionCoreType] | None = None
ProtectionAnalysis: type[ProtectionAnalysisType] | None = None
ProtectionType: type[ProtectionTypeType] | None = None
ProtectionDetector: type[ProtectionDetectorType] | None = None
deep_analyze: Callable[[str, bool], Any] | None = None
get_protection_detector: Callable[[], Any] | None = None
quick_analyze: Callable[[str], Any] | None = None

_lazy_imports: dict[str, dict[str, Any]] = {}


def __getattr__(name: str) -> Any:
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
                logger.warning("Failed to import intellicrack_protection_core: %s", e)
                _lazy_imports["core_module"] = {
                    "DetectionResult": None,
                    "IntellicrackProtectionCore": None,
                    "ProtectionAnalysis": None,
                    "ProtectionType": None,
                }
        result: Any = _lazy_imports["core_module"].get(name)
        return result

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
                logger.warning("Failed to import protection_detector: %s", e)
                _lazy_imports["detector_module"] = {
                    "ProtectionDetector": None,
                    "deep_analyze": None,
                    "get_protection_detector": None,
                    "quick_analyze": None,
                }
        result = _lazy_imports["detector_module"].get(name)
        return result

    error_msg: str = f"module '{__name__}' has no attribute '{name}'"
    logger.error(error_msg)
    raise AttributeError(error_msg)


UnifiedProtectionEngine: type[UnifiedProtectionEngineType] | None
UnifiedProtectionResult: type[UnifiedProtectionResultType] | None
get_unified_engine: Callable[[], Any] | None

try:
    from .unified_protection_engine import (
        UnifiedProtectionEngine as UPE,
        UnifiedProtectionResult as UPR,
        get_unified_engine as gue,
    )

    UnifiedProtectionEngine = UPE
    UnifiedProtectionResult = UPR
    get_unified_engine = gue
except ImportError as e:
    logger.warning("Failed to import unified_protection_engine: %s", e)
    UnifiedProtectionEngine = None
    UnifiedProtectionResult = None
    get_unified_engine = None

ThemidaAnalysisResult: type[ThemidaAnalysisResultType] | None
ThemidaAnalyzer: type[ThemidaAnalyzerType] | None
VMArchitecture: type[VMArchitectureType] | None
ThemidaVersion: type[ThemidaVersionType] | None
VMHandler: type[VMHandlerType] | None
VMContext: type[VMContextType] | None
DevirtualizedCode: type[DevirtualizedCodeType] | None

try:
    from .themida_analyzer import (
        DevirtualizedCode as DC,
        ThemidaAnalysisResult as TAR,
        ThemidaAnalyzer as TA,
        ThemidaVersion as TV,
        VMArchitecture as VMA,
        VMContext as VMC,
        VMHandler as VMH,
    )

    ThemidaAnalysisResult = TAR
    ThemidaAnalyzer = TA
    VMArchitecture = VMA
    ThemidaVersion = TV
    VMHandler = VMH
    VMContext = VMC
    DevirtualizedCode = DC
except ImportError as e:
    logger.warning("Failed to import themida_analyzer: %s", e)
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
