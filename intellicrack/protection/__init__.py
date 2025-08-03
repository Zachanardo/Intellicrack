"""This file is part of Intellicrack.
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
    "DIEProtectionDetector",  # Backward compatibility
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
]
