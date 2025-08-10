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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging

from .model_manager import ModelManager

"""
Intellicrack Models Package

This package contains data models and knowledge bases for Intellicrack.
ML models have been replaced with ICP Engine for protection detection.
"""

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
    "ModelManager",
    "SeverityLevel",
    "VulnerabilityLevel",
]

if get_protection_knowledge_base is not None:
    __all__.append("get_protection_knowledge_base")

# Log initialization

logger = logging.getLogger(__name__)
logger.info("Models package initialized - Using ICP Engine for protection detection")
