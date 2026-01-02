"""Intellicrack Models Package.

This package contains data models and knowledge bases for Intellicrack.
ML models have been replaced with ICP Engine for protection detection.

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
from collections.abc import Callable

from ..utils.severity_levels import SeverityLevel, VulnerabilityLevel
from .model_manager import ModelManager
from .protection_knowledge_base import ProtectionKnowledgeBase


logger: logging.Logger = logging.getLogger(__name__)

get_protection_knowledge_base: Callable[[], ProtectionKnowledgeBase] | None
try:
    from .protection_knowledge_base import get_protection_knowledge_base as _get_protection_knowledge_base

    get_protection_knowledge_base = _get_protection_knowledge_base
except ImportError:
    logger.exception("Import error in __init__")
    get_protection_knowledge_base = None

__all__: list[str] = [
    "ModelManager",
    "SeverityLevel",
    "VulnerabilityLevel",
]

if get_protection_knowledge_base is not None:
    __all__.append("get_protection_knowledge_base")

logger.info("Models package initialized - Using ICP Engine for protection detection")
