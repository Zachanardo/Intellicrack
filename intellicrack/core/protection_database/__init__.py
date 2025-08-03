"""Protection database system for comprehensive protection scheme detection.

This module provides a comprehensive database system for detecting and analyzing
various protection schemes including packers, DRM systems, licensing schemes,
and anti-analysis patterns.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

from .database_manager import ProtectionDatabaseManager
from .pattern_engine import ProtectionPatternEngine
from .signature_database import ProtectionSignatureDatabase, ProtectionType, ArchitectureType
from .pattern_matcher import AdvancedPatternMatcher
from .database_updater import DatabaseUpdater

__all__ = [
    'ProtectionDatabaseManager',
    'ProtectionPatternEngine', 
    'ProtectionSignatureDatabase',
    'AdvancedPatternMatcher',
    'DatabaseUpdater',
    'ProtectionType',
    'ArchitectureType'
]