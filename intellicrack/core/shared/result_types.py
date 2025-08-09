"""Result types for analysis components

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

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AnalysisType(Enum):
    """Types of analysis that can be performed"""

    STATIC = "static"
    DYNAMIC = "dynamic"
    ENTROPY = "entropy"
    STRUCTURE = "structure"
    VULNERABILITY = "vulnerability"
    PATTERN = "pattern"
    BINARY_INFO = "binary_info"
    MEMORY = "memory"
    NETWORK = "network"
    FIRMWARE = "firmware"


@dataclass
class AnalysisResult:
    """Result of an analysis operation"""

    success: bool
    analysis_type: AnalysisType
    data: dict[str, Any]
    errors: list[str] = None
    warnings: list[str] = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self):
        """Initialize default values for mutable fields after dataclass creation."""
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
