"""Result types for analysis components
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
