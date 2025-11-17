"""Result types for analysis components.

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

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AnalysisType(Enum):
    """Types of analysis that can be performed on binaries.

    Enumeration of different analysis categories available for binary examination:
    - STATIC: Static code analysis without execution
    - DYNAMIC: Runtime behavior analysis and execution tracing
    - ENTROPY: Shannon entropy and compression analysis
    - STRUCTURE: Binary structure and PE/ELF format analysis
    - VULNERABILITY: Vulnerability detection and exploitation analysis
    - PATTERN: Signature and pattern matching analysis
    - BINARY_INFO: Metadata and version information extraction
    - MEMORY: Memory layout and section analysis
    - NETWORK: Network protocol and communication analysis
    - FIRMWARE: Firmware-specific analysis for embedded systems
    """

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
    """Result of an analysis operation.

    Represents the output of a binary analysis operation with success status,
    analysis type, data results, and optional error/warning information.

    Attributes:
        success: Whether analysis completed successfully.
        analysis_type: Type of analysis performed (static, dynamic, etc.).
        data: Dictionary containing analysis results and findings.
        errors: List of error messages encountered during analysis.
        warnings: List of warning messages from analysis.
        metadata: Optional dictionary with analysis metadata and context.

    """

    success: bool
    analysis_type: AnalysisType
    data: dict[str, Any]
    errors: list[str] | None = None
    warnings: list[str] | None = None
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        """Initialize default values for mutable fields after dataclass creation.

        Converts None default values to empty lists for errors and warnings
        to avoid mutable default issues in dataclasses.

        Raises:
            None: All operations complete successfully.

        """
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
