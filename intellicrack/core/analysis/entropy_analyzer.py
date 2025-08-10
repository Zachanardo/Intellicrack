"""Entropy analysis module for detecting packed and encrypted binary sections.

This module provides entropy calculation and analysis capabilities to identify
potentially packed, encrypted, or obfuscated sections within binary files,
supporting security research and license protection analysis workflows.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import math
from pathlib import Path
from typing import Any


class EntropyAnalyzer:
    """Entropy analysis engine for binary data examination."""

    def __init__(self):
        """Initialize the entropy analyzer."""
        self.logger = logging.getLogger(__name__)
        self.high_entropy_threshold = 7.0
        self.medium_entropy_threshold = 5.0

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data.

        Args:
            data: Binary data to analyze

        Returns:
            Entropy value (0.0 to 8.0)

        """
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def analyze_entropy(self, binary_path: str | Path) -> dict[str, Any]:
        """Analyze entropy characteristics of a binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Entropy analysis results

        """
        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            overall_entropy = self.calculate_entropy(data)

            return {
                "overall_entropy": overall_entropy,
                "file_size": len(data),
                "entropy_classification": self._classify_entropy(overall_entropy),
                "analysis_status": "completed",
            }
        except Exception as e:
            self.logger.error("Entropy analysis failed: %s", e)
            return {"error": str(e)}

    def _classify_entropy(self, entropy: float) -> str:
        """Classify entropy level."""
        if entropy >= self.high_entropy_threshold:
            return "high"
        if entropy >= self.medium_entropy_threshold:
            return "medium"
        return "low"
