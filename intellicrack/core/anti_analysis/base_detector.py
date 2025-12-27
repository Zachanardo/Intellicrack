"""Base detector for Intellicrack anti-analysis components.

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
import platform
import subprocess
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable


"""
Base Detector for Anti-Analysis Modules

Shared functionality for detection implementations to eliminate code duplication.
"""


class BaseDetector(ABC):
    """Abstract base class for anti-analysis detectors.

    Provides common detection loop functionality.
    """

    def __init__(self) -> None:
        """Initialize the base detector with logging and detection methods registry."""
        self.logger = logging.getLogger("IntellicrackLogger.AntiAnalysis")
        self.detection_methods: dict[str, Callable[[], tuple[bool, float, Any]]] = {}

    def run_detection_loop(self, aggressive: bool = False, aggressive_methods: list[str] | None = None) -> dict[str, Any]:
        """Run the detection loop for all configured methods.

        Args:
            aggressive: Whether to run aggressive detection methods
            aggressive_methods: List of method names considered aggressive

        Returns:
            Detection results dictionary

        """
        if aggressive_methods is None:
            aggressive_methods = []

        results: dict[str, Any] = {
            "detections": {},
            "detection_count": 0,
            "total_confidence": 0,
            "average_confidence": 0,
        }

        detection_count: int = 0
        total_confidence: float = 0.0

        for method_name, method_func in self.detection_methods.items():
            # Skip aggressive methods if not requested
            if not aggressive and method_name in aggressive_methods:
                continue

            try:
                detected, confidence, details = method_func()
                results["detections"][method_name] = {
                    "detected": detected,
                    "confidence": confidence,
                    "details": details,
                }

                if detected:
                    detection_count += 1
                    total_confidence += confidence

            except Exception as e:
                self.logger.debug("Detection method %s failed: %s", method_name, e)

        # Calculate overall results
        results["detection_count"] = detection_count
        results["total_confidence"] = total_confidence

        if detection_count > 0:
            results["average_confidence"] = total_confidence / detection_count
        else:
            results["average_confidence"] = 0

        return results

    @abstractmethod
    def get_aggressive_methods(self) -> list[str]:
        """Get list of method names that are considered aggressive."""

    @abstractmethod
    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""

    def get_running_processes(self) -> tuple[str, list[str]]:
        """Get list of running processes based on platform.

        Returns:
            Tuple of (raw_output, process_list)

        """
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["tasklist"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis
            else:
                result = subprocess.run(["ps", "aux"], check=False, capture_output=True, text=True)  # nosec S607 - Legitimate subprocess usage for security research and binary analysis
            processes = result.stdout.lower()
            process_list: list[str] = []
            if platform.system() == "Windows":
                lines: list[str] = result.stdout.strip().split("\n")[3:]
                for line in lines:
                    if line.strip():
                        process_name: str = line.split()[0].lower()
                        process_list.append(process_name)
            else:
                lines = result.stdout.strip().split("\n")[1:]
                for line in lines:
                    if line.strip():
                        parts: list[str] = line.split()
                        if len(parts) >= 11:
                            process_name = parts[10].lower()
                            process_list.append(process_name)

            return processes, process_list

        except Exception as e:
            self.logger.debug("Error getting process list: %s", e)
            return "", []

    def calculate_detection_score(
        self,
        detections: dict[str, Any],
        strong_methods: list[str],
        medium_methods: list[str] | None = None,
    ) -> int:
        """Calculate detection score based on method difficulty.

        Args:
            detections: Dictionary of detection results
            strong_methods: Methods that score 3 points
            medium_methods: Methods that score 2 points (optional)

        Returns:
            Score capped at 10

        """
        if medium_methods is None:
            medium_methods = []

        score: int = 0
        for method, result in detections.items():
            if isinstance(result, dict) and result.get("detected"):
                if method in strong_methods:
                    score += 3
                elif method in medium_methods:
                    score += 2
                else:
                    score += 1

        return min(10, score)
