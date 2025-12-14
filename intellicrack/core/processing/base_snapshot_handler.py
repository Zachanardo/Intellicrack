"""Base snapshot handler for Intellicrack core processing.

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
from abc import ABC, abstractmethod
from typing import Any


"""
Base Snapshot Handler

Shared functionality for snapshot operations across different emulation/container platforms.
Eliminates duplicate code between Docker and QEMU snapshot handling.
"""


class BaseSnapshotHandler(ABC):
    """Abstract base class for snapshot handling functionality.

    Provides common snapshot comparison logic.
    """

    def __init__(self) -> None:
        """Initialize the base snapshot handler with snapshot tracking and logging setup."""
        self.snapshots: dict[str, dict[str, Any]] = {}
        self.logger = logging.getLogger("IntellicrackLogger.SnapshotHandler")
        self.max_snapshots = 10
        self.snapshot_index = 0

    def compare_snapshots_base(self, snapshot1: str, snapshot2: str) -> dict[str, Any]:
        """Perform base snapshot comparison that's common between platforms.

        Args:
            snapshot1: First snapshot name
            snapshot2: Second snapshot name

        Returns:
            Dictionary containing base comparison results or error

        """
        from ...utils.system.snapshot_common import start_snapshot_comparison

        success, snapshot_data, error_msg = start_snapshot_comparison(
            self.snapshots,
            snapshot1,
            snapshot2,
            self.logger,
        )

        if not success:
            return {"error": error_msg}

        try:
            s1 = snapshot_data["s1"]
            s2 = snapshot_data["s2"]

            # Common base comparison structure
            base_comparison = {
                "snapshot1": snapshot1,
                "snapshot2": snapshot2,
                "timestamp_diff": s2.get("timestamp", 0) - s1.get("timestamp", 0),
                "comparison_time": self._get_current_timestamp(),
                "success": True,
            }

            # Let subclasses add their specific comparison logic
            platform_specific = self._perform_platform_specific_comparison(s1, s2)
            base_comparison |= platform_specific

            return base_comparison

        except Exception as e:
            self.logger.error("Snapshot comparison failed: %s", e, exc_info=True)
            return {"error": f"Comparison failed: {e!s}"}

    @abstractmethod
    def _perform_platform_specific_comparison(self, s1: dict[str, Any], s2: dict[str, Any]) -> dict[str, Any]:
        """Perform platform-specific snapshot comparison logic.

        Args:
            s1: First snapshot data
            s2: Second snapshot data

        Returns:
            Dictionary containing platform-specific comparison results

        """

    def _get_current_timestamp(self) -> float:
        """Get current timestamp for comparison metadata."""
        import time

        return time.time()

    def list_snapshots(self) -> list:
        """Get list of available snapshot names."""
        return list(self.snapshots.keys())

    def get_snapshot_info(self, name: str) -> dict[str, Any]:
        """Get detailed information about a specific snapshot."""
        if name not in self.snapshots:
            return {"error": f"Snapshot '{name}' not found"}
        return self.snapshots[name].copy()

    def has_snapshot(self, name: str) -> bool:
        """Check if a snapshot exists."""
        return name in self.snapshots


__all__ = ["BaseSnapshotHandler"]
