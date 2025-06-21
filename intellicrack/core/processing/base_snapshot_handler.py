"""
Base Snapshot Handler

Shared functionality for snapshot operations across different emulation/container platforms.
Eliminates duplicate code between Docker and QEMU snapshot handling.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseSnapshotHandler(ABC):
    """
    Abstract base class for snapshot handling functionality.
    Provides common snapshot comparison logic.
    """

    def __init__(self):
        self.snapshots: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger("IntellicrackLogger.SnapshotHandler")

    def compare_snapshots_base(self, snapshot1: str, snapshot2: str) -> Dict[str, Any]:
        """
        Perform base snapshot comparison that's common between platforms.

        Args:
            snapshot1: First snapshot name
            snapshot2: Second snapshot name

        Returns:
            Dictionary containing base comparison results or error
        """
        from ...utils.system.snapshot_common import start_snapshot_comparison

        success, snapshot_data, error_msg = start_snapshot_comparison(
            self.snapshots, snapshot1, snapshot2, self.logger
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
                "success": True
            }

            # Let subclasses add their specific comparison logic
            platform_specific = self._perform_platform_specific_comparison(s1, s2)
            base_comparison.update(platform_specific)

            return base_comparison

        except Exception as e:
            self.logger.error(f"Snapshot comparison failed: {e}")
            return {"error": f"Comparison failed: {str(e)}"}

    @abstractmethod
    def _perform_platform_specific_comparison(self, s1: Dict[str, Any], s2: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform platform-specific snapshot comparison logic.

        Args:
            s1: First snapshot data
            s2: Second snapshot data

        Returns:
            Dictionary containing platform-specific comparison results
        """
        pass

    def _get_current_timestamp(self) -> float:
        """Get current timestamp for comparison metadata."""
        import time
        return time.time()

    def list_snapshots(self) -> list:
        """Get list of available snapshot names."""
        return list(self.snapshots.keys())

    def get_snapshot_info(self, name: str) -> Dict[str, Any]:
        """Get detailed information about a specific snapshot."""
        if name not in self.snapshots:
            return {"error": f"Snapshot '{name}' not found"}
        return self.snapshots[name].copy()

    def has_snapshot(self, name: str) -> bool:
        """Check if a snapshot exists."""
        return name in self.snapshots


__all__ = ['BaseSnapshotHandler']
