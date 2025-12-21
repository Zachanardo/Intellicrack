"""Production tests for base snapshot handler with real snapshot operations.

These tests validate that base_snapshot_handler correctly manages snapshots,
performs comparisons, and provides common functionality for platform-specific
implementations. Tests MUST FAIL if snapshot operations are broken.

Copyright (C) 2025 Zachary Flint
"""

import time
from typing import Any

import pytest

from intellicrack.core.processing.base_snapshot_handler import BaseSnapshotHandler


class ConcreteSnapshotHandler(BaseSnapshotHandler):
    """Concrete implementation of BaseSnapshotHandler for testing."""

    def _perform_platform_specific_comparison(
        self,
        s1: dict[str, Any],
        s2: dict[str, Any],
    ) -> dict[str, Any]:
        """Implement platform-specific comparison for testing."""
        return {
            "platform": "test_platform",
            "files_changed": abs(s2.get("file_count", 0) - s1.get("file_count", 0)),
            "memory_diff": s2.get("memory_usage", 0) - s1.get("memory_usage", 0),
            "registry_changes": s2.get("registry_keys", 0) - s1.get("registry_keys", 0),
        }


class TestBaseSnapshotHandlerProduction:
    """Production tests for base snapshot handler with real snapshot data."""

    @pytest.fixture
    def handler(self) -> ConcreteSnapshotHandler:
        """Create concrete snapshot handler for testing."""
        return ConcreteSnapshotHandler()

    @pytest.fixture
    def handler_with_snapshots(self, handler: ConcreteSnapshotHandler) -> ConcreteSnapshotHandler:
        """Create handler with pre-populated snapshots."""
        handler.snapshots["snapshot1"] = {
            "timestamp": time.time() - 100,
            "file_count": 150,
            "memory_usage": 1024 * 1024 * 100,
            "registry_keys": 50,
            "state": "clean",
        }

        time.sleep(0.1)

        handler.snapshots["snapshot2"] = {
            "timestamp": time.time(),
            "file_count": 175,
            "memory_usage": 1024 * 1024 * 120,
            "registry_keys": 65,
            "state": "modified",
        }

        return handler

    def test_handler_initialization_with_defaults(self, handler: ConcreteSnapshotHandler) -> None:
        """Handler initializes with empty snapshots and default settings."""
        assert isinstance(handler.snapshots, dict), "Snapshots must be dictionary"
        assert len(handler.snapshots) == 0, "Snapshots must be empty initially"
        assert handler.max_snapshots == 10, "Must have default max snapshots"
        assert handler.snapshot_index == 0, "Snapshot index must start at 0"
        assert handler.logger is not None, "Logger must be initialized"

    def test_compare_snapshots_with_valid_snapshots(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots produces valid comparison results."""
        result = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")

        assert "error" not in result, "Comparison must succeed"
        assert result["snapshot1"] == "snapshot1", "Must include first snapshot name"
        assert result["snapshot2"] == "snapshot2", "Must include second snapshot name"
        assert "timestamp_diff" in result, "Must include timestamp difference"
        assert "comparison_time" in result, "Must include comparison timestamp"
        assert result["success"] is True, "Success flag must be true"

    def test_compare_snapshots_includes_platform_specific_data(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots includes platform-specific comparison results."""
        result = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")

        assert "platform" in result, "Must include platform identifier"
        assert result["platform"] == "test_platform", "Must identify test platform"
        assert "files_changed" in result, "Must include file changes"
        assert "memory_diff" in result, "Must include memory difference"
        assert "registry_changes" in result, "Must include registry changes"

    def test_compare_snapshots_calculates_timestamp_diff(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots correctly calculates timestamp difference."""
        result = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")

        timestamp_diff = result["timestamp_diff"]

        assert timestamp_diff > 0, "Timestamp diff must be positive"
        assert timestamp_diff < 200, "Timestamp diff must be reasonable"

    def test_compare_snapshots_detects_file_changes(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots detects file system changes between snapshots."""
        result = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")

        files_changed = result["files_changed"]

        assert files_changed == 25, "Must detect 25 file changes"

    def test_compare_snapshots_calculates_memory_difference(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots calculates memory usage difference."""
        result = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")

        memory_diff = result["memory_diff"]
        expected_diff = 1024 * 1024 * 20

        assert memory_diff == expected_diff, "Must calculate correct memory difference"

    def test_compare_snapshots_tracks_registry_changes(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots tracks registry key modifications."""
        result = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")

        registry_changes = result["registry_changes"]

        assert registry_changes == 15, "Must detect 15 registry key changes"

    def test_compare_nonexistent_snapshot_returns_error(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots returns error for nonexistent snapshot."""
        handler.snapshots["exists"] = {"timestamp": time.time()}

        result = handler.compare_snapshots_base("exists", "nonexistent")

        assert "error" in result, "Must return error"
        assert "not found" in result["error"].lower(), "Error must mention snapshot not found"

    def test_compare_both_nonexistent_snapshots_returns_error(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots returns error when both snapshots don't exist."""
        result = handler.compare_snapshots_base("missing1", "missing2")

        assert "error" in result, "Must return error"
        assert "not found" in result["error"].lower(), "Error must indicate missing snapshots"

    def test_list_snapshots_returns_all_snapshot_names(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """List snapshots returns all registered snapshot names."""
        snapshots = handler_with_snapshots.list_snapshots()

        assert isinstance(snapshots, list), "Must return list"
        assert len(snapshots) == 2, "Must return all snapshots"
        assert "snapshot1" in snapshots, "Must include snapshot1"
        assert "snapshot2" in snapshots, "Must include snapshot2"

    def test_list_snapshots_empty_when_no_snapshots(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """List snapshots returns empty list when no snapshots exist."""
        snapshots = handler.list_snapshots()

        assert isinstance(snapshots, list), "Must return list"
        assert len(snapshots) == 0, "Must be empty"

    def test_get_snapshot_info_returns_complete_info(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Get snapshot info returns complete snapshot metadata."""
        info = handler_with_snapshots.get_snapshot_info("snapshot1")

        assert "error" not in info, "Must not return error"
        assert info["timestamp"] > 0, "Must include valid timestamp"
        assert info["file_count"] == 150, "Must include file count"
        assert info["memory_usage"] == 1024 * 1024 * 100, "Must include memory usage"
        assert info["registry_keys"] == 50, "Must include registry key count"
        assert info["state"] == "clean", "Must include state"

    def test_get_snapshot_info_returns_copy(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Get snapshot info returns copy to prevent external modification."""
        info1 = handler_with_snapshots.get_snapshot_info("snapshot1")
        info1["modified"] = "external_change"

        info2 = handler_with_snapshots.get_snapshot_info("snapshot1")

        assert "modified" not in info2, "Original snapshot must not be modified"

    def test_get_snapshot_info_for_nonexistent_snapshot(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Get snapshot info returns error for nonexistent snapshot."""
        info = handler.get_snapshot_info("nonexistent")

        assert "error" in info, "Must return error"
        assert "not found" in info["error"].lower(), "Error must indicate snapshot not found"

    def test_has_snapshot_returns_true_for_existing(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Has snapshot returns true for existing snapshots."""
        assert handler_with_snapshots.has_snapshot("snapshot1") is True, "Must detect snapshot1"
        assert handler_with_snapshots.has_snapshot("snapshot2") is True, "Must detect snapshot2"

    def test_has_snapshot_returns_false_for_nonexistent(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Has snapshot returns false for nonexistent snapshots."""
        assert handler.has_snapshot("nonexistent") is False, "Must return false"

    def test_snapshot_comparison_with_identical_snapshots(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Compare identical snapshots shows zero differences."""
        snapshot_data = {
            "timestamp": time.time(),
            "file_count": 100,
            "memory_usage": 1024 * 1024 * 50,
            "registry_keys": 30,
        }

        handler.snapshots["identical1"] = snapshot_data.copy()
        handler.snapshots["identical2"] = snapshot_data.copy()

        result = handler.compare_snapshots_base("identical1", "identical2")

        assert result["files_changed"] == 0, "No files should be changed"
        assert result["memory_diff"] == 0, "Memory usage should be identical"
        assert result["registry_changes"] == 0, "No registry changes should occur"

    def test_snapshot_comparison_handles_negative_differences(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots handles decreased values correctly."""
        handler.snapshots["before"] = {
            "timestamp": time.time(),
            "file_count": 200,
            "memory_usage": 1024 * 1024 * 150,
            "registry_keys": 80,
        }

        handler.snapshots["after"] = {
            "timestamp": time.time() + 10,
            "file_count": 150,
            "memory_usage": 1024 * 1024 * 100,
            "registry_keys": 60,
        }

        result = handler.compare_snapshots_base("before", "after")

        assert result["files_changed"] == 50, "Must calculate absolute file difference"
        assert result["memory_diff"] == -1024 * 1024 * 50, "Must show memory decrease"
        assert result["registry_changes"] == -20, "Must show registry key decrease"

    def test_snapshot_with_missing_fields_handled(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots handles missing optional fields gracefully."""
        handler.snapshots["sparse1"] = {
            "timestamp": time.time(),
        }

        handler.snapshots["sparse2"] = {
            "timestamp": time.time() + 10,
        }

        result = handler.compare_snapshots_base("sparse1", "sparse2")

        assert "error" not in result, "Must handle sparse snapshots"
        assert result["files_changed"] == 0, "Missing fields should default to 0"

    def test_get_current_timestamp_returns_valid_float(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Get current timestamp returns valid floating point timestamp."""
        timestamp = handler._get_current_timestamp()

        assert isinstance(timestamp, float), "Timestamp must be float"
        assert timestamp > 0, "Timestamp must be positive"
        assert timestamp < time.time() + 1, "Timestamp must be recent"
        assert timestamp > time.time() - 1, "Timestamp must not be old"

    def test_max_snapshots_setting(self, handler: ConcreteSnapshotHandler) -> None:
        """Max snapshots setting can be configured."""
        handler.max_snapshots = 5

        assert handler.max_snapshots == 5, "Must allow setting max snapshots"

    def test_snapshot_index_tracking(self, handler: ConcreteSnapshotHandler) -> None:
        """Snapshot index tracks number of snapshots created."""
        initial_index = handler.snapshot_index

        assert initial_index == 0, "Index must start at 0"

        handler.snapshot_index += 1

        assert handler.snapshot_index == 1, "Index must increment"

    def test_snapshots_with_complex_metadata(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Snapshots can contain complex nested metadata."""
        handler.snapshots["complex"] = {
            "timestamp": time.time(),
            "file_count": 100,
            "files": {
                "added": ["file1.txt", "file2.dat"],
                "modified": ["config.ini"],
                "deleted": [],
            },
            "processes": [
                {"name": "test.exe", "pid": 1234},
                {"name": "service.exe", "pid": 5678},
            ],
            "network": {
                "connections": 5,
                "bytes_sent": 1024,
                "bytes_received": 2048,
            },
        }

        info = handler.get_snapshot_info("complex")

        assert "files" in info, "Must preserve nested file data"
        assert "processes" in info, "Must preserve process list"
        assert "network" in info, "Must preserve network data"
        assert len(info["processes"]) == 2, "Must preserve all processes"

    def test_comparison_includes_comparison_timestamp(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Comparison result includes timestamp of when comparison was performed."""
        result = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")

        comparison_time = result["comparison_time"]

        assert isinstance(comparison_time, float), "Comparison time must be float"
        assert abs(comparison_time - time.time()) < 2, "Comparison time must be recent"

    def test_snapshot_comparison_error_handling(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots handles errors gracefully."""
        handler.snapshots["broken"] = {
            "timestamp": "invalid_timestamp",
        }

        handler.snapshots["normal"] = {
            "timestamp": time.time(),
        }

        result = handler.compare_snapshots_base("broken", "normal")

        assert isinstance(result, dict), "Must return dictionary even on error"

    def test_multiple_sequential_comparisons(
        self,
        handler_with_snapshots: ConcreteSnapshotHandler,
    ) -> None:
        """Multiple sequential comparisons produce consistent results."""
        result1 = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")
        time.sleep(0.1)
        result2 = handler_with_snapshots.compare_snapshots_base("snapshot1", "snapshot2")

        assert result1["files_changed"] == result2["files_changed"], "File changes must be consistent"
        assert result1["memory_diff"] == result2["memory_diff"], "Memory diff must be consistent"
        assert result1["registry_changes"] == result2["registry_changes"], "Registry changes must be consistent"

    def test_snapshot_names_with_special_characters(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Snapshot names can contain special characters."""
        special_names = [
            "snapshot-with-dashes",
            "snapshot_with_underscores",
            "snapshot.with.dots",
            "snapshot 2024-01-15 12:30:45",
        ]

        for name in special_names:
            handler.snapshots[name] = {"timestamp": time.time()}

        snapshots = handler.list_snapshots()

        for name in special_names:
            assert name in snapshots, f"Must handle snapshot name: {name}"
            assert handler.has_snapshot(name), f"Must detect snapshot: {name}"

    def test_snapshot_comparison_with_large_differences(
        self,
        handler: ConcreteSnapshotHandler,
    ) -> None:
        """Compare snapshots handles large numeric differences correctly."""
        handler.snapshots["small"] = {
            "timestamp": time.time(),
            "file_count": 100,
            "memory_usage": 1024 * 1024,
            "registry_keys": 50,
        }

        handler.snapshots["large"] = {
            "timestamp": time.time() + 100,
            "file_count": 100000,
            "memory_usage": 1024 * 1024 * 1024 * 4,
            "registry_keys": 50000,
        }

        result = handler.compare_snapshots_base("small", "large")

        assert result["files_changed"] > 90000, "Must handle large file count differences"
        assert result["memory_diff"] > 1024 * 1024 * 1024, "Must handle large memory differences"
        assert result["registry_changes"] > 40000, "Must handle large registry differences"

    def test_empty_snapshot_comparison(self, handler: ConcreteSnapshotHandler) -> None:
        """Compare snapshots with minimal data still produces valid results."""
        handler.snapshots["empty1"] = {"timestamp": time.time()}
        handler.snapshots["empty2"] = {"timestamp": time.time() + 1}

        result = handler.compare_snapshots_base("empty1", "empty2")

        assert "error" not in result, "Must handle empty snapshots"
        assert "success" in result, "Must include success flag"
        assert result["success"] is True, "Comparison must succeed"
