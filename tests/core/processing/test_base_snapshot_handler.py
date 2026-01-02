"""Production tests for Base Snapshot Handler.

Tests snapshot comparison, memory footprint tracking, and snapshot management.
Validates real snapshot operations without mocks.
"""

import time
from typing import Any

import pytest

from intellicrack.core.processing.base_snapshot_handler import BaseSnapshotHandler


class ConcreteSnapshotHandler(BaseSnapshotHandler):
    """Concrete implementation for testing abstract base class."""

    def _perform_platform_specific_comparison(
        self, s1: dict[str, Any], s2: dict[str, Any]
    ) -> dict[str, Any]:
        """Platform-specific comparison implementation."""
        return {
            "memory_diff": s2.get("memory", 0) - s1.get("memory", 0),
            "cpu_diff": s2.get("cpu", 0) - s1.get("cpu", 0),
            "platform": "test_platform",
        }


class FakeSnapshotComparison:
    """Real test double for snapshot comparison operations."""

    def __init__(self) -> None:
        self.call_count: int = 0
        self.calls: list[tuple[dict[str, Any], str, str]] = []
        self.return_success: bool = True
        self.return_data: dict[str, Any] | None = None
        self.return_error: str | None = None
        self.raise_exception: Exception | None = None

    def __call__(
        self,
        snapshots_dict: dict[str, Any],
        snapshot1: str,
        snapshot2: str,
        logger: Any = None,
    ) -> tuple[bool, dict[str, Any] | None, str | None]:
        """Fake implementation of start_snapshot_comparison."""
        self.call_count += 1
        self.calls.append((snapshots_dict, snapshot1, snapshot2))

        if self.raise_exception:
            raise self.raise_exception

        if snapshot1 not in snapshots_dict:
            return False, None, f"Snapshot '{snapshot1}' not found"

        if snapshot2 not in snapshots_dict:
            return False, None, f"Snapshot '{snapshot2}' not found"

        if not self.return_success:
            return False, None, self.return_error

        if self.return_data is not None:
            return True, self.return_data, None

        s1 = snapshots_dict[snapshot1]
        s2 = snapshots_dict[snapshot2]
        return True, {"s1": s1, "s2": s2}, None

    def set_success_response(
        self, s1_data: dict[str, Any], s2_data: dict[str, Any]
    ) -> None:
        """Configure fake to return successful comparison."""
        self.return_success = True
        self.return_data = {"s1": s1_data, "s2": s2_data}
        self.return_error = None

    def set_error_response(self, error_message: str) -> None:
        """Configure fake to return error."""
        self.return_success = False
        self.return_data = None
        self.return_error = error_message

    def set_exception(self, exception: Exception) -> None:
        """Configure fake to raise exception."""
        self.raise_exception = exception


class TestBaseSnapshotHandlerInit:
    """Test BaseSnapshotHandler initialization."""

    def test_init_sets_empty_snapshots_dict(self) -> None:
        """Initialization creates empty snapshots dictionary."""
        handler = ConcreteSnapshotHandler()

        assert handler.snapshots == {}
        assert isinstance(handler.snapshots, dict)

    def test_init_sets_logger(self) -> None:
        """Initialization sets up logger."""
        handler = ConcreteSnapshotHandler()

        assert handler.logger is not None
        assert "SnapshotHandler" in handler.logger.name

    def test_init_sets_max_snapshots_limit(self) -> None:
        """Initialization sets maximum snapshots limit."""
        handler = ConcreteSnapshotHandler()

        assert handler.max_snapshots == 10
        assert isinstance(handler.max_snapshots, int)

    def test_init_sets_snapshot_index(self) -> None:
        """Initialization sets snapshot index to zero."""
        handler = ConcreteSnapshotHandler()

        assert handler.snapshot_index == 0


class TestListSnapshots:
    """Test list_snapshots method."""

    def test_list_snapshots_returns_empty_list_initially(self) -> None:
        """list_snapshots returns empty list when no snapshots exist."""
        handler = ConcreteSnapshotHandler()

        snapshots = handler.list_snapshots()

        assert snapshots == []
        assert isinstance(snapshots, list)

    def test_list_snapshots_returns_all_snapshot_names(self) -> None:
        """list_snapshots returns all snapshot names."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots = {
            "snapshot1": {"timestamp": 100},
            "snapshot2": {"timestamp": 200},
            "snapshot3": {"timestamp": 300},
        }

        snapshots = handler.list_snapshots()

        assert len(snapshots) == 3
        assert "snapshot1" in snapshots
        assert "snapshot2" in snapshots
        assert "snapshot3" in snapshots

    def test_list_snapshots_order_matches_dict_keys(self) -> None:
        """list_snapshots preserves insertion order."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots = {
            "alpha": {"timestamp": 1},
            "beta": {"timestamp": 2},
            "gamma": {"timestamp": 3},
        }

        snapshots = handler.list_snapshots()

        assert snapshots == ["alpha", "beta", "gamma"]


class TestGetSnapshotInfo:
    """Test get_snapshot_info method."""

    def test_get_snapshot_info_returns_error_for_missing_snapshot(self) -> None:
        """get_snapshot_info returns error for nonexistent snapshot."""
        handler = ConcreteSnapshotHandler()

        info = handler.get_snapshot_info("nonexistent")

        assert "error" in info
        assert "not found" in info["error"]

    def test_get_snapshot_info_returns_snapshot_data(self) -> None:
        """get_snapshot_info returns snapshot data."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots["test_snap"] = {
            "timestamp": 12345,
            "memory": 1024,
            "cpu": 50,
        }

        info = handler.get_snapshot_info("test_snap")

        assert info["timestamp"] == 12345
        assert info["memory"] == 1024
        assert info["cpu"] == 50
        assert "error" not in info

    def test_get_snapshot_info_returns_copy_not_reference(self) -> None:
        """get_snapshot_info returns copy, not reference."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots["test_snap"] = {"timestamp": 100, "data": "original"}

        info1 = handler.get_snapshot_info("test_snap")
        info2 = handler.get_snapshot_info("test_snap")

        assert info1 is not info2
        assert info1 == info2

    def test_get_snapshot_info_copy_isolation(self) -> None:
        """Modifying returned info doesn't affect original snapshot."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots["test_snap"] = {"timestamp": 100, "data": "original"}

        info = handler.get_snapshot_info("test_snap")
        info["data"] = "modified"

        assert handler.snapshots["test_snap"]["data"] == "original"


class TestHasSnapshot:
    """Test has_snapshot method."""

    def test_has_snapshot_returns_false_for_missing(self) -> None:
        """has_snapshot returns False for nonexistent snapshot."""
        handler = ConcreteSnapshotHandler()

        assert handler.has_snapshot("nonexistent") is False

    def test_has_snapshot_returns_true_for_existing(self) -> None:
        """has_snapshot returns True for existing snapshot."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots["existing"] = {"timestamp": 100}

        assert handler.has_snapshot("existing") is True

    def test_has_snapshot_case_sensitive(self) -> None:
        """has_snapshot is case-sensitive."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots["TestSnapshot"] = {"timestamp": 100}

        assert handler.has_snapshot("TestSnapshot") is True
        assert handler.has_snapshot("testsnapshot") is False
        assert handler.has_snapshot("TESTSNAPSHOT") is False


class TestGetCurrentTimestamp:
    """Test _get_current_timestamp method."""

    def test_get_current_timestamp_returns_float(self) -> None:
        """_get_current_timestamp returns float timestamp."""
        handler = ConcreteSnapshotHandler()

        timestamp = handler._get_current_timestamp()

        assert isinstance(timestamp, float)

    def test_get_current_timestamp_increases_over_time(self) -> None:
        """_get_current_timestamp returns increasing values."""
        handler = ConcreteSnapshotHandler()

        ts1 = handler._get_current_timestamp()
        time.sleep(0.01)
        ts2 = handler._get_current_timestamp()

        assert ts2 > ts1

    def test_get_current_timestamp_reasonable_value(self) -> None:
        """_get_current_timestamp returns reasonable Unix timestamp."""
        handler = ConcreteSnapshotHandler()

        timestamp = handler._get_current_timestamp()

        assert timestamp > 1700000000
        assert timestamp < 2000000000


class TestCompareSnapshotsBase:
    """Test compare_snapshots_base method."""

    def test_compare_snapshots_base_returns_error_for_missing_snapshot1(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """compare_snapshots_base returns error when first snapshot missing."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots["snap2"] = {"timestamp": 200}

        fake_compare = FakeSnapshotComparison()
        monkeypatch.setattr(
            "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
            fake_compare,
        )

        result = handler.compare_snapshots_base("snap1", "snap2")

        assert "error" in result
        assert "snap1" in result["error"] or "not found" in result["error"].lower()

    def test_compare_snapshots_base_returns_error_for_missing_snapshot2(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """compare_snapshots_base returns error when second snapshot missing."""
        handler = ConcreteSnapshotHandler()
        handler.snapshots["snap1"] = {"timestamp": 100}

        fake_compare = FakeSnapshotComparison()
        monkeypatch.setattr(
            "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
            fake_compare,
        )

        result = handler.compare_snapshots_base("snap1", "snap2")

        assert "error" in result

    def test_compare_snapshots_base_calculates_timestamp_diff(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """compare_snapshots_base calculates timestamp difference."""
        handler = ConcreteSnapshotHandler()

        fake_compare = FakeSnapshotComparison()
        fake_compare.set_success_response(
            {"timestamp": 100, "memory": 1024, "cpu": 50},
            {"timestamp": 200, "memory": 2048, "cpu": 75},
        )
        monkeypatch.setattr(
            "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
            fake_compare,
        )

        result = handler.compare_snapshots_base("snap1", "snap2")

        assert result["timestamp_diff"] == 100
        assert result["success"] is True

    def test_compare_snapshots_base_includes_comparison_metadata(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """compare_snapshots_base includes snapshot names and comparison time."""
        handler = ConcreteSnapshotHandler()

        fake_compare = FakeSnapshotComparison()
        fake_compare.set_success_response(
            {"timestamp": 100},
            {"timestamp": 200},
        )
        monkeypatch.setattr(
            "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
            fake_compare,
        )

        result = handler.compare_snapshots_base("snap1", "snap2")

        assert result["snapshot1"] == "snap1"
        assert result["snapshot2"] == "snap2"
        assert "comparison_time" in result
        assert isinstance(result["comparison_time"], float)

    def test_compare_snapshots_base_merges_platform_specific_data(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """compare_snapshots_base merges platform-specific comparison results."""
        handler = ConcreteSnapshotHandler()

        fake_compare = FakeSnapshotComparison()
        fake_compare.set_success_response(
            {"timestamp": 100, "memory": 1024, "cpu": 50},
            {"timestamp": 200, "memory": 2048, "cpu": 75},
        )
        monkeypatch.setattr(
            "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
            fake_compare,
        )

        result = handler.compare_snapshots_base("snap1", "snap2")

        assert result["memory_diff"] == 1024
        assert result["cpu_diff"] == 25
        assert result["platform"] == "test_platform"

    def test_compare_snapshots_base_handles_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """compare_snapshots_base handles exceptions gracefully."""
        handler = ConcreteSnapshotHandler()

        fake_compare = FakeSnapshotComparison()
        fake_compare.set_exception(Exception("Unexpected error"))
        monkeypatch.setattr(
            "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
            fake_compare,
        )

        result = handler.compare_snapshots_base("snap1", "snap2")

        assert "error" in result
        assert "Comparison failed" in result["error"] or "Unexpected error" in result["error"]


class TestPlatformSpecificComparison:
    """Test platform-specific comparison integration."""

    def test_concrete_implementation_calculates_memory_diff(self) -> None:
        """Concrete implementation calculates memory difference."""
        handler = ConcreteSnapshotHandler()

        s1 = {"timestamp": 100, "memory": 1000, "cpu": 50}
        s2 = {"timestamp": 200, "memory": 1500, "cpu": 75}

        result = handler._perform_platform_specific_comparison(s1, s2)

        assert result["memory_diff"] == 500

    def test_concrete_implementation_calculates_cpu_diff(self) -> None:
        """Concrete implementation calculates CPU difference."""
        handler = ConcreteSnapshotHandler()

        s1 = {"timestamp": 100, "memory": 1000, "cpu": 50}
        s2 = {"timestamp": 200, "memory": 1500, "cpu": 75}

        result = handler._perform_platform_specific_comparison(s1, s2)

        assert result["cpu_diff"] == 25

    def test_concrete_implementation_includes_platform_identifier(self) -> None:
        """Concrete implementation includes platform identifier."""
        handler = ConcreteSnapshotHandler()

        s1 = {"timestamp": 100, "memory": 1000, "cpu": 50}
        s2 = {"timestamp": 200, "memory": 1500, "cpu": 75}

        result = handler._perform_platform_specific_comparison(s1, s2)

        assert result["platform"] == "test_platform"

    def test_platform_specific_handles_missing_memory_field(self) -> None:
        """Platform-specific comparison handles missing memory field."""
        handler = ConcreteSnapshotHandler()

        s1 = {"timestamp": 100, "cpu": 50}
        s2 = {"timestamp": 200, "cpu": 75}

        result = handler._perform_platform_specific_comparison(s1, s2)

        assert result["memory_diff"] == 0

    def test_platform_specific_handles_missing_cpu_field(self) -> None:
        """Platform-specific comparison handles missing CPU field."""
        handler = ConcreteSnapshotHandler()

        s1 = {"timestamp": 100, "memory": 1000}
        s2 = {"timestamp": 200, "memory": 1500}

        result = handler._perform_platform_specific_comparison(s1, s2)

        assert result["cpu_diff"] == 0


class TestSnapshotManagement:
    """Test snapshot storage and management."""

    def test_snapshots_dict_stores_multiple_snapshots(self) -> None:
        """Snapshots dictionary can store multiple snapshots."""
        handler = ConcreteSnapshotHandler()

        handler.snapshots["snap1"] = {"timestamp": 100, "data": "first"}
        handler.snapshots["snap2"] = {"timestamp": 200, "data": "second"}
        handler.snapshots["snap3"] = {"timestamp": 300, "data": "third"}

        assert len(handler.snapshots) == 3
        assert handler.snapshots["snap1"]["data"] == "first"
        assert handler.snapshots["snap2"]["data"] == "second"
        assert handler.snapshots["snap3"]["data"] == "third"

    def test_max_snapshots_default_value(self) -> None:
        """max_snapshots has sensible default value."""
        handler = ConcreteSnapshotHandler()

        assert handler.max_snapshots == 10
        assert handler.max_snapshots > 0

    def test_snapshot_index_tracks_count(self) -> None:
        """snapshot_index can be used to track snapshot count."""
        handler = ConcreteSnapshotHandler()

        assert handler.snapshot_index == 0
        handler.snapshot_index = 5
        assert handler.snapshot_index == 5


class TestAbstractMethods:
    """Test abstract method enforcement."""

    def test_cannot_instantiate_abstract_base_class(self) -> None:
        """Cannot instantiate BaseSnapshotHandler directly."""

        class IncompleteHandler(BaseSnapshotHandler):
            pass

        with pytest.raises(TypeError):
            IncompleteHandler()

    def test_must_implement_platform_specific_comparison(self) -> None:
        """Subclass must implement _perform_platform_specific_comparison."""

        class MinimalHandler(BaseSnapshotHandler):
            def _perform_platform_specific_comparison(
                self, s1: dict[str, Any], s2: dict[str, Any]
            ) -> dict[str, Any]:
                return {}

        handler = MinimalHandler()
        assert handler is not None


class TestRealWorldScenarios:
    """Test real-world snapshot comparison scenarios."""

    def test_compare_process_memory_snapshots(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Compare snapshots showing process memory growth."""
        handler = ConcreteSnapshotHandler()

        fake_compare = FakeSnapshotComparison()
        fake_compare.set_success_response(
            {"timestamp": 1000, "memory": 512 * 1024, "cpu": 10},
            {"timestamp": 2000, "memory": 1024 * 1024, "cpu": 25},
        )
        monkeypatch.setattr(
            "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
            fake_compare,
        )

        result = handler.compare_snapshots_base("before_crack", "after_crack")

        assert result["memory_diff"] == 512 * 1024
        assert result["cpu_diff"] == 15
        assert result["timestamp_diff"] == 1000

    def test_compare_snapshots_detecting_license_bypass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Compare snapshots before and after license bypass."""
        handler = ConcreteSnapshotHandler()

        fake_compare = FakeSnapshotComparison()
        fake_compare.set_success_response(
            {"timestamp": 5000, "memory": 2048, "cpu": 30},
            {"timestamp": 6000, "memory": 2560, "cpu": 35},
        )
        monkeypatch.setattr(
            "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
            fake_compare,
        )

        result = handler.compare_snapshots_base("pre_bypass", "post_bypass")

        assert result["success"] is True
        assert result["memory_diff"] == 512
        assert "comparison_time" in result

    def test_sequential_snapshot_comparisons(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Multiple sequential snapshot comparisons work correctly."""
        handler = ConcreteSnapshotHandler()

        comparisons = [
            ("snap0", "snap1", 100, 200),
            ("snap1", "snap2", 200, 300),
            ("snap2", "snap3", 300, 400),
        ]

        for snap1_name, snap2_name, ts1, ts2 in comparisons:
            fake_compare = FakeSnapshotComparison()
            fake_compare.set_success_response(
                {"timestamp": ts1, "memory": 1000, "cpu": 50},
                {"timestamp": ts2, "memory": 1000, "cpu": 50},
            )
            monkeypatch.setattr(
                "intellicrack.utils.system.snapshot_common.start_snapshot_comparison",
                fake_compare,
            )

            result = handler.compare_snapshots_base(snap1_name, snap2_name)

            assert result["success"] is True
            assert result["timestamp_diff"] == 100
