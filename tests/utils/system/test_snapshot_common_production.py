"""Production tests for snapshot_common.py.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import logging
from typing import Any

import pytest

from intellicrack.utils.system.snapshot_common import (
    compare_file_lists,
    get_snapshot_data,
    log_comparison_start,
    start_snapshot_comparison,
    validate_snapshots,
)


class TestValidateSnapshots:
    """Test snapshot validation functionality."""

    def test_validate_snapshots_both_exist(self) -> None:
        """Validation succeeds when both snapshots exist."""
        snapshots: dict[str, Any] = {
            "snap1": {"data": "test1"},
            "snap2": {"data": "test2"},
        }

        is_valid, error = validate_snapshots(snapshots, "snap1", "snap2")

        assert is_valid is True
        assert error is None

    def test_validate_snapshots_first_missing(self) -> None:
        """Validation fails when first snapshot missing."""
        snapshots: dict[str, Any] = {"snap2": {"data": "test2"}}

        is_valid, error = validate_snapshots(snapshots, "snap1", "snap2")

        assert is_valid is False
        assert error is not None
        assert "snap1" in error

    def test_validate_snapshots_second_missing(self) -> None:
        """Validation fails when second snapshot missing."""
        snapshots: dict[str, Any] = {"snap1": {"data": "test1"}}

        is_valid, error = validate_snapshots(snapshots, "snap1", "snap2")

        assert is_valid is False
        assert error is not None
        assert "snap2" in error

    def test_validate_snapshots_both_missing(self) -> None:
        """Validation fails when both snapshots missing."""
        snapshots: dict[str, Any] = {}

        is_valid, error = validate_snapshots(snapshots, "snap1", "snap2")

        assert is_valid is False
        assert error is not None

    def test_validate_snapshots_with_logger(self, caplog: pytest.LogCaptureFixture) -> None:
        """Validation logs errors when logger provided."""
        snapshots: dict[str, Any] = {}
        logger: logging.Logger = logging.getLogger("test")

        with caplog.at_level(logging.ERROR):
            validate_snapshots(snapshots, "snap1", "snap2", logger=logger)

        assert len(caplog.records) > 0


class TestLogComparisonStart:
    """Test comparison logging functionality."""

    def test_log_comparison_start_with_logger(self, caplog: pytest.LogCaptureFixture) -> None:
        """Comparison start is logged when logger provided."""
        logger: logging.Logger = logging.getLogger("test")

        with caplog.at_level(logging.INFO):
            log_comparison_start("snap1", "snap2", logger=logger)

        assert any("snap1" in record.message and "snap2" in record.message for record in caplog.records)

    def test_log_comparison_start_without_logger(self) -> None:
        """Logging without logger doesn't raise exception."""
        log_comparison_start("snap1", "snap2", logger=None)


class TestStartSnapshotComparison:
    """Test snapshot comparison initialization."""

    def test_start_snapshot_comparison_success(self) -> None:
        """Comparison starts successfully with valid snapshots."""
        snapshots: dict[str, Any] = {
            "before": {"files": ["file1.txt"], "processes": [100]},
            "after": {"files": ["file1.txt", "file2.txt"], "processes": [100, 200]},
        }

        success, data, error = start_snapshot_comparison(snapshots, "before", "after")

        assert success is True
        assert data is not None
        assert "s1" in data
        assert "s2" in data
        assert error is None

    def test_start_snapshot_comparison_returns_correct_snapshots(self) -> None:
        """Comparison returns correct snapshot data."""
        snapshots: dict[str, Any] = {
            "snap1": {"data": "first"},
            "snap2": {"data": "second"},
        }

        success, data, error = start_snapshot_comparison(snapshots, "snap1", "snap2")

        assert success is True
        assert data["s1"]["data"] == "first"
        assert data["s2"]["data"] == "second"

    def test_start_snapshot_comparison_missing_snapshot(self) -> None:
        """Comparison fails with missing snapshot."""
        snapshots: dict[str, Any] = {"snap1": {"data": "test"}}

        success, data, error = start_snapshot_comparison(snapshots, "snap1", "snap2")

        assert success is False
        assert data is None
        assert error is not None
        assert "snap2" in error

    def test_start_snapshot_comparison_with_logger(self, caplog: pytest.LogCaptureFixture) -> None:
        """Comparison logs with provided logger."""
        snapshots: dict[str, Any] = {
            "snap1": {"data": "test1"},
            "snap2": {"data": "test2"},
        }
        logger: logging.Logger = logging.getLogger("test")

        with caplog.at_level(logging.INFO):
            start_snapshot_comparison(snapshots, "snap1", "snap2", logger=logger)

        assert len(caplog.records) > 0


class TestGetSnapshotData:
    """Test snapshot data retrieval."""

    def test_get_snapshot_data_existing_snapshot(self) -> None:
        """Retrieves data for existing snapshot."""
        snapshots: dict[str, Any] = {
            "snap1": {"files": ["file1"], "processes": [100]},
        }

        data: dict[str, Any] = get_snapshot_data(snapshots, "snap1")

        assert data == {"files": ["file1"], "processes": [100]}

    def test_get_snapshot_data_missing_snapshot(self) -> None:
        """Returns empty dict for missing snapshot."""
        snapshots: dict[str, Any] = {}

        data: dict[str, Any] = get_snapshot_data(snapshots, "nonexistent")

        assert data == {}

    def test_get_snapshot_data_preserves_snapshot_structure(self) -> None:
        """Retrieved data preserves original structure."""
        snapshots: dict[str, Any] = {
            "snap1": {
                "nested": {"key1": "value1", "key2": [1, 2, 3]},
                "list": [10, 20, 30],
            },
        }

        data: dict[str, Any] = get_snapshot_data(snapshots, "snap1")

        assert data["nested"]["key1"] == "value1"
        assert data["nested"]["key2"] == [1, 2, 3]
        assert data["list"] == [10, 20, 30]


class TestCompareFileLists:
    """Test file list comparison functionality."""

    def test_compare_file_lists_detects_new_files(self) -> None:
        """Comparison detects newly added files."""
        files1: str = "file1.txt\nfile2.txt"
        files2: str = "file1.txt\nfile2.txt\nfile3.txt"

        result: dict[str, list[str]] = compare_file_lists(files1, files2)

        assert "file3.txt" in result["new_files"]

    def test_compare_file_lists_detects_deleted_files(self) -> None:
        """Comparison detects deleted files."""
        files1: str = "file1.txt\nfile2.txt\nfile3.txt"
        files2: str = "file1.txt\nfile2.txt"

        result: dict[str, list[str]] = compare_file_lists(files1, files2)

        assert "file3.txt" in result["deleted_files"]

    def test_compare_file_lists_identifies_modified_files(self) -> None:
        """Comparison identifies files present in both snapshots."""
        files1: str = "file1.txt\nfile2.txt"
        files2: str = "file1.txt\nfile2.txt\nfile3.txt"

        result: dict[str, list[str]] = compare_file_lists(files1, files2)

        assert "file1.txt" in result["modified_files"]
        assert "file2.txt" in result["modified_files"]

    def test_compare_file_lists_empty_snapshots(self) -> None:
        """Comparison handles empty file lists."""
        result: dict[str, list[str]] = compare_file_lists(None, None)

        assert result["new_files"] == []
        assert result["deleted_files"] == []
        assert result["modified_files"] == []

    def test_compare_file_lists_respects_limit(self) -> None:
        """Comparison respects limit parameter."""
        files1: str = "file1.txt\nfile2.txt\nfile3.txt"
        files2: str = "\n".join([f"file{i}.txt" for i in range(1, 101)])

        result: dict[str, list[str]] = compare_file_lists(files1, files2, limit=10)

        assert len(result["new_files"]) <= 10
        assert len(result["deleted_files"]) <= 10
        assert len(result["modified_files"]) <= 10

    def test_compare_file_lists_no_changes(self) -> None:
        """Comparison detects when file lists are identical."""
        files: str = "file1.txt\nfile2.txt\nfile3.txt"

        result: dict[str, list[str]] = compare_file_lists(files, files)

        assert len(result["new_files"]) == 0
        assert len(result["deleted_files"]) == 0
        assert len(result["modified_files"]) == 3

    def test_compare_file_lists_all_new_files(self) -> None:
        """Comparison detects all new files scenario."""
        files1: str = ""
        files2: str = "file1.txt\nfile2.txt\nfile3.txt"

        result: dict[str, list[str]] = compare_file_lists(files1, files2)

        assert len(result["new_files"]) == 3
        assert len(result["deleted_files"]) == 0

    def test_compare_file_lists_all_deleted_files(self) -> None:
        """Comparison detects all deleted files scenario."""
        files1: str = "file1.txt\nfile2.txt\nfile3.txt"
        files2: str = ""

        result: dict[str, list[str]] = compare_file_lists(files1, files2)

        assert len(result["new_files"]) == 0
        assert len(result["deleted_files"]) == 3


class TestSnapshotCommonIntegration:
    """Integration tests for snapshot common utilities."""

    def test_full_snapshot_comparison_workflow(self) -> None:
        """Complete snapshot comparison workflow works."""
        snapshots: dict[str, Any] = {
            "before": {"files": "file1.txt\nfile2.txt", "registry": {"key1": "val1"}},
            "after": {"files": "file1.txt\nfile2.txt\nfile3.txt", "registry": {"key1": "val2"}},
        }

        is_valid, error = validate_snapshots(snapshots, "before", "after")
        assert is_valid is True

        success, data, error = start_snapshot_comparison(snapshots, "before", "after")
        assert success is True

        file_changes: dict[str, list[str]] = compare_file_lists(
            data["s1"]["files"],
            data["s2"]["files"]
        )
        assert "file3.txt" in file_changes["new_files"]

    def test_snapshot_utilities_handle_complex_data(self) -> None:
        """Snapshot utilities handle complex nested data structures."""
        snapshots: dict[str, Any] = {
            "snap1": {
                "files": {"directory1": ["file1", "file2"], "directory2": ["file3"]},
                "registry": {"hklm": {"key1": "value1"}},
                "processes": [{"pid": 100, "name": "proc1"}],
            },
            "snap2": {
                "files": {"directory1": ["file1", "file2", "file4"], "directory2": []},
                "registry": {"hklm": {"key1": "value2"}},
                "processes": [{"pid": 200, "name": "proc2"}],
            },
        }

        success, data, error = start_snapshot_comparison(snapshots, "snap1", "snap2")

        assert success is True
        assert data["s1"]["processes"][0]["pid"] == 100
        assert data["s2"]["processes"][0]["pid"] == 200
