"""Production tests for snapshot_utils.py.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

from typing import Any

import pytest

from intellicrack.utils.system.snapshot_utils import compare_snapshots


class TestCompareSnapshots:
    """Test snapshot comparison functionality."""

    def test_compare_snapshots_detects_added_files(self) -> None:
        """Snapshot comparison detects newly added files."""
        snapshot1: dict[str, Any] = {
            "files": {"file1.txt": "hash1", "file2.txt": "hash2"}
        }
        snapshot2: dict[str, Any] = {
            "files": {"file1.txt": "hash1", "file2.txt": "hash2", "file3.txt": "hash3"}
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "file3.txt" in differences["files"]["added"]

    def test_compare_snapshots_detects_removed_files(self) -> None:
        """Snapshot comparison detects removed files."""
        snapshot1: dict[str, Any] = {
            "files": {"file1.txt": "hash1", "file2.txt": "hash2", "file3.txt": "hash3"}
        }
        snapshot2: dict[str, Any] = {
            "files": {"file1.txt": "hash1", "file2.txt": "hash2"}
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "file3.txt" in differences["files"]["removed"]

    def test_compare_snapshots_detects_modified_files(self) -> None:
        """Snapshot comparison detects modified files."""
        snapshot1: dict[str, Any] = {
            "files": {"file1.txt": "hash_old", "file2.txt": "hash2"}
        }
        snapshot2: dict[str, Any] = {
            "files": {"file1.txt": "hash_new", "file2.txt": "hash2"}
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "file1.txt" in differences["files"]["modified"]

    def test_compare_snapshots_detects_registry_changes(self) -> None:
        """Snapshot comparison detects registry changes."""
        snapshot1: dict[str, Any] = {
            "registry": {"HKLM\\Software\\Test": "value1"}
        }
        snapshot2: dict[str, Any] = {
            "registry": {"HKLM\\Software\\Test": "value1", "HKLM\\Software\\New": "value2"}
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "HKLM\\Software\\New" in differences["registry"]["added"]

    def test_compare_snapshots_detects_modified_registry(self) -> None:
        """Snapshot comparison detects modified registry entries."""
        snapshot1: dict[str, Any] = {
            "registry": {"HKLM\\Software\\Test": "old_value"}
        }
        snapshot2: dict[str, Any] = {
            "registry": {"HKLM\\Software\\Test": "new_value"}
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "HKLM\\Software\\Test" in differences["registry"]["modified"]

    def test_compare_snapshots_detects_network_connections(self) -> None:
        """Snapshot comparison detects new network connections."""
        snapshot1: dict[str, Any] = {
            "network": ["192.168.1.1:80", "192.168.1.2:443"]
        }
        snapshot2: dict[str, Any] = {
            "network": ["192.168.1.1:80", "192.168.1.2:443", "10.0.0.1:8080"]
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "10.0.0.1:8080" in differences["network"]["new_connections"]

    def test_compare_snapshots_detects_closed_connections(self) -> None:
        """Snapshot comparison detects closed network connections."""
        snapshot1: dict[str, Any] = {
            "network": ["192.168.1.1:80", "192.168.1.2:443", "10.0.0.1:8080"]
        }
        snapshot2: dict[str, Any] = {
            "network": ["192.168.1.1:80", "192.168.1.2:443"]
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "10.0.0.1:8080" in differences["network"]["closed_connections"]

    def test_compare_snapshots_detects_started_processes(self) -> None:
        """Snapshot comparison detects started processes."""
        snapshot1: dict[str, Any] = {
            "processes": [100, 200, 300]
        }
        snapshot2: dict[str, Any] = {
            "processes": [100, 200, 300, 400]
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert 400 in differences["processes"]["started"]

    def test_compare_snapshots_detects_terminated_processes(self) -> None:
        """Snapshot comparison detects terminated processes."""
        snapshot1: dict[str, Any] = {
            "processes": [100, 200, 300, 400]
        }
        snapshot2: dict[str, Any] = {
            "processes": [100, 200, 300]
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert 400 in differences["processes"]["terminated"]

    def test_compare_snapshots_empty_snapshots(self) -> None:
        """Snapshot comparison handles empty snapshots."""
        snapshot1: dict[str, Any] = {}
        snapshot2: dict[str, Any] = {}

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert differences["files"]["added"] == []
        assert differences["files"]["removed"] == []
        assert differences["files"]["modified"] == []

    def test_compare_snapshots_no_changes(self) -> None:
        """Snapshot comparison detects no changes when identical."""
        snapshot: dict[str, Any] = {
            "files": {"file1.txt": "hash1"},
            "registry": {"key1": "value1"},
            "network": ["192.168.1.1:80"],
            "processes": [100],
        }

        differences: dict[str, Any] = compare_snapshots(snapshot, snapshot)

        assert len(differences["files"]["added"]) == 0
        assert len(differences["files"]["removed"]) == 0
        assert len(differences["registry"]["added"]) == 0
        assert len(differences["network"]["new_connections"]) == 0
        assert len(differences["processes"]["started"]) == 0

    def test_compare_snapshots_returns_all_difference_categories(self) -> None:
        """Snapshot comparison returns all expected difference categories."""
        snapshot1: dict[str, Any] = {}
        snapshot2: dict[str, Any] = {}

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "files" in differences
        assert "registry" in differences
        assert "network" in differences
        assert "processes" in differences
        assert "added" in differences["files"]
        assert "removed" in differences["files"]
        assert "modified" in differences["files"]

    def test_compare_snapshots_complex_file_changes(self) -> None:
        """Snapshot comparison handles complex file change scenarios."""
        snapshot1: dict[str, Any] = {
            "files": {
                "keep.txt": "hash1",
                "modify.txt": "hash_old",
                "delete.txt": "hash2",
            }
        }
        snapshot2: dict[str, Any] = {
            "files": {
                "keep.txt": "hash1",
                "modify.txt": "hash_new",
                "add.txt": "hash3",
            }
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert "add.txt" in differences["files"]["added"]
        assert "delete.txt" in differences["files"]["removed"]
        assert "modify.txt" in differences["files"]["modified"]

    def test_compare_snapshots_handles_missing_sections(self) -> None:
        """Snapshot comparison handles missing sections gracefully."""
        snapshot1: dict[str, Any] = {
            "files": {"file1.txt": "hash1"}
        }
        snapshot2: dict[str, Any] = {
            "files": {"file2.txt": "hash2"},
            "registry": {"key1": "value1"},
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert isinstance(differences, dict)
        assert "files" in differences
        assert "registry" in differences


class TestSnapshotComparisonIntegration:
    """Integration tests for snapshot comparison."""

    def test_full_system_snapshot_comparison(self) -> None:
        """Complete system snapshot comparison workflow."""
        before_snapshot: dict[str, Any] = {
            "files": {
                "C:\\Program Files\\App\\app.exe": "hash1",
                "C:\\Program Files\\App\\config.ini": "hash2",
            },
            "registry": {
                "HKLM\\Software\\App\\Version": "1.0",
                "HKLM\\Software\\App\\InstallDate": "2024-01-01",
            },
            "network": [
                "192.168.1.100:80",
                "192.168.1.101:443",
            ],
            "processes": [1000, 2000, 3000],
        }

        after_snapshot: dict[str, Any] = {
            "files": {
                "C:\\Program Files\\App\\app.exe": "hash1",
                "C:\\Program Files\\App\\config.ini": "hash_modified",
                "C:\\Program Files\\App\\license.dat": "hash3",
            },
            "registry": {
                "HKLM\\Software\\App\\Version": "1.0",
                "HKLM\\Software\\App\\InstallDate": "2024-01-01",
                "HKLM\\Software\\App\\LicenseKey": "ABC123",
            },
            "network": [
                "192.168.1.100:80",
                "licensing.example.com:443",
            ],
            "processes": [1000, 2000, 3000, 4000],
        }

        differences: dict[str, Any] = compare_snapshots(before_snapshot, after_snapshot)

        assert "C:\\Program Files\\App\\license.dat" in differences["files"]["added"]
        assert "C:\\Program Files\\App\\config.ini" in differences["files"]["modified"]
        assert "HKLM\\Software\\App\\LicenseKey" in differences["registry"]["added"]
        assert 4000 in differences["processes"]["started"]
        assert "192.168.1.101:443" in differences["network"]["closed_connections"]
        assert "licensing.example.com:443" in differences["network"]["new_connections"]

    def test_snapshot_comparison_detects_licensing_changes(self) -> None:
        """Snapshot comparison detects licensing-related changes."""
        before: dict[str, Any] = {
            "files": {
                "app.exe": "hash1",
            },
            "registry": {
                "Software\\App\\Installed": "true",
            },
        }

        after: dict[str, Any] = {
            "files": {
                "app.exe": "hash1",
                "license.key": "license_hash",
                "activation.dat": "activation_hash",
            },
            "registry": {
                "Software\\App\\Installed": "true",
                "Software\\App\\Licensed": "true",
                "Software\\App\\SerialNumber": "XXXXX-XXXXX",
            },
        }

        differences: dict[str, Any] = compare_snapshots(before, after)

        licensing_files: list[str] = [
            f for f in differences["files"]["added"]
            if "license" in f or "activation" in f
        ]
        assert len(licensing_files) >= 2

        licensing_registry: list[str] = [
            k for k in differences["registry"]["added"]
            if "license" in k.lower() or "serial" in k.lower()
        ]
        assert len(licensing_registry) >= 2

    def test_snapshot_comparison_performance_many_items(self) -> None:
        """Snapshot comparison handles large numbers of items."""
        snapshot1: dict[str, Any] = {
            "files": {f"file{i}.txt": f"hash{i}" for i in range(1000)},
            "processes": list(range(100, 200)),
        }
        snapshot2: dict[str, Any] = {
            "files": {f"file{i}.txt": f"hash{i}" for i in range(500, 1500)},
            "processes": list(range(150, 250)),
        }

        differences: dict[str, Any] = compare_snapshots(snapshot1, snapshot2)

        assert len(differences["files"]["added"]) == 500
        assert len(differences["files"]["removed"]) == 500
        assert len(differences["processes"]["started"]) == 50
        assert len(differences["processes"]["terminated"]) == 50
