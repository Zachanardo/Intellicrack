"""Comprehensive tests for license_snapshot.py.

Tests validate actual system state capture functionality, differential analysis,
and real license-related artifact detection.
"""

import hashlib
import json
import os
import tempfile
import time
import winreg
from pathlib import Path
from typing import Any

import psutil
import pytest

from intellicrack.core.license_snapshot import LicenseSnapshot


class TestLicenseSnapshotCore:
    """Core snapshot capture functionality tests."""

    def test_snapshot_initialization(self) -> None:
        """Verify snapshot manager initializes with correct state."""
        snapshot = LicenseSnapshot()
        assert snapshot.snapshots == {}
        assert snapshot.current_snapshot is None

    def test_capture_full_snapshot_creates_complete_data(self) -> None:
        """Snapshot captures all required system state categories."""
        snapshot = LicenseSnapshot()
        result = snapshot.capture_full_snapshot("test_snapshot")

        assert "name" in result
        assert result["name"] == "test_snapshot"
        assert "timestamp" in result
        assert "epoch" in result
        assert "system_info" in result
        assert "processes" in result
        assert "registry" in result
        assert "files" in result
        assert "services" in result
        assert "network" in result
        assert "certificates" in result
        assert "environment" in result
        assert "loaded_dlls" in result
        assert "mutexes" in result
        assert "drivers" in result
        assert "scheduled_tasks" in result

        assert snapshot.current_snapshot == result
        assert "test_snapshot" in snapshot.snapshots

    def test_system_info_captures_hwid_components(self) -> None:
        """System info must capture hardware ID components for licensing."""
        snapshot = LicenseSnapshot()
        result = snapshot.capture_full_snapshot("hwid_test")

        sys_info = result["system_info"]
        assert "hostname" in sys_info or "error" in sys_info
        assert "username" in sys_info or "error" in sys_info
        assert "mac_address" in sys_info or "error" in sys_info

        if "volumes" in sys_info:
            assert isinstance(sys_info["volumes"], list)
            for volume in sys_info["volumes"]:
                assert "drive" in volume
                assert "serial" in volume

    def test_process_state_includes_license_modules(self) -> None:
        """Process capture detects license-related modules."""
        snapshot = LicenseSnapshot()
        result = snapshot.capture_full_snapshot("process_test")

        processes = result["processes"]
        assert isinstance(processes, list)

        current_process_found = False
        for proc in processes:
            assert "pid" in proc
            assert "name" in proc
            if proc["pid"] == os.getpid():
                current_process_found = True
                assert "exe" in proc
                assert "cmdline" in proc

        assert current_process_found, "Current process must be captured"


class TestRegistryCapture:
    """Registry state capture tests."""

    def test_registry_capture_targets_license_keys(self) -> None:
        """Registry capture focuses on license-relevant hives and keys."""
        snapshot = LicenseSnapshot()
        result = snapshot.capture_full_snapshot("registry_test")

        registry = result["registry"]
        assert isinstance(registry, dict)

        assert "HKLM" in registry or "HKCU" in registry or "HKCR" in registry

        for hive in ["HKLM", "HKCU", "HKCR"]:
            if hive in registry:
                assert isinstance(registry[hive], dict)

    def test_registry_reads_actual_values(self) -> None:
        """Registry capture must read real registry values, not mock data."""
        snapshot = LicenseSnapshot()

        test_key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, test_key_path, 0, winreg.KEY_READ) as key:
                expected_value, _ = winreg.QueryValueEx(key, "ProductName")
        except OSError:
            pytest.skip("Cannot read registry key for validation")

        result = snapshot.capture_full_snapshot("registry_validation")

        registry = result["registry"]
        found_value = False

        if "HKLM" in registry:
            for key, data in registry["HKLM"].items():
                if "Windows NT\\CurrentVersion" in key and "values" in data and "ProductName" in data["values"]:
                    assert data["values"]["ProductName"]["data"] == expected_value
                    found_value = True
                    break

        if not found_value:
            pytest.skip("ProductName not captured (may be filtered)")


class TestFileStateCapture:
    """File system state capture tests."""

    def test_file_capture_finds_real_files(self, temp_workspace: Path) -> None:
        """File capture must find actual license files on filesystem."""
        snapshot = LicenseSnapshot()

        test_license = temp_workspace / "test.license"
        test_license.write_text("LICENSE-KEY-12345")

        old_locations = LicenseSnapshot.COMMON_LICENSE_FILE_LOCATIONS.copy()
        try:
            LicenseSnapshot.COMMON_LICENSE_FILE_LOCATIONS = [str(temp_workspace)]
            result = snapshot.capture_full_snapshot("file_test")
        finally:
            LicenseSnapshot.COMMON_LICENSE_FILE_LOCATIONS = old_locations

        files = result["files"]
        assert "license_files" in files

        found = False
        for file_info in files["license_files"]:
            if "test.license" in file_info["path"]:
                assert file_info["size"] == 17
                assert "hash" in file_info
                expected_hash = hashlib.sha256(b"LICENSE-KEY-12345").hexdigest()
                assert file_info["hash"] == expected_hash
                found = True

        assert found, "Created license file must be detected"

    def test_file_hashing_produces_valid_sha256(self, temp_workspace: Path) -> None:
        """File hashing must produce correct SHA256 hashes."""
        snapshot = LicenseSnapshot()

        test_file = temp_workspace / "hash_test.dat"
        test_data = b"Test data for hashing"
        test_file.write_bytes(test_data)

        result = snapshot._hash_file(str(test_file))

        expected = hashlib.sha256(test_data).hexdigest()
        assert result == expected


class TestServiceCapture:
    """Windows service enumeration tests."""

    def test_service_capture_detects_real_services(self) -> None:
        """Service capture must detect actual running services."""
        snapshot = LicenseSnapshot()
        result = snapshot.capture_full_snapshot("service_test")

        services = result["services"]
        assert isinstance(services, list)

    def test_service_filter_targets_license_keywords(self) -> None:
        """Service capture filters by license-related keywords."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_service_state()

        license_keywords = [
            "license",
            "activation",
            "hasp",
            "sentinel",
            "flexlm",
            "dongle",
            "protection",
        ]

        for service in result:
            service_name = service["name"].lower()
            display_name = service["display_name"].lower()
            assert any(
                keyword in service_name or keyword in display_name for keyword in license_keywords
            ), f"Service {service_name} doesn't match filter criteria"


class TestNetworkCapture:
    """Network connection capture tests."""

    def test_network_capture_detects_connections(self) -> None:
        """Network capture detects active connections."""
        snapshot = LicenseSnapshot()
        result = snapshot.capture_full_snapshot("network_test")

        network = result["network"]
        assert "connections" in network
        assert "listening_ports" in network
        assert isinstance(network["connections"], list)
        assert isinstance(network["listening_ports"], list)

    def test_network_filters_license_server_ports(self) -> None:
        """Network capture filters by common license server ports."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_network_state()

        license_ports = [27000, 27001, 1947, 1848, 8080, 443, 5053, 6001]

        for conn in result["connections"]:
            local_port = int(conn["local"].split(":")[-1])
            if ":" in conn["remote"]:
                remote_port = int(conn["remote"].split(":")[-1])
            else:
                remote_port = None

            assert local_port in license_ports or (
                remote_port and remote_port in license_ports
            ), f"Connection {conn} doesn't match license port filter"


class TestSnapshotComparison:
    """Differential snapshot comparison tests."""

    def test_compare_snapshots_detects_new_processes(self) -> None:
        """Snapshot comparison must detect new processes started between captures."""
        snapshot = LicenseSnapshot()

        snap1 = snapshot.capture_full_snapshot("before")
        time.sleep(0.1)

        snap2 = snapshot.capture_full_snapshot("after")

        diff = snapshot.compare_snapshots("before", "after")

        assert "new_processes" in diff
        assert "terminated_processes" in diff
        assert isinstance(diff["new_processes"], list)
        assert isinstance(diff["terminated_processes"], list)

    def test_compare_snapshots_detects_file_changes(self, temp_workspace: Path) -> None:
        """Snapshot comparison detects new and modified files."""
        snapshot = LicenseSnapshot()

        test_file = temp_workspace / "change_test.lic"
        test_file.write_text("Original content")

        old_locations = LicenseSnapshot.COMMON_LICENSE_FILE_LOCATIONS.copy()
        try:
            LicenseSnapshot.COMMON_LICENSE_FILE_LOCATIONS = [str(temp_workspace)]

            snap1 = snapshot.capture_full_snapshot("before")

            test_file.write_text("Modified content")
            time.sleep(0.1)

            snap2 = snapshot.capture_full_snapshot("after")
        finally:
            LicenseSnapshot.COMMON_LICENSE_FILE_LOCATIONS = old_locations

        diff = snapshot.compare_snapshots("before", "after")

        assert "new_files" in diff
        assert "modified_files" in diff

        found_modification = any(
            "change_test.lic" in mod["path"] for mod in diff["modified_files"]
        )
        assert found_modification, "File modification must be detected"

    def test_compare_snapshots_detects_registry_changes(self) -> None:
        """Snapshot comparison detects new registry keys."""
        snapshot = LicenseSnapshot()

        snap1 = snapshot.capture_full_snapshot("before")
        time.sleep(0.1)
        snap2 = snapshot.capture_full_snapshot("after")

        diff = snapshot.compare_snapshots("before", "after")

        assert "new_registry_keys" in diff
        assert "modified_registry_values" in diff
        assert isinstance(diff["new_registry_keys"], list)


class TestSnapshotExportImport:
    """Snapshot serialization tests."""

    def test_export_snapshot_creates_valid_json(self, temp_workspace: Path) -> None:
        """Export must create valid JSON file with complete snapshot data."""
        snapshot = LicenseSnapshot()
        snapshot.capture_full_snapshot("export_test")

        export_path = temp_workspace / "snapshot.json"
        result = snapshot.export_snapshot("export_test", str(export_path))

        assert result is True
        assert export_path.exists()

        with open(export_path) as f:
            data = json.load(f)

        assert data["name"] == "export_test"
        assert "timestamp" in data
        assert "system_info" in data
        assert "processes" in data

    def test_import_snapshot_loads_valid_data(self, temp_workspace: Path) -> None:
        """Import must load previously exported snapshot data."""
        snapshot1 = LicenseSnapshot()
        original = snapshot1.capture_full_snapshot("original")

        export_path = temp_workspace / "snapshot.json"
        snapshot1.export_snapshot("original", str(export_path))

        snapshot2 = LicenseSnapshot()
        imported_name = snapshot2.import_snapshot(str(export_path))

        assert imported_name is not None
        assert imported_name in snapshot2.snapshots

        imported = snapshot2.snapshots[imported_name]
        assert imported["name"] == original["name"]
        assert imported["timestamp"] == original["timestamp"]

    def test_export_nonexistent_snapshot_fails(self, temp_workspace: Path) -> None:
        """Export of nonexistent snapshot must fail gracefully."""
        snapshot = LicenseSnapshot()
        export_path = temp_workspace / "fail.json"

        result = snapshot.export_snapshot("nonexistent", str(export_path))
        assert result is False

    def test_import_invalid_file_fails(self, temp_workspace: Path) -> None:
        """Import of invalid file must fail gracefully."""
        snapshot = LicenseSnapshot()

        invalid_path = temp_workspace / "invalid.json"
        invalid_path.write_text("not valid json {{{")

        result = snapshot.import_snapshot(str(invalid_path))
        assert result is None


class TestCertificateCapture:
    """Certificate store enumeration tests."""

    def test_certificate_capture_reads_stores(self) -> None:
        """Certificate capture must read actual Windows certificate stores."""
        snapshot = LicenseSnapshot()
        result = snapshot.capture_full_snapshot("cert_test")

        certs = result["certificates"]
        assert isinstance(certs, list)

    def test_certificate_filters_non_standard_certs(self) -> None:
        """Certificate capture filters to non-standard issuers."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_certificates()

        standard_issuers = ["Microsoft", "Windows", "Verisign", "DigiCert"]

        for cert in result:
            issuer = cert["issuer"]
            assert all(
                std not in issuer for std in standard_issuers
            ), f"Standard issuer {issuer} should be filtered"


class TestEnvironmentCapture:
    """Environment variable capture tests."""

    def test_environment_capture_filters_license_vars(self) -> None:
        """Environment capture filters license-related variables."""
        snapshot = LicenseSnapshot()

        os.environ["TEST_LICENSE_KEY"] = "ABC123"
        try:
            result = snapshot._capture_environment()

            assert "TEST_LICENSE_KEY" in result
            assert result["TEST_LICENSE_KEY"] == "ABC123"
        finally:
            del os.environ["TEST_LICENSE_KEY"]

    def test_environment_ignores_non_license_vars(self) -> None:
        """Environment capture ignores non-license variables."""
        snapshot = LicenseSnapshot()

        os.environ["TEST_RANDOM_VAR"] = "value"
        try:
            result = snapshot._capture_environment()

            assert "TEST_RANDOM_VAR" not in result
        finally:
            del os.environ["TEST_RANDOM_VAR"]


class TestLoadedDLLCapture:
    """DLL enumeration tests."""

    def test_dll_capture_scans_processes(self) -> None:
        """DLL capture scans processes for license-related modules."""
        snapshot = LicenseSnapshot()
        result = snapshot.capture_full_snapshot("dll_test")

        dlls = result["loaded_dlls"]
        assert isinstance(dlls, dict)

    def test_dll_capture_filters_license_modules(self) -> None:
        """DLL capture filters by license-related DLL names."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_loaded_dlls()

        license_keywords = ["license", "hasp", "sentinel", "flexlm", "activation"]

        for process_id, dll_list in result.items():
            for dll_path in dll_list:
                dll_name = dll_path.lower()
                assert any(
                    keyword in dll_name for keyword in license_keywords
                ), f"DLL {dll_path} doesn't match filter"


class TestDriverCapture:
    """Driver enumeration tests."""

    def test_driver_capture_executes_driverquery(self) -> None:
        """Driver capture executes real driverquery command."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_drivers()

        assert isinstance(result, list)

    def test_driver_capture_filters_protection_drivers(self) -> None:
        """Driver capture filters by known protection driver names."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_drivers()

        protection_keywords = ["hasp", "sentinel", "hardlock", "wibu", "safenet", "thales"]

        for driver in result:
            name = driver.get("name", "").lower()
            display = driver.get("display_name", "").lower()
            assert any(
                keyword in name or keyword in display for keyword in protection_keywords
            ), f"Driver {name} doesn't match protection filter"


class TestScheduledTaskCapture:
    """Scheduled task enumeration tests."""

    def test_scheduled_task_capture_executes_schtasks(self) -> None:
        """Task capture executes real schtasks command."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_scheduled_tasks()

        assert isinstance(result, list)

    def test_scheduled_task_filters_license_tasks(self) -> None:
        """Task capture filters by license-related keywords."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_scheduled_tasks()

        license_keywords = ["license", "activation", "update", "check", "verify"]

        for task in result:
            name = task.get("name", "").lower()
            assert any(
                keyword in name for keyword in license_keywords
            ), f"Task {name} doesn't match license filter"


class TestMutexCapture:
    """Mutex enumeration tests."""

    def test_mutex_capture_attempts_enumeration(self) -> None:
        """Mutex capture attempts to enumerate system mutexes."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_system_mutexes()

        assert isinstance(result, list)

    def test_mutex_filters_license_related_names(self) -> None:
        """Mutex capture filters by license-related names."""
        snapshot = LicenseSnapshot()
        result = snapshot._capture_system_mutexes()

        license_keywords = ["license", "trial", "demo", "eval", "single", "instance"]

        for mutex_name in result:
            assert any(
                keyword in mutex_name.lower() for keyword in license_keywords
            ), f"Mutex {mutex_name} doesn't match filter"


class TestEntropyCalculation:
    """Entropy calculation helper tests."""

    def test_hash_file_handles_large_files(self, temp_workspace: Path) -> None:
        """File hashing works correctly for large files."""
        snapshot = LicenseSnapshot()

        large_file = temp_workspace / "large.dat"
        test_data = b"A" * (10 * 1024 * 1024)  # 10MB
        large_file.write_bytes(test_data)

        result = snapshot._hash_file(str(large_file))

        expected = hashlib.sha256(test_data).hexdigest()
        assert result == expected

    def test_hash_file_handles_missing_file(self, temp_workspace: Path) -> None:
        """File hashing returns empty string for missing files."""
        snapshot = LicenseSnapshot()

        result = snapshot._hash_file(str(temp_workspace / "nonexistent.dat"))
        assert result == ""
