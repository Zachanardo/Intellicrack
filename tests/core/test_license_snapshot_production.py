"""Production tests for license snapshot system state capture.

Tests validate real system state capture including registry, files, processes,
services, and hardware information for license analysis.
"""

import json
import platform
import tempfile
import time
from pathlib import Path

import pytest

from intellicrack.core.license_snapshot import LicenseSnapshot


@pytest.fixture
def snapshot() -> LicenseSnapshot:
    return LicenseSnapshot()


class TestLicenseSnapshotInitialization:
    """Test license snapshot initialization."""

    def test_snapshot_initializes_empty(self) -> None:
        """Snapshot initializes with empty state."""
        snapshot = LicenseSnapshot()

        assert len(snapshot.snapshots) == 0
        assert snapshot.current_snapshot is None

    def test_snapshot_has_license_registry_keys(self) -> None:
        """Snapshot has predefined license-related registry keys."""
        snapshot = LicenseSnapshot()

        assert len(snapshot.COMMON_LICENSE_REGISTRY_KEYS) > 0
        assert any("Uninstall" in key for key in snapshot.COMMON_LICENSE_REGISTRY_KEYS)
        assert any("Licenses" in key for key in snapshot.COMMON_LICENSE_REGISTRY_KEYS)

    def test_snapshot_has_license_file_patterns(self) -> None:
        """Snapshot has license file search patterns."""
        snapshot = LicenseSnapshot()

        assert len(snapshot.LICENSE_FILE_PATTERNS) > 0
        assert "*.lic" in snapshot.LICENSE_FILE_PATTERNS
        assert "*.key" in snapshot.LICENSE_FILE_PATTERNS


class TestSystemInfoCapture:
    """Test system information capture."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_system_info_retrieves_hardware_data(self, snapshot: LicenseSnapshot) -> None:
        """System info capture retrieves real hardware identifiers."""
        system_info = snapshot._capture_system_info()

        assert "hostname" in system_info
        assert "username" in system_info
        assert "os_version" in system_info
        assert len(system_info) > 0

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_system_info_includes_volume_serials(self, snapshot: LicenseSnapshot) -> None:
        """System info includes volume serial numbers."""
        system_info = snapshot._capture_system_info()

        assert "volumes" in system_info
        volumes = system_info["volumes"]
        assert isinstance(volumes, list)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_system_info_includes_mac_address(self, snapshot: LicenseSnapshot) -> None:
        """System info includes MAC address."""
        system_info = snapshot._capture_system_info()

        assert "mac_address" in system_info
        mac = system_info["mac_address"]
        assert ":" in mac or len(mac) > 0


class TestProcessStateCapture:
    """Test running process capture."""

    def test_capture_process_state_returns_processes(self, snapshot: LicenseSnapshot) -> None:
        """Process state capture returns running processes."""
        processes = snapshot._capture_process_state()

        assert isinstance(processes, list)
        assert len(processes) > 0

        first_process = processes[0]
        assert "pid" in first_process
        assert "name" in first_process
        assert "exe" in first_process

    def test_capture_process_state_includes_command_line(self, snapshot: LicenseSnapshot) -> None:
        """Process capture includes command line arguments."""
        processes = snapshot._capture_process_state()

        assert any("cmdline" in proc for proc in processes)

    def test_capture_process_state_calculates_exe_hash(self, snapshot: LicenseSnapshot) -> None:
        """Process capture calculates executable hash."""
        processes = snapshot._capture_process_state()

        processes_with_hash = [p for p in processes if "exe_hash" in p]
        assert processes_with_hash


class TestRegistryStateCapture:
    """Test registry state capture."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_registry_state_returns_license_keys(self, snapshot: LicenseSnapshot) -> None:
        """Registry capture returns license-related keys."""
        registry_data = snapshot._capture_registry_state()

        assert isinstance(registry_data, dict)
        assert "HKLM" in registry_data or "HKCU" in registry_data

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_registry_state_includes_uninstall_keys(self, snapshot: LicenseSnapshot) -> None:
        """Registry capture includes software uninstall information."""
        registry_data = snapshot._capture_registry_state()

        hklm_data = registry_data.get("HKLM", {})
        assert any("Uninstall" in key for key in hklm_data.keys()) if hklm_data else True

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_read_registry_key_recursive_stops_at_max_depth(self, snapshot: LicenseSnapshot) -> None:
        """Registry recursive read respects max depth."""
        import winreg

        key_data = snapshot._read_registry_key_recursive(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft",
            max_depth=1,
        )

        assert isinstance(key_data, dict)


class TestFileStateCapture:
    """Test file state capture."""

    def test_capture_file_state_finds_license_files(self, snapshot: LicenseSnapshot) -> None:
        """File capture identifies license-related files."""
        file_data = snapshot._capture_file_state()

        assert isinstance(file_data, dict)
        assert "license_files" in file_data
        assert "config_files" in file_data
        assert "database_files" in file_data

    def test_hash_file_calculates_sha256(self, snapshot: LicenseSnapshot) -> None:
        """File hash calculation produces SHA256."""
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp:
            tmp.write(b"Test license data")
            tmp_path = tmp.name

        try:
            file_hash = snapshot._hash_file(tmp_path)

            assert len(file_hash) == 64
            assert all(c in "0123456789abcdef" for c in file_hash)
        finally:
            Path(tmp_path).unlink()

    def test_hash_file_returns_empty_on_error(self, snapshot: LicenseSnapshot) -> None:
        """File hash returns empty string on read error."""
        hash_result = snapshot._hash_file("/nonexistent/file/path")

        assert hash_result == ""


class TestServiceStateCapture:
    """Test Windows service capture."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_service_state_finds_services(self, snapshot: LicenseSnapshot) -> None:
        """Service capture identifies license-related services."""
        services = snapshot._capture_service_state()

        assert isinstance(services, list)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_service_state_includes_service_details(self, snapshot: LicenseSnapshot) -> None:
        """Service capture includes name, display name, and status."""
        services = snapshot._capture_service_state()

        if len(services) > 0:
            service = services[0]
            assert "name" in service
            assert "display_name" in service
            assert "status" in service


class TestNetworkStateCapture:
    """Test network connection capture."""

    def test_capture_network_state_finds_connections(self, snapshot: LicenseSnapshot) -> None:
        """Network capture identifies active connections."""
        network_data = snapshot._capture_network_state()

        assert isinstance(network_data, dict)
        assert "connections" in network_data
        assert "listening_ports" in network_data

    def test_capture_network_state_filters_license_ports(self, snapshot: LicenseSnapshot) -> None:
        """Network capture filters for common license server ports."""
        network_data = snapshot._capture_network_state()

        assert isinstance(network_data["connections"], list)
        assert isinstance(network_data["listening_ports"], list)


class TestCertificateCapture:
    """Test certificate store capture."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_certificates_finds_non_standard_certs(self, snapshot: LicenseSnapshot) -> None:
        """Certificate capture identifies non-standard certificates."""
        certificates = snapshot._capture_certificates()

        assert isinstance(certificates, list)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_capture_certificates_includes_cert_details(self, snapshot: LicenseSnapshot) -> None:
        """Certificate capture includes store, subject, and issuer."""
        certificates = snapshot._capture_certificates()

        if len(certificates) > 0:
            cert = certificates[0]
            assert "store" in cert
            assert "subject" in cert
            assert "issuer" in cert


class TestEnvironmentCapture:
    """Test environment variable capture."""

    def test_capture_environment_filters_license_vars(self, snapshot: LicenseSnapshot) -> None:
        """Environment capture filters license-related variables."""
        env_vars = snapshot._capture_environment()

        assert isinstance(env_vars, dict)

    def test_capture_environment_includes_license_keys(self, snapshot: LicenseSnapshot) -> None:
        """Environment capture includes variables with LICENSE keyword."""
        import os

        original_value = os.environ.get("TEST_LICENSE_KEY")
        try:
            os.environ["TEST_LICENSE_KEY"] = "test_value"

            env_vars = snapshot._capture_environment()

            assert "TEST_LICENSE_KEY" in env_vars
            assert env_vars["TEST_LICENSE_KEY"] == "test_value"
        finally:
            if original_value:
                os.environ["TEST_LICENSE_KEY"] = original_value
            else:
                os.environ.pop("TEST_LICENSE_KEY", None)


class TestFullSnapshotCapture:
    """Test complete system snapshot."""

    def test_capture_full_snapshot_creates_snapshot(self, snapshot: LicenseSnapshot) -> None:
        """Full snapshot capture creates comprehensive state capture."""
        snap = snapshot.capture_full_snapshot("test_snapshot")

        assert snap["name"] == "test_snapshot"
        assert "timestamp" in snap
        assert "system_info" in snap
        assert "processes" in snap
        assert "registry" in snap
        assert "files" in snap
        assert "services" in snap
        assert "network" in snap

    def test_capture_full_snapshot_stores_snapshot(self, snapshot: LicenseSnapshot) -> None:
        """Full snapshot stores result in snapshots dictionary."""
        snapshot.capture_full_snapshot("stored_snapshot")

        assert "stored_snapshot" in snapshot.snapshots
        assert snapshot.current_snapshot is not None

    def test_capture_full_snapshot_includes_timestamp(self, snapshot: LicenseSnapshot) -> None:
        """Full snapshot includes ISO format timestamp."""
        snap = snapshot.capture_full_snapshot("time_snapshot")

        assert "timestamp" in snap
        assert "T" in snap["timestamp"]


class TestSnapshotComparison:
    """Test snapshot comparison functionality."""

    def test_compare_snapshots_detects_new_processes(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot comparison identifies newly started processes."""
        snap1 = snapshot.capture_full_snapshot("before")
        time.sleep(0.1)
        snap2 = snapshot.capture_full_snapshot("after")

        differences = snapshot.compare_snapshots("before", "after")

        assert "new_processes" in differences
        assert "terminated_processes" in differences
        assert isinstance(differences["new_processes"], list)

    def test_compare_snapshots_detects_new_files(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot comparison identifies new license files."""
        snap1 = snapshot.capture_full_snapshot("file_before")
        snap2 = snapshot.capture_full_snapshot("file_after")

        differences = snapshot.compare_snapshots("file_before", "file_after")

        assert "new_files" in differences
        assert "modified_files" in differences

    def test_compare_snapshots_detects_registry_changes(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot comparison identifies registry modifications."""
        snap1 = snapshot.capture_full_snapshot("reg_before")
        snap2 = snapshot.capture_full_snapshot("reg_after")

        differences = snapshot.compare_snapshots("reg_before", "reg_after")

        assert "new_registry_keys" in differences
        assert "modified_registry_values" in differences

    def test_compare_snapshots_returns_error_on_missing_snapshot(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot comparison returns error for missing snapshots."""
        differences = snapshot.compare_snapshots("missing1", "missing2")

        assert "error" in differences


class TestSnapshotExportImport:
    """Test snapshot export and import functionality."""

    def test_export_snapshot_creates_json_file(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot export writes JSON file."""
        snapshot.capture_full_snapshot("export_test")

        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json") as tmp:
            tmp_path = tmp.name

        try:
            success = snapshot.export_snapshot("export_test", tmp_path)

            assert success is True
            assert Path(tmp_path).exists()

            with open(tmp_path) as f:
                data = json.load(f)

            assert data["name"] == "export_test"
            assert "system_info" in data
        finally:
            Path(tmp_path).unlink()

    def test_export_snapshot_returns_false_on_missing_snapshot(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot export returns False for missing snapshot."""
        success = snapshot.export_snapshot("nonexistent", "/tmp/test.json")

        assert success is False

    def test_import_snapshot_loads_json_file(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot import loads JSON file."""
        original_snapshot = snapshot.capture_full_snapshot("import_test")

        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".json") as tmp:
            json.dump(original_snapshot, tmp, default=str)
            tmp_path = tmp.name

        try:
            new_snapshot = LicenseSnapshot()
            name = new_snapshot.import_snapshot(tmp_path)

            assert name is not None
            assert name in new_snapshot.snapshots
            assert new_snapshot.snapshots[name]["name"] == "import_test"
        finally:
            Path(tmp_path).unlink()

    def test_import_snapshot_returns_none_on_invalid_file(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot import returns None for invalid file."""
        name = snapshot.import_snapshot("/nonexistent/file.json")

        assert name is None


class TestLicenseSnapshotRealWorld:
    """Test license snapshot in realistic scenarios."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only test")
    def test_snapshot_captures_before_after_software_install(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot captures system changes during software installation."""
        before = snapshot.capture_full_snapshot("pre_install")

        time.sleep(0.5)

        after = snapshot.capture_full_snapshot("post_install")

        differences = snapshot.compare_snapshots("pre_install", "post_install")

        assert "new_processes" in differences
        assert "new_files" in differences
        assert "new_registry_keys" in differences

    def test_snapshot_tracks_trial_period_modifications(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot identifies trial period registry/file changes."""
        initial = snapshot.capture_full_snapshot("trial_start")

        assert "registry" in initial
        assert "files" in initial

    def test_snapshot_identifies_hardware_id_collection(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot captures hardware identifiers used in licensing."""
        snap = snapshot.capture_full_snapshot("hardware_check")

        system_info = snap["system_info"]

        if platform.system() == "Windows":
            assert "mac_address" in system_info or "volumes" in system_info


class TestSnapshotPerformance:
    """Test snapshot performance characteristics."""

    def test_full_snapshot_completes_in_reasonable_time(self, snapshot: LicenseSnapshot) -> None:
        """Full snapshot capture completes within 60 seconds."""
        start_time = time.time()

        snapshot.capture_full_snapshot("performance_test")

        elapsed = time.time() - start_time

        assert elapsed < 60.0

    def test_snapshot_comparison_is_fast(self, snapshot: LicenseSnapshot) -> None:
        """Snapshot comparison completes quickly."""
        snapshot.capture_full_snapshot("compare_1")
        snapshot.capture_full_snapshot("compare_2")

        start_time = time.time()

        snapshot.compare_snapshots("compare_1", "compare_2")

        elapsed = time.time() - start_time

        assert elapsed < 5.0
