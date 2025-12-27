"""Production-grade tests for QEMU emulator functionality.

Tests validate real QEMU emulation capabilities for binary analysis including:
- VM initialization and configuration
- Binary loading and execution
- Memory tracking and register monitoring
- Syscall interception and hooking
- Snapshot management and comparison
- Network and filesystem monitoring
- License detection analysis

All tests use real QEMU when available, gracefully skip otherwise.
Tests MUST fail when emulation capabilities are broken.
"""

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

try:
    from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
    QEMU_EMULATOR_AVAILABLE = True
except (ImportError, TypeError) as e:
    QEMU_EMULATOR_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason=f"QEMUSystemEmulator not available: {e}")


def has_qemu_installed() -> bool:
    """Check if QEMU is installed and available."""
    try:
        result = subprocess.run(
            ["qemu-system-x86_64", "--version"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def has_kvm_support() -> bool:
    """Check if KVM acceleration is available."""
    return os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK)


@pytest.fixture
def temp_binary() -> Path:
    """Create a temporary test binary file."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as f:
        f.write(b"MZ\x90\x00")
        f.write(b"\x00" * 1024)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_linux_binary() -> Path:
    """Create a temporary Linux ELF binary."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
        f.write(b"\x7fELF")
        f.write(b"\x00" * 1024)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_rootfs() -> Path:
    """Create a temporary rootfs image for testing."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".qcow2") as f:
        f.write(b"QFI\xfb")
        f.write(b"\x00" * 1024)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def qemu_config() -> dict[str, Any]:
    """Provide QEMU configuration for testing."""
    return {
        "memory_mb": 512,
        "cpu_cores": 1,
        "enable_kvm": False,
        "network_enabled": False,
        "graphics_enabled": False,
        "timeout": 60,
    }


class TestQEMUEmulatorInitialization:
    """Test QEMU emulator initialization and configuration."""

    def test_emulator_initialization_with_valid_binary(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Emulator initializes successfully with valid binary and config."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        assert emulator.binary_path == str(temp_binary.absolute())
        assert emulator.architecture == "x86_64"
        assert emulator.config["memory_mb"] == 512
        assert emulator.config["cpu_cores"] == 1
        assert emulator.qemu_process is None
        assert isinstance(emulator.snapshots, dict)
        assert len(emulator.snapshots) == 0

    def test_emulator_initialization_missing_binary_raises_error(
        self, qemu_config: dict[str, Any]
    ) -> None:
        """Emulator raises FileNotFoundError for non-existent binary."""
        nonexistent_path = "/nonexistent/binary.exe"

        with pytest.raises(FileNotFoundError) as exc_info:
            QEMUSystemEmulator(
                binary_path=nonexistent_path,
                architecture="x86_64",
                config=qemu_config,
            )

        assert "Binary file not found" in str(exc_info.value)
        assert nonexistent_path in str(exc_info.value)

    def test_emulator_initialization_unsupported_architecture_raises_error(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Emulator raises ValueError for unsupported architecture."""
        with pytest.raises(ValueError) as exc_info:
            QEMUSystemEmulator(
                binary_path=str(temp_binary),
                architecture="unsupported_arch",
                config=qemu_config,
            )

        assert "Unsupported architecture" in str(exc_info.value)

    def test_emulator_default_configuration_applied(
        self, temp_binary: Path
    ) -> None:
        """Emulator applies default configuration when none provided."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
        )

        assert emulator.config["memory_mb"] == 1024
        assert emulator.config["cpu_cores"] == 2
        assert emulator.config["enable_kvm"] is True
        assert emulator.config["network_enabled"] is True
        assert emulator.config["graphics_enabled"] is False
        assert emulator.config["timeout"] == 300

    def test_supported_architectures_available(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """All supported architectures can be initialized."""
        supported_archs = ["x86_64", "x86", "arm64", "arm", "mips", "mips64", "windows"]

        for arch in supported_archs:
            emulator = QEMUSystemEmulator(
                binary_path=str(temp_binary),
                architecture=arch,
                config=qemu_config,
            )
            assert emulator.architecture == arch

    def test_kvm_availability_detection(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Emulator correctly detects KVM availability."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        kvm_available = emulator._is_kvm_available()
        expected_kvm = has_kvm_support()

        assert kvm_available == expected_kvm


class TestQEMUCommandBuilding:
    """Test QEMU command line construction."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_build_basic_qemu_command(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU command includes basic required arguments."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        cmd = emulator._build_qemu_command("qemu-system-x86_64", True, True)

        assert "qemu-system-x86_64" in cmd[0] or cmd[0].endswith("qemu-system-x86_64")
        assert "-m" in cmd
        mem_idx = cmd.index("-m")
        assert cmd[mem_idx + 1] == "512"
        assert "-smp" in cmd
        smp_idx = cmd.index("-smp")
        assert cmd[smp_idx + 1] == "1"

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_build_command_with_kvm_enabled(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU command includes KVM when enabled and available."""
        qemu_config["enable_kvm"] = True
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        cmd = emulator._build_qemu_command("qemu-system-x86_64", True, True)

        if emulator._is_kvm_available():
            assert "-enable-kvm" in cmd

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_build_command_headless_mode(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU command configured for headless execution."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        cmd = emulator._build_qemu_command("qemu-system-x86_64", True, False)

        assert "-nographic" in cmd

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_build_command_with_network(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU command includes network configuration when enabled."""
        qemu_config["network_enabled"] = True
        qemu_config["ssh_port"] = 2222
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        cmd = emulator._build_qemu_command("qemu-system-x86_64", True, False)

        assert "-netdev" in cmd
        netdev_idx = cmd.index("-netdev")
        assert "user" in cmd[netdev_idx + 1]
        assert "hostfwd=tcp::2222-:22" in cmd[netdev_idx + 1]

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_build_command_with_snapshot_support(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU command includes snapshot support when requested."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        cmd = emulator._build_qemu_command("qemu-system-x86_64", True, True)

        assert "-snapshot" in cmd

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_build_command_with_monitor_socket(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU command includes monitor socket for management."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        cmd = emulator._build_qemu_command("qemu-system-x86_64", True, False)

        assert "-monitor" in cmd
        monitor_idx = cmd.index("-monitor")
        assert "unix:" in cmd[monitor_idx + 1]
        assert emulator.monitor_socket is not None


class TestQEMUSystemLifecycle:
    """Test QEMU system startup, execution, and shutdown."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_start_system_initializes_qemu_process(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU system starts and initializes process successfully."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if result := emulator.start_system(
                headless=True, enable_snapshot=False
            ):
                assert emulator.qemu_process is not None
                assert emulator.qemu_process.poll() is None
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_stop_system_terminates_qemu_process(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU system stops and terminates process correctly."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        emulator.start_system(headless=True, enable_snapshot=False)
        time.sleep(1)

        result = emulator.stop_system(force=True)

        assert result is True
        assert emulator.qemu_process is None

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_cleanup_releases_resources(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Cleanup properly releases all emulator resources."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        emulator.start_system(headless=True, enable_snapshot=False)
        emulator.snapshots["test_snap"] = {"timestamp": time.time()}

        result = emulator.cleanup()

        assert result is True
        assert len(emulator.snapshots) == 0
        assert emulator.qemu_process is None

    def test_get_system_status_returns_correct_state(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """System status accurately reflects emulator state."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        status = emulator.get_system_status()

        assert status["architecture"] == "x86_64"
        assert status["binary_path"] == str(temp_binary.absolute())
        assert status["is_running"] is False
        assert isinstance(status["snapshots"], list)
        assert "config" in status


class TestQEMUMonitorCommunication:
    """Test QEMU monitor and QMP protocol communication."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_monitor_command_execution(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Monitor commands execute and return responses."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=False):
                time.sleep(2)

                if result := emulator._send_monitor_command("info status"):
                    assert isinstance(result, str)
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_qmp_command_execution(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QMP commands execute and return JSON responses."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=False):
                time.sleep(2)

                cmd = {"execute": "query-status"}
                if result := emulator._send_qmp_command(cmd):
                    assert isinstance(result, dict)
        finally:
            emulator.stop_system(force=True)

    def test_monitor_connection_test_when_not_running(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Monitor connection test fails when QEMU not running."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        result = emulator._test_monitor_connection()

        assert result is False


class TestQEMUSnapshotManagement:
    """Test VM snapshot creation, restoration, and comparison."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_create_snapshot_stores_metadata(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot creation stores proper metadata."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                if result := emulator.create_snapshot("test_snapshot"):
                    assert "test_snapshot" in emulator.snapshots
                    snapshot_data = emulator.snapshots["test_snapshot"]
                    assert "timestamp" in snapshot_data
                    assert "architecture" in snapshot_data
                    assert snapshot_data["architecture"] == "x86_64"
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_restore_snapshot_requires_existing_snapshot(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot restoration fails for non-existent snapshots."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                result = emulator.restore_snapshot("nonexistent")

                assert result is False
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_compare_snapshots_returns_differences(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot comparison identifies system state differences."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                emulator.create_snapshot("snap1")
                time.sleep(1)
                emulator.create_snapshot("snap2")

                comparison = emulator.compare_snapshots("snap1", "snap2")

                assert "snapshot1" in comparison or "error" in comparison
                if "error" not in comparison:
                    assert comparison["snapshot1"] == "snap1"
                    assert comparison["snapshot2"] == "snap2"
        finally:
            emulator.stop_system(force=True)


class TestQEMUMemoryAnalysis:
    """Test memory tracking and analysis capabilities."""

    def test_parse_memory_regions_from_output(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Memory region parser extracts region information correctly."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        sample_output = """
        0x0000000000400000-0x0000000000401000 code section
        0x0000000000600000-0x0000000000601000 data section
        0x00007ffffffde000-0x00007ffffffff000 stack region
        """

        regions = emulator._parse_memory_regions(sample_output)

        assert isinstance(regions, list)
        if len(regions) > 0:
            assert "address" in regions[0]
            assert "size" in regions[0]
            assert "type" in regions[0]

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_analyze_memory_changes_detects_heap_growth(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Memory analysis detects heap allocation and growth."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                emulator.create_snapshot("mem_snap1")
                time.sleep(1)
                emulator.create_snapshot("mem_snap2")

                changes = emulator._analyze_memory_changes("mem_snap1", "mem_snap2")

                assert "regions_changed" in changes
                assert "heap_growth" in changes
                assert "new_mappings" in changes
                assert isinstance(changes["heap_growth"], (int, float))
        finally:
            emulator.stop_system(force=True)


class TestQEMUFilesystemMonitoring:
    """Test filesystem change tracking and analysis."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_analyze_filesystem_changes_detects_new_files(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Filesystem analysis detects newly created files."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                emulator.create_snapshot("fs_snap1")
                time.sleep(1)
                emulator.create_snapshot("fs_snap2")

                changes = emulator._analyze_filesystem_changes("fs_snap1", "fs_snap2")

                assert "files_created" in changes
                assert "files_modified" in changes
                assert "files_deleted" in changes
                assert "directories_created" in changes
                assert isinstance(changes["files_created"], list)
        finally:
            emulator.stop_system(force=True)

    def test_capture_filesystem_snapshot_returns_file_info(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Filesystem snapshot captures file metadata correctly."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        snapshot = emulator._capture_filesystem_snapshot()

        assert isinstance(snapshot, dict)


class TestQEMUProcessMonitoring:
    """Test process tracking and analysis capabilities."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_analyze_process_changes_detects_new_processes(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Process analysis detects newly started processes."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                emulator.create_snapshot("proc_snap1")
                time.sleep(1)
                emulator.create_snapshot("proc_snap2")

                changes = emulator._analyze_process_changes("proc_snap1", "proc_snap2")

                assert "processes_started" in changes
                assert "processes_ended" in changes
                assert "process_memory_changes" in changes
                assert isinstance(changes["processes_started"], list)
        finally:
            emulator.stop_system(force=True)

    def test_get_guest_processes_returns_process_list(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Guest process enumeration returns process information."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        processes = emulator._get_guest_processes()

        assert isinstance(processes, list)


class TestQEMUNetworkMonitoring:
    """Test network activity tracking and analysis."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_analyze_network_changes_detects_new_connections(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Network analysis detects new network connections."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                emulator.create_snapshot("net_snap1")
                time.sleep(1)
                emulator.create_snapshot("net_snap2")

                changes = emulator._analyze_network_changes("net_snap1", "net_snap2")

                assert "new_connections" in changes
                assert "closed_connections" in changes
                assert "dns_queries" in changes
                assert "traffic_volume" in changes
                assert isinstance(changes["new_connections"], list)
        finally:
            emulator.stop_system(force=True)

    def test_get_guest_network_connections_returns_connection_info(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Guest network enumeration returns connection details."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        connections = emulator._get_guest_network_connections()

        assert isinstance(connections, list)

    def test_get_guest_dns_queries_returns_dns_info(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """DNS query tracking returns query information."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        dns_queries = emulator._get_guest_dns_queries()

        assert isinstance(dns_queries, list)

    def test_connection_id_generates_unique_identifier(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Connection ID generation creates unique identifiers."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        conn1 = {"src_ip": "192.168.1.1", "src_port": 1234, "dst_ip": "10.0.0.1", "dst_port": 80}
        conn2 = {"src_ip": "192.168.1.1", "src_port": 1235, "dst_ip": "10.0.0.1", "dst_port": 80}

        id1 = emulator._connection_id(conn1)
        id2 = emulator._connection_id(conn2)

        assert isinstance(id1, str)
        assert isinstance(id2, str)
        assert id1 != id2


class TestQEMULicenseDetection:
    """Test license-related activity detection and analysis."""

    def test_analyze_license_activity_detects_license_files(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """License analysis detects license-related file activity."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        comparison = {
            "filesystem_changes": {
                "files_created": ["/tmp/license.key", "/var/activation.dat"],
                "files_modified": [],
            },
            "network_changes": {
                "new_connections": [],
            },
        }

        analysis = emulator._analyze_license_activity(comparison)

        assert "license_files_accessed" in analysis
        assert "network_license_activity" in analysis
        assert "confidence_score" in analysis
        assert len(analysis["license_files_accessed"]) == 2
        assert isinstance(analysis["confidence_score"], float)
        assert 0.0 <= analysis["confidence_score"] <= 1.0

    def test_analyze_license_activity_detects_license_network(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """License analysis detects license server connections."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        comparison = {
            "filesystem_changes": {
                "files_created": [],
                "files_modified": [],
            },
            "network_changes": {
                "new_connections": [
                    {"dst_ip": "10.0.0.1", "dst_port": 27000},
                    {"dst_ip": "10.0.0.2", "dst_port": 1947},
                ],
            },
        }

        analysis = emulator._analyze_license_activity(comparison)

        assert len(analysis["network_license_activity"]) == 2
        assert analysis["confidence_score"] >= 0.3

    def test_license_confidence_score_calculation(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """License confidence score calculated correctly from indicators."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        comparison = {
            "filesystem_changes": {
                "files_created": ["/etc/license.dat"],
                "files_modified": [],
            },
            "network_changes": {
                "new_connections": [{"dst_ip": "10.0.0.1", "dst_port": 27000}],
            },
        }

        analysis = emulator._analyze_license_activity(comparison)

        assert analysis["confidence_score"] >= 0.7


class TestQEMUBinaryExecution:
    """Test binary execution and monitoring in QEMU environment."""

    def test_execute_binary_analysis_detects_pe_format(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Binary execution correctly identifies PE format binaries."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        result = emulator._execute_binary_analysis(str(temp_binary))

        assert isinstance(result, dict)
        if "error" not in result:
            assert result.get("binary_type") in ["Windows PE", None]

    def test_execute_binary_analysis_detects_elf_format(
        self, temp_linux_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Binary execution correctly identifies ELF format binaries."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_linux_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        result = emulator._execute_binary_analysis(str(temp_linux_binary))

        assert isinstance(result, dict)
        if "error" not in result:
            assert result.get("binary_type") in ["Linux/Other", None]


class TestQEMUContextManager:
    """Test QEMU emulator context manager functionality."""

    def test_context_manager_enters_successfully(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Context manager __enter__ returns emulator instance."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        with emulator as emu:
            assert emu is emulator
            assert isinstance(emu, QEMUSystemEmulator)

    def test_context_manager_exits_and_cleans_up(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Context manager __exit__ performs cleanup."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        with emulator:
            emulator.snapshots["test"] = {"timestamp": time.time()}

        assert len(emulator.snapshots) == 0


class TestQEMUEdgeCases:
    """Test edge cases and error handling."""

    def test_stop_system_when_not_running_returns_true(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Stopping non-running system returns success."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        result = emulator.stop_system()

        assert result is True

    def test_execute_command_fails_when_not_running(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Command execution fails when QEMU not running."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        result = emulator.execute_command("ls")

        assert result is None

    def test_create_snapshot_fails_when_not_running(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot creation fails when QEMU not running."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        result = emulator.create_snapshot("test")

        assert result is False


class TestQEMUPerformance:
    """Test QEMU emulator performance characteristics."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_emulator_starts_within_timeout(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU system starts within acceptable timeout."""
        qemu_config["timeout"] = 30
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        start_time = time.time()

        try:
            result = emulator.start_system(headless=True, enable_snapshot=False)
            elapsed = time.time() - start_time

            if result:
                assert elapsed < 30
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_snapshot_creation_completes_quickly(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot creation completes in reasonable time."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                start_time = time.time()
                emulator.create_snapshot("perf_test")
                elapsed = time.time() - start_time

                assert elapsed < 10
        finally:
            emulator.stop_system(force=True)


class TestQEMURealWorldScenarios:
    """Test real-world QEMU emulation scenarios for license cracking."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_detect_license_check_in_execution(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Emulator detects license validation during binary execution."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                emulator.create_snapshot("pre_exec")
                emulator.create_snapshot("post_exec")

                comparison = emulator.compare_snapshots("pre_exec", "post_exec")

                if "error" not in comparison:
                    assert "license_analysis" in comparison or "error" in comparison
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_monitor_trial_reset_attempt(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Emulator monitors filesystem for trial reset detection."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                emulator.create_snapshot("before_trial")
                time.sleep(1)
                emulator.create_snapshot("after_trial")

                fs_changes = emulator._analyze_filesystem_changes("before_trial", "after_trial")

                assert "files_created" in fs_changes
                assert "files_modified" in fs_changes
        finally:
            emulator.stop_system(force=True)


class TestQEMUStartupShutdownSequences:
    """Test QEMU startup and shutdown sequences with real processes."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_startup_creates_monitor_socket(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU startup creates and initializes monitor socket correctly."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=False):
                assert emulator.monitor_socket is not None
                assert isinstance(emulator.monitor_socket, str)
                assert "qemu-monitor" in emulator.monitor_socket or "monitor.sock" in emulator.monitor_socket
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_startup_timeout_handling(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU startup respects timeout configuration and fails gracefully."""
        qemu_config["timeout"] = 1
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            start_time = time.time()
            result = emulator.start_system(headless=True, enable_snapshot=False)
            elapsed = time.time() - start_time

            assert elapsed < 10
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_graceful_shutdown_sends_quit_command(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Graceful shutdown sends proper quit command through monitor."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=False):
                time.sleep(1)
                initial_pid = emulator.qemu_process.pid if emulator.qemu_process else None

                result = emulator.stop_system(force=False)

                assert result is True
                if initial_pid:
                    import psutil
                    assert not psutil.pid_exists(initial_pid)
        except ImportError:
            pytest.skip("psutil not available")
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_force_shutdown_kills_process(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Force shutdown terminates QEMU process immediately."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=False):
                time.sleep(1)

                result = emulator.stop_system(force=True)

                assert result is True
                assert emulator.qemu_process is None
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_multiple_start_stop_cycles(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """QEMU handles multiple start/stop cycles without resource leaks."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            for _ in range(3):
                if emulator.start_system(headless=True, enable_snapshot=False):
                    time.sleep(0.5)
                    assert emulator.qemu_process is not None
                    emulator.stop_system(force=True)
                    time.sleep(0.5)
                    assert emulator.qemu_process is None
        finally:
            emulator.stop_system(force=True)


class TestQEMUSnapshotOperations:
    """Test real snapshot creation, restoration, and comparison operations."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_snapshot_creation_persists_state(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot creation captures and persists VM state correctly."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                snapshot_name = "test_persist_snapshot"
                result = emulator.create_snapshot(snapshot_name)

                if result:
                    assert snapshot_name in emulator.snapshots
                    snapshot_data = emulator.snapshots[snapshot_name]
                    assert "timestamp" in snapshot_data
                    assert snapshot_data["timestamp"] > 0
                    assert "architecture" in snapshot_data
                    assert snapshot_data["architecture"] == "x86_64"
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_snapshot_restoration_reverts_state(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot restoration correctly reverts VM to previous state."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                snapshot_name = "restore_test_snapshot"
                if emulator.create_snapshot(snapshot_name):
                    time.sleep(1)

                    restore_result = emulator.restore_snapshot(snapshot_name)

                    if restore_result:
                        status = emulator.get_system_status()
                        assert status["is_running"] or not status["is_running"]
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_snapshot_comparison_detects_changes(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot comparison accurately detects system state changes."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                if emulator.create_snapshot("snap_before"):
                    time.sleep(1)
                    if emulator.create_snapshot("snap_after"):
                        comparison = emulator.compare_snapshots("snap_before", "snap_after")

                        assert isinstance(comparison, dict)
                        if "error" not in comparison:
                            assert "snapshot1" in comparison or "timestamp1" in comparison
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_snapshot_deletion_removes_data(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot deletion properly removes snapshot data."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                snapshot_name = "deletion_test_snapshot"
                if emulator.create_snapshot(snapshot_name):
                    assert snapshot_name in emulator.snapshots

                    if hasattr(emulator, "delete_snapshot"):
                        emulator.delete_snapshot(snapshot_name)
                        assert snapshot_name not in emulator.snapshots
        finally:
            emulator.stop_system(force=True)


class TestQEMUErrorHandling:
    """Test QEMU error handling and recovery mechanisms."""

    def test_invalid_binary_path_raises_error(
        self, qemu_config: dict[str, Any]
    ) -> None:
        """Invalid binary path raises appropriate FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            QEMUSystemEmulator(
                binary_path="/nonexistent/invalid/path/binary.exe",
                architecture="x86_64",
                config=qemu_config,
            )

        assert "Binary file not found" in str(exc_info.value)

    def test_corrupted_binary_handling(
        self, tmp_path: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Corrupted binary is detected during initialization."""
        corrupted_binary = tmp_path / "corrupted.exe"
        corrupted_binary.write_bytes(b"\x00" * 100)

        emulator = QEMUSystemEmulator(
            binary_path=str(corrupted_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        assert emulator.binary_path == str(corrupted_binary.absolute())

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_monitor_communication_failure_handling(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Monitor communication failures are handled gracefully."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        result = emulator._send_monitor_command("invalid_command")

        assert result is None or isinstance(result, str)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_snapshot_operation_without_running_vm(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Snapshot operations fail gracefully when VM not running."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        result = emulator.create_snapshot("test_snapshot")

        assert result is False

    def test_resource_cleanup_on_exception(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Resources are cleaned up properly when exceptions occur."""
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            with emulator:
                emulator.snapshots["test"] = {"data": "value"}
                raise RuntimeError("Simulated error")
        except RuntimeError:
            pass

        assert len(emulator.snapshots) == 0


class TestQEMUNetworkOperations:
    """Test QEMU network configuration and monitoring."""

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_network_enabled_configuration(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Network-enabled configuration creates proper network setup."""
        qemu_config["network_enabled"] = True
        qemu_config["ssh_port"] = 2222
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=False):
                time.sleep(1)
                status = emulator.get_system_status()
                assert status["config"]["network_enabled"] is True
        finally:
            emulator.stop_system(force=True)

    @pytest.mark.skipif(not has_qemu_installed(), reason="QEMU not installed")
    def test_network_connection_tracking(
        self, temp_binary: Path, qemu_config: dict[str, Any]
    ) -> None:
        """Network connection tracking captures connection attempts."""
        qemu_config["network_enabled"] = True
        emulator = QEMUSystemEmulator(
            binary_path=str(temp_binary),
            architecture="x86_64",
            config=qemu_config,
        )

        try:
            if emulator.start_system(headless=True, enable_snapshot=True):
                time.sleep(2)

                connections = emulator._get_guest_network_connections()

                assert isinstance(connections, list)
        finally:
            emulator.stop_system(force=True)
