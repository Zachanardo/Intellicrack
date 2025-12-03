"""Comprehensive production-ready tests for QEMU Manager.

Tests validate real QEMU virtual machine management capabilities including:
- VM lifecycle (create, start, stop, destroy)
- SSH connection management with circuit breaker
- Binary injection and execution in VMs
- Snapshot creation, versioning, and hierarchy
- File upload/download via SFTP
- Network isolation and resource management
- Performance monitoring and optimization
- Error handling and recovery
"""

from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch, call

import paramiko
import pytest
from paramiko import RSAKey, SSHClient

from intellicrack.ai.common_types import ExecutionResult
from intellicrack.ai.qemu_manager import (
    QEMUError,
    QEMUManager,
    QEMUSnapshot,
    SecureHostKeyPolicy,
)


@pytest.fixture
def temp_workspace(tmp_path: Path) -> Path:
    """Create temporary workspace for QEMU tests."""
    workspace = tmp_path / "qemu_test_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "images").mkdir(exist_ok=True)
    (workspace / "snapshots").mkdir(exist_ok=True)
    (workspace / "ssh").mkdir(exist_ok=True)
    return workspace


@pytest.fixture
def windows_base_image(temp_workspace: Path) -> Path:
    """Create mock Windows base image."""
    image_path = temp_workspace / "images" / "windows10_base.qcow2"
    image_path.write_bytes(b"QCOW2_WIN10_BASE_IMAGE" * 500)
    return image_path


@pytest.fixture
def linux_base_image(temp_workspace: Path) -> Path:
    """Create mock Linux base image."""
    image_path = temp_workspace / "images" / "ubuntu_base.qcow2"
    image_path.write_bytes(b"QCOW2_UBUNTU_BASE_IMAGE" * 500)
    return image_path


@pytest.fixture
def mock_ssh_key() -> RSAKey:
    """Generate mock SSH key for testing."""
    return RSAKey.generate(2048)


@pytest.fixture
def qemu_manager(
    temp_workspace: Path,
    windows_base_image: Path,
    linux_base_image: Path,
    mock_ssh_key: RSAKey,
) -> QEMUManager:
    """Create QEMUManager instance with mocked dependencies."""
    with patch("intellicrack.core.resources.resource_manager.get_resource_manager") as mock_rm, \
         patch("intellicrack.core.logging.audit_logger.get_audit_logger"), \
         patch("intellicrack.ai.qemu_manager.resource_manager") as mock_resource_mgr, \
         patch("intellicrack.ai.qemu_manager.tempfile.gettempdir", return_value=str(temp_workspace)), \
         patch.object(QEMUManager, "_validate_qemu_setup"), \
         patch.object(QEMUManager, "_init_ssh_keys"), \
         patch.object(QEMUManager, "_get_windows_base_image", return_value=windows_base_image), \
         patch.object(QEMUManager, "_get_linux_base_image", return_value=str(linux_base_image)), \
         patch.object(QEMUManager, "_find_qemu_executable", return_value="qemu-system-x86_64"), \
         patch.object(QEMUManager, "_get_default_rootfs", return_value=str(linux_base_image)):

        mock_rm.return_value = MagicMock()
        mock_resource_mgr.release_resource = MagicMock()
        mock_resource_mgr.acquire_resource = MagicMock(return_value=True)

        manager = QEMUManager()
        manager.working_dir = temp_workspace
        manager.master_ssh_key = mock_ssh_key
        manager.ssh_public_key = f"ssh-rsa {mock_ssh_key.get_base64()} test@qemu"
        return manager


@pytest.fixture
def sample_snapshot(tmp_path: Path) -> QEMUSnapshot:
    """Create sample QEMU snapshot for testing."""
    disk_path = tmp_path / "test_snapshot.qcow2"
    disk_path.write_bytes(b"QCOW2_SNAPSHOT_DATA" * 100)

    return QEMUSnapshot(
        snapshot_id="test_snap_001",
        vm_name="test_vm_001",
        disk_path=str(disk_path),
        binary_path="/tmp/test_binary.exe",
        created_at=datetime.now(),
        ssh_port=22222,
        vnc_port=5900,
    )


class TestVMLifecycle:
    """Test VM creation, start, stop, and destruction."""

    def test_create_script_test_snapshot_creates_overlay_image(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot creation creates QCOW2 overlay image from base."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"PE\x00\x00TEST_BINARY")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            with patch.object(qemu_manager, "_start_vm_for_snapshot"):
                snapshot_id = qemu_manager.create_script_test_snapshot(str(binary_path), "windows")

        assert snapshot_id.startswith("test_")
        assert snapshot_id in qemu_manager.snapshots

        snapshot = qemu_manager.snapshots[snapshot_id]
        assert snapshot.binary_path == str(binary_path)
        assert snapshot.ssh_port >= 22222
        assert snapshot.vnc_port >= 5900

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "qemu-img" in cmd
        assert "create" in cmd
        assert "-f" in cmd
        assert "qcow2" in cmd

    def test_create_snapshot_detects_windows_binary(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot creation detects Windows PE binaries."""
        binary_path = tmp_path / "application.exe"
        binary_path.write_bytes(b"MZ\x90\x00PE_BINARY_DATA")

        os_type = qemu_manager._detect_os_type(str(binary_path))

        assert os_type == "windows"

    def test_create_snapshot_detects_linux_binary(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot creation detects Linux ELF binaries."""
        binary_path = tmp_path / "application.elf"
        binary_path.write_bytes(b"\x7fELF_BINARY_DATA")

        os_type = qemu_manager._detect_os_type(str(binary_path))

        assert os_type == "linux"

    def test_start_vm_for_snapshot_spawns_qemu_process(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """VM startup spawns QEMU process with correct parameters."""
        pid_file = qemu_manager.working_dir / f"{sample_snapshot.snapshot_id}.pid"

        with patch("subprocess.Popen") as mock_popen, \
             patch("time.sleep"):

            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            qemu_manager._start_vm_for_snapshot(sample_snapshot)

        assert sample_snapshot.vm_process is not None

        cmd = mock_popen.call_args[0][0]
        assert qemu_manager.qemu_executable in cmd
        assert "-name" in cmd
        assert sample_snapshot.vm_name in cmd
        assert "-m" in cmd
        assert "2048" in cmd
        assert "-smp" in cmd
        assert "2" in cmd
        assert "-drive" in cmd
        assert sample_snapshot.disk_path in cmd
        assert "-daemonize" in cmd
        assert "-pidfile" in cmd

    def test_start_vm_for_snapshot_configures_network_forwarding(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM startup configures SSH port forwarding."""
        with patch("subprocess.Popen") as mock_popen, \
             patch("time.sleep"):

            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            qemu_manager._start_vm_for_snapshot(sample_snapshot)

        cmd = mock_popen.call_args[0][0]
        cmd_str = " ".join(cmd)

        assert "-netdev" in cmd
        assert f"hostfwd=tcp::{sample_snapshot.ssh_port}-:22" in cmd_str

    def test_start_vm_for_snapshot_handles_startup_failure(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM startup handles process failure."""
        with patch("subprocess.Popen") as mock_popen, \
             patch("time.sleep"):

            mock_process = MagicMock()
            mock_process.poll.return_value = 1
            mock_process.communicate.return_value = (b"", b"QEMU startup failed")
            mock_popen.return_value = mock_process

            with pytest.raises(RuntimeError, match="VM startup failed"):
                qemu_manager._start_vm_for_snapshot(sample_snapshot)

    def test_cleanup_snapshot_terminates_vm_process(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Snapshot cleanup terminates running VM process."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        sample_snapshot.vm_process = mock_process

        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        with patch.object(qemu_manager, "_close_ssh_connection"):
            qemu_manager.cleanup_snapshot(sample_snapshot.snapshot_id)

        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called()

    def test_cleanup_snapshot_removes_disk_file(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Snapshot cleanup deletes disk file."""
        disk_path = Path(sample_snapshot.disk_path)
        assert disk_path.exists()

        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        with patch.object(qemu_manager, "_close_ssh_connection"):
            qemu_manager.cleanup_snapshot(sample_snapshot.snapshot_id)

        assert not disk_path.exists()

    def test_cleanup_snapshot_kills_stuck_process(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """Snapshot cleanup force kills process that won't terminate."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.wait.side_effect = [TimeoutError(), None]
        sample_snapshot.vm_process = mock_process

        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        with patch.object(qemu_manager, "_close_ssh_connection"):
            qemu_manager.cleanup_snapshot(sample_snapshot.snapshot_id)

        mock_process.terminate.assert_called()
        mock_process.kill.assert_called()

    def test_cleanup_all_snapshots_removes_all_vms(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Cleanup all snapshots terminates all VMs."""
        snapshots = []
        for i in range(3):
            disk_path = tmp_path / f"snap_{i}.qcow2"
            disk_path.write_bytes(b"DISK_DATA")

            snap = QEMUSnapshot(
                snapshot_id=f"snap_{i}",
                vm_name=f"vm_{i}",
                disk_path=str(disk_path),
                binary_path="/tmp/test.exe",
                created_at=datetime.now(),
                ssh_port=22222 + i,
                vnc_port=5900 + i,
            )
            qemu_manager.snapshots[snap.snapshot_id] = snap
            snapshots.append(snap)

        with patch.object(qemu_manager, "_close_ssh_connection"):
            qemu_manager.cleanup_all_snapshots()

        assert len(qemu_manager.snapshots) == 0
        for snap in snapshots:
            assert not Path(snap.disk_path).exists()


class TestSSHConnectionManagement:
    """Test SSH connection pooling, retry logic, and circuit breaker."""

    def test_get_ssh_connection_creates_new_connection(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH connection manager creates new connection on first request."""
        mock_client = MagicMock(spec=SSHClient)
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        with patch("paramiko.SSHClient") as mock_ssh_class:
            mock_ssh_class.return_value = mock_client

            client = qemu_manager._get_ssh_connection(sample_snapshot)

        assert client is not None
        mock_client.connect.assert_called_once()

        call_kwargs = mock_client.connect.call_args[1]
        assert call_kwargs["hostname"] == "localhost"
        assert call_kwargs["port"] == sample_snapshot.ssh_port
        assert call_kwargs["username"] == "test"

    def test_get_ssh_connection_reuses_active_connection(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH connection manager reuses active connections from pool."""
        mock_client = MagicMock(spec=SSHClient)
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        pool_key = (sample_snapshot.vm_name, sample_snapshot.ssh_port)
        qemu_manager.ssh_connection_pool[pool_key] = mock_client

        client = qemu_manager._get_ssh_connection(sample_snapshot)

        assert client is mock_client

    def test_get_ssh_connection_retries_on_failure(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH connection manager retries on connection failure."""
        mock_client = MagicMock(spec=SSHClient)
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        call_count = [0]

        def connect_side_effect(*args: Any, **kwargs: Any) -> None:
            call_count[0] += 1
            if call_count[0] < 2:
                raise paramiko.SSHException("Connection refused")

        with patch("paramiko.SSHClient") as mock_ssh_class:
            mock_ssh_class.return_value = mock_client
            mock_client.connect.side_effect = connect_side_effect

            client = qemu_manager._get_ssh_connection(sample_snapshot, retries=3)

        assert client is not None
        assert call_count[0] == 2

    def test_circuit_breaker_opens_after_threshold(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Circuit breaker opens after threshold failures."""
        for _ in range(5):
            qemu_manager._record_connection_failure(sample_snapshot.vm_name)

        assert qemu_manager._is_circuit_open(sample_snapshot.vm_name)

    def test_circuit_breaker_prevents_connections(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Open circuit breaker prevents connection attempts."""
        for _ in range(5):
            qemu_manager._record_connection_failure(sample_snapshot.vm_name)

        client = qemu_manager._get_ssh_connection(sample_snapshot)

        assert client is None

    def test_circuit_breaker_closes_after_timeout(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Circuit breaker closes after timeout period."""
        qemu_manager.circuit_breaker_timeout = 1

        for _ in range(5):
            qemu_manager._record_connection_failure(sample_snapshot.vm_name)

        assert qemu_manager._is_circuit_open(sample_snapshot.vm_name)

        qemu_manager.ssh_circuit_breaker[sample_snapshot.vm_name]["last_failure"] = (
            datetime.now() - timedelta(seconds=2)
        )

        assert not qemu_manager._is_circuit_open(sample_snapshot.vm_name)

    def test_circuit_breaker_resets_on_success(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Circuit breaker resets on successful connection."""
        for _ in range(3):
            qemu_manager._record_connection_failure(sample_snapshot.vm_name)

        qemu_manager._reset_circuit_breaker(sample_snapshot.vm_name)

        breaker = qemu_manager.ssh_circuit_breaker[sample_snapshot.vm_name]
        assert breaker["failures"] == 0
        assert not breaker["open"]

    def test_close_ssh_connection_removes_from_pool(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH connection close removes connection from pool."""
        mock_client = MagicMock(spec=SSHClient)
        pool_key = (sample_snapshot.vm_name, sample_snapshot.ssh_port)
        qemu_manager.ssh_connection_pool[pool_key] = mock_client

        qemu_manager._close_ssh_connection(sample_snapshot)

        assert pool_key not in qemu_manager.ssh_connection_pool
        mock_client.close.assert_called_once()


class TestBinaryExecution:
    """Test binary upload and execution in VMs."""

    def test_upload_file_to_vm_creates_remote_directory(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """File upload creates remote directory if missing."""
        mock_client = MagicMock(spec=SSHClient)
        mock_sftp = MagicMock()
        mock_sftp.stat.side_effect = FileNotFoundError()
        mock_file = MagicMock()
        mock_sftp.file.return_value.__enter__.return_value = mock_file
        mock_client.open_sftp.return_value = mock_sftp

        with patch.object(qemu_manager, "_get_ssh_connection", return_value=mock_client), \
             patch.object(qemu_manager, "_execute_command_in_vm"):

            qemu_manager._upload_file_to_vm(
                sample_snapshot,
                "test content",
                "/remote/path/file.txt"
            )

        mock_file.write.assert_called_once_with("test content")

    def test_upload_binary_to_vm_sets_executable_permission(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """Binary upload sets executable permissions on remote file."""
        local_binary = tmp_path / "binary.exe"
        local_binary.write_bytes(b"PE\x00\x00BINARY_DATA")

        mock_client = MagicMock(spec=SSHClient)
        mock_sftp = MagicMock()
        mock_sftp.stat.side_effect = FileNotFoundError()
        mock_client.open_sftp.return_value = mock_sftp

        with patch.object(qemu_manager, "_get_ssh_connection", return_value=mock_client), \
             patch.object(qemu_manager, "_execute_command_in_vm"):

            qemu_manager._upload_binary_to_vm(
                sample_snapshot,
                str(local_binary),
                "/remote/binary.exe"
            )

        mock_sftp.put.assert_called_once_with(str(local_binary), "/remote/binary.exe")
        mock_sftp.chmod.assert_called_once_with("/remote/binary.exe", 0o755)

    def test_execute_command_in_vm_returns_output(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Command execution returns stdout, stderr, and exit code."""
        mock_client = MagicMock(spec=SSHClient)
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_stdout.read.return_value = b"command output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        with patch.object(qemu_manager, "_get_ssh_connection", return_value=mock_client):
            result = qemu_manager._execute_command_in_vm(sample_snapshot, "echo test")

        assert result["exit_code"] == 0
        assert result["stdout"] == "command output"
        assert result["stderr"] == ""

    def test_execute_command_in_vm_handles_timeout(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Command execution handles timeout."""
        mock_client = MagicMock(spec=SSHClient)
        mock_client.exec_command.side_effect = TimeoutError("Command timeout")

        with patch.object(qemu_manager, "_get_ssh_connection", return_value=mock_client):
            result = qemu_manager._execute_command_in_vm(
                sample_snapshot,
                "sleep 100",
                timeout=1
            )

        assert result["exit_code"] == -1
        assert "timed out" in result["stderr"]

    def test_download_file_from_vm_retrieves_remote_file(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """File download retrieves file from VM."""
        local_path = tmp_path / "downloaded.txt"

        mock_client = MagicMock(spec=SSHClient)
        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp

        with patch.object(qemu_manager, "_get_ssh_connection", return_value=mock_client):
            result = qemu_manager.download_file_from_vm(
                sample_snapshot,
                "/remote/file.txt",
                str(local_path)
            )

        assert result is True
        mock_sftp.get.assert_called_once_with("/remote/file.txt", str(local_path))

    def test_download_file_from_vm_handles_missing_file(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """File download handles missing remote file."""
        local_path = tmp_path / "downloaded.txt"

        mock_client = MagicMock(spec=SSHClient)
        mock_sftp = MagicMock()
        mock_sftp.get.side_effect = FileNotFoundError("Remote file not found")
        mock_client.open_sftp.return_value = mock_sftp

        with patch.object(qemu_manager, "_get_ssh_connection", return_value=mock_client):
            result = qemu_manager.download_file_from_vm(
                sample_snapshot,
                "/nonexistent/file.txt",
                str(local_path)
            )

        assert result is False

    def test_get_modified_binary_downloads_to_local_path(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """Get modified binary downloads and returns local path."""
        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        local_dir = tmp_path / "downloads"
        local_dir.mkdir()

        with patch.object(qemu_manager, "download_file_from_vm", return_value=True):
            local_path = qemu_manager.get_modified_binary(
                sample_snapshot.snapshot_id,
                "/vm/modified_binary.exe",
                str(local_dir)
            )

        assert local_path is not None
        assert local_dir.name in local_path
        assert "modified_binary.exe" in local_path


class TestSnapshotVersioning:
    """Test snapshot versioning and hierarchy."""

    def test_create_versioned_snapshot_creates_child(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """Versioned snapshot creation creates child snapshot."""
        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        binary_path = tmp_path / "modified.exe"
        binary_path.write_bytes(b"MODIFIED_BINARY")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            with patch.object(qemu_manager, "_start_vm_for_snapshot"):
                child_id = qemu_manager.create_versioned_snapshot(
                    sample_snapshot.snapshot_id,
                    str(binary_path)
                )

        assert child_id in qemu_manager.snapshots
        child_snapshot = qemu_manager.snapshots[child_id]
        assert child_snapshot.parent_snapshot == sample_snapshot.snapshot_id
        assert child_snapshot.version == 2

    def test_get_snapshot_hierarchy_builds_tree(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot hierarchy builds parent-child tree."""
        parent_disk = tmp_path / "parent.qcow2"
        parent_disk.write_bytes(b"PARENT_DISK")

        parent = QEMUSnapshot(
            snapshot_id="parent",
            vm_name="parent_vm",
            disk_path=str(parent_disk),
            binary_path="/tmp/binary.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
            parent_snapshot=None,
        )

        child_disk = tmp_path / "child.qcow2"
        child_disk.write_bytes(b"CHILD_DISK")

        child = QEMUSnapshot(
            snapshot_id="child",
            vm_name="child_vm",
            disk_path=str(child_disk),
            binary_path="/tmp/binary.exe",
            created_at=datetime.now(),
            ssh_port=22223,
            vnc_port=5901,
            parent_snapshot="parent",
        )

        qemu_manager.snapshots["parent"] = parent
        qemu_manager.snapshots["child"] = child

        hierarchy = qemu_manager.get_snapshot_hierarchy()

        assert "roots" in hierarchy
        assert len(hierarchy["roots"]) == 1
        assert hierarchy["roots"][0]["snapshot_id"] == "parent"

    def test_snapshot_info_includes_running_status(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Snapshot info includes VM running status."""
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        sample_snapshot.vm_process = mock_process

        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        info = qemu_manager.get_snapshot_info(sample_snapshot.snapshot_id)

        assert info is not None
        assert info["vm_running"] is True
        assert info["snapshot_id"] == sample_snapshot.snapshot_id
        assert info["ssh_port"] == sample_snapshot.ssh_port


class TestNetworkIsolation:
    """Test network isolation and configuration."""

    def test_enable_network_isolation_updates_snapshot(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Network isolation updates snapshot configuration."""
        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        qemu_manager.enable_network_isolation(sample_snapshot.snapshot_id, isolated=True)

        assert sample_snapshot.network_isolated is True

    def test_disable_network_isolation_allows_network(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Disabling network isolation allows network access."""
        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot
        sample_snapshot.network_isolated = True

        qemu_manager.enable_network_isolation(sample_snapshot.snapshot_id, isolated=False)

        assert sample_snapshot.network_isolated is False


class TestPerformanceMonitoring:
    """Test performance monitoring and metrics."""

    def test_monitor_snapshot_performance_collects_metrics(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Performance monitoring collects VM metrics."""
        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        metrics = qemu_manager.monitor_snapshot_performance(sample_snapshot.snapshot_id)

        assert "snapshot_id" in metrics
        assert "timestamp" in metrics
        assert "disk_usage" in metrics
        assert metrics["snapshot_id"] == sample_snapshot.snapshot_id


class TestVMWaitAndReady:
    """Test VM boot waiting and readiness checks."""

    def test_wait_for_vm_ready_succeeds_when_ssh_available(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM ready wait succeeds when SSH connection works."""
        mock_client = MagicMock(spec=SSHClient)
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        ready_response = {"exit_code": 0, "stdout": "ready", "stderr": ""}

        with patch.object(qemu_manager, "_get_ssh_connection", return_value=mock_client), \
             patch.object(qemu_manager, "_execute_command_in_vm", return_value=ready_response), \
             patch.object(qemu_manager, "_inject_ssh_key"):

            result = qemu_manager._wait_for_vm_ready(sample_snapshot, timeout=10)

        assert result is True

    def test_wait_for_vm_ready_times_out(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM ready wait times out when VM doesn't boot."""
        with patch.object(qemu_manager, "_get_ssh_connection", return_value=None), \
             patch("time.sleep"):

            result = qemu_manager._wait_for_vm_ready(sample_snapshot, timeout=1)

        assert result is False


class TestOutputAnalysis:
    """Test script output analysis for success/failure detection."""

    def test_analyze_frida_output_detects_success(
        self, qemu_manager: QEMUManager
    ) -> None:
        """Frida output analysis detects successful execution."""
        stdout = "[+] Script loaded\n[+] Hook installed\nProcess attached"
        stderr = ""

        result = qemu_manager._analyze_frida_output(stdout, stderr)

        assert result is True

    def test_analyze_frida_output_detects_errors(
        self, qemu_manager: QEMUManager
    ) -> None:
        """Frida output analysis detects execution errors."""
        stdout = "Attempting to attach..."
        stderr = "Error: Process not found\nFailed to attach"

        result = qemu_manager._analyze_frida_output(stdout, stderr)

        assert result is False

    def test_analyze_ghidra_output_detects_success(
        self, qemu_manager: QEMUManager
    ) -> None:
        """Ghidra output analysis detects successful analysis."""
        stdout = "INFO: Analysis complete\nPatched function at 0x401000\n3 patches applied"
        stderr = ""

        result = qemu_manager._analyze_ghidra_output(stdout, stderr)

        assert result is True

    def test_analyze_ghidra_output_detects_errors(
        self, qemu_manager: QEMUManager
    ) -> None:
        """Ghidra output analysis detects analysis errors."""
        stdout = "Starting analysis..."
        stderr = "ERROR: Invalid binary format\njava.lang.Exception: Failed to load"

        result = qemu_manager._analyze_ghidra_output(stdout, stderr)

        assert result is False


class TestSnapshotStorage:
    """Test snapshot storage optimization."""

    def test_optimize_snapshot_storage_reports_usage(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Storage optimization reports disk usage."""
        snap1_disk = tmp_path / "snap1.qcow2"
        snap1_disk.write_bytes(b"DISK1" * 1000)

        snap1 = QEMUSnapshot(
            snapshot_id="snap1",
            vm_name="vm1",
            disk_path=str(snap1_disk),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )

        qemu_manager.snapshots["snap1"] = snap1

        result = qemu_manager.optimize_snapshot_storage()

        assert "total_disk_usage" in result
        assert "snapshots_analyzed" in result
        assert result["snapshots_analyzed"] >= 1


class TestSecureHostKeyPolicy:
    """Test secure SSH host key verification."""

    def test_secure_host_key_policy_stores_new_key(
        self, temp_workspace: Path
    ) -> None:
        """Secure host key policy stores new host keys."""
        known_hosts = temp_workspace / "ssh" / "known_hosts"
        policy = SecureHostKeyPolicy(known_hosts)

        mock_client = MagicMock(spec=SSHClient)
        mock_transport = MagicMock()
        mock_transport.getpeername.return_value = ("localhost", 22222)
        mock_client.get_transport.return_value = mock_transport

        test_key = RSAKey.generate(2048)

        policy.missing_host_key(mock_client, "localhost", test_key)

        assert known_hosts.exists()

    def test_secure_host_key_policy_rejects_changed_key(
        self, temp_workspace: Path
    ) -> None:
        """Secure host key policy rejects changed host keys."""
        known_hosts = temp_workspace / "ssh" / "known_hosts"
        policy = SecureHostKeyPolicy(known_hosts)

        mock_client = MagicMock(spec=SSHClient)
        mock_transport = MagicMock()
        mock_transport.getpeername.return_value = ("localhost", 22222)
        mock_client.get_transport.return_value = mock_transport

        key1 = RSAKey.generate(2048)
        policy.missing_host_key(mock_client, "localhost", key1)

        key2 = RSAKey.generate(2048)

        with pytest.raises(paramiko.SSHException, match="Host key verification failed"):
            policy.missing_host_key(mock_client, "localhost", key2)


class TestConfigurationManagement:
    """Test configuration get/update operations."""

    def test_get_base_image_configuration_returns_config(
        self, qemu_manager: QEMUManager
    ) -> None:
        """Base image configuration retrieval returns settings."""
        config = qemu_manager.get_base_image_configuration()

        assert isinstance(config, dict)

    def test_update_base_image_configuration_saves_paths(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Base image configuration update saves new paths."""
        new_image = tmp_path / "new_windows.qcow2"
        new_image.write_bytes(b"NEW_IMAGE")

        qemu_manager.update_base_image_configuration("windows", [str(new_image)])

        qemu_manager.config.set.assert_called()
        qemu_manager.config.save_config.assert_called()

    def test_list_snapshots_returns_all_snapshot_info(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """List snapshots returns information for all snapshots."""
        for i in range(3):
            disk = tmp_path / f"snap{i}.qcow2"
            disk.write_bytes(b"DISK")

            snap = QEMUSnapshot(
                snapshot_id=f"snap{i}",
                vm_name=f"vm{i}",
                disk_path=str(disk),
                binary_path="/tmp/test.exe",
                created_at=datetime.now(),
                ssh_port=22222 + i,
                vnc_port=5900 + i,
            )
            qemu_manager.snapshots[f"snap{i}"] = snap

        snapshots = qemu_manager.list_snapshots()

        assert len(snapshots) == 3
        assert all(info is not None for info in snapshots)


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_qemu_error_exception_contains_message(self) -> None:
        """QEMUError exception preserves error message."""
        error_msg = "VM startup failed: QEMU process exited with code 1"

        with pytest.raises(QEMUError) as exc_info:
            raise QEMUError(error_msg)

        assert str(exc_info.value) == error_msg

    def test_create_snapshot_raises_on_missing_binary(
        self, qemu_manager: QEMUManager
    ) -> None:
        """Snapshot creation raises error for missing binary."""
        with pytest.raises(FileNotFoundError, match="Target binary not found"):
            qemu_manager.create_snapshot("/nonexistent/binary.exe")

    def test_cleanup_snapshot_handles_missing_snapshot(
        self, qemu_manager: QEMUManager
    ) -> None:
        """Cleanup handles missing snapshot gracefully."""
        qemu_manager.cleanup_snapshot("nonexistent_snapshot")

    def test_ssh_injection_handles_connection_failure(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH key injection handles connection failures."""
        with patch.object(
            qemu_manager,
            "_execute_command_in_vm",
            side_effect=Exception("Connection failed")
        ):
            qemu_manager._inject_ssh_key(sample_snapshot)


class TestResourceManagement:
    """Test resource tracking and cleanup."""

    def test_destructor_closes_all_ssh_connections(
        self, qemu_manager: QEMUManager
    ) -> None:
        """Destructor closes all SSH connections in pool."""
        mock_clients = [MagicMock(spec=SSHClient) for _ in range(3)]

        qemu_manager.ssh_connection_pool = {
            ("vm1", 22222): mock_clients[0],
            ("vm2", 22223): mock_clients[1],
            ("vm3", 22224): mock_clients[2],
        }

        with patch.object(qemu_manager, "cleanup_all_snapshots"):
            qemu_manager.__del__()

        for client in mock_clients:
            client.close.assert_called_once()

    def test_get_all_vm_info_returns_complete_details(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Get all VM info returns complete details for UI."""
        disk = tmp_path / "vm.qcow2"
        disk.write_bytes(b"DISK")

        snap = QEMUSnapshot(
            snapshot_id="vm1",
            vm_name="test_vm",
            disk_path=str(disk),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
            version=2,
            parent_snapshot="parent",
        )

        qemu_manager.snapshots["vm1"] = snap

        vm_info = qemu_manager.get_all_vm_info()

        assert len(vm_info) == 1
        assert vm_info[0]["snapshot_id"] == "vm1"
        assert vm_info[0]["version"] == 2
        assert vm_info[0]["parent_snapshot"] == "parent"


class TestImageCreation:
    """Test disk image creation and copying."""

    def test_create_minimal_test_image_creates_qcow2(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Minimal image creation creates QCOW2 disk."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            disk_path = qemu_manager._create_minimal_test_image(snapshot_dir, "windows")

        assert disk_path.suffix == ".qcow2"

        cmd = mock_run.call_args[0][0]
        assert "qemu-img" in cmd
        assert "create" in cmd
        assert "-f" in cmd
        assert "qcow2" in cmd

    def test_create_minimal_test_image_uses_config_size(
        self, qemu_manager: QEMUManager, tmp_path: Path
    ) -> None:
        """Minimal image creation uses configured disk size."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            qemu_manager._create_minimal_test_image(snapshot_dir, "windows")

        cmd = mock_run.call_args[0][0]
        assert "2G" in cmd

    def test_copy_base_image_creates_overlay(
        self, qemu_manager: QEMUManager, tmp_path: Path, windows_base_image: Path
    ) -> None:
        """Base image copy creates QCOW2 overlay."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            overlay = qemu_manager._copy_base_image(windows_base_image, snapshot_dir)

        assert overlay.name == "snapshot_disk.qcow2"

        cmd = mock_run.call_args[0][0]
        assert "-b" in cmd
        assert str(windows_base_image) in cmd

    def test_copy_base_image_falls_back_to_direct_copy(
        self, qemu_manager: QEMUManager, tmp_path: Path, windows_base_image: Path
    ) -> None:
        """Base image copy falls back to direct copy on overlay failure."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="overlay failed")

            with patch("shutil.copy2") as mock_copy:
                overlay = qemu_manager._copy_base_image(windows_base_image, snapshot_dir)

        mock_copy.assert_called_once()
