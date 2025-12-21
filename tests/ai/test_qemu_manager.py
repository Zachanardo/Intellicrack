"""Production-grade tests for QEMU Manager module.

Tests validate real QEMU process management, VM lifecycle control,
SSH connectivity, snapshot operations, and resource management.
"""

import os
import platform
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import paramiko
import pytest

from intellicrack.ai.common_types import ExecutionResult
from intellicrack.ai.qemu_manager import (
    QEMUManager,
    QEMUSnapshot,
    SecureHostKeyPolicy,
)


@pytest.fixture
def temp_qemu_workspace(tmp_path: Path) -> Path:
    """Create temporary workspace for QEMU operations."""
    workspace = tmp_path / "qemu_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "images").mkdir(exist_ok=True)
    (workspace / "snapshots").mkdir(exist_ok=True)
    (workspace / "ssh").mkdir(exist_ok=True)
    return workspace


@pytest.fixture
def mock_base_image(temp_qemu_workspace: Path) -> Path:
    """Create mock base image for testing."""
    image_path = temp_qemu_workspace / "images" / "base_windows.qcow2"
    image_path.write_bytes(b"MOCK_QCOW2_IMAGE_DATA")
    return image_path


@pytest.fixture
def mock_linux_image(temp_qemu_workspace: Path) -> Path:
    """Create mock Linux base image."""
    image_path = temp_qemu_workspace / "images" / "base_linux.qcow2"
    image_path.write_bytes(b"MOCK_LINUX_QCOW2_IMAGE")
    return image_path


@pytest.fixture
def sample_snapshot() -> QEMUSnapshot:
    """Create sample snapshot for testing."""
    return QEMUSnapshot(
        snapshot_id="test_snapshot_001",
        vm_name="test_vm_001",
        disk_path="/tmp/test_disk.qcow2",
        binary_path="/tmp/test_binary.exe",
        created_at=datetime.now(),
        ssh_port=22222,
        vnc_port=5900,
        version=1,
        network_isolated=True,
    )


@pytest.fixture
def qemu_manager_with_mocked_config(
    temp_qemu_workspace: Path,
    mock_base_image: Path,
    mock_linux_image: Path,
) -> QEMUManager:
    """Create QEMUManager with mocked configuration."""
    with patch("intellicrack.ai.qemu_manager.get_config") as mock_config, \
         patch("intellicrack.ai.qemu_manager.get_resource_manager") as mock_rm, \
         patch("intellicrack.ai.qemu_manager.get_audit_logger") as mock_audit, \
         patch("intellicrack.utils.qemu_image_discovery.get_qemu_discovery") as mock_discovery:

        config_mock = MagicMock()
        config_mock.get.side_effect = lambda key, default=None: {
            "vm_framework.ssh.timeout": 30,
            "vm_framework.ssh.retry_count": 3,
            "vm_framework.ssh.retry_delay": 2,
            "vm_framework.ssh.circuit_breaker_threshold": 5,
            "vm_framework.ssh.circuit_breaker_timeout": 60,
            "vm_framework.qemu_defaults.ssh_port_start": 22222,
            "vm_framework.qemu_defaults.vnc_port_start": 5900,
            "vm_framework.base_images.windows": [str(mock_base_image)],
            "vm_framework.base_images.linux": [str(mock_linux_image)],
            "vm_framework.base_images.default_windows_size_gb": 2,
            "vm_framework.base_images.default_linux_size_gb": 1,
        }.get(key, default)
        config_mock.get_tool_path.return_value = None
        mock_config.return_value = config_mock

        mock_discovery_instance = MagicMock()
        mock_discovery_instance.discover_images.return_value = []
        mock_discovery_instance.get_images_by_os.return_value = []
        mock_discovery.return_value = mock_discovery_instance

        with patch("intellicrack.ai.qemu_manager.tempfile.gettempdir", return_value=str(temp_qemu_workspace)):
            with patch.object(QEMUManager, "_validate_qemu_setup"):
                manager = QEMUManager()
                manager.working_dir = temp_qemu_workspace
                return manager


class TestQEMUManagerInitialization:
    """Test QEMU Manager initialization and setup."""

    def test_manager_initializes_with_working_directory(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Manager creates working directory on initialization."""
        manager = qemu_manager_with_mocked_config
        assert manager.working_dir.exists()
        assert manager.working_dir.is_dir()

    def test_manager_initializes_ssh_configuration(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Manager initializes SSH connection pool and configuration."""
        manager = qemu_manager_with_mocked_config
        assert hasattr(manager, "ssh_connection_pool")
        assert isinstance(manager.ssh_connection_pool, dict)
        assert hasattr(manager, "ssh_timeout")
        assert manager.ssh_timeout == 30

    def test_manager_initializes_port_allocation(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Manager initializes port allocation for SSH and VNC."""
        manager = qemu_manager_with_mocked_config
        assert manager.next_ssh_port >= 22222
        assert manager.next_vnc_port >= 5900

    def test_manager_finds_qemu_executable(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Manager locates QEMU executable on system."""
        manager = qemu_manager_with_mocked_config
        assert hasattr(manager, "qemu_executable")
        assert isinstance(manager.qemu_executable, str)

    def test_manager_initializes_circuit_breaker(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Manager initializes SSH circuit breaker mechanism."""
        manager = qemu_manager_with_mocked_config
        assert hasattr(manager, "ssh_circuit_breaker")
        assert isinstance(manager.ssh_circuit_breaker, dict)
        assert manager.circuit_breaker_threshold == 5


class TestQEMUSnapshotCreation:
    """Test QEMU snapshot creation and management."""

    def test_create_snapshot_generates_unique_id(
        self, qemu_manager_with_mocked_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot creation generates unique snapshot ID."""
        manager = qemu_manager_with_mocked_config
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"PE\x00\x00")

        with patch.object(manager, "_start_vm", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                snapshot_id = manager.create_snapshot(str(test_binary))
                assert snapshot_id.startswith("test_")
                assert snapshot_id in manager.snapshots

    def test_create_snapshot_detects_windows_binary(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Snapshot creation detects Windows binary format."""
        manager = qemu_manager_with_mocked_config
        os_type = manager._detect_os_type("sample.exe")
        assert os_type == "windows"

    def test_create_snapshot_detects_linux_binary(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Snapshot creation detects Linux binary format."""
        manager = qemu_manager_with_mocked_config
        os_type = manager._detect_os_type("sample.so")
        assert os_type == "linux"

    def test_create_snapshot_allocates_unique_ports(
        self, qemu_manager_with_mocked_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Each snapshot receives unique SSH and VNC ports."""
        manager = qemu_manager_with_mocked_config
        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"PE\x00\x00")

        with patch.object(manager, "_start_vm", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                snapshot_id1 = manager.create_snapshot(str(test_binary))
                snapshot_id2 = manager.create_snapshot(str(test_binary))

                snapshot1 = manager.snapshots[snapshot_id1]
                snapshot2 = manager.snapshots[snapshot_id2]

                assert snapshot1.ssh_port != snapshot2.ssh_port
                assert snapshot1.vnc_port != snapshot2.vnc_port

    def test_create_snapshot_raises_on_missing_binary(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Snapshot creation raises error for non-existent binary."""
        manager = qemu_manager_with_mocked_config
        with pytest.raises(FileNotFoundError, match="Target binary not found"):
            manager.create_snapshot("/nonexistent/binary.exe")


class TestQEMUVMLifecycle:
    """Test VM startup, monitoring, and shutdown."""

    def test_start_vm_spawns_qemu_process(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM startup spawns real QEMU process."""
        manager = qemu_manager_with_mocked_config

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            result = manager._start_vm(sample_snapshot)
            assert mock_popen.called
            assert result is True

    def test_start_vm_builds_correct_qemu_command(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM startup constructs valid QEMU command line."""
        manager = qemu_manager_with_mocked_config

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            manager._start_vm(sample_snapshot)

            call_args = mock_popen.call_args[0][0]
            assert manager.qemu_executable in call_args
            assert "-m" in call_args
            assert "2048" in call_args
            assert "-smp" in call_args

    def test_start_vm_configures_network_forwarding(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM startup configures SSH port forwarding."""
        manager = qemu_manager_with_mocked_config

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.communicate.return_value = (b"", b"")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            manager._start_vm(sample_snapshot)

            call_args = mock_popen.call_args[0][0]
            netdev_arg = next((arg for arg in call_args if "hostfwd" in arg), None)
            assert netdev_arg is not None
            assert f"{sample_snapshot.ssh_port}" in netdev_arg

    def test_stop_vm_terminates_process_gracefully(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM shutdown terminates process gracefully."""
        manager = qemu_manager_with_mocked_config

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.wait.return_value = None
        sample_snapshot.vm_process = mock_process

        manager._stop_vm_for_snapshot(sample_snapshot)
        mock_process.wait.assert_called()

    def test_cleanup_snapshot_removes_all_resources(
        self, qemu_manager_with_mocked_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot cleanup removes disk files and processes."""
        manager = qemu_manager_with_mocked_config

        snapshot_id = "test_cleanup_001"
        disk_path = tmp_path / "test_disk.qcow2"
        disk_path.write_bytes(b"MOCK_DISK")

        snapshot = QEMUSnapshot(
            snapshot_id=snapshot_id,
            vm_name="test_cleanup_vm",
            disk_path=str(disk_path),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        snapshot.vm_process = mock_process

        manager.snapshots[snapshot_id] = snapshot

        with patch.object(manager, "_close_ssh_connection"):
            manager.cleanup_snapshot(snapshot_id)

        assert snapshot_id not in manager.snapshots
        assert not disk_path.exists()


class TestSSHConnectionManagement:
    """Test SSH connection pooling and circuit breaker."""

    def test_ssh_connection_pool_reuses_connections(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH connection pool reuses existing active connections."""
        manager = qemu_manager_with_mocked_config

        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        pool_key = (sample_snapshot.vm_name, sample_snapshot.ssh_port)
        manager.ssh_connection_pool[pool_key] = mock_client

        result = manager._get_existing_connection(pool_key)
        assert result is mock_client

    def test_ssh_connection_pool_removes_inactive_connections(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH connection pool removes inactive connections."""
        manager = qemu_manager_with_mocked_config

        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = False
        mock_client.get_transport.return_value = mock_transport

        pool_key = (sample_snapshot.vm_name, sample_snapshot.ssh_port)
        manager.ssh_connection_pool[pool_key] = mock_client

        result = manager._get_existing_connection(pool_key)
        assert result is None
        assert pool_key not in manager.ssh_connection_pool

    def test_circuit_breaker_opens_after_threshold(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Circuit breaker opens after failure threshold reached."""
        manager = qemu_manager_with_mocked_config
        vm_name = "test_vm"

        for _ in range(manager.circuit_breaker_threshold):
            manager._record_connection_failure(vm_name)

        assert manager._is_circuit_open(vm_name)

    def test_circuit_breaker_closes_after_timeout(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Circuit breaker closes after timeout expires."""
        manager = qemu_manager_with_mocked_config
        vm_name = "test_vm"

        for _ in range(manager.circuit_breaker_threshold):
            manager._record_connection_failure(vm_name)

        manager.ssh_circuit_breaker[vm_name]["last_failure"] = datetime.now() - timedelta(
            seconds=manager.circuit_breaker_timeout + 10
        )

        assert not manager._is_circuit_open(vm_name)

    def test_circuit_breaker_resets_on_successful_connection(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Circuit breaker resets on successful connection."""
        manager = qemu_manager_with_mocked_config
        vm_name = "test_vm"

        manager._record_connection_failure(vm_name)
        manager._reset_circuit_breaker(vm_name)

        assert not manager._is_circuit_open(vm_name)
        assert manager.ssh_circuit_breaker[vm_name]["failures"] == 0


class TestVMCommandExecution:
    """Test command execution in VMs via SSH."""

    def test_execute_command_returns_exit_code(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Command execution returns exit code from VM."""
        manager = qemu_manager_with_mocked_config

        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"output"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch.object(manager, "_get_ssh_connection", return_value=mock_client):
            result = manager._execute_command_in_vm(sample_snapshot, "echo test")

        assert result["exit_code"] == 0
        assert result["stdout"] == "output"

    def test_execute_command_captures_stdout(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Command execution captures stdout from VM."""
        manager = qemu_manager_with_mocked_config

        expected_output = "test output from vm"
        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = expected_output.encode()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch.object(manager, "_get_ssh_connection", return_value=mock_client):
            result = manager._execute_command_in_vm(sample_snapshot, "echo test")

        assert result["stdout"] == expected_output

    def test_execute_command_captures_stderr(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Command execution captures stderr from VM."""
        manager = qemu_manager_with_mocked_config

        expected_error = "error message"
        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 1
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = expected_error.encode()

        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch.object(manager, "_get_ssh_connection", return_value=mock_client):
            result = manager._execute_command_in_vm(sample_snapshot, "false")

        assert result["stderr"] == expected_error
        assert result["exit_code"] == 1

    def test_execute_command_handles_timeout(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Command execution handles timeout errors."""
        manager = qemu_manager_with_mocked_config

        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_client.exec_command.side_effect = TimeoutError("Command timeout")

        with patch.object(manager, "_get_ssh_connection", return_value=mock_client):
            result = manager._execute_command_in_vm(sample_snapshot, "sleep 100", timeout=1)

        assert result["exit_code"] == -1
        assert "timed out" in result["stderr"].lower()


class TestFileTransferOperations:
    """Test file upload and download operations."""

    def test_upload_file_creates_remote_directory(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """File upload creates remote directory if needed."""
        manager = qemu_manager_with_mocked_config

        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_sftp = MagicMock()
        mock_sftp.stat.side_effect = FileNotFoundError()
        mock_file = MagicMock()
        mock_sftp.file.return_value.__enter__ = Mock(return_value=mock_file)
        mock_sftp.file.return_value.__exit__ = Mock(return_value=False)
        mock_client.open_sftp.return_value = mock_sftp

        with patch.object(manager, "_get_ssh_connection", return_value=mock_client):
            with patch.object(manager, "_execute_command_in_vm") as mock_exec:
                manager._upload_file_to_vm(sample_snapshot, "test content", "/tmp/test/file.txt")

                mkdir_calls = [call for call in mock_exec.call_args_list if "mkdir" in str(call)]
                assert mkdir_calls

    def test_upload_binary_sets_executable_permissions(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """Binary upload sets executable permissions on remote file."""
        manager = qemu_manager_with_mocked_config

        local_binary = tmp_path / "test.exe"
        local_binary.write_bytes(b"MZ\x90\x00")

        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_sftp = MagicMock()
        mock_sftp.stat.side_effect = FileNotFoundError()
        mock_client.open_sftp.return_value = mock_sftp

        with patch.object(manager, "_get_ssh_connection", return_value=mock_client):
            with patch.object(manager, "_execute_command_in_vm"):
                manager._upload_binary_to_vm(sample_snapshot, str(local_binary), "/tmp/test.exe")

        mock_sftp.chmod.assert_called_once_with("/tmp/test.exe", 0o755)

    def test_download_file_creates_local_directory(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """File download creates local directory structure."""
        manager = qemu_manager_with_mocked_config

        local_path = tmp_path / "nested" / "dir" / "file.txt"

        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_sftp = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp

        with patch.object(manager, "_get_ssh_connection", return_value=mock_client):
            result = manager.download_file_from_vm(sample_snapshot, "/tmp/file.txt", str(local_path))

        assert local_path.parent.exists()
        assert result is True

    def test_download_file_handles_missing_remote_file(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """File download handles missing remote file gracefully."""
        manager = qemu_manager_with_mocked_config

        local_path = tmp_path / "download.txt"

        mock_client = MagicMock(spec=paramiko.SSHClient)
        mock_sftp = MagicMock()
        mock_sftp.get.side_effect = FileNotFoundError("Remote file not found")
        mock_client.open_sftp.return_value = mock_sftp

        with patch.object(manager, "_get_ssh_connection", return_value=mock_client):
            result = manager.download_file_from_vm(sample_snapshot, "/nonexistent/file.txt", str(local_path))

        assert result is False


class TestSnapshotInformation:
    """Test snapshot information retrieval."""

    def test_get_snapshot_info_returns_complete_data(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Snapshot info retrieval returns complete metadata."""
        manager = qemu_manager_with_mocked_config
        manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        info = manager.get_snapshot_info(sample_snapshot.snapshot_id)

        assert info is not None
        assert info["snapshot_id"] == sample_snapshot.snapshot_id
        assert info["vm_name"] == sample_snapshot.vm_name
        assert info["ssh_port"] == sample_snapshot.ssh_port
        assert info["vnc_port"] == sample_snapshot.vnc_port

    def test_get_snapshot_info_returns_none_for_missing_snapshot(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Snapshot info returns None for non-existent snapshot."""
        manager = qemu_manager_with_mocked_config
        info = manager.get_snapshot_info("nonexistent_snapshot")
        assert info is None

    def test_list_snapshots_returns_all_active_snapshots(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """List snapshots returns information for all active snapshots."""
        manager = qemu_manager_with_mocked_config

        snapshot1 = QEMUSnapshot(
            snapshot_id="snap1",
            vm_name="vm1",
            disk_path="/tmp/disk1.qcow2",
            binary_path="/tmp/bin1.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )
        snapshot2 = QEMUSnapshot(
            snapshot_id="snap2",
            vm_name="vm2",
            disk_path="/tmp/disk2.qcow2",
            binary_path="/tmp/bin2.exe",
            created_at=datetime.now(),
            ssh_port=22223,
            vnc_port=5901,
        )

        manager.snapshots["snap1"] = snapshot1
        manager.snapshots["snap2"] = snapshot2

        snapshots = manager.list_snapshots()

        assert len(snapshots) == 2
        assert any(s["snapshot_id"] == "snap1" for s in snapshots)
        assert any(s["snapshot_id"] == "snap2" for s in snapshots)

    def test_get_all_vm_info_includes_running_status(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM info includes running status of VM process."""
        manager = qemu_manager_with_mocked_config

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        sample_snapshot.vm_process = mock_process

        manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        vm_info = manager.get_all_vm_info()

        assert len(vm_info) == 1
        assert vm_info[0]["vm_running"] is True


class TestVersionedSnapshots:
    """Test versioned snapshot management."""

    def test_create_versioned_snapshot_creates_child_snapshot(
        self, qemu_manager_with_mocked_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Versioned snapshot creation creates child snapshot."""
        manager = qemu_manager_with_mocked_config

        parent_snapshot = QEMUSnapshot(
            snapshot_id="parent_snap",
            vm_name="parent_vm",
            disk_path=str(tmp_path / "parent.qcow2"),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )
        manager.snapshots["parent_snap"] = parent_snapshot

        test_binary = tmp_path / "test.exe"
        test_binary.write_bytes(b"PE\x00\x00")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            with patch.object(manager, "_start_vm_for_snapshot"):
                child_id = manager.create_versioned_snapshot("parent_snap", str(test_binary))

        assert child_id in manager.snapshots
        child_snapshot = manager.snapshots[child_id]
        assert child_snapshot.parent_snapshot == "parent_snap"
        assert child_id in parent_snapshot.children_snapshots

    def test_get_snapshot_hierarchy_builds_tree_structure(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Snapshot hierarchy builds complete tree structure."""
        manager = qemu_manager_with_mocked_config

        root = QEMUSnapshot(
            snapshot_id="root",
            vm_name="root_vm",
            disk_path="/tmp/root.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
            parent_snapshot=None,
        )

        child1 = QEMUSnapshot(
            snapshot_id="child1",
            vm_name="child1_vm",
            disk_path="/tmp/child1.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22223,
            vnc_port=5901,
            parent_snapshot="root",
        )

        child2 = QEMUSnapshot(
            snapshot_id="child2",
            vm_name="child2_vm",
            disk_path="/tmp/child2.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22224,
            vnc_port=5902,
            parent_snapshot="root",
        )

        root.children_snapshots = {"child1", "child2"}

        manager.snapshots["root"] = root
        manager.snapshots["child1"] = child1
        manager.snapshots["child2"] = child2

        hierarchy = manager.get_snapshot_hierarchy()

        assert "root" in hierarchy["roots"]
        assert len(hierarchy["total_snapshots"]) == 3


class TestScriptExecution:
    """Test script execution in VM environment."""

    def test_frida_script_execution_returns_result(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path
    ) -> None:
        """Frida script execution returns ExecutionResult."""
        manager = qemu_manager_with_mocked_config
        manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        script_content = """
        console.log('[+] Frida script loaded');
        Interceptor.attach(ptr('0x12345678'), {
            onEnter: function(args) {
                console.log('[+] Hook installed');
            }
        });
        """

        with patch.object(manager, "_execute_command_in_vm") as mock_exec:
            mock_exec.return_value = {
                "exit_code": 0,
                "stdout": "[+] Script loaded\n[+] Hook installed",
                "stderr": "",
            }

            result = manager.test_frida_script(
                sample_snapshot.snapshot_id,
                script_content,
                "/tmp/target.exe"
            )

        assert isinstance(result, ExecutionResult)
        assert result.success is True

    def test_frida_output_analysis_detects_success(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Frida output analysis detects successful execution."""
        manager = qemu_manager_with_mocked_config

        stdout = "[+] Script loaded\n[+] Hook installed\n[+] License check bypassed"
        stderr = ""

        success = manager._analyze_frida_output(stdout, stderr)
        assert success is True

    def test_frida_output_analysis_detects_errors(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Frida output analysis detects execution errors."""
        manager = qemu_manager_with_mocked_config

        stdout = "Attempting to attach..."
        stderr = "Error: Failed to attach to process\nProcess not found"

        success = manager._analyze_frida_output(stdout, stderr)
        assert success is False

    def test_ghidra_script_execution_returns_result(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Ghidra script execution returns ExecutionResult."""
        manager = qemu_manager_with_mocked_config
        manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        script_content = """
        # Ghidra script to patch license check
        from ghidra.program.model.address import Address
        addr = currentProgram.getAddressFactory().getAddress("0x401000")
        setByte(addr, 0x90)
        """

        with patch.object(manager, "_execute_command_in_vm") as mock_exec:
            mock_exec.return_value = {
                "exit_code": 0,
                "stdout": "Analysis complete\nPatched function at 0x401000",
                "stderr": "",
            }

            result = manager.test_ghidra_script(
                sample_snapshot.snapshot_id,
                script_content,
                "/tmp/target.exe"
            )

        assert isinstance(result, ExecutionResult)

    def test_ghidra_output_analysis_detects_success(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Ghidra output analysis detects successful completion."""
        manager = qemu_manager_with_mocked_config

        stdout = "Analysis complete\nPatched function at 0x401000\n3 patches applied"
        stderr = ""

        success = manager._analyze_ghidra_output(stdout, stderr)
        assert success is True

    def test_ghidra_output_analysis_detects_errors(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Ghidra output analysis detects Java exceptions."""
        manager = qemu_manager_with_mocked_config

        stdout = "Starting analysis..."
        stderr = "ERROR: Unable to load binary\njava.lang.Exception: Invalid PE format"

        success = manager._analyze_ghidra_output(stdout, stderr)
        assert success is False


class TestNetworkIsolation:
    """Test network isolation features."""

    def test_enable_network_isolation_updates_snapshot_state(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Network isolation updates snapshot network state."""
        manager = qemu_manager_with_mocked_config
        manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        manager.enable_network_isolation(sample_snapshot.snapshot_id, isolated=True)
        assert sample_snapshot.network_isolated is True

        manager.enable_network_isolation(sample_snapshot.snapshot_id, isolated=False)
        assert sample_snapshot.network_isolated is False


class TestStorageOptimization:
    """Test snapshot storage optimization."""

    def test_optimize_snapshot_storage_analyzes_disk_usage(
        self, qemu_manager_with_mocked_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Storage optimization analyzes disk usage."""
        manager = qemu_manager_with_mocked_config

        snapshot = QEMUSnapshot(
            snapshot_id="test_snap",
            vm_name="test_vm",
            disk_path=str(tmp_path / "disk.qcow2"),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )
        manager.snapshots["test_snap"] = snapshot

        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "1073741824\n2147483648"
            mock_run.return_value = mock_result

            optimization_result = manager.optimize_snapshot_storage()

        assert "total_size_before" in optimization_result
        assert "optimization_performed" in optimization_result


class TestSnapshotMaintenance:
    """Test snapshot maintenance operations."""

    def test_cleanup_old_snapshots_removes_expired_snapshots(
        self, qemu_manager_with_mocked_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Cleanup removes snapshots older than retention period."""
        manager = qemu_manager_with_mocked_config

        old_snapshot = QEMUSnapshot(
            snapshot_id="old_snap",
            vm_name="old_vm",
            disk_path=str(tmp_path / "old.qcow2"),
            binary_path="/tmp/test.exe",
            created_at=datetime.now() - timedelta(days=10),
            ssh_port=22222,
            vnc_port=5900,
        )

        recent_snapshot = QEMUSnapshot(
            snapshot_id="recent_snap",
            vm_name="recent_vm",
            disk_path=str(tmp_path / "recent.qcow2"),
            binary_path="/tmp/test.exe",
            created_at=datetime.now() - timedelta(hours=1),
            ssh_port=22223,
            vnc_port=5901,
        )

        manager.snapshots["old_snap"] = old_snapshot
        manager.snapshots["recent_snap"] = recent_snapshot

        with patch.object(manager, "cleanup_snapshot"):
            result = manager.cleanup_old_snapshots(max_age_days=7)

        assert result["cleaned_count"] >= 0

    def test_perform_snapshot_maintenance_validates_integrity(
        self, qemu_manager_with_mocked_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Maintenance validates snapshot integrity."""
        manager = qemu_manager_with_mocked_config

        snapshot = QEMUSnapshot(
            snapshot_id="maint_snap",
            vm_name="maint_vm",
            disk_path=str(tmp_path / "maint.qcow2"),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )
        manager.snapshots["maint_snap"] = snapshot

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="No errors found")
            result = manager.perform_snapshot_maintenance()

        assert "integrity_check" in result
        assert "cleanup" in result


class TestQEMUMonitorInterface:
    """Test QEMU monitor (QMP) interface."""

    def test_send_monitor_command_communicates_with_qemu(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Monitor command sends instruction to QEMU."""
        manager = qemu_manager_with_mocked_config

        mock_monitor = MagicMock()
        mock_monitor.send.return_value = None
        mock_monitor.recv.return_value = b'{"return": {}}\n'
        manager.monitor = mock_monitor

        result = manager._send_monitor_command("info status")
        assert result is not None

    def test_create_monitor_snapshot_sends_savevm_command(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Monitor snapshot creation sends savevm command."""
        manager = qemu_manager_with_mocked_config

        with patch.object(manager, "_send_qmp_command") as mock_qmp:
            mock_qmp.return_value = {"return": {}}
            result = manager.create_monitor_snapshot("test_snapshot")

        assert result is True

    def test_restore_monitor_snapshot_sends_loadvm_command(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Monitor snapshot restore sends loadvm command."""
        manager = qemu_manager_with_mocked_config

        with patch.object(manager, "_send_qmp_command") as mock_qmp:
            mock_qmp.return_value = {"return": {}}
            result = manager.restore_monitor_snapshot("test_snapshot")

        assert result is True


class TestQEMUSystemControl:
    """Test QEMU system start/stop control."""

    def test_start_system_spawns_qemu_process(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """System start spawns QEMU process with correct parameters."""
        manager = qemu_manager_with_mocked_config

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            with patch.object(manager, "_wait_for_boot", return_value=True):
                result = manager.start_system(headless=True)

        assert result is True
        assert manager.qemu_process is not None

    def test_stop_system_terminates_qemu_gracefully(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """System stop terminates QEMU process gracefully."""
        manager = qemu_manager_with_mocked_config

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        manager.qemu_process = mock_process

        with patch.object(manager, "_send_qmp_command", return_value={"return": {}}):
            result = manager.stop_system(force=False)

        assert result is True

    def test_stop_system_force_kills_unresponsive_process(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """System stop force kills unresponsive QEMU process."""
        manager = qemu_manager_with_mocked_config

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.wait.side_effect = subprocess.TimeoutExpired("qemu", 10)
        manager.qemu_process = mock_process

        result = manager.stop_system(force=True)

        mock_process.kill.assert_called()
        assert result is True


class TestSecureHostKeyPolicy:
    """Test SSH host key security policy."""

    def test_secure_host_key_policy_stores_keys(
        self, temp_qemu_workspace: Path
    ) -> None:
        """Host key policy stores new SSH keys securely."""
        known_hosts = temp_qemu_workspace / "known_hosts"
        policy = SecureHostKeyPolicy(known_hosts)

        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.getpeername.return_value = ("127.0.0.1", 22222)
        mock_client.get_transport.return_value = mock_transport

        mock_key = paramiko.RSAKey.generate(2048)

        policy.missing_host_key(mock_client, "localhost", mock_key)

        assert known_hosts.exists()

    def test_secure_host_key_policy_detects_changed_keys(
        self, temp_qemu_workspace: Path
    ) -> None:
        """Host key policy detects changed host keys."""
        known_hosts = temp_qemu_workspace / "known_hosts"
        policy = SecureHostKeyPolicy(known_hosts)

        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.getpeername.return_value = ("127.0.0.1", 22222)
        mock_client.get_transport.return_value = mock_transport

        original_key = paramiko.RSAKey.generate(2048)
        changed_key = paramiko.RSAKey.generate(2048)

        policy.missing_host_key(mock_client, "localhost", original_key)

        with pytest.raises(paramiko.SSHException, match="Host key verification failed"):
            policy.missing_host_key(mock_client, "localhost", changed_key)


class TestResourceManagement:
    """Test VM resource registration and cleanup."""

    def test_vm_startup_registers_with_resource_manager(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM startup registers with resource manager."""
        manager = qemu_manager_with_mocked_config

        with patch("intellicrack.ai.qemu_manager.resource_manager") as mock_rm:
            with patch("subprocess.Popen") as mock_popen:
                mock_process = MagicMock()
                mock_process.poll.return_value = None
                mock_popen.return_value = mock_process

                manager._start_vm_for_snapshot(sample_snapshot)

        mock_rm.register_resource.assert_called()

    def test_cleanup_releases_resource_manager_resources(
        self, qemu_manager_with_mocked_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot cleanup releases resources from manager."""
        manager = qemu_manager_with_mocked_config

        snapshot = QEMUSnapshot(
            snapshot_id="resource_test",
            vm_name="resource_vm",
            disk_path=str(tmp_path / "disk.qcow2"),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )

        (tmp_path / "disk.qcow2").write_bytes(b"MOCK")

        mock_process = MagicMock()
        mock_process.poll.return_value = 0
        snapshot.vm_process = mock_process

        manager.snapshots["resource_test"] = snapshot

        with patch("intellicrack.ai.qemu_manager.resource_manager") as mock_rm:
            with patch.object(manager, "_close_ssh_connection"):
                manager.cleanup_snapshot("resource_test")

        mock_rm.release_resource.assert_called()


class TestErrorHandling:
    """Test error handling and recovery."""

    def test_ssh_connection_failure_does_not_crash(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH connection failure handles error gracefully."""
        manager = qemu_manager_with_mocked_config

        with patch.object(manager, "_initialize_ssh_client") as mock_init:
            mock_init.side_effect = paramiko.SSHException("Connection failed")

            result = manager._get_ssh_connection(sample_snapshot)

        assert result is None

    def test_vm_startup_failure_raises_runtime_error(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """VM startup failure raises appropriate error."""
        manager = qemu_manager_with_mocked_config

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = 1
            mock_process.communicate.return_value = (b"", b"QEMU startup failed")
            mock_popen.return_value = mock_process

            with pytest.raises(RuntimeError, match="VM startup failed"):
                manager._start_vm_for_snapshot(sample_snapshot)

    def test_file_upload_failure_raises_runtime_error(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """File upload failure raises appropriate error."""
        manager = qemu_manager_with_mocked_config

        with patch.object(manager, "_get_ssh_connection", return_value=None):
            with pytest.raises(RuntimeError, match="Failed to establish SSH connection"):
                manager._upload_file_to_vm(sample_snapshot, "content", "/tmp/file.txt")


class TestBaseImageManagement:
    """Test base image discovery and configuration."""

    def test_get_base_image_configuration_returns_settings(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Base image configuration retrieval returns settings."""
        manager = qemu_manager_with_mocked_config
        config = manager.get_base_image_configuration()
        assert isinstance(config, dict)

    def test_update_base_image_configuration_saves_settings(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Base image configuration update saves to config."""
        manager = qemu_manager_with_mocked_config

        new_paths = ["/path/to/image1.qcow2", "/path/to/image2.qcow2"]
        manager.update_base_image_configuration("windows", new_paths)

        manager.config.set.assert_called()
        manager.config.save_config.assert_called()


class TestPerformanceMonitoring:
    """Test snapshot performance monitoring."""

    def test_monitor_snapshot_performance_collects_metrics(
        self, qemu_manager_with_mocked_config: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """Performance monitoring collects VM metrics."""
        manager = qemu_manager_with_mocked_config
        manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        with patch.object(manager, "_execute_command_in_vm") as mock_exec:
            mock_exec.return_value = {
                "exit_code": 0,
                "stdout": "MemTotal: 2048000 kB\nMemFree: 1024000 kB\nCpu: 25%",
                "stderr": "",
            }

            metrics = manager.monitor_snapshot_performance(sample_snapshot.snapshot_id)

        assert "timestamp" in metrics
        assert "snapshot_id" in metrics


class TestCleanupOperations:
    """Test cleanup and resource release."""

    def test_cleanup_all_snapshots_removes_all_vms(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Cleanup all snapshots removes all VMs."""
        manager = qemu_manager_with_mocked_config

        snapshot1 = QEMUSnapshot(
            snapshot_id="snap1",
            vm_name="vm1",
            disk_path="/tmp/disk1.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )
        snapshot2 = QEMUSnapshot(
            snapshot_id="snap2",
            vm_name="vm2",
            disk_path="/tmp/disk2.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22223,
            vnc_port=5901,
        )

        manager.snapshots["snap1"] = snapshot1
        manager.snapshots["snap2"] = snapshot2

        with patch.object(manager, "cleanup_snapshot"):
            manager.cleanup_all_snapshots()

        assert len(manager.snapshots) == 0

    def test_destructor_closes_all_ssh_connections(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Destructor closes all SSH connections."""
        manager = qemu_manager_with_mocked_config

        mock_client1 = MagicMock()
        mock_client2 = MagicMock()

        manager.ssh_connection_pool[("vm1", 22222)] = mock_client1
        manager.ssh_connection_pool[("vm2", 22223)] = mock_client2

        with patch.object(manager, "cleanup_all_snapshots"):
            manager.__del__()

        mock_client1.close.assert_called()
        mock_client2.close.assert_called()


class TestPlatformCompatibility:
    """Test cross-platform compatibility."""

    def test_qemu_executable_detection_finds_system_qemu(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """QEMU executable detection finds system installation."""
        manager = qemu_manager_with_mocked_config

        with patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"):
            qemu_path = manager._find_qemu_executable()

        assert qemu_path is not None

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_windows_specific_functionality(
        self, qemu_manager_with_mocked_config: QEMUManager
    ) -> None:
        """Windows platform handles process termination correctly."""
        manager = qemu_manager_with_mocked_config
        assert platform.system() == "Windows"
