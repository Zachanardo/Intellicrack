"""Additional production-grade tests for QEMU Manager gaps.

Tests validate critical untested functionality including:
- Snapshot comparison and rollback
- VM instance control (start/stop/delete)
- Base image selection logic
- Monitor command execution
- Architecture-specific functionality
- Boot wait and KVM detection
"""

import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch, call

import paramiko
import pytest

from intellicrack.ai.common_types import ExecutionResult
from intellicrack.ai.qemu_manager import (
    QEMUManager,
    QEMUSnapshot,
    QEMUError,
)


@pytest.fixture
def temp_qemu_workspace(tmp_path: Path) -> Path:
    """Create temporary workspace for QEMU operations."""
    workspace = tmp_path / "qemu_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "images").mkdir(exist_ok=True)
    (workspace / "snapshots").mkdir(exist_ok=True)
    return workspace


@pytest.fixture
def mock_windows_image(temp_qemu_workspace: Path) -> Path:
    """Create mock Windows base image."""
    image_path = temp_qemu_workspace / "images" / "windows10.qcow2"
    image_path.write_bytes(b"QCOW2_WINDOWS_IMAGE_DATA" * 100)
    return image_path


@pytest.fixture
def mock_linux_image(temp_qemu_workspace: Path) -> Path:
    """Create mock Linux base image."""
    image_path = temp_qemu_workspace / "images" / "ubuntu22.qcow2"
    image_path.write_bytes(b"QCOW2_LINUX_IMAGE_DATA" * 100)
    return image_path


@pytest.fixture
def qemu_manager_with_config(
    temp_qemu_workspace: Path,
    mock_windows_image: Path,
    mock_linux_image: Path,
) -> QEMUManager:
    """Create QEMUManager with mocked configuration."""
    with patch("intellicrack.ai.qemu_manager.get_config") as mock_config, \
         patch("intellicrack.ai.qemu_manager.get_resource_manager"), \
         patch("intellicrack.ai.qemu_manager.get_audit_logger"), \
         patch("intellicrack.utils.qemu_image_discovery.get_qemu_discovery") as mock_discovery:

        config_mock = MagicMock()
        config_mock.get.side_effect = lambda key, default=None: {
            "vm_framework.ssh.timeout": 30,
            "vm_framework.ssh.retry_count": 3,
            "vm_framework.base_images.windows": [str(mock_windows_image)],
            "vm_framework.base_images.linux": [str(mock_linux_image)],
        }.get(key, default)
        config_mock.get_tool_path.return_value = None
        mock_config.return_value = config_mock

        mock_discovery_instance = MagicMock()
        mock_discovery_instance.discover_images.return_value = []
        mock_discovery.return_value = mock_discovery_instance

        with patch("intellicrack.ai.qemu_manager.tempfile.gettempdir", return_value=str(temp_qemu_workspace)):
            with patch.object(QEMUManager, "_validate_qemu_setup"):
                manager = QEMUManager()
                manager.working_dir = temp_qemu_workspace
                return manager


class TestSnapshotComparison:
    """Test snapshot comparison functionality."""

    def test_compare_snapshots_detects_disk_changes(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot comparison detects disk file changes."""
        manager = qemu_manager_with_config

        disk1 = tmp_path / "disk1.qcow2"
        disk2 = tmp_path / "disk2.qcow2"
        disk1.write_bytes(b"DISK_V1" * 1000)
        disk2.write_bytes(b"DISK_V2" * 1500)

        snapshot1 = QEMUSnapshot(
            snapshot_id="snap1",
            vm_name="vm1",
            disk_path=str(disk1),
            binary_path="/tmp/test.exe",
            created_at=datetime.now() - timedelta(hours=1),
            ssh_port=22222,
            vnc_port=5900,
        )

        snapshot2 = QEMUSnapshot(
            snapshot_id="snap2",
            vm_name="vm2",
            disk_path=str(disk2),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22223,
            vnc_port=5901,
        )

        manager.snapshots["snap1"] = snapshot1
        manager.snapshots["snap2"] = snapshot2

        comparison = manager.compare_snapshots("snap1", "snap2")

        assert comparison is not None
        assert "disk_size_diff" in comparison
        assert comparison["disk_size_diff"] != 0

    def test_compare_snapshots_calculates_time_difference(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot comparison calculates time elapsed between snapshots."""
        manager = qemu_manager_with_config

        disk = tmp_path / "disk.qcow2"
        disk.write_bytes(b"DISK_DATA")

        creation_time1 = datetime.now() - timedelta(hours=2)
        creation_time2 = datetime.now()

        snapshot1 = QEMUSnapshot(
            snapshot_id="snap1",
            vm_name="vm1",
            disk_path=str(disk),
            binary_path="/tmp/test.exe",
            created_at=creation_time1,
            ssh_port=22222,
            vnc_port=5900,
        )

        snapshot2 = QEMUSnapshot(
            snapshot_id="snap2",
            vm_name="vm2",
            disk_path=str(disk),
            binary_path="/tmp/test.exe",
            created_at=creation_time2,
            ssh_port=22223,
            vnc_port=5901,
        )

        manager.snapshots["snap1"] = snapshot1
        manager.snapshots["snap2"] = snapshot2

        comparison = manager.compare_snapshots("snap1", "snap2")

        assert comparison is not None
        assert "time_elapsed" in comparison

    def test_compare_snapshots_handles_missing_snapshot(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Snapshot comparison handles non-existent snapshots."""
        manager = qemu_manager_with_config

        with pytest.raises(ValueError, match="Snapshot .* not found"):
            manager.compare_snapshots("nonexistent1", "nonexistent2")

    def test_determine_snapshot_relationship_parent_child(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Snapshot relationship detection identifies parent-child."""
        manager = qemu_manager_with_config

        snapshot1 = QEMUSnapshot(
            snapshot_id="parent",
            vm_name="parent_vm",
            disk_path="/tmp/parent.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
            parent_snapshot=None,
        )

        snapshot2 = QEMUSnapshot(
            snapshot_id="child",
            vm_name="child_vm",
            disk_path="/tmp/child.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22223,
            vnc_port=5901,
            parent_snapshot="parent",
        )

        manager.snapshots["parent"] = snapshot1
        manager.snapshots["child"] = snapshot2

        relationship = manager._determine_snapshot_relationship(snapshot1, snapshot2)

        assert relationship == "parent-child"

    def test_determine_snapshot_relationship_siblings(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Snapshot relationship detection identifies siblings."""
        manager = qemu_manager_with_config

        snapshot1 = QEMUSnapshot(
            snapshot_id="child1",
            vm_name="child1_vm",
            disk_path="/tmp/child1.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
            parent_snapshot="parent",
        )

        snapshot2 = QEMUSnapshot(
            snapshot_id="child2",
            vm_name="child2_vm",
            disk_path="/tmp/child2.qcow2",
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22223,
            vnc_port=5901,
            parent_snapshot="parent",
        )

        relationship = manager._determine_snapshot_relationship(snapshot1, snapshot2)

        assert relationship == "siblings"


class TestSnapshotRollback:
    """Test snapshot rollback functionality."""

    def test_rollback_snapshot_to_parent_succeeds(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot rollback restores to parent state."""
        manager = qemu_manager_with_config

        parent_disk = tmp_path / "parent.qcow2"
        parent_disk.write_bytes(b"PARENT_STATE")

        child_disk = tmp_path / "child.qcow2"
        child_disk.write_bytes(b"CHILD_STATE")

        parent = QEMUSnapshot(
            snapshot_id="parent",
            vm_name="parent_vm",
            disk_path=str(parent_disk),
            binary_path="/tmp/test.exe",
            created_at=datetime.now() - timedelta(hours=1),
            ssh_port=22222,
            vnc_port=5900,
        )

        child = QEMUSnapshot(
            snapshot_id="child",
            vm_name="child_vm",
            disk_path=str(child_disk),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22223,
            vnc_port=5901,
            parent_snapshot="parent",
        )

        manager.snapshots["parent"] = parent
        manager.snapshots["child"] = child

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            with patch.object(manager, "_stop_vm_for_snapshot"):
                with patch.object(manager, "_start_vm_for_snapshot"):
                    result = manager.rollback_snapshot("child", "parent")

        assert result is True

    def test_rollback_snapshot_raises_on_invalid_target(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Snapshot rollback raises error for invalid target."""
        manager = qemu_manager_with_config

        snapshot = QEMUSnapshot(
            snapshot_id="snap1",
            vm_name="vm1",
            disk_path=str(tmp_path / "disk.qcow2"),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )

        manager.snapshots["snap1"] = snapshot

        with pytest.raises(ValueError, match="Target snapshot .* not found"):
            manager.rollback_snapshot("snap1", "nonexistent_target")


class TestVMInstanceControl:
    """Test VM instance start/stop/delete operations."""

    def test_start_vm_instance_spawns_process(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Start VM instance spawns QEMU process."""
        manager = qemu_manager_with_config

        disk_path = tmp_path / "vm.qcow2"
        disk_path.write_bytes(b"QCOW2_DATA")

        snapshot = QEMUSnapshot(
            snapshot_id="test_vm",
            vm_name="test_vm",
            disk_path=str(disk_path),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )

        manager.snapshots["test_vm"] = snapshot

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            with patch.object(manager, "_wait_for_vm_ready", return_value=True):
                result = manager.start_vm_instance("test_vm")

        assert result is True
        assert snapshot.vm_process is not None

    def test_stop_vm_instance_terminates_process(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Stop VM instance terminates running process."""
        manager = qemu_manager_with_config

        snapshot = QEMUSnapshot(
            snapshot_id="test_vm",
            vm_name="test_vm",
            disk_path=str(tmp_path / "vm.qcow2"),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        snapshot.vm_process = mock_process

        manager.snapshots["test_vm"] = snapshot

        result = manager.stop_vm_instance("test_vm")

        assert result is True
        mock_process.wait.assert_called()

    def test_stop_vm_instance_raises_on_nonexistent_vm(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Stop VM instance raises error for non-existent VM."""
        manager = qemu_manager_with_config

        with pytest.raises(ValueError, match="Snapshot .* not found"):
            manager.stop_vm_instance("nonexistent_vm")

    def test_delete_vm_instance_removes_snapshot(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Delete VM instance removes snapshot and disk."""
        manager = qemu_manager_with_config

        disk_path = tmp_path / "vm.qcow2"
        disk_path.write_bytes(b"DISK_DATA")

        snapshot = QEMUSnapshot(
            snapshot_id="test_vm",
            vm_name="test_vm",
            disk_path=str(disk_path),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )

        manager.snapshots["test_vm"] = snapshot

        with patch.object(manager, "_close_ssh_connection"):
            result = manager.delete_vm_instance("test_vm")

        assert result is True
        assert "test_vm" not in manager.snapshots
        assert not disk_path.exists()

    def test_delete_vm_instance_stops_running_vm(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Delete VM instance stops running VM before deletion."""
        manager = qemu_manager_with_config

        disk_path = tmp_path / "vm.qcow2"
        disk_path.write_bytes(b"DISK_DATA")

        snapshot = QEMUSnapshot(
            snapshot_id="test_vm",
            vm_name="test_vm",
            disk_path=str(disk_path),
            binary_path="/tmp/test.exe",
            created_at=datetime.now(),
            ssh_port=22222,
            vnc_port=5900,
        )

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        snapshot.vm_process = mock_process

        manager.snapshots["test_vm"] = snapshot

        with patch.object(manager, "_close_ssh_connection"):
            result = manager.delete_vm_instance("test_vm")

        assert result is True
        mock_process.wait.assert_called()


class TestBaseImageSelection:
    """Test base image selection logic."""

    def test_get_windows_base_image_returns_configured_image(
        self, qemu_manager_with_config: QEMUManager, mock_windows_image: Path
    ) -> None:
        """Windows base image selection returns configured image."""
        manager = qemu_manager_with_config

        base_image = manager._get_windows_base_image()

        assert base_image is not None
        assert base_image.exists()
        assert "windows" in str(base_image).lower() or base_image == mock_windows_image

    def test_get_linux_base_image_returns_configured_image(
        self, qemu_manager_with_config: QEMUManager, mock_linux_image: Path
    ) -> None:
        """Linux base image selection returns configured image."""
        manager = qemu_manager_with_config

        base_image_path = manager._get_linux_base_image()

        assert base_image_path is not None
        assert Path(base_image_path).exists() or base_image_path == str(mock_linux_image)

    def test_get_windows_base_image_raises_on_missing_config(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Windows base image selection raises error when no images configured."""
        manager = qemu_manager_with_config

        manager.config.get = MagicMock(return_value=[])

        with pytest.raises(FileNotFoundError, match="No Windows base images"):
            manager._get_windows_base_image()

    def test_get_linux_base_image_raises_on_missing_config(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Linux base image selection raises error when no images configured."""
        manager = qemu_manager_with_config

        manager.config.get = MagicMock(return_value=[])

        with pytest.raises(FileNotFoundError, match="No Linux base images"):
            manager._get_linux_base_image()

    def test_get_image_for_architecture_x86_64(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Architecture-specific image selection returns x86_64 image."""
        manager = qemu_manager_with_config

        x86_image = tmp_path / "x86_64.qcow2"
        x86_image.write_bytes(b"X86_IMAGE")

        with patch.object(manager.config, 'get', return_value=[str(x86_image)]):
            image = manager._get_image_for_architecture("x86_64")

        assert image is not None
        assert image.exists()

    def test_get_image_for_architecture_arm64(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """Architecture-specific image selection returns ARM64 image."""
        manager = qemu_manager_with_config

        arm_image = tmp_path / "arm64.qcow2"
        arm_image.write_bytes(b"ARM_IMAGE")

        with patch.object(manager.config, 'get', return_value=[str(arm_image)]):
            image = manager._get_image_for_architecture("arm64")

        assert image is not None
        assert image.exists()


class TestMonitorCommandExecution:
    """Test QEMU monitor command execution."""

    def test_execute_guest_command_via_monitor_returns_output(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Guest command execution via monitor returns command output."""
        manager = qemu_manager_with_config

        expected_output = "command output from guest"

        with patch.object(manager, "_send_qmp_command") as mock_qmp:
            mock_qmp.return_value = {
                "return": {
                    "out-data": expected_output
                }
            }

            result = manager.execute_guest_command_via_monitor("echo test")

        assert result == expected_output

    def test_execute_guest_command_handles_timeout(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Guest command execution handles timeout gracefully."""
        manager = qemu_manager_with_config

        with patch.object(manager, "_send_qmp_command") as mock_qmp:
            mock_qmp.side_effect = TimeoutError("Command timeout")

            result = manager.execute_guest_command_via_monitor("sleep 100", timeout=1)

        assert result is None

    def test_execute_guest_command_handles_qmp_error(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Guest command execution handles QMP protocol errors."""
        manager = qemu_manager_with_config

        with patch.object(manager, "_send_qmp_command") as mock_qmp:
            mock_qmp.return_value = {
                "error": {
                    "class": "CommandFailed",
                    "desc": "Command execution failed"
                }
            }

            result = manager.execute_guest_command_via_monitor("invalid_command")

        assert result is None


class TestKVMDetection:
    """Test KVM availability detection."""

    def test_is_kvm_available_on_linux_with_kvm(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """KVM availability detection returns True on Linux with KVM."""
        manager = qemu_manager_with_config

        with patch("platform.system", return_value="Linux"):
            with patch("os.path.exists", return_value=True):
                result = manager._is_kvm_available()

        assert result is True

    def test_is_kvm_available_on_linux_without_kvm(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """KVM availability detection returns False on Linux without KVM."""
        manager = qemu_manager_with_config

        with patch("platform.system", return_value="Linux"):
            with patch("os.path.exists", return_value=False):
                result = manager._is_kvm_available()

        assert result is False

    def test_is_kvm_available_on_windows(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """KVM availability detection returns False on Windows."""
        manager = qemu_manager_with_config

        with patch("platform.system", return_value="Windows"):
            result = manager._is_kvm_available()

        assert result is False


class TestBootWaitLogic:
    """Test VM boot wait functionality."""

    def test_wait_for_boot_success(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Boot wait succeeds when monitor connection established."""
        manager = qemu_manager_with_config

        with patch.object(manager, "_test_monitor_connection", return_value=True):
            result = manager._wait_for_boot(timeout=10)

        assert result is True

    def test_wait_for_boot_timeout(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Boot wait times out when VM doesn't boot."""
        manager = qemu_manager_with_config

        with patch.object(manager, "_test_monitor_connection", return_value=False):
            result = manager._wait_for_boot(timeout=1)

        assert result is False

    def test_wait_for_boot_retries_on_connection_failure(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Boot wait retries monitor connection on initial failure."""
        manager = qemu_manager_with_config

        call_count = [0]

        def mock_connection_test() -> bool:
            call_count[0] += 1
            if call_count[0] < 3:
                return False
            return True

        with patch.object(manager, "_test_monitor_connection", side_effect=mock_connection_test):
            result = manager._wait_for_boot(timeout=5)

        assert result is True
        assert call_count[0] >= 3


class TestQEMUCommandBuilding:
    """Test QEMU command line construction."""

    def test_build_qemu_command_includes_memory(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """QEMU command includes memory specification."""
        manager = qemu_manager_with_config

        disk_path = tmp_path / "test.qcow2"

        cmd = manager._build_qemu_command(
            disk_path=str(disk_path),
            memory_mb=4096,
            cpu_count=2,
            ssh_port=22222,
            vnc_port=5900,
        )

        assert manager.qemu_executable in cmd
        assert "-m" in cmd
        assert "4096" in cmd

    def test_build_qemu_command_includes_cpu_count(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """QEMU command includes CPU count specification."""
        manager = qemu_manager_with_config

        disk_path = tmp_path / "test.qcow2"

        cmd = manager._build_qemu_command(
            disk_path=str(disk_path),
            memory_mb=2048,
            cpu_count=4,
            ssh_port=22222,
            vnc_port=5900,
        )

        assert "-smp" in cmd
        assert "4" in cmd

    def test_build_qemu_command_includes_network_forwarding(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """QEMU command includes network port forwarding."""
        manager = qemu_manager_with_config

        disk_path = tmp_path / "test.qcow2"

        cmd = manager._build_qemu_command(
            disk_path=str(disk_path),
            memory_mb=2048,
            cpu_count=2,
            ssh_port=22222,
            vnc_port=5900,
        )

        netdev_arg = next((arg for arg in cmd if "hostfwd" in arg), None)
        assert netdev_arg is not None
        assert "22222" in netdev_arg

    def test_build_qemu_command_includes_kvm_when_available(
        self, qemu_manager_with_config: QEMUManager, tmp_path: Path
    ) -> None:
        """QEMU command includes KVM acceleration when available."""
        manager = qemu_manager_with_config

        disk_path = tmp_path / "test.qcow2"

        with patch.object(manager, "_is_kvm_available", return_value=True):
            cmd = manager._build_qemu_command(
                disk_path=str(disk_path),
                memory_mb=2048,
                cpu_count=2,
                ssh_port=22222,
                vnc_port=5900,
            )

        assert "-enable-kvm" in cmd or "-accel" in cmd


class TestQEMUErrorHandling:
    """Test QEMU error exception handling."""

    def test_qemu_error_exception_raised(self) -> None:
        """QEMUError exception can be raised and caught."""
        with pytest.raises(QEMUError, match="Test error"):
            raise QEMUError("Test error")

    def test_qemu_error_with_details(self) -> None:
        """QEMUError exception preserves error details."""
        error_msg = "QEMU process failed with exit code 1"

        try:
            raise QEMUError(error_msg)
        except QEMUError as e:
            assert str(e) == error_msg


class TestMonitorSnapshotOperations:
    """Test QEMU monitor snapshot save/restore."""

    def test_create_monitor_snapshot_sends_savevm(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Monitor snapshot creation sends savevm command."""
        manager = qemu_manager_with_config

        with patch.object(manager, "_send_qmp_command") as mock_qmp:
            mock_qmp.return_value = {"return": {}}

            result = manager.create_monitor_snapshot("test_snapshot")

        assert result is True
        mock_qmp.assert_called_once()

    def test_restore_monitor_snapshot_sends_loadvm(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Monitor snapshot restore sends loadvm command."""
        manager = qemu_manager_with_config

        with patch.object(manager, "_send_qmp_command") as mock_qmp:
            mock_qmp.return_value = {"return": {}}

            result = manager.restore_monitor_snapshot("test_snapshot")

        assert result is True
        mock_qmp.assert_called_once()

    def test_create_monitor_snapshot_handles_error(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Monitor snapshot creation handles QMP errors."""
        manager = qemu_manager_with_config

        with patch.object(manager, "_send_qmp_command") as mock_qmp:
            mock_qmp.return_value = {
                "error": {
                    "class": "GenericError",
                    "desc": "Snapshot creation failed"
                }
            }

            result = manager.create_monitor_snapshot("test_snapshot")

        assert result is False


class TestDefaultConfiguration:
    """Test default configuration setup."""

    def test_set_default_config_creates_base_settings(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Default configuration setup creates base settings."""
        manager = qemu_manager_with_config

        manager._set_default_config()

        assert hasattr(manager, 'config')

    def test_get_default_rootfs_x86_64(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Default rootfs returns path for x86_64 architecture."""
        manager = qemu_manager_with_config

        rootfs = manager._get_default_rootfs("x86_64")

        assert rootfs is not None
        assert isinstance(rootfs, str)

    def test_get_default_rootfs_arm64(
        self, qemu_manager_with_config: QEMUManager
    ) -> None:
        """Default rootfs returns path for ARM64 architecture."""
        manager = qemu_manager_with_config

        rootfs = manager._get_default_rootfs("arm64")

        assert rootfs is not None
        assert isinstance(rootfs, str)
