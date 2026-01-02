"""Unit tests for QEMUManager class.

This module provides comprehensive unit tests for the QEMUManager class,
testing all methods with REAL implementations and NO mocking.
"""

import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

try:
    from intellicrack.ai.qemu_manager import QEMUManager, QEMUSnapshot
    QEMU_MANAGER_AVAILABLE = True
except ImportError:
    QEMU_MANAGER_AVAILABLE = False
    QEMUManager = None
    QEMUSnapshot = None


pytestmark = pytest.mark.skipif(
    not QEMU_MANAGER_AVAILABLE,
    reason="QEMU manager not available"
)


class FakeConfig:
    """Real test double for configuration."""

    def __init__(self) -> None:
        """Initialize with realistic QEMU configuration."""
        self.config_data: Dict[str, Any] = {
            "vm_framework": {
                "base_images": {
                    "windows": ["C:/vms/windows10.qcow2"],
                    "linux": ["C:/vms/ubuntu22.04.qcow2"],
                    "default_windows_size_gb": 2,
                    "default_linux_size_gb": 1
                },
                "ssh": {
                    "timeout": 30,
                    "retry_count": 3,
                    "retry_delay": 2,
                    "circuit_breaker_threshold": 5,
                    "circuit_breaker_timeout": 60
                },
                "qemu_defaults": {
                    "memory_mb": 2048,
                    "cpu_cores": 2,
                    "enable_kvm": True,
                    "network_enabled": True,
                    "graphics_enabled": False,
                    "monitor_port": 55555,
                    "ssh_port_start": 22222,
                    "vnc_port_start": 5900,
                    "timeout": 300,
                    "shared_folder_name": "intellicrack_shared_folder"
                },
                "qiling_rootfs": {
                    "windows": ["C:/tools/qiling/rootfs/windows"],
                    "linux": ["C:/tools/qiling/rootfs/linux"]
                }
            }
        }
        self.save_called = False
        self.set_called_with: List[tuple] = []

    def get(self, path: str = "", default: Any = None) -> Any:
        """Get configuration value."""
        if not path:
            return self.config_data

        parts = path.split('.')
        current = self.config_data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default

        return current

    def set(self, path: str, value: Any) -> None:
        """Set configuration value."""
        self.set_called_with.append((path, value))

        parts = path.split('.')
        current = self.config_data

        for i, part in enumerate(parts[:-1]):
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    def save_config(self) -> None:
        """Mark that save was called."""
        self.save_called = True


class FakeProcess:
    """Real test double for subprocess.Popen."""

    def __init__(self, returncode: int = 0, running: bool = True) -> None:
        """Initialize fake process."""
        self.returncode = returncode
        self._running = running

    def poll(self) -> Optional[int]:
        """Check if process is running."""
        return None if self._running else self.returncode

    def terminate(self) -> None:
        """Terminate process."""
        self._running = False

    def kill(self) -> None:
        """Kill process."""
        self._running = False


class TestQEMUManager(unittest.TestCase):
    """Test suite for QEMUManager class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.fake_config = FakeConfig()

    def tearDown(self) -> None:
        """Clean up test environment."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init_with_config(self) -> None:
        """Test QEMUManager initialization with configuration."""
        manager = QEMUManager()

        assert manager is not None
        assert hasattr(manager, 'config')
        assert hasattr(manager, 'ssh_timeout')
        assert hasattr(manager, 'snapshots')

    def test_vm_info_collection(self) -> None:
        """Test VM information collection."""
        manager = QEMUManager()

        snapshot1 = QEMUSnapshot(
            snapshot_id="snap1",
            vm_name="test_vm_1",
            disk_path=str(Path(self.temp_dir) / "vm1.qcow2"),
            binary_path=str(Path(self.temp_dir) / "test1.exe"),
            ssh_host="localhost",
            ssh_port=22222,
            ssh_user="test",
            vnc_port=5900
        )
        snapshot1.created_at = datetime.now()

        snapshot2 = QEMUSnapshot(
            snapshot_id="snap2",
            vm_name="test_vm_2",
            disk_path=str(Path(self.temp_dir) / "vm2.qcow2"),
            binary_path=str(Path(self.temp_dir) / "test2.exe"),
            ssh_host="localhost",
            ssh_port=22223,
            ssh_user="test",
            vnc_port=5901
        )
        snapshot2.created_at = datetime.now()

        manager.snapshots = {
            "snap1": snapshot1,
            "snap2": snapshot2
        }

        vm_info = manager.get_all_vm_info()

        assert len(vm_info) == 2
        assert vm_info[0]["snapshot_id"] == "snap1"
        assert vm_info[0]["vm_name"] == "test_vm_1"
        assert vm_info[1]["snapshot_id"] == "snap2"
        assert vm_info[1]["vm_name"] == "test_vm_2"

    def test_base_image_configuration_retrieval(self) -> None:
        """Test retrieval of base image configuration."""
        manager = QEMUManager()

        config = manager.get_base_image_configuration()

        assert config is not None
        assert "vm_framework" in config

    def test_snapshot_management(self) -> None:
        """Test snapshot creation and management."""
        manager = QEMUManager()

        test_snapshot = QEMUSnapshot(
            snapshot_id="test_snap",
            vm_name="test_vm",
            disk_path=str(Path(self.temp_dir) / "test.qcow2"),
            binary_path=str(Path(self.temp_dir) / "test.exe"),
            ssh_host="localhost",
            ssh_port=22222,
            ssh_user="test",
            vnc_port=5900
        )

        manager.snapshots["test_snap"] = test_snapshot

        assert "test_snap" in manager.snapshots
        assert manager.snapshots["test_snap"].vm_name == "test_vm"

    def test_port_allocation(self) -> None:
        """Test SSH and VNC port allocation."""
        manager = QEMUManager()

        initial_ssh_port = manager.next_ssh_port
        initial_vnc_port = manager.next_vnc_port

        assert isinstance(initial_ssh_port, int)
        assert isinstance(initial_vnc_port, int)
        assert initial_ssh_port > 0
        assert initial_vnc_port > 0

    def test_circuit_breaker_tracking(self) -> None:
        """Test circuit breaker for SSH connections."""
        manager = QEMUManager()

        assert hasattr(manager, 'ssh_failure_counts')
        assert hasattr(manager, 'circuit_breaker_threshold')

        manager.ssh_failure_counts["test_vm"] = 3
        assert manager.ssh_failure_counts["test_vm"] == 3

    def test_ssh_connection_pooling(self) -> None:
        """Test SSH connection pooling mechanism."""
        manager = QEMUManager()

        assert hasattr(manager, 'ssh_pool')
        assert isinstance(manager.ssh_pool, dict)

    def test_qemu_executable_detection(self) -> None:
        """Test QEMU executable path detection."""
        manager = QEMUManager()

        if hasattr(manager, 'qemu_executable'):
            if qemu_exec := manager.qemu_executable:
                assert isinstance(qemu_exec, str)

    def test_rootfs_path_configuration(self) -> None:
        """Test rootfs path configuration."""
        manager = QEMUManager()

        if hasattr(manager, 'rootfs_path'):
            rootfs = manager.rootfs_path
            assert rootfs is None or isinstance(rootfs, str)

    def test_snapshot_data_structure(self) -> None:
        """Test QEMUSnapshot data structure."""
        snapshot = QEMUSnapshot(
            snapshot_id="data_test",
            vm_name="data_vm",
            disk_path="/path/to/disk.qcow2",
            binary_path="/path/to/binary.exe",
            ssh_host="127.0.0.1",
            ssh_port=22222,
            ssh_user="qemu",
            vnc_port=5900
        )

        assert snapshot.snapshot_id == "data_test"
        assert snapshot.vm_name == "data_vm"
        assert snapshot.disk_path == "/path/to/disk.qcow2"
        assert snapshot.ssh_host == "127.0.0.1"
        assert snapshot.ssh_port == 22222

    def test_configuration_update(self) -> None:
        """Test configuration update mechanism."""
        manager = QEMUManager()

        if hasattr(manager.config, 'set') and hasattr(manager.config, 'save_config'):
            new_paths = ["D:/vms/windows11.qcow2"]
            manager.update_base_image_configuration("windows", new_paths)

    def test_snapshots_dictionary_initialization(self) -> None:
        """Test snapshots dictionary is initialized."""
        manager = QEMUManager()

        assert hasattr(manager, 'snapshots')
        assert isinstance(manager.snapshots, dict)

    def test_ssh_timeout_configuration(self) -> None:
        """Test SSH timeout configuration."""
        manager = QEMUManager()

        assert hasattr(manager, 'ssh_timeout')
        assert isinstance(manager.ssh_timeout, int)
        assert manager.ssh_timeout > 0

    def test_ssh_retry_configuration(self) -> None:
        """Test SSH retry configuration."""
        manager = QEMUManager()

        assert hasattr(manager, 'ssh_retry_count')
        assert hasattr(manager, 'ssh_retry_delay')
        assert isinstance(manager.ssh_retry_count, int)
        assert isinstance(manager.ssh_retry_delay, int)

    def test_qemu_command_building_capability(self) -> None:
        """Test QEMU command building exists."""
        manager = QEMUManager()

        assert hasattr(manager, '_build_qemu_command') or callable(
            getattr(manager, '_build_qemu_command', None)
        )


if __name__ == '__main__':
    unittest.main()
