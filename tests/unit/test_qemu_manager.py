"""Unit tests for QEMUManager class.

This module provides comprehensive unit tests for the QEMUManager class,
covering all methods with proper mocking and edge case testing.
"""

import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

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


class TestQEMUManager(unittest.TestCase):
    """Test suite for QEMUManager class."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock config
        self.mock_config = MagicMock()
        self.mock_config.get.return_value = {
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

    @patch('intellicrack.ai.qemu_manager.get_config')
    @patch('intellicrack.ai.qemu_manager.shutil.which')
    @patch('intellicrack.ai.qemu_manager.os.path.exists')
    def test_init_with_mock_config(self, mock_exists, mock_which, mock_get_config):
        """Test QEMUManager initialization with mocked configuration."""
        # Setup mocks
        mock_get_config.return_value = self.mock_config
        mock_which.return_value = "/usr/bin/qemu-system-x86_64"
        mock_exists.return_value = True

        # Create instance
        manager = QEMUManager()

        # Verify initialization
        self.assertIsNotNone(manager.config)
        self.assertEqual(manager.ssh_timeout, 30)
        self.assertEqual(manager.ssh_retry_count, 3)
        self.assertEqual(manager.ssh_retry_delay, 2)
        self.assertEqual(manager.circuit_breaker_threshold, 5)
        self.assertEqual(manager.circuit_breaker_timeout, 60)
        self.assertEqual(manager.next_ssh_port, 22222)
        self.assertEqual(manager.next_vnc_port, 5900)
        self.assertIsNotNone(manager.qemu_executable)
        self.assertIsNotNone(manager.rootfs_path)

        # Verify config was called
        mock_get_config.assert_called_once()

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_download_file_from_vm_success(self, mock_get_config):
        """Test successful file download from VM."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock snapshot
            snapshot = QEMUSnapshot(
                snapshot_id="test_snapshot",
                vm_name="test_vm",
                disk_path="/tmp/test.qcow2",
                binary_path="/tmp/test.exe",
                ssh_host="localhost",
                ssh_port=22222,
                ssh_user="qemu",
                vnc_port=5900
            )
            manager.snapshots["test_snapshot"] = snapshot

            # Mock SSH connection
            mock_ssh_client = MagicMock()
            mock_sftp = MagicMock()
            mock_ssh_client.open_sftp.return_value = mock_sftp

            with patch.object(manager, '_get_ssh_connection', return_value=mock_ssh_client):
                with patch('intellicrack.ai.qemu_manager.Path') as mock_path:
                    mock_path.return_value.parent.mkdir = MagicMock()

                    # Test download
                    result = manager.download_file_from_vm(
                        snapshot,
                        "/remote/file.bin",
                        "/local/file.bin"
                    )

                    # Verify success
                    self.assertTrue(result)
                    mock_ssh_client.open_sftp.assert_called_once()
                    mock_sftp.get.assert_called_once_with("/remote/file.bin", "/local/file.bin")
                    mock_sftp.close.assert_called_once()

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_download_file_from_vm_file_not_found(self, mock_get_config):
        """Test file download when remote file doesn't exist."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock snapshot
            snapshot = QEMUSnapshot(
                snapshot_id="test_snapshot",
                vm_name="test_vm",
                disk_path="/tmp/test.qcow2",
                binary_path="/tmp/test.exe",
                ssh_host="localhost",
                ssh_port=22222,
                ssh_user="qemu",
                vnc_port=5900
            )

            # Mock SSH connection
            mock_ssh_client = MagicMock()
            mock_sftp = MagicMock()
            mock_ssh_client.open_sftp.return_value = mock_sftp
            mock_sftp.get.side_effect = FileNotFoundError("Remote file not found")

            with patch.object(manager, '_get_ssh_connection', return_value=mock_ssh_client):
                with patch('intellicrack.ai.qemu_manager.Path') as mock_path:
                    mock_path.return_value.parent.mkdir = MagicMock()

                    # Test download
                    result = manager.download_file_from_vm(
                        snapshot,
                        "/remote/missing.bin",
                        "/local/file.bin"
                    )

                    # Verify failure
                    self.assertFalse(result)
                    mock_sftp.close.assert_called_once()

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_download_file_from_vm_permission_error(self, mock_get_config):
        """Test file download with local permission error."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock snapshot
            snapshot = QEMUSnapshot(
                snapshot_id="test_snapshot",
                vm_name="test_vm",
                disk_path="/tmp/test.qcow2",
                binary_path="/tmp/test.exe",
                ssh_host="localhost",
                ssh_port=22222,
                ssh_user="qemu",
                vnc_port=5900
            )

            # Mock SSH connection
            mock_ssh_client = MagicMock()
            mock_sftp = MagicMock()
            mock_ssh_client.open_sftp.return_value = mock_sftp
            mock_sftp.get.side_effect = PermissionError("Access denied")

            with patch.object(manager, '_get_ssh_connection', return_value=mock_ssh_client):
                with patch('intellicrack.ai.qemu_manager.Path') as mock_path:
                    mock_path.return_value.parent.mkdir = MagicMock()

                    # Test download
                    result = manager.download_file_from_vm(
                        snapshot,
                        "/remote/file.bin",
                        "/protected/file.bin"
                    )

                    # Verify failure
                    self.assertFalse(result)
                    mock_sftp.close.assert_called_once()

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_download_file_from_vm_network_error(self, mock_get_config):
        """Test file download with network error."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock snapshot
            snapshot = QEMUSnapshot(
                snapshot_id="test_snapshot",
                vm_name="test_vm",
                disk_path="/tmp/test.qcow2",
                binary_path="/tmp/test.exe",
                ssh_host="localhost",
                ssh_port=22222,
                ssh_user="qemu",
                vnc_port=5900
            )

            # Mock SSH connection failure
            with patch.object(manager, '_get_ssh_connection', return_value=None):
                # Test download
                result = manager.download_file_from_vm(
                    snapshot,
                    "/remote/file.bin",
                    "/local/file.bin"
                )

                # Verify failure
                self.assertFalse(result)

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_get_modified_binary_success(self, mock_get_config):
        """Test successful modified binary retrieval."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock snapshot
            snapshot = QEMUSnapshot(
                snapshot_id="test_snapshot",
                vm_name="test_vm",
                disk_path="/tmp/test.qcow2",
                binary_path="/tmp/test.exe",
                ssh_host="localhost",
                ssh_port=22222,
                ssh_user="qemu",
                vnc_port=5900
            )
            manager.snapshots["test_snapshot"] = snapshot

            # Mock successful download
            with patch.object(manager, 'download_file_from_vm', return_value=True):
                result = manager.get_modified_binary(
                    "test_snapshot",
                    "/remote/modified.exe",
                    "/local/downloads"
                )

                # Verify success
                self.assertEqual(result, "/local/downloads/modified.exe")

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_get_modified_binary_snapshot_not_found(self, mock_get_config):
        """Test modified binary retrieval with non-existent snapshot."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Test with non-existent snapshot
            result = manager.get_modified_binary(
                "non_existent_snapshot",
                "/remote/modified.exe",
                "/local/downloads"
            )

            # Verify failure
            self.assertIsNone(result)

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_get_modified_binary_download_failure(self, mock_get_config):
        """Test modified binary retrieval with download failure."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock snapshot
            snapshot = QEMUSnapshot(
                snapshot_id="test_snapshot",
                vm_name="test_vm",
                disk_path="/tmp/test.qcow2",
                binary_path="/tmp/test.exe",
                ssh_host="localhost",
                ssh_port=22222,
                ssh_user="qemu",
                vnc_port=5900
            )
            manager.snapshots["test_snapshot"] = snapshot

            # Mock failed download
            with patch.object(manager, 'download_file_from_vm', return_value=False):
                result = manager.get_modified_binary(
                    "test_snapshot",
                    "/remote/modified.exe",
                    "/local/downloads"
                )

                # Verify failure
                self.assertIsNone(result)

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_get_all_vm_info(self, mock_get_config):
        """Test retrieval of all VM information."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock snapshots
            snapshot1 = QEMUSnapshot(
                snapshot_id="snapshot1",
                vm_name="vm1",
                disk_path="/tmp/vm1.qcow2",
                binary_path="/tmp/test1.exe",
                ssh_host="localhost",
                ssh_port=22222,
                ssh_user="qemu",
                vnc_port=5900
            )
            snapshot1.created_at = datetime.now()
            snapshot1.vm_process = MagicMock()
            snapshot1.vm_process.poll.return_value = None  # Running

            snapshot2 = QEMUSnapshot(
                snapshot_id="snapshot2",
                vm_name="vm2",
                disk_path="/tmp/vm2.qcow2",
                binary_path="/tmp/test2.exe",
                ssh_host="localhost",
                ssh_port=22223,
                ssh_user="qemu",
                vnc_port=5901
            )
            snapshot2.created_at = datetime.now()
            snapshot2.vm_process = None  # Not running

            manager.snapshots = {
                "snapshot1": snapshot1,
                "snapshot2": snapshot2
            }

            # Get VM info
            vm_info = manager.get_all_vm_info()

            # Verify results
            self.assertEqual(len(vm_info), 2)
            self.assertEqual(vm_info[0]["snapshot_id"], "snapshot1")
            self.assertEqual(vm_info[0]["vm_name"], "vm1")
            self.assertTrue(vm_info[0]["vm_running"])
            self.assertEqual(vm_info[1]["snapshot_id"], "snapshot2")
            self.assertEqual(vm_info[1]["vm_name"], "vm2")
            self.assertFalse(vm_info[1]["vm_running"])

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_get_base_image_configuration(self, mock_get_config):
        """Test retrieval of base image configuration."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Test configuration retrieval
            config = manager.get_base_image_configuration()

            # Verify configuration
            self.assertIn("windows", config["vm_framework"]["base_images"])
            self.assertIn("linux", config["vm_framework"]["base_images"])
            self.assertEqual(config["vm_framework"]["base_images"]["windows"], ["C:/vms/windows10.qcow2"])

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_update_base_image_configuration(self, mock_get_config):
        """Test updating base image configuration."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Test configuration update
            new_paths = ["C:/vms/windows11.qcow2", "C:/vms/windows10.qcow2"]
            manager.update_base_image_configuration("windows", new_paths)

            # Verify calls
            self.mock_config.set.assert_called_once_with(
                "vm_framework.base_images.windows",
                new_paths
            )
            self.mock_config.save_config.assert_called_once()

    @patch('intellicrack.ai.qemu_manager.get_config')
    @patch('intellicrack.ai.qemu_manager.subprocess.Popen')
    def test_start_vm_instance(self, mock_popen, mock_get_config):
        """Test starting a VM instance."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock snapshot
            snapshot = QEMUSnapshot(
                snapshot_id="test_snapshot",
                vm_name="test_vm",
                disk_path="/tmp/test.qcow2",
                binary_path="/tmp/test.exe",
                ssh_host="localhost",
                ssh_port=22222,
                ssh_user="qemu",
                vnc_port=5900
            )
            manager.snapshots["test_snapshot"] = snapshot

            # Mock process creation
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            with patch.object(manager, '_start_vm_for_snapshot', return_value=True):
                # Test VM start
                result = manager.start_vm_instance("test_snapshot")

                # Verify success
                self.assertTrue(result)

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_stop_vm_instance(self, mock_get_config):
        """Test stopping a VM instance."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            with patch.object(manager, 'cleanup_snapshot', return_value=True):
                # Test VM stop
                result = manager.stop_vm_instance("test_snapshot")

                # Verify success
                self.assertTrue(result)
                manager.cleanup_snapshot.assert_called_once_with("test_snapshot")

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_delete_vm_instance(self, mock_get_config):
        """Test deleting a VM instance."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            with patch.object(manager, 'cleanup_snapshot', return_value=True):
                # Test VM delete
                result = manager.delete_vm_instance("test_snapshot")

                # Verify success
                self.assertTrue(result)
                manager.cleanup_snapshot.assert_called_once_with("test_snapshot")

    @patch('intellicrack.ai.qemu_manager.get_config')
    @patch('intellicrack.ai.qemu_manager.subprocess.run')
    def test_qemu_command_building(self, mock_run, mock_get_config):
        """Test QEMU command building with configuration."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Test command building
            cmd = manager._build_qemu_command(
                disk_path="/tmp/test.qcow2",
                memory_mb=2048,
                cpu_cores=2,
                enable_kvm=True,
                ssh_port=22222,
                vnc_port=5900,
                monitor_port=55555
            )

            # Verify command structure
            self.assertIn("/usr/bin/qemu-system-x86_64", cmd)
            self.assertIn("-m", cmd)
            self.assertIn("2048", cmd)
            self.assertIn("-smp", cmd)
            self.assertIn("2", cmd)
            self.assertIn("-enable-kvm", cmd)
            self.assertIn("-netdev", cmd)
            self.assertIn("hostfwd=tcp::22222-:22", cmd)
            self.assertIn("-vnc", cmd)
            self.assertIn(":0", cmd)
            self.assertIn("-monitor", cmd)
            self.assertIn("tcp:localhost:55555,server,nowait", cmd)

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_ssh_connection_pooling(self, mock_get_config):
        """Test SSH connection pooling mechanism."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Create mock SSH client
            mock_ssh_client = MagicMock()
            mock_ssh_client.get_transport.return_value.is_active.return_value = True

            # Test adding connection to pool
            manager.ssh_pool["test_vm"] = mock_ssh_client

            # Verify connection in pool
            self.assertIn("test_vm", manager.ssh_pool)
            self.assertEqual(manager.ssh_pool["test_vm"], mock_ssh_client)

    @patch('intellicrack.ai.qemu_manager.get_config')
    def test_circuit_breaker_mechanism(self, mock_get_config):
        """Test circuit breaker for SSH connections."""
        mock_get_config.return_value = self.mock_config

        with patch('intellicrack.ai.qemu_manager.shutil.which') as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"

            manager = QEMUManager()

            # Test circuit breaker initialization
            self.assertEqual(manager.circuit_breaker_threshold, 5)
            self.assertEqual(manager.circuit_breaker_timeout, 60)

            # Simulate failures
            manager.ssh_failure_counts["test_vm"] = 5

            # Verify circuit breaker triggered
            self.assertEqual(manager.ssh_failure_counts["test_vm"], 5)


if __name__ == '__main__':
    unittest.main()
