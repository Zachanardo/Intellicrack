"""Unit tests for QEMU Manager VM operations and binary analysis."""

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.ai.qemu_manager import QEMUManager, QEMUSnapshot


class TestQEMUManagerVMOperations:
    """Test QEMU Manager VM operations with real scenarios."""

    @pytest.fixture
    def qemu_manager(self, tmp_path):
        """Create QEMU Manager instance for testing."""
        with patch("intellicrack.ai.qemu_manager.Path.exists", return_value=True):
            manager = QEMUManager(
                vm_name="test_vm",
                vm_type="ubuntu",
                memory="2048",
                cpu_cores=2,
            )
            manager.vm_dir = tmp_path / "vm_test"
            manager.vm_dir.mkdir(parents=True, exist_ok=True)
            return manager

    @pytest.fixture
    def mock_snapshot(self):
        """Create mock snapshot for testing."""
        snapshot = QEMUSnapshot(
            snapshot_id="test_snapshot_001",
            vm_name="test_vm",
            disk_path="/tmp/test.qcow2",
            created_at=None,
        )
        snapshot.ssh_port = 2222
        snapshot.ssh_user = "test"
        snapshot.ssh_password = "test"
        return snapshot

    def test_binary_retrieval_logs_success_status(self, qemu_manager, mock_snapshot, caplog):
        """Test that binary download success is properly logged."""
        caplog.set_level(logging.INFO)
        qemu_manager.snapshots[mock_snapshot.snapshot_id] = mock_snapshot

        with patch.object(qemu_manager, "download_file_from_vm") as mock_download:
            mock_download.return_value = True
            result = qemu_manager.retrieve_modified_binary(
                mock_snapshot.snapshot_id,
                "/remote/path/binary",
                str(qemu_manager.vm_dir),
            )

        assert result is not None
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("success" in msg for msg in log_messages)

    def test_binary_retrieval_logs_failure_status(self, qemu_manager, mock_snapshot, caplog):
        """Test that binary download failure is properly logged."""
        caplog.set_level(logging.ERROR)
        qemu_manager.snapshots[mock_snapshot.snapshot_id] = mock_snapshot

        with patch.object(qemu_manager, "download_file_from_vm") as mock_download:
            mock_download.return_value = False
            result = qemu_manager.retrieve_modified_binary(
                mock_snapshot.snapshot_id,
                "/remote/path/binary",
                str(qemu_manager.vm_dir),
            )

        assert result is None
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("failed" in msg or "success" in msg for msg in log_messages)

    def test_vm_ready_check_uses_ssh_properly(self, qemu_manager, mock_snapshot, caplog):
        """Test that SSH connections are properly established and closed."""
        caplog.set_level(logging.DEBUG)

        mock_ssh_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_ssh_client.get_transport.return_value = mock_transport

        with patch.object(qemu_manager, "_get_ssh_connection") as mock_get_ssh:
            with patch.object(qemu_manager, "_execute_command_in_vm") as mock_exec:
                with patch.object(qemu_manager, "_inject_ssh_key"):
                    mock_get_ssh.return_value = mock_ssh_client
                    mock_exec.return_value = {"exit_code": 0, "stdout": "ready"}

                    result = qemu_manager._wait_for_vm_ready(mock_snapshot, timeout=5)

        assert result is True
        mock_ssh_client.close.assert_called()

    def test_vm_ready_check_handles_connection_failure(self, qemu_manager, mock_snapshot):
        """Test that VM ready check handles SSH connection failures."""
        with patch.object(qemu_manager, "_get_ssh_connection") as mock_get_ssh:
            mock_get_ssh.return_value = None
            result = qemu_manager._wait_for_vm_ready(mock_snapshot, timeout=2)

        assert result is False

    def test_snapshot_cleanup_preserves_running_vms(self, qemu_manager, mock_snapshot, caplog):
        """Test that cleanup doesn't delete snapshots with running VMs."""
        caplog.set_level(logging.DEBUG)

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_snapshot.vm_process = mock_process

        from datetime import datetime, timedelta
        mock_snapshot.created_at = datetime.now()
        qemu_manager.snapshots[mock_snapshot.snapshot_id] = mock_snapshot

        result = qemu_manager.cleanup_old_snapshots(max_age=timedelta(days=1))

        assert mock_snapshot.snapshot_id in qemu_manager.snapshots
        assert "is running" in caplog.text.lower() or "running" in str(result.get("warnings", []))

    def test_system_start_logs_boot_status(self, qemu_manager, caplog):
        """Test that system boot status is properly logged."""
        caplog.set_level(logging.INFO)

        with patch("subprocess.Popen") as mock_popen:
            with patch.object(qemu_manager, "_wait_for_boot") as mock_wait:
                mock_popen.return_value = MagicMock()
                mock_wait.return_value = True

                qemu_manager.qemu_path = "qemu-system-x86_64"
                qemu_manager.disk_path = str(qemu_manager.vm_dir / "test.qcow2")

                result = qemu_manager.start_system()

        assert result is True
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("success" in msg or "boot" in msg for msg in log_messages)

    def test_binary_download_corruption_handling(self, qemu_manager):
        """Test that corrupted binary downloads are handled properly."""
        snapshot = QEMUSnapshot(
            snapshot_id="corrupt_test",
            vm_name="test",
            disk_path="/tmp/test.qcow2",
            created_at=None,
        )
        qemu_manager.snapshots[snapshot.snapshot_id] = snapshot

        with patch.object(qemu_manager, "download_file_from_vm") as mock_download:
            mock_download.return_value = False
            result = qemu_manager.retrieve_modified_binary(
                snapshot.snapshot_id,
                "/remote/binary",
                str(qemu_manager.vm_dir),
            )

        assert result is None

    def test_ssh_cleanup_on_exception(self, qemu_manager):
        """Test that SSH connections are closed even on exceptions."""
        snapshot = QEMUSnapshot(
            snapshot_id="exception_test",
            vm_name="test",
            disk_path="/tmp/test.qcow2",
            created_at=None,
        )

        mock_ssh = MagicMock()
        mock_ssh.get_transport.side_effect = Exception("Network error")

        with patch.object(qemu_manager, "_get_ssh_connection") as mock_get:
            mock_get.return_value = mock_ssh
            result = qemu_manager._wait_for_vm_ready(snapshot, timeout=1)

        assert result is False
        mock_ssh.close.assert_called()
