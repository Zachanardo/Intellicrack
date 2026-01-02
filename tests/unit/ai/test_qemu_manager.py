"""Unit tests for QEMU Manager VM operations and binary analysis."""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.qemu_manager import QEMUManager, QEMUSnapshot


class FakeProcess:
    """Fake process object for testing subprocess operations."""

    def __init__(self, is_running: bool = True) -> None:
        self.is_running = is_running
        self.poll_called = 0

    def poll(self) -> int | None:
        """Simulate process poll operation."""
        self.poll_called += 1
        return None if self.is_running else 0


class FakeSSHClient:
    """Fake SSH client for testing SSH operations."""

    def __init__(
        self,
        transport_active: bool = True,
        should_raise: bool = False,
        raise_on_transport: bool = False,
    ) -> None:
        self.transport_active = transport_active
        self.should_raise = should_raise
        self.raise_on_transport = raise_on_transport
        self.close_called = 0
        self.transport_calls = 0

    def get_transport(self) -> "FakeTransport":
        """Get fake transport object."""
        self.transport_calls += 1
        if self.raise_on_transport:
            raise Exception("Network error")
        return FakeTransport(self.transport_active)

    def close(self) -> None:
        """Track close calls."""
        self.close_called += 1


class FakeTransport:
    """Fake SSH transport for testing connection state."""

    def __init__(self, active: bool = True) -> None:
        self.active = active
        self.is_active_called = 0

    def is_active(self) -> bool:
        """Return transport active state."""
        self.is_active_called += 1
        return self.active


class FakePath:
    """Fake Path object for testing file system operations."""

    def __init__(self, exists: bool = True) -> None:
        self.exists_value = exists
        self.exists_called = 0

    def exists(self) -> bool:
        """Track exists calls and return configured value."""
        self.exists_called += 1
        return self.exists_value


class FakePopen:
    """Fake Popen for testing subprocess operations."""

    def __init__(self) -> None:
        self.poll_called = 0

    def poll(self) -> int | None:
        """Simulate successful process."""
        self.poll_called += 1
        return None


class TestQEMUManagerVMOperations:
    """Test QEMU Manager VM operations with real scenarios."""

    @pytest.fixture
    def qemu_manager(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> QEMUManager:
        """Create QEMU Manager instance for testing."""
        fake_path = FakePath(exists=True)

        original_path_class = Path

        def fake_path_exists(self: Path) -> bool:
            fake_path.exists_called += 1
            return fake_path.exists_value

        monkeypatch.setattr(Path, "exists", fake_path_exists)

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
    def mock_snapshot(self) -> QEMUSnapshot:
        """Create snapshot for testing."""
        snapshot = QEMUSnapshot(
            snapshot_id="test_snapshot_001",
            vm_name="test_vm",
            disk_path="/tmp/test.qcow2",
            binary_path="/tmp/test_binary",
            created_at=datetime.now(),
        )
        snapshot.ssh_port = 2222
        return snapshot

    def test_binary_retrieval_logs_success_status(
        self,
        qemu_manager: QEMUManager,
        mock_snapshot: QEMUSnapshot,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that binary download success is properly logged."""
        caplog.set_level(logging.INFO)
        qemu_manager.snapshots[mock_snapshot.snapshot_id] = mock_snapshot

        download_called = {"count": 0, "args": []}

        def fake_download(snapshot: QEMUSnapshot, remote_path: str, local_path: str) -> bool:
            download_called["count"] += 1
            download_called["args"].append((snapshot, remote_path, local_path))
            return True

        monkeypatch.setattr(qemu_manager, "download_file_from_vm", fake_download)

        result = qemu_manager.retrieve_modified_binary(
            mock_snapshot.snapshot_id,
            "/remote/path/binary",
            str(qemu_manager.vm_dir),
        )

        assert result is not None
        assert download_called["count"] == 1
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("success" in msg for msg in log_messages)

    def test_binary_retrieval_logs_failure_status(
        self,
        qemu_manager: QEMUManager,
        mock_snapshot: QEMUSnapshot,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that binary download failure is properly logged."""
        caplog.set_level(logging.ERROR)
        qemu_manager.snapshots[mock_snapshot.snapshot_id] = mock_snapshot

        download_called = {"count": 0}

        def fake_download(snapshot: QEMUSnapshot, remote_path: str, local_path: str) -> bool:
            download_called["count"] += 1
            return False

        monkeypatch.setattr(qemu_manager, "download_file_from_vm", fake_download)

        result = qemu_manager.retrieve_modified_binary(
            mock_snapshot.snapshot_id,
            "/remote/path/binary",
            str(qemu_manager.vm_dir),
        )

        assert result is None
        assert download_called["count"] == 1
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("failed" in msg or "success" in msg for msg in log_messages)

    def test_vm_ready_check_uses_ssh_properly(
        self,
        qemu_manager: QEMUManager,
        mock_snapshot: QEMUSnapshot,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that SSH connections are properly established and closed."""
        caplog.set_level(logging.DEBUG)

        fake_ssh_client = FakeSSHClient(transport_active=True)

        get_ssh_called = {"count": 0}
        exec_called = {"count": 0}
        inject_called = {"count": 0}

        def fake_get_ssh(
            snapshot: QEMUSnapshot,
            timeout: int = 30,
            retry_interval: int = 5,
            max_retries: int = 3,
        ) -> FakeSSHClient:
            get_ssh_called["count"] += 1
            return fake_ssh_client

        def fake_exec(
            snapshot: QEMUSnapshot,
            command: str,
            timeout: int = 30,
            use_sudo: bool = False,
        ) -> dict[str, Any]:
            exec_called["count"] += 1
            return {"exit_code": 0, "stdout": "ready"}

        def fake_inject(snapshot: QEMUSnapshot) -> None:
            inject_called["count"] += 1

        monkeypatch.setattr(qemu_manager, "_get_ssh_connection", fake_get_ssh)
        monkeypatch.setattr(qemu_manager, "_execute_command_in_vm", fake_exec)
        monkeypatch.setattr(qemu_manager, "_inject_ssh_key", fake_inject)

        result = qemu_manager._wait_for_vm_ready(mock_snapshot, timeout=5)

        assert result is True
        assert fake_ssh_client.close_called == 1
        assert get_ssh_called["count"] > 0

    def test_vm_ready_check_handles_connection_failure(
        self,
        qemu_manager: QEMUManager,
        mock_snapshot: QEMUSnapshot,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that VM ready check handles SSH connection failures."""
        get_ssh_called = {"count": 0}

        def fake_get_ssh(
            snapshot: QEMUSnapshot,
            timeout: int = 30,
            retry_interval: int = 5,
            max_retries: int = 3,
        ) -> None:
            get_ssh_called["count"] += 1
            return None

        monkeypatch.setattr(qemu_manager, "_get_ssh_connection", fake_get_ssh)

        result = qemu_manager._wait_for_vm_ready(mock_snapshot, timeout=2)

        assert result is False
        assert get_ssh_called["count"] > 0

    def test_snapshot_cleanup_preserves_running_vms(
        self,
        qemu_manager: QEMUManager,
        mock_snapshot: QEMUSnapshot,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test that cleanup doesn't delete snapshots with running VMs."""
        caplog.set_level(logging.DEBUG)

        fake_process = FakeProcess(is_running=True)
        mock_snapshot.vm_process = fake_process
        mock_snapshot.created_at = datetime.now()
        qemu_manager.snapshots[mock_snapshot.snapshot_id] = mock_snapshot

        result = qemu_manager.cleanup_old_snapshots(max_age=timedelta(days=1))

        assert mock_snapshot.snapshot_id in qemu_manager.snapshots
        assert fake_process.poll_called > 0
        assert "is running" in caplog.text.lower() or "running" in str(result.get("warnings", []))

    def test_system_start_logs_boot_status(
        self,
        qemu_manager: QEMUManager,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that system boot status is properly logged."""
        caplog.set_level(logging.INFO)

        popen_called = {"count": 0}
        wait_boot_called = {"count": 0}

        def fake_popen(*args: Any, **kwargs: Any) -> FakePopen:
            popen_called["count"] += 1
            return FakePopen()

        def fake_wait_boot(timeout: int = 60) -> bool:
            wait_boot_called["count"] += 1
            return True

        import subprocess
        monkeypatch.setattr(subprocess, "Popen", fake_popen)
        monkeypatch.setattr(qemu_manager, "_wait_for_boot", fake_wait_boot)

        qemu_manager.qemu_path = "qemu-system-x86_64"
        qemu_manager.disk_path = str(qemu_manager.vm_dir / "test.qcow2")

        result = qemu_manager.start_system()

        assert result is True
        assert popen_called["count"] == 1
        assert wait_boot_called["count"] == 1
        log_messages = [record.message.lower() for record in caplog.records]
        assert any("success" in msg or "boot" in msg for msg in log_messages)

    def test_binary_download_corruption_handling(
        self,
        qemu_manager: QEMUManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that corrupted binary downloads are handled properly."""
        snapshot = QEMUSnapshot(
            snapshot_id="corrupt_test",
            vm_name="test",
            disk_path="/tmp/test.qcow2",
            binary_path="/tmp/test_binary",
            created_at=datetime.now(),
        )
        qemu_manager.snapshots[snapshot.snapshot_id] = snapshot

        download_called = {"count": 0}

        def fake_download(snap: QEMUSnapshot, remote_path: str, local_path: str) -> bool:
            download_called["count"] += 1
            return False

        monkeypatch.setattr(qemu_manager, "download_file_from_vm", fake_download)

        result = qemu_manager.retrieve_modified_binary(
            snapshot.snapshot_id,
            "/remote/binary",
            str(qemu_manager.vm_dir),
        )

        assert result is None
        assert download_called["count"] == 1

    def test_ssh_cleanup_on_exception(
        self,
        qemu_manager: QEMUManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that SSH connections are closed even on exceptions."""
        snapshot = QEMUSnapshot(
            snapshot_id="exception_test",
            vm_name="test",
            disk_path="/tmp/test.qcow2",
            binary_path="/tmp/test_binary",
            created_at=datetime.now(),
        )

        fake_ssh = FakeSSHClient(transport_active=True, raise_on_transport=True)

        get_ssh_called = {"count": 0}

        def fake_get_ssh(
            snap: QEMUSnapshot,
            timeout: int = 30,
            retry_interval: int = 5,
            max_retries: int = 3,
        ) -> FakeSSHClient:
            get_ssh_called["count"] += 1
            return fake_ssh

        monkeypatch.setattr(qemu_manager, "_get_ssh_connection", fake_get_ssh)

        result = qemu_manager._wait_for_vm_ready(snapshot, timeout=1)

        assert result is False
        assert fake_ssh.close_called == 1
        assert get_ssh_called["count"] > 0
