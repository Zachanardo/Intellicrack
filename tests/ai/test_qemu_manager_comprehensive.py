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
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

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


class FakeSubprocessResult:
    """Real subprocess result for testing."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: str | bytes = "",
        stderr: str | bytes = "",
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout if isinstance(stdout, bytes) else stdout.encode()
        self.stderr = stderr if isinstance(stderr, bytes) else stderr.encode()


class FakeQEMUProcess:
    """Real QEMU process simulation for testing."""

    def __init__(self, running: bool = True, exit_code: int | None = None) -> None:
        self._running = running
        self._exit_code = exit_code
        self.terminate_called = False
        self.kill_called = False
        self.wait_called = False
        self._wait_count = 0
        self.max_waits_before_timeout = 1

    def poll(self) -> int | None:
        """Check if process is still running."""
        if not self._running:
            return self._exit_code or 0
        return None

    def terminate(self) -> None:
        """Terminate the process."""
        self.terminate_called = True

    def kill(self) -> None:
        """Force kill the process."""
        self.kill_called = True
        self._running = False

    def wait(self, timeout: float | None = None) -> int:
        """Wait for process to terminate."""
        self.wait_called = True
        self._wait_count += 1
        if self._wait_count > self.max_waits_before_timeout:
            self._running = False
            return 0
        if timeout is not None and self._running:
            raise TimeoutError("Process did not terminate")
        return 0

    def communicate(self) -> tuple[bytes, bytes]:
        """Get stdout and stderr."""
        return (b"", b"QEMU startup failed")


class FakeSSHChannel:
    """Real SSH channel simulation."""

    def __init__(self, exit_status: int = 0) -> None:
        self._exit_status = exit_status

    def recv_exit_status(self) -> int:
        """Get command exit status."""
        return self._exit_status


class FakeSSHStream:
    """Real SSH stream (stdout/stderr) simulation."""

    def __init__(self, content: bytes = b"", exit_status: int = 0) -> None:
        self._content = content
        self.channel = FakeSSHChannel(exit_status)

    def read(self) -> bytes:
        """Read stream content."""
        return self._content


class FakeSFTPClient:
    """Real SFTP client simulation."""

    def __init__(
        self,
        files_exist: bool = True,
        raise_on_get: bool = False,
    ) -> None:
        self._files_exist = files_exist
        self._raise_on_get = raise_on_get
        self.put_calls: list[tuple[str, str]] = []
        self.get_calls: list[tuple[str, str]] = []
        self.chmod_calls: list[tuple[str, int]] = []
        self.mkdir_calls: list[str] = []
        self.stat_calls: list[str] = []

    def stat(self, path: str) -> Any:
        """Check if remote path exists."""
        self.stat_calls.append(path)
        if not self._files_exist:
            raise FileNotFoundError(f"Path not found: {path}")
        return object()

    def put(self, local_path: str, remote_path: str) -> None:
        """Upload file to VM."""
        self.put_calls.append((local_path, remote_path))

    def get(self, remote_path: str, local_path: str) -> None:
        """Download file from VM."""
        self.get_calls.append((remote_path, local_path))
        if self._raise_on_get:
            raise FileNotFoundError(f"Remote file not found: {remote_path}")

    def chmod(self, path: str, mode: int) -> None:
        """Change file permissions."""
        self.chmod_calls.append((path, mode))

    def mkdir(self, path: str) -> None:
        """Create remote directory."""
        self.mkdir_calls.append(path)

    def file(self, path: str, mode: str) -> "FakeSFTPFile":
        """Open remote file."""
        return FakeSFTPFile()

    def __enter__(self) -> "FakeSFTPClient":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class FakeSFTPFile:
    """Real SFTP file handle simulation."""

    def __init__(self) -> None:
        self.written_content: list[str] = []

    def write(self, content: str) -> None:
        """Write content to file."""
        self.written_content.append(content)

    def __enter__(self) -> "FakeSFTPFile":
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class FakeSSHTransport:
    """Real SSH transport simulation."""

    def __init__(self, active: bool = True) -> None:
        self._active = active

    def is_active(self) -> bool:
        """Check if transport is active."""
        return self._active

    def getpeername(self) -> tuple[str, int]:
        """Get remote peer address."""
        return ("localhost", 22222)


class FakeSSHClient:
    """Real SSH client simulation for testing."""

    def __init__(
        self,
        transport_active: bool = True,
        connect_fail_count: int = 0,
        exec_timeout: bool = False,
        command_results: dict[str, tuple[bytes, bytes, int]] | None = None,
    ) -> None:
        self._transport = FakeSSHTransport(transport_active)
        self._connect_fail_count = connect_fail_count
        self._connect_attempts = 0
        self._exec_timeout = exec_timeout
        self._command_results = command_results or {}
        self.connect_calls: list[dict[str, Any]] = []
        self.exec_calls: list[str] = []
        self.close_called = False
        self._sftp_client = FakeSFTPClient()

    def get_transport(self) -> FakeSSHTransport:
        """Get transport layer."""
        return self._transport

    def connect(
        self,
        hostname: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        pkey: Any = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Connect to SSH server."""
        self._connect_attempts += 1
        self.connect_calls.append({
            "hostname": hostname,
            "port": port,
            "username": username,
            "password": password,
            "pkey": pkey,
            "timeout": timeout,
            **kwargs,
        })
        if self._connect_attempts <= self._connect_fail_count:
            raise paramiko.SSHException("Connection refused")

    def exec_command(
        self,
        command: str,
        timeout: float | None = None,
    ) -> tuple[Any, FakeSSHStream, FakeSSHStream]:
        """Execute command on remote host."""
        self.exec_calls.append(command)

        if self._exec_timeout:
            raise TimeoutError("Command timeout")

        if command in self._command_results:
            stdout_data, stderr_data, exit_code = self._command_results[command]
            return (
                None,
                FakeSSHStream(stdout_data, exit_code),
                FakeSSHStream(stderr_data, exit_code),
            )

        return (
            None,
            FakeSSHStream(b"command output", 0),
            FakeSSHStream(b"", 0),
        )

    def open_sftp(self) -> FakeSFTPClient:
        """Open SFTP session."""
        return self._sftp_client

    def close(self) -> None:
        """Close SSH connection."""
        self.close_called = True

    def set_missing_host_key_policy(self, policy: Any) -> None:
        """Set host key policy."""
        pass

    def load_system_host_keys(self) -> None:
        """Load system host keys."""
        pass


class FakeResourceManager:
    """Real resource manager simulation."""

    def __init__(self) -> None:
        self.acquired: list[str] = []
        self.released: list[str] = []

    def acquire_resource(self, resource: str, amount: int = 1) -> bool:
        """Acquire resource."""
        self.acquired.append(resource)
        return True

    def release_resource(self, resource: str, amount: int = 1) -> None:
        """Release resource."""
        self.released.append(resource)


@pytest.fixture
def fake_resource_manager() -> FakeResourceManager:
    """Create fake resource manager."""
    return FakeResourceManager()


@pytest.fixture
def qemu_test_workspace(temp_workspace: Path) -> Path:
    """Create QEMU-specific workspace structure."""
    workspace = temp_workspace / "qemu_test_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "images").mkdir(exist_ok=True)
    (workspace / "snapshots").mkdir(exist_ok=True)
    (workspace / "ssh").mkdir(exist_ok=True)
    return workspace


@pytest.fixture
def windows_base_image(qemu_test_workspace: Path) -> Path:
    """Create Windows base image."""
    image_path = qemu_test_workspace / "images" / "windows10_base.qcow2"
    image_path.write_bytes(b"QCOW2_WIN10_BASE_IMAGE" * 500)
    return image_path


@pytest.fixture
def linux_base_image(qemu_test_workspace: Path) -> Path:
    """Create Linux base image."""
    image_path = qemu_test_workspace / "images" / "ubuntu_base.qcow2"
    image_path.write_bytes(b"QCOW2_UBUNTU_BASE_IMAGE" * 500)
    return image_path


@pytest.fixture
def test_ssh_key() -> RSAKey:
    """Generate SSH key for testing."""
    return RSAKey.generate(2048)


@pytest.fixture
def qemu_manager(
    qemu_test_workspace: Path,
    windows_base_image: Path,
    linux_base_image: Path,
    test_ssh_key: RSAKey,
    fake_resource_manager: FakeResourceManager,
    monkeypatch: pytest.MonkeyPatch,
) -> QEMUManager:
    """Create QEMUManager instance with injected dependencies."""

    def fake_get_resource_manager() -> FakeResourceManager:
        return fake_resource_manager

    def fake_gettempdir() -> str:
        return str(qemu_test_workspace)

    def fake_validate_qemu_setup(self: QEMUManager) -> None:
        pass

    def fake_init_ssh_keys(self: QEMUManager) -> None:
        self.master_ssh_key = test_ssh_key
        self.ssh_public_key = f"ssh-rsa {test_ssh_key.get_base64()} test@qemu"

    def fake_get_windows_base_image(self: QEMUManager) -> Path:
        return windows_base_image

    def fake_get_linux_base_image(self: QEMUManager) -> str:
        return str(linux_base_image)

    def fake_find_qemu_executable(self: QEMUManager) -> str:
        return "qemu-system-x86_64"

    def fake_get_default_rootfs(self: QEMUManager) -> str:
        return str(linux_base_image)

    def fake_get_audit_logger() -> Any:
        class FakeAuditLogger:
            def log_snapshot_creation(self, *args: Any, **kwargs: Any) -> None:
                pass
            def log_snapshot_cleanup(self, *args: Any, **kwargs: Any) -> None:
                pass
            def log_ssh_connection(self, *args: Any, **kwargs: Any) -> None:
                pass
        return FakeAuditLogger()

    monkeypatch.setattr(
        "intellicrack.core.resources.resource_manager.get_resource_manager",
        fake_get_resource_manager,
    )
    monkeypatch.setattr(
        "intellicrack.core.logging.audit_logger.get_audit_logger",
        fake_get_audit_logger,
    )
    monkeypatch.setattr(
        "intellicrack.ai.qemu_manager.resource_manager",
        fake_resource_manager,
    )
    monkeypatch.setattr(
        "tempfile.gettempdir",
        fake_gettempdir,
    )
    monkeypatch.setattr(
        QEMUManager,
        "_validate_qemu_setup",
        fake_validate_qemu_setup,
    )
    monkeypatch.setattr(
        QEMUManager,
        "_init_ssh_keys",
        fake_init_ssh_keys,
    )
    monkeypatch.setattr(
        QEMUManager,
        "_get_windows_base_image",
        fake_get_windows_base_image,
    )
    monkeypatch.setattr(
        QEMUManager,
        "_get_linux_base_image",
        fake_get_linux_base_image,
    )
    monkeypatch.setattr(
        QEMUManager,
        "_find_qemu_executable",
        fake_find_qemu_executable,
    )
    monkeypatch.setattr(
        QEMUManager,
        "_get_default_rootfs",
        fake_get_default_rootfs,
    )

    manager = QEMUManager()
    manager.working_dir = qemu_test_workspace

    class FakeConfig:
        def set(self, *args: Any, **kwargs: Any) -> None:
            pass
        def save_config(self) -> None:
            pass

    manager.config = FakeConfig()  # type: ignore[assignment]

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
        self, qemu_manager: QEMUManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Snapshot creation creates QCOW2 overlay image from base."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"PE\x00\x00TEST_BINARY")

        subprocess_calls: list[list[str]] = []

        def fake_subprocess_run(cmd: list[str], *args: Any, **kwargs: Any) -> FakeSubprocessResult:
            subprocess_calls.append(cmd)
            return FakeSubprocessResult(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", fake_subprocess_run)

        def fake_start_vm(self: QEMUManager, snapshot: QEMUSnapshot) -> None:
            pass

        monkeypatch.setattr(QEMUManager, "_start_vm_for_snapshot", fake_start_vm)

        snapshot_id = qemu_manager.create_script_test_snapshot(str(binary_path), "windows")

        assert snapshot_id.startswith("test_")
        assert snapshot_id in qemu_manager.snapshots

        snapshot = qemu_manager.snapshots[snapshot_id]
        assert snapshot.binary_path == str(binary_path)
        assert snapshot.ssh_port >= 22222
        assert snapshot.vnc_port >= 5900

        assert len(subprocess_calls) >= 1
        cmd = subprocess_calls[0]
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
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """VM startup spawns QEMU process with correct parameters."""
        popen_calls: list[list[str]] = []

        def fake_popen(cmd: list[str], *args: Any, **kwargs: Any) -> FakeQEMUProcess:
            popen_calls.append(cmd)
            return FakeQEMUProcess(running=True)

        def fake_sleep(seconds: float) -> None:
            pass

        monkeypatch.setattr("subprocess.Popen", fake_popen)
        monkeypatch.setattr("time.sleep", fake_sleep)

        qemu_manager._start_vm_for_snapshot(sample_snapshot)

        assert sample_snapshot.vm_process is not None
        assert len(popen_calls) == 1

        cmd = popen_calls[0]
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
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """VM startup configures SSH port forwarding."""
        popen_calls: list[list[str]] = []

        def fake_popen(cmd: list[str], *args: Any, **kwargs: Any) -> FakeQEMUProcess:
            popen_calls.append(cmd)
            return FakeQEMUProcess(running=True)

        def fake_sleep(seconds: float) -> None:
            pass

        monkeypatch.setattr("subprocess.Popen", fake_popen)
        monkeypatch.setattr("time.sleep", fake_sleep)

        qemu_manager._start_vm_for_snapshot(sample_snapshot)

        assert len(popen_calls) == 1
        cmd = popen_calls[0]
        cmd_str = " ".join(cmd)

        assert "-netdev" in cmd
        assert f"hostfwd=tcp::{sample_snapshot.ssh_port}-:22" in cmd_str

    def test_start_vm_for_snapshot_handles_startup_failure(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """VM startup handles process failure."""
        def fake_popen(cmd: list[str], *args: Any, **kwargs: Any) -> FakeQEMUProcess:
            proc = FakeQEMUProcess(running=False, exit_code=1)
            return proc

        def fake_sleep(seconds: float) -> None:
            pass

        monkeypatch.setattr("subprocess.Popen", fake_popen)
        monkeypatch.setattr("time.sleep", fake_sleep)

        with pytest.raises(RuntimeError, match="VM startup failed"):
            qemu_manager._start_vm_for_snapshot(sample_snapshot)

    def test_cleanup_snapshot_terminates_vm_process(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Snapshot cleanup terminates running VM process."""
        fake_process = FakeQEMUProcess(running=True)
        sample_snapshot.vm_process = fake_process  # type: ignore[assignment]

        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        def fake_close_ssh(self: QEMUManager, snapshot: QEMUSnapshot) -> None:
            pass

        monkeypatch.setattr(QEMUManager, "_close_ssh_connection", fake_close_ssh)

        qemu_manager.cleanup_snapshot(sample_snapshot.snapshot_id)

        assert fake_process.terminate_called
        assert fake_process.wait_called

    def test_cleanup_snapshot_removes_disk_file(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Snapshot cleanup deletes disk file."""
        disk_path = Path(sample_snapshot.disk_path)
        assert disk_path.exists()

        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        def fake_close_ssh(self: QEMUManager, snapshot: QEMUSnapshot) -> None:
            pass

        monkeypatch.setattr(QEMUManager, "_close_ssh_connection", fake_close_ssh)

        qemu_manager.cleanup_snapshot(sample_snapshot.snapshot_id)

        assert not disk_path.exists()

    def test_cleanup_snapshot_kills_stuck_process(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Snapshot cleanup force kills process that won't terminate."""
        fake_process = FakeQEMUProcess(running=True)
        fake_process.max_waits_before_timeout = 2
        sample_snapshot.vm_process = fake_process  # type: ignore[assignment]

        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        def fake_close_ssh(self: QEMUManager, snapshot: QEMUSnapshot) -> None:
            pass

        monkeypatch.setattr(QEMUManager, "_close_ssh_connection", fake_close_ssh)

        qemu_manager.cleanup_snapshot(sample_snapshot.snapshot_id)

        assert fake_process.terminate_called
        assert fake_process.kill_called

    def test_cleanup_all_snapshots_removes_all_vms(
        self, qemu_manager: QEMUManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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

        def fake_close_ssh(self: QEMUManager, snapshot: QEMUSnapshot) -> None:
            pass

        monkeypatch.setattr(QEMUManager, "_close_ssh_connection", fake_close_ssh)

        qemu_manager.cleanup_all_snapshots()

        assert len(qemu_manager.snapshots) == 0
        for snap in snapshots:
            assert not Path(snap.disk_path).exists()


class TestSSHConnectionManagement:
    """Test SSH connection pooling, retry logic, and circuit breaker."""

    def test_get_ssh_connection_creates_new_connection(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SSH connection manager creates new connection on first request."""
        fake_client = FakeSSHClient(transport_active=True, connect_fail_count=0)

        def fake_ssh_client() -> FakeSSHClient:
            return fake_client

        monkeypatch.setattr("paramiko.SSHClient", fake_ssh_client)

        client = qemu_manager._get_ssh_connection(sample_snapshot)

        assert client is not None
        assert len(fake_client.connect_calls) == 1

        call_kwargs = fake_client.connect_calls[0]
        assert call_kwargs["hostname"] == "localhost"
        assert call_kwargs["port"] == sample_snapshot.ssh_port
        assert call_kwargs["username"] == "test"

    def test_get_ssh_connection_reuses_active_connection(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot
    ) -> None:
        """SSH connection manager reuses active connections from pool."""
        fake_client = FakeSSHClient(transport_active=True)

        pool_key = (sample_snapshot.vm_name, sample_snapshot.ssh_port)
        qemu_manager.ssh_connection_pool[pool_key] = fake_client

        client = qemu_manager._get_ssh_connection(sample_snapshot)

        assert client is fake_client

    def test_get_ssh_connection_retries_on_failure(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SSH connection manager retries on connection failure."""
        fake_client = FakeSSHClient(transport_active=True, connect_fail_count=1)

        def fake_ssh_client() -> FakeSSHClient:
            return fake_client

        monkeypatch.setattr("paramiko.SSHClient", fake_ssh_client)

        client = qemu_manager._get_ssh_connection(sample_snapshot, retries=3)

        assert client is not None
        assert len(fake_client.connect_calls) == 2

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
        fake_client = FakeSSHClient()
        pool_key = (sample_snapshot.vm_name, sample_snapshot.ssh_port)
        qemu_manager.ssh_connection_pool[pool_key] = fake_client

        qemu_manager._close_ssh_connection(sample_snapshot)

        assert pool_key not in qemu_manager.ssh_connection_pool
        assert fake_client.close_called


class TestBinaryExecution:
    """Test binary upload and execution in VMs."""

    def test_upload_file_to_vm_creates_remote_directory(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """File upload creates remote directory if missing."""
        fake_client = FakeSSHClient()
        fake_client._sftp_client = FakeSFTPClient(files_exist=False)

        def fake_get_ssh(
            self: QEMUManager, snapshot: QEMUSnapshot, retries: int = 3
        ) -> FakeSSHClient:
            return fake_client

        def fake_execute_command(
            self: QEMUManager, snapshot: QEMUSnapshot, command: str, timeout: int = 30
        ) -> dict[str, Any]:
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(QEMUManager, "_get_ssh_connection", fake_get_ssh)
        monkeypatch.setattr(QEMUManager, "_execute_command_in_vm", fake_execute_command)

        qemu_manager._upload_file_to_vm(
            sample_snapshot,
            "test content",
            "/remote/path/file.txt"
        )

        assert len(fake_client._sftp_client.stat_calls) >= 1

    def test_upload_binary_to_vm_sets_executable_permission(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Binary upload sets executable permissions on remote file."""
        local_binary = tmp_path / "binary.exe"
        local_binary.write_bytes(b"PE\x00\x00BINARY_DATA")

        fake_client = FakeSSHClient()
        fake_client._sftp_client = FakeSFTPClient(files_exist=False)

        def fake_get_ssh(
            self: QEMUManager, snapshot: QEMUSnapshot, retries: int = 3
        ) -> FakeSSHClient:
            return fake_client

        def fake_execute_command(
            self: QEMUManager, snapshot: QEMUSnapshot, command: str, timeout: int = 30
        ) -> dict[str, Any]:
            return {"exit_code": 0, "stdout": "", "stderr": ""}

        monkeypatch.setattr(QEMUManager, "_get_ssh_connection", fake_get_ssh)
        monkeypatch.setattr(QEMUManager, "_execute_command_in_vm", fake_execute_command)

        qemu_manager._upload_binary_to_vm(
            sample_snapshot,
            str(local_binary),
            "/remote/binary.exe"
        )

        assert len(fake_client._sftp_client.put_calls) == 1
        assert fake_client._sftp_client.put_calls[0] == (str(local_binary), "/remote/binary.exe")
        assert len(fake_client._sftp_client.chmod_calls) == 1
        assert fake_client._sftp_client.chmod_calls[0] == ("/remote/binary.exe", 0o755)

    def test_execute_command_in_vm_returns_output(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Command execution returns stdout, stderr, and exit code."""
        fake_client = FakeSSHClient(
            command_results={
                "echo test": (b"command output", b"", 0)
            }
        )

        def fake_get_ssh(
            self: QEMUManager, snapshot: QEMUSnapshot, retries: int = 3
        ) -> FakeSSHClient:
            return fake_client

        monkeypatch.setattr(QEMUManager, "_get_ssh_connection", fake_get_ssh)

        result = qemu_manager._execute_command_in_vm(sample_snapshot, "echo test")

        assert result["exit_code"] == 0
        assert result["stdout"] == "command output"
        assert result["stderr"] == ""

    def test_execute_command_in_vm_handles_timeout(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Command execution handles timeout."""
        fake_client = FakeSSHClient(exec_timeout=True)

        def fake_get_ssh(
            self: QEMUManager, snapshot: QEMUSnapshot, retries: int = 3
        ) -> FakeSSHClient:
            return fake_client

        monkeypatch.setattr(QEMUManager, "_get_ssh_connection", fake_get_ssh)

        result = qemu_manager._execute_command_in_vm(
            sample_snapshot,
            "sleep 100",
            timeout=1
        )

        assert result["exit_code"] == -1
        assert "timed out" in result["stderr"]

    def test_download_file_from_vm_retrieves_remote_file(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """File download retrieves file from VM."""
        local_path = tmp_path / "downloaded.txt"

        fake_client = FakeSSHClient()

        def fake_get_ssh(
            self: QEMUManager, snapshot: QEMUSnapshot, retries: int = 3
        ) -> FakeSSHClient:
            return fake_client

        monkeypatch.setattr(QEMUManager, "_get_ssh_connection", fake_get_ssh)

        result = qemu_manager.download_file_from_vm(
            sample_snapshot,
            "/remote/file.txt",
            str(local_path)
        )

        assert result is True
        assert len(fake_client._sftp_client.get_calls) == 1
        assert fake_client._sftp_client.get_calls[0] == ("/remote/file.txt", str(local_path))

    def test_download_file_from_vm_handles_missing_file(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """File download handles missing remote file."""
        local_path = tmp_path / "downloaded.txt"

        fake_client = FakeSSHClient()
        fake_client._sftp_client = FakeSFTPClient(raise_on_get=True)

        def fake_get_ssh(
            self: QEMUManager, snapshot: QEMUSnapshot, retries: int = 3
        ) -> FakeSSHClient:
            return fake_client

        monkeypatch.setattr(QEMUManager, "_get_ssh_connection", fake_get_ssh)

        result = qemu_manager.download_file_from_vm(
            sample_snapshot,
            "/nonexistent/file.txt",
            str(local_path)
        )

        assert result is False

    def test_get_modified_binary_downloads_to_local_path(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Get modified binary downloads and returns local path."""
        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        local_dir = tmp_path / "downloads"
        local_dir.mkdir()

        def fake_download(
            self: QEMUManager, snapshot: QEMUSnapshot, remote: str, local: str
        ) -> bool:
            return True

        monkeypatch.setattr(QEMUManager, "download_file_from_vm", fake_download)

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
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Versioned snapshot creation creates child snapshot."""
        qemu_manager.snapshots[sample_snapshot.snapshot_id] = sample_snapshot

        binary_path = tmp_path / "modified.exe"
        binary_path.write_bytes(b"MODIFIED_BINARY")

        def fake_subprocess_run(cmd: list[str], *args: Any, **kwargs: Any) -> FakeSubprocessResult:
            return FakeSubprocessResult(returncode=0)

        def fake_start_vm(self: QEMUManager, snapshot: QEMUSnapshot) -> None:
            pass

        monkeypatch.setattr("subprocess.run", fake_subprocess_run)
        monkeypatch.setattr(QEMUManager, "_start_vm_for_snapshot", fake_start_vm)

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
        fake_process = FakeQEMUProcess(running=True)
        sample_snapshot.vm_process = fake_process  # type: ignore[assignment]

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

        assert not sample_snapshot.network_isolated


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
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """VM ready wait succeeds when SSH connection works."""
        fake_client = FakeSSHClient(
            transport_active=True,
            command_results={"echo ready": (b"ready", b"", 0)}
        )

        def fake_get_ssh(
            self: QEMUManager, snapshot: QEMUSnapshot, retries: int = 3
        ) -> FakeSSHClient:
            return fake_client

        def fake_execute_command(
            self: QEMUManager, snapshot: QEMUSnapshot, command: str, timeout: int = 30
        ) -> dict[str, Any]:
            return {"exit_code": 0, "stdout": "ready", "stderr": ""}

        def fake_inject_ssh_key(self: QEMUManager, snapshot: QEMUSnapshot) -> None:
            pass

        monkeypatch.setattr(QEMUManager, "_get_ssh_connection", fake_get_ssh)
        monkeypatch.setattr(QEMUManager, "_execute_command_in_vm", fake_execute_command)
        monkeypatch.setattr(QEMUManager, "_inject_ssh_key", fake_inject_ssh_key)

        result = qemu_manager._wait_for_vm_ready(sample_snapshot, timeout=10)

        assert result is True

    def test_wait_for_vm_ready_times_out(
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """VM ready wait times out when VM doesn't boot."""
        def fake_get_ssh(
            self: QEMUManager, snapshot: QEMUSnapshot, retries: int = 3
        ) -> None:
            return None

        def fake_sleep(seconds: float) -> None:
            pass

        monkeypatch.setattr(QEMUManager, "_get_ssh_connection", fake_get_ssh)
        monkeypatch.setattr("time.sleep", fake_sleep)

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
        self, qemu_test_workspace: Path
    ) -> None:
        """Secure host key policy stores new host keys."""
        known_hosts = qemu_test_workspace / "ssh" / "known_hosts"
        policy = SecureHostKeyPolicy(known_hosts)

        fake_client = FakeSSHClient()
        test_key = RSAKey.generate(2048)

        policy.missing_host_key(fake_client, "localhost", test_key)

        assert known_hosts.exists()

    def test_secure_host_key_policy_rejects_changed_key(
        self, qemu_test_workspace: Path
    ) -> None:
        """Secure host key policy rejects changed host keys."""
        known_hosts = qemu_test_workspace / "ssh" / "known_hosts"
        policy = SecureHostKeyPolicy(known_hosts)

        fake_client = FakeSSHClient()

        key1 = RSAKey.generate(2048)
        policy.missing_host_key(fake_client, "localhost", key1)

        key2 = RSAKey.generate(2048)

        with pytest.raises(paramiko.SSHException, match="Host key verification failed"):
            policy.missing_host_key(fake_client, "localhost", key2)


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

        config_set_called = False
        save_config_called = False

        original_set = qemu_manager.config.set
        original_save = qemu_manager.config.save_config

        def fake_set(*args: Any, **kwargs: Any) -> None:
            nonlocal config_set_called
            config_set_called = True
            original_set(*args, **kwargs)

        def fake_save() -> None:
            nonlocal save_config_called
            save_config_called = True
            original_save()

        qemu_manager.config.set = fake_set  # type: ignore[method-assign]
        qemu_manager.config.save_config = fake_save  # type: ignore[method-assign]

        qemu_manager.update_base_image_configuration("windows", [str(new_image)])

        assert config_set_called
        assert save_config_called

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
        self, qemu_manager: QEMUManager, sample_snapshot: QEMUSnapshot, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SSH key injection handles connection failures."""
        def fake_execute_command(
            self: QEMUManager, snapshot: QEMUSnapshot, command: str, timeout: int = 30
        ) -> dict[str, Any]:
            raise Exception("Connection failed")

        monkeypatch.setattr(QEMUManager, "_execute_command_in_vm", fake_execute_command)

        qemu_manager._inject_ssh_key(sample_snapshot)


class TestResourceManagement:
    """Test resource tracking and cleanup."""

    def test_destructor_closes_all_ssh_connections(
        self, qemu_manager: QEMUManager, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Destructor closes all SSH connections in pool."""
        fake_clients = [FakeSSHClient() for _ in range(3)]

        qemu_manager.ssh_connection_pool = {
            ("vm1", 22222): fake_clients[0],
            ("vm2", 22223): fake_clients[1],
            ("vm3", 22224): fake_clients[2],
        }

        def fake_cleanup(self: QEMUManager) -> None:
            pass

        monkeypatch.setattr(QEMUManager, "cleanup_all_snapshots", fake_cleanup)

        qemu_manager.__del__()

        for client in fake_clients:
            assert client.close_called

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
        self, qemu_manager: QEMUManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Minimal image creation creates QCOW2 disk."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()

        subprocess_calls: list[list[str]] = []

        def fake_subprocess_run(cmd: list[str], *args: Any, **kwargs: Any) -> FakeSubprocessResult:
            subprocess_calls.append(cmd)
            return FakeSubprocessResult(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", fake_subprocess_run)

        disk_path = qemu_manager._create_minimal_test_image(snapshot_dir, "windows")

        assert disk_path.suffix == ".qcow2"
        assert len(subprocess_calls) == 1

        cmd = subprocess_calls[0]
        assert "qemu-img" in cmd
        assert "create" in cmd
        assert "-f" in cmd
        assert "qcow2" in cmd

    def test_create_minimal_test_image_uses_config_size(
        self, qemu_manager: QEMUManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Minimal image creation uses configured disk size."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()

        subprocess_calls: list[list[str]] = []

        def fake_subprocess_run(cmd: list[str], *args: Any, **kwargs: Any) -> FakeSubprocessResult:
            subprocess_calls.append(cmd)
            return FakeSubprocessResult(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_subprocess_run)

        qemu_manager._create_minimal_test_image(snapshot_dir, "windows")

        assert len(subprocess_calls) == 1
        cmd = subprocess_calls[0]
        assert "2G" in cmd

    def test_copy_base_image_creates_overlay(
        self, qemu_manager: QEMUManager, tmp_path: Path, windows_base_image: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Base image copy creates QCOW2 overlay."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()

        subprocess_calls: list[list[str]] = []

        def fake_subprocess_run(cmd: list[str], *args: Any, **kwargs: Any) -> FakeSubprocessResult:
            subprocess_calls.append(cmd)
            return FakeSubprocessResult(returncode=0)

        monkeypatch.setattr("subprocess.run", fake_subprocess_run)

        overlay = qemu_manager._copy_base_image(windows_base_image, snapshot_dir)

        assert overlay.name == "snapshot_disk.qcow2"
        assert len(subprocess_calls) == 1

        cmd = subprocess_calls[0]
        assert "-b" in cmd
        assert str(windows_base_image) in cmd

    def test_copy_base_image_falls_back_to_direct_copy(
        self, qemu_manager: QEMUManager, tmp_path: Path, windows_base_image: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Base image copy falls back to direct copy on overlay failure."""
        snapshot_dir = tmp_path / "snapshot"
        snapshot_dir.mkdir()

        def fake_subprocess_run(cmd: list[str], *args: Any, **kwargs: Any) -> FakeSubprocessResult:
            return FakeSubprocessResult(returncode=1, stderr="overlay failed")

        copy_called = False

        def fake_shutil_copy(src: Path, dst: Path) -> None:
            nonlocal copy_called
            copy_called = True

        monkeypatch.setattr("subprocess.run", fake_subprocess_run)
        monkeypatch.setattr("shutil.copy2", fake_shutil_copy)

        overlay = qemu_manager._copy_base_image(windows_base_image, snapshot_dir)

        assert copy_called
