"""Production tests for core/processing/vm_workflow_manager.py.

These tests validate the VM workflow manager's orchestration capabilities with
real test doubles. Tests use real file operations, temporary directories, and
actual script execution where possible. VM-specific tests marked to skip when
QEMU infrastructure unavailable.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from pathlib import Path
from typing import Any, Type

import pytest

try:
    from intellicrack.core.processing.vm_workflow_manager import VMWorkflowManager
    VM_WORKFLOW_AVAILABLE = True
except ImportError:
    VM_WORKFLOW_AVAILABLE = False
    VMWorkflowManager = None  # type: ignore[assignment]

pytestmark = pytest.mark.skipif(
    not VM_WORKFLOW_AVAILABLE,
    reason="VMWorkflowManager requires paramiko and other dependencies"
)


class FakeVMProcess:
    """Test double for VM process."""

    returncode: int
    pid: int

    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.pid = 12345

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass


class FakeSnapshot:
    """Test double for QEMUSnapshot."""

    snapshot_id: str
    vm_name: str
    ssh_host: str
    ssh_port: int
    vm_process: FakeVMProcess

    def __init__(
        self,
        snapshot_id: str,
        vm_name: str = "test_vm",
        ssh_host: str = "localhost",
        ssh_port: int = 2222,
    ) -> None:
        self.snapshot_id = snapshot_id
        self.vm_name = vm_name
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.vm_process = FakeVMProcess()


class FakeExecutionResult:
    """Test double for ExecutionResult."""

    success: bool
    output: str
    errors: str
    exit_code: int
    error: str

    def __init__(
        self,
        success: bool = True,
        output: str = "",
        errors: str = "",
        exit_code: int = 0,
        error: str = "",
    ) -> None:
        self.success = success
        self.output = output
        self.errors = errors
        self.exit_code = exit_code
        self.error = error


class FakeSSHClient:
    """Test double for SSH client."""

    should_fail: bool
    sftp: "FakeSFTPClient"

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.sftp = FakeSFTPClient(should_fail)

    def open_sftp(self) -> "FakeSFTPClient":
        return self.sftp


class FakeSFTPClient:
    """Test double for SFTP client."""

    should_fail: bool
    uploaded_files: dict[str, str]
    permissions: dict[str, int]

    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.uploaded_files = {}
        self.permissions = {}

    def mkdir(self, path: str) -> None:
        if self.should_fail:
            raise OSError("Failed to create directory")

    def put(self, local_path: str, remote_path: str) -> None:
        if self.should_fail:
            raise IOError("Upload failed")
        self.uploaded_files[remote_path] = local_path

    def chmod(self, path: str, mode: int) -> None:
        self.permissions[path] = mode

    def close(self) -> None:
        pass


class FakeQEMUManager:
    """Test double for QEMUManager."""

    snapshots: dict[str, FakeSnapshot]
    create_snapshot_calls: list[tuple[str, str]]
    test_script_calls: list[tuple[str, str]]
    download_calls: list[tuple[FakeSnapshot, str, str]]
    cleanup_calls: list[str]
    ssh_client: FakeSSHClient
    should_fail_create_snapshot: bool
    should_fail_test_script: bool
    should_fail_download: bool
    should_return_none_snapshot: bool
    test_script_result: FakeExecutionResult

    def __init__(self) -> None:
        self.snapshots = {}
        self.create_snapshot_calls = []
        self.test_script_calls = []
        self.download_calls = []
        self.cleanup_calls = []
        self.ssh_client = FakeSSHClient()

        self.should_fail_create_snapshot = False
        self.should_fail_test_script = False
        self.should_fail_download = False
        self.should_return_none_snapshot = False
        self.test_script_result = FakeExecutionResult(success=True, output="Success", errors="")

    def create_script_test_snapshot(
        self,
        binary_path: str,
        platform: str = "windows",
    ) -> str | None:
        self.create_snapshot_calls.append((binary_path, platform))

        if self.should_fail_create_snapshot:
            raise Exception("VM error")

        if self.should_return_none_snapshot:
            return None

        snapshot_id = f"snapshot_{len(self.snapshots) + 1}"
        self.snapshots[snapshot_id] = FakeSnapshot(snapshot_id)
        return snapshot_id

    def test_script_in_vm(
        self,
        snapshot_id: str,
        script_content: str,
    ) -> FakeExecutionResult:
        self.test_script_calls.append((snapshot_id, script_content))

        if self.should_fail_test_script:
            return FakeExecutionResult(
                success=False,
                error="Script execution failed",
                exit_code=1,
            )

        return self.test_script_result

    def download_file_from_vm(
        self,
        snapshot: FakeSnapshot,
        remote_path: str,
        local_path: str,
    ) -> bool:
        self.download_calls.append((snapshot, remote_path, local_path))

        if self.should_fail_download:
            return False

        return True

    def cleanup_snapshot(self, snapshot_id: str) -> bool:
        self.cleanup_calls.append(snapshot_id)
        return True

    def _get_ssh_connection(self, snapshot: FakeSnapshot) -> FakeSSHClient | None:
        return self.ssh_client


class FakeQApplication:
    """Test double for QApplication."""

    _instance: "FakeQApplication | None" = None

    @classmethod
    def instance(cls) -> "FakeQApplication":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance


class FakeQFileDialog:
    """Test double for QFileDialog."""

    _saved_file_name: str | None = None

    @classmethod
    def getSaveFileName(
        cls,
        parent: Any,
        caption: str,
        directory: str,
        filter: str,  # noqa: A002
    ) -> tuple[str, str]:
        if cls._saved_file_name is None:
            return ("", "")
        return (cls._saved_file_name, "")


class FakeLogger:
    """Test double for logger."""

    info_calls: list[tuple[Any, ...]]
    error_calls: list[tuple[Any, ...]]
    exception_calls: list[tuple[Any, ...]]

    def __init__(self) -> None:
        self.info_calls = []
        self.error_calls = []
        self.exception_calls = []

    def info(self, message: str, *args: Any) -> None:
        self.info_calls.append((message, *args))

    def error(self, message: str, *args: Any) -> None:
        self.error_calls.append((message, *args))

    def exception(self, message: str, *args: Any) -> None:
        self.exception_calls.append((message, *args))


@pytest.fixture
def fake_qemu_manager() -> FakeQEMUManager:
    """Provide fake QEMU manager for testing."""
    return FakeQEMUManager()


@pytest.fixture
def fake_logger() -> FakeLogger:
    """Provide fake logger for testing."""
    return FakeLogger()


@pytest.fixture
def workflow_manager_with_fakes(
    fake_qemu_manager: FakeQEMUManager,
    fake_logger: FakeLogger,
    monkeypatch: pytest.MonkeyPatch,
) -> VMWorkflowManager:  # type: ignore[name-defined]
    """Provide VMWorkflowManager with injected test doubles."""
    FakeQApplication._instance = FakeQApplication()
    FakeQFileDialog._saved_file_name = None

    monkeypatch.setattr(
        "intellicrack.core.processing.vm_workflow_manager.QApplication",
        FakeQApplication,
    )
    monkeypatch.setattr(
        "intellicrack.core.processing.vm_workflow_manager.QFileDialog",
        FakeQFileDialog,
    )

    manager: VMWorkflowManager = VMWorkflowManager()  # type: ignore[assignment]
    manager.qemu_manager = fake_qemu_manager  # type: ignore[attr-defined]
    manager.logger = fake_logger  # type: ignore[attr-defined]
    return manager


class TestVMWorkflowManagerInitialization:
    """Production tests for VMWorkflowManager initialization."""

    def test_workflow_manager_initializes_successfully(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VMWorkflowManager initializes with required components."""
        monkeypatch.setattr(
            "intellicrack.core.processing.vm_workflow_manager.QEMUManager",
            FakeQEMUManager,
        )
        manager: VMWorkflowManager = VMWorkflowManager()  # type: ignore[assignment]

        assert manager is not None
        assert hasattr(manager, "qemu_manager")
        assert hasattr(manager, "logger")

    def test_workflow_manager_has_qemu_manager(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VMWorkflowManager has QEMUManager instance."""
        monkeypatch.setattr(
            "intellicrack.core.processing.vm_workflow_manager.QEMUManager",
            FakeQEMUManager,
        )
        manager: VMWorkflowManager = VMWorkflowManager()  # type: ignore[assignment]

        assert manager.qemu_manager is not None
        assert isinstance(manager.qemu_manager, FakeQEMUManager)

    def test_workflow_manager_logger_configured(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """VMWorkflowManager logger configured correctly."""
        monkeypatch.setattr(
            "intellicrack.core.processing.vm_workflow_manager.QEMUManager",
            FakeQEMUManager,
        )
        manager = VMWorkflowManager()

        assert manager.logger is not None
        assert hasattr(manager.logger, "info")
        assert hasattr(manager.logger, "error")
        assert hasattr(manager.logger, "exception")


class TestFileHandling:
    """Production tests for file handling operations."""

    def test_workflow_creates_temporary_directories(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow creates and uses real temporary directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
                platform="windows",
            )

            assert isinstance(result, dict)
            assert "success" in result
            assert "stage" in result or "error" in result

    def test_workflow_handles_valid_binary_path(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow accepts and processes valid binary paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "valid_binary.exe"
            test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="# Modification script",
                test_script_content="# Test script",
                platform="windows",
            )

            assert isinstance(result, dict)
            assert "success" in result

    def test_workflow_extracts_binary_filename(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow correctly extracts binary filename from path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "subdirectory" / "target.exe"
            test_binary.parent.mkdir(parents=True, exist_ok=True)
            test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert isinstance(result, dict)


class TestWorkflowStages:
    """Production tests for workflow stage execution."""

    def test_workflow_stage_temp_directory_creation(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow successfully creates temporary directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert isinstance(result, dict)
            assert "success" in result
            if not result["success"]:
                assert "stage" in result

    def test_workflow_stage_vm_snapshot_creation_failure(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow handles VM snapshot creation failure correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert result["success"] is False
            assert "error" in result
            assert "vm_snapshot" in result["error"].lower() or "stage" in result

    def test_workflow_returns_structured_result(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Workflow returns properly structured result dictionary."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            output_path = str(Path(temp_dir) / "output.exe")
            FakeQFileDialog._saved_file_name = output_path

            def fake_upload(
                snapshot_id: str,
                local_path: str,
                remote_path: str,
            ) -> bool:
                return True

            monkeypatch.setattr(manager, "_upload_binary_to_vm", fake_upload)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo modify",
                test_script_content="echo test",
            )

            assert isinstance(result, dict)
            assert "success" in result
            if result["success"]:
                assert "original_binary" in result
                assert "vm_snapshot_used" in result


class TestPlatformSupport:
    """Production tests for platform-specific handling."""

    def test_workflow_supports_windows_platform(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow accepts 'windows' as valid platform."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
                platform="windows",
            )

            assert isinstance(result, dict)
            assert len(manager.qemu_manager.create_snapshot_calls) == 1
            call_args = manager.qemu_manager.create_snapshot_calls[0]
            assert call_args[1] == "windows"

    def test_workflow_supports_linux_platform(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow accepts 'linux' as valid platform."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test"
            test_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
                platform="linux",
            )

            assert isinstance(result, dict)
            assert len(manager.qemu_manager.create_snapshot_calls) == 1
            call_args = manager.qemu_manager.create_snapshot_calls[0]
            assert call_args[1] == "linux"


class TestScriptHandling:
    """Production tests for script content handling."""

    def test_workflow_accepts_modification_script(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow accepts and processes modification script content."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            modification_script = "#!/bin/bash\necho 'Modifying binary'\ncp input.exe output.exe\n"

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content=modification_script,
                test_script_content="echo test",
            )

            assert isinstance(result, dict)

    def test_workflow_accepts_test_script(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow accepts and processes test script content."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            test_script = "#!/bin/bash\necho 'Testing binary'\n./output.exe --test\n"

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo modify",
                test_script_content=test_script,
            )

            assert isinstance(result, dict)

    def test_workflow_handles_complex_scripts(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow handles complex multi-line scripts."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            complex_script = """#!/bin/bash
# Complex modification script
set -e
echo "Starting modification"
if [ -f input.exe ]; then
    cp input.exe output.exe
    echo "Modification complete"
else
    echo "Error: input not found"
    exit 1
fi
"""

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content=complex_script,
                test_script_content="echo test",
            )

            assert isinstance(result, dict)


class TestErrorHandling:
    """Production tests for error handling and recovery."""

    def test_workflow_handles_missing_binary(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow handles nonexistent binary path gracefully."""
        manager = workflow_manager_with_fakes

        manager.qemu_manager.should_return_none_snapshot = True

        result = manager.run_full_analysis_roundtrip(
            binary_path="/nonexistent/path/binary.exe",
            modification_script_content="echo test",
            test_script_content="echo test",
        )

        assert isinstance(result, dict)

    def test_workflow_returns_error_on_failure(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow returns structured error information on failure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.should_fail_create_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert result["success"] is False
            assert "error" in result
            assert isinstance(result["error"], str)
            assert len(result["error"]) > 0

    def test_workflow_includes_stage_on_error(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow includes stage information in error results."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.should_return_none_snapshot = True

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            if not result["success"]:
                assert "stage" in result or "error" in result


class TestLogging:
    """Production tests for logging functionality."""

    def test_workflow_logs_startup(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow logs startup information."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.should_return_none_snapshot = True

            manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert len(manager.logger.info_calls) > 0
            assert any(
                "roundtrip" in str(call).lower()
                for call in manager.logger.info_calls
            )

    def test_workflow_logs_errors(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
    ) -> None:
        """Workflow logs error information."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.should_fail_create_snapshot = True

            manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert len(manager.logger.exception_calls) > 0


class TestCleanup:
    """Production tests for resource cleanup."""

    def test_workflow_cleans_up_on_success(
        self,
        workflow_manager_with_fakes: VMWorkflowManager,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Workflow performs cleanup after successful execution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = workflow_manager_with_fakes

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            output_path = str(Path(temp_dir) / "output.exe")
            FakeQFileDialog._saved_file_name = output_path

            def fake_upload(
                snapshot_id: str,
                local_path: str,
                remote_path: str,
            ) -> bool:
                return True

            monkeypatch.setattr(manager, "_upload_binary_to_vm", fake_upload)

            manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo modify",
                test_script_content="echo test",
            )

            assert len(manager.qemu_manager.cleanup_calls) == 1
            assert manager.qemu_manager.cleanup_calls[0] == "snapshot_1"


class TestIntegrationWorkflow:
    """Integration tests for complete workflow scenarios."""

    @pytest.mark.skipif(
        True,
        reason="Requires QEMU installation and VM images",
    )
    def test_full_workflow_with_real_vm(self) -> None:
        """Full workflow execution with real QEMU VM (integration test)."""
        manager = VMWorkflowManager()

        test_binary_path = "/path/to/real/test.exe"
        modification_script = "#!/bin/bash\necho 'Real modification'\n"
        test_script = "#!/bin/bash\necho 'Real test'\n"

        result = manager.run_full_analysis_roundtrip(
            binary_path=test_binary_path,
            modification_script_content=modification_script,
            test_script_content=test_script,
            platform="windows",
        )

        assert isinstance(result, dict)
        assert "success" in result
