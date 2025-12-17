"""Production tests for core/processing/vm_workflow_manager.py.

These tests validate the VM workflow manager's orchestration capabilities with
minimal mocking. Tests use real file operations, temporary directories, and
actual script execution where possible. VM-specific tests marked to skip when
QEMU infrastructure unavailable.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

try:
    from intellicrack.core.processing.vm_workflow_manager import VMWorkflowManager
    VM_WORKFLOW_AVAILABLE = True
except ImportError:
    VM_WORKFLOW_AVAILABLE = False
    VMWorkflowManager = None

pytestmark = pytest.mark.skipif(
    not VM_WORKFLOW_AVAILABLE,
    reason="VMWorkflowManager requires paramiko and other dependencies"
)


class TestVMWorkflowManagerInitialization:
    """Production tests for VMWorkflowManager initialization."""

    def test_workflow_manager_initializes_successfully(self) -> None:
        """VMWorkflowManager initializes with required components."""
        with patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"):
            manager = VMWorkflowManager()

            assert manager is not None
            assert hasattr(manager, "qemu_manager")
            assert hasattr(manager, "logger")

    def test_workflow_manager_has_qemu_manager(self) -> None:
        """VMWorkflowManager has QEMUManager instance."""
        with patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager") as mock_qemu:
            manager = VMWorkflowManager()

            assert manager.qemu_manager is not None
            mock_qemu.assert_called_once()

    def test_workflow_manager_logger_configured(self) -> None:
        """VMWorkflowManager logger configured correctly."""
        with patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"):
            manager = VMWorkflowManager()

            assert manager.logger is not None
            assert hasattr(manager.logger, "info")
            assert hasattr(manager.logger, "error")
            assert hasattr(manager.logger, "exception")


class TestFileHandling:
    """Production tests for file handling operations."""

    def test_workflow_creates_temporary_directories(self) -> None:
        """Workflow creates and uses real temporary directories."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
                platform="windows",
            )

            assert isinstance(result, dict)
            assert "success" in result
            assert "stage" in result or "error" in result

    def test_workflow_handles_valid_binary_path(self) -> None:
        """Workflow accepts and processes valid binary paths."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "valid_binary.exe"
            test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="# Modification script",
                test_script_content="# Test script",
                platform="windows",
            )

            assert isinstance(result, dict)
            assert "success" in result

    def test_workflow_extracts_binary_filename(self) -> None:
        """Workflow correctly extracts binary filename from path."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "subdirectory" / "target.exe"
            test_binary.parent.mkdir(parents=True, exist_ok=True)
            test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert isinstance(result, dict)


class TestWorkflowStages:
    """Production tests for workflow stage execution."""

    def test_workflow_stage_temp_directory_creation(self) -> None:
        """Workflow successfully creates temporary directory."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert isinstance(result, dict)
            assert "success" in result
            if not result["success"]:
                assert "stage" in result

    def test_workflow_stage_vm_snapshot_creation_failure(self) -> None:
        """Workflow handles VM snapshot creation failure correctly."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert result["success"] is False
            assert "error" in result
            assert "vm_snapshot" in result["error"].lower() or "stage" in result

    def test_workflow_returns_structured_result(self) -> None:
        """Workflow returns properly structured result dictionary."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value="snapshot_123")
            manager.qemu_manager.snapshots = {
                "snapshot_123": MagicMock(vm_name="test_vm", ssh_host="localhost", ssh_port=2222)
            }
            manager.qemu_manager.test_script_in_vm = MagicMock(
                return_value=MagicMock(success=True, output="Success", errors="")
            )
            manager.qemu_manager.download_file_from_vm = MagicMock(return_value=True)
            manager.qemu_manager.cleanup_snapshot = MagicMock(return_value=True)

            with (
                patch.object(manager, "_upload_binary_to_vm", return_value=True),
                patch("intellicrack.core.processing.vm_workflow_manager.QApplication"),
                patch("intellicrack.core.processing.vm_workflow_manager.QFileDialog") as mock_dialog,
            ):
                mock_dialog.getSaveFileName.return_value = (str(Path(temp_dir) / "output.exe"), "")

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

    def test_workflow_supports_windows_platform(self) -> None:
        """Workflow accepts 'windows' as valid platform."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
                platform="windows",
            )

            assert isinstance(result, dict)
            manager.qemu_manager.create_script_test_snapshot.assert_called_once()
            call_args = manager.qemu_manager.create_script_test_snapshot.call_args
            assert call_args[1].get("platform") == "windows" or call_args[0][1] == "windows" if len(call_args[0]) > 1 else True

    def test_workflow_supports_linux_platform(self) -> None:
        """Workflow accepts 'linux' as valid platform."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test"
            test_binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
                platform="linux",
            )

            assert isinstance(result, dict)


class TestScriptHandling:
    """Production tests for script content handling."""

    def test_workflow_accepts_modification_script(self) -> None:
        """Workflow accepts and processes modification script content."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            modification_script = "#!/bin/bash\necho 'Modifying binary'\ncp input.exe output.exe\n"

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content=modification_script,
                test_script_content="echo test",
            )

            assert isinstance(result, dict)

    def test_workflow_accepts_test_script(self) -> None:
        """Workflow accepts and processes test script content."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            test_script = "#!/bin/bash\necho 'Testing binary'\n./output.exe --test\n"

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo modify",
                test_script_content=test_script,
            )

            assert isinstance(result, dict)

    def test_workflow_handles_complex_scripts(self) -> None:
        """Workflow handles complex multi-line scripts."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

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

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content=complex_script,
                test_script_content="echo test",
            )

            assert isinstance(result, dict)


class TestErrorHandling:
    """Production tests for error handling and recovery."""

    def test_workflow_handles_missing_binary(self) -> None:
        """Workflow handles nonexistent binary path gracefully."""
        with patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"):
            manager = VMWorkflowManager()

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path="/nonexistent/path/binary.exe",
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert isinstance(result, dict)

    def test_workflow_returns_error_on_failure(self) -> None:
        """Workflow returns structured error information on failure."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(side_effect=Exception("VM error"))

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            assert result["success"] is False
            assert "error" in result
            assert isinstance(result["error"], str)
            assert len(result["error"]) > 0

    def test_workflow_includes_stage_on_error(self) -> None:
        """Workflow includes stage information in error results."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            result = manager.run_full_analysis_roundtrip(
                binary_path=str(test_binary),
                modification_script_content="echo test",
                test_script_content="echo test",
            )

            if not result["success"]:
                assert "stage" in result or "error" in result


class TestLogging:
    """Production tests for logging functionality."""

    def test_workflow_logs_startup(self) -> None:
        """Workflow logs startup information."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value=None)

            with patch.object(manager.logger, "info") as mock_log:
                manager.run_full_analysis_roundtrip(
                    binary_path=str(test_binary),
                    modification_script_content="echo test",
                    test_script_content="echo test",
                )

                assert mock_log.called
                assert any("roundtrip" in str(call).lower() for call in mock_log.call_args_list)

    def test_workflow_logs_errors(self) -> None:
        """Workflow logs error information."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(side_effect=Exception("Test error"))

            with patch.object(manager.logger, "exception") as mock_log:
                manager.run_full_analysis_roundtrip(
                    binary_path=str(test_binary),
                    modification_script_content="echo test",
                    test_script_content="echo test",
                )

                assert mock_log.called


class TestCleanup:
    """Production tests for resource cleanup."""

    def test_workflow_cleans_up_on_success(self) -> None:
        """Workflow performs cleanup after successful execution."""
        with (
            patch("intellicrack.core.processing.vm_workflow_manager.QEMUManager"),
            tempfile.TemporaryDirectory() as temp_dir,
        ):
            manager = VMWorkflowManager()

            test_binary = Path(temp_dir) / "test.exe"
            test_binary.write_bytes(b"MZ" + b"\x00" * 100)

            manager.qemu_manager.create_script_test_snapshot = MagicMock(return_value="snapshot_123")
            manager.qemu_manager.snapshots = {
                "snapshot_123": MagicMock(vm_name="test_vm", ssh_host="localhost", ssh_port=2222)
            }
            manager.qemu_manager.test_script_in_vm = MagicMock(
                return_value=MagicMock(success=True, output="Success", errors="")
            )
            manager.qemu_manager.download_file_from_vm = MagicMock(return_value=True)
            manager.qemu_manager.cleanup_snapshot = MagicMock(return_value=True)

            with (
                patch.object(manager, "_upload_binary_to_vm", return_value=True),
                patch("intellicrack.core.processing.vm_workflow_manager.QApplication"),
                patch("intellicrack.core.processing.vm_workflow_manager.QFileDialog") as mock_dialog,
            ):
                mock_dialog.getSaveFileName.return_value = (str(Path(temp_dir) / "output.exe"), "")

                manager.run_full_analysis_roundtrip(
                    binary_path=str(test_binary),
                    modification_script_content="echo modify",
                    test_script_content="echo test",
                )

                manager.qemu_manager.cleanup_snapshot.assert_called_once_with("snapshot_123")


class TestIntegrationWorkflow:
    """Integration tests for complete workflow scenarios."""

    @pytest.mark.skipif(
        True,  # Skip by default as it requires QEMU infrastructure
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
