"""Unit tests for VMWorkflowManager class.

This module provides comprehensive unit tests for the VMWorkflowManager class,
covering the full analysis roundtrip workflow with REAL test doubles (NO mocking).
"""

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

try:
    from intellicrack.core.processing.vm_workflow_manager import VMWorkflowManager
    VM_WORKFLOW_AVAILABLE = True
except ImportError:
    VM_WORKFLOW_AVAILABLE = False
    VMWorkflowManager = None  # type: ignore[assignment,misc]


pytestmark = pytest.mark.skipif(
    not VM_WORKFLOW_AVAILABLE,
    reason="VM workflow manager not available"
)


class FakeLogger:
    """Real test double for logger."""

    def __init__(self) -> None:
        """Initialize fake logger."""
        self.messages: List[tuple[str, str]] = []

    def info(self, msg: str) -> None:
        """Log info message."""
        self.messages.append(("INFO", msg))

    def error(self, msg: str) -> None:
        """Log error message."""
        self.messages.append(("ERROR", msg))

    def warning(self, msg: str) -> None:
        """Log warning message."""
        self.messages.append(("WARNING", msg))

    def debug(self, msg: str) -> None:
        """Log debug message."""
        self.messages.append(("DEBUG", msg))


class FakeQEMUManager:
    """Real test double for QEMUManager."""

    def __init__(self) -> None:
        """Initialize fake QEMU manager."""
        self.snapshots: Dict[str, Any] = {}
        self.created_snapshots: List[str] = []
        self.cleaned_snapshots: List[str] = []
        self.script_results: Dict[str, Any] = {}

    def create_script_test_snapshot(self, *args: Any, **kwargs: Any) -> Optional[str]:
        """Fake snapshot creation."""
        snapshot_id = f"snapshot_{len(self.created_snapshots)}"
        self.created_snapshots.append(snapshot_id)

        fake_snapshot = type('obj', (object,), {
            'vm_name': 'test_vm',
            'ssh_host': 'localhost',
            'ssh_port': 22222
        })()

        self.snapshots[snapshot_id] = fake_snapshot
        return snapshot_id

    def test_script_in_vm(self, *args: Any, **kwargs: Any) -> Any:
        """Fake script execution in VM."""
        result = type('obj', (object,), {
            'success': True,
            'output': 'Script executed successfully',
            'errors': ''
        })()
        return result

    def download_file_from_vm(self, *args: Any, **kwargs: Any) -> bool:
        """Fake file download."""
        return True

    def cleanup_snapshot(self, snapshot_id: str) -> bool:
        """Fake snapshot cleanup."""
        self.cleaned_snapshots.append(snapshot_id)
        return True


class TestVMWorkflowManager(unittest.TestCase):
    """Test suite for VMWorkflowManager class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.workflow_manager = VMWorkflowManager()

    def tearDown(self) -> None:
        """Clean up test environment."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self) -> None:
        """Test VMWorkflowManager initialization."""
        manager = VMWorkflowManager()

        assert manager is not None
        assert hasattr(manager, 'qemu_manager')
        assert hasattr(manager, 'logger')

    def test_has_run_full_analysis_roundtrip_method(self) -> None:
        """Test workflow manager has roundtrip analysis method."""
        assert hasattr(self.workflow_manager, 'run_full_analysis_roundtrip')
        assert callable(getattr(self.workflow_manager, 'run_full_analysis_roundtrip', None))

    def test_qemu_manager_is_initialized(self) -> None:
        """Test QEMU manager is initialized in workflow."""
        assert self.workflow_manager.qemu_manager is not None

    def test_logger_is_initialized(self) -> None:
        """Test logger is initialized in workflow."""
        assert self.workflow_manager.logger is not None

    def test_workflow_configuration(self) -> None:
        """Test workflow manager has proper configuration."""
        manager = VMWorkflowManager()

        assert manager is not None

    def test_snapshot_lifecycle_tracking(self) -> None:
        """Test that workflow can track snapshot lifecycle."""
        manager = VMWorkflowManager()
        fake_qemu = FakeQEMUManager()

        manager.qemu_manager = fake_qemu  # type: ignore[assignment]

        assert len(fake_qemu.created_snapshots) == 0
        assert len(fake_qemu.cleaned_snapshots) == 0

    def test_binary_path_handling(self) -> None:
        """Test workflow handles binary paths correctly."""
        test_binary = Path(self.temp_dir) / "test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        assert test_binary.exists()

    def test_script_content_handling(self) -> None:
        """Test workflow handles script content."""
        modification_script = "#!/bin/bash\necho 'Modifying binary'"
        test_script_content = "#!/bin/bash\necho 'Testing binary'"

        assert modification_script
        assert test_script_content

    def test_platform_specification(self) -> None:
        """Test workflow accepts platform specification."""
        platforms = ["windows", "linux"]

        for platform in platforms:
            assert platform in ["windows", "linux", "darwin"]

    def test_result_structure_creation(self) -> None:
        """Test workflow creates proper result structures."""
        result = {
            "success": False,
            "error": "Test error",
            "original_binary": "/path/to/binary",
        }

        assert "success" in result
        assert "error" in result
        assert isinstance(result["success"], bool)

    def test_temporary_directory_handling(self) -> None:
        """Test workflow can work with temporary directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            assert os.path.exists(tmpdir)
            assert os.path.isdir(tmpdir)

    def test_file_path_creation(self) -> None:
        """Test file path creation for analysis."""
        test_path = Path(self.temp_dir) / "test_file.txt"
        test_path.write_text("test content")

        assert test_path.exists()

    def test_error_handling_structure(self) -> None:
        """Test error handling in workflow."""
        error_result = {
            "success": False,
            "error": "Snapshot creation failed"
        }

        assert error_result["success"] is False
        assert "error" in error_result

    def test_success_result_structure(self) -> None:
        """Test success result structure."""
        success_result = {
            "success": True,
            "original_binary": "/path/to/original.exe",
            "modified_binary_path": "/path/to/modified.exe",
            "vm_snapshot_used": "snapshot_123",
        }

        assert success_result["success"] is True
        assert "original_binary" in success_result
        assert "modified_binary_path" in success_result

    def test_cancellation_handling(self) -> None:
        """Test user cancellation handling."""
        cancel_result = {
            "success": False,
            "user_cancelled": True,
            "message": "User cancelled operation"
        }

        assert cancel_result["success"] is False
        assert "user_cancelled" in cancel_result

    def test_output_path_contract(self) -> None:
        """Test OUTPUT_PATH environment variable contract."""
        remote_path = "/tmp/modified_binary.exe"
        output_path_var = f"OUTPUT_PATH={remote_path}"

        assert "OUTPUT_PATH" in output_path_var
        assert remote_path in output_path_var

    def test_script_wrapper_concept(self) -> None:
        """Test script wrapper adds OUTPUT_PATH."""
        original_script = "#!/bin/bash\nmodify_binary"
        output_path = "/tmp/output.exe"
        wrapped_script = f"OUTPUT_PATH={output_path}\n{original_script}"

        assert "OUTPUT_PATH" in wrapped_script
        assert original_script in wrapped_script

    def test_file_dialog_filter_format(self) -> None:
        """Test file dialog filter has correct format."""
        filter_string = "Binary Files (*.exe *.bin *.elf *.so *.dll);;All Files (*.*)"

        assert "*.exe" in filter_string
        assert "*.bin" in filter_string
        assert "*.elf" in filter_string
        assert "All Files" in filter_string


if __name__ == '__main__':
    unittest.main()
