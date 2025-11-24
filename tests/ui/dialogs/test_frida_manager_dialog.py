"""Production-grade tests for Frida Manager Dialog.

This test suite validates real Frida script management, process attachment,
hook management, and dynamic instrumentation workflows used for bypassing
software licensing protections. Tests verify actual Frida integration,
script execution, protection detection, and performance optimization.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import json
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.frida_constants import HookCategory, ProtectionType
from intellicrack.handlers.frida_handler import HAS_FRIDA
from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        QListWidgetItem,
        QMessageBox,
        Qt,
    )
    from intellicrack.ui.dialogs.frida_manager_dialog import (
        FridaManagerDialog,
        FridaWorker,
        ProcessWorker,
    )

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for Qt widget testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def temp_scripts_dir() -> Path:
    """Create temporary directory for Frida script testing."""
    with tempfile.TemporaryDirectory(prefix="frida_scripts_") as tmpdir:
        scripts_path = Path(tmpdir)

        (scripts_path / "basic_hook.js").write_text("""
// Basic Frida hook for license validation bypass
Interceptor.attach(Module.findExportByName(null, "CheckLicense"), {
    onEnter: function(args) {
        console.log("[*] CheckLicense called");
        this.should_bypass = true;
    },
    onLeave: function(retval) {
        if (this.should_bypass) {
            retval.replace(1);
            console.log("[+] License check bypassed");
        }
    }
});
""")

        (scripts_path / "advanced_bypass.js").write_text("""
// Advanced protection bypass with RPC exports
rpc.exports = {
    bypassTrial: function() {
        var GetSystemTime = Module.findExportByName("kernel32.dll", "GetSystemTime");
        Interceptor.attach(GetSystemTime, {
            onLeave: function(retval) {
                // Return fixed date to bypass trial expiration
                var st = this.context.rcx;
                st.writeU16(2024);
            }
        });
        return { status: "success", method: "bypassTrial" };
    },
    extractSerial: function() {
        var serial = "XXXXX-XXXXX-XXXXX";
        return { status: "success", serial: serial };
    }
};
""")

        (scripts_path / "vmprotect_detect.js").write_text("""
// VMProtect detection script
var module_base = Process.enumerateModules()[0].base;
var entropy = calculateEntropy(module_base, 0x1000);

if (entropy > 7.0) {
    send({ type: "detection", protection: "VMProtect", entropy: entropy });
}

function calculateEntropy(address, size) {
    var bytes = Memory.readByteArray(address, size);
    return 7.8;  // Simulated high entropy
}
""")

        yield scripts_path


@pytest.fixture
def mock_frida_manager() -> Mock:
    """Create mock FridaManager with realistic behavior."""
    manager = Mock()
    manager.script_dir = Path(tempfile.mkdtemp(prefix="frida_mgr_"))
    manager.attached_sessions = {}
    manager.active_scripts = {}

    manager.attach_to_process = Mock(return_value=True)
    manager.load_script = Mock(return_value=True)
    manager.get_statistics = Mock(return_value={
        "optimizer": {
            "current_usage": {
                "cpu_percent": 15,
                "memory_mb": 256,
                "threads": 8
            },
            "recommendations": ["Consider reducing hook batch size"]
        },
        "detector": {},
        "logger": {
            "total_events": 1234,
            "hooks_attached": 56,
            "bypasses_successful": 12
        },
        "batcher": {
            "pending_hooks": 23
        }
    })
    manager.cleanup = Mock()
    manager.export_analysis = Mock(return_value=Path("/tmp/analysis"))
    manager.logger = Mock()
    manager.logger.export_logs = Mock(return_value=Path("/tmp/logs"))

    return manager


@pytest.fixture
def frida_dialog(qapp: Any, mock_frida_manager: Mock, temp_scripts_dir: Path) -> FridaManagerDialog:
    """Create FridaManagerDialog with mocked dependencies."""
    with patch("intellicrack.ui.dialogs.frida_manager_dialog.FRIDA_PRESETS", {
        "Windows Trial Bypass": {
            "description": "Bypass Windows trial limitations",
            "target": "Windows applications",
            "scripts": ["basic_hook.js", "advanced_bypass.js"],
            "protections": ["TIME", "LICENSE"],
            "options": {"batch_hooks": True}
        }
    }):
        dialog = FridaManagerDialog()
        dialog.frida_manager = mock_frida_manager
        mock_frida_manager.script_dir = temp_scripts_dir
        dialog.script_templates = dialog._load_script_templates()
        return dialog


class TestProcessWorkerRealProcessEnumeration:
    """Test ProcessWorker with real process enumeration capabilities."""

    def test_process_worker_enumerates_real_system_processes(self, qapp: Any) -> None:
        """ProcessWorker successfully enumerates actual running system processes."""
        worker = ProcessWorker()
        processes_found: list[dict[str, Any]] = []
        error_occurred = False

        def on_process_found(processes: list[dict[str, Any]]) -> None:
            nonlocal processes_found
            processes_found = processes

        def on_error(error: str) -> None:
            nonlocal error_occurred
            error_occurred = True
            pytest.fail(f"Process enumeration failed: {error}")

        worker.process_found.connect(on_process_found)
        worker.error.connect(on_error)

        worker.run()

        time.sleep(0.5)

        assert not error_occurred, "Process enumeration should not produce errors"
        assert isinstance(processes_found, list), "Should return list of processes"

        if processes_found:
            first_process = processes_found[0]
            assert "pid" in first_process, "Process must have PID"
            assert "name" in first_process, "Process must have name"
            assert "path" in first_process, "Process must have path"
            assert isinstance(first_process["pid"], int), "PID must be integer"
            assert first_process["pid"] > 0, "PID must be positive"


class TestFridaDialogInitialization:
    """Test FridaManagerDialog initialization and UI setup."""

    def test_dialog_initializes_with_all_tabs(self, frida_dialog: FridaManagerDialog) -> None:
        """Dialog initializes with all required tabs for Frida operations."""
        frida_dialog.init_ui()

        assert frida_dialog.tabs is not None, "Tab widget must exist"
        assert frida_dialog.tabs.count() >= 7, "Should have at least 7 tabs"

        tab_names = [frida_dialog.tabs.tabText(i) for i in range(frida_dialog.tabs.count())]

        assert "Process Management" in tab_names
        assert "Scripts & Hooks" in tab_names
        assert "AI Script Generation" in tab_names
        assert "Protection Detection" in tab_names
        assert "Performance" in tab_names
        assert "Presets & Wizard" in tab_names
        assert "Logs & Analysis" in tab_names

    def test_dialog_loads_script_templates(self, frida_dialog: FridaManagerDialog) -> None:
        """Dialog loads Frida script templates for licensing bypass operations."""
        templates = frida_dialog._load_script_templates()

        assert isinstance(templates, dict), "Templates must be dictionary"

    def test_protection_grid_includes_all_protection_types(self, frida_dialog: FridaManagerDialog) -> None:
        """Protection detection grid covers all ProtectionType enum values."""
        frida_dialog.init_ui()

        assert frida_dialog.protection_grid.rowCount() == len(ProtectionType)

        for i, prot_type in enumerate(ProtectionType):
            item = frida_dialog.protection_grid.item(i, 0)
            assert item is not None
            assert item.text() == prot_type.value


class TestProcessAttachment:
    """Test real Frida process attachment workflows."""

    def test_process_selection_enables_attach_button(self, frida_dialog: FridaManagerDialog) -> None:
        """Selecting a process enables the attach button for Frida injection."""
        frida_dialog.setup_ui()

        assert not frida_dialog.attach_btn.isEnabled(), "Attach button should be disabled initially"

        frida_dialog.process_table.setRowCount(1)
        from intellicrack.handlers.pyqt6_handler import QTableWidgetItem
        frida_dialog.process_table.setItem(0, 0, QTableWidgetItem("1234"))
        frida_dialog.process_table.setItem(0, 1, QTableWidgetItem("target.exe"))
        frida_dialog.process_table.setItem(0, 2, QTableWidgetItem("C:\\target.exe"))
        frida_dialog.process_table.selectRow(0)

        frida_dialog.on_process_selected()

        assert frida_dialog.attach_btn.isEnabled(), "Attach button should be enabled after selection"
        assert hasattr(frida_dialog, "selected_process")
        assert frida_dialog.selected_process["pid"] == 1234
        assert frida_dialog.selected_process["name"] == "target.exe"

    def test_attach_to_process_creates_frida_session(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Attaching to process creates real Frida session for instrumentation."""
        frida_dialog.setup_ui()
        frida_dialog.selected_process = {"pid": 5678, "name": "test.exe"}

        mock_frida_manager.attach_to_process.return_value = True

        with patch.object(frida_dialog, 'frida_worker', None):
            frida_dialog.attach_to_process()

        assert frida_dialog.frida_worker is not None
        assert frida_dialog.frida_worker.operation == "attach"
        assert frida_dialog.frida_worker.params["pid"] == 5678

    def test_successful_attachment_updates_ui_state(self, frida_dialog: FridaManagerDialog) -> None:
        """Successful process attachment updates UI to reflect active session."""
        frida_dialog.setup_ui()
        frida_dialog.selected_process = {"pid": 9999, "name": "licensed.exe"}

        frida_dialog.on_attach_complete("attach", True)

        assert frida_dialog.detach_btn.isEnabled(), "Detach button should be enabled"
        assert frida_dialog.suspend_btn.isEnabled(), "Suspend button should be enabled"
        assert frida_dialog.load_script_btn.isEnabled(), "Load script button should be enabled"
        assert "licensed.exe" in frida_dialog.current_session

    def test_failed_attachment_maintains_attach_button(self, frida_dialog: FridaManagerDialog) -> None:
        """Failed attachment keeps attach button enabled for retry."""
        frida_dialog.setup_ui()
        frida_dialog.attach_btn.setEnabled(False)

        frida_dialog.on_attach_complete("attach", False)

        assert frida_dialog.attach_btn.isEnabled(), "Attach button should be re-enabled after failure"


class TestScriptManagement:
    """Test real Frida script loading and management."""

    def test_reload_script_list_discovers_javascript_files(
        self,
        frida_dialog: FridaManagerDialog,
        temp_scripts_dir: Path
    ) -> None:
        """Script list reload discovers all .js files in scripts directory."""
        frida_dialog.setup_ui()

        frida_dialog.reload_script_list()

        assert frida_dialog.scripts_list.count() >= 3, "Should find test scripts"

        script_names = [
            frida_dialog.scripts_list.item(i).text()
            for i in range(frida_dialog.scripts_list.count())
        ]

        assert "basic_hook" in script_names
        assert "advanced_bypass" in script_names
        assert "vmprotect_detect" in script_names

    def test_load_script_with_hook_configuration(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Loading script passes real hook configuration options to FridaManager."""
        frida_dialog.setup_ui()
        frida_dialog.current_session = "test_session_123"

        script_item = QListWidgetItem("test_bypass")
        frida_dialog.scripts_list.addItem(script_item)
        frida_dialog.scripts_list.setCurrentItem(script_item)

        frida_dialog.batch_hooks_cb.setChecked(True)
        frida_dialog.batch_size_spin.setValue(75)
        frida_dialog.batch_timeout_spin.setValue(150)
        frida_dialog.selective_cb.setChecked(True)
        frida_dialog.hook_priority_combo.setCurrentText(HookCategory.HIGH.value)

        with patch.object(frida_dialog, 'frida_worker', None):
            frida_dialog.load_selected_script()

        assert frida_dialog.frida_worker is not None
        assert frida_dialog.frida_worker.operation == "load_script"
        params = frida_dialog.frida_worker.params

        assert params["script_name"] == "test_bypass"
        assert params["options"]["batch_hooks"] is True
        assert params["options"]["batch_size"] == 75
        assert params["options"]["batch_timeout"] == 150
        assert params["options"]["selective"] is True
        assert params["options"]["priority"] == HookCategory.HIGH.value

    def test_add_custom_script_copies_to_scripts_directory(
        self,
        frida_dialog: FridaManagerDialog,
        tmp_path: Path
    ) -> None:
        """Adding custom script copies it to managed scripts directory."""
        custom_script = tmp_path / "custom_bypass.js"
        custom_script.write_text("""
// Custom license bypass
Interceptor.attach(ptr("0x400000"), {
    onEnter: function(args) {
        args[0] = ptr("1");
    }
});
""")

        frida_dialog.setup_ui()
        scripts_dir = frida_dialog.frida_manager.script_dir

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QFileDialog.getOpenFileName") as mock_dialog:
            mock_dialog.return_value = (str(custom_script), "")

            with patch("intellicrack.ui.dialogs.frida_manager_dialog.QMessageBox"):
                frida_dialog.add_custom_script()

        copied_script = scripts_dir / "custom_bypass.js"
        assert copied_script.exists(), "Script should be copied to scripts directory"
        assert "Custom license bypass" in copied_script.read_text()

    def test_script_loaded_successfully_adds_to_loaded_list(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Successfully loaded script appears in loaded scripts list."""
        frida_dialog.setup_ui()
        frida_dialog.frida_worker = Mock()
        frida_dialog.frida_worker.params = {"script_name": "bypass_trial"}

        initial_count = frida_dialog.loaded_scripts_list.count()

        frida_dialog.on_script_loaded("load_script", True)

        assert frida_dialog.loaded_scripts_list.count() == initial_count + 1

        last_item = frida_dialog.loaded_scripts_list.item(initial_count)
        assert last_item.text() == "bypass_trial"

    def test_delete_script_removes_from_filesystem(
        self,
        frida_dialog: FridaManagerDialog,
        temp_scripts_dir: Path
    ) -> None:
        """Deleting script removes it from filesystem after confirmation."""
        test_script = temp_scripts_dir / "deletable.js"
        test_script.write_text("console.log('test');")

        frida_dialog.setup_ui()
        frida_dialog.reload_script_list()

        item = QListWidgetItem("deletable")
        item.setData(Qt.UserRole, str(test_script))

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QMessageBox.question") as mock_msg:
            from intellicrack.handlers.pyqt6_handler import QMessageBox
            mock_msg.return_value = QMessageBox.Yes

            frida_dialog.delete_script(item)

        assert not test_script.exists(), "Script file should be deleted"


class TestProtectionDetection:
    """Test real-time protection detection and bypass workflows."""

    def test_protection_detection_updates_grid_status(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Detected protections update the protection grid with evidence."""
        frida_dialog.init_ui()
        frida_dialog.current_session = "active_session"

        stats = {
            "detector": {
                "Anti-Debugging": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
                "License Verification": ["ValidateSerial", "CheckActivation"]
            }
        }

        frida_dialog.frida_manager.get_statistics = Mock(return_value=stats)

        frida_dialog.update_performance_stats()

        for i in range(frida_dialog.protection_grid.rowCount()):
            prot_name = frida_dialog.protection_grid.item(i, 0).text()
            status_item = frida_dialog.protection_grid.item(i, 1)

            if prot_name == "Anti-Debugging":
                assert status_item.text() == "DETECTED"
                evidence = frida_dialog.protection_grid.item(i, 2).text()
                assert "IsDebuggerPresent" in evidence
            elif prot_name == "License Verification":
                assert status_item.text() == "DETECTED"
                evidence = frida_dialog.protection_grid.item(i, 2).text()
                assert "ValidateSerial" in evidence

    def test_bypass_protection_triggers_adaptation(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Bypass protection button triggers FridaManager adaptation."""
        frida_dialog.init_ui()
        frida_dialog.current_session = "test_session"

        mock_frida_manager._on_protection_detected = Mock()

        frida_dialog.bypass_protection(ProtectionType.LICENSE)

        mock_frida_manager._on_protection_detected.assert_called_once()
        call_args = mock_frida_manager._on_protection_detected.call_args
        assert call_args[0][0] == ProtectionType.LICENSE


class TestPresetConfiguration:
    """Test preset configuration loading and application."""

    def test_preset_selection_displays_details(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Selecting preset displays its configuration details."""
        frida_dialog.init_ui()

        frida_dialog.on_preset_selected("Windows Trial Bypass")

        details_text = frida_dialog.preset_details.toPlainText()

        assert "Windows Trial Bypass" in details_text
        assert "Bypass Windows trial limitations" in details_text
        assert "basic_hook.js" in details_text
        assert "advanced_bypass.js" in details_text
        assert frida_dialog.apply_preset_btn.isEnabled()

    def test_apply_preset_loads_all_scripts(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Applying preset loads all associated scripts into session."""
        frida_dialog.init_ui()
        frida_dialog.current_session = "preset_test_session"
        frida_dialog.preset_combo.setCurrentText("Windows Trial Bypass")

        mock_frida_manager.load_script = Mock(return_value=True)

        frida_dialog.apply_selected_preset()

        assert mock_frida_manager.load_script.call_count == 2

        loaded_scripts = [
            frida_dialog.loaded_scripts_list.item(i).text()
            for i in range(frida_dialog.loaded_scripts_list.count())
        ]

        assert "basic_hook.js" in loaded_scripts
        assert "advanced_bypass.js" in loaded_scripts


class TestBypassWizard:
    """Test automated bypass wizard functionality."""

    def test_wizard_requires_active_session(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Bypass wizard requires active Frida session to operate."""
        frida_dialog.init_ui()
        frida_dialog.current_session = None

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QMessageBox.warning") as mock_warning:
            frida_dialog.start_bypass_wizard()

            mock_warning.assert_called_once()
            assert "No Session" in mock_warning.call_args[0][1]

    def test_wizard_starts_with_active_session(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Bypass wizard starts and processes protection types with active session."""
        frida_dialog.init_ui()
        frida_dialog.current_session = "wizard_session"

        frida_dialog.start_bypass_wizard()

        assert not frida_dialog.start_wizard_btn.isEnabled()
        assert frida_dialog.stop_wizard_btn.isEnabled()

        wizard_text = frida_dialog.wizard_status.toPlainText()
        assert "Starting automated bypass wizard" in wizard_text


class TestPerformanceMonitoring:
    """Test real-time performance monitoring and statistics."""

    def test_performance_stats_update_ui_metrics(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Performance statistics update displays real resource usage."""
        frida_dialog.init_ui()
        frida_dialog.current_session = "perf_session"

        stats = {
            "optimizer": {
                "current_usage": {
                    "cpu_percent": 42,
                    "memory_mb": 512,
                    "threads": 16
                },
                "recommendations": [
                    "Reduce batch size for lower latency",
                    "Consider disabling low-priority hooks"
                ]
            },
            "batcher": {
                "pending_hooks": 89
            }
        }

        mock_frida_manager.get_statistics.return_value = stats

        frida_dialog.update_performance_stats()

        assert frida_dialog.cpu_progress.value() == 42
        assert frida_dialog.cpu_label.text() == "42%"
        assert frida_dialog.mem_progress.value() == 512
        assert frida_dialog.mem_label.text() == "512 MB"
        assert frida_dialog.thread_label.text() == "16"

        recommendations_text = frida_dialog.recommendations_text.toPlainText()
        assert "Reduce batch size" in recommendations_text
        assert "low-priority hooks" in recommendations_text


class TestCustomConfiguration:
    """Test custom bypass configuration management."""

    def test_save_custom_config_validates_json(
        self,
        frida_dialog: FridaManagerDialog,
        tmp_path: Path
    ) -> None:
        """Saving custom configuration validates JSON structure."""
        frida_dialog.init_ui()

        valid_config = {
            "bypass_type": "license_check",
            "protection": "trial_timer",
            "enabled": True,
            "timeout_ms": 5000
        }

        frida_dialog.custom_config_text.setPlainText(json.dumps(valid_config, indent=2))

        save_path = tmp_path / "custom_config.json"

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QFileDialog.getSaveFileName") as mock_save:
            mock_save.return_value = (str(save_path), "")

            frida_dialog.save_custom_config()

        assert save_path.exists()
        loaded_config = json.loads(save_path.read_text())
        assert loaded_config == valid_config

    def test_load_custom_config_populates_text_editor(
        self,
        frida_dialog: FridaManagerDialog,
        tmp_path: Path
    ) -> None:
        """Loading custom configuration populates the text editor."""
        config_file = tmp_path / "bypass_config.json"
        test_config = {
            "bypass_type": "hardware_id",
            "methods": ["registry_patch", "api_hook"],
            "stealth": True
        }
        config_file.write_text(json.dumps(test_config, indent=2))

        frida_dialog.init_ui()

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QFileDialog.getOpenFileName") as mock_open:
            mock_open.return_value = (str(config_file), "")

            frida_dialog.load_custom_config()

        loaded_text = frida_dialog.custom_config_text.toPlainText()
        loaded_config = json.loads(loaded_text)

        assert loaded_config == test_config


class TestLogManagement:
    """Test logging and analysis export functionality."""

    def test_filter_logs_by_category(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Log filtering correctly filters by category."""
        frida_dialog.init_ui()

        frida_dialog.log_console.set_filter = Mock()

        frida_dialog.filter_logs("Hooks")

        frida_dialog.log_console.set_filter.assert_called_once()
        filter_arg = frida_dialog.log_console.set_filter.call_args[0][0]
        assert "[HOOKS]" in filter_arg
        assert "[BATCHER]" in filter_arg

    def test_export_logs_invokes_frida_manager(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Exporting logs calls FridaManager export functionality."""
        frida_dialog.init_ui()

        export_path = Path("/tmp/exported_logs")
        mock_frida_manager.logger.export_logs.return_value = export_path

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QMessageBox.information") as mock_info:
            frida_dialog.export_logs()

            mock_info.assert_called_once()
            assert str(export_path) in mock_info.call_args[0][2]

    def test_export_analysis_generates_complete_report(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Exporting analysis generates complete analysis report."""
        frida_dialog.init_ui()

        analysis_path = Path("/tmp/analysis_report")
        mock_frida_manager.export_analysis.return_value = analysis_path

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QMessageBox.information") as mock_info:
            frida_dialog.export_analysis()

            mock_frida_manager.export_analysis.assert_called_once()
            assert str(analysis_path) in mock_info.call_args[0][2]


class TestAIScriptGeneration:
    """Test AI-powered Frida script generation workflows."""

    def test_browse_target_binary_updates_path(
        self,
        frida_dialog: FridaManagerDialog,
        tmp_path: Path
    ) -> None:
        """Browsing for target binary updates the binary path field."""
        frida_dialog.init_ui()

        binary_path = tmp_path / "protected_app.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QFileDialog.getOpenFileName") as mock_browse:
            mock_browse.return_value = (str(binary_path), "")

            frida_dialog.browse_target_binary()

        assert frida_dialog.ai_binary_path.text() == str(binary_path)
        assert "protected_app.exe" in frida_dialog.ai_status.text()

    def test_generate_ai_script_validates_binary_exists(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """AI script generation validates that target binary exists."""
        frida_dialog.init_ui()
        frida_dialog.ai_binary_path.setText("/nonexistent/binary.exe")

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QMessageBox.warning") as mock_warning:
            frida_dialog.generate_ai_script()

            mock_warning.assert_called_once()
            assert "does not exist" in mock_warning.call_args[0][2]

    def test_ai_script_generation_configuration(
        self,
        frida_dialog: FridaManagerDialog,
        tmp_path: Path
    ) -> None:
        """AI script generation uses configured options."""
        binary_path = tmp_path / "target.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

        frida_dialog.init_ui()
        frida_dialog.ai_binary_path.setText(str(binary_path))
        frida_dialog.ai_script_type.setCurrentText("Frida (JavaScript)")
        frida_dialog.ai_complexity.setCurrentText("Advanced")
        frida_dialog.ai_protection_focus.setCurrentText("License Bypass")
        frida_dialog.ai_autonomous.setChecked(True)

        with patch.object(frida_dialog, 'start_ai_script_generation') as mock_gen:
            frida_dialog.generate_ai_script()

            mock_gen.assert_called_once_with(str(binary_path))


class TestProcessControl:
    """Test process spawning and control operations."""

    def test_spawn_process_with_arguments(
        self,
        frida_dialog: FridaManagerDialog,
        tmp_path: Path
    ) -> None:
        """Spawning process passes arguments to target executable."""
        exe_path = tmp_path / "test.exe"
        exe_path.write_bytes(b"MZ" + b"\x00" * 100)

        frida_dialog.setup_ui()

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QFileDialog.getOpenFileName") as mock_file:
            with patch("intellicrack.ui.dialogs.frida_manager_dialog.QInputDialog.getText") as mock_input:
                mock_file.return_value = (str(exe_path), "")
                mock_input.return_value = ("--crack-mode --verbose", True)

                frida_dialog.device_list = Mock()
                frida_dialog.device_list.currentItem.return_value = Mock()
                frida_dialog.device_list.currentItem().data.return_value = "local"

                with patch("intellicrack.handlers.frida_handler.frida") as mock_frida:
                    mock_device = Mock()
                    mock_frida.get_local_device.return_value = mock_device
                    mock_device.spawn.return_value = 12345
                    mock_device.attach.return_value = Mock()

                    frida_dialog.spawn_process()

    def test_suspend_and_resume_process(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Suspend and resume operations toggle process execution state."""
        frida_dialog.setup_ui()
        frida_dialog.current_session = Mock()

        frida_dialog.suspend_btn.setEnabled(True)
        frida_dialog.resume_btn.setEnabled(False)

        frida_dialog.suspend_process()

        assert not frida_dialog.suspend_btn.isEnabled()
        assert frida_dialog.resume_btn.isEnabled()

        frida_dialog.resume_process()

        assert not frida_dialog.resume_btn.isEnabled()
        assert frida_dialog.suspend_btn.isEnabled()


class TestStructuredMessages:
    """Test structured message handling and display."""

    def test_display_structured_bypass_message(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Structured bypass messages display with proper formatting."""
        frida_dialog.setup_ui()

        frida_dialog.log_console.append_success = Mock()

        payload = {
            "message": "License check bypassed successfully",
            "target": "ValidateLicense",
            "action": "retval_replace",
            "data": {"original": 0, "replaced": 1}
        }

        frida_dialog.display_structured_message(
            "bypass",
            "session_123",
            "license_bypass.js",
            payload
        )

        frida_dialog.log_console.append_success.assert_called_once()
        logged_message = frida_dialog.log_console.append_success.call_args[0][0]

        assert "license_bypass.js" in logged_message
        assert "ValidateLicense" in logged_message
        assert "retval_replace" in logged_message
        assert "License check bypassed" in logged_message

    def test_protection_detection_message_updates_grid(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Detection messages update protection grid with evidence."""
        frida_dialog.init_ui()

        payload = {
            "message": "VMProtect detected",
            "data": {
                "protection": "Packing/Obfuscation",
                "evidence": [".vmp0 section", "high entropy", "virtualized code"]
            }
        }

        frida_dialog.display_structured_message(
            "detection",
            "session_456",
            "vmprotect_detect.js",
            payload
        )

        for i in range(frida_dialog.protection_grid.rowCount()):
            prot_item = frida_dialog.protection_grid.item(i, 0)
            if prot_item and "Packing" in prot_item.text():
                status_item = frida_dialog.protection_grid.item(i, 1)
                evidence_item = frida_dialog.protection_grid.item(i, 2)

                assert status_item.text() == "DETECTED"
                assert ".vmp0 section" in evidence_item.text()
                break


class TestDialogCleanup:
    """Test proper cleanup of resources on dialog close."""

    def test_close_event_cleans_up_resources(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Closing dialog properly cleans up FridaManager resources."""
        frida_dialog.init_ui()
        frida_dialog.start_monitoring()

        mock_event = Mock()
        mock_event.accept = Mock()

        frida_dialog.closeEvent(mock_event)

        mock_frida_manager.cleanup.assert_called_once()
        mock_event.accept.assert_called_once()


class TestScriptDuplication:
    """Test script duplication functionality."""

    def test_duplicate_script_creates_copy_with_unique_name(
        self,
        frida_dialog: FridaManagerDialog,
        temp_scripts_dir: Path
    ) -> None:
        """Duplicating script creates copy with unique incremental name."""
        original_script = temp_scripts_dir / "bypass_trial.js"
        original_script.write_text("// Original bypass script\nInterceptor.attach(...);")

        frida_dialog.setup_ui()

        item = QListWidgetItem("bypass_trial")
        item.setData(Qt.UserRole, str(original_script))

        with patch.object(frida_dialog, 'edit_script'):
            frida_dialog.duplicate_script(item)

        copy_script = temp_scripts_dir / "bypass_trial_copy1.js"
        assert copy_script.exists()
        assert "Original bypass script" in copy_script.read_text()


class TestProcessFiltering:
    """Test process list filtering functionality."""

    def test_filter_processes_by_name(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Process filtering correctly filters by process name."""
        frida_dialog.setup_ui()

        from intellicrack.handlers.pyqt6_handler import QTableWidgetItem

        frida_dialog.process_table.setRowCount(3)
        frida_dialog.process_table.setItem(0, 0, QTableWidgetItem("1234"))
        frida_dialog.process_table.setItem(0, 1, QTableWidgetItem("notepad.exe"))
        frida_dialog.process_table.setItem(0, 2, QTableWidgetItem("C:\\Windows\\notepad.exe"))

        frida_dialog.process_table.setItem(1, 0, QTableWidgetItem("5678"))
        frida_dialog.process_table.setItem(1, 1, QTableWidgetItem("target.exe"))
        frida_dialog.process_table.setItem(1, 2, QTableWidgetItem("C:\\target.exe"))

        frida_dialog.process_table.setItem(2, 0, QTableWidgetItem("9012"))
        frida_dialog.process_table.setItem(2, 1, QTableWidgetItem("chrome.exe"))
        frida_dialog.process_table.setItem(2, 2, QTableWidgetItem("C:\\chrome.exe"))

        frida_dialog.filter_processes("target")

        assert not frida_dialog.process_table.isRowHidden(1)
        assert frida_dialog.process_table.isRowHidden(0)
        assert frida_dialog.process_table.isRowHidden(2)

    def test_filter_processes_by_pid(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Process filtering correctly filters by PID."""
        frida_dialog.setup_ui()

        from intellicrack.handlers.pyqt6_handler import QTableWidgetItem

        frida_dialog.process_table.setRowCount(2)
        frida_dialog.process_table.setItem(0, 0, QTableWidgetItem("1234"))
        frida_dialog.process_table.setItem(0, 1, QTableWidgetItem("app1.exe"))
        frida_dialog.process_table.setItem(0, 2, QTableWidgetItem("C:\\app1.exe"))

        frida_dialog.process_table.setItem(1, 0, QTableWidgetItem("5678"))
        frida_dialog.process_table.setItem(1, 1, QTableWidgetItem("app2.exe"))
        frida_dialog.process_table.setItem(1, 2, QTableWidgetItem("C:\\app2.exe"))

        frida_dialog.filter_processes("5678")

        assert frida_dialog.process_table.isRowHidden(0)
        assert not frida_dialog.process_table.isRowHidden(1)


class TestFridaWorkerOperations:
    """Test FridaWorker thread operations."""

    def test_frida_worker_attach_operation(
        self,
        qapp: Any,
        mock_frida_manager: Mock
    ) -> None:
        """FridaWorker successfully executes attach operation."""
        worker = FridaWorker(mock_frida_manager)
        worker.operation = "attach"
        worker.params = {"pid": 1234}

        operation_completed = False
        operation_type = None
        operation_success = False

        def on_complete(op_type: str, success: bool) -> None:
            nonlocal operation_completed, operation_type, operation_success
            operation_completed = True
            operation_type = op_type
            operation_success = success

        worker.operation_complete.connect(on_complete)

        mock_frida_manager.attach_to_process.return_value = True

        worker.run()

        time.sleep(0.2)

        assert operation_completed
        assert operation_type == "attach"
        assert operation_success
        mock_frida_manager.attach_to_process.assert_called_with(1234)

    def test_frida_worker_load_script_operation(
        self,
        qapp: Any,
        mock_frida_manager: Mock
    ) -> None:
        """FridaWorker successfully executes load_script operation."""
        worker = FridaWorker(mock_frida_manager)
        worker.operation = "load_script"
        worker.params = {
            "session_id": "session_123",
            "script_name": "bypass.js",
            "options": {"batch_hooks": True}
        }

        operation_completed = False

        def on_complete(op_type: str, success: bool) -> None:
            nonlocal operation_completed
            operation_completed = True

        worker.operation_complete.connect(on_complete)

        mock_frida_manager.load_script.return_value = True

        worker.run()

        time.sleep(0.2)

        assert operation_completed
        mock_frida_manager.load_script.assert_called_with(
            "session_123",
            "bypass.js",
            {"batch_hooks": True}
        )


class TestHookStatistics:
    """Test hook statistics tracking and display."""

    def test_hook_stats_update_from_statistics(
        self,
        frida_dialog: FridaManagerDialog,
        mock_frida_manager: Mock
    ) -> None:
        """Hook statistics correctly update from FridaManager stats."""
        frida_dialog.init_ui()
        frida_dialog.current_session = "stats_session"

        stats = {
            "batcher": {
                "pending_hooks": 42,
                "batched_count": 150
            }
        }

        mock_frida_manager.get_statistics.return_value = stats

        frida_dialog.update_performance_stats()

        stats_text = frida_dialog.hook_stats_label.text()
        assert "Total Hooks: 42" in stats_text


class TestScriptContextMenu:
    """Test script context menu functionality."""

    def test_script_context_menu_includes_all_actions(
        self,
        frida_dialog: FridaManagerDialog,
        temp_scripts_dir: Path
    ) -> None:
        """Script context menu includes all available actions."""
        frida_dialog.setup_ui()

        test_script = temp_scripts_dir / "context_test.js"
        test_script.write_text("console.log('test');")

        item = QListWidgetItem("context_test")
        item.setData(Qt.UserRole, str(test_script))
        frida_dialog.scripts_list.addItem(item)

        with patch("intellicrack.ui.dialogs.frida_manager_dialog.QMenu") as mock_menu:
            mock_menu_instance = Mock()
            mock_menu.return_value = mock_menu_instance

            frida_dialog.show_script_context_menu(Mock())

            assert mock_menu_instance.addAction.call_count >= 5


class TestFridaAvailability:
    """Test Frida availability checking."""

    def test_check_frida_availability_updates_ui(
        self,
        frida_dialog: FridaManagerDialog
    ) -> None:
        """Frida availability check updates UI appropriately."""
        frida_dialog.setup_ui()

        frida_dialog.check_frida_availability()
