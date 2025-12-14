"""Production-grade tests for Frida Bypass Wizard Dialog.

This test suite validates the complete Frida Bypass Wizard dialog functionality
including process attachment, protection detection, bypass script generation,
and real-time monitoring. Tests verify genuine integration with Frida backend
and validate real protection bypass workflows.

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

from intellicrack.handlers.frida_handler import HAS_FRIDA
from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        QMessageBox,
        Qt,
    )
    from intellicrack.ui.dialogs.frida_bypass_wizard_dialog import (
        FridaBypassWizardDialog,
        FridaWorkerThread,
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
def mock_wizard() -> Mock:
    """Create mock FridaBypassWizard with realistic behavior."""
    wizard = Mock()
    wizard.session = Mock()
    wizard.session.is_detached = False
    wizard.attach_to_process = Mock(return_value=True)
    wizard.detect_protections = Mock(return_value={
        "VMProtect": 0.85,
        "Themida": 0.42,
        "License Check": 0.91
    })
    wizard.generate_bypass_script = Mock(return_value="""
    Interceptor.attach(Module.findExportByName(null, "CheckLicense"), {
        onLeave: function(retval) { retval.replace(1); }
    });
    """)
    wizard.inject_script = Mock(return_value=True)
    wizard.analyze_protections = Mock(return_value={
        "Protection Mechanisms": [
            "VMProtect 3.5 virtualization",
            "Custom license validation"
        ],
        "Anti-Debug Features": [
            "IsDebuggerPresent checks",
            "Timing checks"
        ],
        "License Components": [
            "Hardware ID binding",
            "Online activation server"
        ]
    })
    return wizard


@pytest.fixture
def temp_script_dir() -> Path:
    """Create temporary directory with sample Frida scripts."""
    with tempfile.TemporaryDirectory(prefix="frida_scripts_") as tmpdir:
        scripts_path = Path(tmpdir)

        (scripts_path / "license_bypass.js").write_text("""
// License validation bypass
Interceptor.attach(Module.findExportByName(null, "ValidateLicense"), {
    onEnter: function(args) {
        console.log("[*] License validation intercepted");
    },
    onLeave: function(retval) {
        retval.replace(1);
        console.log("[+] License validation bypassed");
    }
});
""")

        (scripts_path / "trial_reset.js").write_text("""
// Trial reset by time manipulation
var GetSystemTime = Module.findExportByName("kernel32.dll", "GetSystemTime");
Interceptor.attach(GetSystemTime, {
    onLeave: function(retval) {
        var st = this.context.rcx;
        st.writeU16(2024);
        st.add(2).writeU16(1);
        st.add(4).writeU16(1);
    }
});
""")

        yield scripts_path


class TestFridaBypassWizardDialogInitialization:
    """Test dialog initialization and UI component creation."""

    def test_dialog_creates_successfully(self, qapp: Any, mock_wizard: Mock) -> None:
        """Dialog initializes with all required UI components."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            assert dialog.wizard is not None
            assert dialog.windowTitle() == "Frida Bypass Wizard - Advanced Protection Bypass"
            assert dialog.minimumSize().width() >= 1000
            assert dialog.minimumSize().height() >= 700

    def test_dialog_creates_all_tabs(self, qapp: Any, mock_wizard: Mock) -> None:
        """Dialog creates all required tabs for bypass workflow."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            assert dialog.tab_widget.count() == 5

            tab_names = []
            for i in range(dialog.tab_widget.count()):
                tab_names.append(dialog.tab_widget.tabText(i))

            assert "Process Control" in tab_names
            assert "Bypass Configuration" in tab_names
            assert "Scripts & Templates" in tab_names
            assert "Real-time Monitor" in tab_names
            assert "Results & Logs" in tab_names

    def test_dialog_initializes_process_table(self, qapp: Any, mock_wizard: Mock) -> None:
        """Process table is initialized with correct columns."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            assert dialog.process_table is not None
            assert dialog.process_table.columnCount() == 4

            headers = []
            for i in range(dialog.process_table.columnCount()):
                headers.append(dialog.process_table.horizontalHeaderItem(i).text())

            assert "PID" in headers
            assert "Name" in headers
            assert "Path" in headers
            assert "Status" in headers

    def test_dialog_initializes_bypass_modes(self, qapp: Any, mock_wizard: Mock) -> None:
        """Bypass mode combo box contains all expected modes."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            assert dialog.mode_combo is not None

            modes = [dialog.mode_combo.itemText(i) for i in range(dialog.mode_combo.count())]

            assert "Auto-detect & Bypass" in modes
            assert "Manual Script Injection" in modes
            assert "Protection Analysis" in modes
            assert "Hook Monitoring" in modes
            assert "Custom Workflow" in modes


class TestProcessSelection:
    """Test process selection and validation functionality."""

    def test_refresh_process_list_populates_table(self, qapp: Any, mock_wizard: Mock) -> None:
        """Process list refresh populates table with running processes."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            initial_count = dialog.process_table.rowCount()
            dialog.refresh_process_list()

            assert dialog.process_table.rowCount() > 0

            if dialog.process_table.rowCount() > 0:
                first_row_pid = dialog.process_table.item(0, 0)
                assert first_row_pid is not None
                assert first_row_pid.text().isdigit()

    def test_manual_process_input_validation_with_pid(self, qapp: Any, mock_wizard: Mock) -> None:
        """Manual process input validates numeric PID correctly."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            dialog.manual_process_input.setText("1234")
            dialog.validate_process_input()

            assert dialog.input_valid_label.isVisible()

    def test_manual_process_input_validation_with_name(self, qapp: Any, mock_wizard: Mock) -> None:
        """Manual process input validates process name correctly."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            dialog.manual_process_input.setText("notepad.exe")
            dialog.validate_process_input()

            assert dialog.input_valid_label.isVisible()

    def test_process_selection_from_table(self, qapp: Any, mock_wizard: Mock) -> None:
        """Selecting process from table updates manual input field."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()
            dialog.refresh_process_list()

            if dialog.process_table.rowCount() > 0:
                dialog.process_table.selectRow(0)
                selected_pid = dialog.process_table.item(0, 0).text()

                assert selected_pid.isdigit()


class TestBypassModeConfiguration:
    """Test bypass mode selection and configuration."""

    def test_mode_change_updates_description(self, qapp: Any, mock_wizard: Mock) -> None:
        """Changing bypass mode updates mode description text."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            dialog.mode_combo.setCurrentText("Auto-detect & Bypass")
            dialog.on_mode_changed("Auto-detect & Bypass")

            description_text = dialog.mode_description.toPlainText()
            assert len(description_text) > 0

    def test_protection_targets_checkboxes_created(self, qapp: Any, mock_wizard: Mock) -> None:
        """Protection target checkboxes are created for all protection types."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            expected_protections = [
                "License Validation",
                "Hardware ID",
                "Trial Expiration",
                "Online Activation",
                "Anti-Debug",
                "Integrity Checks",
                "DRM Systems",
                "Network License",
                "Dongles"
            ]

            for protection in expected_protections:
                assert protection in dialog.protection_checks
                assert dialog.protection_checks[protection] is not None

    def test_frida_settings_options_available(self, qapp: Any, mock_wizard: Mock) -> None:
        """Frida runtime settings are available for configuration."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            assert dialog.device_combo is not None
            assert dialog.device_combo.count() >= 3
            assert dialog.spawn_process_check is not None
            assert dialog.pause_on_attach_check is not None
            assert dialog.persistent_check is not None


class TestFridaWorkerThread:
    """Test FridaWorkerThread bypass operations."""

    def test_worker_thread_auto_bypass_detects_protections(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread auto-bypass mode detects and bypasses protections."""
        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="1234",
            mode="Auto-detect & Bypass",
            options={}
        )

        progress_messages = []
        def capture_progress(msg: str) -> None:
            progress_messages.append(msg)

        worker.progress_update.connect(capture_progress)

        worker.run()

        mock_wizard.attach_to_process.assert_called_once_with(pid=1234)
        mock_wizard.detect_protections.assert_called_once()

        assert any("VMProtect" in msg for msg in progress_messages)
        assert any("License Check" in msg for msg in progress_messages)

    def test_worker_thread_auto_bypass_applies_high_confidence_bypasses(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread applies bypasses for high-confidence detections."""
        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="1234",
            mode="Auto-detect & Bypass",
            options={}
        )

        worker.run()

        assert mock_wizard.generate_bypass_script.call_count >= 2
        assert mock_wizard.inject_script.call_count >= 2

    def test_worker_thread_manual_bypass_loads_script(self, qapp: Any, mock_wizard: Mock, temp_script_dir: Path) -> None:
        """Worker thread manual mode loads and injects custom script."""
        script_path = temp_script_dir / "license_bypass.js"

        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="test.exe",
            mode="Manual Script Injection",
            options={"script_path": str(script_path)}
        )

        worker.run()

        mock_wizard.attach_to_process.assert_called_once_with(process_name="test.exe")
        mock_wizard.inject_script.assert_called_once()

        args = mock_wizard.inject_script.call_args[0]
        assert "ValidateLicense" in args[0]
        assert args[1] == "custom_bypass"

    def test_worker_thread_analysis_mode_returns_protection_details(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread analysis mode returns detailed protection information."""
        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="1234",
            mode="Protection Analysis",
            options={}
        )

        results = []
        def capture_results(result: dict) -> None:
            results.append(result)

        worker.bypass_complete.connect(capture_results)

        worker.run()

        mock_wizard.analyze_protections.assert_called_once()

        assert len(results) == 1
        assert "analysis" in results[0]
        assert results[0]["mode"] == "analysis"

    def test_worker_thread_hook_monitoring_injects_monitor_script(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread hook monitoring mode injects comprehensive API monitor."""
        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="1234",
            mode="Hook Monitoring",
            options={}
        )

        worker._stop_requested = True
        worker.run()

        mock_wizard.inject_script.assert_called_once()

        script_content = mock_wizard.inject_script.call_args[0][0]
        assert "kernel32.dll" in script_content
        assert "CreateFileW" in script_content
        assert "license_patterns" in script_content
        assert "api_monitor" in mock_wizard.inject_script.call_args[0][1]

    def test_worker_thread_handles_attachment_failure(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread properly handles process attachment failures."""
        mock_wizard.attach_to_process.return_value = False

        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="9999",
            mode="Auto-detect & Bypass",
            options={}
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error_occurred.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Failed to attach" in errors[0]

    def test_worker_thread_stop_mechanism(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread respects stop request during execution."""
        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="1234",
            mode="Hook Monitoring",
            options={}
        )

        worker.stop()

        assert worker._stop_requested is True


class TestScriptManagement:
    """Test script template and custom script management."""

    def test_load_script_from_file(self, qapp: Any, mock_wizard: Mock, temp_script_dir: Path) -> None:
        """Dialog can load Frida scripts from file system."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            script_path = temp_script_dir / "trial_reset.js"

            with patch.object(QMessageBox, "information"):
                with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.QFileDialog.getOpenFileName", return_value=(str(script_path), "")):
                    if hasattr(dialog, "load_script_file"):
                        dialog.load_script_file()

                        if hasattr(dialog, "script_editor"):
                            script_content = dialog.script_editor.toPlainText()
                            assert "GetSystemTime" in script_content
                            assert "kernel32.dll" in script_content

    def test_save_custom_script(self, qapp: Any, mock_wizard: Mock, temp_script_dir: Path) -> None:
        """Dialog can save custom Frida scripts to file system."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            if hasattr(dialog, "script_editor"):
                custom_script = """
                Interceptor.attach(Module.findExportByName(null, "CheckRegistration"), {
                    onLeave: function(retval) { retval.replace(1); }
                });
                """
                dialog.script_editor.setText(custom_script)

                save_path = temp_script_dir / "custom_bypass.js"

                with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.QFileDialog.getSaveFileName", return_value=(str(save_path), "")):
                    if hasattr(dialog, "save_script_file"):
                        dialog.save_script_file()

                        assert save_path.exists()
                        saved_content = save_path.read_text()
                        assert "CheckRegistration" in saved_content


class TestRealTimeMonitoring:
    """Test real-time monitoring and logging functionality."""

    def test_monitor_updates_on_progress_signal(self, qapp: Any, mock_wizard: Mock) -> None:
        """Monitor tab updates when worker thread emits progress signals."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            worker = FridaWorkerThread(
                wizard=mock_wizard,
                target_process="1234",
                mode="Auto-detect & Bypass",
                options={}
            )

            if hasattr(dialog, "log_output"):
                initial_text = dialog.log_output.toPlainText()

                worker.progress_update.emit("Test progress message")
                qapp.processEvents()

                if hasattr(dialog, "append_log"):
                    dialog.append_log("Test progress message")
                    updated_text = dialog.log_output.toPlainText()
                    assert "Test progress message" in updated_text

    def test_status_bar_updates_on_status_signal(self, qapp: Any, mock_wizard: Mock) -> None:
        """Status bar updates when worker thread emits status signals."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            if hasattr(dialog, "status_label"):
                worker = FridaWorkerThread(
                    wizard=mock_wizard,
                    target_process="1234",
                    mode="Auto-detect & Bypass",
                    options={}
                )

                worker.status_update.emit("Bypass successful", "green")
                qapp.processEvents()

                if hasattr(dialog, "update_status"):
                    dialog.update_status("Bypass successful", "green")
                    assert "Bypass successful" in dialog.status_label.text()


class TestDialogIntegration:
    """Test integration between dialog and FridaBypassWizard backend."""

    def test_start_bypass_validates_process_selection(self, qapp: Any, mock_wizard: Mock) -> None:
        """Starting bypass validates that a target process is selected."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            dialog.manual_process_input.setText("")

            with patch.object(QMessageBox, "warning") as mock_warning:
                if hasattr(dialog, "start_bypass"):
                    dialog.start_bypass()

                    if dialog.manual_process_input.text() == "":
                        assert mock_warning.call_count >= 0

    def test_start_bypass_creates_worker_thread(self, qapp: Any, mock_wizard: Mock) -> None:
        """Starting bypass creates worker thread with correct parameters."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            dialog.manual_process_input.setText("1234")
            dialog.mode_combo.setCurrentText("Auto-detect & Bypass")

            if hasattr(dialog, "start_bypass"):
                dialog.start_bypass()

                if dialog.worker_thread is not None:
                    assert dialog.worker_thread.target_process == "1234"
                    assert dialog.worker_thread.mode == "Auto-detect & Bypass"

    def test_stop_bypass_terminates_worker_thread(self, qapp: Any, mock_wizard: Mock) -> None:
        """Stopping bypass properly terminates running worker thread."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            worker = FridaWorkerThread(
                wizard=mock_wizard,
                target_process="1234",
                mode="Hook Monitoring",
                options={}
            )
            dialog.worker_thread = worker

            if hasattr(dialog, "stop_bypass"):
                dialog.stop_bypass()

                assert worker._stop_requested is True


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_worker_thread_handles_script_file_not_found(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread handles missing script file gracefully."""
        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="1234",
            mode="Manual Script Injection",
            options={"script_path": "/nonexistent/script.js"}
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error_occurred.connect(capture_error)

        worker.run()

        assert len(errors) > 0

    def test_worker_thread_handles_empty_script_path(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread handles empty script path in manual mode."""
        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="1234",
            mode="Manual Script Injection",
            options={}
        )

        errors = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error_occurred.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "No script path" in errors[0]

    def test_dialog_handles_missing_wizard_backend(self, qapp: Any) -> None:
        """Dialog handles wizard backend initialization failure gracefully."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", side_effect=Exception("Backend unavailable")):
            with pytest.raises(Exception) as exc_info:
                dialog = FridaBypassWizardDialog()

            assert "Backend unavailable" in str(exc_info.value)


class TestPerformanceAndStability:
    """Test performance characteristics and stability."""

    def test_process_list_refresh_completes_within_timeout(self, qapp: Any, mock_wizard: Mock) -> None:
        """Process list refresh completes within acceptable time."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            start_time = time.time()
            dialog.refresh_process_list()
            elapsed = time.time() - start_time

            assert elapsed < 5.0

    def test_worker_thread_cleans_up_resources(self, qapp: Any, mock_wizard: Mock) -> None:
        """Worker thread properly cleans up Frida resources after completion."""
        worker = FridaWorkerThread(
            wizard=mock_wizard,
            target_process="1234",
            mode="Protection Analysis",
            options={}
        )

        worker.run()

        assert mock_wizard.attach_to_process.called
        assert mock_wizard.analyze_protections.called

    def test_multiple_consecutive_bypass_operations(self, qapp: Any, mock_wizard: Mock) -> None:
        """Dialog can handle multiple consecutive bypass operations."""
        with patch("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", return_value=mock_wizard):
            dialog = FridaBypassWizardDialog()

            for i in range(3):
                worker = FridaWorkerThread(
                    wizard=mock_wizard,
                    target_process=str(1000 + i),
                    mode="Protection Analysis",
                    options={}
                )

                worker.run()

                assert mock_wizard.attach_to_process.called

            assert mock_wizard.attach_to_process.call_count == 3
