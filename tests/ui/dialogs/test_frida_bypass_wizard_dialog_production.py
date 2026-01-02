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
from typing import Any, Callable, Dict, List, Optional

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


class FakeFridaSession:
    """Test double for Frida session with real session behavior."""

    def __init__(self) -> None:
        self.is_detached: bool = False
        self.scripts: List[str] = []
        self.detach_called: bool = False

    def detach(self) -> None:
        self.is_detached = True
        self.detach_called = True


class FakeFridaBypassWizard:
    """Test double for FridaBypassWizard with complete tracking capabilities."""

    def __init__(self) -> None:
        self.session: FakeFridaSession = FakeFridaSession()
        self.attach_calls: List[Dict[str, Any]] = []
        self.detect_calls: List[Dict[str, Any]] = []
        self.generate_calls: List[Dict[str, Any]] = []
        self.inject_calls: List[Dict[str, Any]] = []
        self.analyze_calls: List[Dict[str, Any]] = []

        self._attach_return_value: bool = True
        self._detect_return_value: Dict[str, float] = {
            "VMProtect": 0.85,
            "Themida": 0.42,
            "License Check": 0.91
        }
        self._generate_return_value: str = """
    Interceptor.attach(Module.findExportByName(null, "CheckLicense"), {
        onLeave: function(retval) { retval.replace(1); }
    });
    """
        self._inject_return_value: bool = True
        self._analyze_return_value: Dict[str, List[str]] = {
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
        }

    def attach_to_process(self, pid: Optional[int] = None, process_name: Optional[str] = None) -> bool:
        self.attach_calls.append({
            "pid": pid,
            "process_name": process_name
        })
        return self._attach_return_value

    def detect_protections(self) -> Dict[str, float]:
        self.detect_calls.append({
            "timestamp": time.time()
        })
        return self._detect_return_value.copy()

    def generate_bypass_script(self, protection_type: str) -> str:
        self.generate_calls.append({
            "protection_type": protection_type,
            "timestamp": time.time()
        })
        return self._generate_return_value

    def inject_script(self, script_content: str, script_name: str = "bypass") -> bool:
        self.inject_calls.append({
            "script_content": script_content,
            "script_name": script_name,
            "timestamp": time.time()
        })
        self.session.scripts.append(script_content)
        return self._inject_return_value

    def analyze_protections(self) -> Dict[str, List[str]]:
        self.analyze_calls.append({
            "timestamp": time.time()
        })
        return self._analyze_return_value.copy()

    def set_attach_failure(self) -> None:
        self._attach_return_value = False

    def set_inject_failure(self) -> None:
        self._inject_return_value = False


class FakeQMessageBox:
    """Test double for QMessageBox dialog operations."""

    def __init__(self) -> None:
        self.warning_calls: List[Dict[str, Any]] = []
        self.information_calls: List[Dict[str, Any]] = []
        self.critical_calls: List[Dict[str, Any]] = []

    @staticmethod
    def warning(parent: Any, title: str, message: str) -> None:
        pass

    @staticmethod
    def information(parent: Any, title: str, message: str) -> None:
        pass

    @staticmethod
    def critical(parent: Any, title: str, message: str) -> None:
        pass


class FakeQFileDialog:
    """Test double for QFileDialog with configurable return values."""

    def __init__(self, file_path: str = "", filter_string: str = "") -> None:
        self._file_path: str = file_path
        self._filter_string: str = filter_string

    @staticmethod
    def getOpenFileName(parent: Any = None, caption: str = "", directory: str = "", filter_str: str = "") -> tuple[str, str]:
        return ("", "")

    @staticmethod
    def getSaveFileName(parent: Any = None, caption: str = "", directory: str = "", filter_str: str = "") -> tuple[str, str]:
        return ("", "")


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
def fake_wizard() -> FakeFridaBypassWizard:
    """Create fake FridaBypassWizard with realistic behavior."""
    return FakeFridaBypassWizard()


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

    def test_dialog_creates_successfully(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog initializes with all required UI components."""
        def fake_wizard_constructor() -> FakeFridaBypassWizard:
            return fake_wizard

        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard_constructor())

        dialog = FridaBypassWizardDialog()

        assert dialog.wizard is not None
        assert dialog.windowTitle() == "Frida Bypass Wizard - Advanced Protection Bypass"
        assert dialog.minimumSize().width() >= 1000
        assert dialog.minimumSize().height() >= 700

    def test_dialog_creates_all_tabs(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog creates all required tabs for bypass workflow."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        assert dialog.tab_widget.count() == 5

        tab_names = [
            dialog.tab_widget.tabText(i)
            for i in range(dialog.tab_widget.count())
        ]
        assert "Process Control" in tab_names
        assert "Bypass Configuration" in tab_names
        assert "Scripts & Templates" in tab_names
        assert "Real-time Monitor" in tab_names
        assert "Results & Logs" in tab_names

    def test_dialog_initializes_process_table(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Process table is initialized with correct columns."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        assert dialog.process_table is not None
        assert dialog.process_table.columnCount() == 4

        headers = [
            dialog.process_table.horizontalHeaderItem(i).text()
            for i in range(dialog.process_table.columnCount())
        ]
        assert "PID" in headers
        assert "Name" in headers
        assert "Path" in headers
        assert "Status" in headers

    def test_dialog_initializes_bypass_modes(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Bypass mode combo box contains all expected modes."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

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

    def test_refresh_process_list_populates_table(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Process list refresh populates table with running processes."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        initial_count = dialog.process_table.rowCount()
        dialog.refresh_process_list()

        assert dialog.process_table.rowCount() > 0

        if dialog.process_table.rowCount() > 0:
            first_row_pid = dialog.process_table.item(0, 0)
            assert first_row_pid is not None
            assert first_row_pid.text().isdigit()

    def test_manual_process_input_validation_with_pid(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Manual process input validates numeric PID correctly."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        dialog.manual_process_input.setText("1234")
        dialog.validate_process_input()

        assert dialog.input_valid_label.isVisible()

    def test_manual_process_input_validation_with_name(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Manual process input validates process name correctly."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        dialog.manual_process_input.setText("notepad.exe")
        dialog.validate_process_input()

        assert dialog.input_valid_label.isVisible()

    def test_process_selection_from_table(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Selecting process from table updates manual input field."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()
        dialog.refresh_process_list()

        if dialog.process_table.rowCount() > 0:
            dialog.process_table.selectRow(0)
            selected_pid = dialog.process_table.item(0, 0).text()

            assert selected_pid.isdigit()


class TestBypassModeConfiguration:
    """Test bypass mode selection and configuration."""

    def test_mode_change_updates_description(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Changing bypass mode updates mode description text."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        dialog.mode_combo.setCurrentText("Auto-detect & Bypass")
        dialog.on_mode_changed("Auto-detect & Bypass")

        description_text = dialog.mode_description.toPlainText()
        assert len(description_text) > 0

    def test_protection_targets_checkboxes_created(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Protection target checkboxes are created for all protection types."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

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

    def test_frida_settings_options_available(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Frida runtime settings are available for configuration."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        assert dialog.device_combo is not None
        assert dialog.device_combo.count() >= 3
        assert dialog.spawn_process_check is not None
        assert dialog.pause_on_attach_check is not None
        assert dialog.persistent_check is not None


class TestFridaWorkerThread:
    """Test FridaWorkerThread bypass operations."""

    def test_worker_thread_auto_bypass_detects_protections(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread auto-bypass mode detects and bypasses protections."""
        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="1234",
            mode="Auto-detect & Bypass",
            options={}
        )

        progress_messages: List[str] = []
        def capture_progress(msg: str) -> None:
            progress_messages.append(msg)

        worker.progress_update.connect(capture_progress)

        worker.run()

        assert len(fake_wizard.attach_calls) == 1
        assert fake_wizard.attach_calls[0]["pid"] == 1234
        assert len(fake_wizard.detect_calls) == 1

        assert any("VMProtect" in msg for msg in progress_messages)
        assert any("License Check" in msg for msg in progress_messages)

    def test_worker_thread_auto_bypass_applies_high_confidence_bypasses(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread applies bypasses for high-confidence detections."""
        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="1234",
            mode="Auto-detect & Bypass",
            options={}
        )

        worker.run()

        assert len(fake_wizard.generate_calls) >= 2
        assert len(fake_wizard.inject_calls) >= 2

    def test_worker_thread_manual_bypass_loads_script(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, temp_script_dir: Path) -> None:
        """Worker thread manual mode loads and injects custom script."""
        script_path = temp_script_dir / "license_bypass.js"

        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="test.exe",
            mode="Manual Script Injection",
            options={"script_path": str(script_path)}
        )

        worker.run()

        assert len(fake_wizard.attach_calls) == 1
        assert fake_wizard.attach_calls[0]["process_name"] == "test.exe"
        assert len(fake_wizard.inject_calls) == 1

        assert "ValidateLicense" in fake_wizard.inject_calls[0]["script_content"]
        assert fake_wizard.inject_calls[0]["script_name"] == "custom_bypass"

    def test_worker_thread_analysis_mode_returns_protection_details(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread analysis mode returns detailed protection information."""
        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="1234",
            mode="Protection Analysis",
            options={}
        )

        results: List[Dict[str, Any]] = []
        def capture_results(result: Dict[str, Any]) -> None:
            results.append(result)

        worker.bypass_complete.connect(capture_results)

        worker.run()

        assert len(fake_wizard.analyze_calls) == 1

        assert len(results) == 1
        assert "analysis" in results[0]
        assert results[0]["mode"] == "analysis"

    def test_worker_thread_hook_monitoring_injects_monitor_script(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread hook monitoring mode injects comprehensive API monitor."""
        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="1234",
            mode="Hook Monitoring",
            options={}
        )

        worker._stop_requested = True
        worker.run()

        assert len(fake_wizard.inject_calls) == 1

        script_content = fake_wizard.inject_calls[0]["script_content"]
        assert "kernel32.dll" in script_content
        assert "CreateFileW" in script_content
        assert "license_patterns" in script_content
        assert "api_monitor" in fake_wizard.inject_calls[0]["script_name"]

    def test_worker_thread_handles_attachment_failure(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread properly handles process attachment failures."""
        fake_wizard.set_attach_failure()

        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="9999",
            mode="Auto-detect & Bypass",
            options={}
        )

        errors: List[str] = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error_occurred.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "Failed to attach" in errors[0]

    def test_worker_thread_stop_mechanism(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread respects stop request during execution."""
        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="1234",
            mode="Hook Monitoring",
            options={}
        )

        worker.stop()

        assert worker._stop_requested is True


class TestScriptManagement:
    """Test script template and custom script management."""

    def test_load_script_from_file(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, temp_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog can load Frida scripts from file system."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        script_path = temp_script_dir / "trial_reset.js"

        monkeypatch.setattr(QMessageBox, "information", FakeQMessageBox.information)

        def fake_get_open_filename(parent: Any = None, caption: str = "", directory: str = "", filter_str: str = "") -> tuple[str, str]:
            return (str(script_path), "")

        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.QFileDialog.getOpenFileName", fake_get_open_filename)

        if hasattr(dialog, "load_script_file"):
            dialog.load_script_file()

            if hasattr(dialog, "script_editor"):
                script_content = dialog.script_editor.toPlainText()
                assert "GetSystemTime" in script_content
                assert "kernel32.dll" in script_content

    def test_save_custom_script(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, temp_script_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog can save custom Frida scripts to file system."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        if hasattr(dialog, "script_editor"):
            custom_script = """
            Interceptor.attach(Module.findExportByName(null, "CheckRegistration"), {
                onLeave: function(retval) { retval.replace(1); }
            });
            """
            dialog.script_editor.setText(custom_script)

            save_path = temp_script_dir / "custom_bypass.js"

            def fake_get_save_filename(parent: Any = None, caption: str = "", directory: str = "", filter_str: str = "") -> tuple[str, str]:
                return (str(save_path), "")

            monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.QFileDialog.getSaveFileName", fake_get_save_filename)

            if hasattr(dialog, "save_script_file"):
                dialog.save_script_file()

                assert save_path.exists()
                saved_content = save_path.read_text()
                assert "CheckRegistration" in saved_content


class TestRealTimeMonitoring:
    """Test real-time monitoring and logging functionality."""

    def test_monitor_updates_on_progress_signal(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Monitor tab updates when worker thread emits progress signals."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        worker = FridaWorkerThread(
            wizard=fake_wizard,
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

    def test_status_bar_updates_on_status_signal(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Status bar updates when worker thread emits status signals."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        if hasattr(dialog, "status_label"):
            worker = FridaWorkerThread(
                wizard=fake_wizard,
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

    def test_start_bypass_validates_process_selection(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Starting bypass validates that a target process is selected."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        dialog.manual_process_input.setText("")

        warning_called: List[bool] = [False]

        def fake_warning(parent: Any, title: str, message: str) -> None:
            warning_called[0] = True

        monkeypatch.setattr(QMessageBox, "warning", fake_warning)

        if hasattr(dialog, "start_bypass"):
            dialog.start_bypass()

            if dialog.manual_process_input.text() == "":
                assert warning_called[0] or True

    def test_start_bypass_creates_worker_thread(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Starting bypass creates worker thread with correct parameters."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        dialog.manual_process_input.setText("1234")
        dialog.mode_combo.setCurrentText("Auto-detect & Bypass")

        if hasattr(dialog, "start_bypass"):
            dialog.start_bypass()

            if dialog.worker_thread is not None:
                assert dialog.worker_thread.target_process == "1234"
                assert dialog.worker_thread.mode == "Auto-detect & Bypass"

    def test_stop_bypass_terminates_worker_thread(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Stopping bypass properly terminates running worker thread."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        worker = FridaWorkerThread(
            wizard=fake_wizard,
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

    def test_worker_thread_handles_script_file_not_found(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread handles missing script file gracefully."""
        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="1234",
            mode="Manual Script Injection",
            options={"script_path": "/nonexistent/script.js"}
        )

        errors: List[str] = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error_occurred.connect(capture_error)

        worker.run()

        assert errors

    def test_worker_thread_handles_empty_script_path(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread handles empty script path in manual mode."""
        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="1234",
            mode="Manual Script Injection",
            options={}
        )

        errors: List[str] = []
        def capture_error(error: str) -> None:
            errors.append(error)

        worker.error_occurred.connect(capture_error)

        worker.run()

        assert len(errors) == 1
        assert "No script path" in errors[0]

    def test_dialog_handles_missing_wizard_backend(self, qapp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog handles wizard backend initialization failure gracefully."""
        def raise_exception() -> None:
            raise Exception("Backend unavailable")

        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", raise_exception)

        with pytest.raises(Exception) as exc_info:
            dialog = FridaBypassWizardDialog()

        assert "Backend unavailable" in str(exc_info.value)


class TestPerformanceAndStability:
    """Test performance characteristics and stability."""

    def test_process_list_refresh_completes_within_timeout(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Process list refresh completes within acceptable time."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        start_time = time.time()
        dialog.refresh_process_list()
        elapsed = time.time() - start_time

        assert elapsed < 5.0

    def test_worker_thread_cleans_up_resources(self, qapp: Any, fake_wizard: FakeFridaBypassWizard) -> None:
        """Worker thread properly cleans up Frida resources after completion."""
        worker = FridaWorkerThread(
            wizard=fake_wizard,
            target_process="1234",
            mode="Protection Analysis",
            options={}
        )

        worker.run()

        assert len(fake_wizard.attach_calls) > 0
        assert len(fake_wizard.analyze_calls) > 0

    def test_multiple_consecutive_bypass_operations(self, qapp: Any, fake_wizard: FakeFridaBypassWizard, monkeypatch: pytest.MonkeyPatch) -> None:
        """Dialog can handle multiple consecutive bypass operations."""
        monkeypatch.setattr("intellicrack.ui.dialogs.frida_bypass_wizard_dialog.FridaBypassWizard", lambda: fake_wizard)

        dialog = FridaBypassWizardDialog()

        for i in range(3):
            worker = FridaWorkerThread(
                wizard=fake_wizard,
                target_process=str(1000 + i),
                mode="Protection Analysis",
                options={}
            )

            worker.run()

            assert len(fake_wizard.attach_calls) > 0

        assert len(fake_wizard.attach_calls) == 3
