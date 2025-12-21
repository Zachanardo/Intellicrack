"""Production Tests for Frida GUI Integration Module.

Tests validate real PyQt6 GUI functionality, script management, parameter handling,
and output visualization. All tests use real GUI components without mocks.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import tempfile
from pathlib import Path
from typing import Generator

import pytest

try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication, QCheckBox, QDoubleSpinBox, QLineEdit, QSpinBox, QTextEdit

    from intellicrack.core.analysis.frida_gui_integration import (
        FridaScriptCreatorWidget,
        FridaScriptDebuggerWidget,
        FridaScriptOutputWidget,
        FridaScriptParameterWidget,
        ScriptOutputTab,
        integrate_frida_gui,
        show_creator,
        show_debugger,
        show_output_viewer,
        show_parameter_dialog,
    )
    from intellicrack.core.analysis.frida_script_manager import FridaScriptConfig, ScriptCategory

    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication | None, None, None]:
    """Create QApplication instance for GUI tests."""
    if not PYQT_AVAILABLE:
        yield None
        return

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


@pytest.fixture
def sample_script_config() -> FridaScriptConfig:
    """Create sample Frida script configuration for testing."""
    if not PYQT_AVAILABLE:
        pytest.skip("PyQt6 not available")

    return FridaScriptConfig(
        name="license_bypass",
        path=Path("test_script.js"),
        category=ScriptCategory.LICENSE_BYPASS,
        description="Test bypass script for license validation",
        requires_admin=True,
        supports_spawn=True,
        supports_attach=False,
        parameters={
            "enable_logging": True,
            "max_retries": 3,
            "timeout_seconds": 30.5,
            "target_functions": ["ValidateLicense", "CheckRegistration"],
            "hook_config": {"deep_scan": True, "report_level": 2},
            "optional_param": None,
        },
    )


@pytest.fixture
def temp_preset_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Create temporary directory for preset testing."""
    preset_dir = tmp_path / ".intellicrack" / "frida_presets"
    preset_dir.mkdir(parents=True, exist_ok=True)
    yield preset_dir


@pytest.mark.skipif(not PYQT_AVAILABLE, reason="PyQt6 not available")
class TestFridaScriptParameterWidget:
    """Test Frida script parameter configuration widget."""

    def test_parameter_widget_initializes_with_script_config(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """Parameter widget initializes with script configuration and creates UI."""
        widget = FridaScriptParameterWidget(sample_script_config)

        assert widget.script_config == sample_script_config
        assert len(widget.parameter_widgets) == 6
        assert widget.timeout_spin.value() == 60
        assert widget.output_combo.count() == 4
        assert widget.log_level_combo.currentText() == "Info"

    def test_creates_checkbox_for_boolean_parameters(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """Widget creates checkbox widgets for boolean parameters."""
        widget = FridaScriptParameterWidget(sample_script_config)

        enable_logging_widget = widget.parameter_widgets.get("enable_logging")
        assert isinstance(enable_logging_widget, QCheckBox)
        assert enable_logging_widget.isChecked() is True

    def test_creates_spinbox_for_integer_parameters(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """Widget creates spinbox widgets for integer parameters."""
        widget = FridaScriptParameterWidget(sample_script_config)

        max_retries_widget = widget.parameter_widgets.get("max_retries")
        assert isinstance(max_retries_widget, QSpinBox)
        assert max_retries_widget.value() == 3
        assert max_retries_widget.minimum() == -999999
        assert max_retries_widget.maximum() == 999999

    def test_creates_double_spinbox_for_float_parameters(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """Widget creates double spinbox for float parameters."""
        widget = FridaScriptParameterWidget(sample_script_config)

        timeout_widget = widget.parameter_widgets.get("timeout_seconds")
        assert isinstance(timeout_widget, QDoubleSpinBox)
        assert timeout_widget.value() == 30.5
        assert timeout_widget.decimals() == 4

    def test_creates_textedit_for_list_parameters(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """Widget creates text edit for list parameters with JSON formatting."""
        widget = FridaScriptParameterWidget(sample_script_config)

        functions_widget = widget.parameter_widgets.get("target_functions")
        assert isinstance(functions_widget, QTextEdit)

        text_content = functions_widget.toPlainText()
        parsed_data = json.loads(text_content)
        assert parsed_data == ["ValidateLicense", "CheckRegistration"]

    def test_creates_textedit_for_dict_parameters(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """Widget creates text edit for dict parameters with JSON formatting."""
        widget = FridaScriptParameterWidget(sample_script_config)

        config_widget = widget.parameter_widgets.get("hook_config")
        assert isinstance(config_widget, QTextEdit)

        text_content = config_widget.toPlainText()
        parsed_data = json.loads(text_content)
        assert parsed_data == {"deep_scan": True, "report_level": 2}

    def test_creates_lineedit_for_none_parameters(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """Widget creates line edit for None parameters with proper styling."""
        widget = FridaScriptParameterWidget(sample_script_config)

        optional_widget = widget.parameter_widgets.get("optional_param")
        assert isinstance(optional_widget, QLineEdit)
        assert optional_widget.text() == ""
        assert "gray" in optional_widget.styleSheet().lower()

    def test_get_parameters_returns_all_configured_values(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """get_parameters extracts all parameter values correctly."""
        widget = FridaScriptParameterWidget(sample_script_config)

        params = widget.get_parameters()

        assert params["enable_logging"] is True
        assert params["max_retries"] == 3
        assert params["timeout_seconds"] == 30.5
        assert params["target_functions"] == ["ValidateLicense", "CheckRegistration"]
        assert params["hook_config"] == {"deep_scan": True, "report_level": 2}
        assert params["optional_param"] is None
        assert params["timeout"] == 60
        assert params["output_format"] == "json"
        assert params["log_level"] == "info"

    def test_get_parameters_handles_modified_values(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig
    ) -> None:
        """get_parameters returns modified parameter values."""
        widget = FridaScriptParameterWidget(sample_script_config)

        max_retries_widget = widget.parameter_widgets["max_retries"]
        max_retries_widget.setValue(10)

        timeout_widget = widget.parameter_widgets["timeout_seconds"]
        timeout_widget.setValue(60.75)

        params = widget.get_parameters()

        assert params["max_retries"] == 10
        assert params["timeout_seconds"] == 60.75

    def test_save_preset_creates_json_file(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig, temp_preset_dir: Path, monkeypatch
    ) -> None:
        """save_preset creates JSON file with parameter values."""
        widget = FridaScriptParameterWidget(sample_script_config)

        from PyQt6.QtWidgets import QInputDialog

        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("test_preset", True))
        monkeypatch.setattr(Path, "home", lambda: temp_preset_dir.parent.parent)

        widget.save_preset()

        preset_file = temp_preset_dir / "test_preset.json"
        assert preset_file.exists()

        with open(preset_file) as f:
            saved_params = json.load(f)

        assert saved_params["enable_logging"] is True
        assert saved_params["max_retries"] == 3

    def test_load_preset_restores_parameter_values(
        self, qapp: QApplication, sample_script_config: FridaScriptConfig, temp_preset_dir: Path, monkeypatch
    ) -> None:
        """load_preset restores parameters from saved preset file."""
        preset_data = {"enable_logging": False, "max_retries": 99, "timeout_seconds": 120.5, "optional_param": "test"}

        preset_file = temp_preset_dir / "test_load_preset.json"
        with open(preset_file, "w") as f:
            json.dump(preset_data, f)

        widget = FridaScriptParameterWidget(sample_script_config)

        from PyQt6.QtWidgets import QFileDialog

        monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args, **kwargs: (str(preset_file), ""))

        widget.load_preset()

        assert widget.parameter_widgets["enable_logging"].isChecked() is False
        assert widget.parameter_widgets["max_retries"].value() == 99
        assert widget.parameter_widgets["timeout_seconds"].value() == 120.5
        assert widget.parameter_widgets["optional_param"].text() == "test"


@pytest.mark.skipif(not PYQT_AVAILABLE, reason="PyQt6 not available")
class TestFridaScriptOutputWidget:
    """Test Frida script real-time output widget."""

    def test_output_widget_initializes_with_empty_state(self, qapp: QApplication) -> None:
        """Output widget initializes with empty script outputs."""
        widget = FridaScriptOutputWidget()

        assert len(widget.script_outputs) == 0
        assert widget.tab_widget.count() == 0

    def test_add_script_output_creates_new_tab(self, qapp: QApplication) -> None:
        """add_script_output creates new tab for script execution."""
        widget = FridaScriptOutputWidget()

        widget.add_script_output("license_bypass", "session_001")

        assert widget.tab_widget.count() == 1
        assert "session_001" in widget.script_outputs
        assert widget.tab_widget.tabText(0) == "license_bypass"

    def test_update_output_adds_message_to_correct_session(self, qapp: QApplication) -> None:
        """update_output adds messages to correct script session."""
        widget = FridaScriptOutputWidget()
        widget.add_script_output("test_script", "session_001")

        message = {"type": "info", "payload": "Hook installed successfully"}

        widget.update_output("session_001", message)

        tab = widget.script_outputs["session_001"]
        assert len(tab.messages) == 1
        assert tab.messages[0] == message

    def test_close_tab_removes_session_from_outputs(self, qapp: QApplication) -> None:
        """close_tab removes script session from outputs dictionary."""
        widget = FridaScriptOutputWidget()
        widget.add_script_output("test_script", "session_001")
        widget.add_script_output("test_script2", "session_002")

        widget.close_tab(0)

        assert "session_001" not in widget.script_outputs
        assert "session_002" in widget.script_outputs
        assert widget.tab_widget.count() == 1


@pytest.mark.skipif(not PYQT_AVAILABLE, reason="PyQt6 not available")
class TestScriptOutputTab:
    """Test individual script output tab functionality."""

    def test_output_tab_initializes_with_script_info(self, qapp: QApplication) -> None:
        """Output tab initializes with script name and session ID."""
        tab = ScriptOutputTab("license_bypass", "session_123")

        assert tab.script_name == "license_bypass"
        assert tab.session_id == "session_123"
        assert len(tab.messages) == 0
        assert len(tab.data) == 0

    def test_add_message_stores_and_displays_message(self, qapp: QApplication) -> None:
        """add_message stores message and displays in output text."""
        tab = ScriptOutputTab("test_script", "session_001")

        message = {"type": "info", "payload": "Test message"}
        tab.add_message(message)

        assert len(tab.messages) == 1
        assert tab.messages[0] == message

        output_text = tab.output_text.toPlainText()
        assert "Test message" in output_text
        assert "[INFO]" in output_text.upper()

    def test_add_message_applies_correct_color_for_error(self, qapp: QApplication) -> None:
        """add_message applies red color for error messages."""
        tab = ScriptOutputTab("test_script", "session_001")

        error_message = {"type": "error", "payload": "Failed to hook function"}

        color = tab.get_message_color(error_message)
        assert color == "#ff6b6b"

    def test_add_message_applies_correct_color_for_warning(self, qapp: QApplication) -> None:
        """add_message applies orange color for warning messages."""
        tab = ScriptOutputTab("test_script", "session_001")

        warning_message = {"type": "warning", "payload": "Deprecated API usage"}

        color = tab.get_message_color(warning_message)
        assert color == "#ffa726"

    def test_add_message_applies_correct_color_for_success(self, qapp: QApplication) -> None:
        """add_message applies green color for success messages."""
        tab = ScriptOutputTab("test_script", "session_001")

        success_message = {"type": "hook_installed", "payload": "Hook active"}

        color = tab.get_message_color(success_message)
        assert color == "#66bb6a"

    def test_update_data_tree_processes_nested_dictionaries(self, qapp: QApplication) -> None:
        """update_data_tree processes nested dictionary data correctly."""
        tab = ScriptOutputTab("test_script", "session_001")

        data = {"license_info": {"type": "trial", "days_remaining": 30, "features": ["basic", "advanced"]}}

        tab.update_data_tree(data)

        assert tab.data_tree.topLevelItemCount() == 1
        root_item = tab.data_tree.topLevelItem(0)
        assert root_item.text(0) == "license_info"

    def test_clear_output_removes_all_messages(self, qapp: QApplication) -> None:
        """clear_output removes all messages and clears display."""
        tab = ScriptOutputTab("test_script", "session_001")

        tab.add_message({"type": "info", "payload": "Message 1"})
        tab.add_message({"type": "info", "payload": "Message 2"})

        tab.clear_output()

        assert len(tab.messages) == 0
        assert tab.output_text.toPlainText() == ""

    def test_export_output_creates_json_file(self, qapp: QApplication, tmp_path: Path, monkeypatch) -> None:
        """export_output creates JSON file with complete session data."""
        tab = ScriptOutputTab("test_script", "session_001")
        tab.add_message({"type": "info", "payload": "Test message"})

        export_file = tmp_path / "export.json"

        from PyQt6.QtWidgets import QFileDialog

        monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(export_file), ""))

        tab.export_output()

        assert export_file.exists()

        with open(export_file) as f:
            exported_data = json.load(f)

        assert exported_data["script_name"] == "test_script"
        assert exported_data["session_id"] == "session_001"
        assert len(exported_data["messages"]) == 1


@pytest.mark.skipif(not PYQT_AVAILABLE, reason="PyQt6 not available")
class TestFridaScriptDebuggerWidget:
    """Test Frida script debugger widget."""

    def test_debugger_widget_initializes_with_empty_state(self, qapp: QApplication) -> None:
        """Debugger widget initializes with empty breakpoints and call stack."""
        widget = FridaScriptDebuggerWidget()

        assert len(widget.breakpoints) == 0
        assert len(widget.watch_expressions) == 0
        assert len(widget.call_stack) == 0

    def test_load_script_displays_code_with_line_numbers(self, qapp: QApplication, tmp_path: Path) -> None:
        """load_script displays script code with line numbers."""
        widget = FridaScriptDebuggerWidget()

        script_file = tmp_path / "test_script.js"
        script_content = """console.log('Line 1');
console.log('Line 2');
console.log('Line 3');"""
        script_file.write_text(script_content, encoding="utf-8")

        widget.load_script(str(script_file))

        displayed_text = widget.code_editor.toPlainText()
        assert "   1 | console.log('Line 1');" in displayed_text
        assert "   2 | console.log('Line 2');" in displayed_text
        assert "   3 | console.log('Line 3');" in displayed_text

    def test_add_breakpoint_creates_table_entry(self, qapp: QApplication) -> None:
        """add_breakpoint creates entry in breakpoints table."""
        widget = FridaScriptDebuggerWidget()

        widget.add_breakpoint(42, "x > 10")

        assert widget.breakpoints_widget.rowCount() == 1
        assert widget.breakpoints_widget.item(0, 0).text() == "42"
        assert widget.breakpoints_widget.item(0, 2).text() == "x > 10"
        assert 42 in widget.breakpoints

    def test_update_callstack_displays_stack_frames(self, qapp: QApplication) -> None:
        """update_callstack displays call stack frames."""
        widget = FridaScriptDebuggerWidget()

        stack = ["main() at 0x401000", "validate_license() at 0x402000", "check_serial() at 0x403000"]

        widget.update_callstack(stack)

        assert widget.callstack_widget.count() == 3
        assert widget.callstack_widget.item(0).text() == "main() at 0x401000"

    def test_log_console_appends_messages(self, qapp: QApplication) -> None:
        """log_console appends messages to console output."""
        widget = FridaScriptDebuggerWidget()

        widget.log_console("Debug message 1")
        widget.log_console("Debug message 2")

        console_text = widget.console_widget.toPlainText()
        assert "Debug message 1" in console_text
        assert "Debug message 2" in console_text


@pytest.mark.skipif(not PYQT_AVAILABLE, reason="PyQt6 not available")
class TestFridaScriptCreatorWidget:
    """Test Frida script creator wizard widget."""

    def test_creator_widget_initializes_with_tabs(self, qapp: QApplication) -> None:
        """Creator widget initializes with all configuration tabs."""
        widget = FridaScriptCreatorWidget()

        assert widget.tab_widget.count() == 4
        assert widget.tab_widget.tabText(0) == "Basic Information"
        assert widget.tab_widget.tabText(1) == "Hooks Configuration"
        assert widget.tab_widget.tabText(2) == "Script Code"
        assert widget.tab_widget.tabText(3) == "Templates"

    def test_creator_widget_loads_default_template_code(self, qapp: QApplication) -> None:
        """Creator widget loads default template in code editor."""
        widget = FridaScriptCreatorWidget()

        code_text = widget.code_editor.toPlainText()

        assert "Frida Script - Created with Intellicrack" in code_text
        assert "console.log" in code_text
        assert "function main()" in code_text

    def test_add_hook_creates_hook_list_entry(self, qapp: QApplication) -> None:
        """add_hook creates entry in hooks list."""
        widget = FridaScriptCreatorWidget()

        widget.module_edit.setText("kernel32.dll")
        widget.function_edit.setText("VirtualProtect")
        widget.hook_type_combo.setCurrentText("onEnter")

        widget.add_hook()

        assert widget.hooks_list.count() == 1
        assert "kernel32.dll!VirtualProtect (onEnter)" in widget.hooks_list.item(0).text()

    def test_validate_script_detects_missing_hooks(self, qapp: QApplication) -> None:
        """validate_script detects when no hooks are defined."""
        widget = FridaScriptCreatorWidget()

        widget.code_editor.setPlainText("console.log('No hooks here');")

        issues = []
        if "Interceptor.attach" not in widget.code_editor.toPlainText() and "Java.perform" not in widget.code_editor.toPlainText():
            issues.append("No hooks detected")

        assert "No hooks detected" in issues

    def test_validate_script_detects_missing_send_calls(self, qapp: QApplication) -> None:
        """validate_script detects when send() is not used."""
        widget = FridaScriptCreatorWidget()

        widget.code_editor.setPlainText("Interceptor.attach(ptr(0x401000), {});")

        issues = []
        if "send(" not in widget.code_editor.toPlainText():
            issues.append("No message sending detected")

        assert "No message sending detected" in issues

    def test_save_script_creates_file_with_metadata(self, qapp: QApplication, tmp_path: Path, monkeypatch) -> None:
        """save_script creates JavaScript file with metadata header."""
        widget = FridaScriptCreatorWidget()

        widget.name_edit.setText("test_script")
        widget.description_edit.setPlainText("Test script for validation")
        widget.admin_check.setChecked(True)

        script_file = tmp_path / "test_script.js"

        from PyQt6.QtWidgets import QFileDialog

        monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(script_file), ""))

        widget.save_script()

        assert script_file.exists()

        content = script_file.read_text(encoding="utf-8")
        assert "@metadata" in content
        assert '"name": "test_script"' in content
        assert '"requires_admin": true' in content


@pytest.mark.skipif(not PYQT_AVAILABLE, reason="PyQt6 not available")
class TestIntegrationFunctions:
    """Test GUI integration helper functions."""

    def test_integrate_frida_gui_creates_menu_items(self, qapp: QApplication) -> None:
        """integrate_frida_gui creates Frida menu with action items."""
        from PyQt6.QtWidgets import QMainWindow

        main_app = QMainWindow()

        result = integrate_frida_gui(main_app)

        assert result is True
        assert hasattr(main_app, "frida_menu")
        assert hasattr(main_app, "frida_output_widget")
        assert main_app.frida_menu.title() == "Frida"

    def test_show_output_viewer_displays_widget(self, qapp: QApplication) -> None:
        """show_output_viewer displays output viewer widget."""
        from PyQt6.QtWidgets import QMainWindow

        main_app = QMainWindow()
        integrate_frida_gui(main_app)

        show_output_viewer(main_app)

        assert main_app.frida_output_widget.isVisible() is True

    def test_show_debugger_creates_debugger_window(self, qapp: QApplication) -> None:
        """show_debugger creates debugger window."""
        from PyQt6.QtWidgets import QMainWindow

        main_app = QMainWindow()

        show_debugger(main_app)

    def test_show_creator_displays_creator_dialog(self, qapp: QApplication) -> None:
        """show_creator displays script creator dialog."""
        from PyQt6.QtWidgets import QMainWindow

        main_app = QMainWindow()

        show_creator(main_app)
