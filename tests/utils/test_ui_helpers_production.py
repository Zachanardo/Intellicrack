"""Production tests for UI helper functions - validates real helper utilities.

Tests verify UI helper functions including binary path validation, log message emission,
file dialogs, confirmation dialogs, and exploit payload generation for security research.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from pathlib import Path
from typing import Any

import pytest

from intellicrack.types.ui import StandardButton
from intellicrack.utils.ui.ui_helpers import (
    ask_yes_no_question,
    check_binary_path_and_warn,
    emit_log_message,
    generate_exploit_payload_common,
    generate_exploit_strategy_common,
    show_file_dialog,
)


class FakeSignal:
    """Test double for signal emission."""

    def __init__(self) -> None:
        self.emitted_messages: list[str] = []

    def emit(self, message: str) -> None:
        self.emitted_messages.append(message)


class FakeAppInstance:
    """Test double for application instance with binary path."""

    def __init__(self, binary_path: str | None = None) -> None:
        self.binary_path: str | None = binary_path
        self.update_output: FakeSignal = FakeSignal()


class FakeWidget:
    """Test double for widget protocol implementation."""

    def __init__(self) -> None:
        self._enabled: bool = True
        self._visible: bool = True

    def setEnabled(self, enabled: bool) -> None:
        self._enabled = enabled

    def isEnabled(self) -> bool:
        return self._enabled

    def setVisible(self, visible: bool) -> None:
        self._visible = visible

    def isVisible(self) -> bool:
        return self._visible

    def show(self) -> None:
        self._visible = True

    def hide(self) -> None:
        self._visible = False

    def close(self) -> bool:
        self._visible = False
        return True

    def setLayout(self, layout: object) -> None:
        pass


class FakeMessageBox:
    """Test double for message box dialogs."""

    last_warning_parent: FakeWidget | None = None
    last_warning_title: str = ""
    last_warning_text: str = ""
    last_question_parent: FakeWidget | None = None
    last_question_title: str = ""
    last_question_text: str = ""
    question_response: int = StandardButton.Yes

    @classmethod
    def reset(cls) -> None:
        cls.last_warning_parent = None
        cls.last_warning_title = ""
        cls.last_warning_text = ""
        cls.last_question_parent = None
        cls.last_question_title = ""
        cls.last_question_text = ""
        cls.question_response = StandardButton.Yes

    @staticmethod
    def warning(
        parent: Any,
        title: str,
        text: str,
        buttons: int = StandardButton.Ok,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        FakeMessageBox.last_warning_parent = parent
        FakeMessageBox.last_warning_title = title
        FakeMessageBox.last_warning_text = text
        return StandardButton.Ok

    @staticmethod
    def question(
        parent: Any,
        title: str,
        text: str,
        buttons: int = StandardButton.Yes | StandardButton.No,
        default_button: int = StandardButton.NoButton,
    ) -> int:
        FakeMessageBox.last_question_parent = parent
        FakeMessageBox.last_question_title = title
        FakeMessageBox.last_question_text = text
        return FakeMessageBox.question_response


class FakeFileDialog:
    """Test double for file dialogs."""

    save_file_response: tuple[str, str] = ("", "")

    @classmethod
    def reset(cls) -> None:
        cls.save_file_response = ("", "")

    @staticmethod
    def getSaveFileName(
        parent: Any,
        caption: str = "",
        directory: str = "",
        file_filter: str = "",
    ) -> tuple[str, str]:
        return FakeFileDialog.save_file_response


class FakeExploitationModule:
    """Test double for exploitation module."""

    generate_strategy_result: dict[str, Any] = {}
    should_raise_error: bool = False
    error_message: str = "Test error"

    @classmethod
    def reset(cls) -> None:
        cls.generate_strategy_result = {}
        cls.should_raise_error = False
        cls.error_message = "Test error"

    @staticmethod
    def generate_bypass_script(binary_path: str, vulnerability_type: str) -> dict[str, Any]:
        if FakeExploitationModule.should_raise_error:
            raise ValueError(FakeExploitationModule.error_message)
        return FakeExploitationModule.generate_strategy_result


@pytest.fixture(autouse=True)
def reset_fakes() -> None:
    """Reset all fake state between tests."""
    FakeMessageBox.reset()
    FakeFileDialog.reset()
    FakeExploitationModule.reset()


@pytest.fixture
def inject_fake_message_box(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject fake message box into ui_helpers module."""
    monkeypatch.setattr("intellicrack.utils.ui.ui_helpers.get_message_box", lambda: FakeMessageBox)


@pytest.fixture
def inject_fake_file_dialog(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject fake file dialog into ui_helpers module."""
    monkeypatch.setattr("intellicrack.utils.ui.ui_helpers.get_file_dialog", lambda: FakeFileDialog)


@pytest.fixture
def inject_fake_exploitation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject fake exploitation module into ui_helpers."""
    monkeypatch.setattr(
        "intellicrack.utils.ui.ui_helpers.generate_bypass_script",
        FakeExploitationModule.generate_bypass_script,
    )


class TestCheckBinaryPathAndWarn:
    """Test check_binary_path_and_warn function."""

    def test_returns_false_when_no_binary_path(self, inject_fake_message_box: None) -> None:
        """Test function returns False when binary path is missing."""
        app_instance = FakeAppInstance(binary_path=None)

        result = check_binary_path_and_warn(app_instance)

        assert result is False
        assert FakeMessageBox.last_warning_title == "No File Selected"
        assert "Please select a program first" in FakeMessageBox.last_warning_text

    def test_returns_false_when_empty_binary_path(self, inject_fake_message_box: None) -> None:
        """Test function returns False when binary path is empty string."""
        app_instance = FakeAppInstance(binary_path="")

        result = check_binary_path_and_warn(app_instance)

        assert result is False

    def test_returns_true_when_binary_path_exists(self) -> None:
        """Test function returns True when valid binary path present."""
        app_instance = FakeAppInstance(binary_path="/path/to/binary.exe")

        result = check_binary_path_and_warn(app_instance)

        assert result is True

    def test_shows_warning_dialog_on_missing_path(self, inject_fake_message_box: None) -> None:
        """Test warning dialog is shown when path is missing."""
        app_instance = FakeAppInstance(binary_path=None)

        check_binary_path_and_warn(app_instance)

        assert "No File Selected" in FakeMessageBox.last_warning_title
        assert "Please select a program first" in FakeMessageBox.last_warning_text


class TestEmitLogMessage:
    """Test emit_log_message function."""

    def test_emits_message_with_update_output_signal(self) -> None:
        """Test message is emitted through update_output signal."""
        app_instance = FakeAppInstance()

        emit_log_message(app_instance, "Test log message")

        assert len(app_instance.update_output.emitted_messages) == 1
        assert "Test log message" in app_instance.update_output.emitted_messages[0]

    def test_handles_missing_update_output(self) -> None:
        """Test graceful handling when update_output is missing."""
        app_instance = FakeWidget()

        emit_log_message(app_instance, "Message")

    def test_uses_log_message_utility_when_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test uses log_message utility for formatting."""
        app_instance = FakeAppInstance()

        def fake_log_message(msg: str) -> str:
            return f"[LOG] {msg}"

        monkeypatch.setattr("intellicrack.utils.ui.ui_helpers.log_message", fake_log_message)

        emit_log_message(app_instance, "Message")

        assert app_instance.update_output.emitted_messages[0] == "[LOG] Message"


class TestShowFileDialog:
    """Test show_file_dialog function."""

    def test_returns_selected_filename(self, inject_fake_file_dialog: None) -> None:
        """Test dialog returns selected filename."""
        parent = FakeWidget()
        FakeFileDialog.save_file_response = ("/path/to/file.html", "HTML Files (*.html)")

        result = show_file_dialog(parent, "Save File")

        assert result == "/path/to/file.html"

    def test_returns_empty_string_on_cancel(self, inject_fake_file_dialog: None) -> None:
        """Test dialog returns empty string when cancelled."""
        parent = FakeWidget()
        FakeFileDialog.save_file_response = ("", "")

        result = show_file_dialog(parent, "Save File")

        assert result == ""

    def test_uses_custom_file_filter(self, inject_fake_file_dialog: None) -> None:
        """Test dialog uses provided file filter."""
        parent = FakeWidget()
        FakeFileDialog.save_file_response = ("/file.txt", "")

        result = show_file_dialog(parent, "Title", "Text Files (*.txt)")

        assert result == "/file.txt"

    def test_handles_import_error_gracefully(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test graceful handling of missing PyQt6."""
        parent = FakeWidget()

        def raise_import_error() -> type:
            raise ImportError()

        monkeypatch.setattr("intellicrack.utils.ui.ui_helpers.get_file_dialog", raise_import_error)

        result = show_file_dialog(parent, "Title")

        assert result == ""


class TestAskYesNoQuestion:
    """Test ask_yes_no_question function."""

    def test_returns_true_for_yes_response(self, inject_fake_message_box: None) -> None:
        """Test function returns True when Yes is clicked."""
        parent = FakeWidget()
        FakeMessageBox.question_response = StandardButton.Yes

        result = ask_yes_no_question(parent, "Title", "Question?")

        assert result is True

    def test_returns_false_for_no_response(self, inject_fake_message_box: None) -> None:
        """Test function returns False when No is clicked."""
        parent = FakeWidget()
        FakeMessageBox.question_response = StandardButton.No

        result = ask_yes_no_question(parent, "Title", "Question?")

        assert result is False

    def test_handles_import_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test graceful handling when QMessageBox is unavailable."""
        parent = FakeWidget()

        def raise_import_error() -> type:
            raise ImportError()

        monkeypatch.setattr("intellicrack.utils.ui.ui_helpers.get_message_box", raise_import_error)

        result = ask_yes_no_question(parent, "Title", "Question?")

        assert result is False


class TestGenerateExploitPayloadCommon:
    """Test generate_exploit_payload_common for security research."""

    def test_generates_license_bypass_payload(self) -> None:
        """Test generating license bypass payload for security research."""
        result = generate_exploit_payload_common("License Bypass")

        assert result["method"] == "patch"
        assert "payload_bytes" in result
        assert result["patch_type"] == "license_bypass"
        assert "instructions" in result
        assert len(result["instructions"]) > 0

        payload_bytes = bytes.fromhex(result["payload_bytes"])
        assert len(payload_bytes) > 0

    def test_generates_function_hijack_payload(self) -> None:
        """Test generating function hijacking payload."""
        result = generate_exploit_payload_common("Function Hijack")

        assert result["method"] == "function_hijacking"
        assert "payload_bytes" in result
        assert result["patch_type"] == "function_hijack"

        assert "JMP" in result["description"] or "hijack" in result["description"].lower()

    def test_generates_nop_slide_payload(self) -> None:
        """Test generating NOP slide payload."""
        result = generate_exploit_payload_common("NOP Slide")

        assert result["method"] == "nop_slide"
        assert "payload_bytes" in result
        assert result["patch_type"] == "nop_bypass"

        payload_bytes = bytes.fromhex(result["payload_bytes"])
        assert all(b == 0x90 for b in payload_bytes)

    def test_handles_unknown_payload_type(self) -> None:
        """Test error handling for unknown payload types."""
        result = generate_exploit_payload_common("Unknown Type")

        assert "error" in result
        assert "Unknown payload type" in result["error"]

    def test_includes_target_information_when_exists(self, tmp_path: Path) -> None:
        """Test payload includes target file information when it exists."""
        target_file = tmp_path / "target.exe"
        target_file.write_bytes(b"\x00" * 100)

        result = generate_exploit_payload_common("License Bypass", str(target_file))

        assert result["target"] == str(target_file)
        assert result["target_exists"] is True

    def test_marks_nonexistent_target(self) -> None:
        """Test payload marks nonexistent targets correctly."""
        result = generate_exploit_payload_common("License Bypass", "/nonexistent/path.exe")

        assert result["target"] == "/nonexistent/path.exe"
        assert result["target_exists"] is False

    def test_payload_bytes_are_valid_hex(self) -> None:
        """Test all generated payloads have valid hex format."""
        payload_types = ["License Bypass", "Function Hijack", "NOP Slide"]

        for payload_type in payload_types:
            result = generate_exploit_payload_common(payload_type)

            if "payload_bytes" in result:
                try:
                    bytes.fromhex(result["payload_bytes"])
                except ValueError:
                    pytest.fail(f"Invalid hex in {payload_type} payload")


class TestGenerateExploitStrategyCommon:
    """Test generate_exploit_strategy_common function."""

    def test_calls_generate_exploit_strategy(self, tmp_path: Path, inject_fake_exploitation: None) -> None:
        """Test function calls exploitation module."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"\x00" * 100)

        FakeExploitationModule.generate_strategy_result = {"strategy": "test_strategy"}

        result = generate_exploit_strategy_common(str(binary_path), "buffer_overflow")

        assert result["strategy"] == "test_strategy"

    def test_handles_exploitation_errors(self, inject_fake_exploitation: None) -> None:
        """Test error handling for exploitation failures."""
        FakeExploitationModule.should_raise_error = True
        FakeExploitationModule.error_message = "Test error"

        result = generate_exploit_strategy_common("/test/binary", "buffer_overflow")

        assert "error" in result
        assert "Test error" in result["error"]

    def test_supports_different_vulnerability_types(self, tmp_path: Path, inject_fake_exploitation: None) -> None:
        """Test strategy generation for different vulnerability types."""
        binary_path = tmp_path / "vuln.exe"
        binary_path.write_bytes(b"\x00" * 100)

        FakeExploitationModule.generate_strategy_result = {"strategy": "custom"}

        result = generate_exploit_strategy_common(str(binary_path), "format_string")

        assert "strategy" in result


@pytest.mark.integration
class TestUIHelpersIntegration:
    """Integration tests for UI helper functions."""

    def test_binary_path_validation_workflow(self, inject_fake_message_box: None) -> None:
        """Test complete binary path validation workflow."""
        app_with_path = FakeAppInstance(binary_path="/valid/path.exe")
        app_without_path = FakeAppInstance(binary_path=None)

        assert check_binary_path_and_warn(app_with_path) is True
        assert check_binary_path_and_warn(app_without_path) is False

    def test_payload_generation_workflow(self, tmp_path: Path) -> None:
        """Test complete payload generation workflow for security research."""
        target_binary = tmp_path / "protected_app.exe"
        target_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        bypass_payload = generate_exploit_payload_common("License Bypass", str(target_binary))
        assert bypass_payload["target_exists"] is True
        assert "payload_bytes" in bypass_payload

        hijack_payload = generate_exploit_payload_common("Function Hijack", str(target_binary))
        assert hijack_payload["target_exists"] is True
        assert "payload_bytes" in hijack_payload

        assert bypass_payload["payload_bytes"] != hijack_payload["payload_bytes"]

    def test_file_dialog_with_real_interaction(self, inject_fake_file_dialog: None) -> None:
        """Test file dialog with simulated user interaction."""
        parent = FakeWidget()
        expected_path = "/output/report.html"
        FakeFileDialog.save_file_response = (expected_path, "HTML Files (*.html)")

        result = show_file_dialog(parent, "Export Report", "HTML Files (*.html);;All Files (*)")

        assert result == expected_path

    def test_log_message_emission_chain(self) -> None:
        """Test log message emission through application instance."""
        app = FakeAppInstance()

        messages = ["Analysis started", "Protection detected", "Analysis complete"]

        for msg in messages:
            emit_log_message(app, msg)

        assert len(app.update_output.emitted_messages) == 3

    def test_payload_generation_for_different_targets(self, tmp_path: Path) -> None:
        """Test payload generation adapts to different target files."""
        targets = {
            "notepad.exe": tmp_path / "notepad.exe",
            "calculator.exe": tmp_path / "calculator.exe",
            "protected_app.exe": tmp_path / "protected_app.exe",
        }

        for path in targets.values():
            path.write_bytes(b"MZ" + b"\x00" * 50)

        for path in targets.values():
            payload = generate_exploit_payload_common("License Bypass", str(path))

            assert payload["target"] == str(path)
            assert payload["target_exists"] is True
            assert "payload_bytes" in payload
