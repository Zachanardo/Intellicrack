"""Production tests for UI helper functions - validates real helper utilities.

Tests verify UI helper functions including binary path validation, log message emission,
file dialogs, confirmation dialogs, and exploit payload generation for security research.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.utils.ui.ui_helpers import (
    ask_yes_no_question,
    check_binary_path_and_warn,
    emit_log_message,
    generate_exploit_payload_common,
    generate_exploit_strategy_common,
    show_file_dialog,
)


class TestCheckBinaryPathAndWarn:
    """Test check_binary_path_and_warn function."""

    def test_returns_false_when_no_binary_path(self) -> None:
        """Test function returns False when binary path is missing."""
        app_instance = MagicMock()
        app_instance.binary_path = None

        with patch("intellicrack.utils.ui.ui_helpers.QMessageBox") as mock_msgbox:
            result = check_binary_path_and_warn(app_instance)

            assert result is False
            mock_msgbox.warning.assert_called_once()

    def test_returns_false_when_empty_binary_path(self) -> None:
        """Test function returns False when binary path is empty string."""
        app_instance = MagicMock()
        app_instance.binary_path = ""

        with patch("intellicrack.utils.ui.ui_helpers.QMessageBox") as mock_msgbox:
            result = check_binary_path_and_warn(app_instance)

            assert result is False

    def test_returns_true_when_binary_path_exists(self) -> None:
        """Test function returns True when valid binary path present."""
        app_instance = MagicMock()
        app_instance.binary_path = "/path/to/binary.exe"

        result = check_binary_path_and_warn(app_instance)

        assert result is True

    def test_shows_warning_dialog_on_missing_path(self) -> None:
        """Test warning dialog is shown when path is missing."""
        app_instance = MagicMock()
        app_instance.binary_path = None

        with patch("intellicrack.utils.ui.ui_helpers.QMessageBox") as mock_msgbox:
            check_binary_path_and_warn(app_instance)

            args = mock_msgbox.warning.call_args[0]
            assert "No File Selected" in args[1]
            assert "Please select a program first" in args[2]


class TestEmitLogMessage:
    """Test emit_log_message function."""

    def test_emits_message_with_update_output_signal(self) -> None:
        """Test message is emitted through update_output signal."""
        app_instance = MagicMock()
        app_instance.update_output = MagicMock()
        app_instance.update_output.emit = MagicMock()

        emit_log_message(app_instance, "Test log message")

        app_instance.update_output.emit.assert_called_once()
        call_args = app_instance.update_output.emit.call_args[0]
        assert "Test log message" in str(call_args[0])

    def test_handles_missing_update_output(self) -> None:
        """Test graceful handling when update_output is missing."""
        app_instance = MagicMock(spec=[])

        emit_log_message(app_instance, "Message")

    def test_uses_log_message_utility_when_available(self) -> None:
        """Test uses log_message utility for formatting."""
        app_instance = MagicMock()
        app_instance.update_output = MagicMock()
        app_instance.update_output.emit = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.log_message", return_value="[LOG] Message"):
            emit_log_message(app_instance, "Message")

            app_instance.update_output.emit.assert_called_with("[LOG] Message")


class TestShowFileDialog:
    """Test show_file_dialog function."""

    def test_returns_selected_filename(self) -> None:
        """Test dialog returns selected filename."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.QFileDialog") as mock_dialog:
            mock_dialog.getSaveFileName.return_value = ("/path/to/file.html", "HTML Files (*.html)")

            result = show_file_dialog(parent, "Save File")

            assert result == "/path/to/file.html"

    def test_returns_empty_string_on_cancel(self) -> None:
        """Test dialog returns empty string when cancelled."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.QFileDialog") as mock_dialog:
            mock_dialog.getSaveFileName.return_value = ("", "")

            result = show_file_dialog(parent, "Save File")

            assert result == ""

    def test_uses_custom_file_filter(self) -> None:
        """Test dialog uses provided file filter."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.QFileDialog") as mock_dialog:
            mock_dialog.getSaveFileName.return_value = ("/file.txt", "")

            show_file_dialog(parent, "Title", "Text Files (*.txt)")

            call_args = mock_dialog.getSaveFileName.call_args[0]
            assert "Text Files (*.txt)" in call_args

    def test_handles_import_error_gracefully(self) -> None:
        """Test graceful handling of missing PyQt6."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.QFileDialog", side_effect=ImportError()):
            result = show_file_dialog(parent, "Title")

            assert result == ""


class TestAskYesNoQuestion:
    """Test ask_yes_no_question function."""

    def test_returns_true_for_yes_response(self) -> None:
        """Test function returns True when Yes is clicked."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.QMessageBox") as mock_msgbox:
            mock_msgbox.question.return_value = mock_msgbox.Yes
            mock_msgbox.Yes = 0x4000

            result = ask_yes_no_question(parent, "Title", "Question?")

            assert result is True

    def test_returns_false_for_no_response(self) -> None:
        """Test function returns False when No is clicked."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.QMessageBox") as mock_msgbox:
            mock_msgbox.question.return_value = mock_msgbox.No
            mock_msgbox.Yes = 0x4000
            mock_msgbox.No = 0x10000

            result = ask_yes_no_question(parent, "Title", "Question?")

            assert result is False

    def test_handles_import_error(self) -> None:
        """Test graceful handling when QMessageBox is unavailable."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.QMessageBox", side_effect=ImportError()):
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

    def test_calls_generate_exploit_strategy(self, tmp_path: Path) -> None:
        """Test function calls exploitation module."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"\x00" * 100)

        with patch("intellicrack.utils.ui.ui_helpers.generate_exploit_strategy") as mock_gen:
            mock_gen.return_value = {"strategy": "test_strategy"}

            result = generate_exploit_strategy_common(str(binary_path), "buffer_overflow")

            mock_gen.assert_called_once_with(str(binary_path), "buffer_overflow")
            assert result["strategy"] == "test_strategy"

    def test_handles_exploitation_errors(self) -> None:
        """Test error handling for exploitation failures."""
        with patch("intellicrack.utils.ui.ui_helpers.generate_exploit_strategy", side_effect=ValueError("Test error")):
            result = generate_exploit_strategy_common("/test/binary", "buffer_overflow")

            assert "error" in result
            assert "Test error" in result["error"]

    def test_supports_different_vulnerability_types(self, tmp_path: Path) -> None:
        """Test strategy generation for different vulnerability types."""
        binary_path = tmp_path / "vuln.exe"
        binary_path.write_bytes(b"\x00" * 100)

        with patch("intellicrack.utils.ui.ui_helpers.generate_exploit_strategy") as mock_gen:
            mock_gen.return_value = {"strategy": "custom"}

            result = generate_exploit_strategy_common(str(binary_path), "format_string")

            assert "strategy" in result


@pytest.mark.integration
class TestUIHelpersIntegration:
    """Integration tests for UI helper functions."""

    def test_binary_path_validation_workflow(self) -> None:
        """Test complete binary path validation workflow."""
        app_with_path = MagicMock()
        app_with_path.binary_path = "/valid/path.exe"

        app_without_path = MagicMock()
        app_without_path.binary_path = None

        assert check_binary_path_and_warn(app_with_path) is True

        with patch("intellicrack.utils.ui.ui_helpers.QMessageBox"):
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

    def test_file_dialog_with_real_interaction(self) -> None:
        """Test file dialog with simulated user interaction."""
        parent = MagicMock()

        with patch("intellicrack.utils.ui.ui_helpers.QFileDialog") as mock_dialog:
            expected_path = "/output/report.html"
            mock_dialog.getSaveFileName.return_value = (expected_path, "HTML Files (*.html)")

            result = show_file_dialog(parent, "Export Report", "HTML Files (*.html);;All Files (*)")

            assert result == expected_path
            assert mock_dialog.getSaveFileName.called

    def test_log_message_emission_chain(self) -> None:
        """Test log message emission through application instance."""
        app = MagicMock()
        app.update_output = MagicMock()
        app.update_output.emit = MagicMock()

        messages = ["Analysis started", "Protection detected", "Analysis complete"]

        for msg in messages:
            emit_log_message(app, msg)

        assert app.update_output.emit.call_count == 3

    def test_payload_generation_for_different_targets(self, tmp_path: Path) -> None:
        """Test payload generation adapts to different target files."""
        targets = {
            "notepad.exe": tmp_path / "notepad.exe",
            "calculator.exe": tmp_path / "calculator.exe",
            "protected_app.exe": tmp_path / "protected_app.exe",
        }

        for name, path in targets.items():
            path.write_bytes(b"MZ" + b"\x00" * 50)

        for name, path in targets.items():
            payload = generate_exploit_payload_common("License Bypass", str(path))

            assert payload["target"] == str(path)
            assert payload["target_exists"] is True
            assert "payload_bytes" in payload
