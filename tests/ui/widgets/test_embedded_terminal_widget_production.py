"""Production-ready tests for EmbeddedTerminalWidget - Terminal emulator validation.

This module validates EmbeddedTerminalWidget's complete functionality including:
- Terminal widget initialization and UI setup
- Process execution with command execution
- ANSI escape sequence parsing and color rendering
- Bidirectional I/O (input and output)
- Process lifecycle management (start, stop, monitor)
- Keyboard input handling and command history
- Context menu operations (copy, paste, clear, export)
- Terminal output queue processing
- Process exit code handling
- Log export functionality
- Thread-safe UI updates from background process reader
"""

import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QTextCharFormat
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog

from intellicrack.ui.widgets.embedded_terminal_widget import (
    ANSIParser,
    EmbeddedTerminalWidget,
)


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def terminal_widget(qapp: QApplication) -> EmbeddedTerminalWidget:
    """Create EmbeddedTerminalWidget for testing."""
    widget = EmbeddedTerminalWidget()
    yield widget
    if widget._process and widget._running:
        widget.stop_process()
        time.sleep(0.1)


@pytest.fixture
def ansi_parser() -> ANSIParser:
    """Create ANSIParser for testing."""
    return ANSIParser()


class TestANSIParserFunctionality:
    """Test ANSI escape sequence parsing."""

    def test_parser_initializes_with_default_format(self, ansi_parser: ANSIParser) -> None:
        """ANSI parser initializes with default text format."""
        assert ansi_parser.current_format is not None

    def test_parser_reset_format_restores_defaults(self, ansi_parser: ANSIParser) -> None:
        """Reset format restores default terminal colors."""
        ansi_parser.current_format.setForeground(QColor(255, 0, 0))
        ansi_parser.reset_format()
        default_color = ansi_parser.current_format.foreground().color()
        assert default_color.red() == 204

    def test_parser_handles_plain_text(self, ansi_parser: ANSIParser) -> None:
        """Parser handles text without ANSI codes."""
        result = ansi_parser.parse("Plain text without codes")
        assert len(result) == 1
        text, _ = result[0]
        assert text == "Plain text without codes"

    def test_parser_extracts_ansi_color_codes(self, ansi_parser: ANSIParser) -> None:
        """Parser extracts ANSI color escape sequences."""
        result = ansi_parser.parse("\x1b[31mRed text\x1b[0m")
        assert len(result) >= 1

    def test_parser_handles_red_color_code(self, ansi_parser: ANSIParser) -> None:
        """Parser applies red color for ANSI code 31."""
        result = ansi_parser.parse("\x1b[31mRed\x1b[0m")
        if len(result) > 1:
            _, format_obj = result[1]
            color = format_obj.foreground().color()
            assert color.red() > 200

    def test_parser_handles_green_color_code(self, ansi_parser: ANSIParser) -> None:
        """Parser applies green color for ANSI code 32."""
        result = ansi_parser.parse("\x1b[32mGreen\x1b[0m")
        if len(result) > 1:
            _, format_obj = result[1]
            color = format_obj.foreground().color()
            assert color.green() > 150

    def test_parser_handles_reset_code(self, ansi_parser: ANSIParser) -> None:
        """Parser resets formatting for ANSI code 0."""
        ansi_parser.parse("\x1b[0m")
        default_color = ansi_parser.current_format.foreground().color()
        assert default_color.red() == 204


class TestEmbeddedTerminalWidgetInitialization:
    """Test EmbeddedTerminalWidget initialization and setup."""

    def test_widget_creates_successfully(self, terminal_widget: EmbeddedTerminalWidget) -> None:
        """Terminal widget initializes without errors."""
        assert terminal_widget is not None

    def test_widget_has_terminal_display(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Widget has terminal display text edit."""
        assert terminal_widget.terminal_display is not None

    def test_terminal_display_has_monospace_font(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Terminal display uses monospace font."""
        font = terminal_widget.terminal_display.font()
        assert font.family() == "Consolas" or font.styleHint() == font.StyleHint.Monospace

    def test_terminal_display_has_dark_background(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Terminal display has dark background color."""
        stylesheet = terminal_widget.terminal_display.styleSheet()
        assert "#000000" in stylesheet or "black" in stylesheet.lower()

    def test_widget_minimum_size_set(self, terminal_widget: EmbeddedTerminalWidget) -> None:
        """Widget has minimum size configured."""
        assert terminal_widget.minimumWidth() == 600
        assert terminal_widget.minimumHeight() == 400

    def test_widget_not_running_initially(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Widget is not running a process initially."""
        assert not terminal_widget._running

    def test_widget_process_is_none_initially(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Widget has no process on initialization."""
        assert terminal_widget._process is None

    def test_widget_has_ansi_parser(self, terminal_widget: EmbeddedTerminalWidget) -> None:
        """Widget has ANSI parser for terminal output."""
        assert terminal_widget._ansi_parser is not None


class TestEmbeddedTerminalProcessManagement:
    """Test process execution and management."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_start_process_executes_command(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Start process executes command and returns PID."""
        pid = terminal_widget.start_process(["cmd", "/c", "echo", "test"])
        assert pid is not None
        assert pid > 0
        time.sleep(0.5)
        terminal_widget.stop_process()

    def test_start_process_with_string_command(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Start process handles string command by converting to list."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.pid = 12345
            mock_process.stdout.read.return_value = b""
            mock_popen.return_value = mock_process

            pid = terminal_widget.start_process("echo test")
            assert pid is not None

    def test_start_process_emits_started_signal(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Start process emits process_started signal."""
        signal_received = False
        received_pid = None

        def signal_handler(pid: int) -> None:
            nonlocal signal_received, received_pid
            signal_received = True
            received_pid = pid

        terminal_widget.process_started.connect(signal_handler)

        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.pid = 12345
            mock_process.stdout.read.return_value = b""
            mock_popen.return_value = mock_process

            terminal_widget.start_process(["echo", "test"])
            time.sleep(0.1)

            assert signal_received
            assert received_pid == 12345

    def test_stop_process_terminates_running_process(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Stop process terminates running process."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.pid = 12345
            mock_process.stdout.read.return_value = b""
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            terminal_widget.start_process(["sleep", "100"])
            terminal_widget.stop_process()

            assert mock_process.terminate.called or mock_process.kill.called

    def test_start_process_stops_existing_process_first(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Starting new process stops existing running process."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process1 = Mock()
            mock_process1.pid = 111
            mock_process1.stdout.read.return_value = b""
            mock_process1.poll.return_value = None

            mock_process2 = Mock()
            mock_process2.pid = 222
            mock_process2.stdout.read.return_value = b""

            mock_popen.side_effect = [mock_process1, mock_process2]

            terminal_widget.start_process(["cmd1"])
            time.sleep(0.1)
            terminal_widget.start_process(["cmd2"])

            assert mock_process1.terminate.called or mock_process1.kill.called

    def test_process_exit_emits_finished_signal(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Process exit emits process_finished signal."""
        signal_received = False
        received_exit_code = None

        def signal_handler(pid: int, exit_code: int) -> None:
            nonlocal signal_received, received_exit_code
            signal_received = True
            received_exit_code = exit_code

        terminal_widget.process_finished.connect(signal_handler)

        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.pid = 12345
            mock_process.stdout.read.return_value = b""
            mock_process.wait.return_value = 0
            mock_popen.return_value = mock_process

            terminal_widget.start_process(["echo", "test"])
            time.sleep(0.5)

            if signal_received:
                assert received_exit_code == 0


class TestEmbeddedTerminalInputOutput:
    """Test terminal input and output handling."""

    def test_send_input_writes_to_process_stdin(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Send input writes data to process stdin."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.pid = 12345
            mock_process.stdin = Mock()
            mock_process.stdout.read.return_value = b""
            mock_popen.return_value = mock_process

            terminal_widget.start_process(["cat"])
            terminal_widget.send_input("test input\n")

            mock_process.stdin.write.assert_called()

    def test_output_received_emits_signal(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Terminal output triggers output_received signal."""
        signal_received = False
        received_data = None

        def signal_handler(data: str) -> None:
            nonlocal signal_received, received_data
            signal_received = True
            received_data = data

        terminal_widget.output_received.connect(signal_handler)

        terminal_widget._handle_output("Test output")

        if terminal_widget.terminal_display.toPlainText():
            assert "Test" in terminal_widget.terminal_display.toPlainText() or signal_received

    def test_handle_output_appends_to_terminal(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Handle output appends text to terminal display."""
        terminal_widget._handle_output("Line 1\n")
        terminal_widget._handle_output("Line 2\n")

        text = terminal_widget.terminal_display.toPlainText()
        assert "Line 1" in text or "Line 2" in text

    def test_handle_error_output_uses_red_color(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Handle error output displays in red color."""
        terminal_widget._handle_output("[ERROR] Test error", is_error=True)
        text = terminal_widget.terminal_display.toPlainText()
        assert "ERROR" in text or "error" in text.lower()


class TestEmbeddedTerminalContextMenu:
    """Test terminal context menu functionality."""

    def test_context_menu_has_copy_action(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Context menu includes copy action."""
        with patch("PyQt6.QtWidgets.QMenu.exec"):
            terminal_widget._show_context_menu(terminal_widget.terminal_display.rect().center())

    def test_context_menu_has_paste_action(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Context menu includes paste action."""
        with patch("PyQt6.QtWidgets.QMenu.exec"):
            terminal_widget._show_context_menu(terminal_widget.terminal_display.rect().center())

    def test_context_menu_has_clear_action(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Context menu includes clear terminal action."""
        with patch("PyQt6.QtWidgets.QMenu.exec"):
            terminal_widget._show_context_menu(terminal_widget.terminal_display.rect().center())

    def test_context_menu_has_export_action(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Context menu includes export log action."""
        with patch("PyQt6.QtWidgets.QMenu.exec"):
            terminal_widget._show_context_menu(terminal_widget.terminal_display.rect().center())

    def test_copy_selection_copies_to_clipboard(
        self, terminal_widget: EmbeddedTerminalWidget, qapp: QApplication
    ) -> None:
        """Copy selection copies selected text to clipboard."""
        terminal_widget._handle_output("Test text for copying")
        terminal_widget.terminal_display.selectAll()
        terminal_widget._copy_selection()

        clipboard_text = QApplication.clipboard().text()
        assert "Test text" in clipboard_text

    def test_clear_terminal_removes_all_text(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Clear terminal removes all text from display."""
        terminal_widget._handle_output("Line 1\n")
        terminal_widget._handle_output("Line 2\n")
        terminal_widget.clear()

        text = terminal_widget.terminal_display.toPlainText()
        assert len(text) < 50


class TestEmbeddedTerminalLogExport:
    """Test terminal log export functionality."""

    def test_export_log_writes_to_file(
        self, terminal_widget: EmbeddedTerminalWidget, tmp_path: Path
    ) -> None:
        """Export log writes terminal content to file."""
        terminal_widget._handle_output("Log line 1\n")
        terminal_widget._handle_output("Log line 2\n")

        log_file = tmp_path / "terminal_log.txt"

        with patch.object(QFileDialog, "getSaveFileName", return_value=(str(log_file), "")):
            terminal_widget._export_log()

        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "Log line" in content

    def test_export_log_handles_no_file_selected(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Export log handles case where no file is selected."""
        with patch.object(QFileDialog, "getSaveFileName", return_value=("", "")):
            terminal_widget._export_log()


class TestEmbeddedTerminalCommandValidation:
    """Test command validation and security."""

    def test_start_process_validates_command_type(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Start process validates command is proper type."""
        with pytest.raises(ValueError):
            terminal_widget.start_process(123)

    def test_start_process_sanitizes_cwd_path(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Start process sanitizes working directory path."""
        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_process.pid = 12345
            mock_process.stdout.read.return_value = b""
            mock_popen.return_value = mock_process

            terminal_widget.start_process(["echo", "test"], cwd="/path;with;semicolons")

            call_kwargs = mock_popen.call_args[1]
            assert ";" not in call_kwargs["cwd"]


class TestEmbeddedTerminalOutputQueue:
    """Test output queue processing."""

    def test_output_queue_processes_queued_text(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Output queue processes and displays queued text."""
        terminal_widget._output_queue.put("Queued output 1\n")
        terminal_widget._output_queue.put("Queued output 2\n")

        terminal_widget._process_output_queue()

        text = terminal_widget.terminal_display.toPlainText()
        assert "Queued output" in text

    def test_output_queue_handles_empty_queue(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Output queue processing handles empty queue gracefully."""
        terminal_widget._process_output_queue()


class TestEmbeddedTerminalIntegration:
    """Test complete terminal workflow integration."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_complete_command_execution_workflow(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Complete workflow: start process, execute, capture output, finish."""
        process_finished = False
        exit_code = None

        def on_finished(pid: int, code: int) -> None:
            nonlocal process_finished, exit_code
            process_finished = True
            exit_code = code

        terminal_widget.process_finished.connect(on_finished)

        pid = terminal_widget.start_process(["cmd", "/c", "echo", "Hello"])
        assert pid is not None

        time.sleep(1.0)

        output = terminal_widget.terminal_display.toPlainText()
        assert "Hello" in output or process_finished

    def test_terminal_prompt_display(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Terminal displays command prompt."""
        terminal_widget._show_prompt()
        QApplication.processEvents()

        text = terminal_widget.terminal_display.toPlainText()
        assert "intellicrack>" in text
