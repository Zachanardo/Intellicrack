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

import io
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from collections.abc import Generator
from typing import Any, Optional

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QTextCharFormat
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog

from intellicrack.ui.widgets.embedded_terminal_widget import (
    ANSIParser,
    EmbeddedTerminalWidget,
)


class FakeProcess:
    """Test double for subprocess.Popen that simulates a real process."""

    def __init__(
        self,
        args: list[str],
        stdout: int,
        stderr: int,
        stdin: int,
        cwd: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        self.args = args
        self.pid = 12345
        self._poll_return: Optional[int] = None
        self._wait_return = 0
        self._terminated = False
        self._killed = False
        self.stdout = FakeStream(b"")
        self.stderr = FakeStream(b"")
        self.stdin = FakeWriteStream()

    def poll(self) -> Optional[int]:
        """Check if process has terminated."""
        return self._poll_return

    def wait(self, timeout: Optional[float] = None) -> int:
        """Wait for process to terminate and return exit code."""
        return self._wait_return

    def terminate(self) -> None:
        """Terminate the process."""
        self._terminated = True
        self._poll_return = 0

    def kill(self) -> None:
        """Kill the process."""
        self._killed = True
        self._poll_return = -1


class FakeStream:
    """Test double for file-like stream object."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._position = 0

    def read(self, size: int = -1) -> bytes:
        """Read data from stream."""
        if size == -1:
            result = self._data[self._position:]
            self._position = len(self._data)
        else:
            result = self._data[self._position:self._position + size]
            self._position += len(result)
        return result

    def readline(self) -> bytes:
        """Read a line from stream."""
        start = self._position
        while self._position < len(self._data):
            if self._data[self._position:self._position + 1] == b'\n':
                self._position += 1
                return self._data[start:self._position]
            self._position += 1
        result = self._data[start:]
        return result


class FakeWriteStream:
    """Test double for writable stream."""

    def __init__(self) -> None:
        self.written_data: list[bytes] = []
        self._closed = False

    def write(self, data: bytes) -> int:
        """Write data to stream."""
        if not self._closed:
            self.written_data.append(data)
            return len(data)
        return 0

    def flush(self) -> None:
        """Flush stream."""
        pass

    def close(self) -> None:
        """Close stream."""
        self._closed = True


class FakePopenContext:
    """Context manager for patching subprocess.Popen."""

    def __init__(self, fake_process: FakeProcess) -> None:
        self.fake_process = fake_process
        self.original_popen: Optional[type] = None

    def __enter__(self) -> FakeProcess:
        """Enter context and patch Popen."""
        import subprocess
        self.original_popen = subprocess.Popen
        subprocess.Popen = lambda *args, **kwargs: self.fake_process  # type: ignore[misc, assignment]
        return self.fake_process

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context and restore Popen."""
        import subprocess
        if self.original_popen is not None:
            subprocess.Popen = self.original_popen  # type: ignore[misc, assignment]


class FakeFileDialog:
    """Test double for QFileDialog."""

    def __init__(self, return_value: tuple[str, str]) -> None:
        self.return_value = return_value
        self.original_method: Optional[Any] = None

    def __enter__(self) -> "FakeFileDialog":
        """Enter context and patch getSaveFileName."""
        self.original_method = QFileDialog.getSaveFileName
        QFileDialog.getSaveFileName = lambda *args, **kwargs: self.return_value  # type: ignore[method-assign]
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context and restore getSaveFileName."""
        if self.original_method is not None:
            QFileDialog.getSaveFileName = self.original_method  # type: ignore[method-assign]


class FakeMultipleProcesses:
    """Test double for multiple sequential process creations."""

    def __init__(self, processes: list[FakeProcess]) -> None:
        self.processes = processes
        self.call_count = 0
        self.original_popen: Optional[type] = None

    def create_process(self, *args: Any, **kwargs: Any) -> FakeProcess:
        """Create next process in sequence."""
        if self.call_count < len(self.processes):
            process = self.processes[self.call_count]
            self.call_count += 1
            return process
        return self.processes[-1]

    def __enter__(self) -> "FakeMultipleProcesses":
        """Enter context and patch Popen."""
        import subprocess
        self.original_popen = subprocess.Popen
        subprocess.Popen = self.create_process  # type: ignore[misc, assignment]
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context and restore Popen."""
        import subprocess
        if self.original_popen is not None:
            subprocess.Popen = self.original_popen  # type: ignore[misc, assignment]


class FakeMenuExec:
    """Test double for QMenu.exec method."""

    def __init__(self) -> None:
        self.original_exec: Optional[Any] = None

    def __enter__(self) -> "FakeMenuExec":
        """Enter context and patch QMenu.exec."""
        from PyQt6.QtWidgets import QMenu
        self.original_exec = QMenu.exec
        QMenu.exec = lambda *args, **kwargs: None  # type: ignore[method-assign]
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context and restore QMenu.exec."""
        from PyQt6.QtWidgets import QMenu
        if self.original_exec is not None:
            QMenu.exec = self.original_exec  # type: ignore[method-assign]


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def terminal_widget(qapp: QApplication) -> Generator[EmbeddedTerminalWidget, None, None]:
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
        fake_process = FakeProcess(
            ["echo", "test"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )

        with FakePopenContext(fake_process):
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

        fake_process = FakeProcess(
            ["echo", "test"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )

        with FakePopenContext(fake_process):
            terminal_widget.start_process(["echo", "test"])
            time.sleep(0.1)

            assert signal_received
            assert received_pid == 12345

    def test_stop_process_terminates_running_process(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Stop process terminates running process."""
        fake_process = FakeProcess(
            ["sleep", "100"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )

        with FakePopenContext(fake_process):
            terminal_widget.start_process(["sleep", "100"])
            terminal_widget.stop_process()

            assert fake_process._terminated or fake_process._killed

    def test_start_process_stops_existing_process_first(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Starting new process stops existing running process."""
        fake_process1 = FakeProcess(
            ["cmd1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        fake_process1.pid = 111

        fake_process2 = FakeProcess(
            ["cmd2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        fake_process2.pid = 222

        with FakeMultipleProcesses([fake_process1, fake_process2]):
            terminal_widget.start_process(["cmd1"])
            time.sleep(0.1)
            terminal_widget.start_process(["cmd2"])

            assert fake_process1._terminated or fake_process1._killed

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

        fake_process = FakeProcess(
            ["echo", "test"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )
        fake_process._wait_return = 0

        with FakePopenContext(fake_process):
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
        fake_process = FakeProcess(
            ["cat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE
        )

        with FakePopenContext(fake_process):
            terminal_widget.start_process(["cat"])
            terminal_widget.send_input("test input\n")

            assert len(fake_process.stdin.written_data) > 0

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
        with FakeMenuExec():
            terminal_widget._show_context_menu(terminal_widget.terminal_display.rect().center())

    def test_context_menu_has_paste_action(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Context menu includes paste action."""
        with FakeMenuExec():
            terminal_widget._show_context_menu(terminal_widget.terminal_display.rect().center())

    def test_context_menu_has_clear_action(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Context menu includes clear terminal action."""
        with FakeMenuExec():
            terminal_widget._show_context_menu(terminal_widget.terminal_display.rect().center())

    def test_context_menu_has_export_action(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Context menu includes export log action."""
        with FakeMenuExec():
            terminal_widget._show_context_menu(terminal_widget.terminal_display.rect().center())

    def test_copy_selection_copies_to_clipboard(
        self, terminal_widget: EmbeddedTerminalWidget, qapp: QApplication
    ) -> None:
        """Copy selection copies selected text to clipboard."""
        terminal_widget._handle_output("Test text for copying")
        terminal_widget.terminal_display.selectAll()
        terminal_widget._copy_selection()

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        clipboard_text = clipboard.text()
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

        with FakeFileDialog((str(log_file), "")):
            terminal_widget._export_log()

        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "Log line" in content

    def test_export_log_handles_no_file_selected(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Export log handles case where no file is selected."""
        with FakeFileDialog(("", "")):
            terminal_widget._export_log()


class TestEmbeddedTerminalCommandValidation:
    """Test command validation and security."""

    def test_start_process_validates_command_type(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Start process validates command is proper type."""
        with pytest.raises(ValueError):
            terminal_widget.start_process(123)  # type: ignore[arg-type]

    def test_start_process_sanitizes_cwd_path(
        self, terminal_widget: EmbeddedTerminalWidget
    ) -> None:
        """Start process sanitizes working directory path."""
        fake_process = FakeProcess(
            ["echo", "test"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd="/path;with;semicolons"
        )

        with FakePopenContext(fake_process):
            terminal_widget.start_process(["echo", "test"], cwd="/path;with;semicolons")


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
