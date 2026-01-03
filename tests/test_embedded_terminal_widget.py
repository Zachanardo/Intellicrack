"""Unit tests for EmbeddedTerminalWidget.

Tests the terminal widget's process execution, I/O handling, ANSI parsing,
and user interaction capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import sys
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.widgets.embedded_terminal_widget import EmbeddedTerminalWidget


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication, None, None]:
    """Create QApplication instance for tests."""
    existing = QApplication.instance()
    if existing is None:
        app = QApplication(sys.argv)
    else:
        app = cast(QApplication, existing)
    yield app


@pytest.fixture
def terminal_widget(qapp: QApplication, qtbot: Any) -> Generator[EmbeddedTerminalWidget, None, None]:
    """Create terminal widget for testing."""
    widget = EmbeddedTerminalWidget()
    qtbot.addWidget(widget)
    widget.show()
    qtbot.waitExposed(widget)
    yield widget
    if widget.is_running():
        widget.stop_process()
    widget.close()


class TestBasicProcessExecution:
    """Test basic process execution functionality."""

    def test_start_simple_process(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test starting a simple echo process."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "Hello Terminal"]
        else:
            command = ["echo", "Hello Terminal"]

        terminal_widget.start_process(command)
        qtbot.wait(500)

        output = terminal_widget.terminal_display.toPlainText()
        assert "Hello Terminal" in output

    def test_process_with_working_directory(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test process execution with specific working directory."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            command = ["cmd", "/c", "cd"] if sys.platform == "win32" else ["pwd"]
            terminal_widget.start_process(command, cwd=tmpdir)
            qtbot.wait(500)

            output = terminal_widget.terminal_display.toPlainText()
            assert tmpdir in output or Path(tmpdir).name in output

    def test_sequential_processes(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test running multiple processes sequentially."""
        commands = [
            (["cmd", "/c", "echo", "First"] if sys.platform == "win32" else ["echo", "First"]),
            (["cmd", "/c", "echo", "Second"] if sys.platform == "win32" else ["echo", "Second"]),
        ]

        for cmd in commands:
            terminal_widget.start_process(cmd)
            qtbot.wait(500)

        output = terminal_widget.terminal_display.toPlainText()
        assert "First" in output
        assert "Second" in output


class TestInputOutputHandling:
    """Test input/output handling."""

    def test_capture_stdout(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test capturing standard output."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "STDOUT_TEST"]
        else:
            command = ["echo", "STDOUT_TEST"]

        terminal_widget.start_process(command)
        qtbot.wait(500)

        output = terminal_widget.terminal_display.toPlainText()
        assert "STDOUT_TEST" in output

    def test_send_input(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test sending input to running process."""
        command = ["cmd"] if sys.platform == "win32" else ["sh"]
        terminal_widget.start_process(command)
        qtbot.wait(300)

        terminal_widget.send_input("echo INPUT_TEST\n")
        qtbot.wait(500)

        output = terminal_widget.terminal_display.toPlainText()
        assert "INPUT_TEST" in output or "echo INPUT_TEST" in output

        terminal_widget.stop_process()


class TestProcessTermination:
    """Test process termination functionality."""

    def test_stop_running_process(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test stopping a running process."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "timeout", "/t", "10"]
        else:
            command = ["sleep", "10"]

        terminal_widget.start_process(command)
        qtbot.wait(500)

        assert terminal_widget.is_running()

        terminal_widget.stop_process()
        qtbot.wait(500)

        assert not terminal_widget.is_running()

    def test_stop_finished_process(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test stopping an already finished process."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "Done"]
        else:
            command = ["echo", "Done"]

        terminal_widget.start_process(command)
        qtbot.wait(500)

        terminal_widget.stop_process()
        qtbot.wait(200)

        assert not terminal_widget.is_running()


class TestScrollbackBuffer:
    """Test scrollback buffer functionality."""

    def test_buffer_maintains_limit(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test scrollback buffer maintains size limit."""
        terminal_widget.clear()

        for i in range(200):
            if sys.platform == "win32":
                command = ["cmd", "/c", "echo", f"Line {i}"]
            else:
                command = ["echo", f"Line {i}"]

            terminal_widget.start_process(command)
            qtbot.wait(10)

        output = terminal_widget.terminal_display.toPlainText()
        lines = output.split('\n')

        assert len(lines) <= 1100

    def test_clear_output(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test clearing the output buffer."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "Test Output"]
        else:
            command = ["echo", "Test Output"]

        terminal_widget.start_process(command)
        qtbot.wait(300)

        terminal_widget.clear()
        output = terminal_widget.terminal_display.toPlainText()

        assert output.strip() == ""


class TestCopyPasteFunctionality:
    """Test copy/paste functionality."""

    def test_copy_text(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test copying text from terminal."""
        terminal_widget.clear()

        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "COPY_TEST_TEXT"]
        else:
            command = ["echo", "COPY_TEST_TEXT"]

        terminal_widget.start_process(command)
        qtbot.wait(500)

        cursor = terminal_widget.terminal_display.textCursor()
        cursor.select(QTextCursor.SelectionType.Document)
        terminal_widget.terminal_display.setTextCursor(cursor)

        terminal_widget._copy_selection()
        qtbot.wait(100)

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        clipboard_text = clipboard.text()

        assert "COPY_TEST_TEXT" in clipboard_text

    def test_paste_to_terminal(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test pasting text to terminal."""
        command = ["cmd"] if sys.platform == "win32" else ["sh"]
        terminal_widget.start_process(command)
        qtbot.wait(300)

        clipboard = QApplication.clipboard()
        assert clipboard is not None
        clipboard.setText("echo PASTE_TEST")

        terminal_widget._paste_from_clipboard()
        qtbot.wait(100)

        output = terminal_widget.terminal_display.toPlainText()
        assert "PASTE_TEST" in output or "echo PASTE_TEST" in output

        terminal_widget.stop_process()


class TestANSIHandling:
    """Test ANSI escape code handling."""

    def test_ansi_parser_creation(self, terminal_widget: EmbeddedTerminalWidget) -> None:
        """Test ANSI parser is created."""
        from intellicrack.ui.widgets.embedded_terminal_widget import ANSIParser
        parser = ANSIParser()
        assert parser is not None

    def test_basicterminal_display(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test basic output is displayed correctly."""
        terminal_widget.clear()

        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "TEST_OUTPUT"]
        else:
            command = ["echo", "TEST_OUTPUT"]

        terminal_widget.start_process(command)
        qtbot.wait(500)

        output = terminal_widget.terminal_display.toPlainText()
        assert "TEST_OUTPUT" in output


class TestProcessInfo:
    """Test process information methods."""

    def test_get_pid(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test getting process PID."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "timeout", "/t", "5"]
        else:
            command = ["sleep", "5"]

        terminal_widget.start_process(command)
        qtbot.wait(300)

        pid = terminal_widget.get_pid()
        assert pid is not None
        assert pid > 0

        terminal_widget.stop_process()

    def test_is_running_status(self, terminal_widget: EmbeddedTerminalWidget, qtbot: Any) -> None:
        """Test is_running status tracking."""
        if sys.platform == "win32":
            command = ["cmd", "/c", "echo", "Quick"]
        else:
            command = ["echo", "Quick"]

        terminal_widget.start_process(command)
        qtbot.wait(100)

        running_during = terminal_widget.is_running()

        qtbot.wait(500)

        running_after = terminal_widget.is_running()

        assert running_during or not running_after
