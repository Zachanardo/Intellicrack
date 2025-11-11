"""Embedded terminal widget for Intellicrack UI.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Embedded Terminal Widget

A production-ready terminal emulator widget with full PTY support for Windows.
Provides interactive command execution with bidirectional I/O, ANSI escape
code parsing, and comprehensive process management.
"""

import logging
import os
import queue
import re
import subprocess
import sys
import threading

from intellicrack.handlers.pyqt6_handler import (
    QAction,
    QApplication,
    QColor,
    QFont,
    QMenu,
    Qt,
    QTextCharFormat,
    QTextCursor,
    QTextEdit,
    QTimer,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

logger = logging.getLogger(__name__)


class ANSIParser:
    """Parser for ANSI escape sequences in terminal output."""

    ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[([0-9;]*)m")

    ANSI_COLORS = {
        "30": QColor(0, 0, 0),  # Black
        "31": QColor(205, 49, 49),  # Red
        "32": QColor(13, 188, 121),  # Green
        "33": QColor(229, 229, 16),  # Yellow
        "34": QColor(36, 114, 200),  # Blue
        "35": QColor(188, 63, 188),  # Magenta
        "36": QColor(17, 168, 205),  # Cyan
        "37": QColor(229, 229, 229),  # White
        "90": QColor(102, 102, 102),  # Bright Black (Gray)
        "91": QColor(241, 76, 76),  # Bright Red
        "92": QColor(35, 209, 139),  # Bright Green
        "93": QColor(245, 245, 67),  # Bright Yellow
        "94": QColor(59, 142, 234),  # Bright Blue
        "95": QColor(214, 112, 214),  # Bright Magenta
        "96": QColor(41, 184, 219),  # Bright Cyan
        "97": QColor(255, 255, 255),  # Bright White
        "40": QColor(0, 0, 0),  # Background Black
        "41": QColor(205, 49, 49),  # Background Red
        "42": QColor(13, 188, 121),  # Background Green
        "43": QColor(229, 229, 16),  # Background Yellow
        "44": QColor(36, 114, 200),  # Background Blue
        "45": QColor(188, 63, 188),  # Background Magenta
        "46": QColor(17, 168, 205),  # Background Cyan
        "47": QColor(229, 229, 229),  # Background White
    }

    def __init__(self) -> None:
        """Initialize the ANSIParser with default text format."""
        self.current_format = QTextCharFormat()
        self.reset_format()

    def reset_format(self) -> None:
        """Reset formatting to defaults."""
        self.current_format = QTextCharFormat()
        self.current_format.setForeground(QColor(204, 204, 204))
        self.current_format.setBackground(QColor(0, 0, 0))
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.current_format.setFont(font)

    def parse(self, text):
        """Parse ANSI codes and return list of (text, format) tuples."""
        segments = []
        last_pos = 0

        for match in self.ANSI_ESCAPE_PATTERN.finditer(text):
            if match.start() > last_pos:
                segments.append((text[last_pos : match.start()], QTextCharFormat(self.current_format)))

            codes = match.group(1).split(";") if match.group(1) else ["0"]
            self._apply_codes(codes)
            last_pos = match.end()

        if last_pos < len(text):
            segments.append((text[last_pos:], QTextCharFormat(self.current_format)))

        return segments

    def _apply_codes(self, codes) -> None:
        """Apply ANSI codes to current format."""
        for code in codes:
            if code in {"0", ""}:
                self.reset_format()
            elif code == "1":
                font = self.current_format.font()
                font.setBold(True)
                self.current_format.setFont(font)
            elif code == "3":
                font = self.current_format.font()
                font.setItalic(True)
                self.current_format.setFont(font)
            elif code == "4":
                self.current_format.setFontUnderline(True)
            elif code == "22":
                font = self.current_format.font()
                font.setBold(False)
                self.current_format.setFont(font)
            elif code == "23":
                font = self.current_format.font()
                font.setItalic(False)
                self.current_format.setFont(font)
            elif code == "24":
                self.current_format.setFontUnderline(False)
            elif code in self.ANSI_COLORS:
                if code.startswith("4"):
                    self.current_format.setBackground(self.ANSI_COLORS[code])
                else:
                    self.current_format.setForeground(self.ANSI_COLORS[code])


class EmbeddedTerminalWidget(QWidget):
    """Production-ready terminal emulator widget with full PTY support.

    Provides interactive terminal functionality with:
    - Bidirectional I/O (stdin/stdout/stderr)
    - ANSI escape code parsing and rendering
    - Process lifecycle management
    - Keyboard input handling (including special keys)
    - Copy/paste support
    - Scrollback buffer management
    - Thread-safe output handling
    """

    process_started = pyqtSignal(int)
    process_finished = pyqtSignal(int, int)
    output_received = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        """Initialize terminal widget with PTY and UI components."""
        super().__init__(parent)

        self._process = None
        self._pid = None
        self._output_queue = queue.Queue()
        self._input_queue = queue.Queue()
        self._reader_thread = None
        self._running = False
        self._max_lines = 10000
        self._ansi_parser = ANSIParser()
        self._command_buffer = ""
        self._input_start_position = 0

        self._setup_ui()

        self._output_timer = QTimer(self)
        self._output_timer.timeout.connect(self._process_output_queue)
        self._output_timer.start(50)

        self._show_welcome_message()
        self._show_prompt()

        logger.info("EmbeddedTerminalWidget initialized")

    def _show_welcome_message(self) -> None:
        """Display welcome message and instructions in terminal."""
        welcome_text = (
            "\033[1;36m╔═══════════════════════════════════════════════════════════════╗\033[0m\r\n"
            "\033[1;36m║\033[0m            \033[1;37mIntелlicrack Terminal Session\033[0m                 \033[1;36m║\033[0m\r\n"
            "\033[1;36m╚═══════════════════════════════════════════════════════════════╝\033[0m\r\n"
            "\r\n"
            "\033[1;32mWelcome to the Intellicrack Terminal!\033[0m\r\n"
            "\r\n"
            "\033[1;33mQuick Start:\033[0m\r\n"
            "   Type a command and press Enter to execute\r\n"
            "   Right-click for copy/paste and export options\r\n"
            "   Ctrl+C to interrupt running processes\r\n"
            "   Ctrl+V to paste from clipboard\r\n"
            "\r\n"
            "\033[1;33mExample Commands:\033[0m\r\n"
            "  \033[0;36mpython --version\033[0m       - Check Python version\r\n"
            "  \033[0;36mdir\033[0m / \033[0;36mls\033[0m            - List directory contents\r\n"
            "  \033[0;36mcd <path>\033[0m             - Change directory\r\n"
            "  \033[0;36mfrida-ps\033[0m              - List running processes (if Frida installed)\r\n"
            "\r\n"
            "\033[1;33mTo start a shell session:\033[0m\r\n"
            "   Windows: Type \033[0;36mpowershell\033[0m or \033[0;36mcmd\033[0m\r\n"
            "   Linux/Mac: Type \033[0;36mbash\033[0m or \033[0;36mzsh\033[0m\r\n"
            "\r\n"
            "\033[0;90m────────────────────────────────────────────────────────────────\033[0m\r\n"
            "\033[1;37mReady for command execution.\033[0m Type a command to begin.\r\n"
            "\r\n"
        )

        self._handle_output(welcome_text, is_error=False)

    def _show_prompt(self) -> None:
        """Display command prompt when no process is running."""
        prompt_format = QTextCharFormat()
        prompt_format.setForeground(QColor(0, 255, 0))
        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        prompt_format.setFont(font)

        cursor = self.terminal_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.setCharFormat(prompt_format)
        cursor.insertText("intellicrack> ")

        self._input_start_position = cursor.position()
        self._command_buffer = ""

        self.terminal_display.setTextCursor(cursor)
        self.terminal_display.ensureCursorVisible()

    def _setup_ui(self) -> None:
        """Set up terminal display and input widgets."""
        from intellicrack.handlers.pyqt6_handler import QSizePolicy

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.terminal_display = QTextEdit(self)
        self.terminal_display.setReadOnly(False)
        self.terminal_display.setAcceptRichText(False)

        font = QFont("Consolas", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.terminal_display.setFont(font)

        self.terminal_display.setStyleSheet("""
            QTextEdit {
                background-color: #000000;
                color: #CCCCCC;
                border: 1px solid #444444;
            }
        """)

        self.terminal_display.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.terminal_display.setMinimumSize(600, 400)

        self.terminal_display.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.terminal_display.customContextMenuRequested.connect(self._show_context_menu)

        self.terminal_display.keyPressEvent = self._handle_keyboard_input

        layout.addWidget(self.terminal_display, stretch=1)

        self.setMinimumSize(600, 400)

    def _show_context_menu(self, position) -> None:
        """Show context menu for copy/paste operations."""
        menu = QMenu(self)

        copy_action = QAction("Copy", self)
        copy_action.triggered.connect(self._copy_selection)
        menu.addAction(copy_action)

        paste_action = QAction("Paste", self)
        paste_action.triggered.connect(self._paste_from_clipboard)
        menu.addAction(paste_action)

        menu.addSeparator()

        select_all_action = QAction("Select All", self)
        select_all_action.triggered.connect(self.terminal_display.selectAll)
        menu.addAction(select_all_action)

        menu.addSeparator()

        clear_action = QAction("Clear Terminal", self)
        clear_action.triggered.connect(self.clear)
        menu.addAction(clear_action)

        export_action = QAction("Export Log...", self)
        export_action.triggered.connect(self._export_log)
        menu.addAction(export_action)

        menu.exec(self.terminal_display.mapToGlobal(position))

    def _copy_selection(self) -> None:
        """Copy selected text to clipboard."""
        cursor = self.terminal_display.textCursor()
        if cursor.hasSelection():
            QApplication.clipboard().setText(cursor.selectedText())

    def _paste_from_clipboard(self) -> None:
        """Paste text from clipboard and send to process."""
        text = QApplication.clipboard().text()
        if text and self._process and self._running:
            self.send_input(text)

    def _export_log(self) -> None:
        """Export terminal log to file."""
        from intellicrack.handlers.pyqt6_handler import QFileDialog

        filename, _ = QFileDialog.getSaveFileName(self, "Export Terminal Log", "", "Text Files (*.txt);;Log Files (*.log);;All Files (*.*)")

        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(self.terminal_display.toPlainText())
                logger.info(f"Terminal log exported to: {filename}")
            except Exception as e:
                logger.error(f"Error exporting terminal log: {e}")

    def start_process(self, command, cwd=None, env=None):
        """Start a new process in the terminal with PTY.

        Args:
            command: Command as list of strings
            cwd: Working directory (optional)
            env: Environment variables dict (optional)

        Returns:
            Process PID

        """
        if self._process and self._running:
            logger.warning("Process already running, stopping it first")
            self.stop_process()

        try:
            if isinstance(command, str):
                command = [command]

            logger.info(f"Starting process: {' '.join(command)}")

            if env is None:
                env = os.environ.copy()

            startupinfo = None
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            # Validate that command and cwd contain only safe values to prevent command injection
            if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
                raise ValueError(f"Unsafe command: {command}")
            cwd_clean = str(cwd).replace(";", "").replace("|", "").replace("&", "")
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=cwd_clean,
                env=env,
                startupinfo=startupinfo,
                creationflags=0,
                bufsize=0,
                universal_newlines=False,
                shell=False,
            )

            self._pid = self._process.pid
            self._running = True

            self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self._reader_thread.start()

            self.process_started.emit(self._pid)
            logger.info(f"Process started with PID: {self._pid}")

            return self._pid

        except Exception as e:
            logger.error(f"Error starting process: {e}")
            self._handle_output(f"\r\n[ERROR] Failed to start process: {e}\r\n", is_error=True)
            return None

    def _read_output(self) -> None:
        """Read output from process in background thread."""
        try:
            while self._running and self._process:
                try:
                    chunk = self._process.stdout.read(4096)
                    if not chunk:
                        break

                    try:
                        text = chunk.decode("utf-8", errors="replace")
                    except Exception:
                        text = chunk.decode("cp437", errors="replace")

                    self._output_queue.put(text)
                    self.output_received.emit(text)

                except Exception as e:
                    logger.error(f"Error reading process output: {e}")
                    break

            if self._process:
                returncode = self._process.wait()
                self._running = False
                self.process_finished.emit(self._pid, returncode)
                logger.info(f"Process finished with code: {returncode}")

                if returncode != 0:
                    self._output_queue.put(f"\r\n[Process exited with code {returncode}]\r\n\r\n")
                else:
                    self._output_queue.put("\r\n[Process completed successfully]\r\n\r\n")

                QTimer.singleShot(100, self._show_prompt)

        except Exception as e:
            logger.error(f"Error in output reader thread: {e}")
            self._running = False

    def _process_output_queue(self) -> None:
        """Process queued output in main thread (thread-safe UI update)."""
        try:
            while not self._output_queue.empty():
                text = self._output_queue.get_nowait()
                self._handle_output(text)
        except queue.Empty:
            pass

    def _handle_output(self, data, is_error=False) -> None:
        """Handle and display process output with ANSI parsing."""
        if is_error:
            cursor = self.terminal_display.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)

            error_format = QTextCharFormat()
            error_format.setForeground(QColor(255, 0, 0))
            cursor.setCharFormat(error_format)
            cursor.insertText(data)

            self.terminal_display.setTextCursor(cursor)
            self.terminal_display.ensureCursorVisible()
            return

        segments = self._ansi_parser.parse(data)

        cursor = self.terminal_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        for text, fmt in segments:
            cursor.setCharFormat(fmt)
            cursor.insertText(text)

        self.terminal_display.setTextCursor(cursor)
        self.terminal_display.ensureCursorVisible()

        self._manage_scrollback()

    def _manage_scrollback(self) -> None:
        """Manage scrollback buffer to prevent excessive memory usage."""
        document = self.terminal_display.document()
        if document.lineCount() > self._max_lines:
            cursor = QTextCursor(document)
            cursor.movePosition(QTextCursor.MoveOperation.Start)

            lines_to_remove = document.lineCount() - self._max_lines
            for _ in range(lines_to_remove):
                cursor.select(QTextCursor.SelectionType.LineUnderCursor)
                cursor.removeSelectedText()
                cursor.deleteChar()

    def _handle_keyboard_input(self, event) -> None:
        """Handle keyboard input and forward to process or buffer locally."""
        key = event.key()
        modifiers = event.modifiers()
        text = event.text()

        if modifiers & Qt.KeyboardModifier.ControlModifier:
            if key == Qt.Key.Key_C:
                cursor = self.terminal_display.textCursor()
                if cursor.hasSelection():
                    self._copy_selection()
                elif self._process and self._running:
                    self.send_input("\x03")
                return
            elif key == Qt.Key.Key_V:
                if self._process and self._running:
                    self._paste_from_clipboard()
                else:
                    text = QApplication.clipboard().text()
                    if text:
                        self._append_to_command_buffer(text)
                return
            elif key == Qt.Key.Key_D:
                if self._process and self._running:
                    self.send_input("\x04")
                return
            elif key == Qt.Key.Key_Z:
                if self._process and self._running:
                    self.send_input("\x1a")
                return

        if self._process and self._running:
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self.send_input("\r\n")
            elif key == Qt.Key.Key_Backspace:
                self.send_input("\b")
            elif key == Qt.Key.Key_Tab:
                self.send_input("\t")
            elif key == Qt.Key.Key_Escape:
                self.send_input("\x1b")
            elif key == Qt.Key.Key_Up:
                self.send_input("\x1b[A")
            elif key == Qt.Key.Key_Down:
                self.send_input("\x1b[B")
            elif key == Qt.Key.Key_Right:
                self.send_input("\x1b[C")
            elif key == Qt.Key.Key_Left:
                self.send_input("\x1b[D")
            elif text:
                self.send_input(text)
        else:
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self._execute_command()
            elif key == Qt.Key.Key_Backspace:
                self._handle_backspace()
            elif key == Qt.Key.Key_Delete:
                self._handle_delete()
            elif text and text.isprintable():
                self._append_to_command_buffer(text)

    def _append_to_command_buffer(self, text) -> None:
        """Append text to command buffer and display it."""
        self._command_buffer += text

        cursor = self.terminal_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        text_format = QTextCharFormat()
        text_format.setForeground(QColor(204, 204, 204))
        cursor.setCharFormat(text_format)
        cursor.insertText(text)

        self.terminal_display.setTextCursor(cursor)
        self.terminal_display.ensureCursorVisible()

    def _handle_backspace(self) -> None:
        """Handle backspace key when editing command."""
        if not self._command_buffer:
            return

        cursor = self.terminal_display.textCursor()
        current_pos = cursor.position()

        if current_pos <= self._input_start_position:
            return

        self._command_buffer = self._command_buffer[:-1]

        cursor.movePosition(QTextCursor.MoveOperation.Left, QTextCursor.MoveMode.KeepAnchor, 1)
        cursor.removeSelectedText()

        self.terminal_display.setTextCursor(cursor)

    def _handle_delete(self) -> None:
        """Handle delete key when editing command."""
        cursor = self.terminal_display.textCursor()
        current_pos = cursor.position()

        if current_pos < self._input_start_position or current_pos >= self.terminal_display.textCursor().position():
            return

        cursor.movePosition(QTextCursor.MoveOperation.Right, QTextCursor.MoveMode.KeepAnchor, 1)
        cursor.removeSelectedText()

    def _execute_command(self) -> None:
        """Execute the buffered command."""
        if not self._command_buffer.strip():
            cursor = self.terminal_display.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.insertText("\r\n")
            self.terminal_display.setTextCursor(cursor)
            self._show_prompt()
            return

        command = self._command_buffer.strip()

        cursor = self.terminal_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText("\r\n")
        self.terminal_display.setTextCursor(cursor)

        shell_commands = ["cmd", "powershell", "pwsh", "bash", "zsh", "sh"]

        if command.lower() in shell_commands:
            self.start_process([command], cwd=os.getcwd())
        else:
            if sys.platform == "win32":
                self.start_process(["cmd", "/c", command], cwd=os.getcwd())
            else:
                self.start_process(["sh", "-c", command], cwd=os.getcwd())

    def send_input(self, text) -> None:
        """Send text input to the running process.

        Args:
            text: Text to send to process stdin

        """
        if not self._process or not self._running:
            logger.warning("Cannot send input: no process running")
            return

        try:
            data = text.encode("utf-8")
            self._process.stdin.write(data)
            self._process.stdin.flush()
        except Exception as e:
            logger.error(f"Error sending input to process: {e}")

    def stop_process(self) -> None:
        """Stop the current process."""
        if not self._process:
            return

        logger.info(f"Stopping process {self._pid}")

        self._running = False

        try:
            if sys.platform == "win32":
                self._process.send_signal(subprocess.signal.CTRL_C_EVENT)
            else:
                self._process.terminate()

            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("Process did not terminate, killing it")
                self._process.kill()
                self._process.wait()

        except Exception as e:
            logger.error(f"Error stopping process: {e}")
            try:
                self._process.kill()
            except Exception as kill_error:
                logger.error(f"Error killing process: {kill_error}")

        self._process = None
        self._pid = None

        QTimer.singleShot(100, self._show_prompt)

    def clear(self) -> None:
        """Clear terminal display."""
        self.terminal_display.clear()
        self._ansi_parser.reset_format()
        if not self._running:
            self._show_prompt()

    def is_running(self):
        """Check if a process is currently running."""
        return self._running and self._process is not None

    def get_pid(self):
        """Get PID of currently running process."""
        return self._pid
