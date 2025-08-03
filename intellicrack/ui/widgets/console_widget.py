"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Console Widget for displaying logs and output

A professional console widget with syntax highlighting, filtering, and search capabilities.
"""

from datetime import datetime

from PyQt6.QtCore import QRegularExpression, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class ConsoleSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for console output"""

    def __init__(self, parent=None):
        super().__init__(parent)

        # Define highlighting rules
        self.rules = []

        # Timestamps
        timestamp_format = QTextCharFormat()
        timestamp_format.setForeground(QColor("#666666"))
        self.rules.append(
            (QRegularExpression(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"), timestamp_format)
        )
        self.rules.append((QRegularExpression(r"\d{2}:\d{2}:\d{2}"), timestamp_format))

        # Log levels
        # ERROR
        error_format = QTextCharFormat()
        error_format.setForeground(QColor("#ff6b6b"))
        error_format.setFontWeight(QFont.Bold)
        self.rules.append((QRegularExpression(r"\[ERROR\]|\[FAILED\]|ERROR:|FAIL:"), error_format))

        # WARNING
        warning_format = QTextCharFormat()
        warning_format.setForeground(QColor("#ffa500"))
        self.rules.append(
            (QRegularExpression(r"\[WARNING\]|\[WARN\]|WARNING:|WARN:"), warning_format)
        )

        # SUCCESS
        success_format = QTextCharFormat()
        success_format.setForeground(QColor("#51cf66"))
        success_format.setFontWeight(QFont.Bold)
        self.rules.append((QRegularExpression(r"\[SUCCESS\]|\[OK\]|SUCCESS:|OK:"), success_format))

        # INFO
        info_format = QTextCharFormat()
        info_format.setForeground(QColor("#339af0"))
        self.rules.append((QRegularExpression(r"\[INFO\]|INFO:"), info_format))

        # DEBUG
        debug_format = QTextCharFormat()
        debug_format.setForeground(QColor("#868e96"))
        self.rules.append((QRegularExpression(r"\[DEBUG\]|DEBUG:"), debug_format))

        # Special tags
        # Script/Module names
        script_format = QTextCharFormat()
        script_format.setForeground(QColor("#a78bfa"))
        self.rules.append((QRegularExpression(r"\[SCRIPT\]|\[MODULE\]|\[HOOK\]"), script_format))

        # Process/Session
        process_format = QTextCharFormat()
        process_format.setForeground(QColor("#0ea5e9"))
        self.rules.append((QRegularExpression(r"\[PROCESS\]|\[SESSION\]|PID:"), process_format))

        # Paths (Windows and Unix)
        path_format = QTextCharFormat()
        path_format.setForeground(QColor("#94a3b8"))
        path_format.setFontItalic(True)
        self.rules.append((QRegularExpression(r"[A-Za-z]:\\\\[^\s]+|/[^\s]+"), path_format))

        # IP addresses
        ip_format = QTextCharFormat()
        ip_format.setForeground(QColor("#06b6d4"))
        self.rules.append(
            (QRegularExpression(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), ip_format)
        )

        # Hex values
        hex_format = QTextCharFormat()
        hex_format.setForeground(QColor("#f59e0b"))
        hex_format.setFontFamily("Consolas, monospace")
        self.rules.append((QRegularExpression(r"0x[0-9a-fA-F]+"), hex_format))

        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#10b981"))
        self.rules.append((QRegularExpression(r"\b\d+\b"), number_format))

        # Quoted strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#64748b"))
        self.rules.append((QRegularExpression(r'"[^"]*"'), string_format))
        self.rules.append((QRegularExpression(r"'[^']*'"), string_format))

    def highlightBlock(self, text):
        """Apply syntax highlighting to a block of text"""
        for pattern, format in self.rules:
            expression = QRegularExpression(pattern)
            match_iterator = expression.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)


class ConsoleWidget(QWidget):
    """Professional console widget with filtering and search"""

    # Signals
    commandEntered = pyqtSignal(str)

    def __init__(self, parent=None, enable_input=False):
        """Initialize console widget with input capability, command history, and UI setup."""
        super().__init__(parent)
        self.enable_input = enable_input
        self.command_history = []
        self.history_index = -1
        self.max_lines = 10000
        self.filters = []

        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Toolbar
        toolbar_layout = QHBoxLayout()

        # Filter controls
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(
            [
                "All",
                "Errors",
                "Warnings",
                "Success",
                "Info",
                "Debug",
            ]
        )
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        toolbar_layout.addWidget(self.filter_combo)

        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search...")
        self.search_input.textChanged.connect(self.search_text)
        toolbar_layout.addWidget(self.search_input)

        # Options
        self.wrap_cb = QCheckBox("Wrap")
        self.wrap_cb.stateChanged.connect(self.toggle_wrap)
        toolbar_layout.addWidget(self.wrap_cb)

        self.autoscroll_cb = QCheckBox("Auto-scroll")
        self.autoscroll_cb.setChecked(True)
        toolbar_layout.addWidget(self.autoscroll_cb)

        toolbar_layout.addStretch()

        # Clear button
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear)
        toolbar_layout.addWidget(self.clear_btn)

        # Export button
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_log)
        toolbar_layout.addWidget(self.export_btn)

        layout.addLayout(toolbar_layout)

        # Console output
        self.output = QTextEdit()
        self.output.setReadOnly(not self.enable_input)
        self.output.setFont(QFont("Consolas", 10))
        self.output.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #444;
                padding: 5px;
            }
        """)

        # Apply syntax highlighter
        self.highlighter = ConsoleSyntaxHighlighter(self.output.document())

        layout.addWidget(self.output)

        # Command input (if enabled)
        if self.enable_input:
            self.command_input = QLineEdit()
            self.command_input.setPlaceholderText("Enter command...")
            self.command_input.returnPressed.connect(self.process_command)
            self.command_input.installEventFilter(self)
            layout.addWidget(self.command_input)

        self.setLayout(layout)

    def append_output(self, text: str, level: str = "INFO"):
        """Append text to the console with optional level prefix"""
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Format the output
        if level and level != "RAW":
            formatted_text = f"{timestamp} [{level}] {text}"
        else:
            formatted_text = text

        # Check line limit
        if self.output.document().lineCount() > self.max_lines:
            # Remove oldest lines
            cursor = QTextCursor(self.output.document())
            cursor.movePosition(QTextCursor.Start)
            cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor, 100)
            cursor.removeSelectedText()

        # Append new text
        self.output.append(formatted_text)

        # Auto-scroll if enabled
        if self.autoscroll_cb.isChecked():
            scrollbar = self.output.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def append_error(self, text: str):
        """Append error text"""
        self.append_output(text, "ERROR")

    def append_warning(self, text: str):
        """Append warning text"""
        self.append_output(text, "WARNING")

    def append_success(self, text: str):
        """Append success text"""
        self.append_output(text, "SUCCESS")

    def append_info(self, text: str):
        """Append info text"""
        self.append_output(text, "INFO")

    def append_debug(self, text: str):
        """Append debug text"""
        self.append_output(text, "DEBUG")

    def clear(self):
        """Clear the console"""
        self.output.clear()

    def apply_filter(self, filter_text: str):
        """Apply log level filter"""
        # This is a simplified version - in production you'd actually filter the display
        if filter_text != "All":
            self.append_output(f"Filter applied: {filter_text}", "INFO")

    def search_text(self, search_term: str):
        """Search for text in the console"""
        if not search_term:
            # Clear highlighting
            cursor = self.output.textCursor()
            cursor.clearSelection()
            self.output.setTextCursor(cursor)
            return

        # Find and highlight matches
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.Start)

        # Clear previous selections
        self.output.setExtraSelections([])

        # Find all occurrences
        found = False
        while True:
            cursor = self.output.document().find(
                search_term,
                cursor,
                QTextCursor.FindFlags(),
            )

            if cursor.isNull():
                break

            found = True
            # Highlight the match
            cursor.movePosition(
                QTextCursor.Right,
                QTextCursor.KeepAnchor,
                len(search_term),
            )

            # Move to first match
            if not found:
                self.output.setTextCursor(cursor)

    def toggle_wrap(self, state):
        """Toggle text wrapping"""
        if state == Qt.Checked:
            self.output.setLineWrapMode(QTextEdit.WidgetWidth)
        else:
            self.output.setLineWrapMode(QTextEdit.NoWrap)

    def export_log(self):
        """Export console log to file"""
        from PyQt6.QtWidgets import QFileDialog

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Console Log",
            f"console_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*.*)",
        )

        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(self.output.toPlainText())
                self.append_success(f"Log exported to: {filename}")
            except Exception as e:
                self.logger.error("Exception in console_widget: %s", e)
                self.append_error(f"Failed to export log: {e}")

    def process_command(self):
        """Process entered command (if input enabled)"""
        if not hasattr(self, "command_input"):
            return

        command = self.command_input.text().strip()
        if not command:
            return

        # Add to history
        self.command_history.append(command)
        self.history_index = len(self.command_history)

        # Display command
        self.append_output(f"> {command}", "RAW")

        # Clear input
        self.command_input.clear()

        # Emit signal
        self.commandEntered.emit(command)

    def eventFilter(self, obj, event):
        """Handle key events for command history"""
        if hasattr(self, "command_input") and obj == self.command_input:
            if event.type() == event.KeyPress:
                if event.key() == Qt.Key_Up:
                    # Previous command
                    if self.history_index > 0:
                        self.history_index -= 1
                        self.command_input.setText(
                            self.command_history[self.history_index],
                        )
                    return True
                if event.key() == Qt.Key_Down:
                    # Next command
                    if self.history_index < len(self.command_history) - 1:
                        self.history_index += 1
                        self.command_input.setText(
                            self.command_history[self.history_index],
                        )
                    elif self.history_index == len(self.command_history) - 1:
                        self.history_index = len(self.command_history)
                        self.command_input.clear()
                    return True

        return super().eventFilter(obj, event)

    def get_content(self) -> str:
        """Get the console content"""
        return self.output.toPlainText()

    def set_max_lines(self, max_lines: int):
        """Set maximum number of lines to keep"""
        self.max_lines = max_lines


# Export the widget
__all__ = ["ConsoleWidget"]
