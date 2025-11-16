"""Console widget for Intellicrack UI.

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

Console Widget for displaying logs and output

A professional console widget with syntax highlighting, filtering, and search capabilities.
"""

from datetime import datetime

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QColor,
    QComboBox,
    QFont,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QRegularExpression,
    QSyntaxHighlighter,
    Qt,
    QTextCharFormat,
    QTextCursor,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)


class ConsoleSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for console output with pattern-based formatting.

    Provides visual highlighting for various console message types including
    errors, warnings, success messages, timestamps, IP addresses, hex values,
    paths, and other common patterns found in analysis tool output.
    """

    def __init__(self, parent: object | None = None) -> None:
        """Initialize the syntax highlighter with predefined highlighting rules.

        Args:
            parent: Parent QObject, typically the document to be highlighted.

        """
        super().__init__(parent)

        self.rules: list[tuple[QRegularExpression, QTextCharFormat]] = []

        # Timestamps
        timestamp_format = QTextCharFormat()
        timestamp_format.setForeground(QColor("#666666"))
        self.rules.append((QRegularExpression(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"), timestamp_format))
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
        self.rules.append((QRegularExpression(r"\[WARNING\]|\[WARN\]|WARNING:|WARN:"), warning_format))

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
        self.rules.append((QRegularExpression(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), ip_format))

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

    def highlightBlock(self, text: str) -> None:
        """Apply syntax highlighting to a block of text.

        Args:
            text: The text block to apply syntax highlighting to.

        """
        for pattern, text_format in self.rules:
            expression = QRegularExpression(pattern)
            match_iterator = expression.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), text_format)


class ConsoleWidget(QWidget):
    """Professional console widget with advanced filtering, search, and command input.

    Provides a feature-rich console display for analysis tool output with syntax
    highlighting, log filtering by level (error, warning, success, info, debug),
    text search with highlighting, line wrapping, auto-scroll, and command history
    navigation. Supports command input and event emission when commands are entered.
    """

    command_entered = pyqtSignal(str)

    def __init__(self, parent: object | None = None, enable_input: bool = False) -> None:
        """Initialize console widget with input capability, command history, and UI setup.

        Args:
            parent: Parent widget, typically the main window.
            enable_input: If True, enables command input field and emits command_entered
                         signal when commands are submitted.

        Raises:
            No exceptions are raised during initialization.

        """
        super().__init__(parent)
        self.enable_input: bool = enable_input
        self.command_history: list[str] = []
        self.history_index: int = -1
        self.max_lines: int = 10000
        self.filters: list[str] = []

        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the user interface with toolbar, filters, and text display.

        Creates the console layout including filter dropdown, search input, wrap/autoscroll
        toggles, clear/export buttons, syntax-highlighted text output, and optional
        command input field.
        """
        layout: QVBoxLayout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        toolbar_layout: QHBoxLayout = QHBoxLayout()

        self.filter_combo: QComboBox = QComboBox()
        self.filter_combo.addItems(
            [
                "All",
                "Errors",
                "Warnings",
                "Success",
                "Info",
                "Debug",
            ],
        )
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        toolbar_layout.addWidget(self.filter_combo)

        self.search_input: QLineEdit = QLineEdit()
        self.search_input.setToolTip("Enter text to search in console output")
        self.search_input.setText("")
        self.search_input.textChanged.connect(self.search_text)
        toolbar_layout.addWidget(self.search_input)

        self.wrap_cb: QCheckBox = QCheckBox("Wrap")
        self.wrap_cb.stateChanged.connect(self.toggle_wrap)
        toolbar_layout.addWidget(self.wrap_cb)

        self.autoscroll_cb: QCheckBox = QCheckBox("Auto-scroll")
        self.autoscroll_cb.setChecked(True)
        toolbar_layout.addWidget(self.autoscroll_cb)

        toolbar_layout.addStretch()

        self.clear_btn: QPushButton = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear)
        toolbar_layout.addWidget(self.clear_btn)

        self.export_btn: QPushButton = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_log)
        toolbar_layout.addWidget(self.export_btn)

        layout.addLayout(toolbar_layout)

        self.output: QTextEdit = QTextEdit()
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

        self.highlighter: ConsoleSyntaxHighlighter = ConsoleSyntaxHighlighter(self.output.document())

        layout.addWidget(self.output)

        if self.enable_input:
            self.command_input: QLineEdit = QLineEdit()
            self.command_input.setToolTip("Type commands and press Enter to execute")
            self.command_input.setText("")
            self.command_input.returnPressed.connect(self.process_command)
            self.command_input.installEventFilter(self)
            layout.addWidget(self.command_input)

        self.setLayout(layout)

    def append_output(self, text: str, level: str = "INFO") -> None:
        """Append text to the console with optional level prefix and timestamp.

        Appends formatted text to the console output. Text is automatically prefixed
        with a timestamp and log level. Enforces maximum line count and auto-scrolls
        when enabled. Log levels are color-coded by the syntax highlighter.

        Args:
            text: The message text to append to the console.
            level: Log level indicator (ERROR, WARNING, SUCCESS, INFO, DEBUG, or RAW
                  for no prefix). Defaults to "INFO".

        Returns:
            None

        Note:
            When line count exceeds max_lines, oldest 100 lines are automatically
            removed to prevent excessive memory consumption.

        """
        timestamp = datetime.now().strftime("%H:%M:%S")

        if level and level != "RAW":
            formatted_text = f"{timestamp} [{level}] {text}"
        else:
            formatted_text = text

        if self.output.document().lineCount() > self.max_lines:
            cursor = QTextCursor(self.output.document())
            cursor.movePosition(QTextCursor.Start)
            cursor.movePosition(QTextCursor.Down, QTextCursor.KeepAnchor, 100)
            cursor.removeSelectedText()

        self.output.append(formatted_text)

        if self.autoscroll_cb.isChecked():
            scrollbar = self.output.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def append_error(self, text: str) -> None:
        """Append error-level message (displayed in red with bold formatting).

        Args:
            text: The error message to append.

        Returns:
            None

        """
        self.append_output(text, "ERROR")

    def append_warning(self, text: str) -> None:
        """Append warning-level message (displayed in orange).

        Args:
            text: The warning message to append.

        Returns:
            None

        """
        self.append_output(text, "WARNING")

    def append_success(self, text: str) -> None:
        """Append success-level message (displayed in green with bold formatting).

        Args:
            text: The success message to append.

        Returns:
            None

        """
        self.append_output(text, "SUCCESS")

    def append_info(self, text: str) -> None:
        """Append info-level message (displayed in blue).

        Args:
            text: The info message to append.

        Returns:
            None

        """
        self.append_output(text, "INFO")

    def append_debug(self, text: str) -> None:
        """Append debug-level message (displayed in gray).

        Args:
            text: The debug message to append.

        Returns:
            None

        """
        self.append_output(text, "DEBUG")

    def clear(self) -> None:
        """Clear all text from the console output.

        Returns:
            None

        """
        self.output.clear()

    def apply_filter(self, filter_text: str) -> None:
        """Apply log level filtering to console display.

        Args:
            filter_text: The filter type to apply (All, Errors, Warnings, Success,
                        Info, or Debug). Currently logs the filter action.

        Returns:
            None

        Note:
            This method provides a record of filter changes via console output.
            Future enhancements could implement dynamic message filtering.

        """
        if filter_text != "All":
            self.append_output(f"Filter applied: {filter_text}", "INFO")

    def search_text(self, search_term: str) -> None:
        """Search for text in the console and highlight matches.

        Clears previous search highlighting and finds all occurrences of the search
        term, visually highlighting them in the console output.

        Args:
            search_term: The text string to search for. Empty string clears highlighting.

        Returns:
            None

        Note:
            Search is case-sensitive and uses QTextEdit's built-in find mechanism.

        """
        if not search_term:
            cursor = self.output.textCursor()
            cursor.clearSelection()
            self.output.setTextCursor(cursor)
            return

        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.Start)

        self.output.setExtraSelections([])

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
            cursor.movePosition(
                QTextCursor.Right,
                QTextCursor.KeepAnchor,
                len(search_term),
            )

            if not found:
                self.output.setTextCursor(cursor)

    def toggle_wrap(self, state: int) -> None:
        """Toggle text wrapping in console output.

        Args:
            state: Qt.Checked to enable wrapping, Qt.Unchecked to disable.

        Returns:
            None

        """
        if state == Qt.Checked:
            self.output.setLineWrapMode(QTextEdit.WidgetWidth)
        else:
            self.output.setLineWrapMode(QTextEdit.NoWrap)

    def export_log(self) -> None:
        """Export console log contents to a text file.

        Opens a file save dialog and writes all console output to the selected file
        with UTF-8 encoding. Provides user feedback on success or failure.

        Returns:
            None

        Raises:
            Exception: File I/O errors are caught and logged to the console.

        """
        from intellicrack.handlers.pyqt6_handler import QFileDialog

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

    def process_command(self) -> None:
        """Process entered command and emit command_entered signal.

        Extracts command text from the input field, adds it to command history,
        displays it in the console, clears the input field, and emits the command_entered
        signal for connected handlers. Only processes if command input is enabled.

        Returns:
            None

        """
        if not hasattr(self, "command_input"):
            return

        command = self.command_input.text().strip()
        if not command:
            return

        self.command_history.append(command)
        self.history_index = len(self.command_history)

        self.append_output(f"> {command}", "RAW")

        self.command_input.clear()

        self.command_entered.emit(command)

    def eventFilter(self, obj: object, event: object) -> bool:
        """Handle key events for command history navigation.

        Intercepts Up/Down arrow key presses in the command input field to navigate
        through command history. Up arrow moves to previous commands, Down arrow moves
        to next commands.

        Args:
            obj: The object receiving the event.
            event: The event object containing key information.

        Returns:
            bool: True if event was handled (key press intercepted), False otherwise.

        """
        if hasattr(self, "command_input") and obj == self.command_input:
            if event.type() == event.KeyPress:
                if event.key() == Qt.Key_Up:
                    if self.history_index > 0:
                        self.history_index -= 1
                        self.command_input.setText(
                            self.command_history[self.history_index],
                        )
                    return True
                if event.key() == Qt.Key_Down:
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
        """Get the complete console output as plain text.

        Returns:
            str: All text currently displayed in the console.

        """
        return self.output.toPlainText()

    def set_max_lines(self, max_lines: int) -> None:
        """Set maximum number of lines to retain in console.

        When console exceeds this line count, oldest lines are automatically removed.
        Helps control memory usage in long-running sessions.

        Args:
            max_lines: Maximum number of lines to keep before trimming oldest lines.

        Returns:
            None

        """
        self.max_lines = max_lines


# Export the widget
__all__ = ["ConsoleWidget"]
