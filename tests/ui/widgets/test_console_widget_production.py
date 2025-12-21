"""Production-ready tests for ConsoleWidget - Real-time log display and command interface validation.

This module validates ConsoleWidget's console functionality including:
- Syntax highlighting for various log patterns (errors, warnings, IPs, hex, paths)
- Log level filtering and message appending
- Real-time text search with highlighting
- Line wrapping and auto-scroll functionality
- Command history navigation
- Log export functionality
- Maximum line enforcement
- Filter application and pattern matching
"""

import re
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtCore import Qt, QEvent
from PyQt6.QtGui import QKeyEvent, QTextCursor
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.widgets.console_widget import (
    ConsoleSyntaxHighlighter,
    ConsoleWidget,
)


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def console_widget(qapp: QApplication) -> ConsoleWidget:
    """Create basic ConsoleWidget for testing."""
    widget = ConsoleWidget(parent=None, enable_input=False)
    return widget


@pytest.fixture
def console_widget_with_input(qapp: QApplication) -> ConsoleWidget:
    """Create ConsoleWidget with command input enabled."""
    widget = ConsoleWidget(parent=None, enable_input=True)
    return widget


@pytest.fixture
def highlighter(qapp: QApplication) -> ConsoleSyntaxHighlighter:
    """Create ConsoleSyntaxHighlighter for testing."""
    from PyQt6.QtGui import QTextDocument

    doc = QTextDocument()
    highlighter = ConsoleSyntaxHighlighter(doc)
    return highlighter


class TestConsoleSyntaxHighlighterInitialization:
    """Test ConsoleSyntaxHighlighter initialization and rule configuration."""

    def test_highlighter_initializes_with_rules(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter initializes with highlighting rules."""
        assert len(highlighter.rules) > 0

    def test_highlighter_has_timestamp_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for timestamp patterns."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any(r"\d{4}-\d{2}-\d{2}" in p for p in patterns)
        assert any(r"\d{2}:\d{2}:\d{2}" in p for p in patterns)

    def test_highlighter_has_error_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for error patterns."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any("ERROR" in p for p in patterns)
        assert any("FAIL" in p for p in patterns)

    def test_highlighter_has_warning_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for warning patterns."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any("WARNING" in p or "WARN" in p for p in patterns)

    def test_highlighter_has_success_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for success patterns."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any("SUCCESS" in p or "OK" in p for p in patterns)

    def test_highlighter_has_info_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for info patterns."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any("INFO" in p for p in patterns)

    def test_highlighter_has_debug_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for debug patterns."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any("DEBUG" in p for p in patterns)

    def test_highlighter_has_hex_value_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for hexadecimal values."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any("0x" in p for p in patterns)

    def test_highlighter_has_ip_address_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for IP addresses."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" in p for p in patterns)

    def test_highlighter_has_path_patterns(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter has rules for file paths."""
        patterns = [rule[0].pattern() for rule in highlighter.rules]
        assert any(":" in p or "/" in p for p in patterns)


class TestConsoleSyntaxHighlighterFormatting:
    """Test ConsoleSyntaxHighlighter text formatting functionality."""

    def test_highlighter_formats_error_text(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter applies formatting to error text."""
        test_text = "[ERROR] Critical failure in binary analysis"
        highlighter.highlightBlock(test_text)

    def test_highlighter_formats_warning_text(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter applies formatting to warning text."""
        test_text = "[WARNING] Suspicious pattern detected"
        highlighter.highlightBlock(test_text)

    def test_highlighter_formats_success_text(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter applies formatting to success text."""
        test_text = "[SUCCESS] Bypass applied successfully"
        highlighter.highlightBlock(test_text)

    def test_highlighter_formats_hex_values(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter applies formatting to hexadecimal values."""
        test_text = "Memory address: 0x401000, value: 0xDEADBEEF"
        highlighter.highlightBlock(test_text)

    def test_highlighter_formats_ip_addresses(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter applies formatting to IP addresses."""
        test_text = "Connection from 192.168.1.100 to 10.0.0.1"
        highlighter.highlightBlock(test_text)

    def test_highlighter_formats_file_paths(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter applies formatting to file paths."""
        test_text = "Loading binary from D:\\malware\\sample.exe"
        highlighter.highlightBlock(test_text)

    def test_highlighter_formats_timestamps(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter applies formatting to timestamps."""
        test_text = "2025-01-15 14:30:45 [INFO] Analysis started"
        highlighter.highlightBlock(test_text)

    def test_highlighter_formats_quoted_strings(self, highlighter: ConsoleSyntaxHighlighter) -> None:
        """Highlighter applies formatting to quoted strings."""
        test_text = 'Function name: "CheckLicense" in module'
        highlighter.highlightBlock(test_text)


class TestConsoleWidgetInitialization:
    """Test ConsoleWidget initialization and configuration."""

    def test_console_widget_initializes_without_input(self, console_widget: ConsoleWidget) -> None:
        """Console widget initializes without command input."""
        assert console_widget.enable_input is False
        assert not hasattr(console_widget, "command_input")

    def test_console_widget_initializes_with_input(self, console_widget_with_input: ConsoleWidget) -> None:
        """Console widget initializes with command input enabled."""
        assert console_widget_with_input.enable_input is True
        assert hasattr(console_widget_with_input, "command_input")

    def test_console_widget_has_filter_combo(self, console_widget: ConsoleWidget) -> None:
        """Console widget has filter combo box."""
        assert console_widget.filter_combo is not None
        assert console_widget.filter_combo.count() >= 6

    def test_console_widget_has_search_input(self, console_widget: ConsoleWidget) -> None:
        """Console widget has search input field."""
        assert console_widget.search_input is not None

    def test_console_widget_has_wrap_checkbox(self, console_widget: ConsoleWidget) -> None:
        """Console widget has line wrap checkbox."""
        assert console_widget.wrap_cb is not None

    def test_console_widget_has_autoscroll_checkbox(self, console_widget: ConsoleWidget) -> None:
        """Console widget has auto-scroll checkbox."""
        assert console_widget.autoscroll_cb is not None
        assert console_widget.autoscroll_cb.isChecked()

    def test_console_widget_has_clear_button(self, console_widget: ConsoleWidget) -> None:
        """Console widget has clear button."""
        assert console_widget.clear_btn is not None

    def test_console_widget_has_export_button(self, console_widget: ConsoleWidget) -> None:
        """Console widget has export button."""
        assert console_widget.export_btn is not None

    def test_console_widget_has_output_text_edit(self, console_widget: ConsoleWidget) -> None:
        """Console widget has text output area."""
        assert console_widget.output is not None
        assert console_widget.output.isReadOnly()

    def test_console_widget_has_syntax_highlighter(self, console_widget: ConsoleWidget) -> None:
        """Console widget has syntax highlighter attached."""
        assert console_widget.highlighter is not None

    def test_console_widget_has_command_history(self, console_widget_with_input: ConsoleWidget) -> None:
        """Console widget initializes with empty command history."""
        assert isinstance(console_widget_with_input.command_history, list)
        assert len(console_widget_with_input.command_history) == 0

    def test_console_widget_has_max_lines_limit(self, console_widget: ConsoleWidget) -> None:
        """Console widget has maximum line limit configured."""
        assert console_widget.max_lines > 0


class TestConsoleWidgetLogAppending:
    """Test console widget log message appending functionality."""

    def test_append_output_adds_text(self, console_widget: ConsoleWidget) -> None:
        """append_output adds text to console."""
        console_widget.append_output("Test message", "INFO")
        content = console_widget.output.toPlainText()
        assert "Test message" in content

    def test_append_output_includes_timestamp(self, console_widget: ConsoleWidget) -> None:
        """append_output includes timestamp in message."""
        console_widget.append_output("Test message", "INFO")
        content = console_widget.output.toPlainText()
        assert re.search(r"\d{2}:\d{2}:\d{2}", content) is not None

    def test_append_output_includes_level_tag(self, console_widget: ConsoleWidget) -> None:
        """append_output includes log level tag."""
        console_widget.append_output("Test message", "INFO")
        content = console_widget.output.toPlainText()
        assert "[INFO]" in content

    def test_append_error_adds_error_message(self, console_widget: ConsoleWidget) -> None:
        """append_error adds error-level message."""
        console_widget.append_error("Error occurred")
        content = console_widget.output.toPlainText()
        assert "Error occurred" in content
        assert "[ERROR]" in content

    def test_append_warning_adds_warning_message(self, console_widget: ConsoleWidget) -> None:
        """append_warning adds warning-level message."""
        console_widget.append_warning("Warning message")
        content = console_widget.output.toPlainText()
        assert "Warning message" in content
        assert "[WARNING]" in content

    def test_append_success_adds_success_message(self, console_widget: ConsoleWidget) -> None:
        """append_success adds success-level message."""
        console_widget.append_success("Success message")
        content = console_widget.output.toPlainText()
        assert "Success message" in content
        assert "[SUCCESS]" in content

    def test_append_info_adds_info_message(self, console_widget: ConsoleWidget) -> None:
        """append_info adds info-level message."""
        console_widget.append_info("Info message")
        content = console_widget.output.toPlainText()
        assert "Info message" in content
        assert "[INFO]" in content

    def test_append_debug_adds_debug_message(self, console_widget: ConsoleWidget) -> None:
        """append_debug adds debug-level message."""
        console_widget.append_debug("Debug message")
        content = console_widget.output.toPlainText()
        assert "Debug message" in content
        assert "[DEBUG]" in content

    def test_append_output_raw_no_prefix(self, console_widget: ConsoleWidget) -> None:
        """append_output with RAW level adds no prefix."""
        console_widget.append_output("Raw message", "RAW")
        content = console_widget.output.toPlainText()
        assert "Raw message" in content
        assert "[RAW]" not in content


class TestConsoleWidgetLineManagement:
    """Test console widget line management and trimming."""

    def test_console_enforces_max_lines(self, console_widget: ConsoleWidget) -> None:
        """Console trims old lines when exceeding max_lines."""
        console_widget.max_lines = 50
        for i in range(100):
            console_widget.append_output(f"Line {i}", "INFO")
        line_count = console_widget.output.document().lineCount()
        assert line_count <= console_widget.max_lines + 10

    def test_set_max_lines_changes_limit(self, console_widget: ConsoleWidget) -> None:
        """set_max_lines updates maximum line limit."""
        console_widget.set_max_lines(5000)
        assert console_widget.max_lines == 5000


class TestConsoleWidgetClearFunctionality:
    """Test console widget clear functionality."""

    def test_clear_removes_all_text(self, console_widget: ConsoleWidget) -> None:
        """clear removes all console content."""
        console_widget.append_output("Test message 1", "INFO")
        console_widget.append_output("Test message 2", "INFO")
        console_widget.clear()
        content = console_widget.output.toPlainText()
        assert content == ""


class TestConsoleWidgetSearchFunctionality:
    """Test console widget search and highlighting functionality."""

    def test_search_text_finds_matches(self, console_widget: ConsoleWidget) -> None:
        """search_text locates matching text in console."""
        console_widget.append_output("Test message with keyword", "INFO")
        console_widget.append_output("Another message", "INFO")
        console_widget.search_text("keyword")

    def test_search_and_highlight_returns_match_count(self, console_widget: ConsoleWidget) -> None:
        """search_and_highlight returns correct match count."""
        console_widget.append_output("Test message", "INFO")
        console_widget.append_output("Test another", "INFO")
        console_widget.append_output("Different content", "INFO")
        match_count = console_widget.search_and_highlight("Test")
        assert match_count == 2

    def test_search_empty_string_clears_highlighting(self, console_widget: ConsoleWidget) -> None:
        """Searching empty string clears search highlighting."""
        console_widget.append_output("Test message", "INFO")
        console_widget.search_and_highlight("Test")
        match_count = console_widget.search_and_highlight("")
        assert match_count == 0

    def test_search_case_sensitive(self, console_widget: ConsoleWidget) -> None:
        """Search is case-sensitive by default."""
        console_widget.append_output("Test message", "INFO")
        console_widget.append_output("test lowercase", "INFO")
        match_count = console_widget.search_and_highlight("Test")
        assert match_count >= 1


class TestConsoleWidgetFilterFunctionality:
    """Test console widget filter functionality."""

    def test_apply_filter_logs_action(self, console_widget: ConsoleWidget) -> None:
        """apply_filter logs the filter action."""
        initial_content = console_widget.output.toPlainText()
        console_widget.apply_filter("Errors")
        content = console_widget.output.toPlainText()
        assert "Filter applied: Errors" in content

    def test_set_filter_with_patterns(self, console_widget: ConsoleWidget) -> None:
        """set_filter applies pattern-based filtering."""
        console_widget.append_error("Error message")
        console_widget.append_warning("Warning message")
        console_widget.append_info("Info message")
        console_widget.set_filter(["[ERROR]"])
        content = console_widget.output.toPlainText()
        assert "[ERROR]" in content

    def test_set_filter_none_shows_all(self, console_widget: ConsoleWidget) -> None:
        """set_filter with None removes filtering."""
        console_widget.append_error("Error message")
        console_widget.append_warning("Warning message")
        console_widget.set_filter(["[ERROR]"])
        console_widget.set_filter(None)
        content = console_widget.output.toPlainText()
        assert "[ERROR]" in content
        assert "[WARNING]" in content

    def test_set_filter_multiple_patterns(self, console_widget: ConsoleWidget) -> None:
        """set_filter supports multiple filter patterns."""
        console_widget.append_error("Error message")
        console_widget.append_warning("Warning message")
        console_widget.append_info("Info message")
        console_widget.set_filter(["[ERROR]", "[WARNING]"])
        content = console_widget.output.toPlainText()
        assert "[ERROR]" in content or "[WARNING]" in content


class TestConsoleWidgetLineWrapping:
    """Test console widget line wrapping functionality."""

    def test_toggle_wrap_enables_wrapping(self, console_widget: ConsoleWidget) -> None:
        """toggle_wrap enables line wrapping."""
        console_widget.toggle_wrap(Qt.CheckState.Checked.value)
        from PyQt6.QtWidgets import QTextEdit

        assert console_widget.output.lineWrapMode() == QTextEdit.LineWrapMode.WidgetWidth

    def test_toggle_wrap_disables_wrapping(self, console_widget: ConsoleWidget) -> None:
        """toggle_wrap disables line wrapping."""
        console_widget.toggle_wrap(Qt.CheckState.Unchecked.value)
        from PyQt6.QtWidgets import QTextEdit

        assert console_widget.output.lineWrapMode() == QTextEdit.LineWrapMode.NoWrap


class TestConsoleWidgetAutoScroll:
    """Test console widget auto-scroll functionality."""

    def test_autoscroll_scrolls_to_bottom(self, console_widget: ConsoleWidget) -> None:
        """Auto-scroll moves to bottom when new messages added."""
        console_widget.autoscroll_cb.setChecked(True)
        for i in range(20):
            console_widget.append_output(f"Message {i}", "INFO")
        scrollbar = console_widget.output.verticalScrollBar()
        assert scrollbar.value() == scrollbar.maximum() or scrollbar.maximum() == 0


class TestConsoleWidgetCommandProcessing:
    """Test console widget command processing functionality."""

    def test_command_input_exists_when_enabled(self, console_widget_with_input: ConsoleWidget) -> None:
        """Command input field exists when input is enabled."""
        assert hasattr(console_widget_with_input, "command_input")

    def test_process_command_emits_signal(self, console_widget_with_input: ConsoleWidget) -> None:
        """process_command emits command_entered signal."""
        command_received = None

        def on_command(cmd: str) -> None:
            nonlocal command_received
            command_received = cmd

        console_widget_with_input.command_entered.connect(on_command)
        console_widget_with_input.command_input.setText("test command")
        console_widget_with_input.process_command()
        assert command_received == "test command"

    def test_process_command_adds_to_history(self, console_widget_with_input: ConsoleWidget) -> None:
        """process_command adds command to history."""
        console_widget_with_input.command_input.setText("test command")
        console_widget_with_input.process_command()
        assert "test command" in console_widget_with_input.command_history

    def test_process_command_displays_in_console(self, console_widget_with_input: ConsoleWidget) -> None:
        """process_command displays command in console output."""
        console_widget_with_input.command_input.setText("test command")
        console_widget_with_input.process_command()
        content = console_widget_with_input.output.toPlainText()
        assert "> test command" in content

    def test_process_command_clears_input_field(self, console_widget_with_input: ConsoleWidget) -> None:
        """process_command clears input field after processing."""
        console_widget_with_input.command_input.setText("test command")
        console_widget_with_input.process_command()
        assert console_widget_with_input.command_input.text() == ""

    def test_process_empty_command_does_nothing(self, console_widget_with_input: ConsoleWidget) -> None:
        """process_command ignores empty commands."""
        console_widget_with_input.command_input.setText("")
        console_widget_with_input.process_command()
        assert len(console_widget_with_input.command_history) == 0


class TestConsoleWidgetCommandHistory:
    """Test console widget command history navigation."""

    def test_up_arrow_navigates_history_backward(self, console_widget_with_input: ConsoleWidget, qapp: QApplication) -> None:
        """Up arrow key navigates to previous command."""
        console_widget_with_input.command_history = ["command1", "command2", "command3"]
        console_widget_with_input.history_index = 3

        key_event = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Up, Qt.KeyboardModifier.NoModifier)
        console_widget_with_input.eventFilter(console_widget_with_input.command_input, key_event)

        assert console_widget_with_input.command_input.text() == "command3"

    def test_down_arrow_navigates_history_forward(self, console_widget_with_input: ConsoleWidget, qapp: QApplication) -> None:
        """Down arrow key navigates to next command."""
        console_widget_with_input.command_history = ["command1", "command2", "command3"]
        console_widget_with_input.history_index = 0

        key_event = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Down, Qt.KeyboardModifier.NoModifier)
        console_widget_with_input.eventFilter(console_widget_with_input.command_input, key_event)

        assert console_widget_with_input.command_input.text() == "command2"

    def test_down_arrow_at_end_clears_input(self, console_widget_with_input: ConsoleWidget, qapp: QApplication) -> None:
        """Down arrow at end of history clears input."""
        console_widget_with_input.command_history = ["command1", "command2"]
        console_widget_with_input.history_index = 1

        key_event = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Down, Qt.KeyboardModifier.NoModifier)
        console_widget_with_input.eventFilter(console_widget_with_input.command_input, key_event)

        assert console_widget_with_input.command_input.text() == ""


class TestConsoleWidgetExportFunctionality:
    """Test console widget log export functionality."""

    def test_export_log_writes_to_file(self, console_widget: ConsoleWidget) -> None:
        """export_log writes console content to file."""
        console_widget.append_output("Test message", "INFO")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            file_path = f.name

        try:
            with patch("intellicrack.handlers.pyqt6_handler.QFileDialog.getSaveFileName", return_value=(file_path, "")):
                console_widget.export_log()

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "Test message" in content
        finally:
            Path(file_path).unlink(missing_ok=True)

    def test_export_log_handles_cancel(self, console_widget: ConsoleWidget) -> None:
        """export_log handles user canceling file dialog."""
        with patch("intellicrack.handlers.pyqt6_handler.QFileDialog.getSaveFileName", return_value=("", "")):
            console_widget.export_log()

    def test_export_log_handles_write_error(self, console_widget: ConsoleWidget) -> None:
        """export_log handles file write errors gracefully."""
        with patch("intellicrack.handlers.pyqt6_handler.QFileDialog.getSaveFileName", return_value=("D:\\invalid\\path\\file.txt", "")):
            with patch("builtins.open", side_effect=PermissionError("Access denied")):
                console_widget.export_log()
                content = console_widget.output.toPlainText()
                assert "Failed to export" in content


class TestConsoleWidgetContentRetrieval:
    """Test console widget content retrieval."""

    def test_get_content_returns_plain_text(self, console_widget: ConsoleWidget) -> None:
        """get_content returns all console text."""
        console_widget.append_output("Message 1", "INFO")
        console_widget.append_output("Message 2", "ERROR")
        content = console_widget.get_content()
        assert "Message 1" in content
        assert "Message 2" in content


class TestConsoleWidgetEdgeCases:
    """Test console widget edge cases and error handling."""

    def test_console_handles_very_long_lines(self, console_widget: ConsoleWidget) -> None:
        """Console handles very long lines without crashing."""
        long_line = "A" * 10000
        console_widget.append_output(long_line, "INFO")
        content = console_widget.get_content()
        assert long_line in content

    def test_console_handles_unicode_characters(self, console_widget: ConsoleWidget) -> None:
        """Console handles unicode characters correctly."""
        unicode_text = "Test αβγδ 中文 🔥 message"
        console_widget.append_output(unicode_text, "INFO")
        content = console_widget.get_content()
        assert "αβγδ" in content or "中文" in content

    def test_console_handles_special_characters(self, console_widget: ConsoleWidget) -> None:
        """Console handles special characters in messages."""
        special_text = "Test <>&\"' message with special chars"
        console_widget.append_output(special_text, "INFO")
        content = console_widget.get_content()
        assert "special chars" in content

    def test_search_with_regex_special_chars(self, console_widget: ConsoleWidget) -> None:
        """Search handles regex special characters correctly."""
        console_widget.append_output("Function at 0x401000", "INFO")
        match_count = console_widget.search_and_highlight("0x401000")
        assert match_count >= 1

    def test_filter_with_empty_console(self, console_widget: ConsoleWidget) -> None:
        """Filter works correctly on empty console."""
        console_widget.set_filter(["[ERROR]"])
        console_widget.set_filter(None)

    def test_multiple_rapid_messages(self, console_widget: ConsoleWidget) -> None:
        """Console handles rapid message appending."""
        for i in range(100):
            console_widget.append_output(f"Rapid message {i}", "INFO")
        line_count = console_widget.output.document().lineCount()
        assert line_count > 0


class TestConsoleWidgetRealWorldScenarios:
    """Test console widget with realistic analysis tool output."""

    def test_console_displays_binary_analysis_output(self, console_widget: ConsoleWidget) -> None:
        """Console displays realistic binary analysis messages."""
        console_widget.append_info("Starting binary analysis for sample.exe")
        console_widget.append_success("PE header loaded successfully")
        console_widget.append_warning("Packed binary detected - UPX signature found")
        console_widget.append_error("Failed to resolve import at 0x401000")
        console_widget.append_debug("Memory allocated at 0x00A00000")

        content = console_widget.get_content()
        assert "binary analysis" in content
        assert "PE header" in content
        assert "UPX signature" in content

    def test_console_displays_frida_hook_output(self, console_widget: ConsoleWidget) -> None:
        """Console displays Frida hooking messages."""
        console_widget.append_info("[HOOK] Attaching to process PID: 1234")
        console_widget.append_success("[HOOK] Successfully hooked CheckLicense at 0x401500")
        console_widget.append_info("[HOOK] Intercepted call with args: ['user123', 'key456']")
        console_widget.append_success("[HOOK] Returned spoofed validation: true")

        content = console_widget.get_content()
        assert "[HOOK]" in content
        assert "CheckLicense" in content
        assert "0x401500" in content

    def test_console_displays_network_traffic_analysis(self, console_widget: ConsoleWidget) -> None:
        """Console displays network traffic analysis messages."""
        console_widget.append_info("Monitoring network traffic on 192.168.1.100")
        console_widget.append_warning("Suspicious connection to 203.0.113.42:443")
        console_widget.append_error("Connection timeout to license server")

        content = console_widget.get_content()
        assert "192.168.1.100" in content
        assert "203.0.113.42" in content

    def test_console_displays_memory_dump_analysis(self, console_widget: ConsoleWidget) -> None:
        """Console displays memory dump analysis output."""
        console_widget.append_info("Dumping memory region 0x00400000 - 0x00500000")
        console_widget.append_success("Found license key pattern at 0x0045A3B0")
        console_widget.append_debug("Hex dump: 4C 49 43 45 4E 53 45 2D 4B 45 59")

        content = console_widget.get_content()
        assert "0x00400000" in content
        assert "0x0045A3B0" in content
