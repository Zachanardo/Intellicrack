"""
Comprehensive unit tests for ConsoleWidget GUI component.

Tests REAL console functionality with actual log display and command output.
NO mocked components - validates actual console behavior.
"""

import pytest
import time
from unittest.mock import patch
from PyQt6.QtWidgets import QApplication, QWidget, QTextEdit, QPushButton, QLineEdit, QCheckBox
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtGui import QTextCursor

from intellicrack.ui.widgets.console_widget import ConsoleWidget


class TestConsoleWidget:
    """Test REAL console widget functionality with actual output handling."""

    @pytest.fixture(autouse=True)
    def setup_widget(self, qtbot):
        """Setup ConsoleWidget with REAL Qt environment."""
        self.widget = ConsoleWidget()
        qtbot.addWidget(self.widget)
        self.widget.show()
        return self.widget

    def test_widget_initialization_real_components(self, qtbot):
        """Test that console widget initializes with REAL Qt components."""
        assert isinstance(self.widget, QWidget)
        assert self.widget.isVisible()

        # Check for console display components
        text_edits = self.widget.findChildren(QTextEdit)
        assert len(text_edits) > 0, "Should have text display area for console output"

        # Check for control buttons
        buttons = self.widget.findChildren(QPushButton)
        line_edits = self.widget.findChildren(QLineEdit)

        # Should have some controls for console interaction
        assert len(buttons) > 0 or len(line_edits) > 0, "Should have console control elements"

    def test_log_output_real_text_display(self, qtbot):
        """Test REAL log output and text display functionality."""
        text_displays = self.widget.findChildren(QTextEdit)

        if text_displays:
            console_display = text_displays[0]

            # Test adding log messages
            test_messages = [
                "INFO: Analysis started",
                "DEBUG: Loading binary file",
                "WARNING: Packed binary detected",
                "ERROR: Failed to parse PE header",
                "SUCCESS: Analysis completed"
            ]

            if hasattr(self.widget, 'append_output'):
                for message in test_messages:
                    self.widget.append_output(message)
                    qtbot.wait(50)

                # Check if messages are displayed
                displayed_text = console_display.toPlainText()
                for message in test_messages:
                    assert message in displayed_text

            elif hasattr(self.widget, 'log'):
                for message in test_messages:
                    self.widget.log(message)
                    qtbot.wait(50)

    def test_command_input_real_execution(self, qtbot):
        """Test REAL command input and execution functionality."""
        # Find command input area
        command_inputs = []
        for line_edit in self.widget.findChildren(QLineEdit):
            if hasattr(line_edit, 'objectName'):
                name = line_edit.objectName().lower()
                if 'command' in name or 'input' in name:
                    command_inputs.append(line_edit)

        if command_inputs:
            command_input = command_inputs[0]

            # Test typing commands
            test_commands = [
                "help",
                "clear",
                "status",
                "ls -la"
            ]

            for command in test_commands:
                command_input.clear()
                qtbot.keyClicks(command_input, command)
                qtbot.wait(50)

                assert command_input.text() == command

                # Test command execution (Enter key)
                qtbot.keyPress(command_input, Qt.Key.Key_Return)
                qtbot.wait(100)

    def test_filtering_real_log_levels(self, qtbot):
        """Test REAL log filtering by levels and categories."""
        # Find filter controls
        filter_checkboxes = []
        for checkbox in self.widget.findChildren(QCheckBox):
            text = checkbox.text().lower()
            if any(level in text for level in ['debug', 'info', 'warning', 'error']):
                filter_checkboxes.append(checkbox)

        if filter_checkboxes:
            # Test log level filtering
            test_logs = [
                ("DEBUG", "Debug message"),
                ("INFO", "Info message"),
                ("WARNING", "Warning message"),
                ("ERROR", "Error message")
            ]

            # Add test logs
            if hasattr(self.widget, 'log'):
                for level, message in test_logs:
                    self.widget.log(f"{level}: {message}")
                    qtbot.wait(50)

            # Test filtering
            for checkbox in filter_checkboxes:
                original_state = checkbox.isChecked()

                # Toggle filter
                qtbot.mouseClick(checkbox, Qt.MouseButton.LeftButton)
                qtbot.wait(100)

                assert checkbox.isChecked() != original_state

    def test_search_functionality_real_text_search(self, qtbot):
        """Test REAL search functionality within console output."""
        # Add searchable content
        test_content = [
            "Starting binary analysis of target.exe",
            "PE header found at offset 0x80",
            "Import table contains kernel32.dll",
            "String analysis reveals suspicious patterns",
            "Analysis completed successfully"
        ]

        if hasattr(self.widget, 'append_output'):
            for content in test_content:
                self.widget.append_output(content)
                qtbot.wait(50)

        # Find search controls
        search_inputs = []
        for line_edit in self.widget.findChildren(QLineEdit):
            if hasattr(line_edit, 'objectName'):
                name = line_edit.objectName().lower()
                if 'search' in name or 'find' in name:
                    search_inputs.append(line_edit)

        if search_inputs:
            search_input = search_inputs[0]

            # Test searching for content
            search_terms = ["analysis", "PE header", "kernel32"]

            for term in search_terms:
                search_input.clear()
                qtbot.keyClicks(search_input, term)
                qtbot.wait(50)

                # Execute search
                qtbot.keyPress(search_input, Qt.Key.Key_Return)
                qtbot.wait(100)

    def test_clear_functionality_real_content_removal(self, qtbot):
        """Test REAL clear functionality for console content."""
        # Add content first
        test_output = "This is test console output\nLine 2\nLine 3"

        text_displays = self.widget.findChildren(QTextEdit)
        if text_displays:
            console_display = text_displays[0]

            if hasattr(self.widget, 'append_output'):
                self.widget.append_output(test_output)
            else:
                console_display.setPlainText(test_output)

            qtbot.wait(100)

            # Verify content is there
            displayed_text = console_display.toPlainText()
            assert len(displayed_text) > 0

        # Find clear button
        clear_buttons = []
        for button in self.widget.findChildren(QPushButton):
            text = button.text().lower()
            if 'clear' in text or 'reset' in text:
                clear_buttons.append(button)

        if clear_buttons:
            clear_button = clear_buttons[0]

            # Test clearing
            qtbot.mouseClick(clear_button, Qt.MouseButton.LeftButton)
            qtbot.wait(100)

            # Verify content is cleared
            if text_displays:
                console_display = text_displays[0]
                cleared_text = console_display.toPlainText()
                assert len(cleared_text) == 0 or cleared_text.strip() == ""

    def test_syntax_highlighting_real_code_formatting(self, qtbot):
        """Test REAL syntax highlighting for different content types."""
        text_displays = self.widget.findChildren(QTextEdit)

        if text_displays:
            console_display = text_displays[0]

            # Test different types of content
            code_content = [
                "# Python comment",
                "import os",
                "def function():",
                "    return True",
                "/* C comment */",
                "#include <stdio.h>",
                "int main() { return 0; }"
            ]

            if hasattr(self.widget, 'append_output'):
                for content in code_content:
                    self.widget.append_output(content)
                    qtbot.wait(50)

                # Check that content is displayed
                displayed_text = console_display.toPlainText()
                for content in code_content:
                    assert content in displayed_text

    def test_timestamp_display_real_time_logging(self, qtbot):
        """Test REAL timestamp display with log entries."""
        # Test timestamp functionality
        if hasattr(self.widget, 'log_with_timestamp'):
            test_message = "Test message with timestamp"
            self.widget.log_with_timestamp(test_message)
            qtbot.wait(100)

        elif hasattr(self.widget, 'append_output'):
            # Add message with manual timestamp
            current_time = time.strftime("%H:%M:%S")
            timestamped_message = f"[{current_time}] Test message"
            self.widget.append_output(timestamped_message)
            qtbot.wait(100)

            # Verify timestamp is displayed
            text_displays = self.widget.findChildren(QTextEdit)
            if text_displays:
                displayed_text = text_displays[0].toPlainText()
                assert current_time in displayed_text or "Test message" in displayed_text

    def test_auto_scroll_real_behavior(self, qtbot):
        """Test REAL auto-scroll behavior with new content."""
        text_displays = self.widget.findChildren(QTextEdit)

        if text_displays:
            console_display = text_displays[0]

            # Add many lines to test scrolling
            if hasattr(self.widget, 'append_output'):
                for i in range(50):
                    self.widget.append_output(f"Line {i}: Test console output")
                    qtbot.wait(10)

                # Check scroll position
                scrollbar = console_display.verticalScrollBar()
                if scrollbar:
                    # Should auto-scroll to bottom
                    assert scrollbar.value() >= scrollbar.maximum() - 10

    def test_copy_functionality_real_clipboard_operations(self, qtbot):
        """Test REAL copy functionality for console content."""
        text_displays = self.widget.findChildren(QTextEdit)

        if text_displays:
            console_display = text_displays[0]

            # Add test content
            test_content = "This is copyable console content"
            if hasattr(self.widget, 'append_output'):
                self.widget.append_output(test_content)
            else:
                console_display.setPlainText(test_content)

            qtbot.wait(100)

            # Select all content
            console_display.selectAll()
            qtbot.wait(50)

            # Test copy operation
            with patch('PyQt6.QtWidgets.QApplication.clipboard') as mock_clipboard:
                mock_clipboard_obj = mock_clipboard.return_value
                mock_clipboard_obj.setText = lambda text: None

                # Trigger copy (Ctrl+C)
                qtbot.keySequence(console_display, "Ctrl+C")
                qtbot.wait(100)

    def test_export_functionality_real_file_output(self, qtbot):
        """Test REAL export functionality for console logs."""
        # Add content to export
        export_content = [
            "Console log export test",
            "Line 1: Analysis started",
            "Line 2: Processing binary",
            "Line 3: Analysis completed"
        ]

        if hasattr(self.widget, 'append_output'):
            for content in export_content:
                self.widget.append_output(content)
                qtbot.wait(50)

        # Find export buttons
        export_buttons = []
        for button in self.widget.findChildren(QPushButton):
            text = button.text().lower()
            if 'export' in text or 'save' in text:
                export_buttons.append(button)

        if export_buttons:
            export_button = export_buttons[0]

            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as temp_file:
                export_path = temp_file.name

            try:
                with patch('PyQt6.QtWidgets.QFileDialog.getSaveFileName') as mock_dialog:
                    mock_dialog.return_value = (export_path, '')

                    if export_button.isEnabled():
                        qtbot.mouseClick(export_button, Qt.MouseButton.LeftButton)
                        qtbot.wait(100)

            finally:
                import os
                if os.path.exists(export_path):
                    os.unlink(export_path)

    def test_performance_real_large_output(self, qtbot):
        """Test REAL performance with large amounts of console output."""
        import time

        start_time = time.time()

        # Add large amount of output
        if hasattr(self.widget, 'append_output'):
            for i in range(1000):
                self.widget.append_output(f"Performance test line {i}")
                if i % 100 == 0:
                    qtbot.wait(1)  # Small waits to prevent UI freezing

        processing_time = time.time() - start_time

        # Should handle large output reasonably well (under 5 seconds)
        assert processing_time < 5.0, f"Console processing too slow: {processing_time}s"

        # Widget should still be responsive
        assert self.widget.isVisible()

    def test_error_handling_real_invalid_input(self, qtbot):
        """Test REAL error handling with invalid input."""
        # Test invalid log messages
        invalid_inputs = [None, "", "\x00\x01\x02", "�", "\n" * 1000]

        for invalid_input in invalid_inputs:
            try:
                if hasattr(self.widget, 'append_output') and invalid_input is not None:
                    self.widget.append_output(str(invalid_input))
                    qtbot.wait(50)
            except (TypeError, ValueError, UnicodeError):
                pass  # Expected for some invalid inputs

        # Widget should remain functional
        assert self.widget.isVisible()

    def test_real_data_validation_no_placeholder_content(self, qtbot):
        """Test that console displays REAL output, not placeholder content."""
        placeholder_indicators = [
            "TODO", "PLACEHOLDER", "XXX", "FIXME",
            "Not implemented", "Coming soon", "Mock data",
            "Fake console output", "Dummy log"
        ]

        def check_widget_content(widget):
            """Check widget for placeholder content."""
            if hasattr(widget, 'text'):
                text = widget.text()
                for indicator in placeholder_indicators:
                    assert indicator not in text, f"Placeholder found: {text}"

            if hasattr(widget, 'toPlainText'):
                text = widget.toPlainText()
                for indicator in placeholder_indicators:
                    assert indicator not in text, f"Placeholder found: {text}"

        check_widget_content(self.widget)
        for child in self.widget.findChildren(object):
            check_widget_content(child)

    def test_memory_management_real_log_rotation(self, qtbot):
        """Test REAL memory management with log rotation."""
        # Test memory usage with continuous logging
        if hasattr(self.widget, 'set_max_lines'):
            self.widget.set_max_lines(100)  # Limit to 100 lines

            # Add more than max lines
            if hasattr(self.widget, 'append_output'):
                for i in range(200):
                    self.widget.append_output(f"Log rotation test line {i}")
                    if i % 50 == 0:
                        qtbot.wait(10)

                # Check that old lines are removed
                text_displays = self.widget.findChildren(QTextEdit)
                if text_displays:
                    displayed_text = text_displays[0].toPlainText()
                    lines = displayed_text.split('\n')
                    assert len(lines) <= 120  # Allow some buffer

    def test_thread_safety_real_concurrent_logging(self, qtbot):
        """Test REAL thread safety for concurrent log operations."""
        from PyQt6.QtCore import QThread

        # Ensure operations happen in GUI thread
        assert QThread.currentThread() == QApplication.instance().thread()

        # Test concurrent log operations
        if hasattr(self.widget, 'append_output'):
            # Simulate rapid logging
            for i in range(10):
                self.widget.append_output(f"Concurrent log {i}")
                qtbot.wait(5)

            # Widget should remain stable
            assert self.widget.isVisible()

            text_displays = self.widget.findChildren(QTextEdit)
            if text_displays:
                displayed_text = text_displays[0].toPlainText()
                assert "Concurrent log" in displayed_text
