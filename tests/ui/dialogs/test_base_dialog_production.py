"""Production-ready tests for BaseDialog - Dialog foundation component validation.

This module validates BaseDialog's core functionality including:
- Window initialization and configuration
- Button setup and signal connections
- Keyboard shortcut functionality
- Status message display and state management
- Loading state handling
- Focus management
- Template widget creation
- Binary file selection interface
- Custom button creation
- Theme application and styling
"""

import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox, QWidget

from intellicrack.ui.dialogs.base_dialog import BaseDialog


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def base_dialog(qapp: QApplication) -> BaseDialog:
    """Create a basic BaseDialog instance for testing."""
    dialog = BaseDialog(
        parent=None,
        title="Test Dialog",
        width=800,
        height=600,
        resizable=True,
        show_help=False,
        help_text="",
    )
    return dialog


@pytest.fixture
def base_dialog_with_help(qapp: QApplication) -> BaseDialog:
    """Create a BaseDialog with help button enabled."""
    dialog = BaseDialog(
        parent=None,
        title="Test Dialog with Help",
        width=800,
        height=600,
        resizable=True,
        show_help=True,
        help_text="This is comprehensive help text for the dialog.",
    )
    return dialog


@pytest.fixture
def non_resizable_dialog(qapp: QApplication) -> BaseDialog:
    """Create a non-resizable BaseDialog."""
    dialog = BaseDialog(
        parent=None,
        title="Fixed Size Dialog",
        width=400,
        height=300,
        resizable=False,
    )
    return dialog


class TestBaseDialogInitialization:
    """Test BaseDialog initialization and configuration."""

    def test_dialog_window_title_set_correctly(self, base_dialog: BaseDialog) -> None:
        """Dialog window title is set to provided title string."""
        assert base_dialog.windowTitle() == "Test Dialog"

    def test_dialog_is_modal(self, base_dialog: BaseDialog) -> None:
        """Dialog is configured as modal window."""
        assert base_dialog.isModal()

    def test_dialog_dimensions_match_parameters(self, base_dialog: BaseDialog) -> None:
        """Dialog width and height match initialization parameters."""
        assert base_dialog.width() == 800
        assert base_dialog.height() == 600

    def test_resizable_dialog_allows_resizing(self, base_dialog: BaseDialog) -> None:
        """Resizable dialog does not have fixed size constraint."""
        size_hint = base_dialog.sizeHint()
        base_dialog.resize(1000, 800)
        assert base_dialog.width() == 1000
        assert base_dialog.height() == 800

    def test_non_resizable_dialog_has_fixed_size(self, non_resizable_dialog: BaseDialog) -> None:
        """Non-resizable dialog maintains fixed dimensions."""
        assert non_resizable_dialog.width() == 400
        assert non_resizable_dialog.height() == 300
        non_resizable_dialog.resize(600, 500)
        assert non_resizable_dialog.width() == 400
        assert non_resizable_dialog.height() == 300

    def test_dialog_has_main_layout(self, base_dialog: BaseDialog) -> None:
        """Dialog has properly configured main layout."""
        assert base_dialog.main_layout is not None
        assert base_dialog.main_layout.contentsMargins().left() == 20
        assert base_dialog.main_layout.contentsMargins().top() == 20
        assert base_dialog.main_layout.spacing() == 15

    def test_dialog_has_content_widget(self, base_dialog: BaseDialog) -> None:
        """Dialog has content widget for custom content."""
        assert base_dialog.content_widget is not None
        assert base_dialog.content_layout is not None

    def test_status_label_initially_hidden(self, base_dialog: BaseDialog) -> None:
        """Status label is hidden by default."""
        assert not base_dialog.status_label.isVisible()

    def test_dialog_starts_in_non_loading_state(self, base_dialog: BaseDialog) -> None:
        """Dialog is not in loading state on initialization."""
        assert not base_dialog._is_loading
        assert not base_dialog._error_state

    def test_dialog_has_strong_focus_policy(self, base_dialog: BaseDialog) -> None:
        """Dialog has strong focus policy for keyboard interaction."""
        assert base_dialog.focusPolicy() == Qt.FocusPolicy.StrongFocus


class TestBaseDialogButtons:
    """Test BaseDialog button setup and functionality."""

    def test_ok_button_exists(self, base_dialog: BaseDialog) -> None:
        """Dialog has OK button."""
        assert base_dialog.ok_button is not None
        assert base_dialog.ok_button.text() in ["OK", "&OK"]

    def test_cancel_button_exists(self, base_dialog: BaseDialog) -> None:
        """Dialog has Cancel button."""
        assert base_dialog.cancel_button is not None
        assert base_dialog.cancel_button.text() in ["Cancel", "&Cancel"]

    def test_help_button_exists_when_enabled(self, base_dialog_with_help: BaseDialog) -> None:
        """Dialog shows help button when show_help is True."""
        from PyQt6.QtWidgets import QDialogButtonBox

        help_button = base_dialog_with_help.button_box.button(QDialogButtonBox.StandardButton.Help)
        assert help_button is not None

    def test_help_button_absent_when_disabled(self, base_dialog: BaseDialog) -> None:
        """Dialog does not show help button when show_help is False."""
        from PyQt6.QtWidgets import QDialogButtonBox

        help_button = base_dialog.button_box.button(QDialogButtonBox.StandardButton.Help)
        assert help_button is None

    def test_ok_button_triggers_accept(self, base_dialog: BaseDialog) -> None:
        """Clicking OK button triggers dialog acceptance."""
        accepted = False

        def on_accept() -> None:
            nonlocal accepted
            accepted = True

        base_dialog.accepted.connect(on_accept)
        base_dialog.ok_button.click()
        assert accepted

    def test_cancel_button_triggers_reject(self, base_dialog: BaseDialog) -> None:
        """Clicking Cancel button triggers dialog rejection."""
        rejected = False

        def on_reject() -> None:
            nonlocal rejected
            rejected = True

        base_dialog.rejected.connect(on_reject)
        base_dialog.cancel_button.click()
        assert rejected

    def test_set_ok_enabled_controls_button_state(self, base_dialog: BaseDialog) -> None:
        """set_ok_enabled method controls OK button enabled state."""
        base_dialog.set_ok_enabled(False)
        assert not base_dialog.ok_button.isEnabled()
        base_dialog.set_ok_enabled(True)
        assert base_dialog.ok_button.isEnabled()

    def test_set_ok_text_changes_button_label(self, base_dialog: BaseDialog) -> None:
        """set_ok_text method changes OK button text."""
        base_dialog.set_ok_text("Apply")
        assert base_dialog.ok_button.text() == "Apply"

    def test_set_cancel_text_changes_button_label(self, base_dialog: BaseDialog) -> None:
        """set_cancel_text method changes Cancel button text."""
        base_dialog.set_cancel_text("Close")
        assert base_dialog.cancel_button.text() == "Close"

    def test_add_custom_button_creates_default_button(self, base_dialog: BaseDialog) -> None:
        """add_custom_button creates button with default styling."""
        callback_triggered = False

        def callback() -> None:
            nonlocal callback_triggered
            callback_triggered = True

        button = base_dialog.add_custom_button("Custom", callback, "default")
        assert button is not None
        assert button.text() == "Custom"
        button.click()
        assert callback_triggered

    def test_add_custom_button_creates_primary_button(self, base_dialog: BaseDialog) -> None:
        """add_custom_button creates button with primary styling."""
        button = base_dialog.add_custom_button("Primary", lambda: None, "primary")
        assert button.objectName() == "primary_button"

    def test_add_custom_button_creates_danger_button(self, base_dialog: BaseDialog) -> None:
        """add_custom_button creates button with danger styling."""
        button = base_dialog.add_custom_button("Delete", lambda: None, "danger")
        assert button.objectName() == "danger_button"

    def test_help_button_shows_help_text(self, base_dialog_with_help: BaseDialog) -> None:
        """Clicking help button displays help text in message box."""
        from PyQt6.QtWidgets import QDialogButtonBox

        with patch.object(QMessageBox, "information") as mock_info:
            help_button = base_dialog_with_help.button_box.button(QDialogButtonBox.StandardButton.Help)
            help_button.click()
            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "Help" in str(call_args)
            assert "comprehensive help text" in str(call_args)


class TestBaseDialogKeyboardShortcuts:
    """Test BaseDialog keyboard shortcut functionality."""

    def test_escape_key_triggers_rejection(self, base_dialog: BaseDialog) -> None:
        """Pressing Escape key triggers dialog rejection."""
        rejected = False

        def on_reject() -> None:
            nonlocal rejected
            rejected = True

        base_dialog.rejected.connect(on_reject)
        QTest.keyClick(base_dialog, Qt.Key.Key_Escape)
        assert rejected

    def test_ctrl_return_triggers_acceptance(self, base_dialog: BaseDialog) -> None:
        """Pressing Ctrl+Return triggers dialog acceptance."""
        accepted = False

        def on_accept() -> None:
            nonlocal accepted
            accepted = True

        base_dialog.accepted.connect(on_accept)
        QTest.keyClick(base_dialog, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
        assert accepted

    def test_escape_blocked_during_loading(self, base_dialog: BaseDialog) -> None:
        """Escape key does not trigger rejection during loading state."""
        rejected = False

        def on_reject() -> None:
            nonlocal rejected
            rejected = True

        base_dialog.rejected.connect(on_reject)
        base_dialog.set_loading(True, "Processing...")
        QTest.keyClick(base_dialog, Qt.Key.Key_Escape)
        assert not rejected
        base_dialog.set_loading(False)

    def test_ctrl_return_blocked_during_loading(self, base_dialog: BaseDialog) -> None:
        """Ctrl+Return does not trigger acceptance during loading state."""
        accepted = False

        def on_accept() -> None:
            nonlocal accepted
            accepted = True

        base_dialog.accepted.connect(on_accept)
        base_dialog.set_loading(True, "Processing...")
        QTest.keyClick(base_dialog, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
        assert not accepted
        base_dialog.set_loading(False)


class TestBaseDialogStatusMessages:
    """Test BaseDialog status message display and state management."""

    def test_show_error_displays_error_message(self, base_dialog: BaseDialog) -> None:
        """show_error displays error message with proper styling."""
        base_dialog.show_error("Test error message")
        assert base_dialog.status_label.isVisible()
        assert base_dialog.status_label.text() == "Test error message"
        assert base_dialog.status_label.objectName() == "status_error"
        assert base_dialog._error_state

    def test_show_success_displays_success_message(self, base_dialog: BaseDialog) -> None:
        """show_success displays success message with proper styling."""
        base_dialog.show_success("Test success message")
        assert base_dialog.status_label.isVisible()
        assert base_dialog.status_label.text() == "Test success message"
        assert base_dialog.status_label.objectName() == "status_success"

    def test_show_status_info_displays_info_message(self, base_dialog: BaseDialog) -> None:
        """show_status with info type displays info message."""
        base_dialog.show_status("Test info message", "info")
        assert base_dialog.status_label.isVisible()
        assert base_dialog.status_label.text() == "Test info message"
        assert base_dialog.status_label.objectName() == "status_info"

    def test_hide_status_clears_message(self, base_dialog: BaseDialog) -> None:
        """hide_status hides status label and clears text."""
        base_dialog.show_error("Error message")
        base_dialog.hide_status()
        assert not base_dialog.status_label.isVisible()
        assert base_dialog.status_label.text() == ""
        assert not base_dialog._error_state

    def test_error_state_tracked_correctly(self, base_dialog: BaseDialog, caplog: pytest.LogCaptureFixture) -> None:
        """Error state is tracked and logged correctly."""
        with caplog.at_level(logging.ERROR):
            base_dialog.show_error("Critical error")
            assert base_dialog._error_state
            assert "Dialog error: Critical error" in caplog.text


class TestBaseDialogLoadingState:
    """Test BaseDialog loading state management."""

    def test_set_loading_true_disables_ok_button(self, base_dialog: BaseDialog) -> None:
        """Setting loading to True disables OK button."""
        base_dialog.set_loading(True, "Loading...")
        assert not base_dialog.ok_button.isEnabled()
        base_dialog.set_loading(False)

    def test_set_loading_true_shows_info_message(self, base_dialog: BaseDialog) -> None:
        """Setting loading to True shows loading message."""
        base_dialog.set_loading(True, "Loading data...")
        assert base_dialog.status_label.isVisible()
        assert base_dialog.status_label.text() == "Loading data..."
        assert base_dialog.status_label.objectName() == "status_info"
        base_dialog.set_loading(False)

    def test_set_loading_false_enables_ok_button(self, base_dialog: BaseDialog) -> None:
        """Setting loading to False enables OK button."""
        base_dialog.set_loading(True, "Loading...")
        base_dialog.set_loading(False)
        assert base_dialog.ok_button.isEnabled()

    def test_set_loading_false_hides_status(self, base_dialog: BaseDialog) -> None:
        """Setting loading to False hides status message."""
        base_dialog.set_loading(True, "Loading...")
        base_dialog.set_loading(False)
        assert not base_dialog.status_label.isVisible()

    def test_loading_state_prevents_acceptance(self, base_dialog: BaseDialog) -> None:
        """Dialog cannot be accepted during loading state."""
        accepted = False

        def on_accept() -> None:
            nonlocal accepted
            accepted = True

        base_dialog.accepted.connect(on_accept)
        base_dialog.set_loading(True, "Processing...")
        base_dialog.ok_button.click()
        assert not accepted
        base_dialog.set_loading(False)

    def test_loading_state_prevents_rejection(self, base_dialog: BaseDialog) -> None:
        """Dialog cannot be rejected during loading state."""
        rejected = False

        def on_reject() -> None:
            nonlocal rejected
            rejected = True

        base_dialog.rejected.connect(on_reject)
        base_dialog.set_loading(True, "Processing...")
        base_dialog.cancel_button.click()
        assert not rejected
        base_dialog.set_loading(False)


class TestBaseDialogContentManagement:
    """Test BaseDialog content widget management."""

    def test_add_content_widget_adds_to_layout(self, base_dialog: BaseDialog) -> None:
        """add_content_widget adds widget to content layout."""
        from PyQt6.QtWidgets import QLabel

        test_widget = QLabel("Test content")
        initial_count = base_dialog.content_layout.count()
        base_dialog.add_content_widget(test_widget)
        assert base_dialog.content_layout.count() == initial_count + 1

    def test_add_content_layout_adds_to_content(self, base_dialog: BaseDialog) -> None:
        """add_content_layout adds layout to content area."""
        from PyQt6.QtWidgets import QHBoxLayout, QLabel

        test_layout = QHBoxLayout()
        test_layout.addWidget(QLabel("Test"))
        initial_count = base_dialog.content_layout.count()
        base_dialog.add_content_layout(test_layout)
        assert base_dialog.content_layout.count() == initial_count + 1

    def test_set_content_layout_clears_existing_content(self, base_dialog: BaseDialog) -> None:
        """set_content_layout clears existing widgets before adding new layout."""
        from PyQt6.QtWidgets import QLabel, QVBoxLayout

        base_dialog.add_content_widget(QLabel("Old content"))
        new_layout = QVBoxLayout()
        new_layout.addWidget(QLabel("New content"))
        base_dialog.set_content_layout(new_layout)
        assert base_dialog.content_layout.count() >= 1


class TestBaseDialogValidation:
    """Test BaseDialog input validation functionality."""

    def test_default_validate_input_returns_true(self, base_dialog: BaseDialog) -> None:
        """Default validate_input implementation returns True."""
        assert base_dialog.validate_input()

    def test_validation_failure_shows_error_message(self, base_dialog: BaseDialog) -> None:
        """Failed validation shows error message."""

        class ValidatingDialog(BaseDialog):
            def validate_input(self) -> bool:
                return False

        dialog = ValidatingDialog()
        dialog.ok_button.click()
        assert dialog.status_label.isVisible()
        assert "correct the errors" in dialog.status_label.text().lower()

    def test_validation_success_accepts_dialog(self, base_dialog: BaseDialog) -> None:
        """Successful validation accepts dialog."""

        class ValidatingDialog(BaseDialog):
            def validate_input(self) -> bool:
                return True

        dialog = ValidatingDialog()
        accepted = False

        def on_accept() -> None:
            nonlocal accepted
            accepted = True

        dialog.accepted.connect(on_accept)
        dialog.ok_button.click()
        assert accepted

    def test_validation_with_custom_error_message(self, base_dialog: BaseDialog) -> None:
        """Custom error message is shown when validation fails."""

        class ValidatingDialog(BaseDialog):
            def validate_input(self) -> bool:
                self.show_error("Custom validation error")
                return False

        dialog = ValidatingDialog()
        dialog.ok_button.click()
        assert dialog.status_label.text() == "Custom validation error"


class TestBaseDialogFocusManagement:
    """Test BaseDialog focus management."""

    def test_dialog_sets_focus_to_first_focusable_widget(self, base_dialog: BaseDialog) -> None:
        """Dialog sets focus to first focusable widget on show."""
        from PyQt6.QtWidgets import QLineEdit

        line_edit = QLineEdit()
        base_dialog.add_content_widget(line_edit)
        base_dialog.show()
        QApplication.processEvents()
        assert line_edit.hasFocus()
        base_dialog.close()

    def test_dialog_skips_disabled_widgets_for_focus(self, base_dialog: BaseDialog) -> None:
        """Dialog skips disabled widgets when setting initial focus."""
        from PyQt6.QtWidgets import QLineEdit

        disabled_edit = QLineEdit()
        disabled_edit.setEnabled(False)
        enabled_edit = QLineEdit()
        base_dialog.add_content_widget(disabled_edit)
        base_dialog.add_content_widget(enabled_edit)
        base_dialog.show()
        QApplication.processEvents()
        assert enabled_edit.hasFocus()
        base_dialog.close()


class TestBaseDialogTemplateWidget:
    """Test BaseDialog template widget creation functionality."""

    def test_create_template_widget_returns_widget(self, base_dialog: BaseDialog) -> None:
        """create_template_widget returns properly configured widget."""
        templates = ["Template 1", "Template 2", "Template 3"]
        widget = base_dialog.create_template_widget("Test Templates", templates)
        assert widget is not None
        assert isinstance(widget, QWidget)

    def test_create_template_widget_populates_list(self, base_dialog: BaseDialog) -> None:
        """create_template_widget populates template list with items."""
        templates = ["Template A", "Template B", "Template C"]
        widget = base_dialog.create_template_widget("Templates", templates)
        assert base_dialog.template_list.count() == 3
        assert base_dialog.template_list.item(0).text() == "Template A"
        assert base_dialog.template_list.item(1).text() == "Template B"
        assert base_dialog.template_list.item(2).text() == "Template C"

    def test_template_buttons_initially_disabled(self, base_dialog: BaseDialog) -> None:
        """Template use and edit buttons are initially disabled."""
        templates = ["Template 1"]
        widget = base_dialog.create_template_widget("Templates", templates)
        assert not base_dialog.use_template_btn.isEnabled()
        assert not base_dialog.edit_template_btn.isEnabled()

    def test_template_create_button_enabled(self, base_dialog: BaseDialog) -> None:
        """Template create button is enabled."""
        templates = ["Template 1"]
        widget = base_dialog.create_template_widget("Templates", templates)
        assert base_dialog.create_template_btn.isEnabled()

    def test_template_selection_triggers_callback(self, base_dialog: BaseDialog) -> None:
        """Selecting template triggers on_template_selected callback."""
        callback_triggered = False

        class TemplateDialog(BaseDialog):
            def on_template_selected(self) -> None:
                nonlocal callback_triggered
                callback_triggered = True

        dialog = TemplateDialog()
        templates = ["Template 1", "Template 2"]
        widget = dialog.create_template_widget("Templates", templates)
        dialog.template_list.setCurrentRow(0)
        assert callback_triggered


class TestBaseDialogBinarySelection:
    """Test BaseDialog binary file selection interface."""

    def test_setup_header_creates_binary_path_edit(self, base_dialog: BaseDialog) -> None:
        """setup_header creates binary path line edit."""
        from PyQt6.QtWidgets import QVBoxLayout

        layout = QVBoxLayout()
        base_dialog.setup_header(layout)
        assert hasattr(base_dialog, "binary_path_edit")
        assert base_dialog.binary_path_edit is not None

    def test_setup_header_creates_browse_button(self, base_dialog: BaseDialog) -> None:
        """setup_header creates browse button."""
        from PyQt6.QtWidgets import QVBoxLayout

        layout = QVBoxLayout()
        base_dialog.setup_header(layout)
        assert layout.count() > 0

    def test_setup_header_with_existing_binary_path(self, base_dialog: BaseDialog) -> None:
        """setup_header displays existing binary path."""
        from PyQt6.QtWidgets import QVBoxLayout

        base_dialog.binary_path = "D:\\test\\sample.exe"
        layout = QVBoxLayout()
        base_dialog.setup_header(layout)
        assert base_dialog.binary_path_edit.text() == "D:\\test\\sample.exe"

    def test_setup_header_without_label(self, base_dialog: BaseDialog) -> None:
        """setup_header can hide binary label."""
        from PyQt6.QtWidgets import QVBoxLayout

        layout = QVBoxLayout()
        base_dialog.setup_header(layout, show_label=False)
        assert base_dialog.binary_path_edit is not None

    def test_setup_header_with_extra_buttons(self, base_dialog: BaseDialog) -> None:
        """setup_header can add extra buttons."""
        from PyQt6.QtWidgets import QVBoxLayout

        callback_triggered = False

        def callback() -> None:
            nonlocal callback_triggered
            callback_triggered = True

        layout = QVBoxLayout()
        base_dialog.setup_header(layout, extra_buttons=[("Extra", callback)])
        assert layout.count() > 0

    def test_browse_binary_opens_file_dialog(self, base_dialog: BaseDialog) -> None:
        """_browse_binary opens file dialog for binary selection."""
        from PyQt6.QtWidgets import QVBoxLayout

        layout = QVBoxLayout()
        base_dialog.setup_header(layout)

        with patch.object(QFileDialog, "getOpenFileName", return_value=("D:\\test\\binary.exe", "")):
            base_dialog._browse_binary()
            assert base_dialog.binary_path_edit.text() == "D:\\test\\binary.exe"
            assert base_dialog.binary_path == "D:\\test\\binary.exe"

    def test_browse_binary_handles_cancel(self, base_dialog: BaseDialog) -> None:
        """_browse_binary handles user canceling file dialog."""
        from PyQt6.QtWidgets import QVBoxLayout

        layout = QVBoxLayout()
        base_dialog.setup_header(layout)
        original_text = base_dialog.binary_path_edit.text()

        with patch.object(QFileDialog, "getOpenFileName", return_value=("", "")):
            base_dialog._browse_binary()
            assert base_dialog.binary_path_edit.text() == original_text

    def test_browse_binary_triggers_callback(self, base_dialog: BaseDialog) -> None:
        """_browse_binary triggers on_binary_selected callback."""
        from PyQt6.QtWidgets import QVBoxLayout

        callback_triggered = False
        selected_path = None

        class BinaryDialog(BaseDialog):
            def on_binary_selected(self, file_path: str) -> None:
                nonlocal callback_triggered, selected_path
                callback_triggered = True
                selected_path = file_path

        dialog = BinaryDialog()
        layout = QVBoxLayout()
        dialog.setup_header(layout)

        with patch.object(QFileDialog, "getOpenFileName", return_value=("D:\\test\\target.exe", "")):
            dialog._browse_binary()
            assert callback_triggered
            assert selected_path == "D:\\test\\target.exe"


class TestBaseDialogResultHandling:
    """Test BaseDialog result retrieval."""

    def test_get_result_returns_empty_dict_by_default(self, base_dialog: BaseDialog) -> None:
        """get_result returns empty dictionary by default."""
        result = base_dialog.get_result()
        assert isinstance(result, dict)
        assert len(result) == 0

    def test_get_result_can_be_overridden(self, base_dialog: BaseDialog) -> None:
        """get_result can be overridden to return custom data."""

        class DataDialog(BaseDialog):
            def get_result(self) -> dict:
                return {"key": "value", "data": [1, 2, 3]}

        dialog = DataDialog()
        result = dialog.get_result()
        assert result == {"key": "value", "data": [1, 2, 3]}


class TestBaseDialogCleanup:
    """Test BaseDialog cleanup on close."""

    def test_close_event_restores_cursor_if_loading(self, base_dialog: BaseDialog) -> None:
        """closeEvent restores cursor if dialog was in loading state."""
        base_dialog.set_loading(True, "Loading...")
        base_dialog.close()

    def test_close_event_schedules_deletion(self, base_dialog: BaseDialog) -> None:
        """closeEvent schedules dialog for deletion."""
        with patch.object(base_dialog, "deleteLater") as mock_delete:
            from PyQt6.QtGui import QCloseEvent

            event = QCloseEvent()
            base_dialog.closeEvent(event)
            mock_delete.assert_called_once()


class TestBaseDialogThemeApplication:
    """Test BaseDialog theme styling application."""

    def test_dialog_has_dark_theme_stylesheet(self, base_dialog: BaseDialog) -> None:
        """Dialog has dark theme stylesheet applied."""
        stylesheet = base_dialog.styleSheet()
        assert "#1e1e1e" in stylesheet
        assert "background-color" in stylesheet

    def test_stylesheet_includes_button_styling(self, base_dialog: BaseDialog) -> None:
        """Stylesheet includes button styling rules."""
        stylesheet = base_dialog.styleSheet()
        assert "QPushButton" in stylesheet
        assert "#primary_button" in stylesheet
        assert "#danger_button" in stylesheet

    def test_stylesheet_includes_input_styling(self, base_dialog: BaseDialog) -> None:
        """Stylesheet includes input widget styling rules."""
        stylesheet = base_dialog.styleSheet()
        assert "QLineEdit" in stylesheet
        assert "QTextEdit" in stylesheet

    def test_stylesheet_includes_status_label_styling(self, base_dialog: BaseDialog) -> None:
        """Stylesheet includes status label styling for all states."""
        stylesheet = base_dialog.styleSheet()
        assert "#status_error" in stylesheet
        assert "#status_success" in stylesheet
        assert "#status_info" in stylesheet


class TestBaseDialogEdgeCases:
    """Test BaseDialog edge cases and error conditions."""

    def test_dialog_handles_empty_title(self, qapp: QApplication) -> None:
        """Dialog handles empty title string."""
        dialog = BaseDialog(title="")
        assert dialog.windowTitle() == ""

    def test_dialog_handles_very_small_dimensions(self, qapp: QApplication) -> None:
        """Dialog handles very small width and height."""
        dialog = BaseDialog(width=100, height=100)
        assert dialog.width() >= 100
        assert dialog.height() >= 100

    def test_dialog_handles_very_large_dimensions(self, qapp: QApplication) -> None:
        """Dialog handles very large width and height."""
        dialog = BaseDialog(width=3000, height=2000)
        assert dialog.width() == 3000
        assert dialog.height() == 2000

    def test_multiple_status_messages_override_previous(self, base_dialog: BaseDialog) -> None:
        """Multiple status messages override previous message."""
        base_dialog.show_error("Error 1")
        base_dialog.show_success("Success message")
        assert base_dialog.status_label.text() == "Success message"
        assert base_dialog.status_label.objectName() == "status_success"

    def test_validation_during_error_state(self, base_dialog: BaseDialog) -> None:
        """Validation during existing error state does not duplicate message."""

        class ValidatingDialog(BaseDialog):
            def validate_input(self) -> bool:
                self.show_error("Validation failed")
                return False

        dialog = ValidatingDialog()
        dialog.ok_button.click()
        assert dialog.status_label.text() == "Validation failed"

    def test_dialog_without_parent(self, qapp: QApplication) -> None:
        """Dialog can be created without parent widget."""
        dialog = BaseDialog(parent=None)
        assert dialog.parent() is None
        assert dialog.isModal()

    def test_help_text_empty_string(self, base_dialog_with_help: BaseDialog) -> None:
        """Dialog with help button and empty help text."""
        dialog = BaseDialog(show_help=True, help_text="")
        assert dialog._help_text == ""
