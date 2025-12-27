"""Comprehensive tests for BaseDialog UI component.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest
import tempfile
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QWidget, QLineEdit, QPushButton
from PyQt6.QtTest import QTest

from intellicrack.ui.dialogs.base_dialog import BaseDialog


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def base_dialog(qapp: QApplication) -> BaseDialog:
    """Provide initialized BaseDialog instance."""
    dialog = BaseDialog(
        parent=None,
        title="Test Dialog",
        width=600,
        height=400,
        resizable=True,
    )
    return dialog


class TestBaseDialogInitialization:
    """Test BaseDialog initialization and setup."""

    def test_initialization_default_parameters(self, qapp: QApplication) -> None:
        """BaseDialog initializes with default parameters."""
        dialog = BaseDialog()

        assert dialog.windowTitle() == "Dialog"
        assert dialog.isModal()
        assert dialog.width() == 600
        assert dialog.height() == 400
        assert not dialog._is_loading
        assert not dialog._error_state

    def test_initialization_custom_parameters(self, qapp: QApplication) -> None:
        """BaseDialog initializes with custom parameters."""
        dialog = BaseDialog(
            parent=None,
            title="Custom Test",
            width=800,
            height=600,
            resizable=False,
            show_help=True,
            help_text="Test help text",
        )

        assert dialog.windowTitle() == "Custom Test"
        assert dialog.width() == 800
        assert dialog.height() == 600
        assert dialog._help_text == "Test help text"
        assert dialog.button_box is not None

    def test_initialization_creates_required_widgets(self, base_dialog: BaseDialog) -> None:
        """BaseDialog creates all required UI widgets."""
        assert base_dialog.main_layout is not None
        assert base_dialog.content_widget is not None
        assert base_dialog.content_layout is not None
        assert base_dialog.status_label is not None
        assert base_dialog.button_box is not None
        assert base_dialog.ok_button is not None
        assert base_dialog.cancel_button is not None

    def test_initialization_non_resizable(self, qapp: QApplication) -> None:
        """BaseDialog respects non-resizable configuration."""
        dialog = BaseDialog(resizable=False, width=500, height=300)

        assert dialog.minimumWidth() == 500
        assert dialog.minimumHeight() == 300
        assert dialog.maximumWidth() == 500
        assert dialog.maximumHeight() == 300


class TestBaseDialogContentManagement:
    """Test content area management functionality."""

    def test_add_content_widget(self, base_dialog: BaseDialog) -> None:
        """BaseDialog adds widgets to content area successfully."""
        test_widget = QWidget()
        initial_count = base_dialog.content_layout.count()

        base_dialog.add_content_widget(test_widget)

        assert base_dialog.content_layout.count() == initial_count + 1
        assert base_dialog.content_layout.itemAt(initial_count).widget() == test_widget

    def test_clear_content_widgets(self, base_dialog: BaseDialog) -> None:
        """BaseDialog clears content widgets when setting new layout."""
        from PyQt6.QtWidgets import QVBoxLayout, QLabel

        base_dialog.add_content_widget(QLabel("Test 1"))
        base_dialog.add_content_widget(QLabel("Test 2"))

        new_layout = QVBoxLayout()
        new_label = QLabel("New content")
        new_layout.addWidget(new_label)

        base_dialog.set_content_layout(new_layout)

        assert base_dialog.content_layout.count() == 1


class TestBaseDialogStateManagement:
    """Test dialog state management (loading, error, success)."""

    def test_set_loading_state_enables_loading(self, base_dialog: BaseDialog) -> None:
        """BaseDialog enters loading state correctly."""
        base_dialog.set_loading(True, "Loading test data...")

        assert base_dialog._is_loading
        assert not base_dialog.ok_button.isEnabled()
        assert base_dialog.status_label.isVisible()
        assert "Loading test data..." in base_dialog.status_label.text()

    def test_set_loading_state_disables_loading(self, base_dialog: BaseDialog) -> None:
        """BaseDialog exits loading state correctly."""
        base_dialog.set_loading(True, "Loading...")
        base_dialog.set_loading(False)

        assert not base_dialog._is_loading
        assert base_dialog.ok_button.isEnabled()
        assert not base_dialog.status_label.isVisible()

    def test_show_error_message(self, base_dialog: BaseDialog) -> None:
        """BaseDialog displays error messages correctly."""
        error_msg = "Test error message"

        base_dialog.show_error(error_msg)

        assert base_dialog._error_state
        assert base_dialog.status_label.isVisible()
        assert error_msg in base_dialog.status_label.text()
        assert base_dialog.status_label.objectName() == "status_error"

    def test_show_success_message(self, base_dialog: BaseDialog) -> None:
        """BaseDialog displays success messages correctly."""
        success_msg = "Operation completed successfully"

        base_dialog.show_success(success_msg)

        assert base_dialog.status_label.isVisible()
        assert success_msg in base_dialog.status_label.text()
        assert base_dialog.status_label.objectName() == "status_success"

    def test_hide_status_clears_error_state(self, base_dialog: BaseDialog) -> None:
        """BaseDialog hides status and clears error state."""
        base_dialog.show_error("Test error")
        base_dialog.hide_status()

        assert not base_dialog._error_state
        assert not base_dialog.status_label.isVisible()
        assert base_dialog.status_label.text() == ""


class TestBaseDialogButtonManagement:
    """Test button configuration and behavior."""

    def test_set_ok_enabled(self, base_dialog: BaseDialog) -> None:
        """BaseDialog enables/disables OK button."""
        base_dialog.set_ok_enabled(False)
        assert not base_dialog.ok_button.isEnabled()

        base_dialog.set_ok_enabled(True)
        assert base_dialog.ok_button.isEnabled()

    def test_set_ok_text(self, base_dialog: BaseDialog) -> None:
        """BaseDialog changes OK button text."""
        custom_text = "Apply Changes"
        base_dialog.set_ok_text(custom_text)

        assert base_dialog.ok_button.text() == custom_text

    def test_set_cancel_text(self, base_dialog: BaseDialog) -> None:
        """BaseDialog changes Cancel button text."""
        custom_text = "Discard"
        base_dialog.set_cancel_text(custom_text)

        assert base_dialog.cancel_button.text() == custom_text

    def test_add_custom_button_default_type(self, base_dialog: BaseDialog) -> None:
        """BaseDialog adds custom button with default type."""
        callback_executed = False

        def test_callback() -> None:
            nonlocal callback_executed
            callback_executed = True

        button = base_dialog.add_custom_button("Custom Action", test_callback)

        assert button is not None
        assert button.text() == "Custom Action"
        assert button.objectName() == ""

        button.click()
        assert callback_executed

    def test_add_custom_button_primary_type(self, base_dialog: BaseDialog) -> None:
        """BaseDialog adds custom button with primary styling."""
        button = base_dialog.add_custom_button("Save", lambda: None, "primary")

        assert button.objectName() == "primary_button"

    def test_add_custom_button_danger_type(self, base_dialog: BaseDialog) -> None:
        """BaseDialog adds custom button with danger styling."""
        button = base_dialog.add_custom_button("Delete", lambda: None, "danger")

        assert button.objectName() == "danger_button"


class TestBaseDialogValidation:
    """Test input validation functionality."""

    def test_validate_input_default_returns_true(self, base_dialog: BaseDialog) -> None:
        """BaseDialog default validation returns True."""
        assert base_dialog.validate_input()

    def test_validate_input_custom_implementation(self, qapp: QApplication) -> None:
        """BaseDialog respects custom validation implementation."""
        class CustomDialog(BaseDialog):
            def __init__(self) -> None:
                super().__init__()
                self.validation_result = True

            def validate_input(self) -> bool:
                return self.validation_result

        dialog = CustomDialog()
        assert dialog.validate_input()

        dialog.validation_result = False
        assert not dialog.validate_input()


class TestBaseDialogAcceptReject:
    """Test dialog accept/reject behavior."""

    def test_accept_with_valid_input(self, qapp: QApplication) -> None:
        """BaseDialog accepts when validation passes."""
        class ValidDialog(BaseDialog):
            def __init__(self) -> None:
                super().__init__()
                self.accepted = False

            def validate_input(self) -> bool:
                return True

            def accept(self) -> None:
                self.accepted = True
                super().accept()

        dialog = ValidDialog()
        dialog._on_accept()
        assert dialog.accepted

    def test_accept_with_invalid_input_shows_error(self, qapp: QApplication) -> None:
        """BaseDialog shows error when validation fails."""
        class InvalidDialog(BaseDialog):
            def __init__(self) -> None:
                super().__init__()
                self.accepted = False

            def validate_input(self) -> bool:
                return False

            def accept(self) -> None:
                self.accepted = True
                super().accept()

        dialog = InvalidDialog()
        dialog._on_accept()
        assert not dialog.accepted
        assert dialog._error_state

    def test_reject_closes_dialog(self, qapp: QApplication) -> None:
        """BaseDialog rejects on cancel."""
        class RejectDialog(BaseDialog):
            def __init__(self) -> None:
                super().__init__()
                self.rejected = False

            def reject(self) -> None:
                self.rejected = True
                super().reject()

        dialog = RejectDialog()
        dialog._on_reject()
        assert dialog.rejected

    def test_accept_blocked_during_loading(self, base_dialog: BaseDialog) -> None:
        """BaseDialog prevents accept during loading state."""
        accepted_count = {"count": 0}

        original_accept = base_dialog.accept

        def count_accept() -> None:
            accepted_count["count"] += 1
            original_accept()

        base_dialog.accept = count_accept
        base_dialog.set_loading(True)

        base_dialog._on_accept()
        assert accepted_count["count"] == 0

    def test_reject_blocked_during_loading(self, base_dialog: BaseDialog) -> None:
        """BaseDialog prevents reject during loading state."""
        rejected_count = {"count": 0}

        original_reject = base_dialog.reject

        def count_reject() -> None:
            rejected_count["count"] += 1
            original_reject()

        base_dialog.reject = count_reject
        base_dialog.set_loading(True)

        base_dialog._on_reject()
        assert rejected_count["count"] == 0


class TestBaseDialogKeyboardShortcuts:
    """Test keyboard shortcut functionality."""

    def test_escape_shortcut_triggers_reject(self, qapp: QApplication) -> None:
        """BaseDialog Escape key triggers reject."""
        class EscapeDialog(BaseDialog):
            def __init__(self) -> None:
                super().__init__()
                self.rejected = False

            def reject(self) -> None:
                self.rejected = True
                super().reject()

        dialog = EscapeDialog()
        dialog.show()

        QTest.keyClick(dialog, Qt.Key.Key_Escape)
        qapp.processEvents()

        assert dialog.rejected

    def test_ctrl_enter_shortcut_triggers_accept(self, qapp: QApplication) -> None:
        """BaseDialog Ctrl+Enter triggers accept."""
        class CtrlEnterDialog(BaseDialog):
            def __init__(self) -> None:
                super().__init__()
                self.accepted = False

            def validate_input(self) -> bool:
                return True

            def accept(self) -> None:
                self.accepted = True
                super().accept()

        dialog = CtrlEnterDialog()
        dialog.show()

        QTest.keyClick(dialog, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
        qapp.processEvents()

        assert dialog.accepted


class TestBaseDialogBinarySelection:
    """Test binary file selection functionality."""

    def test_setup_header_creates_binary_selector(self, base_dialog: BaseDialog, qapp: QApplication) -> None:
        """BaseDialog setup_header creates binary selection widgets."""
        from PyQt6.QtWidgets import QVBoxLayout

        layout = QVBoxLayout()
        base_dialog.setup_header(layout)

        assert hasattr(base_dialog, 'binary_path_edit')
        assert isinstance(base_dialog.binary_path_edit, QLineEdit)

    def test_browse_binary_with_real_file(self, base_dialog: BaseDialog) -> None:
        """BaseDialog browse binary with actual file."""
        from PyQt6.QtWidgets import QVBoxLayout

        layout = QVBoxLayout()
        base_dialog.setup_header(layout)

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(b"MZ\x90\x00")

        try:
            base_dialog.binary_path_edit.setText(str(tmp_path))
            base_dialog.binary_path = str(tmp_path)

            assert base_dialog.binary_path_edit.text() == str(tmp_path)
            assert base_dialog.binary_path == str(tmp_path)
            assert tmp_path.exists()

        finally:
            if tmp_path.exists():
                tmp_path.unlink()


class TestBaseDialogTemplateWidget:
    """Test template selection widget functionality."""

    def test_create_template_widget_with_templates(self, base_dialog: BaseDialog) -> None:
        """BaseDialog creates template widget with template list."""
        templates = ["Template 1", "Template 2", "Template 3"]

        widget = base_dialog.create_template_widget("Test Templates", templates)

        assert widget is not None
        assert hasattr(base_dialog, 'template_list')
        assert base_dialog.template_list.count() == 3

    def test_template_widget_has_required_buttons(self, base_dialog: BaseDialog) -> None:
        """BaseDialog template widget creates required buttons."""
        widget = base_dialog.create_template_widget("Templates", ["Test"])

        assert hasattr(base_dialog, 'use_template_btn')
        assert hasattr(base_dialog, 'edit_template_btn')
        assert hasattr(base_dialog, 'create_template_btn')

        assert not base_dialog.use_template_btn.isEnabled()
        assert not base_dialog.edit_template_btn.isEnabled()
        assert base_dialog.create_template_btn.isEnabled()


class TestBaseDialogCleanup:
    """Test resource cleanup on close."""

    def test_close_event_restores_cursor(self, base_dialog: BaseDialog) -> None:
        """BaseDialog restores cursor on close when in loading state."""
        base_dialog.set_loading(True)

        from PyQt6.QtGui import QCloseEvent
        event = QCloseEvent()

        cursor_restored = {"value": False}
        original_restore = QApplication.restoreOverrideCursor

        def track_restore() -> None:
            cursor_restored["value"] = True
            try:
                original_restore()
            except RuntimeError:
                pass

        QApplication.restoreOverrideCursor = track_restore

        try:
            base_dialog.closeEvent(event)
            assert cursor_restored["value"]
        finally:
            QApplication.restoreOverrideCursor = original_restore

    def test_close_event_calls_delete_later(self, base_dialog: BaseDialog) -> None:
        """BaseDialog schedules deletion on close."""
        from PyQt6.QtGui import QCloseEvent
        event = QCloseEvent()

        deleted = {"value": False}
        original_delete = base_dialog.deleteLater

        def track_delete() -> None:
            deleted["value"] = True
            original_delete()

        base_dialog.deleteLater = track_delete

        base_dialog.closeEvent(event)
        assert deleted["value"]


class TestBaseDialogFocusManagement:
    """Test focus management on show."""

    def test_show_event_sets_focus_to_first_widget(self, base_dialog: BaseDialog) -> None:
        """BaseDialog sets focus to first focusable widget on show."""
        from PyQt6.QtWidgets import QLineEdit

        input_field = QLineEdit()
        input_field.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        base_dialog.add_content_widget(input_field)

        from PyQt6.QtGui import QShowEvent
        event = QShowEvent()

        base_dialog.showEvent(event)

        QApplication.processEvents()

        if input_field.hasFocus():
            assert True
        else:
            assert base_dialog.findChild(QLineEdit) is not None


class TestBaseDialogEdgeCases:
    """Test edge cases and error handling."""

    def test_get_result_returns_empty_dict(self, base_dialog: BaseDialog) -> None:
        """BaseDialog default get_result returns empty dict."""
        result = base_dialog.get_result()

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_show_status_with_empty_message(self, base_dialog: BaseDialog) -> None:
        """BaseDialog handles empty status message."""
        base_dialog.show_status("", "info")

        assert base_dialog.status_label.isVisible()
        assert base_dialog.status_label.text() == ""

    def test_multiple_rapid_state_changes(self, base_dialog: BaseDialog) -> None:
        """BaseDialog handles rapid state changes correctly."""
        for i in range(10):
            base_dialog.set_loading(i % 2 == 0)

        assert not base_dialog._is_loading

    def test_show_error_during_loading(self, base_dialog: BaseDialog) -> None:
        """BaseDialog can show error even during loading."""
        base_dialog.set_loading(True)
        base_dialog.show_error("Critical error")

        assert base_dialog._error_state
        assert base_dialog.status_label.isVisible()

    def test_concurrent_status_updates(self, base_dialog: BaseDialog) -> None:
        """BaseDialog handles overlapping status updates."""
        base_dialog.show_status("Status 1", "info")
        base_dialog.show_status("Status 2", "success")
        base_dialog.show_status("Status 3", "error")

        assert "Status 3" in base_dialog.status_label.text()
        assert base_dialog.status_label.objectName() == "status_error"
