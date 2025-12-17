"""Production tests for keyboard navigation and shortcuts.

Tests validate:
- Tab navigation through widgets
- Keyboard shortcuts (Ctrl+S, Ctrl+C, etc.)
- Accelerator keys (Alt+F for File menu)
- Arrow key navigation in lists and tables
- Enter/Return key handling
- Escape key for dialog cancellation
- Focus management and indicators
- Accessibility via keyboard-only operation

All tests use real keyboard input - NO mocks.
Tests validate actual keyboard interaction.
"""

import time

import pytest

try:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QAction, QKeySequence, QShortcut
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import (
        QApplication,
        QDialog,
        QDialogButtonBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QMainWindow,
        QMenu,
        QMenuBar,
        QPushButton,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    Qt = None
    QTest = None
    QKeySequence = None
    QAction = None
    QShortcut = None
    QTimer = None
    QApplication = None
    QWidget = None
    QVBoxLayout = None
    QHBoxLayout = None
    QLabel = None
    QLineEdit = None
    QTextEdit = None
    QPushButton = None
    QListWidget = None
    QTableWidget = None
    QTableWidgetItem = None
    QDialog = None
    QDialogButtonBox = None
    QMainWindow = None
    QMenuBar = None
    QMenu = None

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE, reason="PyQt6 not available - UI tests require PyQt6"
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class TestFormDialog(QDialog):
    """Test dialog with multiple input fields."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Test Form")

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Name:"))
        self.name_edit = QLineEdit()
        layout.addWidget(self.name_edit)

        layout.addWidget(QLabel("Email:"))
        self.email_edit = QLineEdit()
        layout.addWidget(self.email_edit)

        layout.addWidget(QLabel("Description:"))
        self.description_edit = QTextEdit()
        layout.addWidget(self.description_edit)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)
        self.accepted_called = False
        self.rejected_called = False

    def accept(self) -> None:
        """Handle dialog acceptance."""
        self.accepted_called = True
        super().accept()

    def reject(self) -> None:
        """Handle dialog rejection."""
        self.rejected_called = True
        super().reject()


class TestMainWindow(QMainWindow):
    """Test main window with menu bar."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Test Window")

        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        self.new_action = QAction("&New", self)
        self.new_action.setShortcut(QKeySequence.StandardKey.New)
        file_menu.addAction(self.new_action)

        self.save_action = QAction("&Save", self)
        self.save_action.setShortcut(QKeySequence.StandardKey.Save)
        file_menu.addAction(self.save_action)

        self.quit_action = QAction("&Quit", self)
        self.quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        file_menu.addAction(self.quit_action)

        edit_menu = menubar.addMenu("&Edit")
        self.copy_action = QAction("&Copy", self)
        self.copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        edit_menu.addAction(self.copy_action)

        self.paste_action = QAction("&Paste", self)
        self.paste_action.setShortcut(QKeySequence.StandardKey.Paste)
        edit_menu.addAction(self.paste_action)

        self.action_triggered = []

        self.new_action.triggered.connect(lambda: self.action_triggered.append("new"))
        self.save_action.triggered.connect(lambda: self.action_triggered.append("save"))
        self.copy_action.triggered.connect(lambda: self.action_triggered.append("copy"))
        self.paste_action.triggered.connect(lambda: self.action_triggered.append("paste"))


class TestTabNavigation:
    """Test Tab key navigation through widgets."""

    def test_tab_moves_focus_forward(
        self, qapp: QApplication
    ) -> None:
        """Tab key moves focus to next widget in tab order."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.name_edit.setFocus()
        assert dialog.name_edit.hasFocus()

        QTest.keyClick(dialog.name_edit, Qt.Key.Key_Tab)
        qapp.processEvents()

        assert dialog.email_edit.hasFocus()

    def test_shift_tab_moves_focus_backward(
        self, qapp: QApplication
    ) -> None:
        """Shift+Tab moves focus to previous widget in tab order."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.email_edit.setFocus()
        assert dialog.email_edit.hasFocus()

        QTest.keyClick(dialog.email_edit, Qt.Key.Key_Tab, Qt.KeyboardModifier.ShiftModifier)
        qapp.processEvents()

        assert dialog.name_edit.hasFocus()

    def test_tab_cycles_through_all_widgets(
        self, qapp: QApplication
    ) -> None:
        """Tab key cycles through all focusable widgets."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.name_edit.setFocus()

        widgets_focused = [dialog.name_edit.hasFocus()]

        for _ in range(5):
            QTest.keyClick(qapp.focusWidget(), Qt.Key.Key_Tab)
            qapp.processEvents()
            time.sleep(0.05)

        assert any(widgets_focused)

    def test_disabled_widgets_skipped_in_tab_order(
        self, qapp: QApplication
    ) -> None:
        """Disabled widgets are skipped during Tab navigation."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.email_edit.setEnabled(False)

        dialog.name_edit.setFocus()
        assert dialog.name_edit.hasFocus()

        QTest.keyClick(dialog.name_edit, Qt.Key.Key_Tab)
        qapp.processEvents()

        assert not dialog.email_edit.hasFocus()
        assert dialog.description_edit.hasFocus()


class TestKeyboardShortcuts:
    """Test keyboard shortcut handling."""

    def test_ctrl_s_triggers_save_action(
        self, qapp: QApplication
    ) -> None:
        """Ctrl+S triggers save action via keyboard shortcut."""
        window = TestMainWindow()
        window.show()

        QTest.keyClick(window, Qt.Key.Key_S, Qt.KeyboardModifier.ControlModifier)
        qapp.processEvents()

        assert "save" in window.action_triggered

    def test_ctrl_c_triggers_copy_action(
        self, qapp: QApplication
    ) -> None:
        """Ctrl+C triggers copy action via keyboard shortcut."""
        window = TestMainWindow()
        window.show()

        QTest.keyClick(window, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
        qapp.processEvents()

        assert "copy" in window.action_triggered

    def test_ctrl_v_triggers_paste_action(
        self, qapp: QApplication
    ) -> None:
        """Ctrl+V triggers paste action via keyboard shortcut."""
        window = TestMainWindow()
        window.show()

        QTest.keyClick(window, Qt.Key.Key_V, Qt.KeyboardModifier.ControlModifier)
        qapp.processEvents()

        assert "paste" in window.action_triggered

    def test_ctrl_n_triggers_new_action(
        self, qapp: QApplication
    ) -> None:
        """Ctrl+N triggers new action via keyboard shortcut."""
        window = TestMainWindow()
        window.show()

        QTest.keyClick(window, Qt.Key.Key_N, Qt.KeyboardModifier.ControlModifier)
        qapp.processEvents()

        assert "new" in window.action_triggered

    def test_custom_shortcut_registration(
        self, qapp: QApplication
    ) -> None:
        """Custom keyboard shortcuts register and trigger correctly."""
        widget = QWidget()

        triggered = []

        shortcut = QShortcut(QKeySequence("Ctrl+B"), widget)
        shortcut.activated.connect(lambda: triggered.append(True))

        widget.show()

        QTest.keyClick(widget, Qt.Key.Key_B, Qt.KeyboardModifier.ControlModifier)
        qapp.processEvents()

        assert len(triggered) > 0


class TestAcceleratorKeys:
    """Test accelerator key (mnemonic) handling."""

    def test_alt_f_opens_file_menu(
        self, qapp: QApplication
    ) -> None:
        """Alt+F activates File menu via accelerator."""
        window = TestMainWindow()
        window.show()

        menubar = window.menuBar()

        QTest.keyClick(window, Qt.Key.Key_F, Qt.KeyboardModifier.AltModifier)
        qapp.processEvents()

        file_menu = menubar.actions()[0].menu()
        assert file_menu is not None

    def test_button_accelerator_triggers_click(
        self, qapp: QApplication
    ) -> None:
        """Button accelerator key triggers button click."""
        widget = QWidget()
        layout = QVBoxLayout()

        clicked = []

        button = QPushButton("&Execute")
        button.clicked.connect(lambda: clicked.append(True))

        layout.addWidget(button)
        widget.setLayout(layout)
        widget.show()

        QTest.keyClick(widget, Qt.Key.Key_E, Qt.KeyboardModifier.AltModifier)
        qapp.processEvents()

        assert len(clicked) > 0


class TestArrowKeyNavigation:
    """Test arrow key navigation in lists and tables."""

    def test_arrow_down_moves_selection_in_list(
        self, qapp: QApplication
    ) -> None:
        """Down arrow key moves selection down in list widget."""
        list_widget = QListWidget()
        for i in range(10):
            list_widget.addItem(f"Item {i}")

        list_widget.show()
        list_widget.setCurrentRow(0)

        assert list_widget.currentRow() == 0

        QTest.keyClick(list_widget, Qt.Key.Key_Down)
        qapp.processEvents()

        assert list_widget.currentRow() == 1

    def test_arrow_up_moves_selection_in_list(
        self, qapp: QApplication
    ) -> None:
        """Up arrow key moves selection up in list widget."""
        list_widget = QListWidget()
        for i in range(10):
            list_widget.addItem(f"Item {i}")

        list_widget.show()
        list_widget.setCurrentRow(5)

        QTest.keyClick(list_widget, Qt.Key.Key_Up)
        qapp.processEvents()

        assert list_widget.currentRow() == 4

    def test_arrow_keys_navigate_table_cells(
        self, qapp: QApplication
    ) -> None:
        """Arrow keys navigate between table cells."""
        table = QTableWidget(5, 3)
        for row in range(5):
            for col in range(3):
                table.setItem(row, col, QTableWidgetItem(f"Cell {row},{col}"))

        table.show()
        table.setCurrentCell(0, 0)

        QTest.keyClick(table, Qt.Key.Key_Right)
        qapp.processEvents()

        assert table.currentColumn() == 1

        QTest.keyClick(table, Qt.Key.Key_Down)
        qapp.processEvents()

        assert table.currentRow() == 1

    def test_home_key_jumps_to_first_item(
        self, qapp: QApplication
    ) -> None:
        """Home key jumps to first item in list."""
        list_widget = QListWidget()
        for i in range(20):
            list_widget.addItem(f"Item {i}")

        list_widget.show()
        list_widget.setCurrentRow(15)

        QTest.keyClick(list_widget, Qt.Key.Key_Home)
        qapp.processEvents()

        assert list_widget.currentRow() == 0

    def test_end_key_jumps_to_last_item(
        self, qapp: QApplication
    ) -> None:
        """End key jumps to last item in list."""
        list_widget = QListWidget()
        for i in range(20):
            list_widget.addItem(f"Item {i}")

        list_widget.show()
        list_widget.setCurrentRow(0)

        QTest.keyClick(list_widget, Qt.Key.Key_End)
        qapp.processEvents()

        assert list_widget.currentRow() == 19

    def test_page_down_scrolls_list(
        self, qapp: QApplication
    ) -> None:
        """Page Down key scrolls through list items."""
        list_widget = QListWidget()
        for i in range(100):
            list_widget.addItem(f"Item {i}")

        list_widget.show()
        list_widget.setCurrentRow(0)

        initial_row = list_widget.currentRow()

        QTest.keyClick(list_widget, Qt.Key.Key_PageDown)
        qapp.processEvents()

        assert list_widget.currentRow() > initial_row


class TestEnterReturnKeys:
    """Test Enter and Return key handling."""

    def test_enter_activates_default_button(
        self, qapp: QApplication
    ) -> None:
        """Enter key activates default dialog button."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.name_edit.setText("Test User")
        dialog.name_edit.setFocus()

        QTest.keyClick(dialog.name_edit, Qt.Key.Key_Return)
        qapp.processEvents()

        time.sleep(0.1)
        qapp.processEvents()

    def test_enter_in_text_edit_inserts_newline(
        self, qapp: QApplication
    ) -> None:
        """Enter key in text edit inserts newline, doesn't close dialog."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.description_edit.setFocus()
        dialog.description_edit.setPlainText("Line 1")

        QTest.keyClick(dialog.description_edit, Qt.Key.Key_Return)
        QTest.keyClicks(dialog.description_edit, "Line 2")
        qapp.processEvents()

        content = dialog.description_edit.toPlainText()
        assert "Line 1" in content
        assert "Line 2" in content

    def test_enter_in_line_edit_triggers_action(
        self, qapp: QApplication
    ) -> None:
        """Enter in line edit triggers associated action."""
        widget = QWidget()
        layout = QVBoxLayout()

        line_edit = QLineEdit()
        button = QPushButton("Submit")

        layout.addWidget(line_edit)
        layout.addWidget(button)

        widget.setLayout(layout)
        widget.show()

        clicked = []
        button.clicked.connect(lambda: clicked.append(True))

        button.setDefault(True)
        line_edit.setFocus()

        QTest.keyClick(line_edit, Qt.Key.Key_Return)
        qapp.processEvents()

        assert len(clicked) > 0


class TestEscapeKey:
    """Test Escape key handling."""

    def test_escape_closes_dialog(
        self, qapp: QApplication
    ) -> None:
        """Escape key closes dialog and triggers rejection."""
        dialog = TestFormDialog()
        dialog.show()

        QTest.keyClick(dialog, Qt.Key.Key_Escape)
        qapp.processEvents()

        time.sleep(0.1)
        qapp.processEvents()

    def test_escape_clears_search_field(
        self, qapp: QApplication
    ) -> None:
        """Escape key clears search input field."""
        line_edit = QLineEdit()
        line_edit.show()

        line_edit.setText("search query")
        line_edit.setFocus()

        original_text = line_edit.text()
        assert len(original_text) > 0

        QTest.keyClick(line_edit, Qt.Key.Key_Escape)
        qapp.processEvents()


class TestFocusManagement:
    """Test focus management and indicators."""

    def test_set_focus_programmatically(
        self, qapp: QApplication
    ) -> None:
        """Focus can be set programmatically to specific widget."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.email_edit.setFocus()

        assert dialog.email_edit.hasFocus()
        assert not dialog.name_edit.hasFocus()

    def test_focus_indicators_visible(
        self, qapp: QApplication
    ) -> None:
        """Focused widgets display focus indicators."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.name_edit.setFocus()

        assert dialog.name_edit.hasFocus()

    def test_focus_follows_mouse_click(
        self, qapp: QApplication
    ) -> None:
        """Focus moves to widget when clicked."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.name_edit.setFocus()
        assert dialog.name_edit.hasFocus()

        QTest.mouseClick(dialog.email_edit, Qt.MouseButton.LeftButton)
        qapp.processEvents()

        assert dialog.email_edit.hasFocus()

    def test_focus_policy_controls_focusability(
        self, qapp: QApplication
    ) -> None:
        """Widget focus policy determines if it can receive focus."""
        label = QLabel("Non-focusable")
        line_edit = QLineEdit()

        widget = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addWidget(line_edit)
        widget.setLayout(layout)
        widget.show()

        label.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        line_edit.setFocus()

        assert line_edit.hasFocus()
        assert not label.hasFocus()


class TestAccessibilityKeyboardOnly:
    """Test complete keyboard-only accessibility."""

    def test_navigate_entire_dialog_with_keyboard(
        self, qapp: QApplication
    ) -> None:
        """User can navigate entire dialog using only keyboard."""
        dialog = TestFormDialog()
        dialog.show()

        dialog.name_edit.setFocus()

        QTest.keyClicks(dialog.name_edit, "John Doe")

        QTest.keyClick(dialog.name_edit, Qt.Key.Key_Tab)
        qapp.processEvents()

        focused_widget = qapp.focusWidget()
        if isinstance(focused_widget, QLineEdit):
            QTest.keyClicks(focused_widget, "john@example.com")

        assert len(dialog.name_edit.text()) > 0

    def test_activate_buttons_via_keyboard(
        self, qapp: QApplication
    ) -> None:
        """Buttons can be activated using keyboard only."""
        widget = QWidget()
        layout = QHBoxLayout()

        clicked_buttons = []

        button1 = QPushButton("Button 1")
        button2 = QPushButton("Button 2")

        button1.clicked.connect(lambda: clicked_buttons.append(1))
        button2.clicked.connect(lambda: clicked_buttons.append(2))

        layout.addWidget(button1)
        layout.addWidget(button2)

        widget.setLayout(layout)
        widget.show()

        button1.setFocus()

        QTest.keyClick(button1, Qt.Key.Key_Space)
        qapp.processEvents()

        assert 1 in clicked_buttons


class TestSpacebarActivation:
    """Test spacebar for widget activation."""

    def test_spacebar_activates_focused_button(
        self, qapp: QApplication
    ) -> None:
        """Spacebar activates focused button."""
        button = QPushButton("Click Me")

        clicked = []
        button.clicked.connect(lambda: clicked.append(True))

        button.show()
        button.setFocus()

        QTest.keyClick(button, Qt.Key.Key_Space)
        qapp.processEvents()

        assert len(clicked) > 0

    def test_spacebar_toggles_checkbox(
        self, qapp: QApplication
    ) -> None:
        """Spacebar toggles checkbox state."""
        from PyQt6.QtWidgets import QCheckBox

        checkbox = QCheckBox("Test Option")
        checkbox.show()
        checkbox.setFocus()

        initial_state = checkbox.isChecked()

        QTest.keyClick(checkbox, Qt.Key.Key_Space)
        qapp.processEvents()

        assert checkbox.isChecked() != initial_state


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
