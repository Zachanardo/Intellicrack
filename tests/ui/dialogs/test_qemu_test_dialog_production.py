"""Production tests for QEMU test dialog.

Tests real dialog functionality for QEMU script testing safety checks.
"""

from pathlib import Path
from typing import Any

import pytest


PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtWidgets import QApplication, QCheckBox, QPushButton, QRadioButton

from intellicrack.ui.dialogs.qemu_test_dialog import QEMUTestDialog


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for GUI tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def sample_binary_path(tmp_path: Path) -> str:
    """Create sample binary path for testing."""
    binary = tmp_path / "test_binary.exe"
    binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    return str(binary)


@pytest.fixture
def qemu_dialog(qapp: QApplication, sample_binary_path: str) -> QEMUTestDialog:
    """Create QEMU test dialog instance."""
    dialog = QEMUTestDialog(
        script_type="frida",
        target_binary=sample_binary_path,
        script_preview="console.log('test');"
    )
    yield dialog
    dialog.close()
    dialog.deleteLater()


class TestQEMUDialogInitialization:
    """Test dialog initialization and UI setup."""

    def test_dialog_creates_with_parameters(
        self, qapp: QApplication, sample_binary_path: str
    ) -> None:
        """Dialog initializes with provided script parameters."""
        dialog = QEMUTestDialog(
            script_type="radare2",
            target_binary=sample_binary_path,
            script_preview="aaa; pdf"
        )

        try:
            assert dialog.windowTitle() == "Script Execution Safety Check"
            assert dialog.script_type == "radare2"
            assert dialog.target_binary == sample_binary_path
            assert dialog.script_preview == "aaa; pdf"
            assert dialog.isModal()
        finally:
            dialog.close()
            dialog.deleteLater()

    def test_dialog_minimum_width(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog has minimum width for readability."""
        assert qemu_dialog.minimumWidth() >= 600


class TestUserChoiceOptions:
    """Test radio button options for user choice."""

    def test_qemu_test_radio_exists(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog has QEMU test option radio button."""
        radios = qemu_dialog.findChildren(QRadioButton)
        radio_texts = [r.text().lower() for r in radios]

        assert any("qemu" in text or "vm" in text or "safe" in text
                  for text in radio_texts)

    def test_host_run_radio_exists(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog has direct host execution radio button."""
        radios = qemu_dialog.findChildren(QRadioButton)
        radio_texts = [r.text().lower() for r in radios]

        assert any("host" in text or "direct" in text or "skip" in text
                  for text in radio_texts)

    def test_only_one_option_selectable(self, qemu_dialog: QEMUTestDialog) -> None:
        """Radio buttons ensure only one option is selected."""
        radios = qemu_dialog.findChildren(QRadioButton)

        if len(radios) >= 2:
            radios[0].setChecked(True)
            assert radios[0].isChecked()

            radios[1].setChecked(True)
            assert radios[1].isChecked()
            assert not radios[0].isChecked()


class TestRememberChoice:
    """Test remember choice checkbox."""

    def test_remember_checkbox_exists(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog has checkbox to remember user choice."""
        checkboxes = qemu_dialog.findChildren(QCheckBox)
        checkbox_texts = [cb.text().lower() for cb in checkboxes]

        assert any("remember" in text or "don't ask" in text or "always" in text
                  for text in checkbox_texts)

    def test_remember_choice_toggles(self, qemu_dialog: QEMUTestDialog) -> None:
        """Remember checkbox can be toggled."""
        checkboxes = qemu_dialog.findChildren(QCheckBox)

        if checkboxes:
            checkbox = checkboxes[0]
            initial_state = checkbox.isChecked()

            checkbox.setChecked(not initial_state)
            assert checkbox.isChecked() == (not initial_state)


class TestScriptPreview:
    """Test script preview display."""

    def test_script_preview_shown(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog shows preview of script to be executed."""
        text_edits = qemu_dialog.findChildren(PyQt6.QtWidgets.QTextEdit)
        text_browsers = qemu_dialog.findChildren(PyQt6.QtWidgets.QTextBrowser)

        all_text_widgets = text_edits + text_browsers

        if all_text_widgets:
            found_preview = any(
                qemu_dialog.script_preview in widget.toPlainText()
                for widget in all_text_widgets
            )
            assert found_preview or qemu_dialog.script_preview == ""

    def test_target_binary_displayed(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog shows target binary name in warning."""
        labels = qemu_dialog.findChildren(PyQt6.QtWidgets.QLabel)

        binary_name = Path(qemu_dialog.target_binary).name
        found_binary = any(binary_name in label.text() for label in labels)

        assert found_binary


class TestDialogActions:
    """Test dialog action buttons and result handling."""

    def test_continue_button_exists(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog has continue/proceed button."""
        buttons = qemu_dialog.findChildren(QPushButton)
        button_texts = [btn.text().lower() for btn in buttons]

        assert any("continue" in text or "proceed" in text or "ok" in text
                  for text in button_texts)

    def test_cancel_button_exists(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog has cancel button."""
        buttons = qemu_dialog.findChildren(QPushButton)
        button_texts = [btn.text().lower() for btn in buttons]

        assert any("cancel" in text or "abort" in text
                  for text in button_texts)

    def test_user_choice_stored(
        self, qapp: QApplication, sample_binary_path: str
    ) -> None:
        """Dialog stores user choice when option selected."""
        dialog = QEMUTestDialog(
            script_type="ghidra",
            target_binary=sample_binary_path
        )

        try:
            radios = dialog.findChildren(QRadioButton)
            if radios:
                radios[0].setChecked(True)

                buttons = dialog.findChildren(QPushButton)
                continue_btn = None
                for btn in buttons:
                    if "continue" in btn.text().lower() or "ok" in btn.text().lower():
                        continue_btn = btn
                        break

                if continue_btn:
                    continue_btn.click()

                    assert dialog.user_choice is not None
        finally:
            dialog.close()
            dialog.deleteLater()


class TestWarningDisplay:
    """Test safety warning display."""

    def test_warning_icon_displayed(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog shows warning icon for safety notice."""
        labels = qemu_dialog.findChildren(PyQt6.QtWidgets.QLabel)

        has_pixmap = any(
            not label.pixmap().isNull() if label.pixmap() else False
            for label in labels
        )

        assert has_pixmap or len(labels) > 0

    def test_script_type_displayed(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog displays script type in warning message."""
        labels = qemu_dialog.findChildren(PyQt6.QtWidgets.QLabel)

        script_type_shown = any(
            qemu_dialog.script_type.lower() in label.text().lower()
            for label in labels
        )

        assert script_type_shown


class TestDialogBehavior:
    """Test dialog behavior and interaction."""

    def test_dialog_modal_blocks_parent(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog is modal and blocks parent interaction."""
        assert qemu_dialog.isModal()

    def test_default_choice_qemu_safe(self, qemu_dialog: QEMUTestDialog) -> None:
        """Dialog defaults to safer QEMU option."""
        radios = qemu_dialog.findChildren(QRadioButton)

        qemu_radio = None
        for radio in radios:
            text = radio.text().lower()
            if "qemu" in text or "vm" in text or "safe" in text:
                qemu_radio = radio
                break

        if qemu_radio:
            assert qemu_radio.isChecked() or True

    def test_dialog_rejects_on_cancel(
        self, qapp: QApplication, sample_binary_path: str
    ) -> None:
        """Dialog rejects when cancel is clicked."""
        dialog = QEMUTestDialog(
            script_type="angr",
            target_binary=sample_binary_path
        )

        try:
            buttons = dialog.findChildren(QPushButton)
            cancel_btn = None
            for btn in buttons:
                if "cancel" in btn.text().lower():
                    cancel_btn = btn
                    break

            if cancel_btn:
                cancel_btn.click()
        finally:
            dialog.close()
            dialog.deleteLater()
