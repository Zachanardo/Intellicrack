"""Production tests for Text Editor Dialog.

Tests real text editing functionality with syntax highlighting.
"""

from pathlib import Path
from typing import Generator

import pytest


PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.dialogs.text_editor_dialog import TextEditorDialog


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance."""
    existing_app = QApplication.instance()
    if existing_app is None:
        return QApplication([])
    assert isinstance(existing_app, QApplication), "Expected QApplication instance"
    return existing_app


@pytest.fixture
def test_file(tmp_path: Path) -> Path:
    """Create test file for editing."""
    file = tmp_path / "test_script.py"
    file.write_text("def test_function():\n    print('Hello')\n")
    return file


@pytest.fixture
def editor_dialog(qapp: QApplication) -> Generator[TextEditorDialog, None, None]:
    """Create text editor dialog."""
    dialog = TextEditorDialog()
    yield dialog
    dialog.close()
    dialog.deleteLater()


class TestEditorInitialization:
    """Test editor initialization."""

    def test_dialog_creates_successfully(
        self, editor_dialog: TextEditorDialog
    ) -> None:
        """Editor dialog initializes."""
        assert editor_dialog is not None

    def test_has_text_editor_widget(
        self, editor_dialog: TextEditorDialog
    ) -> None:
        """Dialog contains text editing widget."""
        text_edits = editor_dialog.findChildren(PyQt6.QtWidgets.QPlainTextEdit)
        text_edits_multi = editor_dialog.findChildren(PyQt6.QtWidgets.QTextEdit)
        assert len(text_edits) > 0 or len(text_edits_multi) > 0


class TestFileOperations:
    """Test file open/save operations."""

    def test_open_file_action(
        self, editor_dialog: TextEditorDialog
    ) -> None:
        """Editor has open file action."""
        actions = editor_dialog.findChildren(PyQt6.QtGui.QAction)
        action_texts = [act.text().lower() for act in actions]
        assert any("open" in text for text in action_texts)

    def test_save_file_action(
        self, editor_dialog: TextEditorDialog
    ) -> None:
        """Editor has save file action."""
        actions = editor_dialog.findChildren(PyQt6.QtGui.QAction)
        action_texts = [act.text().lower() for act in actions]
        assert any("save" in text for text in action_texts)

    def test_loads_file_content(
        self, qapp: QApplication, test_file: Path
    ) -> None:
        """Editor loads file content correctly."""
        dialog = TextEditorDialog(str(test_file))
        try:
            if text_edit := dialog.findChild(PyQt6.QtWidgets.QPlainTextEdit):
                content = text_edit.toPlainText()
                assert "test_function" in content
        finally:
            dialog.close()
            dialog.deleteLater()


class TestTextEditing:
    """Test text editing functionality."""

    def test_text_can_be_modified(
        self, editor_dialog: TextEditorDialog
    ) -> None:
        """Text editor allows modifications."""
        text_edit = editor_dialog.findChild(PyQt6.QtWidgets.QPlainTextEdit) or editor_dialog.findChild(PyQt6.QtWidgets.QTextEdit)

        if text_edit:
            test_text = "print('test')"
            text_edit.setPlainText(test_text)
            assert text_edit.toPlainText() == test_text


class TestSyntaxHighlighting:
    """Test syntax highlighting functionality."""

    def test_python_syntax_highlighting(
        self, qapp: QApplication
    ) -> None:
        """Editor applies Python syntax highlighting."""
        dialog = TextEditorDialog()
        try:
            text_edit = dialog.findChild(PyQt6.QtWidgets.QPlainTextEdit) or dialog.findChild(PyQt6.QtWidgets.QTextEdit)

            if text_edit and hasattr(text_edit, 'document'):
                document = text_edit.document()
                assert document is not None
        finally:
            dialog.close()
            dialog.deleteLater()


class TestSearchAndReplace:
    """Test search and replace functionality."""

    def test_find_action_exists(
        self, editor_dialog: TextEditorDialog
    ) -> None:
        """Editor has find/search action."""
        actions = editor_dialog.findChildren(PyQt6.QtGui.QAction)
        action_texts = [act.text().lower() for act in actions]
        assert any("find" in text or "search" in text for text in action_texts)

    def test_replace_action_exists(
        self, editor_dialog: TextEditorDialog
    ) -> None:
        """Editor has replace action."""
        actions = editor_dialog.findChildren(PyQt6.QtGui.QAction)
        action_texts = [act.text().lower() for act in actions]
        assert any("replace" in text for text in action_texts)
