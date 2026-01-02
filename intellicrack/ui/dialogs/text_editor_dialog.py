"""Text Editor Dialog for Intellicrack.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
from re import Pattern
from typing import TYPE_CHECKING, Any, cast

from intellicrack.handlers.pyqt6_handler import (
    HAS_PYQT,
    QAction,
    QCheckBox,
    QColor,
    QComboBox,
    QDateTime,
    QDialog,
    QFileDialog,
    QFileSystemWatcher,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QKeySequence,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QSyntaxHighlighter,
    Qt,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
    QToolBar,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)


if TYPE_CHECKING:
    from PyQt6.QtGui import QCloseEvent


logger = logging.getLogger(__name__)


class PythonSyntaxHighlighter(QSyntaxHighlighter if HAS_PYQT and QSyntaxHighlighter else object):
    """Syntax highlighter for Python code."""

    def __init__(self, document: QTextDocument | None = None) -> None:
        """Initialize the Python syntax highlighter with formatting rules.

        Args:
            document: The text document to highlight, or None.

        """
        self.highlighting_rules: list[tuple[Pattern[str], QTextCharFormat]] = []

        if not HAS_PYQT or QSyntaxHighlighter is None:
            self.document_ref = document
            return

        if document is not None:
            super().__init__(document)
        else:
            super().__init__()

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(85, 85, 255))
        keyword_format.setFontWeight(QFont.Weight.Bold)

        keywords = [
            "and",
            "as",
            "assert",
            "break",
            "class",
            "continue",
            "def",
            "del",
            "elif",
            "else",
            "except",
            "exec",
            "finally",
            "for",
            "from",
            "global",
            "if",
            "import",
            "in",
            "is",
            "lambda",
            "not",
            "or",
            "pass",
            "print",
            "raise",
            "return",
            "try",
            "while",
            "with",
            "yield",
            "True",
            "False",
            "None",
        ]

        for kw in keywords:
            pattern = r"\b" + kw + r"\b"
            self.highlighting_rules.append((re.compile(pattern), keyword_format))

        string_format = QTextCharFormat()
        string_format.setForeground(QColor(0, 128, 0))
        self.highlighting_rules.append((re.compile(r'".*?"'), string_format))
        self.highlighting_rules.append((re.compile(r"'.*?'"), string_format))

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(128, 128, 128))
        comment_format.setFontItalic(True)
        self.highlighting_rules.append((re.compile(r"#.*"), comment_format))

        number_format = QTextCharFormat()
        number_format.setForeground(QColor(255, 0, 255))
        self.highlighting_rules.append((re.compile(r"\b\d+\b"), number_format))

        function_format = QTextCharFormat()
        function_format.setForeground(QColor(0, 0, 255))
        function_format.setFontWeight(QFont.Weight.Bold)
        self.highlighting_rules.append((re.compile(r"\bdef\s+(\w+)"), function_format))

    def highlightBlock(self, text: str | None) -> None:  # noqa: N802
        """Apply syntax highlighting to a block of text.

        Args:
            text: The text block to highlight.

        """
        if not HAS_PYQT or text is None:
            return

        for pattern, text_format in self.highlighting_rules:
            for match in pattern.finditer(text):
                start = match.start()
                length = match.end() - start
                self.setFormat(start, length, text_format)

    def setDocument(self, document: QTextDocument | None) -> None:  # noqa: N802
        """Set document for highlighting.

        Args:
            document: The text document to highlight.

        """
        if HAS_PYQT and QSyntaxHighlighter is not None:
            super().setDocument(document)


class FindReplaceDialog(QDialog if HAS_PYQT and QDialog else object):
    """Find and replace dialog."""

    def __init__(self, parent: TextEditorDialog | QWidget | None = None) -> None:
        """Initialize the find and replace dialog.

        Args:
            parent: The parent widget for this dialog.

        """
        self.text_editor: TextEditorDialog | None = None
        self.find_edit: QLineEdit | None = None
        self.replace_edit: QLineEdit | None = None
        self.case_sensitive: QCheckBox | None = None
        self.whole_words: QCheckBox | None = None
        self.regex_mode: QCheckBox | None = None
        self.find_next_btn: QPushButton | None = None
        self.find_prev_btn: QPushButton | None = None
        self.replace_btn: QPushButton | None = None
        self.replace_all_btn: QPushButton | None = None
        self.close_btn: QPushButton | None = None

        if not HAS_PYQT or QDialog is None:
            return

        parent_widget = cast("QWidget | None", parent) if isinstance(parent, QWidget) else None
        super().__init__(parent_widget)

        if isinstance(parent, TextEditorDialog):
            self.text_editor = parent

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the find/replace UI."""
        if not HAS_PYQT:
            return

        self.setWindowTitle("Find and Replace")
        self.setModal(False)
        self.resize(400, 200)

        layout = QVBoxLayout()

        find_layout = QHBoxLayout()
        find_layout.addWidget(QLabel("Find:"))
        self.find_edit = QLineEdit()
        find_layout.addWidget(self.find_edit)
        layout.addLayout(find_layout)

        replace_layout = QHBoxLayout()
        replace_layout.addWidget(QLabel("Replace:"))
        self.replace_edit = QLineEdit()
        replace_layout.addWidget(self.replace_edit)
        layout.addLayout(replace_layout)

        options_layout = QHBoxLayout()
        self.case_sensitive = QCheckBox("Case sensitive")
        self.whole_words = QCheckBox("Whole words")
        self.regex_mode = QCheckBox("Regular expressions")

        options_layout.addWidget(self.case_sensitive)
        options_layout.addWidget(self.whole_words)
        options_layout.addWidget(self.regex_mode)
        layout.addLayout(options_layout)

        button_layout = QHBoxLayout()

        self.find_next_btn = QPushButton("Find Next")
        self.find_next_btn.clicked.connect(self.find_next)

        self.find_prev_btn = QPushButton("Find Previous")
        self.find_prev_btn.clicked.connect(self.find_previous)

        self.replace_btn = QPushButton("Replace")
        self.replace_btn.clicked.connect(self.replace_current)

        self.replace_all_btn = QPushButton("Replace All")
        self.replace_all_btn.clicked.connect(self.replace_all)

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)

        button_layout.addWidget(self.find_next_btn)
        button_layout.addWidget(self.find_prev_btn)
        button_layout.addWidget(self.replace_btn)
        button_layout.addWidget(self.replace_all_btn)
        button_layout.addWidget(self.close_btn)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        self.find_edit.returnPressed.connect(self.find_next)

    def find_next(self) -> None:
        """Find next occurrence."""
        if self.text_editor is not None and self.find_edit is not None:
            self.text_editor.find_text(self.find_edit.text(), forward=True)

    def find_previous(self) -> None:
        """Find previous occurrence."""
        if self.text_editor is not None and self.find_edit is not None:
            self.text_editor.find_text(self.find_edit.text(), forward=False)

    def replace_current(self) -> None:
        """Replace current selection."""
        if self.text_editor is not None and self.find_edit is not None and self.replace_edit is not None:
            self.text_editor.replace_text(self.find_edit.text(), self.replace_edit.text())

    def replace_all(self) -> None:
        """Replace all occurrences."""
        if not HAS_PYQT:
            return
        if self.text_editor is not None and self.find_edit is not None and self.replace_edit is not None:
            count = self.text_editor.replace_all_text(self.find_edit.text(), self.replace_edit.text())
            QMessageBox.information(self, "Replace All", f"Replaced {count} occurrences")

    def show(self) -> None:
        """Show the dialog."""
        if HAS_PYQT and QDialog is not None:
            super().show()

    def hide(self) -> None:
        """Hide the dialog."""
        if HAS_PYQT and QDialog is not None:
            super().hide()


class TextEditorDialog(QDialog if HAS_PYQT and QDialog else object):
    """Advanced text editor dialog for Intellicrack."""

    if HAS_PYQT:
        file_saved = pyqtSignal(str)
        content_changed = pyqtSignal(bool)

    def __init__(
        self,
        title: str = "Text Editor",
        content: str = "",
        syntax: str = "python",
        parent: QWidget | None = None,
    ) -> None:
        """Initialize text editor dialog.

        Args:
            title: The window title for the text editor.
            content: The initial content to display in the editor.
            syntax: The syntax highlighting mode to use (default: "python").
            parent: The parent widget for this dialog.

        """
        self.current_file: str | None = None
        self.is_modified: bool = False
        self.syntax_mode: str = syntax
        self.find_replace_dialog: FindReplaceDialog | None = None
        self.file_watcher: QFileSystemWatcher | None = None
        self.text_edit: QPlainTextEdit | None = None
        self.file_path: str | None = None
        self.original_content: str = ""
        self.highlighter: PythonSyntaxHighlighter | None = None
        self.save_btn: QPushButton | None = None
        self.save_as_btn: QPushButton | None = None
        self.export_btn: QPushButton | None = None
        self.reload_btn: QPushButton | None = None
        self.close_btn: QPushButton | None = None
        self.toolbar: QToolBar | None = None
        self.status_bar: QStatusBar | None = None
        self.line_col_label: QLabel | None = None
        self.file_status_label: QLabel | None = None
        self.font_size_spin: QSpinBox | None = None
        self.new_action: QAction | None = None
        self.open_action: QAction | None = None
        self.save_action: QAction | None = None
        self.save_as_action: QAction | None = None
        self.export_action: QAction | None = None
        self.undo_action: QAction | None = None
        self.redo_action: QAction | None = None
        self.cut_action: QAction | None = None
        self.copy_action: QAction | None = None
        self.paste_action: QAction | None = None
        self.select_all_action: QAction | None = None
        self.find_action: QAction | None = None
        self.find_next_action: QAction | None = None
        self.find_prev_action: QAction | None = None
        self._content: str = content
        self._title: str = title
        self._parent: QWidget | None = parent

        if not HAS_PYQT or QDialog is None:
            return

        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(800, 600)

        self.file_watcher = QFileSystemWatcher()
        self.file_watcher.fileChanged.connect(self._on_file_changed_externally)

        self._setup_ui()
        self._setup_connections()
        self._setup_shortcuts()

        self.set_content(content)
        self.set_syntax_highlighting(syntax)
        self._configure_editor()

        logger.info("Text Editor Dialog initialized with syntax: %s", syntax)

    def set_content(self, content: str) -> None:
        """Set the editor content.

        Args:
            content: The content to display in the editor.

        """
        self._content = content
        if self.text_edit is not None:
            self.text_edit.setPlainText(content)
        self.original_content = content
        self.is_modified = False

    def get_content(self) -> str:
        """Get editor content.

        Returns:
            The current editor content.

        """
        if self.text_edit is not None:
            return self.text_edit.toPlainText()
        return self._content

    def set_syntax_highlighting(self, syntax: str) -> None:
        """Set the syntax highlighting mode.

        Args:
            syntax: The syntax highlighting mode to use (e.g., "python").

        """
        self.syntax_mode = syntax

    def _configure_editor(self) -> None:
        """Configure editor appearance and behavior settings."""

    def _setup_ui(self) -> None:
        """Set up the user interface components for the text editor."""
        if not HAS_PYQT:
            return

        self.setWindowTitle("Text Editor")
        self.resize(800, 600)

        main_layout = QVBoxLayout()

        self.text_edit = QPlainTextEdit()
        self.text_edit.setFont(QFont("Consolas", 10))
        self.text_edit.textChanged.connect(self._on_content_changed)

        if self.file_path and self.file_path.endswith(".py") and self.text_edit is not None:
            self.highlighter = PythonSyntaxHighlighter(self.text_edit.document())

        main_layout.addWidget(self.text_edit)

        button_layout = QHBoxLayout()

        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_file)
        self.save_btn.setEnabled(False)

        self.save_as_btn = QPushButton("Save As...")
        self.save_as_btn.clicked.connect(self.save_file_as)

        self.export_btn = QPushButton("Export...")
        self.export_btn.clicked.connect(self.export_file)

        self.reload_btn = QPushButton("Reload")
        self.reload_btn.clicked.connect(self.reload_file)
        self.reload_btn.setEnabled(bool(self.file_path))

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self._close_with_confirmation)

        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.save_as_btn)
        button_layout.addWidget(self.export_btn)
        button_layout.addWidget(self.reload_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.close_btn)

        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def _setup_connections(self) -> None:
        """Set up signal connections for text editor and file watcher."""
        if self.text_edit is not None:
            self.text_edit.textChanged.connect(self._on_content_changed)
            self.text_edit.cursorPositionChanged.connect(self._update_cursor_position)

    def _setup_actions(self) -> None:
        """Set up keyboard shortcuts and actions for menu and toolbar."""
        if not HAS_PYQT:
            return

        self.new_action = QAction("New", self)
        self.new_action.setShortcut(QKeySequence.StandardKey.New)
        self.new_action.triggered.connect(self.new_file)

        self.open_action = QAction("Open", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.triggered.connect(self.open_file)

        self.save_action = QAction("Save", self)
        self.save_action.setShortcut(QKeySequence.StandardKey.Save)
        self.save_action.triggered.connect(self.save_file)

        self.save_as_action = QAction("Save As...", self)
        self.save_as_action.setShortcut(QKeySequence.StandardKey.SaveAs)
        self.save_as_action.triggered.connect(self.save_file_as)

        self.export_action = QAction("Export...", self)
        self.export_action.setShortcut(QKeySequence("Ctrl+E"))
        self.export_action.triggered.connect(self.export_file)

        self.undo_action = QAction("Undo", self)
        self.undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        if self.text_edit is not None:
            self.undo_action.triggered.connect(self.text_edit.undo)

        self.redo_action = QAction("Redo", self)
        self.redo_action.setShortcut(QKeySequence.StandardKey.Redo)
        if self.text_edit is not None:
            self.redo_action.triggered.connect(self.text_edit.redo)

        self.cut_action = QAction("Cut", self)
        self.cut_action.setShortcut(QKeySequence.StandardKey.Cut)
        if self.text_edit is not None:
            self.cut_action.triggered.connect(self.text_edit.cut)

        self.copy_action = QAction("Copy", self)
        self.copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        if self.text_edit is not None:
            self.copy_action.triggered.connect(self.text_edit.copy)

        self.paste_action = QAction("Paste", self)
        self.paste_action.setShortcut(QKeySequence.StandardKey.Paste)
        if self.text_edit is not None:
            self.paste_action.triggered.connect(self.text_edit.paste)

        self.select_all_action = QAction("Select All", self)
        self.select_all_action.setShortcut(QKeySequence.StandardKey.SelectAll)
        if self.text_edit is not None:
            self.select_all_action.triggered.connect(self.text_edit.selectAll)

        self.find_action = QAction("Find", self)
        self.find_action.setShortcut(QKeySequence.StandardKey.Find)
        self.find_action.triggered.connect(self.show_find_replace)

        self.find_next_action = QAction("Find Next", self)
        self.find_next_action.setShortcut(QKeySequence.StandardKey.FindNext)

        self.find_prev_action = QAction("Find Previous", self)
        self.find_prev_action.setShortcut(QKeySequence.StandardKey.FindPrevious)

        for action in [
            self.new_action,
            self.open_action,
            self.save_action,
            self.save_as_action,
            self.export_action,
            self.undo_action,
            self.redo_action,
            self.cut_action,
            self.copy_action,
            self.paste_action,
            self.select_all_action,
            self.find_action,
            self.find_next_action,
            self.find_prev_action,
        ]:
            if action is not None:
                self.addAction(action)

    def _setup_shortcuts(self) -> None:
        """Set up keyboard shortcuts."""
        self._setup_actions()

    def _setup_toolbar(self) -> None:
        """Set up the toolbar."""
        if not HAS_PYQT:
            return

        self.toolbar = QToolBar()

        for action in [
            self.new_action,
            self.open_action,
            self.save_action,
            self.save_as_action,
            self.export_action,
        ]:
            if action is not None:
                self.toolbar.addAction(action)

        self.toolbar.addSeparator()

        for action in [self.undo_action, self.redo_action]:
            if action is not None:
                self.toolbar.addAction(action)

        self.toolbar.addSeparator()

        for action in [self.cut_action, self.copy_action, self.paste_action]:
            if action is not None:
                self.toolbar.addAction(action)

        self.toolbar.addSeparator()

        if self.find_action is not None:
            self.toolbar.addAction(self.find_action)

        self.toolbar.addSeparator()
        self.toolbar.addWidget(QLabel("Font Size:"))

        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 72)
        self.font_size_spin.setValue(10)
        self.font_size_spin.valueChanged.connect(self._change_font_size)
        self.toolbar.addWidget(self.font_size_spin)

        layout = self.layout()
        if layout is not None:
            layout.insertWidget(0, self.toolbar)

    def _setup_status_bar(self) -> None:
        """Set up the status bar."""
        if not HAS_PYQT:
            return

        self.status_bar = QStatusBar()

        self.line_col_label = QLabel("Line: 1, Col: 1")
        self.status_bar.addPermanentWidget(self.line_col_label)

        self.file_status_label = QLabel("Ready")
        self.status_bar.addWidget(self.file_status_label)

        layout = self.layout()
        if layout is not None:
            layout.addWidget(self.status_bar)

        if self.text_edit is not None:
            self.text_edit.cursorPositionChanged.connect(self._update_cursor_position)

    def _update_cursor_position(self) -> None:
        """Update cursor position display in status bar."""
        if self.text_edit is None or self.line_col_label is None:
            return
        cursor = self.text_edit.textCursor()
        line = cursor.blockNumber() + 1
        col = cursor.columnNumber() + 1
        self.line_col_label.setText(f"Line: {line}, Col: {col}")

    def _change_font_size(self, size: int) -> None:
        """Change the font size of the text editor.

        Args:
            size: The new font size in points.

        """
        if self.text_edit is None:
            return
        font = self.text_edit.font()
        font.setPointSize(size)
        self.text_edit.setFont(font)

    def _on_content_changed(self) -> None:
        """Handle content changes and update UI accordingly."""
        if self.text_edit is None:
            return

        current_content = self.text_edit.toPlainText()
        self.is_modified = current_content != self.original_content

        title = "Text Editor"
        if self.file_path:
            title += f" - {os.path.basename(self.file_path)}"
        if self.is_modified:
            title += " *"
        self.setWindowTitle(title)

        if self.save_btn is not None:
            self.save_btn.setEnabled(self.is_modified)

        if HAS_PYQT and hasattr(self, "content_changed"):
            self.content_changed.emit(self.is_modified)

    def new_file(self) -> None:
        """Create a new file and reset editor state."""
        if not self._check_save_changes():
            return
        if self.text_edit is not None:
            self.text_edit.clear()
        self.file_path = None
        self.original_content = ""
        self.is_modified = False
        self.setWindowTitle("Text Editor - New File")
        if self.reload_btn is not None:
            self.reload_btn.setEnabled(False)

    def open_file(self) -> None:
        """Open a file via file dialog."""
        if not HAS_PYQT:
            return
        if not self._check_save_changes():
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File",
            "",
            "Text Files (*.txt *.py *.js *.json *.xml *.html *.css);;All Files (*.*)",
        )

        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path: str) -> None:
        """Load a file into the editor.

        Args:
            file_path: Path to the file to load.

        """
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            if self.text_edit is not None:
                self.text_edit.setPlainText(content)
            self.file_path = file_path
            self.original_content = content
            self.is_modified = False

            self.setWindowTitle(f"Text Editor - {os.path.basename(file_path)}")
            if self.file_status_label is not None:
                self.file_status_label.setText(f"Loaded: {file_path}")
            if self.reload_btn is not None:
                self.reload_btn.setEnabled(True)

            if file_path.endswith(".py") and self.text_edit is not None:
                self.highlighter = PythonSyntaxHighlighter(self.text_edit.document())

            if self.file_watcher is not None:
                if files := self.file_watcher.files():
                    self.file_watcher.removePaths(files)
                self.file_watcher.addPath(file_path)

        except (OSError, ValueError, RuntimeError):
            logger.exception("Error loading file in text_editor_dialog")
            if HAS_PYQT:
                QMessageBox.critical(self, "Error", "Failed to load file")

    def save_file(self) -> None:
        """Save the current file to disk."""
        if not self.file_path:
            self.save_file_as()
            return

        try:
            content = self.text_edit.toPlainText() if self.text_edit is not None else ""

            with open(self.file_path, "w", encoding="utf-8") as f:
                f.write(content)

            self.original_content = content
            self.is_modified = False
            if self.save_btn is not None:
                self.save_btn.setEnabled(False)

            if self.file_status_label is not None:
                self.file_status_label.setText(f"Saved: {self.file_path}")
            self.setWindowTitle(f"Text Editor - {os.path.basename(self.file_path)}")

            if HAS_PYQT and hasattr(self, "file_saved"):
                self.file_saved.emit(self.file_path)

        except (OSError, ValueError, RuntimeError):
            logger.exception("Error saving file in text_editor_dialog")
            if HAS_PYQT:
                QMessageBox.critical(self, "Error", "Failed to save file")

    def save_file_as(self) -> None:
        """Save the file with a new name via file dialog."""
        if not HAS_PYQT:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save File",
            self.file_path or "untitled.txt",
            "Text Files (*.txt *.py *.js *.json *.xml *.html *.css);;All Files (*.*)",
        )

        if file_path:
            self.file_path = file_path
            self.save_file()
            if self.reload_btn is not None:
                self.reload_btn.setEnabled(True)

    def export_file(self) -> None:
        """Export the file to various formats via export dialog."""
        if not HAS_PYQT:
            return

        export_dialog = QDialog(self)
        export_dialog.setWindowTitle("Export File")
        export_dialog.setModal(True)

        layout = QVBoxLayout()

        format_label = QLabel("Select export format:")
        layout.addWidget(format_label)

        format_combo = QComboBox()
        format_combo.addItems([
            "HTML (.html)",
            "PDF (.pdf)",
            "Rich Text Format (.rtf)",
            "Markdown (.md)",
            "Plain Text (.txt)",
            "CSV (.csv)",
            "JSON (.json)",
        ])
        layout.addWidget(format_combo)

        options_group = QGroupBox("Export Options")
        options_layout = QVBoxLayout()

        include_highlighting = QCheckBox("Include syntax highlighting (HTML/PDF only)")
        include_highlighting.setChecked(True)
        options_layout.addWidget(include_highlighting)

        include_line_numbers = QCheckBox("Include line numbers")
        include_line_numbers.setChecked(False)
        options_layout.addWidget(include_line_numbers)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        button_layout = QHBoxLayout()
        export_btn = QPushButton("Export")
        cancel_btn = QPushButton("Cancel")
        button_layout.addWidget(export_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        export_dialog.setLayout(layout)

        export_btn.clicked.connect(
            lambda: self._perform_export(
                format_combo.currentText(),
                export_dialog,
                include_highlighting=include_highlighting.isChecked(),
                include_line_numbers=include_line_numbers.isChecked(),
            ),
        )
        cancel_btn.clicked.connect(export_dialog.reject)

        export_dialog.exec()

    def _perform_export(
        self,
        format_type: str,
        dialog: QDialog,
        *,
        include_highlighting: bool,
        include_line_numbers: bool,
    ) -> None:
        """Perform the actual export operation.

        Args:
            format_type: The export format type selected.
            dialog: The export dialog to close after export.
            include_highlighting: Whether to include syntax highlighting.
            include_line_numbers: Whether to include line numbers.

        """
        if not HAS_PYQT:
            return

        format_map: dict[str, tuple[str, str]] = {
            "HTML (.html)": ("html", "HTML Files (*.html)"),
            "PDF (.pdf)": ("pdf", "PDF Files (*.pdf)"),
            "Rich Text Format (.rtf)": ("rtf", "RTF Files (*.rtf)"),
            "Markdown (.md)": ("md", "Markdown Files (*.md)"),
            "Plain Text (.txt)": ("txt", "Text Files (*.txt)"),
            "CSV (.csv)": ("csv", "CSV Files (*.csv)"),
            "JSON (.json)": ("json", "JSON Files (*.json)"),
        }

        ext, file_filter = format_map.get(format_type, ("txt", "Text Files (*.txt)"))

        default_name = os.path.splitext(self.file_path or "untitled")[0] + f".{ext}"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export as {format_type}",
            default_name,
            file_filter,
        )

        if not file_path:
            dialog.reject()
            return

        try:
            content = self.text_edit.toPlainText() if self.text_edit is not None else ""

            if ext == "html":
                self._export_to_html(
                    file_path,
                    content,
                    include_highlighting=include_highlighting,
                    include_line_numbers=include_line_numbers,
                )
            elif ext == "pdf":
                self._export_to_pdf(
                    file_path,
                    content,
                    include_highlighting=include_highlighting,
                    include_line_numbers=include_line_numbers,
                )
            elif ext == "rtf":
                self._export_to_rtf(file_path, content, include_line_numbers=include_line_numbers)
            elif ext == "md":
                self._export_to_markdown(file_path, content)
            elif ext == "csv":
                self._export_to_csv(file_path, content)
            elif ext == "json":
                self._export_to_json(file_path, content)
            else:
                with open(file_path, "w", encoding="utf-8") as f:
                    if include_line_numbers:
                        lines = content.split("\n")
                        numbered_content = "\n".join(f"{i + 1:4d}: {line}" for i, line in enumerate(lines))
                        f.write(numbered_content)
                    else:
                        f.write(content)

            QMessageBox.information(self, "Export Successful", f"File exported to:\n{file_path}")
            dialog.accept()

        except Exception:
            logger.exception("Export failed")
            QMessageBox.critical(self, "Export Failed", "Failed to export file")

    def _export_to_html(
        self,
        file_path: str,
        content: str,
        *,
        include_highlighting: bool,
        include_line_numbers: bool,
    ) -> None:
        """Export content to HTML format.

        Args:
            file_path: Path to save the HTML file.
            content: The content to export.
            include_highlighting: Whether to include syntax highlighting.
            include_line_numbers: Whether to include line numbers.

        """
        html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{ font-family: 'Consolas', 'Monaco', monospace; background: #f5f5f5; padding: 20px; }}
        pre {{ background: white; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .line-number {{ color: #999; margin-right: 10px; user-select: none; }}
        .keyword {{ color: #0000ff; font-weight: bold; }}
        .string {{ color: #008000; }}
        .comment {{ color: #808080; font-style: italic; }}
        .function {{ color: #795E26; }}
        .number {{ color: #098658; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <pre>{content}</pre>
</body>
</html>"""

        title = os.path.basename(self.file_path or "Untitled")

        if include_highlighting and self.file_path and self.file_path.endswith(".py"):
            formatted_content = self._apply_python_highlighting(content, include_line_numbers=include_line_numbers)
        elif include_line_numbers:
            lines = content.split("\n")
            formatted_content = "\n".join(
                f'<span class="line-number">{i + 1:4d}:</span> {self._escape_html(line)}' for i, line in enumerate(lines)
            )
        else:
            formatted_content = self._escape_html(content)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content.format(title=title, content=formatted_content))

    def _export_to_pdf(
        self,
        file_path: str,
        content: str,
        *,
        include_highlighting: bool,
        include_line_numbers: bool,
    ) -> None:
        """Export content to PDF format.

        Args:
            file_path: Path to save the PDF file.
            content: The content to export.
            include_highlighting: Whether to include syntax highlighting.
            include_line_numbers: Whether to include line numbers.

        """
        try:
            from intellicrack.handlers.pyqt6_handler import QPrinter

            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(file_path)

            document = QTextDocument()
            font = QFont("Consolas", 10)
            document.setDefaultFont(font)

            if include_line_numbers:
                lines = content.split("\n")
                formatted_content = "\n".join(f"{i + 1:4d}: {line}" for i, line in enumerate(lines))
            else:
                formatted_content = content

            if include_highlighting and self.file_path and self.file_path.endswith(".py"):
                document.setHtml(self._get_highlighted_html(formatted_content))
            else:
                document.setPlainText(formatted_content)

            document.print(printer)

        except ImportError:
            if HAS_PYQT:
                QMessageBox.warning(
                    self,
                    "PDF Export",
                    "PDF export requires PyQt6.QtPrintSupport. Saving as text instead.",
                )
            with open(file_path.replace(".pdf", ".txt"), "w", encoding="utf-8") as f:
                f.write(content)

    @staticmethod
    def _export_to_rtf(file_path: str, content: str, *, include_line_numbers: bool) -> None:
        """Export content to RTF format.

        Args:
            file_path: Path to save the RTF file.
            content: The content to export.
            include_line_numbers: Whether to include line numbers.

        """
        rtf_header = r"{\rtf1\ansi\deff0 {\fonttbl{\f0 Courier New;}}\f0\fs20 "
        rtf_footer = "}"

        rtf_content = content.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
        rtf_content = rtf_content.replace("\n", "\\par\n")

        if include_line_numbers:
            lines = rtf_content.split("\\par\n")
            rtf_content = "\\par\n".join(f"{i + 1:4d}: {line}" for i, line in enumerate(lines))

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(rtf_header + rtf_content + rtf_footer)

    def _export_to_markdown(self, file_path: str, content: str) -> None:
        """Export content to Markdown format.

        Args:
            file_path: Path to save the Markdown file.
            content: The content to export.

        """
        lang = ""
        if self.file_path:
            ext = os.path.splitext(self.file_path)[1].lower()
            lang_map = {
                ".py": "python",
                ".js": "javascript",
                ".java": "java",
                ".cpp": "cpp",
                ".c": "c",
                ".cs": "csharp",
                ".html": "html",
                ".css": "css",
                ".json": "json",
            }
            lang = lang_map.get(ext, "")

        md_content = f"# {os.path.basename(self.file_path or 'Code Export')}\n\n"
        md_content += f"```{lang}\n{content}\n```\n"

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(md_content)

    @staticmethod
    def _export_to_csv(file_path: str, content: str) -> None:
        """Export content to CSV format (line by line).

        Args:
            file_path: Path to save the CSV file.
            content: The content to export.

        """
        lines = content.split("\n")
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Line Number", "Content"])
            for i, line in enumerate(lines, 1):
                writer.writerow([i, line])

    def _export_to_json(self, file_path: str, content: str) -> None:
        """Export content to JSON format.

        Args:
            file_path: Path to save the JSON file.
            content: The content to export.

        """
        export_date = ""
        if HAS_PYQT:
            export_date = QDateTime.currentDateTime().toString(Qt.DateFormat.ISODate)

        data: dict[str, Any] = {
            "filename": os.path.basename(self.file_path or "untitled"),
            "content": content,
            "lines": content.split("\n"),
            "line_count": len(content.split("\n")),
            "character_count": len(content),
            "export_date": export_date,
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters.

        Args:
            text: The text to escape.

        Returns:
            The escaped text safe for HTML output.

        """
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _apply_python_highlighting(self, content: str, *, include_line_numbers: bool) -> str:
        """Apply simple Python syntax highlighting for HTML export.

        Args:
            content: The Python code content to highlight.
            include_line_numbers: Whether to include line numbers in the output.

        Returns:
            The HTML-formatted content with syntax highlighting applied.

        """
        content = self._escape_html(content)

        keywords = (
            r"\b(and|as|assert|break|class|continue|def|del|elif|else|except|"
            r"finally|for|from|global|if|import|in|is|lambda|not|or|pass|raise|"
            r"return|try|while|with|yield|None|True|False)\b"
        )

        content = re.sub(keywords, r'<span class="keyword">\1</span>', content)
        content = re.sub(
            r"#.*$",
            lambda m: f'<span class="comment">{m.group()}</span>',
            content,
            flags=re.MULTILINE,
        )
        content = re.sub(r'"[^"]*"|\'[^\']*\'', lambda m: f'<span class="string">{m.group()}</span>', content)
        content = re.sub(r"\b\d+\b", lambda m: f'<span class="number">{m.group()}</span>', content)
        content = re.sub(r"\bdef\s+(\w+)", r'def <span class="function">\1</span>', content)

        if include_line_numbers:
            lines = content.split("\n")
            content = "\n".join(f'<span class="line-number">{i + 1:4d}:</span> {line}' for i, line in enumerate(lines))

        return content

    def _get_highlighted_html(self, content: str) -> str:
        """Get HTML with syntax highlighting for PDF export.

        Args:
            content: The code content to highlight.

        Returns:
            HTML-formatted content with syntax highlighting.

        """
        return f"""<html>
<head>
<style>
    body {{ font-family: Consolas, monospace; }}
    .keyword {{ color: blue; }}
    .string {{ color: green; }}
    .comment {{ color: gray; }}
</style>
</head>
<body>
<pre>{self._apply_python_highlighting(content, include_line_numbers=False)}</pre>
</body>
</html>"""

    def reload_file(self) -> None:
        """Reload the file from disk, discarding any unsaved changes."""
        if not self.file_path:
            return

        if self.is_modified and HAS_PYQT:
            reply = QMessageBox.question(
                self,
                "Reload File",
                "The file has been modified. Reload and lose changes?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self.load_file(self.file_path)

    def _on_file_changed_externally(self, file_path: str) -> None:
        """Handle external file changes.

        Args:
            file_path: Path to the file that has changed externally.

        """
        if not HAS_PYQT:
            return
        if file_path == self.file_path:
            reply = QMessageBox.question(
                self,
                "File Changed",
                "The file has been changed externally. Reload?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.load_file(file_path)

    def show_find_replace(self) -> None:
        """Show the find/replace dialog, creating it if necessary."""
        if not self.find_replace_dialog:
            self.find_replace_dialog = FindReplaceDialog(self)

        self.find_replace_dialog.show()
        if HAS_PYQT and hasattr(self.find_replace_dialog, "raise_"):
            self.find_replace_dialog.raise_()
        if HAS_PYQT and hasattr(self.find_replace_dialog, "activateWindow"):
            self.find_replace_dialog.activateWindow()

    def find_text(self, text: str, *, forward: bool = True) -> None:
        """Find text in the editor.

        Args:
            text: The text to find.
            forward: If True, search forward; if False, search backward.

        """
        if not text or self.text_edit is None or not HAS_PYQT:
            return

        flags = QTextDocument.FindFlag(0)
        if not forward:
            flags = QTextDocument.FindFlag.FindBackward

        if not self.text_edit.find(text, flags):
            cursor = self.text_edit.textCursor()
            if forward:
                cursor.movePosition(QTextCursor.MoveOperation.Start)
            else:
                cursor.movePosition(QTextCursor.MoveOperation.End)
            self.text_edit.setTextCursor(cursor)

            if not self.text_edit.find(text, flags):
                QMessageBox.information(self, "Find", f"'{text}' not found")

    def replace_text(self, find_text: str, replace_text: str) -> None:
        """Replace current selection.

        Args:
            find_text: The text to find in the selection.
            replace_text: The text to replace it with.

        """
        if self.text_edit is None:
            return
        cursor = self.text_edit.textCursor()
        if cursor.hasSelection() and cursor.selectedText() == find_text:
            cursor.insertText(replace_text)

    def replace_all_text(self, find_text: str, replace_text: str) -> int:
        """Replace all occurrences of text.

        Args:
            find_text: The text to find and replace.
            replace_text: The replacement text.

        Returns:
            The number of replacements made.

        """
        if self.text_edit is None:
            return 0
        content = self.text_edit.toPlainText()
        new_content = content.replace(find_text, replace_text)
        count = content.count(find_text)

        if count > 0:
            self.text_edit.setPlainText(new_content)

        return count

    def _check_save_changes(self) -> bool:
        """Check if there are unsaved changes and ask user.

        Returns:
            True if safe to proceed, False if cancelled.

        """
        if not self.is_modified:
            return True

        if not HAS_PYQT:
            return True

        reply = QMessageBox.question(
            self,
            "Unsaved Changes",
            "The document has been modified. Save changes?",
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
        )

        if reply == QMessageBox.StandardButton.Save:
            self.save_file()
            return not self.is_modified
        return reply == QMessageBox.StandardButton.Discard

    def _close_with_confirmation(self) -> None:
        """Close the dialog with save confirmation."""
        if self._check_save_changes():
            self.accept()

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        """Handle close event.

        Args:
            event: The close event to handle.

        """
        if event is None:
            return
        if self._check_save_changes():
            event.accept()
        else:
            event.ignore()

    def show(self) -> None:
        """Show the dialog."""
        if HAS_PYQT and QDialog is not None:
            super().show()

    def exec(self) -> int:
        """Execute the dialog.

        Returns:
            Dialog result code.

        """
        if HAS_PYQT and QDialog is not None:
            result: int = super().exec()
            return result
        return 0


__all__ = ["FindReplaceDialog", "PythonSyntaxHighlighter", "TextEditorDialog"]
