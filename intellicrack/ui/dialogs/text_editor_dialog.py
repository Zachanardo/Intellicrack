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

# ruff: noqa: D417  # Implicit self parameter does not need docstring

import logging
import os
import re

# Import common PyQt6 components
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
    pyqtSignal,
)


logger = logging.getLogger(__name__)


if HAS_PYQT and QSyntaxHighlighter:

    class PythonSyntaxHighlighter(QSyntaxHighlighter):
        """Syntax highlighter for Python code."""

        def __init__(self, document: QTextDocument) -> None:
            """Initialize the Python syntax highlighter with formatting rules for keywords, strings, comments, and functions."""
            super().__init__(document)

            # Define syntax highlighting rules
            self.highlighting_rules = []

            # Python keywords
            keyword_format = QTextCharFormat()
            keyword_format.setColor(QColor(85, 85, 255))
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

            for _keyword in keywords:
                pattern = r"\b" + _keyword + r"\b"
                self.highlighting_rules.append((re.compile(pattern), keyword_format))

            # String literals
            string_format = QTextCharFormat()
            string_format.setColor(QColor(0, 128, 0))
            self.highlighting_rules.append((re.compile(r'".*?"'), string_format))
            self.highlighting_rules.append((re.compile(r"'.*?'"), string_format))

            # Comments
            comment_format = QTextCharFormat()
            comment_format.setColor(QColor(128, 128, 128))
            comment_format.setFontItalic(True)
            self.highlighting_rules.append((re.compile(r"#.*"), comment_format))

            # Numbers
            number_format = QTextCharFormat()
            number_format.setColor(QColor(255, 0, 255))
            self.highlighting_rules.append((re.compile(r"\b\d+\b"), number_format))

            # Functions
            function_format = QTextCharFormat()
            function_format.setColor(QColor(0, 0, 255))
            function_format.setFontWeight(QFont.Weight.Bold)
            self.highlighting_rules.append((re.compile(r"\bdef\s+(\w+)"), function_format))

        def highlightBlock(self: TextEditorDialog, text: str) -> None:
            """Apply syntax highlighting to a block of text."""
            for pattern, text_format in self.highlighting_rules:
                for _match in pattern.finditer(text):
                    start = _match.start()
                    length = _match.end() - start
                    self.setFormat(start, length, text_format)

else:

    class PythonSyntaxHighlighter:
        """Fallback syntax highlighter when PyQt6 is not available."""

        def __init__(self, document: object | None = None) -> None:
            """Initialize fallback highlighter.

            Args:
                document: The text document to highlight, or None.

            """
            self.document = document

        def setDocument(self, document: object) -> None:
            """Set document for highlighting.

            Args:
                document: The text document to highlight.

            """
            self.document = document

        def rehighlight(self: TextEditorDialog) -> None:
            """Rehighlight document - no-op in fallback."""

        def highlightBlock(self: TextEditorDialog, text: str) -> None:
            """No-op highlighting in fallback.

            Args:
                text: The text to highlight.

            """


if HAS_PYQT and QDialog:

    class FindReplaceDialog(QDialog):
        """Find and replace dialog."""

        def __init__(self, parent: object | None = None) -> None:
            """Initialize the find and replace dialog for text search and replacement functionality.

            Args:
                parent: The parent widget for this dialog.

            """
            if not HAS_PYQT:
                return

            super().__init__(parent)
            self.text_editor = parent
            self.setup_ui()

        def setup_ui(self: TextEditorDialog) -> None:
            """Set up the find/replace UI."""
            self.setWindowTitle("Find and Replace")
            self.setModal(False)
            self.resize(400, 200)

            layout = QVBoxLayout()

            # Find section
            find_layout = QHBoxLayout()
            find_layout.addWidget(QLabel("Find:"))
            self.find_edit = QLineEdit()
            find_layout.addWidget(self.find_edit)
            layout.addLayout(find_layout)

            # Replace section
            replace_layout = QHBoxLayout()
            replace_layout.addWidget(QLabel("Replace:"))
            self.replace_edit = QLineEdit()
            replace_layout.addWidget(self.replace_edit)
            layout.addLayout(replace_layout)

            # Options
            options_layout = QHBoxLayout()
            self.case_sensitive = QCheckBox("Case sensitive")
            self.whole_words = QCheckBox("Whole words")
            self.regex_mode = QCheckBox("Regular expressions")

            options_layout.addWidget(self.case_sensitive)
            options_layout.addWidget(self.whole_words)
            options_layout.addWidget(self.regex_mode)
            layout.addLayout(options_layout)

            # Buttons
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

            # Connect enter key to find next
            self.find_edit.returnPressed.connect(self.find_next)

    def find_next(self: TextEditorDialog) -> None:
        """Find next occurrence."""
        if self.text_editor and hasattr(self.text_editor, "find_text"):
            self.text_editor.find_text(self.find_edit.text(), forward=True)

    def find_previous(self: TextEditorDialog) -> None:
        """Find previous occurrence."""
        if self.text_editor and hasattr(self.text_editor, "find_text"):
            self.text_editor.find_text(self.find_edit.text(), forward=False)

    def replace_current(self: TextEditorDialog) -> None:
        """Replace current selection."""
        if self.text_editor and hasattr(self.text_editor, "replace_text"):
            self.text_editor.replace_text(self.find_edit.text(), self.replace_edit.text())

    def replace_all(self: TextEditorDialog) -> None:
        """Replace all occurrences."""
        if self.text_editor and hasattr(self.text_editor, "replace_all_text") and HAS_PYQT:
            count = self.text_editor.replace_all_text(self.find_edit.text(), self.replace_edit.text())
            QMessageBox.information(self, "Replace All", f"Replaced {count} occurrences")

else:

    class FindReplaceDialog:
        """Fallback find and replace dialog when PyQt6 is not available."""

        def __init__(self: TextEditorDialog, parent: object | None = None) -> None:
            """Initialize fallback find and replace dialog.

            Args:
                parent: The parent widget for this dialog.

            """

        def show(self: TextEditorDialog) -> None:
            """Show dialog (no-op in fallback)."""

        def hide(self: TextEditorDialog) -> None:
            """Hide dialog (no-op in fallback)."""


if HAS_PYQT and QDialog:

    class TextEditorDialog(QDialog):
        """Advanced text editor dialog for Intellicrack."""

        #: Emitted when file is saved (type: str)
        file_saved = pyqtSignal(str)
        #: Emitted when content changes (type: bool)
        content_changed = pyqtSignal(bool)

        def __init__(
            self,
            title: str = "Text Editor",
            content: str = "",
            syntax: str = "python",
            parent: object | None = None,
        ) -> None:
            """Initialize text editor dialog with syntax highlighting and advanced editing features.

            Args:
                title: The window title for the text editor.
                content: The initial content to display in the editor.
                syntax: The syntax highlighting mode to use (default: "python").
                parent: The parent widget for this dialog.

            """
            super().__init__(parent)
            self.setWindowTitle(title)
            self.setMinimumSize(800, 600)

            # Editor state
            self.current_file: str | None = None
            self.is_modified: bool = False
            self.syntax_mode: str = syntax
            self.find_replace_dialog: FindReplaceDialog | None = None

            # File watcher for external changes
            self.file_watcher = QFileSystemWatcher()
            self.file_watcher.fileChanged.connect(self.on_file_changed_externally)

            # Setup UI
            self.setup_ui()
            self.setup_connections()
            self.setup_shortcuts()

            # Set content and syntax highlighting
            self.set_content(content)
            self.set_syntax_highlighting(syntax)

            # Configure editor
            self.configure_editor()

            # Track modifications
            self.text_edit.textChanged.connect(self.on_content_changed)

            logger.info(f"Text Editor Dialog initialized with syntax: {syntax}")

    def set_content(self: TextEditorDialog, content: str) -> None:
        """Set the editor content.

        Args:
            content: The content to display in the editor.

        """
        self.text_edit.setPlainText(content)
        self.original_content = content
        self.is_modified = False

    def set_syntax_highlighting(self: TextEditorDialog, syntax: str) -> None:
        """Set the syntax highlighting mode.

        Args:
            syntax: The syntax highlighting mode to use (e.g., "python").

        """
        self.syntax_mode = syntax

    def configure_editor(self: TextEditorDialog) -> None:
        """Configure editor appearance and behavior settings."""
        pass

    def setup_ui(self: TextEditorDialog) -> None:
        """Set up the user interface components for the text editor."""
        self.setWindowTitle("Text Editor")
        self.resize(800, 600)

        # Main layout
        main_layout: QVBoxLayout = QVBoxLayout()

        # Text editor
        self.text_edit: QPlainTextEdit = QPlainTextEdit()
        self.text_edit.setFont(QFont("Consolas", 10))
        self.text_edit.textChanged.connect(self.on_content_changed)

        # Enable syntax highlighting for Python files
        self.file_path: str | None = None
        self.original_content: str = ""
        if self.file_path and self.file_path.endswith(".py"):
            self.highlighter: PythonSyntaxHighlighter = PythonSyntaxHighlighter(self.text_edit.document())

        main_layout.addWidget(self.text_edit)

        # Button layout
        button_layout: QHBoxLayout = QHBoxLayout()

        self.save_btn: QPushButton = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_file)
        self.save_btn.setEnabled(False)

        self.save_as_btn: QPushButton = QPushButton("Save As...")
        self.save_as_btn.clicked.connect(self.save_file_as)

        self.export_btn: QPushButton = QPushButton("Export...")
        self.export_btn.clicked.connect(self.export_file)

        self.reload_btn: QPushButton = QPushButton("Reload")
        self.reload_btn.clicked.connect(self.reload_file)
        self.reload_btn.setEnabled(bool(self.file_path))

        self.close_btn: QPushButton = QPushButton("Close")
        self.close_btn.clicked.connect(self.close_with_confirmation)

        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.save_as_btn)
        button_layout.addWidget(self.export_btn)
        button_layout.addWidget(self.reload_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.close_btn)

        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def setup_connections(self: TextEditorDialog) -> None:
        """Set up signal connections for text editor and file watcher."""
        # Connect text editor signals
        self.text_edit.textChanged.connect(self.on_content_changed)
        self.text_edit.cursorPositionChanged.connect(self.update_cursor_position)

    def setup_actions(self: TextEditorDialog) -> None:
        """Set up keyboard shortcuts and actions for menu and toolbar."""
        # File actions
        self.new_action: QAction = QAction("New", self)
        self.new_action.setShortcut(QKeySequence.New)
        self.new_action.triggered.connect(self.new_file)

        self.open_action: QAction = QAction("Open", self)
        self.open_action.setShortcut(QKeySequence.Open)
        self.open_action.triggered.connect(self.open_file)

        self.save_action: QAction = QAction("Save", self)
        self.save_action.setShortcut(QKeySequence.Save)
        self.save_action.triggered.connect(self.save_file)

        self.save_as_action: QAction = QAction("Save As...", self)
        self.save_as_action.setShortcut(QKeySequence.SaveAs)
        self.save_as_action.triggered.connect(self.save_file_as)

        self.export_action: QAction = QAction("Export...", self)
        self.export_action.setShortcut(QKeySequence("Ctrl+E"))
        self.export_action.triggered.connect(self.export_file)

        # Edit actions
        self.undo_action: QAction = QAction("Undo", self)
        self.undo_action.setShortcut(QKeySequence.Undo)
        self.undo_action.triggered.connect(self.text_edit.undo)

        self.redo_action: QAction = QAction("Redo", self)
        self.redo_action.setShortcut(QKeySequence.Redo)
        self.redo_action.triggered.connect(self.text_edit.redo)

        self.cut_action: QAction = QAction("Cut", self)
        self.cut_action.setShortcut(QKeySequence.Cut)
        self.cut_action.triggered.connect(self.text_edit.cut)

        self.copy_action: QAction = QAction("Copy", self)
        self.copy_action.setShortcut(QKeySequence.Copy)
        self.copy_action.triggered.connect(self.text_edit.copy)

        self.paste_action: QAction = QAction("Paste", self)
        self.paste_action.setShortcut(QKeySequence.Paste)
        self.paste_action.triggered.connect(self.text_edit.paste)

        self.select_all_action: QAction = QAction("Select All", self)
        self.select_all_action.setShortcut(QKeySequence.SelectAll)
        self.select_all_action.triggered.connect(self.text_edit.selectAll)

        # Find/Replace
        self.find_action: QAction = QAction("Find", self)
        self.find_action.setShortcut(QKeySequence.Find)
        self.find_action.triggered.connect(self.show_find_replace)

        self.find_next_action: QAction = QAction("Find Next", self)
        self.find_next_action.setShortcut(QKeySequence.FindNext)

        self.find_prev_action: QAction = QAction("Find Previous", self)
        self.find_prev_action.setShortcut(QKeySequence.FindPrevious)

        # Add actions to widget for shortcuts to work
        self.addAction(self.new_action)
        self.addAction(self.open_action)
        self.addAction(self.save_action)
        self.addAction(self.save_as_action)
        self.addAction(self.export_action)
        self.addAction(self.undo_action)
        self.addAction(self.redo_action)
        self.addAction(self.cut_action)
        self.addAction(self.copy_action)
        self.addAction(self.paste_action)
        self.addAction(self.select_all_action)
        self.addAction(self.find_action)
        self.addAction(self.find_next_action)
        self.addAction(self.find_prev_action)

    def setup_toolbar(self: TextEditorDialog) -> None:
        """Set up the toolbar."""
        self.toolbar: QToolBar = QToolBar()

        # File buttons
        self.toolbar.addAction(self.new_action)
        self.toolbar.addAction(self.open_action)
        self.toolbar.addAction(self.save_action)
        self.toolbar.addAction(self.save_as_action)
        self.toolbar.addAction(self.export_action)
        self.toolbar.addSeparator()

        # Edit buttons
        self.toolbar.addAction(self.undo_action)
        self.toolbar.addAction(self.redo_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.cut_action)
        self.toolbar.addAction(self.copy_action)
        self.toolbar.addAction(self.paste_action)
        self.toolbar.addSeparator()

        # Find button
        self.toolbar.addAction(self.find_action)

        # Font size control
        self.toolbar.addSeparator()
        self.toolbar.addWidget(QLabel("Font Size:"))

        self.font_size_spin: QSpinBox = QSpinBox()
        self.font_size_spin.setRange(8, 72)
        self.font_size_spin.setValue(10)
        self.font_size_spin.valueChanged.connect(self.change_font_size)
        self.toolbar.addWidget(self.font_size_spin)

        # Add toolbar to layout
        layout = self.layout()
        layout.insertWidget(0, self.toolbar)

    def setup_status_bar(self: TextEditorDialog) -> None:
        """Set up the status bar."""
        self.status_bar: QStatusBar = QStatusBar()

        # Line/column indicator
        self.line_col_label: QLabel = QLabel("Line: 1, Col: 1")
        self.status_bar.addPermanentWidget(self.line_col_label)

        # File status
        self.file_status_label: QLabel = QLabel("Ready")
        self.status_bar.addWidget(self.file_status_label)

        # Add status bar to layout
        layout = self.layout()
        layout.addWidget(self.status_bar)

        # Update line/column info when cursor moves
        self.text_edit.cursorPositionChanged.connect(self.update_cursor_position)

    def update_cursor_position(self: TextEditorDialog) -> None:
        """Update cursor position display in status bar."""
        cursor: QTextCursor = self.text_edit.textCursor()
        line: int = cursor.blockNumber() + 1
        col: int = cursor.columnNumber() + 1
        self.line_col_label.setText(f"Line: {line}, Col: {col}")

    def change_font_size(self: TextEditorDialog, size: int) -> None:
        """Change the font size of the text editor.

        Args:
            size: The new font size in points.

        """
        font: QFont = self.text_edit.font()
        font.setPointSize(size)
        self.text_edit.setFont(font)

    def on_content_changed(self: TextEditorDialog) -> None:
        """Handle content changes and update UI accordingly."""
        current_content: str = self.text_edit.toPlainText()
        self.is_modified = current_content != self.original_content

        # Update window title and save button
        title: str = "Text Editor"
        if self.file_path:
            title += f" - {os.path.basename(self.file_path)}"
        if self.is_modified:
            title += " *"
        self.setWindowTitle(title)

        self.save_btn.setEnabled(self.is_modified)
        self.content_changed.emit(self.is_modified)

    def new_file(self: TextEditorDialog) -> None:
        """Create a new file and reset editor state."""
        if self.check_save_changes():
            self.text_edit.clear()
            self.file_path = None
            self.original_content = ""
            self.is_modified = False
            self.setWindowTitle("Text Editor - New File")
            self.reload_btn.setEnabled(False)

    def open_file(self: TextEditorDialog) -> None:
        """Open a file via file dialog."""
        if not self.check_save_changes():
            return

        file_path: str
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File",
            "",
            "Text Files (*.txt *.py *.js *.json *.xml *.html *.css);;All Files (*.*)",
        )

        if file_path:
            self.load_file(file_path)

    def load_file(self: TextEditorDialog, file_path: str) -> None:
        """Load a file into the editor.

        Args:
            file_path: Path to the file to load.

        """
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            self.text_edit.setPlainText(content)
            self.file_path = file_path
            self.original_content = content
            self.is_modified = False

            # Update UI
            self.setWindowTitle(f"Text Editor - {os.path.basename(file_path)}")
            self.file_status_label.setText(f"Loaded: {file_path}")
            self.reload_btn.setEnabled(True)

            # Enable syntax highlighting for Python files
            if file_path.endswith(".py"):
                self.highlighter = PythonSyntaxHighlighter(self.text_edit.document())

            # Watch for external changes
            if self.file_watcher:
                self.file_watcher.removePaths(self.file_watcher.files())
                self.file_watcher.addPath(file_path)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in text_editor_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Failed to load file: {e!s}")

    def save_file(self: TextEditorDialog) -> None:
        """Save the current file to disk."""
        if not self.file_path:
            self.save_file_as()
            return

        try:
            content: str = self.text_edit.toPlainText()

            with open(self.file_path, "w", encoding="utf-8") as f:
                f.write(content)

            self.original_content = content
            self.is_modified = False
            self.save_btn.setEnabled(False)

            self.file_status_label.setText(f"Saved: {self.file_path}")
            self.setWindowTitle(f"Text Editor - {os.path.basename(self.file_path)}")

            self.file_saved.emit(self.file_path)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in text_editor_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Failed to save file: {e!s}")

    def save_file_as(self: TextEditorDialog) -> None:
        """Save the file with a new name via file dialog."""
        file_path: str
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save File",
            self.file_path or "untitled.txt",
            "Text Files (*.txt *.py *.js *.json *.xml *.html *.css);;All Files (*.*)",
        )

        if file_path:
            self.file_path = file_path
            self.save_file()
            self.reload_btn.setEnabled(True)

    def export_file(self: TextEditorDialog) -> None:
        """Export the file to various formats via export dialog."""
        export_dialog: QDialog = QDialog(self)
        export_dialog.setWindowTitle("Export File")
        export_dialog.setModal(True)

        layout: QVBoxLayout = QVBoxLayout()

        # Format selection
        format_label: QLabel = QLabel("Select export format:")
        layout.addWidget(format_label)

        format_combo: QComboBox = QComboBox()
        format_combo.addItems(
            [
                "HTML (.html)",
                "PDF (.pdf)",
                "Rich Text Format (.rtf)",
                "Markdown (.md)",
                "Plain Text (.txt)",
                "CSV (.csv)",
                "JSON (.json)",
            ],
        )
        layout.addWidget(format_combo)

        # Options
        options_group: QGroupBox = QGroupBox("Export Options")
        options_layout: QVBoxLayout = QVBoxLayout()

        include_highlighting: QCheckBox = QCheckBox("Include syntax highlighting (HTML/PDF only)")
        include_highlighting.setChecked(True)
        options_layout.addWidget(include_highlighting)

        include_line_numbers: QCheckBox = QCheckBox("Include line numbers")
        include_line_numbers.setChecked(False)
        options_layout.addWidget(include_line_numbers)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Buttons
        button_layout: QHBoxLayout = QHBoxLayout()
        export_btn: QPushButton = QPushButton("Export")
        cancel_btn: QPushButton = QPushButton("Cancel")
        button_layout.addWidget(export_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        export_dialog.setLayout(layout)

        # Connect buttons
        export_btn.clicked.connect(
            lambda: self._perform_export(
                format_combo.currentText(),
                include_highlighting.isChecked(),
                include_line_numbers.isChecked(),
                export_dialog,
            ),
        )
        cancel_btn.clicked.connect(export_dialog.reject)

        export_dialog.exec()

    def _perform_export(
        self: TextEditorDialog,
        format_type: str,
        include_highlighting: bool,
        include_line_numbers: bool,
        dialog: QDialog,
    ) -> None:
        """Perform the actual export operation.

        Args:
            format_type: The export format type selected.
            include_highlighting: Whether to include syntax highlighting.
            include_line_numbers: Whether to include line numbers.
            dialog: The export dialog to close after export.

        """
        # Determine file extension
        format_map: dict[str, tuple[str, str]] = {
            "HTML (.html)": ("html", "HTML Files (*.html)"),
            "PDF (.pdf)": ("pdf", "PDF Files (*.pdf)"),
            "Rich Text Format (.rtf)": ("rtf", "RTF Files (*.rtf)"),
            "Markdown (.md)": ("md", "Markdown Files (*.md)"),
            "Plain Text (.txt)": ("txt", "Text Files (*.txt)"),
            "CSV (.csv)": ("csv", "CSV Files (*.csv)"),
            "JSON (.json)": ("json", "JSON Files (*.json)"),
        }

        ext: str
        file_filter: str
        ext, file_filter = format_map.get(format_type, ("txt", "Text Files (*.txt)"))

        # Get save path
        default_name: str = os.path.splitext(self.file_path or "untitled")[0] + f".{ext}"
        file_path: str
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
            content: str = self.text_edit.toPlainText()

            if ext == "html":
                self._export_to_html(file_path, content, include_highlighting, include_line_numbers)
            elif ext == "pdf":
                self._export_to_pdf(file_path, content, include_highlighting, include_line_numbers)
            elif ext == "rtf":
                self._export_to_rtf(file_path, content, include_line_numbers)
            elif ext == "md":
                self._export_to_markdown(file_path, content)
            elif ext == "csv":
                self._export_to_csv(file_path, content)
            elif ext == "json":
                self._export_to_json(file_path, content)
            else:
                # Plain text export
                with open(file_path, "w", encoding="utf-8") as f:
                    if include_line_numbers:
                        lines = content.split("\n")
                        numbered_content = "\n".join(f"{i + 1:4d}: {line}" for i, line in enumerate(lines))
                        f.write(numbered_content)
                    else:
                        f.write(content)

            QMessageBox.information(self, "Export Successful", f"File exported to:\n{file_path}")
            dialog.accept()

        except Exception as e:
            logger.error(f"Export failed: {e}")
            QMessageBox.critical(self, "Export Failed", f"Failed to export file:\n{e!s}")

    def _export_to_html(
        self: TextEditorDialog,
        file_path: str,
        content: str,
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
        html_content: str = """<!DOCTYPE html>
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

        title: str = os.path.basename(self.file_path or "Untitled")

        if include_highlighting and self.file_path and self.file_path.endswith(".py"):
            # Simple Python syntax highlighting
            formatted_content = self._apply_python_highlighting(content, include_line_numbers)
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
        self: TextEditorDialog,
        file_path: str,
        content: str,
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
            from intellicrack.handlers.pyqt6_handler import QPrinter, QTextDocument

            printer: object = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(file_path)

            document: object = QTextDocument()

            # Set font
            font: QFont = QFont("Consolas", 10)
            document.setDefaultFont(font)

            # Format content
            if include_line_numbers:
                lines: list[str] = content.split("\n")
                formatted_content: str = "\n".join(f"{i + 1:4d}: {line}" for i, line in enumerate(lines))
            else:
                formatted_content = content

            # Apply highlighting if requested
            if include_highlighting and self.file_path and self.file_path.endswith(".py"):
                document.setHtml(self._get_highlighted_html(formatted_content))
            else:
                document.setPlainText(formatted_content)

            document.print(printer)

        except ImportError:
            # Fallback if PyQt6.QtPrintSupport is not available
            QMessageBox.warning(
                self,
                "PDF Export",
                "PDF export requires PyQt6.QtPrintSupport. Saving as text instead.",
            )
            with open(file_path.replace(".pdf", ".txt"), "w", encoding="utf-8") as f:
                f.write(content)

    def _export_to_rtf(
        self: TextEditorDialog,
        file_path: str,
        content: str,
        include_line_numbers: bool,
    ) -> None:
        """Export content to RTF format.

        Args:
            file_path: Path to save the RTF file.
            content: The content to export.
            include_line_numbers: Whether to include line numbers.

        """
        rtf_header: str = r"{\rtf1\ansi\deff0 {\fonttbl{\f0 Courier New;}}\f0\fs20 "
        rtf_footer: str = "}"

        # Escape RTF special characters
        rtf_content: str = content.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}")
        rtf_content = rtf_content.replace("\n", "\\par\n")

        if include_line_numbers:
            lines: list[str] = rtf_content.split("\\par\n")
            rtf_content = "\\par\n".join(f"{i + 1:4d}: {line}" for i, line in enumerate(lines))

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(rtf_header + rtf_content + rtf_footer)

    def _export_to_markdown(self: TextEditorDialog, file_path: str, content: str) -> None:
        """Export content to Markdown format.

        Args:
            file_path: Path to save the Markdown file.
            content: The content to export.

        """
        # Detect language for code block
        lang: str = ""
        if self.file_path:
            ext: str = os.path.splitext(self.file_path)[1].lower()
            lang_map: dict[str, str] = {
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

        md_content: str = f"# {os.path.basename(self.file_path or 'Code Export')}\n\n"
        md_content += f"```{lang}\n{content}\n```\n"

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(md_content)

    def _export_to_csv(self: TextEditorDialog, file_path: str, content: str) -> None:
        """Export content to CSV format (line by line).

        Args:
            file_path: Path to save the CSV file.
            content: The content to export.

        """
        import csv

        lines: list[str] = content.split("\n")
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer: csv.writer = csv.writer(f)
            writer.writerow(["Line Number", "Content"])
            for i, line in enumerate(lines, 1):
                writer.writerow([i, line])

    def _export_to_json(self: TextEditorDialog, file_path: str, content: str) -> None:
        """Export content to JSON format.

        Args:
            file_path: Path to save the JSON file.
            content: The content to export.

        """
        import json

        data: dict[str, object] = {
            "filename": os.path.basename(self.file_path or "untitled"),
            "content": content,
            "lines": content.split("\n"),
            "line_count": len(content.split("\n")),
            "character_count": len(content),
            "export_date": QDateTime.currentDateTime().toString(Qt.DateFormat.ISODate),
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _escape_html(self: TextEditorDialog, text: str) -> str:
        """Escape HTML special characters.

        Args:
            text: The text to escape.

        Returns:
            The escaped text safe for HTML output.

        """
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _apply_python_highlighting(self: TextEditorDialog, content: str, include_line_numbers: bool) -> str:
        """Apply simple Python syntax highlighting for HTML export.

        Args:
            content: The Python code content to highlight.
            include_line_numbers: Whether to include line numbers in output.

        Returns:
            The HTML-formatted content with syntax highlighting applied.

        """
        import re

        # Escape HTML first
        content = self._escape_html(content)

        # Python keywords
        keywords: str = (
            r"\b(and|as|assert|break|class|continue|def|del|elif|else|except|"
            r"finally|for|from|global|if|import|in|is|lambda|not|or|pass|raise|"
            r"return|try|while|with|yield|None|True|False)\b"
        )

        # Apply highlighting
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
            lines: list[str] = content.split("\n")
            content = "\n".join(f'<span class="line-number">{i + 1:4d}:</span> {line}' for i, line in enumerate(lines))

        return content

    def _get_highlighted_html(self: TextEditorDialog, content: str) -> str:
        """Get HTML with syntax highlighting for PDF export.

        Args:
            content: The code content to highlight.

        Returns:
            HTML-formatted content with syntax highlighting.

        """
        html: str = f"""<html>
<head>
<style>
    body {{ font-family: Consolas, monospace; }}
    .keyword {{ color: blue; }}
    .string {{ color: green; }}
    .comment {{ color: gray; }}
</style>
</head>
<body>
<pre>{self._apply_python_highlighting(content, False)}</pre>
</body>
</html>"""
        return html

    def reload_file(self: TextEditorDialog) -> None:
        """Reload the file from disk, discarding any unsaved changes."""
        if not self.file_path:
            return

        if self.is_modified:
            reply: int = QMessageBox.question(
                self,
                "Reload File",
                "The file has been modified. Reload and lose changes?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

        self.load_file(self.file_path)

    def on_file_changed_externally(self: TextEditorDialog, file_path: str) -> None:
        """Handle external file changes.

        Args:
            file_path: Path to the file that has changed externally.

        """
        if file_path == self.file_path:
            reply: int = QMessageBox.question(
                self,
                "File Changed",
                "The file has been changed externally. Reload?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                self.load_file(file_path)

    def show_find_replace(self: TextEditorDialog) -> None:
        """Show the find/replace dialog, creating it if necessary."""
        if not self.find_replace_dialog:
            self.find_replace_dialog = FindReplaceDialog(self)

        self.find_replace_dialog.show()
        self.find_replace_dialog.raise_()
        self.find_replace_dialog.activateWindow()

    def find_text(self: TextEditorDialog, text: str, forward: bool = True) -> None:
        """Find text in the editor.

        Args:
            text: The text to find.
            forward: If True, search forward; if False, search backward.

        """
        if not text:
            return

        flags: object = QTextDocument.FindFlags()
        if not forward:
            flags |= QTextDocument.FindBackward

        if not self.text_edit.find(text, flags):
            # If not found, start from beginning/end
            cursor: QTextCursor = self.text_edit.textCursor()
            if forward:
                cursor.movePosition(QTextCursor.Start)
            else:
                cursor.movePosition(QTextCursor.End)
            self.text_edit.setTextCursor(cursor)

            # Try again
            if not self.text_edit.find(text, flags):
                QMessageBox.information(self, "Find", f"'{text}' not found")

    def replace_text(self: TextEditorDialog, find_text: str, replace_text: str) -> None:
        """Replace current selection.

        Args:
            find_text: The text to find in the selection.
            replace_text: The text to replace it with.

        """
        cursor: QTextCursor = self.text_edit.textCursor()
        if cursor.hasSelection() and cursor.selectedText() == find_text:
            cursor.insertText(replace_text)

    def replace_all_text(self: TextEditorDialog, find_text: str, replace_text: str) -> int:
        """Replace all occurrences of text.

        Args:
            find_text: The text to find and replace.
            replace_text: The replacement text.

        Returns:
            The number of replacements made.

        """
        content: str = self.text_edit.toPlainText()
        new_content: str = content.replace(find_text, replace_text)
        count: int = content.count(find_text)

        if count > 0:
            self.text_edit.setPlainText(new_content)

        return count

    def check_save_changes(self: TextEditorDialog) -> bool:
        """Check if there are unsaved changes and ask user.

        Returns:
            True if safe to proceed (no changes, or user chose to discard/save), False if cancelled.

        """
        if not self.is_modified:
            return True

        reply: int = QMessageBox.question(
            self,
            "Unsaved Changes",
            "The document has been modified. Save changes?",
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
        )

        if reply == QMessageBox.Save:
            self.save_file()
            return not self.is_modified
        return reply == QMessageBox.Discard

    def close_with_confirmation(self: TextEditorDialog) -> None:
        """Close the dialog with save confirmation."""
        if self.check_save_changes():
            self.accept()

    def closeEvent(self: TextEditorDialog, event: object) -> None:
        """Handle close event.

        Args:
            event: The close event to handle.

        """
        if self.check_save_changes():
            event.accept()
        else:
            event.ignore()

else:

    class TextEditorDialog:
        """Fallback text editor dialog when PyQt6 is not available."""

        def __init__(
            self: TextEditorDialog,
            parent: object | None = None,
            title: str = "Text Editor",
            content: str = "",
        ) -> None:
            """Initialize fallback text editor dialog.

            Args:
                parent: The parent widget for this dialog.
                title: The window title for the text editor.
                content: The initial content to display in the editor.

            """
            self.content: str = content
            self.title: str = title
            self.parent: object | None = parent

        def show(self: TextEditorDialog) -> None:
            """Show dialog (no-op in fallback)."""

        def exec(self: TextEditorDialog) -> int:
            """Execute dialog (no-op in fallback).

            Returns:
                Always returns 0.

            """
            return 0

        def get_content(self: TextEditorDialog) -> str:
            """Get editor content.

            Returns:
                The current editor content.

            """
            return self.content

        def set_content(self: TextEditorDialog, content: str) -> None:
            """Set editor content.

            Args:
                content: The content to set in the editor.

            """
            self.content = content


# Export for external use
__all__ = ["FindReplaceDialog", "PythonSyntaxHighlighter", "TextEditorDialog"]
