"""
Text Editor Dialog for Intellicrack.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging
import os
import re

# Import common PyQt5 components
from .common_imports import (
    HAS_PYQT,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    logger,
    pyqtSignal,
)

try:
    from PyQt6.QtCore import QDateTime, QFileSystemWatcher, Qt
    from PyQt6.QtGui import (
        QAction,
        QColor,
        QKeySequence,
        QSyntaxHighlighter,
        QTextCharFormat,
        QTextCursor,
        QTextDocument,
    )
    from PyQt6.QtWidgets import (
        QPlainTextEdit,
        QStatusBar,
        QToolBar,
    )
except ImportError as e:
    logger.error("Import error in text_editor_dialog: %s", e)
    pass

logger = logging.getLogger(__name__)


class PythonSyntaxHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for Python code."""

    def __init__(self, document: QTextDocument):
        """Initialize the Python syntax highlighter with formatting rules for keywords, strings, comments, and functions."""
        if not HAS_PYQT:
            return

        super().__init__(document)

        # Define syntax highlighting rules
        self.highlighting_rules = []

        # Python keywords
        keyword_format = QTextCharFormat()
        keyword_format.setColor(QColor(85, 85, 255))
        keyword_format.setFontWeight(QFont.Bold)

        keywords = [
            'and', 'as', 'assert', 'break', 'class', 'continue', 'def',
            'del', 'elif', 'else', 'except', 'exec', 'finally', 'for',
            'from', 'global', 'if', 'import', 'in', 'is', 'lambda',
            'not', 'or', 'pass', 'print', 'raise', 'return', 'try',
            'while', 'with', 'yield', 'True', 'False', 'None'
        ]

        for _keyword in keywords:
            pattern = r'\b' + _keyword + r'\b'
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
        self.highlighting_rules.append((re.compile(r'#.*'), comment_format))

        # Numbers
        number_format = QTextCharFormat()
        number_format.setColor(QColor(255, 0, 255))
        self.highlighting_rules.append((re.compile(r'\b\d+\b'), number_format))

        # Functions
        function_format = QTextCharFormat()
        function_format.setColor(QColor(0, 0, 255))
        function_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((re.compile(r'\bdef\s+(\w+)'), function_format))

    def highlightBlock(self, text: str):
        """Apply syntax highlighting to a block of text."""
        if not HAS_PYQT:
            return

        for pattern, text_format in self.highlighting_rules:
            for _match in pattern.finditer(text):
                start = _match.start()
                length = _match.end() - start
                self.setFormat(start, length, text_format)


class FindReplaceDialog(QDialog):
    """Find and replace dialog."""

    def __init__(self, parent=None):
        """Initialize the find and replace dialog for text search and replacement functionality."""
        if not HAS_PYQT:
            return

        super().__init__(parent)
        self.text_editor = parent
        self.setup_ui()

    def setup_ui(self):
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

    def find_next(self):
        """Find next occurrence."""
        if self.text_editor and hasattr(self.text_editor, 'find_text'):
            self.text_editor.find_text(self.find_edit.text(), forward=True)

    def find_previous(self):
        """Find previous occurrence."""
        if self.text_editor and hasattr(self.text_editor, 'find_text'):
            self.text_editor.find_text(self.find_edit.text(), forward=False)

    def replace_current(self):
        """Replace current selection."""
        if self.text_editor and hasattr(self.text_editor, 'replace_text'):
            self.text_editor.replace_text(self.find_edit.text(), self.replace_edit.text())

    def replace_all(self):
        """Replace all occurrences."""
        if self.text_editor and hasattr(self.text_editor, 'replace_all_text'):
            count = self.text_editor.replace_all_text(self.find_edit.text(), self.replace_edit.text())
            if HAS_PYQT:
                QMessageBox.information(self, "Replace All", f"Replaced {count} occurrences")


class TextEditorDialog(QDialog):
    """Advanced text editor dialog for Intellicrack."""

    file_saved = pyqtSignal(str)  # Emitted when file is saved
    content_changed = pyqtSignal(bool)  # Emitted when content changes

    def __init__(self, title="Text Editor", content="", syntax="python", parent=None):
        """Initialize text editor dialog with syntax highlighting and advanced editing features."""
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(800, 600)

        # Editor state
        self.current_file = None
        self.is_modified = False
        self.syntax_mode = syntax
        self.find_replace_dialog = None

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

        # Load settings
        self.load_settings()

        # Track modifications
        self.text_edit.textChanged.connect(self.on_text_changed)

        logger.info(f"Text Editor Dialog initialized with syntax: {syntax}")

    def setup_ui(self):
        """Set up the user interface."""
        self.setWindowTitle("Text Editor")
        self.resize(800, 600)

        # Main layout
        main_layout = QVBoxLayout()

        # Text editor
        self.text_edit = QPlainTextEdit()
        self.text_edit.setFont(QFont("Consolas", 10))
        self.text_edit.textChanged.connect(self.on_content_changed)

        # Enable syntax highlighting for Python files
        if self.file_path and self.file_path.endswith('.py'):
            self.highlighter = PythonSyntaxHighlighter(self.text_edit.document())

        main_layout.addWidget(self.text_edit)

        # Button layout
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
        self.close_btn.clicked.connect(self.close_with_confirmation)

        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.save_as_btn)
        button_layout.addWidget(self.export_btn)
        button_layout.addWidget(self.reload_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.close_btn)

        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def setup_connections(self):
        """Set up signal connections."""
        # Connect text editor signals
        self.text_edit.textChanged.connect(self.on_content_changed)
        self.text_edit.cursorPositionChanged.connect(self.update_cursor_position)

        # Connect action signals (already connected in setup_actions)
        # File watcher is already connected in __init__
        pass

    def setup_actions(self):
        """Set up keyboard shortcuts and actions."""
        # File actions
        self.new_action = QAction("New", self)
        self.new_action.setShortcut(QKeySequence.New)
        self.new_action.triggered.connect(self.new_file)

        self.open_action = QAction("Open", self)
        self.open_action.setShortcut(QKeySequence.Open)
        self.open_action.triggered.connect(self.open_file)

        self.save_action = QAction("Save", self)
        self.save_action.setShortcut(QKeySequence.Save)
        self.save_action.triggered.connect(self.save_file)

        self.save_as_action = QAction("Save As...", self)
        self.save_as_action.setShortcut(QKeySequence.SaveAs)
        self.save_as_action.triggered.connect(self.save_file_as)

        self.export_action = QAction("Export...", self)
        self.export_action.setShortcut(QKeySequence("Ctrl+E"))
        self.export_action.triggered.connect(self.export_file)

        # Edit actions
        self.undo_action = QAction("Undo", self)
        self.undo_action.setShortcut(QKeySequence.Undo)
        self.undo_action.triggered.connect(self.text_edit.undo)

        self.redo_action = QAction("Redo", self)
        self.redo_action.setShortcut(QKeySequence.Redo)
        self.redo_action.triggered.connect(self.text_edit.redo)

        self.cut_action = QAction("Cut", self)
        self.cut_action.setShortcut(QKeySequence.Cut)
        self.cut_action.triggered.connect(self.text_edit.cut)

        self.copy_action = QAction("Copy", self)
        self.copy_action.setShortcut(QKeySequence.Copy)
        self.copy_action.triggered.connect(self.text_edit.copy)

        self.paste_action = QAction("Paste", self)
        self.paste_action.setShortcut(QKeySequence.Paste)
        self.paste_action.triggered.connect(self.text_edit.paste)

        self.select_all_action = QAction("Select All", self)
        self.select_all_action.setShortcut(QKeySequence.SelectAll)
        self.select_all_action.triggered.connect(self.text_edit.selectAll)

        # Find/Replace
        self.find_action = QAction("Find", self)
        self.find_action.setShortcut(QKeySequence.Find)
        self.find_action.triggered.connect(self.show_find_replace)

        self.find_next_action = QAction("Find Next", self)
        self.find_next_action.setShortcut(QKeySequence.FindNext)

        self.find_prev_action = QAction("Find Previous", self)
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

    def setup_toolbar(self):
        """Set up the toolbar."""
        self.toolbar = QToolBar()

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

        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 72)
        self.font_size_spin.setValue(10)
        self.font_size_spin.valueChanged.connect(self.change_font_size)
        self.toolbar.addWidget(self.font_size_spin)

        # Add toolbar to layout
        layout = self.layout()
        layout.insertWidget(0, self.toolbar)

    def setup_status_bar(self):
        """Set up the status bar."""
        self.status_bar = QStatusBar()

        # Line/column indicator
        self.line_col_label = QLabel("Line: 1, Col: 1")
        self.status_bar.addPermanentWidget(self.line_col_label)

        # File status
        self.file_status_label = QLabel("Ready")
        self.status_bar.addWidget(self.file_status_label)

        # Add status bar to layout
        layout = self.layout()
        layout.addWidget(self.status_bar)

        # Update line/column info when cursor moves
        self.text_edit.cursorPositionChanged.connect(self.update_cursor_position)

    def update_cursor_position(self):
        """Update cursor position in status bar."""
        cursor = self.text_edit.textCursor()
        line = cursor.blockNumber() + 1
        col = cursor.columnNumber() + 1
        self.line_col_label.setText(f"Line: {line}, Col: {col}")

    def change_font_size(self, size: int):
        """Change the font size of the text editor."""
        font = self.text_edit.font()
        font.setPointSize(size)
        self.text_edit.setFont(font)

    def on_content_changed(self):
        """Handle content changes."""
        current_content = self.text_edit.toPlainText()
        self.is_modified = current_content != self.original_content

        # Update window title and save button
        title = "Text Editor"
        if self.file_path:
            title += f" - {os.path.basename(self.file_path)}"
        if self.is_modified:
            title += " *"
        self.setWindowTitle(title)

        self.save_btn.setEnabled(self.is_modified)
        self.content_changed.emit(self.is_modified)

    def new_file(self):
        """Create a new file."""
        if self.check_save_changes():
            self.text_edit.clear()
            self.file_path = None
            self.original_content = ""
            self.is_modified = False
            self.setWindowTitle("Text Editor - New File")
            self.reload_btn.setEnabled(False)

    def open_file(self):
        """Open a file."""
        if not self.check_save_changes():
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File",
            "",
            "Text Files (*.txt *.py *.js *.json *.xml *.html *.css);;All Files (*.*)"
        )

        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path: str):
        """Load a file into the editor."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
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
            if file_path.endswith('.py'):
                self.highlighter = PythonSyntaxHighlighter(self.text_edit.document())

            # Watch for external changes
            if self.file_watcher:
                self.file_watcher.removePaths(self.file_watcher.files())
                self.file_watcher.addPath(file_path)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in text_editor_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Failed to load file: {str(e)}")

    def save_file(self):
        """Save the current file."""
        if not self.file_path:
            self.save_file_as()
            return

        try:
            content = self.text_edit.toPlainText()

            with open(self.file_path, 'w', encoding='utf-8') as f:
                f.write(content)

            self.original_content = content
            self.is_modified = False
            self.save_btn.setEnabled(False)

            self.file_status_label.setText(f"Saved: {self.file_path}")
            self.setWindowTitle(f"Text Editor - {os.path.basename(self.file_path)}")

            self.file_saved.emit(self.file_path)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in text_editor_dialog: %s", e)
            QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")

    def save_file_as(self):
        """Save the file with a new name."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save File",
            self.file_path or "untitled.txt",
            "Text Files (*.txt *.py *.js *.json *.xml *.html *.css);;All Files (*.*)"
        )

        if file_path:
            self.file_path = file_path
            self.save_file()
            self.reload_btn.setEnabled(True)

    def export_file(self):
        """Export the file to various formats."""
        export_dialog = QDialog(self)
        export_dialog.setWindowTitle("Export File")
        export_dialog.setModal(True)

        layout = QVBoxLayout()

        # Format selection
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
            "JSON (.json)"
        ])
        layout.addWidget(format_combo)

        # Options
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

        # Buttons
        button_layout = QHBoxLayout()
        export_btn = QPushButton("Export")
        cancel_btn = QPushButton("Cancel")
        button_layout.addWidget(export_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        export_dialog.setLayout(layout)

        # Connect buttons
        export_btn.clicked.connect(lambda: self._perform_export(
            format_combo.currentText(),
            include_highlighting.isChecked(),
            include_line_numbers.isChecked(),
            export_dialog
        ))
        cancel_btn.clicked.connect(export_dialog.reject)

        export_dialog.exec()

    def _perform_export(self, format_type, include_highlighting, include_line_numbers, dialog):
        """Perform the actual export operation."""
        # Determine file extension
        format_map = {
            "HTML (.html)": ("html", "HTML Files (*.html)"),
            "PDF (.pdf)": ("pdf", "PDF Files (*.pdf)"),
            "Rich Text Format (.rtf)": ("rtf", "RTF Files (*.rtf)"),
            "Markdown (.md)": ("md", "Markdown Files (*.md)"),
            "Plain Text (.txt)": ("txt", "Text Files (*.txt)"),
            "CSV (.csv)": ("csv", "CSV Files (*.csv)"),
            "JSON (.json)": ("json", "JSON Files (*.json)")
        }

        ext, file_filter = format_map.get(format_type, ("txt", "Text Files (*.txt)"))

        # Get save path
        default_name = os.path.splitext(self.file_path or "untitled")[0] + f".{ext}"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export as {format_type}",
            default_name,
            file_filter
        )

        if not file_path:
            dialog.reject()
            return

        try:
            content = self.text_edit.toPlainText()

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
                with open(file_path, 'w', encoding='utf-8') as f:
                    if include_line_numbers:
                        lines = content.split('\n')
                        numbered_content = '\n'.join(f"{i+1:4d}: {line}" for i, line in enumerate(lines))
                        f.write(numbered_content)
                    else:
                        f.write(content)

            QMessageBox.information(self, "Export Successful", f"File exported to:\n{file_path}")
            dialog.accept()

        except Exception as e:
            logger.error(f"Export failed: {e}")
            QMessageBox.critical(self, "Export Failed", f"Failed to export file:\n{str(e)}")

    def _export_to_html(self, file_path, content, include_highlighting, include_line_numbers):
        """Export content to HTML format."""
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

        if include_highlighting and self.file_path and self.file_path.endswith('.py'):
            # Simple Python syntax highlighting
            formatted_content = self._apply_python_highlighting(content, include_line_numbers)
        else:
            if include_line_numbers:
                lines = content.split('\n')
                formatted_content = '\n'.join(
                    f'<span class="line-number">{i+1:4d}:</span> {self._escape_html(line)}'
                    for i, line in enumerate(lines)
                )
            else:
                formatted_content = self._escape_html(content)

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content.format(title=title, content=formatted_content))

    def _export_to_pdf(self, file_path, content, include_highlighting, include_line_numbers):
        """Export content to PDF format."""
        try:
            from PyQt6.QtGui import QTextDocument
            from PyQt6.QtPrintSupport import QPrinter

            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(file_path)

            document = QTextDocument()

            # Set font
            font = QFont("Consolas", 10)
            document.setDefaultFont(font)

            # Format content
            if include_line_numbers:
                lines = content.split('\n')
                formatted_content = '\n'.join(f"{i+1:4d}: {line}" for i, line in enumerate(lines))
            else:
                formatted_content = content

            # Apply highlighting if requested
            if include_highlighting and self.file_path and self.file_path.endswith('.py'):
                document.setHtml(self._get_highlighted_html(formatted_content))
            else:
                document.setPlainText(formatted_content)

            document.print(printer)

        except ImportError:
            # Fallback if PyQt6.QtPrintSupport is not available
            QMessageBox.warning(self, "PDF Export",
                               "PDF export requires PyQt6.QtPrintSupport. Saving as text instead.")
            with open(file_path.replace('.pdf', '.txt'), 'w', encoding='utf-8') as f:
                f.write(content)

    def _export_to_rtf(self, file_path, content, include_line_numbers):
        """Export content to RTF format."""
        rtf_header = r"{\rtf1\ansi\deff0 {\fonttbl{\f0 Courier New;}}\f0\fs20 "
        rtf_footer = "}"

        # Escape RTF special characters
        rtf_content = content.replace('\\', '\\\\').replace('{', '\\{').replace('}', '\\}')
        rtf_content = rtf_content.replace('\n', '\\par\n')

        if include_line_numbers:
            lines = rtf_content.split('\\par\n')
            rtf_content = '\\par\n'.join(f"{i+1:4d}: {line}" for i, line in enumerate(lines))

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(rtf_header + rtf_content + rtf_footer)

    def _export_to_markdown(self, file_path, content):
        """Export content to Markdown format."""
        # Detect language for code block
        lang = ""
        if self.file_path:
            ext = os.path.splitext(self.file_path)[1].lower()
            lang_map = {
                '.py': 'python', '.js': 'javascript', '.java': 'java',
                '.cpp': 'cpp', '.c': 'c', '.cs': 'csharp',
                '.html': 'html', '.css': 'css', '.json': 'json'
            }
            lang = lang_map.get(ext, '')

        md_content = f"# {os.path.basename(self.file_path or 'Code Export')}\n\n"
        md_content += f"```{lang}\n{content}\n```\n"

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

    def _export_to_csv(self, file_path, content):
        """Export content to CSV format (line by line)."""
        import csv

        lines = content.split('\n')
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Line Number', 'Content'])
            for i, line in enumerate(lines, 1):
                writer.writerow([i, line])

    def _export_to_json(self, file_path, content):
        """Export content to JSON format."""
        import json

        data = {
            'filename': os.path.basename(self.file_path or 'untitled'),
            'content': content,
            'lines': content.split('\n'),
            'line_count': len(content.split('\n')),
            'character_count': len(content),
            'export_date': QDateTime.currentDateTime().toString(Qt.DateFormat.ISODate)
        }

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _escape_html(self, text):
        """Escape HTML special characters."""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def _apply_python_highlighting(self, content, include_line_numbers):
        """Apply simple Python syntax highlighting for HTML export."""
        import re

        # Escape HTML first
        content = self._escape_html(content)

        # Python keywords
        keywords = r'\b(and|as|assert|break|class|continue|def|del|elif|else|except|' \
                  r'finally|for|from|global|if|import|in|is|lambda|not|or|pass|raise|' \
                  r'return|try|while|with|yield|None|True|False)\b'

        # Apply highlighting
        content = re.sub(keywords, r'<span class="keyword">\1</span>', content)
        content = re.sub(r'#.*$', lambda m: f'<span class="comment">{m.group()}</span>', content, flags=re.MULTILINE)
        content = re.sub(r'"[^"]*"|\'[^\']*\'', lambda m: f'<span class="string">{m.group()}</span>', content)
        content = re.sub(r'\b\d+\b', lambda m: f'<span class="number">{m.group()}</span>', content)
        content = re.sub(r'\bdef\s+(\w+)', r'def <span class="function">\1</span>', content)

        if include_line_numbers:
            lines = content.split('\n')
            content = '\n'.join(
                f'<span class="line-number">{i+1:4d}:</span> {line}'
                for i, line in enumerate(lines)
            )

        return content

    def _get_highlighted_html(self, content):
        """Get HTML with syntax highlighting for PDF export."""
        html = f"""<html>
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

    def reload_file(self):
        """Reload the file from disk."""
        if not self.file_path:
            return

        if self.is_modified:
            reply = QMessageBox.question(
                self,
                "Reload File",
                "The file has been modified. Reload and lose changes?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return

        self.load_file(self.file_path)

    def on_file_changed_externally(self, file_path: str):
        """Handle external file changes."""
        if file_path == self.file_path:
            reply = QMessageBox.question(
                self,
                "File Changed",
                "The file has been changed externally. Reload?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.load_file(file_path)

    def show_find_replace(self):
        """Show the find/replace dialog."""
        if not self.find_replace_dialog:
            self.find_replace_dialog = FindReplaceDialog(self)

        self.find_replace_dialog.show()
        self.find_replace_dialog.raise_()
        self.find_replace_dialog.activateWindow()

    def find_text(self, text: str, forward: bool = True):
        """Find text in the editor."""
        if not text:
            return

        flags = QTextDocument.FindFlags()
        if not forward:
            flags |= QTextDocument.FindBackward

        if not self.text_edit.find(text, flags):
            # If not found, start from beginning/end
            cursor = self.text_edit.textCursor()
            if forward:
                cursor.movePosition(QTextCursor.Start)
            else:
                cursor.movePosition(QTextCursor.End)
            self.text_edit.setTextCursor(cursor)

            # Try again
            if not self.text_edit.find(text, flags):
                QMessageBox.information(self, "Find", f"'{text}' not found")

    def replace_text(self, find_text: str, replace_text: str):
        """Replace current selection."""
        cursor = self.text_edit.textCursor()
        if cursor.hasSelection() and cursor.selectedText() == find_text:
            cursor.insertText(replace_text)

    def replace_all_text(self, find_text: str, replace_text: str) -> int:
        """Replace all occurrences of text."""
        content = self.text_edit.toPlainText()
        new_content = content.replace(find_text, replace_text)
        count = content.count(find_text)

        if count > 0:
            self.text_edit.setPlainText(new_content)

        return count

    def check_save_changes(self) -> bool:
        """Check if there are unsaved changes and ask user."""
        if not self.is_modified:
            return True

        reply = QMessageBox.question(
            self,
            "Unsaved Changes",
            "The document has been modified. Save changes?",
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel
        )

        if reply == QMessageBox.Save:
            self.save_file()
            return not self.is_modified  # Return False if save failed
        elif reply == QMessageBox.Discard:
            return True
        else:  # Cancel
            return False

    def close_with_confirmation(self):
        """Close the dialog with save confirmation."""
        if self.check_save_changes():
            self.accept()

    def closeEvent(self, event):
        """Handle close event."""
        if self.check_save_changes():
            event.accept()
        else:
            event.ignore()


# Export for external use
__all__ = ['TextEditorDialog', 'PythonSyntaxHighlighter', 'FindReplaceDialog']
