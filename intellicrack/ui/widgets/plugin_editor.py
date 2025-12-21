"""Plugin editor widget for editing and managing plugin code.

Enhanced Plugin Editor with syntax highlighting and validation.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import ast
import os

from PyQt6.QtCore import QPoint, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont, QKeySequence, QTextCursor, QTextDocument
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QSplitter,
    QStatusBar,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.utils.logger import logger

from .syntax_highlighters import JavaScriptHighlighter, PythonHighlighter


class PluginValidator:
    """Validates plugin code for syntax and structure."""

    @staticmethod
    def validate_syntax(code: str) -> tuple[bool, list[str]]:
        """Validate Python syntax."""
        errors = []
        try:
            ast.parse(code)
            return True, []
        except SyntaxError as e:
            logger.error("SyntaxError in plugin_editor: %s", e)
            errors.append(f"Line {e.lineno}: {e.msg}")
            return False, errors

    @staticmethod
    def validate_structure(code: str) -> tuple[bool, list[str]]:
        """Validate plugin structure requirements."""
        from ...utils.validation.import_validator import PluginStructureValidator

        # Plugin editor checks for both 'run' and 'get_metadata' methods
        return PluginStructureValidator.validate_structure_from_code(
            code,
            {"run", "get_metadata"},
        )

    @staticmethod
    def validate_imports(code: str) -> tuple[bool, list[str]]:
        """Check if imports are available."""
        from ...utils.validation.import_validator import validate_imports

        return validate_imports(code)


class PluginEditor(QWidget):
    """Enhanced plugin editor with syntax highlighting and validation."""

    text_changed = pyqtSignal()
    validation_complete = pyqtSignal(dict)
    #: Emits file path (type: str)
    save_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize plugin editor with validation and UI setup."""
        super().__init__(parent)
        self.current_file: str | None = None
        self.validator: PluginValidator = PluginValidator()
        self.validation_timer: QTimer = QTimer()
        self.validation_timer.timeout.connect(self.perform_validation)
        self.validation_timer.setSingleShot(True)
        self.file_label: QLabel
        self.syntax_combo: QComboBox
        self.editor: QTextEdit
        self.highlighter: PythonHighlighter | JavaScriptHighlighter | None
        self.validation_list: QListWidget
        self.outline_list: QListWidget
        self.status_bar: QStatusBar
        self.setup_ui()

    def setup_ui(self) -> None:
        """Set up the editor UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Toolbar
        toolbar = QToolBar()

        if new_action := toolbar.addAction("📄 New"):
            new_action.triggered.connect(self.new_file)

        if open_action := toolbar.addAction("📂 Open"):
            open_action.triggered.connect(self.open_file)

        if save_action := toolbar.addAction(" Save"):
            save_action.setShortcut(QKeySequence.StandardKey.Save)
            save_action.triggered.connect(self.save_file)

        toolbar.addSeparator()

        # Edit actions
        undo_action: QAction | None = toolbar.addAction("↶ Undo")
        if undo_action:
            undo_action.setShortcut(QKeySequence.StandardKey.Undo)

        redo_action: QAction | None = toolbar.addAction("↷ Redo")
        if redo_action:
            redo_action.setShortcut(QKeySequence.StandardKey.Redo)

        toolbar.addSeparator()

        if validate_action := toolbar.addAction("OK Validate"):
            validate_action.triggered.connect(self.perform_validation)

        layout.addWidget(toolbar)

        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Code editor
        editor_widget = QWidget()
        editor_layout = QVBoxLayout(editor_widget)
        editor_layout.setContentsMargins(0, 0, 0, 0)

        # Editor header
        header_layout = QHBoxLayout()
        self.file_label = QLabel("Untitled")
        self.file_label.setStyleSheet("font-weight: bold;")
        header_layout.addWidget(self.file_label)

        self.syntax_combo = QComboBox()
        self.syntax_combo.addItems(["Python", "JavaScript", "Plain Text"])
        self.syntax_combo.currentTextChanged.connect(self.change_syntax)
        header_layout.addWidget(self.syntax_combo)

        editor_layout.addLayout(header_layout)

        # Text editor
        self.editor = QTextEdit()
        self.editor.setFont(QFont("Consolas", 10))
        self.editor.textChanged.connect(self.on_text_changed)

        # Connect undo/redo
        if undo_action:
            undo_action.triggered.connect(self.editor.undo)
        if redo_action:
            redo_action.triggered.connect(self.editor.redo)

        # Set up syntax highlighter
        self.highlighter = PythonHighlighter(self.editor.document())

        editor_layout.addWidget(self.editor)

        splitter.addWidget(editor_widget)

        # Side panel
        side_panel = QWidget()
        side_layout = QVBoxLayout(side_panel)
        side_layout.setContentsMargins(0, 0, 0, 0)

        # Validation results
        validation_label = QLabel("Validation Results")
        validation_label.setStyleSheet("font-weight: bold;")
        side_layout.addWidget(validation_label)

        self.validation_list = QListWidget()
        side_layout.addWidget(self.validation_list)

        # Code outline
        outline_label = QLabel("Code Outline")
        outline_label.setStyleSheet("font-weight: bold;")
        side_layout.addWidget(outline_label)

        self.outline_list = QListWidget()
        side_layout.addWidget(self.outline_list)

        splitter.addWidget(side_panel)
        splitter.setSizes([700, 300])

        layout.addWidget(splitter)

        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.showMessage("Ready")
        layout.addWidget(self.status_bar)

        # Set up context menu
        self.editor.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.editor.customContextMenuRequested.connect(self.show_context_menu)

    def new_file(self) -> None:
        """Create a new file."""
        doc: QTextDocument | None = self.editor.document()
        if doc and doc.isModified():
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "Do you want to save your changes?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.save_file()
            elif reply == QMessageBox.StandardButton.Cancel:
                return

        self.editor.clear()
        self.current_file = None
        self.file_label.setText("Untitled")
        self.status_bar.showMessage("New file created")

    def open_file(self) -> None:
        """Open a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Plugin",
            "",
            "Plugin Files (*.py *.js);;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()

                self.editor.setPlainText(content)
                self.current_file = file_path
                self.file_label.setText(os.path.basename(file_path))

                # Auto-detect syntax
                if file_path.endswith(".js"):
                    self.syntax_combo.setCurrentText("JavaScript")
                elif file_path.endswith(".py"):
                    self.syntax_combo.setCurrentText("Python")

                self.status_bar.showMessage(f"Opened {file_path}")
                if doc := self.editor.document():
                    doc.setModified(False)

            except Exception as e:
                logger.error("Exception in plugin_editor: %s", e)
                QMessageBox.critical(self, "Error", f"Failed to open file:\n{e!s}")

    def save_file(self) -> None:
        """Save the current file."""
        if not self.current_file:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Plugin",
                "",
                "Python Files (*.py);;JavaScript Files (*.js);;All Files (*.*)",
            )
            if not file_path:
                return
            self.current_file = file_path

        try:
            with open(self.current_file, "w", encoding="utf-8") as f:
                f.write(self.editor.toPlainText())

            self.file_label.setText(os.path.basename(self.current_file))
            self.status_bar.showMessage(f"Saved {self.current_file}")
            if doc := self.editor.document():
                doc.setModified(False)
            self.save_requested.emit(self.current_file)

        except Exception as e:
            logger.error("Exception in plugin_editor: %s", e)
            QMessageBox.critical(self, "Error", f"Failed to save file:\n{e!s}")

    def on_text_changed(self) -> None:
        """Handle text changes."""
        self.text_changed.emit()

        # Start validation timer
        self.validation_timer.stop()
        self.validation_timer.start(1000)  # Validate after 1 second of no typing

        # Update code outline
        self.update_code_outline()

    def change_syntax(self, syntax: str) -> None:
        """Change syntax highlighting."""
        doc: QTextDocument | None = self.editor.document()
        if not doc:
            return
        if syntax == "Python":
            self.highlighter = PythonHighlighter(doc)
        elif syntax == "JavaScript":
            self.highlighter = JavaScriptHighlighter(doc)
        else:
            self.highlighter = None

    def perform_validation(self) -> None:
        """Validate the current code."""
        self.validation_list.clear()

        code = self.editor.toPlainText()
        if not code.strip():
            return

        # Only validate Python code
        if self.syntax_combo.currentText() != "Python":
            item = QListWidgetItem("i Validation only available for Python")
            self.validation_list.addItem(item)
            return

        # Syntax validation
        syntax_valid, syntax_errors = self.validator.validate_syntax(code)
        if not syntax_valid:
            for error in syntax_errors:
                item = QListWidgetItem(f"ERROR Syntax: {error}")
                item.setForeground(QColor(255, 0, 0))
                self.validation_list.addItem(item)

        # Structure validation
        if syntax_valid:
            _structure_valid, structure_errors = self.validator.validate_structure(code)
            for error in structure_errors:
                item = QListWidgetItem(f"WARNING️ Structure: {error}")
                item.setForeground(QColor(255, 165, 0))
                self.validation_list.addItem(item)

            # Import validation
            _imports_valid, import_warnings = self.validator.validate_imports(code)
            for warning in import_warnings:
                item = QListWidgetItem(f"WARNING️ Import: {warning}")
                item.setForeground(QColor(255, 165, 0))
                self.validation_list.addItem(item)

        if self.validation_list.count() == 0:
            item = QListWidgetItem("OK Validation passed!")
            item.setForeground(QColor(0, 255, 0))
            self.validation_list.addItem(item)

        # Emit validation results
        results = {
            "valid": syntax_valid and self.validation_list.count() == 1,
            "errors": syntax_errors + (structure_errors if syntax_valid else []),
            "warnings": import_warnings if syntax_valid else [],
        }
        self.validation_complete.emit(results)

    def update_code_outline(self) -> None:
        """Update the code outline."""
        self.outline_list.clear()

        code = self.editor.toPlainText()
        if not code.strip() or self.syntax_combo.currentText() != "Python":
            return

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_item = QListWidgetItem(f" {node.name}")
                    self.outline_list.addItem(class_item)

                    # Add methods
                    for body_item in node.body:
                        if isinstance(body_item, ast.FunctionDef):
                            method_item = QListWidgetItem(f"   {body_item.name}")
                            self.outline_list.addItem(method_item)

                elif isinstance(node, ast.FunctionDef) and node.col_offset == 0:
                    item = QListWidgetItem(f" {node.name}")
                    self.outline_list.addItem(item)

        except Exception as e:
            logger.debug("Failed to parse code for outline: %s", e)

    def show_context_menu(self, position: QPoint) -> None:
        """Show context menu."""
        menu = QMenu(self)

        if cut_action := menu.addAction("Cut"):
            cut_action.setShortcut(QKeySequence.StandardKey.Cut)
            cut_action.triggered.connect(self.editor.cut)

        if copy_action := menu.addAction("Copy"):
            copy_action.setShortcut(QKeySequence.StandardKey.Copy)
            copy_action.triggered.connect(self.editor.copy)

        if paste_action := menu.addAction("Paste"):
            paste_action.setShortcut(QKeySequence.StandardKey.Paste)
            paste_action.triggered.connect(self.editor.paste)

        menu.addSeparator()

        if find_action := menu.addAction("Find..."):
            find_action.setShortcut(QKeySequence.StandardKey.Find)
            find_action.triggered.connect(self.show_find_dialog)

        menu.exec(self.editor.mapToGlobal(position))

    def show_find_dialog(self) -> None:
        """Show find/replace dialog."""
        # Simple find implementation
        from intellicrack.handlers.pyqt6_handler import QInputDialog

        text, ok = QInputDialog.getText(self, "Find", "Find text:")
        if ok and text:
            cursor: QTextCursor = self.editor.textCursor()
            found: bool = self.editor.find(text)
            if not found:
                # Try from beginning
                cursor.movePosition(QTextCursor.MoveOperation.Start)
                self.editor.setTextCursor(cursor)
                self.editor.find(text)

    def get_code(self) -> str:
        """Get the current code."""
        return self.editor.toPlainText()

    def set_code(self, code: str) -> None:
        """Set the editor code."""
        self.editor.setPlainText(code)
