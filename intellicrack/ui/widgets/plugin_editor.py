"""
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import ast
import importlib
from typing import Dict, List, Tuple

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel,
    QPushButton, QComboBox, QSplitter, QFrame, QListWidget,
    QListWidgetItem, QMenu, QAction, QMessageBox, QToolBar,
    QStatusBar, QFileDialog
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QRegExp
from PyQt5.QtGui import (
    QFont, QColor, QTextCharFormat, QSyntaxHighlighter,
    QTextDocument, QTextCursor, QKeySequence
)


class PluginValidator:
    """Validates plugin code for syntax and structure"""
    
    @staticmethod
    def validate_syntax(code: str) -> Tuple[bool, List[str]]:
        """Validate Python syntax"""
        errors = []
        try:
            ast.parse(code)
            return True, []
        except SyntaxError as e:
            errors.append(f"Line {e.lineno}: {e.msg}")
            return False, errors
    
    @staticmethod
    def validate_structure(code: str) -> Tuple[bool, List[str]]:
        """Validate plugin structure requirements"""
        errors = []
        try:
            tree = ast.parse(code)
            
            # Check for required methods
            has_run = False
            has_get_metadata = False
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if node.name == 'run':
                        has_run = True
                    elif node.name == 'get_metadata':
                        has_get_metadata = True
                elif isinstance(node, ast.ClassDef):
                    # Check methods in classes
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            if item.name == 'run':
                                has_run = True
                            elif item.name == 'get_metadata':
                                has_get_metadata = True
            
            if not has_run:
                errors.append("Missing required 'run' method")
            
            return len(errors) == 0, errors
            
        except Exception as e:
            errors.append(f"Structure validation error: {str(e)}")
            return False, errors
    
    @staticmethod
    def validate_imports(code: str) -> Tuple[bool, List[str]]:
        """Check if imports are available"""
        warnings = []
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        try:
                            importlib.import_module(alias.name)
                        except ImportError:
                            warnings.append(f"Module not found: {alias.name}")
                            
                elif isinstance(node, ast.ImportFrom):
                    try:
                        importlib.import_module(node.module)
                    except ImportError:
                        warnings.append(f"Module not found: {node.module}")
            
            return True, warnings
            
        except Exception as e:
            return False, [f"Import validation error: {str(e)}"]


class PythonHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for Python code"""
    
    def __init__(self, document):
        super().__init__(document)
        
        # Define highlighting rules
        self.highlighting_rules = []
        
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(86, 156, 214))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            'and', 'as', 'assert', 'break', 'class', 'continue', 'def',
            'del', 'elif', 'else', 'except', 'False', 'finally', 'for',
            'from', 'global', 'if', 'import', 'in', 'is', 'lambda',
            'None', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return',
            'True', 'try', 'while', 'with', 'yield'
        ]
        for keyword in keywords:
            pattern = QRegExp(f'\\b{keyword}\\b')
            self.highlighting_rules.append((pattern, keyword_format))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor(214, 157, 133))
        self.highlighting_rules.append((QRegExp('"[^"]*"'), string_format))
        self.highlighting_rules.append((QRegExp("'[^']*'"), string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(106, 153, 85))
        self.highlighting_rules.append((QRegExp('#.*'), comment_format))
        
        # Functions
        function_format = QTextCharFormat()
        function_format.setForeground(QColor(220, 220, 170))
        self.highlighting_rules.append((QRegExp('\\b[A-Za-z0-9_]+(?=\\()'), function_format))
        
        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor(181, 206, 168))
        self.highlighting_rules.append((QRegExp('\\b[0-9]+\\b'), number_format))
        
        # Multi-line strings
        self.triple_single_quote_format = QTextCharFormat()
        self.triple_single_quote_format.setForeground(QColor(214, 157, 133))
        self.triple_double_quote_format = QTextCharFormat()
        self.triple_double_quote_format.setForeground(QColor(214, 157, 133))
    
    def highlightBlock(self, text):
        """Apply syntax highlighting to block"""
        # Single line rules
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)
        
        self.setCurrentBlockState(0)
        
        # Multi-line strings
        self.match_multiline_string(text, QRegExp('"""'), 1, self.triple_double_quote_format)
        self.match_multiline_string(text, QRegExp("'''"), 2, self.triple_single_quote_format)
    
    def match_multiline_string(self, text, expression, state, format):
        """Handle multi-line string highlighting"""
        if self.previousBlockState() == state:
            start = 0
            add = 0
        else:
            start = expression.indexIn(text)
            add = expression.matchedLength()
        
        while start >= 0:
            end = expression.indexIn(text, start + add)
            if end == -1:
                self.setCurrentBlockState(state)
                comment_length = len(text) - start
            else:
                comment_length = end - start + expression.matchedLength()
            
            self.setFormat(start, comment_length, format)
            start = expression.indexIn(text, start + comment_length)


class JavaScriptHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for JavaScript/Frida code"""
    
    def __init__(self, document):
        super().__init__(document)
        
        # Define highlighting rules
        self.highlighting_rules = []
        
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor(86, 156, 214))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            'break', 'case', 'catch', 'class', 'const', 'continue',
            'debugger', 'default', 'delete', 'do', 'else', 'export',
            'extends', 'finally', 'for', 'function', 'if', 'import',
            'in', 'instanceof', 'let', 'new', 'return', 'super',
            'switch', 'this', 'throw', 'try', 'typeof', 'var',
            'void', 'while', 'with', 'yield'
        ]
        for keyword in keywords:
            pattern = QRegExp(f'\\b{keyword}\\b')
            self.highlighting_rules.append((pattern, keyword_format))
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor(214, 157, 133))
        self.highlighting_rules.append((QRegExp('"[^"]*"'), string_format))
        self.highlighting_rules.append((QRegExp("'[^']*'"), string_format))
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor(106, 153, 85))
        self.highlighting_rules.append((QRegExp('//.*'), comment_format))
        
        # Functions
        function_format = QTextCharFormat()
        function_format.setForeground(QColor(220, 220, 170))
        self.highlighting_rules.append((QRegExp('\\b[A-Za-z0-9_]+(?=\\()'), function_format))
        
        # Numbers
        number_format = QTextCharFormat()
        number_format.setForeground(QColor(181, 206, 168))
        self.highlighting_rules.append((QRegExp('\\b[0-9]+\\b'), number_format))
    
    def highlightBlock(self, text):
        """Apply syntax highlighting to block"""
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)


class PluginEditor(QWidget):
    """Enhanced plugin editor with syntax highlighting and validation"""
    
    textChanged = pyqtSignal()
    validationComplete = pyqtSignal(dict)
    saveRequested = pyqtSignal(str)  # Emits file path
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_file = None
        self.validator = PluginValidator()
        self.validation_timer = QTimer()
        self.validation_timer.timeout.connect(self.perform_validation)
        self.validation_timer.setSingleShot(True)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the editor UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Toolbar
        toolbar = QToolBar()
        
        # File actions
        new_action = toolbar.addAction("📄 New")
        new_action.triggered.connect(self.new_file)
        
        open_action = toolbar.addAction("📂 Open")
        open_action.triggered.connect(self.open_file)
        
        save_action = toolbar.addAction("💾 Save")
        save_action.setShortcut(QKeySequence.Save)
        save_action.triggered.connect(self.save_file)
        
        toolbar.addSeparator()
        
        # Edit actions
        undo_action = toolbar.addAction("↶ Undo")
        undo_action.setShortcut(QKeySequence.Undo)
        
        redo_action = toolbar.addAction("↷ Redo")
        redo_action.setShortcut(QKeySequence.Redo)
        
        toolbar.addSeparator()
        
        # Validation action
        validate_action = toolbar.addAction("✓ Validate")
        validate_action.triggered.connect(self.perform_validation)
        
        layout.addWidget(toolbar)
        
        # Main content area
        splitter = QSplitter(Qt.Horizontal)
        
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
        undo_action.triggered.connect(self.editor.undo)
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
        self.editor.setContextMenuPolicy(Qt.CustomContextMenu)
        self.editor.customContextMenuRequested.connect(self.show_context_menu)
    
    def new_file(self):
        """Create a new file"""
        if self.editor.document().isModified():
            reply = QMessageBox.question(
                self, "Unsaved Changes",
                "Do you want to save your changes?",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
            )
            if reply == QMessageBox.Yes:
                self.save_file()
            elif reply == QMessageBox.Cancel:
                return
        
        self.editor.clear()
        self.current_file = None
        self.file_label.setText("Untitled")
        self.status_bar.showMessage("New file created")
    
    def open_file(self):
        """Open a file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Plugin",
            "", "Plugin Files (*.py *.js);;All Files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                self.editor.setPlainText(content)
                self.current_file = file_path
                self.file_label.setText(os.path.basename(file_path))
                
                # Auto-detect syntax
                if file_path.endswith('.js'):
                    self.syntax_combo.setCurrentText("JavaScript")
                elif file_path.endswith('.py'):
                    self.syntax_combo.setCurrentText("Python")
                
                self.status_bar.showMessage(f"Opened {file_path}")
                self.editor.document().setModified(False)
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open file:\n{str(e)}")
    
    def save_file(self):
        """Save the current file"""
        if not self.current_file:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save Plugin",
                "", "Python Files (*.py);;JavaScript Files (*.js);;All Files (*.*)"
            )
            if not file_path:
                return
            self.current_file = file_path
        
        try:
            with open(self.current_file, 'w') as f:
                f.write(self.editor.toPlainText())
            
            self.file_label.setText(os.path.basename(self.current_file))
            self.status_bar.showMessage(f"Saved {self.current_file}")
            self.editor.document().setModified(False)
            self.saveRequested.emit(self.current_file)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save file:\n{str(e)}")
    
    def on_text_changed(self):
        """Handle text changes"""
        self.textChanged.emit()
        
        # Start validation timer
        self.validation_timer.stop()
        self.validation_timer.start(1000)  # Validate after 1 second of no typing
        
        # Update code outline
        self.update_code_outline()
    
    def change_syntax(self, syntax):
        """Change syntax highlighting"""
        if syntax == "Python":
            self.highlighter = PythonHighlighter(self.editor.document())
        elif syntax == "JavaScript":
            self.highlighter = JavaScriptHighlighter(self.editor.document())
        else:
            self.highlighter = None
    
    def perform_validation(self):
        """Validate the current code"""
        self.validation_list.clear()
        
        code = self.editor.toPlainText()
        if not code.strip():
            return
        
        # Only validate Python code
        if self.syntax_combo.currentText() != "Python":
            item = QListWidgetItem("ℹ️ Validation only available for Python")
            self.validation_list.addItem(item)
            return
        
        # Syntax validation
        syntax_valid, syntax_errors = self.validator.validate_syntax(code)
        if not syntax_valid:
            for error in syntax_errors:
                item = QListWidgetItem(f"❌ Syntax: {error}")
                item.setForeground(QColor(255, 0, 0))
                self.validation_list.addItem(item)
        
        # Structure validation
        if syntax_valid:
            structure_valid, structure_errors = self.validator.validate_structure(code)
            for error in structure_errors:
                item = QListWidgetItem(f"⚠️ Structure: {error}")
                item.setForeground(QColor(255, 165, 0))
                self.validation_list.addItem(item)
            
            # Import validation
            imports_valid, import_warnings = self.validator.validate_imports(code)
            for warning in import_warnings:
                item = QListWidgetItem(f"⚠️ Import: {warning}")
                item.setForeground(QColor(255, 165, 0))
                self.validation_list.addItem(item)
        
        if self.validation_list.count() == 0:
            item = QListWidgetItem("✅ Validation passed!")
            item.setForeground(QColor(0, 255, 0))
            self.validation_list.addItem(item)
        
        # Emit validation results
        results = {
            'valid': syntax_valid and self.validation_list.count() == 1,
            'errors': syntax_errors + (structure_errors if syntax_valid else []),
            'warnings': import_warnings if syntax_valid else []
        }
        self.validationComplete.emit(results)
    
    def update_code_outline(self):
        """Update the code outline"""
        self.outline_list.clear()
        
        code = self.editor.toPlainText()
        if not code.strip() or self.syntax_combo.currentText() != "Python":
            return
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    item = QListWidgetItem(f"📦 {node.name}")
                    self.outline_list.addItem(item)
                    
                    # Add methods
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            method_item = QListWidgetItem(f"  🔧 {item.name}")
                            self.outline_list.addItem(method_item)
                
                elif isinstance(node, ast.FunctionDef) and node.col_offset == 0:
                    item = QListWidgetItem(f"🔧 {node.name}")
                    self.outline_list.addItem(item)
                    
        except:
            pass  # Ignore parsing errors during typing
    
    def show_context_menu(self, position):
        """Show context menu"""
        menu = QMenu(self)
        
        # Add actions
        cut_action = menu.addAction("Cut")
        cut_action.setShortcut(QKeySequence.Cut)
        cut_action.triggered.connect(self.editor.cut)
        
        copy_action = menu.addAction("Copy")
        copy_action.setShortcut(QKeySequence.Copy)
        copy_action.triggered.connect(self.editor.copy)
        
        paste_action = menu.addAction("Paste")
        paste_action.setShortcut(QKeySequence.Paste)
        paste_action.triggered.connect(self.editor.paste)
        
        menu.addSeparator()
        
        # Find/Replace
        find_action = menu.addAction("Find...")
        find_action.setShortcut(QKeySequence.Find)
        find_action.triggered.connect(self.show_find_dialog)
        
        menu.exec_(self.editor.mapToGlobal(position))
    
    def show_find_dialog(self):
        """Show find/replace dialog"""
        # Simple find implementation
        from PyQt5.QtWidgets import QInputDialog
        text, ok = QInputDialog.getText(self, "Find", "Find text:")
        if ok and text:
            cursor = self.editor.textCursor()
            found = self.editor.find(text)
            if not found:
                # Try from beginning
                cursor.movePosition(QTextCursor.Start)
                self.editor.setTextCursor(cursor)
                self.editor.find(text)
    
    def get_code(self):
        """Get the current code"""
        return self.editor.toPlainText()
    
    def set_code(self, code):
        """Set the editor code"""
        self.editor.setPlainText(code)