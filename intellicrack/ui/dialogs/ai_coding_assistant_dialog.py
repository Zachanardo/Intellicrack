"""AI Coding Assistant Dialog with Three-Panel Layout

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

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QAction,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFileSystemWatcher,
    QFont,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenuBar,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStatusBar,
    Qt,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ...utils.logger import get_logger
from ..widgets.syntax_highlighters import JavaScriptHighlighter, PythonHighlighter

logger = get_logger(__name__)






class FileTreeWidget(QTreeWidget):
    """Enhanced file tree widget with project navigation."""

    file_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        """Initialize the FileTreeWidget with default values."""
        super().__init__(parent)
        self.setHeaderLabel("Project Files")
        self.setRootIsDecorated(True)
        self.setAlternatingRowColors(True)
        self.current_root = None
        self.file_watcher = QFileSystemWatcher()
        self.file_watcher.directoryChanged.connect(self.refresh_tree)

        # Connect signals
        self.itemClicked.connect(self.on_item_clicked)
        self.itemDoubleClicked.connect(self.on_item_double_clicked)

        # Supported file extensions for syntax highlighting
        self.supported_extensions = {
            ".py": "python",
            ".js": "javascript",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
            ".hpp": "cpp",
            ".java": "java",
            ".txt": "text",
            ".md": "markdown",
            ".json": "json",
            ".xml": "xml",
            ".html": "html",
            ".css": "css",
        }

    def set_root_directory(self, root_path: str):
        """Set the root directory for the file tree."""
        self.current_root = Path(root_path)
        self.clear()

        # Add to file system watcher
        if self.file_watcher.directories():
            self.file_watcher.removePaths(self.file_watcher.directories())
        self.file_watcher.addPath(str(self.current_root))

        self.populate_tree()

    def populate_tree(self):
        """Populate the tree with files and directories."""
        if not self.current_root or not self.current_root.exists():
            return

        # Add root item
        root_item = QTreeWidgetItem(self, [self.current_root.name])
        root_item.setData(0, Qt.UserRole, str(self.current_root))
        root_item.setExpanded(True)

        self._add_directory_items(root_item, self.current_root)

    def _add_directory_items(self, parent_item: QTreeWidgetItem, directory: Path):
        """Recursively add directory items."""
        try:
            # Sort items: directories first, then files
            items = sorted(directory.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))

            for item in items:
                if item.name.startswith("."):
                    continue  # Skip hidden files

                tree_item = QTreeWidgetItem(parent_item, [item.name])
                tree_item.setData(0, Qt.UserRole, str(item))

                if item.is_dir():
                    tree_item.setIcon(0, self.style().standardIcon(self.style().SP_DirIcon))
                    # Add subdirectories (up to 3 levels deep to avoid performance issues)
                    if len(str(item).split(os.sep)) - len(str(self.current_root).split(os.sep)) < 3:
                        self._add_directory_items(tree_item, item)
                # Set file icon based on extension
                elif item.suffix.lower() in self.supported_extensions:
                    tree_item.setIcon(0, self.style().standardIcon(self.style().SP_FileIcon))
                else:
                    tree_item.setIcon(0, self.style().standardIcon(self.style().SP_ComputerIcon))
        except PermissionError as e:
            logger.error("Permission error in ai_coding_assistant_dialog: %s", e)
            # Skip directories we can't read

    def refresh_tree(self):
        """Refresh the file tree."""
        if self.current_root:
            expanded_items = self.get_expanded_items()
            self.clear()
            self.populate_tree()
            self.restore_expanded_items(expanded_items)

    def get_expanded_items(self) -> list[str]:
        """Get list of expanded item paths."""
        expanded = []

        def traverse(item):
            if item.isExpanded():
                path = item.data(0, Qt.UserRole)
                if path:
                    expanded.append(path)

            for i in range(item.childCount()):
                traverse(item.child(i))

        for i in range(self.topLevelItemCount()):
            traverse(self.topLevelItem(i))

        return expanded

    def restore_expanded_items(self, expanded_paths: list[str]):
        """Restore expanded state of items."""

        def traverse(item):
            path = item.data(0, Qt.UserRole)
            if path in expanded_paths:
                item.setExpanded(True)

            for i in range(item.childCount()):
                traverse(item.child(i))

        for i in range(self.topLevelItemCount()):
            traverse(self.topLevelItem(i))

    def on_item_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle item click."""
        logger.debug(f"Item clicked in column {column}")
        path = item.data(0, Qt.UserRole)
        if path and Path(path).is_file():
            self.file_selected.emit(path)

    def on_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Handle item double click."""
        logger.debug(f"Item double-clicked in column {column}")
        path = item.data(0, Qt.UserRole)
        if path and Path(path).is_file():
            self.file_selected.emit(path)


class CodeEditor(QPlainTextEdit):
    """Enhanced code editor with syntax highlighting and AI integration."""

    #: Signal emitted when content changes (str: file path)
    content_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        """Initialize the CodeEditor with default values."""
        super().__init__(parent)
        self.current_file = None
        self.is_modified = False
        self.syntax_highlighter = None

        # Set font
        font = QFont("Consolas", 11)
        font.setFixedPitch(True)
        self.setFont(font)

        # Connect signals
        self.textChanged.connect(self.on_text_changed)

        # Line numbers (basic implementation)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)

    def load_file(self, file_path: str):
        """Load a file into the editor."""
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            self.setPlainText(content)
            self.current_file = file_path
            self.is_modified = False

            # Set syntax highlighting based on file extension
            self.set_syntax_highlighting(file_path)

            logger.info(f"Loaded file: {file_path}")

        except Exception as e:
            logger.error(f"Failed to load file {file_path}: {e}")
            QMessageBox.warning(self, "Error", f"Failed to load file:\n{e}")

    def save_file(self, file_path: str = None):
        """Save the current content to file."""
        if not file_path:
            file_path = self.current_file

        if not file_path:
            return False

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.toPlainText())

            self.current_file = file_path
            self.is_modified = False
            logger.info(f"Saved file: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to save file {file_path}: {e}")
            QMessageBox.warning(self, "Error", f"Failed to save file:\n{e}")
            return False

    def set_syntax_highlighting(self, file_path: str):
        """Set syntax highlighting based on file extension."""
        if self.syntax_highlighter:
            self.syntax_highlighter.setParent(None)
            self.syntax_highlighter = None

        file_ext = Path(file_path).suffix.lower()

        if file_ext == ".py":
            self.syntax_highlighter = PythonHighlighter(self.document())
        elif file_ext == ".js":
            self.syntax_highlighter = JavaScriptHighlighter(self.document())
        # Add more syntax highlighters as needed

    def on_text_changed(self):
        """Handle text change."""
        if self.current_file:
            self.is_modified = True
            self.content_changed.emit(self.current_file)

    def get_current_selection(self) -> str:
        """Get currently selected text."""
        cursor = self.textCursor()
        return cursor.selectedText()

    def insert_text_at_cursor(self, text: str):
        """Insert text at current cursor position."""
        cursor = self.textCursor()
        cursor.insertText(text)
        self.setTextCursor(cursor)


class ChatWidget(QWidget):
    """Chat interface for AI assistant interaction."""

    message_sent = pyqtSignal(str)

    def __init__(self, parent=None):
        """Initialize the ChatWidget with default values."""
        super().__init__(parent)
        self.setup_ui()
        self.conversation_history = []

    def setup_ui(self):
        """Set up the chat interface."""
        layout = QVBoxLayout(self)

        # Chat history
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setMaximumHeight(400)
        layout.addWidget(QLabel("AI Assistant Chat"))
        layout.addWidget(self.chat_history)

        # Input area
        input_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Ask AI to help with your code...")
        self.message_input.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)

        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)
        layout.addLayout(input_layout)

        # Quick actions
        actions_layout = QHBoxLayout()

        self.explain_button = QPushButton("Explain Code")
        self.explain_button.clicked.connect(
            lambda: self.send_quick_message("Explain the selected code")
        )

        self.optimize_button = QPushButton("Optimize")
        self.optimize_button.clicked.connect(
            lambda: self.send_quick_message("Optimize the selected code")
        )

        self.debug_button = QPushButton("Debug")
        self.debug_button.clicked.connect(lambda: self.send_quick_message("Help debug this code"))

        actions_layout.addWidget(self.explain_button)
        actions_layout.addWidget(self.optimize_button)
        actions_layout.addWidget(self.debug_button)
        layout.addLayout(actions_layout)

        # AI Settings
        settings_layout = QHBoxLayout()

        settings_layout.addWidget(QLabel("Model:"))
        self.model_combo = QComboBox()
        self.model_combo.addItems(["Claude", "GPT-4", "Local GGUF", "Ollama"])
        settings_layout.addWidget(self.model_combo)

        self.context_checkbox = QCheckBox("Include file context")
        self.context_checkbox.setChecked(True)
        settings_layout.addWidget(self.context_checkbox)

        layout.addLayout(settings_layout)

    def send_message(self):
        """Send a message to the AI."""
        message = self.message_input.text().strip()
        if message:
            self.add_message("User", message)
            self.message_sent.emit(message)
            self.message_input.clear()

    def send_quick_message(self, message: str):
        """Send a predefined quick message."""
        self.add_message("User", message)
        self.message_sent.emit(message)

    def add_message(self, sender: str, message: str):
        """Add a message to the chat history."""
        self.conversation_history.append({"sender": sender, "message": message})

        # Format message for display
        if sender == "User":
            formatted = f"<p><b style='color: blue;'>You:</b> {message}</p>"
        else:
            formatted = f"<p><b style='color: green;'>AI:</b> {message}</p>"

        self.chat_history.append(formatted)

        # Auto-scroll to bottom
        scrollbar = self.chat_history.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_history(self):
        """Clear the chat history."""
        self.chat_history.clear()
        self.conversation_history.clear()


class AICodingAssistantWidget(QWidget):
    """AI Coding Assistant Widget with three-panel layout - extracted from dialog for reuse."""

    def __init__(self, parent=None):
        """Initialize the AICodingAssistantWidget with development environment features."""
        super().__init__(parent)

        # Main state
        self.current_project_dir = None
        self.current_file = None
        self.llm_enabled = True

        # Threading
        self.worker_thread = None
        self.generation_thread = None

        # Setup UI
        self.setup_ui()
        self.setup_connections()
        self.setup_shortcuts()

        # Load initial state
        self.load_initial_project()

    def setup_ui(self):
        """Set up the three-panel UI layout."""
        layout = QVBoxLayout(self)

        # Menu bar
        self.setup_menu_bar(layout)

        # Main content area with three panels
        main_splitter = QSplitter(Qt.Horizontal)

        # Left panel: File tree
        left_panel = self.create_file_panel()
        main_splitter.addWidget(left_panel)

        # Center panel: Code editor with tabs
        center_panel = self.create_editor_panel()
        main_splitter.addWidget(center_panel)

        # Right panel: AI chat and tools
        right_panel = self.create_ai_panel()
        main_splitter.addWidget(right_panel)

        # Set splitter proportions (25%, 50%, 25%)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 2)
        main_splitter.setStretchFactor(2, 1)

        layout.addWidget(main_splitter)

        # Status bar
        self.setup_status_bar(layout)

    def setup_menu_bar(self, layout):
        """Set up the menu bar."""
        # Simplified menu bar for widget - full implementation when needed
        pass

    def create_file_panel(self) -> QWidget:
        """Create the left file navigation panel."""
        panel = QLabel("File Explorer\n(Coming in Phase 4)")
        panel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        panel.setObjectName("placeholderPanel")
        return panel

    def create_editor_panel(self) -> QWidget:
        """Create the center code editor panel."""
        panel = QLabel("Code Editor\n(Coming in Phase 4)")
        panel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        panel.setObjectName("placeholderPanel")
        return panel

    def create_ai_panel(self) -> QWidget:
        """Create the right AI assistant panel."""
        panel = QLabel("AI Assistant\n(Coming in Phase 4)")
        panel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        panel.setObjectName("placeholderPanel")
        return panel

    def setup_status_bar(self, layout):
        """Set up the status bar."""
        # Simplified status bar for widget
        pass

    def setup_connections(self):
        """Set up signal connections."""
        # Simplified connections for widget
        pass

    def setup_shortcuts(self):
        """Set up keyboard shortcuts."""
        # Simplified shortcuts for widget
        pass

    def load_initial_project(self):
        """Load initial project state."""
        # Simplified initial loading for widget
        pass


class AICodingAssistantDialog(QDialog):
    """AI Coding Assistant with three-panel layout similar to Claude Code."""

    def __init__(self, parent=None):
        """Initialize the AICodingAssistantDialog as a container for the widget."""
        super().__init__(parent)
        self.setWindowTitle("AI Coding Assistant")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)

        # Create layout and add the widget
        layout = QVBoxLayout(self)

        # Create the AI Coding Assistant widget
        self.ai_widget = AICodingAssistantWidget(self)
        layout.addWidget(self.ai_widget)

        # Set layout with no margins for seamless integration
        layout.setContentsMargins(0, 0, 0, 0)

        # Delegate properties to widget for backward compatibility
        self.current_project_dir = self.ai_widget.current_project_dir
        self.current_file = self.ai_widget.current_file
        self.llm_enabled = self.ai_widget.llm_enabled
        self.worker_thread = self.ai_widget.worker_thread
        self.generation_thread = self.ai_widget.generation_thread

        logger.info("AI Coding Assistant Dialog initialized with widget")

    def setup_ui(self):
        """Set up the three-panel UI layout."""
        layout = QVBoxLayout(self)

        # Menu bar
        self.setup_menu_bar(layout)

        # Main content area with three panels
        main_splitter = QSplitter(Qt.Horizontal)

        # Left panel: File tree
        left_panel = self.create_file_panel()
        main_splitter.addWidget(left_panel)

        # Center panel: Code editor with tabs
        center_panel = self.create_editor_panel()
        main_splitter.addWidget(center_panel)

        # Right panel: AI chat and tools
        right_panel = self.create_ai_panel()
        main_splitter.addWidget(right_panel)

        # Set splitter proportions (25%, 50%, 25%)
        main_splitter.setStretchFactor(0, 1)
        main_splitter.setStretchFactor(1, 2)
        main_splitter.setStretchFactor(2, 1)

        layout.addWidget(main_splitter)

        # Status bar
        self.setup_status_bar(layout)

    def setup_menu_bar(self, layout):
        """Set up the menu bar."""
        menubar = QMenuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        open_action = QAction("Open Project", self)
        open_action.triggered.connect(self.open_project)
        file_menu.addAction(open_action)

        save_action = QAction("Save Current File", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_current_file)
        file_menu.addAction(save_action)

        save_all_action = QAction("Save All", self)
        save_all_action.setShortcut("Ctrl+Shift+S")
        save_all_action.triggered.connect(self.save_all_files)
        file_menu.addAction(save_all_action)

        # AI menu
        ai_menu = menubar.addMenu("AI")

        generate_script_action = QAction("Generate Script", self)
        generate_script_action.triggered.connect(self.generate_script_dialog)
        ai_menu.addAction(generate_script_action)

        analyze_code_action = QAction("Analyze Code", self)
        analyze_code_action.triggered.connect(self.analyze_current_code)
        ai_menu.addAction(analyze_code_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        run_script_action = QAction("Run Current Script", self)
        run_script_action.setShortcut("F5")
        run_script_action.triggered.connect(self.run_current_script)
        tools_menu.addAction(run_script_action)

        layout.setMenuBar(menubar)

    def create_file_panel(self) -> QWidget:
        """Create the left file navigation panel."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)
        panel.setMaximumWidth(300)

        layout = QVBoxLayout(panel)

        # Panel header
        header = QLabel("Project Explorer")
        header.setObjectName("headerBold")
        layout.addWidget(header)

        # File tree
        self.file_tree = FileTreeWidget()
        layout.addWidget(self.file_tree)

        # Project actions
        actions_layout = QHBoxLayout()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.file_tree.refresh_tree)

        new_file_btn = QPushButton("New File")
        new_file_btn.clicked.connect(self.create_new_file)

        actions_layout.addWidget(refresh_btn)
        actions_layout.addWidget(new_file_btn)
        layout.addLayout(actions_layout)

        return panel

    def create_editor_panel(self) -> QWidget:
        """Create the center code editor panel."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)

        layout = QVBoxLayout(panel)

        # Editor tabs
        self.editor_tabs = QTabWidget()
        self.editor_tabs.setTabsClosable(True)
        self.editor_tabs.tabCloseRequested.connect(self.close_tab)

        layout.addWidget(self.editor_tabs)

        # Editor toolbar
        toolbar = QToolBar()

        # Run button
        run_action = QAction("Run", self)
        run_action.setIcon(self.style().standardIcon(self.style().SP_MediaPlay))
        run_action.triggered.connect(self.run_current_script)
        toolbar.addAction(run_action)

        # Format button
        format_action = QAction("Format", self)
        format_action.triggered.connect(self.format_current_code)
        toolbar.addAction(format_action)

        # AI generate button
        ai_action = QAction("AI Generate", self)
        ai_action.setIcon(self.style().standardIcon(self.style().SP_ComputerIcon))
        ai_action.triggered.connect(self.ai_generate_code)
        toolbar.addAction(ai_action)

        layout.insertWidget(0, toolbar)

        return panel

    def create_ai_panel(self) -> QWidget:
        """Create the right AI assistant panel."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)
        panel.setMaximumWidth(400)

        layout = QVBoxLayout(panel)

        # Panel header
        header = QLabel("AI Assistant")
        header.setObjectName("headerBold")
        layout.addWidget(header)

        # Chat widget
        self.chat_widget = ChatWidget()
        layout.addWidget(self.chat_widget)

        # AI generation options
        generation_group = QFrame()
        generation_group.setFrameStyle(QFrame.StyledPanel)
        gen_layout = QVBoxLayout(generation_group)

        gen_layout.addWidget(QLabel("Code Generation"))

        self.script_type_combo = QComboBox()
        self.script_type_combo.addItems(
            ["Frida Script", "Ghidra Script", "Python Tool", "General Code"]
        )
        gen_layout.addWidget(self.script_type_combo)

        generate_btn = QPushButton("Generate Code")
        generate_btn.clicked.connect(self.ai_generate_code)
        gen_layout.addWidget(generate_btn)

        layout.addWidget(generation_group)

        # Context information
        context_group = QFrame()
        context_group.setFrameStyle(QFrame.StyledPanel)
        ctx_layout = QVBoxLayout(context_group)

        ctx_layout.addWidget(QLabel("Context"))

        self.context_info = QTextEdit()
        self.context_info.setMaximumHeight(150)
        self.context_info.setReadOnly(True)
        ctx_layout.addWidget(self.context_info)

        layout.addWidget(context_group)

        return panel

    def setup_status_bar(self, layout):
        """Set up the status bar."""
        self.status_bar = QStatusBar()

        # Current file label
        self.current_file_label = QLabel("No file open")
        self.status_bar.addWidget(self.current_file_label)

        # Modified indicator
        self.modified_label = QLabel("")
        self.status_bar.addPermanentWidget(self.modified_label)

        # AI status
        self.ai_status_label = QLabel("AI Ready")
        self.status_bar.addPermanentWidget(self.ai_status_label)

        layout.addWidget(self.status_bar)

    def setup_connections(self):
        """Set up signal connections."""
        # File tree connections
        self.file_tree.file_selected.connect(self.open_file_in_editor)

        # Chat connections
        self.chat_widget.message_sent.connect(self.handle_ai_message)

    def load_intellicrack_project(self):
        """Auto-load the Intellicrack project."""
        project_root = Path(__file__).parent.parent.parent.parent
        if project_root.exists() and (project_root / "intellicrack").exists():
            self.set_project_root(str(project_root))
            self.status_bar.showMessage(f"Loaded project: {project_root.name}", 3000)

    def set_project_root(self, root_path: str):
        """Set the project root directory."""
        self.current_project = Path(root_path)
        self.file_tree.set_root_directory(root_path)
        self.update_context_info()

    def open_project(self):
        """Open a project directory."""
        directory = QFileDialog.getExistingDirectory(self, "Select Project Directory")
        if directory:
            self.set_project_root(directory)

    def open_file_in_editor(self, file_path: str):
        """Open a file in the code editor."""
        # Check if file is already open
        for i in range(self.editor_tabs.count()):
            editor = self.editor_tabs.widget(i)
            if hasattr(editor, "current_file") and editor.current_file == file_path:
                self.editor_tabs.setCurrentIndex(i)
                return

        # Create new editor tab
        editor = CodeEditor()
        editor.load_file(file_path)
        editor.content_changed.connect(self.on_file_modified)

        # Add tab
        file_name = Path(file_path).name
        tab_index = self.editor_tabs.addTab(editor, file_name)
        self.editor_tabs.setCurrentIndex(tab_index)

        # Update status
        self.current_file_label.setText(f"File: {file_name}")
        self.update_context_info()

    def close_tab(self, index: int):
        """Close an editor tab."""
        editor = self.editor_tabs.widget(index)
        if editor and hasattr(editor, "is_modified") and editor.is_modified:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "File has unsaved changes. Save before closing?",
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
            )

            if reply == QMessageBox.Save:
                if not editor.save_file():
                    return  # Don't close if save failed
            elif reply == QMessageBox.Cancel:
                return  # Don't close

        self.editor_tabs.removeTab(index)

        # Update status if this was the current tab
        if self.editor_tabs.count() == 0:
            self.current_file_label.setText("No file open")
            self.update_context_info()

    def save_current_file(self):
        """Save the currently active file."""
        current_editor = self.get_current_editor()
        if current_editor:
            current_editor.save_file()
            self.update_modified_status()

    def save_all_files(self):
        """Save all modified files."""
        for i in range(self.editor_tabs.count()):
            editor = self.editor_tabs.widget(i)
            if editor and hasattr(editor, "is_modified") and editor.is_modified:
                editor.save_file()

        self.update_modified_status()

    def get_current_editor(self) -> CodeEditor | None:
        """Get the currently active code editor."""
        current_widget = self.editor_tabs.currentWidget()
        if isinstance(current_widget, CodeEditor):
            return current_widget
        return None

    def on_file_modified(self, file_path: str):
        """Handle file modification."""
        self.modified_files.add(file_path)
        self.update_modified_status()
        self.update_context_info()

    def update_modified_status(self):
        """Update the modified files indicator."""
        if self.modified_files:
            self.modified_label.setText(f"Modified: {len(self.modified_files)} files")
        else:
            self.modified_label.setText("")

    def update_context_info(self):
        """Update the context information panel."""
        current_editor = self.get_current_editor()
        if current_editor and current_editor.current_file:
            file_path = Path(current_editor.current_file)

            info = f"File: {file_path.name}\n"
            info += f"Type: {file_path.suffix}\n"
            info += f"Size: {file_path.stat().st_size} bytes\n"

            # Add selected text info if any
            selected_text = current_editor.get_current_selection()
            if selected_text:
                info += f"Selection: {len(selected_text)} chars\n"

            self.context_info.setPlainText(info)
        else:
            self.context_info.setPlainText("No file selected")

    def handle_ai_message(self, message: str):
        """Handle AI assistant message."""
        try:
            self.ai_status_label.setText("AI Processing...")

            # Get context for AI
            context = self.get_ai_context()

            # Process with AI assistant
            response = self.process_ai_request(message, context)

            # Add response to chat
            self.chat_widget.add_message("AI", response)

            self.ai_status_label.setText("AI Ready")

        except Exception as e:
            logger.error(f"AI processing error: {e}")
            self.chat_widget.add_message("AI", f"Error: {e}")
            self.ai_status_label.setText("AI Error")

    def get_ai_context(self) -> dict[str, Any]:
        """Get context information for AI processing."""
        context = {
            "project_root": str(self.current_project) if self.current_project else None,
            "current_file": None,
            "selected_text": None,
            "file_content": None,
            "file_type": None,
        }

        current_editor = self.get_current_editor()
        if current_editor and current_editor.current_file:
            context["current_file"] = current_editor.current_file
            context["selected_text"] = current_editor.get_current_selection()
            context["file_content"] = current_editor.toPlainText()
            context["file_type"] = Path(current_editor.current_file).suffix

        return context

    def process_ai_request(self, message: str, context: dict[str, Any]) -> str:
        """Process AI request and return response."""
        try:
            # Handle specific commands first
            if "explain" in message.lower() and context.get("selected_text"):
                # Create a more specific question with context
                code_snippet = context["selected_text"][:500]  # Limit code length
                question = f"Please explain this code:\n```\n{code_snippet}\n```"
                response = self.ai_tools.ask_question(question)
                return response

            if "generate" in message.lower():
                # Handle code generation requests
                script_type = self.script_type_combo.currentText()
                if context.get("file_content"):
                    # Include current file context
                    question = f"Generate a {script_type} based on this context:\n{context['file_content'][:1000]}"
                else:
                    question = f"Generate a {script_type} for: {message}"
                response = self.ai_tools.ask_question(question)
                return response

            if "optimize" in message.lower() and context.get("selected_text"):
                # Handle optimization requests
                code_snippet = context["selected_text"][:500]
                question = f"Please optimize this code:\n```\n{code_snippet}\n```"
                response = self.ai_tools.ask_question(question)
                return response

            if "debug" in message.lower() and context.get("selected_text"):
                # Handle debugging requests
                code_snippet = context["selected_text"][:500]
                question = f"Help me debug this code:\n```\n{code_snippet}\n```"
                response = self.ai_tools.ask_question(question)
                return response

            # For general questions, use ask_question directly
            response = self.ai_tools.ask_question(message)
            return response

        except Exception as e:
            logger.error(f"Error processing AI request: {e}")
            # Fallback to basic responses if AI fails
            if "explain" in message.lower():
                return "Please select some code to explain."
            if "generate" in message.lower():
                script_type = self.script_type_combo.currentText()
                return f"AI generation temporarily unavailable for {script_type}."
            return f"AI processing error: {e!s}"

    def ai_generate_code(self):
        """Generate code using AI."""
        current_editor = self.get_current_editor()
        if not current_editor:
            QMessageBox.information(self, "Info", "Please open a file first.")
            return

        script_type = self.script_type_combo.currentText()

        # This would integrate with the AI script generation system
        generated_code = f"""# Generated {script_type}
# This is where AI-generated code would appear

def example_function():
    '''AI-generated function based on context'''
    print("Generated by AI assistant")
    return True
"""

        # Insert at cursor position
        current_editor.insert_text_at_cursor(generated_code)

        # Add to chat
        self.chat_widget.add_message(
            "AI", f"Generated {script_type} code and inserted into editor."
        )

    def run_current_script(self):
        """Run the current script with optional QEMU testing."""
        current_editor = self.get_current_editor()
        if not current_editor or not current_editor.current_file:
            QMessageBox.information(self, "Info", "No file to run.")
            return

        file_path = Path(current_editor.current_file)

        # Initialize ScriptExecutionManager if not already done
        if not hasattr(self, "script_execution_manager"):
            from ...core.execution import ScriptExecutionManager

            self.script_execution_manager = ScriptExecutionManager(self)

        # Determine script type based on file extension
        script_type = None
        if file_path.suffix == ".py":
            script_type = "python"
        elif file_path.suffix == ".js":
            script_type = "frida"
        else:
            QMessageBox.information(
                self, "Info", f"Don't know how to run {file_path.suffix} files."
            )
            return

        # Read script content
        try:
            with open(file_path, encoding="utf-8") as f:
                script_content = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read script: {e!s}")
            return

        # Get target binary if available
        target_binary = getattr(self, "target_binary", "") or ""

        # Execute through ScriptExecutionManager
        result = self.script_execution_manager.execute_script(
            script_type=script_type,
            script_content=script_content,
            target_binary=target_binary,
            options={
                "file_path": str(file_path),
                "from_editor": True,
            },
        )

        # Show result in chat widget
        if result.get("success"):
            output_msg = f"Script executed successfully: {file_path.name}"
            if "output" in result:
                output_msg += f"\n\nOutput:\n{result['output']}"
            if result.get("qemu_tested"):
                output_msg += "\n\n[Script was tested in QEMU before execution]"
            self.chat_widget.add_message("System", output_msg)
        else:
            error_msg = f"Script execution failed: {result.get('error', 'Unknown error')}"
            self.chat_widget.add_message("System", error_msg)

    def run_python_script(self, file_path: str):
        """Run a Python script."""
        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                ["python", file_path],  # noqa: S607
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            output = f"Exit code: {result.returncode}\n\nStdout:\n{result.stdout}\n\nStderr:\n{result.stderr}"
            self.chat_widget.add_message("System", f"Script execution result:\n{output}")

        except subprocess.TimeoutExpired as e:
            logger.error("Subprocess timeout in ai_coding_assistant_dialog: %s", e)
            self.chat_widget.add_message("System", "Script execution timed out.")
        except Exception as e:
            logger.error("Exception in ai_coding_assistant_dialog: %s", e)
            self.chat_widget.add_message("System", f"Script execution error: {e}")

    def run_javascript_script(self, file_path: str):
        """Run a JavaScript script (if Node.js is available)."""
        try:
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                ["node", file_path],  # noqa: S607
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            output = f"Exit code: {result.returncode}\n\nOutput:\n{result.stdout}\n\nErrors:\n{result.stderr}"
            self.chat_widget.add_message("System", f"Script execution result:\n{output}")

        except FileNotFoundError as e:
            logger.error("File not found in ai_coding_assistant_dialog: %s", e)
            self.chat_widget.add_message(
                "System", "Node.js not found. Cannot run JavaScript files."
            )
        except subprocess.TimeoutExpired as e:
            logger.error("Subprocess timeout in ai_coding_assistant_dialog: %s", e)
            self.chat_widget.add_message("System", "Script execution timed out.")
        except Exception as e:
            logger.error("Exception in ai_coding_assistant_dialog: %s", e)
            self.chat_widget.add_message("System", f"Script execution error: {e}")

    def format_current_code(self):
        """Format the current code."""
        current_editor = self.get_current_editor()
        if not current_editor:
            return

        file_path = Path(current_editor.current_file) if current_editor.current_file else None

        if file_path and file_path.suffix == ".py":
            self.format_python_code(current_editor)
        else:
            QMessageBox.information(
                self, "Info", "Code formatting not supported for this file type."
            )

    def format_python_code(self, editor: CodeEditor):
        """Format Python code using black if available."""
        try:
            # Try to format with black
            content = editor.toPlainText()

            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            try:
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    ["black", "--quiet", temp_file_path],  # noqa: S607
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0:
                    with open(temp_file_path) as f:
                        formatted_content = f.read()

                    editor.setPlainText(formatted_content)
                    self.chat_widget.add_message("System", "Code formatted successfully.")
                else:
                    self.chat_widget.add_message("System", f"Formatting failed: {result.stderr}")

            finally:
                os.unlink(temp_file_path)

        except FileNotFoundError as e:
            logger.error("File not found in ai_coding_assistant_dialog: %s", e)
            self.chat_widget.add_message(
                "System", "Black formatter not found. Please install: pip install black"
            )
        except Exception as e:
            logger.error("Exception in ai_coding_assistant_dialog: %s", e)
            self.chat_widget.add_message("System", f"Formatting error: {e}")

    def analyze_current_code(self):
        """Analyze the current code with AI."""
        current_editor = self.get_current_editor()
        if not current_editor:
            QMessageBox.information(self, "Info", "No file to analyze.")
            return

        try:
            # Get the current code content
            code_content = current_editor.toPlainText()
            file_path = current_editor.current_file

            # Determine language from file extension
            language = "auto"
            if file_path:
                file_ext = Path(file_path).suffix.lower()
                ext_to_lang = {
                    ".py": "python",
                    ".js": "javascript",
                    ".c": "c",
                    ".cpp": "cpp",
                    ".h": "c",
                    ".hpp": "cpp",
                    ".java": "java",
                }
                language = ext_to_lang.get(file_ext, "auto")

            # Update status
            self.ai_status_label.setText("Analyzing code...")
            self.chat_widget.add_message("AI", "Analyzing code, please wait...")

            # Perform analysis using ai_tools
            analysis_result = self.ai_tools.analyze_code(code_content, language)

            # Format and display results
            if analysis_result.get("status") == "success":
                formatted_analysis = self._format_analysis_results(analysis_result)
                self.chat_widget.add_message("AI", formatted_analysis)

                # If there are security issues or suggestions, highlight them
                if analysis_result.get("security_issues"):
                    self._highlight_security_issues(analysis_result["security_issues"])

            else:
                error_msg = analysis_result.get("error", "Unknown error occurred")
                self.chat_widget.add_message("AI", f"Analysis failed: {error_msg}")

            self.ai_status_label.setText("AI Ready")

        except Exception as e:
            logger.error(f"Code analysis error: {e}")
            self.chat_widget.add_message("AI", f"Error during code analysis: {e!s}")
            self.ai_status_label.setText("AI Error")

    def _format_analysis_results(self, analysis_result: dict[str, Any]) -> str:
        """Format code analysis results for display."""
        lines = ["📊 **Code Analysis Results**\n"]

        # Basic info
        lines.append(f"**Language:** {analysis_result.get('language', 'Unknown')}")
        lines.append(f"**Lines of Code:** {analysis_result.get('lines_of_code', 0)}")
        lines.append(f"**Complexity:** {analysis_result.get('complexity', 'Unknown')}")
        lines.append(
            f"**AI Analysis:** {'Enabled' if analysis_result.get('ai_enabled', False) else 'Disabled'}"
        )
        lines.append("")

        # Insights
        insights = analysis_result.get("insights", [])
        if insights:
            lines.append("**🔍 Insights:**")
            for insight in insights:
                lines.append(f"  • {insight}")
            lines.append("")

        # Security Issues
        security_issues = analysis_result.get("security_issues", [])
        if security_issues:
            lines.append("**🔒 Security Issues:**")
            for issue in security_issues:
                lines.append(f"  ⚠️ {issue}")
            lines.append("")

        # Suggestions
        suggestions = analysis_result.get("suggestions", [])
        if suggestions:
            lines.append("**💡 Suggestions:**")
            for suggestion in suggestions:
                lines.append(f"  • {suggestion}")
            lines.append("")

        # Patterns
        patterns = analysis_result.get("patterns", [])
        if patterns:
            lines.append("**🎯 Detected Patterns:**")
            for pattern in patterns:
                lines.append(f"  • {pattern}")
            lines.append("")

        # Timestamp
        timestamp = analysis_result.get("analysis_timestamp", "")
        if timestamp:
            lines.append(f"\n_Analysis performed at: {timestamp}_")

        return "\n".join(lines)

    def _highlight_security_issues(self, security_issues: list[str]):
        """Highlight security issues in the code editor."""
        current_editor = self.get_current_editor()
        if not current_editor:
            return

        # For now, just log the security issues
        # In a full implementation, this would highlight the relevant lines in the editor
        for issue in security_issues:
            logger.warning(f"Security issue detected: {issue}")

        # Show a warning dialog if there are critical security issues
        if any(
            "critical" in issue.lower() or "vulnerability" in issue.lower()
            for issue in security_issues
        ):
            QMessageBox.warning(
                self,
                "Security Issues Detected",
                f"Found {len(security_issues)} security issue(s) in the code.\n"
                "Please review the analysis results in the chat panel.",
            )

    def generate_script_dialog(self):
        """Open script generation dialog."""
        script_type = self.script_type_combo.currentText()
        message = f"Generate a {script_type} for the current context"
        self.chat_widget.send_quick_message(message)

    def create_new_file(self):
        """Create a new file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Create New File",
            str(self.current_project) if self.current_project else "",
            "Python Files (*.py);;JavaScript Files (*.js);;All Files (*)",
        )

        if file_path:
            # Create empty file
            with open(file_path, "w") as f:
                f.write("")

            # Refresh file tree
            self.file_tree.refresh_tree()

            # Open in editor
            self.open_file_in_editor(file_path)
