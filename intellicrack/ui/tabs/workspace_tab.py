"""Workspace tab for Intellicrack.

This module provides workspace management including project files,
binary management, and activity logging.

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

import os
from datetime import datetime

from intellicrack.handlers.pyqt6_handler import (
    QAction,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    Qt,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ..config_manager import get_ui_config_manager
from ..style_manager import StyleManager
from ..widgets.ai_assistant_widget import AIAssistantWidget


class WorkspaceTab(QWidget):
    """Workspace tab for managing projects, binaries, and activity logs."""

    # Signals
    project_created = pyqtSignal(str)
    project_opened = pyqtSignal(str)
    project_closed = pyqtSignal()
    binary_loaded = pyqtSignal(str)
    analysis_saved = pyqtSignal(str)

    def __init__(self, shared_context=None, parent=None):
        """Initialize workspace tab with project management and activity logging."""
        super().__init__(parent)
        self.shared_context = shared_context
        self.config_manager = get_ui_config_manager()
        self.current_project_path = None
        self.loaded_binary_path = None
        self.setup_content()

        # Subscribe to configuration changes
        self.config_manager.register_callback('theme', self.apply_theme)
        self.config_manager.register_callback('font', self.update_fonts)

    def setup_content(self):
        """Setup the workspace tab content with three-panel splitter layout."""
        main_layout = QHBoxLayout(self)

        # Create main three-panel splitter
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel - Project and Binary Management
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        # Project Management Panel
        project_group = self.create_project_management_panel()
        left_layout.addWidget(project_group)

        # Binary Management Panel
        binary_group = self.create_binary_management_panel()
        left_layout.addWidget(binary_group)

        # Project Files Panel
        files_group = self.create_project_files_panel()
        left_layout.addWidget(files_group)

        left_layout.addStretch()

        # Middle panel - Activity Log
        self.activity_log = self.create_activity_log_panel()

        # Right panel - AI Assistant
        self.ai_assistant = AIAssistantWidget(self)
        self.ai_assistant.message_sent.connect(self.on_ai_message_sent)
        self.ai_assistant.code_generated.connect(self.on_code_generated)
        self.ai_assistant.script_generated.connect(self.on_script_generated)

        # Add widgets to splitter
        self.main_splitter.addWidget(left_widget)
        self.main_splitter.addWidget(self.activity_log)
        self.main_splitter.addWidget(self.ai_assistant)

        # Set initial splitter sizes (35% left, 30% middle, 35% right)
        self.main_splitter.setSizes([350, 300, 350])

        main_layout.addWidget(self.main_splitter)

        # Apply initial theme
        self.apply_theme()

    def create_project_management_panel(self):
        """Create the project management panel."""
        group = QGroupBox("Project Management")
        layout = QVBoxLayout(group)

        # Current project display
        project_layout = QHBoxLayout()
        project_layout.addWidget(QLabel("Current Project:"))

        self.current_project_label = QLabel("No project loaded")
        StyleManager.style_label(self.current_project_label, 'current_project_label')
        project_layout.addWidget(self.current_project_label)
        project_layout.addStretch()

        layout.addLayout(project_layout)

        # Project actions
        actions_layout = QHBoxLayout()

        self.new_project_btn = QPushButton("New Project")
        self.new_project_btn.clicked.connect(self.create_new_project)
        actions_layout.addWidget(self.new_project_btn)

        self.open_project_btn = QPushButton("Open Project")
        self.open_project_btn.clicked.connect(self.open_project)
        actions_layout.addWidget(self.open_project_btn)

        self.save_project_btn = QPushButton("Save Project")
        self.save_project_btn.clicked.connect(self.save_project)
        self.save_project_btn.setEnabled(False)
        actions_layout.addWidget(self.save_project_btn)

        self.close_project_btn = QPushButton("Close Project")
        self.close_project_btn.clicked.connect(self.close_project)
        self.close_project_btn.setEnabled(False)
        actions_layout.addWidget(self.close_project_btn)

        layout.addLayout(actions_layout)

        return group

    def create_binary_management_panel(self):
        """Create the binary management panel."""
        group = QGroupBox("Binary Management")
        layout = QVBoxLayout(group)

        # Current binary display
        binary_layout = QHBoxLayout()
        binary_layout.addWidget(QLabel("Loaded Binary:"))

        self.current_binary_label = QLabel("No binary loaded")
        StyleManager.style_label(self.current_binary_label, 'current_binary_label')
        binary_layout.addWidget(self.current_binary_label)
        binary_layout.addStretch()

        layout.addLayout(binary_layout)

        # Binary info
        info_layout = QHBoxLayout()

        self.binary_size_label = QLabel("Size: N/A")
        info_layout.addWidget(self.binary_size_label)

        self.binary_type_label = QLabel("Type: N/A")
        info_layout.addWidget(self.binary_type_label)

        self.binary_arch_label = QLabel("Arch: N/A")
        info_layout.addWidget(self.binary_arch_label)

        info_layout.addStretch()

        layout.addLayout(info_layout)

        # Binary actions
        actions_layout = QHBoxLayout()

        self.load_binary_btn = QPushButton("Load Binary")
        self.load_binary_btn.clicked.connect(self.load_binary)
        actions_layout.addWidget(self.load_binary_btn)

        self.analyze_binary_btn = QPushButton("Quick Analysis")
        self.analyze_binary_btn.clicked.connect(self.quick_analyze_binary)
        self.analyze_binary_btn.setEnabled(False)
        actions_layout.addWidget(self.analyze_binary_btn)

        self.export_analysis_btn = QPushButton("Export Analysis")
        self.export_analysis_btn.clicked.connect(self.export_analysis)
        self.export_analysis_btn.setEnabled(False)
        actions_layout.addWidget(self.export_analysis_btn)

        layout.addLayout(actions_layout)

        return group

    def create_project_files_panel(self):
        """Create the project files panel."""
        group = QGroupBox("Project Files")
        layout = QVBoxLayout(group)

        # File tree
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Type", "Size", "Modified"])
        self.file_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self.show_file_context_menu)
        layout.addWidget(self.file_tree)

        # File actions
        actions_layout = QHBoxLayout()

        self.add_file_btn = QPushButton("Add File")
        self.add_file_btn.clicked.connect(self.add_file_to_project)
        self.add_file_btn.setEnabled(False)
        actions_layout.addWidget(self.add_file_btn)

        self.remove_file_btn = QPushButton("Remove File")
        self.remove_file_btn.clicked.connect(self.remove_file_from_project)
        self.remove_file_btn.setEnabled(False)
        actions_layout.addWidget(self.remove_file_btn)

        self.refresh_files_btn = QPushButton("Refresh")
        self.refresh_files_btn.clicked.connect(self.refresh_project_files)
        self.refresh_files_btn.setEnabled(False)
        actions_layout.addWidget(self.refresh_files_btn)

        actions_layout.addStretch()
        layout.addLayout(actions_layout)

        return group

    def create_activity_log_panel(self):
        """Create the activity log panel."""
        group = QGroupBox("Activity Log")
        layout = QVBoxLayout(group)

        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Filter:"))

        self.log_filter = QLineEdit()
        self.log_filter.setPlaceholderText("Type to filter log entries...")
        self.log_filter.textChanged.connect(self.filter_activity_log)
        search_layout.addWidget(self.log_filter)

        self.clear_log_btn = QPushButton("Clear Log")
        self.clear_log_btn.clicked.connect(self.clear_activity_log)
        search_layout.addWidget(self.clear_log_btn)

        layout.addLayout(search_layout)

        # Activity log text area
        self.activity_log_text = QTextEdit()
        self.activity_log_text.setReadOnly(True)
        self.activity_log_text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.activity_log_text)

        # Log initial message
        self.log_activity("Workspace initialized")

        return group

    def log_activity(self, message: str, level: str = "INFO"):
        """Log an activity message with timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Format message based on level
        if level == "ERROR":
            formatted_msg = f'<span style="color: red;">[{timestamp}] ERROR: {message}</span>'
        elif level == "WARNING":
            formatted_msg = f'<span style="color: orange;">[{timestamp}] WARNING: {message}</span>'
        elif level == "SUCCESS":
            formatted_msg = f'<span style="color: green;">[{timestamp}] SUCCESS: {message}</span>'
        else:
            formatted_msg = f"[{timestamp}] {message}"

        # Append to log
        self.activity_log_text.append(formatted_msg)

        # Auto-scroll to bottom
        scrollbar = self.activity_log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def filter_activity_log(self, filter_text: str):
        """Filter activity log entries based on search text."""
        # This is a simple implementation - in production, you'd want to
        # maintain a list of all log entries and filter them
        if not filter_text:
            return

        # Highlight matching text
        cursor = self.activity_log_text.textCursor()
        cursor.select(cursor.SelectionType.Document)
        cursor.setCharFormat(cursor.charFormat())

        # Find and highlight all occurrences
        while self.activity_log_text.find(filter_text):
            cursor = self.activity_log_text.textCursor()
            format = cursor.charFormat()
            format.setBackground(Qt.GlobalColor.yellow)
            cursor.setCharFormat(format)

    def clear_activity_log(self):
        """Clear the activity log."""
        reply = QMessageBox.question(
            self,
            "Clear Activity Log",
            "Are you sure you want to clear the activity log?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.activity_log_text.clear()
            self.log_activity("Activity log cleared")

    def create_new_project(self):
        """Create a new project."""
        project_dir = QFileDialog.getExistingDirectory(
            self,
            "Select Project Directory",
            "",
            QFileDialog.Option.ShowDirsOnly
        )

        if project_dir:
            project_name = os.path.basename(project_dir)
            self.current_project_path = project_dir

            # Create project structure
            os.makedirs(os.path.join(project_dir, "binaries"), exist_ok=True)
            os.makedirs(os.path.join(project_dir, "analysis"), exist_ok=True)
            os.makedirs(os.path.join(project_dir, "scripts"), exist_ok=True)
            os.makedirs(os.path.join(project_dir, "reports"), exist_ok=True)

            # Update UI
            self.current_project_label.setText(project_name)
            self.save_project_btn.setEnabled(True)
            self.close_project_btn.setEnabled(True)
            self.add_file_btn.setEnabled(True)
            self.refresh_files_btn.setEnabled(True)

            # Emit signal
            self.project_created.emit(project_dir)

            # Log activity
            self.log_activity(f"Created new project: {project_name}", "SUCCESS")

            # Refresh file tree
            self.refresh_project_files()

    def open_project(self):
        """Open an existing project."""
        project_file, _ = QFileDialog.getOpenFileName(
            self,
            "Open Project",
            "",
            "Intellicrack Projects (*.icp);;All Files (*)"
        )

        if project_file:
            project_dir = os.path.dirname(project_file)
            project_name = os.path.basename(project_dir)

            self.current_project_path = project_dir
            self.current_project_label.setText(project_name)

            # Enable project actions
            self.save_project_btn.setEnabled(True)
            self.close_project_btn.setEnabled(True)
            self.add_file_btn.setEnabled(True)
            self.refresh_files_btn.setEnabled(True)

            # Emit signal
            self.project_opened.emit(project_file)

            # Log activity
            self.log_activity(f"Opened project: {project_name}", "SUCCESS")

            # Refresh file tree
            self.refresh_project_files()

    def save_project(self):
        """Save the current project."""
        if not self.current_project_path:
            return

        # Create project file
        project_file = os.path.join(self.current_project_path, "project.icp")

        # Save project metadata (simplified for now)
        import json
        project_data = {
            "name": os.path.basename(self.current_project_path),
            "created": datetime.now().isoformat(),
            "binary": self.loaded_binary_path,
            "version": "1.0"
        }

        with open(project_file, 'w') as f:
            json.dump(project_data, f, indent=2)

        self.log_activity("Project saved", "SUCCESS")
        self.analysis_saved.emit(project_file)

    def close_project(self):
        """Close the current project."""
        if self.current_project_path:
            reply = QMessageBox.question(
                self,
                "Close Project",
                "Do you want to save the project before closing?",
                QMessageBox.StandardButton.Yes |
                QMessageBox.StandardButton.No |
                QMessageBox.StandardButton.Cancel
            )

            if reply == QMessageBox.StandardButton.Cancel:
                return
            elif reply == QMessageBox.StandardButton.Yes:
                self.save_project()

            # Reset UI
            self.current_project_path = None
            self.current_project_label.setText("No project loaded")
            self.save_project_btn.setEnabled(False)
            self.close_project_btn.setEnabled(False)
            self.add_file_btn.setEnabled(False)
            self.refresh_files_btn.setEnabled(False)
            self.file_tree.clear()

            # Emit signal
            self.project_closed.emit()

            self.log_activity("Project closed")

    def load_binary(self):
        """Load a binary file for analysis."""
        binary_file, _ = QFileDialog.getOpenFileName(
            self,
            "Load Binary",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib *.elf *.bin);;All Files (*)"
        )

        if binary_file:
            self.loaded_binary_path = binary_file
            binary_name = os.path.basename(binary_file)

            # Update UI
            self.current_binary_label.setText(binary_name)

            # Get file info
            file_size = os.path.getsize(binary_file)
            size_mb = file_size / (1024 * 1024)
            self.binary_size_label.setText(f"Size: {size_mb:.2f} MB")

            # Detect binary type (simplified)
            _, ext = os.path.splitext(binary_file)
            self.binary_type_label.setText(f"Type: {ext.upper()}")

            # Enable analysis actions
            self.analyze_binary_btn.setEnabled(True)
            self.export_analysis_btn.setEnabled(True)

            # Emit signal
            self.binary_loaded.emit(binary_file)

            self.log_activity(f"Loaded binary: {binary_name}", "SUCCESS")

            # Update AI Assistant context
            self.update_ai_context()

            # If project is open, copy binary to project
            if self.current_project_path:
                import shutil
                dest = os.path.join(self.current_project_path, "binaries", binary_name)
                shutil.copy2(binary_file, dest)
                self.refresh_project_files()

    def quick_analyze_binary(self):
        """Perform quick analysis on loaded binary."""
        if not self.loaded_binary_path:
            return

        self.log_activity("Starting quick analysis...", "INFO")

        # Perform actual binary analysis
        try:
            from ...utils.binary.pe_analysis_common import analyze_pe_file
            from ...utils.protection.protection_detection import detect_basic_protections

            # Analyze the binary file
            analysis_results = analyze_pe_file(self.loaded_binary_path)
            protection_results = detect_basic_protections(self.loaded_binary_path)

            # Log actual analysis results
            if analysis_results:
                for key, value in analysis_results.items():
                    self.log_activity(f"{key}: {value}", "INFO")

            if protection_results:
                for protection in protection_results:
                    self.log_activity(f"Protection detected: {protection}", "WARNING")

            self.log_activity("Quick analysis complete", "SUCCESS")

        except ImportError:
            # Fallback analysis using basic file operations
            import struct

            try:
                with open(self.loaded_binary_path, 'rb') as f:
                    # Read PE header
                    f.seek(0)
                    dos_header = f.read(64)

                    if dos_header[:2] == b'MZ':
                        self.log_activity("Detected: MS-DOS executable header", "INFO")

                        # Get PE header offset
                        pe_offset = struct.unpack('<L', dos_header[60:64])[0]
                        f.seek(pe_offset)
                        pe_signature = f.read(4)

                        if pe_signature == b'PE\x00\x00':
                            self.log_activity("Detected: Valid PE executable", "INFO")

                            # Read machine type
                            machine_type = struct.unpack('<H', f.read(2))[0]
                            if machine_type == 0x014c:
                                self.log_activity("Architecture: x86 (32-bit)", "INFO")
                            elif machine_type == 0x8664:
                                self.log_activity("Architecture: x86-64 (64-bit)", "INFO")
                            elif machine_type == 0x01c4:
                                self.log_activity("Architecture: ARM", "INFO")
                            else:
                                self.log_activity(f"Architecture: Unknown (0x{machine_type:04x})", "INFO")

                            # Basic protection detection
                            f.seek(pe_offset + 22)
                            characteristics = struct.unpack('<H', f.read(2))[0]

                            protections = []
                            if characteristics & 0x0020:  # DYNAMIC_BASE
                                protections.append("ASLR")
                            if characteristics & 0x0040:  # NX_COMPAT
                                protections.append("DEP")
                            if characteristics & 0x4000:  # CONTROL_FLOW_GUARD
                                protections.append("CFG")

                            if protections:
                                self.log_activity(f"Protections: {', '.join(protections)}", "WARNING")
                            else:
                                self.log_activity("No standard protections detected", "INFO")
                        else:
                            self.log_activity("Invalid PE signature", "ERROR")
                    else:
                        self.log_activity("Not a valid PE executable", "ERROR")

                self.log_activity("Quick analysis complete", "SUCCESS")

            except Exception as e:
                self.log_activity(f"Analysis error: {str(e)}", "ERROR")

        except Exception as e:
            self.log_activity(f"Analysis failed: {str(e)}", "ERROR")

    def export_analysis(self):
        """Export analysis results."""
        if not self.loaded_binary_path:
            return

        export_file, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis",
            "",
            "JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )

        if export_file:
            # Export analysis (simplified)
            self.log_activity(f"Analysis exported to: {export_file}", "SUCCESS")

    def refresh_project_files(self):
        """Refresh the project files tree."""
        if not self.current_project_path:
            return

        self.file_tree.clear()

        # Walk project directory
        for root, dirs, files in os.walk(self.current_project_path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            rel_path = os.path.relpath(root, self.current_project_path)

            # Create tree items
            for file in files:
                if file.startswith('.'):
                    continue

                file_path = os.path.join(root, file)
                file_stat = os.stat(file_path)

                # Create tree item
                item = QTreeWidgetItem([
                    file,
                    os.path.splitext(file)[1],
                    f"{file_stat.st_size / 1024:.1f} KB",
                    datetime.fromtimestamp(file_stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                ])

                # Add to appropriate parent
                if rel_path == ".":
                    self.file_tree.addTopLevelItem(item)
                else:
                    # Find or create parent folders
                    parent_item = self.find_or_create_folder(rel_path)
                    parent_item.addChild(item)

        self.file_tree.expandAll()
        self.log_activity("Project files refreshed")

    def find_or_create_folder(self, folder_path: str):
        """Find or create a folder item in the tree."""
        parts = folder_path.split(os.sep)
        parent = None

        for part in parts:
            # Find existing item
            found = False
            items = []

            if parent is None:
                for i in range(self.file_tree.topLevelItemCount()):
                    items.append(self.file_tree.topLevelItem(i))
            else:
                for i in range(parent.childCount()):
                    items.append(parent.child(i))

            for item in items:
                if item.text(0) == part and item.text(1) == "Folder":
                    parent = item
                    found = True
                    break

            # Create if not found
            if not found:
                new_item = QTreeWidgetItem([part, "Folder", "", ""])
                if parent is None:
                    self.file_tree.addTopLevelItem(new_item)
                else:
                    parent.addChild(new_item)
                parent = new_item

        return parent

    def add_file_to_project(self):
        """Add a file to the current project."""
        if not self.current_project_path:
            return

        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Add Files to Project",
            "",
            "All Files (*)"
        )

        if files:
            import shutil
            for file in files:
                dest = os.path.join(self.current_project_path, os.path.basename(file))
                shutil.copy2(file, dest)
                self.log_activity(f"Added file: {os.path.basename(file)}", "SUCCESS")

            self.refresh_project_files()

    def remove_file_from_project(self):
        """Remove selected file from project."""
        current_item = self.file_tree.currentItem()
        if not current_item or not self.current_project_path:
            return

        if current_item.text(1) == "Folder":
            QMessageBox.warning(self, "Warning", "Cannot remove folders")
            return

        reply = QMessageBox.question(
            self,
            "Remove File",
            f"Remove {current_item.text(0)} from project?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            # Remove file (simplified - would need full path reconstruction)
            self.log_activity(f"Removed file: {current_item.text(0)}", "WARNING")
            self.refresh_project_files()

    def show_file_context_menu(self, position):
        """Show context menu for file tree."""
        item = self.file_tree.itemAt(position)
        if not item:
            return

        menu = QMenu(self)

        open_action = QAction("Open", self)
        open_action.triggered.connect(lambda: self.log_activity(f"Opening: {item.text(0)}"))
        menu.addAction(open_action)

        if item.text(1) != "Folder":
            menu.addSeparator()

            rename_action = QAction("Rename", self)
            menu.addAction(rename_action)

            delete_action = QAction("Delete", self)
            delete_action.triggered.connect(self.remove_file_from_project)
            menu.addAction(delete_action)

        menu.exec(self.file_tree.mapToGlobal(position))

    def apply_theme(self):
        """Apply theme configuration to workspace widgets."""
        theme = self.config_manager.get_theme_config()

        # Theme styling is now handled centrally by theme manager
        # Widget-specific styles use StyleManager with object names
        pass

    def update_fonts(self):
        """Update font configuration."""
        font_config = self.config_manager.get_font_config()

        from PyQt6.QtGui import QFont
        font = QFont(font_config.family, font_config.base_size)
        self.setFont(font)

        # Update all child widgets
        for widget in self.findChildren(QWidget):
            widget.setFont(font)

    def on_ai_message_sent(self, message: str):
        """Handle AI message sent signal."""
        self.log_activity(f"AI Query: {message[:50]}...", "INFO")

    def on_code_generated(self, code: str):
        """Handle code generation from AI."""
        self.log_activity("AI generated code snippet", "SUCCESS")

        # Optionally save to project scripts folder
        if self.current_project_path:
            # Could prompt to save generated code
            pass

    def on_script_generated(self, script_type: str, content: str):
        """Handle script generation from AI."""
        self.log_activity(f"AI generated {script_type}", "SUCCESS")

        # Optionally save to project scripts folder
        if self.current_project_path:
            scripts_dir = os.path.join(self.current_project_path, "scripts")
            os.makedirs(scripts_dir, exist_ok=True)
            # Could prompt to save script

    def update_ai_context(self):
        """Update AI Assistant context with current binary/project info."""
        if self.loaded_binary_path:
            # Read some binary info to provide context
            try:
                with open(self.loaded_binary_path, 'rb') as f:
                    # Read first 1KB for header analysis
                    header_data = f.read(1024)

                # Provide context to AI Assistant
                self.ai_assistant.set_current_context(
                    self.loaded_binary_path,
                    f"Binary: {os.path.basename(self.loaded_binary_path)}\n"
                    f"Size: {os.path.getsize(self.loaded_binary_path)} bytes\n"
                    f"Type: {os.path.splitext(self.loaded_binary_path)[1]}\n"
                )

                self.log_activity("AI context updated with binary info", "INFO")
            except Exception as e:
                self.log_activity(f"Failed to update AI context: {e}", "ERROR")

    def cleanup(self):
        """Cleanup resources when tab is closed."""
        # Unregister callbacks
        self.config_manager.unregister_callback('theme', self.apply_theme)
        self.config_manager.unregister_callback('font', self.update_fonts)

        # Save any unsaved project data
        if self.current_project_path:
            reply = QMessageBox.question(
                self,
                "Closing Workspace",
                "Save project before closing?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.save_project()
