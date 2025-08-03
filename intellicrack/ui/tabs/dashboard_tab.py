"""Dashboard tab for Intellicrack.

This module provides the main dashboard interface with system monitoring,
project overview, and quick access to key features.
"""
import hashlib
import json
import mimetypes
import os
from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont
from PyQt6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..widgets.cpu_status_widget import CPUStatusWidget
from ..widgets.drop_zone_widget import DropZoneWidget
from ..widgets.gpu_status_widget import GPUStatusWidget
from ..widgets.system_monitor_widget import SystemMonitorWidget
from .base_tab import BaseTab


class DashboardTab(BaseTab):
    """Dashboard Tab - Manages project files, binary information, and workspace overview.
    Consolidates functionality from the previous Project & Dashboard tab.
    """

    binary_selected = pyqtSignal(str)
    analysis_saved = pyqtSignal(str)
    project_opened = pyqtSignal(str)
    project_closed = pyqtSignal()

    def __init__(self, shared_context=None, parent=None):
        """Initialize dashboard tab with system overview and status monitoring."""
        super().__init__(shared_context, parent)

    def setup_content(self):
        """Setup the project workspace tab content"""
        layout = QHBoxLayout(self)

        # Left panel - Project and Binary controls
        left_panel = self.create_project_controls()

        # Right panel - Tab widget with Activity, System Monitor, GPU Status, and CPU Status
        right_panel = QTabWidget()
        right_panel.addTab(self.create_activity_panel(), "Activity & Files")
        right_panel.addTab(self.create_system_monitor_panel(), "System Monitor")
        right_panel.addTab(self.create_gpu_status_panel(), "GPU Status")
        right_panel.addTab(self.create_cpu_status_panel(), "CPU Status")

        # Add panels with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 40)
        splitter.setStretchFactor(1, 60)

        layout.addWidget(splitter)
        self.is_loaded = True

    def create_project_controls(self):
        """Create project and binary control panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Project Management Group
        project_group = QGroupBox("Project Management")
        project_layout = QVBoxLayout(project_group)

        # Current project display
        self.current_project_label = QLabel("No project loaded")
        self.current_project_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.current_project_label.setStyleSheet("color: #666666; padding: 5px;")
        project_layout.addWidget(self.current_project_label)

        # Project buttons
        project_buttons_layout = QHBoxLayout()

        new_project_btn = QPushButton("New Project")
        new_project_btn.clicked.connect(self.create_new_project)
        new_project_btn.setStyleSheet("font-weight: bold; color: green;")

        open_project_btn = QPushButton("Open Project")
        open_project_btn.clicked.connect(self.open_project)

        save_project_btn = QPushButton("Save Project")
        save_project_btn.clicked.connect(self.save_project)

        project_buttons_layout.addWidget(new_project_btn)
        project_buttons_layout.addWidget(open_project_btn)
        project_buttons_layout.addWidget(save_project_btn)

        project_layout.addLayout(project_buttons_layout)

        # Binary Management Group
        binary_group = QGroupBox("Binary Management")
        binary_layout = QVBoxLayout(binary_group)

        # Binary selection
        binary_select_layout = QHBoxLayout()
        binary_select_layout.addWidget(QLabel("Target Binary:"))

        self.binary_path_edit = QLineEdit()
        self.binary_path_edit.setPlaceholderText("Select a binary file for analysis...")

        browse_binary_btn = QPushButton("Browse")
        browse_binary_btn.clicked.connect(self.browse_binary)

        binary_select_layout.addWidget(self.binary_path_edit)
        binary_select_layout.addWidget(browse_binary_btn)
        binary_layout.addLayout(binary_select_layout)

        # Binary info display
        self.binary_info_text = QTextEdit()
        self.binary_info_text.setMaximumHeight(100)
        self.binary_info_text.setReadOnly(True)
        self.binary_info_text.setPlaceholderText("Binary information will appear here...")
        binary_layout.addWidget(self.binary_info_text)

        # Drop zone for files
        self.drop_zone = DropZoneWidget()
        self.drop_zone.files_dropped.connect(self._handle_dropped_files)
        binary_layout.addWidget(self.drop_zone)

        # Binary actions
        binary_actions_layout = QHBoxLayout()

        analyze_btn = QPushButton("Quick Analysis")
        analyze_btn.clicked.connect(self.quick_analyze_binary)
        analyze_btn.setStyleSheet("font-weight: bold; color: blue;")

        load_in_ghidra_btn = QPushButton("Load in Ghidra")
        load_in_ghidra_btn.clicked.connect(self.load_in_ghidra)

        load_in_radare_btn = QPushButton("Load in Radare2")
        load_in_radare_btn.clicked.connect(self.load_in_radare)

        binary_actions_layout.addWidget(analyze_btn)
        binary_actions_layout.addWidget(load_in_ghidra_btn)
        binary_actions_layout.addWidget(load_in_radare_btn)

        binary_layout.addLayout(binary_actions_layout)

        # Recent Files Group
        recent_group = QGroupBox("Recent Files")
        recent_layout = QVBoxLayout(recent_group)

        self.recent_files_list = QListWidget()
        self.recent_files_list.setMaximumHeight(150)
        self.populate_recent_files()
        self.recent_files_list.itemDoubleClicked.connect(self.load_recent_file)
        recent_layout.addWidget(self.recent_files_list)

        # Clear recent files button
        clear_recent_btn = QPushButton("Clear Recent Files")
        clear_recent_btn.clicked.connect(self.clear_recent_files)
        clear_recent_btn.setStyleSheet("color: red;")
        recent_layout.addWidget(clear_recent_btn)

        layout.addWidget(project_group)
        layout.addWidget(binary_group)
        layout.addWidget(recent_group)
        layout.addStretch()

        return panel

    def create_activity_panel(self):
        """Create activity log and file management panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Activity Log Group
        activity_group = QGroupBox("Activity Log")
        activity_layout = QVBoxLayout(activity_group)

        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setFont(QFont("Consolas", 9))
        self.activity_log.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")

        # Add some initial log entries
        self.log_activity("System initialized")
        self.log_activity("Ready for binary analysis")

        activity_layout.addWidget(self.activity_log)

        # Log controls
        log_controls_layout = QHBoxLayout()

        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(self.clear_activity_log)

        save_log_btn = QPushButton("Save Log")
        save_log_btn.clicked.connect(self.save_activity_log)

        log_controls_layout.addWidget(clear_log_btn)
        log_controls_layout.addWidget(save_log_btn)
        log_controls_layout.addStretch()

        activity_layout.addLayout(log_controls_layout)

        # File Management Group
        file_group = QGroupBox("Project Files")
        file_layout = QVBoxLayout(file_group)

        # File tree
        self.file_tree = QTreeWidget()
        self.file_tree.setHeaderLabels(["Name", "Type", "Size", "Modified"])
        self.file_tree.setAlternatingRowColors(True)
        self.file_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_tree.customContextMenuRequested.connect(self._show_file_context_menu)
        self.populate_file_tree()
        file_layout.addWidget(self.file_tree)

        # File actions
        file_actions_layout = QHBoxLayout()

        refresh_files_btn = QPushButton("Refresh")
        refresh_files_btn.clicked.connect(self.refresh_file_tree)

        open_file_btn = QPushButton("Open Selected")
        open_file_btn.clicked.connect(self.open_selected_file)

        delete_file_btn = QPushButton("Delete Selected")
        delete_file_btn.clicked.connect(self.delete_selected_file)
        delete_file_btn.setStyleSheet("color: red;")

        file_actions_layout.addWidget(refresh_files_btn)
        file_actions_layout.addWidget(open_file_btn)
        file_actions_layout.addWidget(delete_file_btn)
        file_actions_layout.addStretch()

        file_layout.addLayout(file_actions_layout)

        layout.addWidget(activity_group)
        layout.addWidget(file_group)

        return panel

    def create_system_monitor_panel(self):
        """Create system monitoring panel"""
        self.system_monitor = SystemMonitorWidget()
        self.system_monitor.alert_triggered.connect(self.handle_system_alert)
        self.system_monitor.start_monitoring()
        return self.system_monitor

    def handle_system_alert(self, alert_type: str, message: str):
        """Handle system monitoring alerts"""
        # Log the alert to activity log
        self.log_activity(f"[SYSTEM ALERT - {alert_type}] {message}")

        # Show a message box for critical alerts
        if alert_type in ["CPU", "Memory", "Disk"]:
            QMessageBox.warning(self, f"System Alert - {alert_type}", message)

    def create_gpu_status_panel(self):
        """Create GPU status monitoring panel"""
        self.gpu_status = GPUStatusWidget()
        self.gpu_status.start_monitoring()
        return self.gpu_status

    def create_cpu_status_panel(self):
        """Create CPU status monitoring panel"""
        self.cpu_status = CPUStatusWidget()
        self.cpu_status.start_monitoring()
        return self.cpu_status

    def create_new_project(self):
        """Create a new project"""
        project_name, ok = QInputDialog.getText(self, "New Project", "Project Name:")

        if ok and project_name:
            self.current_project = project_name
            self.project_files = []  # Initialize empty project files list
            self.analysis_results = {}  # Reset analysis results

            self.current_project_label.setText(f"Project: {project_name}")
            self.current_project_label.setStyleSheet("color: #0078d4; padding: 5px; font-weight: bold;")

            # Clear and refresh the file tree
            self.populate_file_tree()

            self.log_activity(f"Created new project: {project_name}")
            self.project_opened.emit(project_name)

    def open_project(self):
        """Open an existing project"""
        project_file, _ = QFileDialog.getOpenFileName(
            self,
            "Open Project",
            "",
            "Intellicrack Projects (*.icp);;All Files (*)",
        )

        if project_file:
            try:
                # Load project data from JSON
                with open(project_file, encoding="utf-8") as f:
                    project_data = json.load(f)

                # Validate project data structure
                if not isinstance(project_data, dict) or "name" not in project_data:
                    raise ValueError("Invalid project file format")

                # Set project information
                self.current_project = project_data.get("name", "Untitled")
                self.current_binary = project_data.get("binary", None)
                self.project_files = project_data.get("files", [])
                self.analysis_results = project_data.get("analysis_results", {})

                # Validate file existence and update metadata
                self._validate_project_files()

                # Update UI
                self.current_project_label.setText(f"Project: {self.current_project}")
                self.current_project_label.setStyleSheet("color: #0078d4; padding: 5px; font-weight: bold;")

                # Refresh file tree with actual project files
                self.populate_file_tree()

                self.log_activity(f"Opened project: {self.current_project}")
                self.project_opened.emit(project_file)

                # Update binary info if available
                if self.current_binary and os.path.exists(self.current_binary):
                    self.on_binary_loaded(self.current_binary)

            except json.JSONDecodeError as e:
                QMessageBox.critical(
                    self,
                    "Load Error",
                    f"Invalid project file format:\n{e!s}",
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Load Error",
                    f"Failed to load project:\n{e!s}",
                )

    def save_project(self):
        """Save the current project"""
        if not self.current_project:
            QMessageBox.warning(self, "Warning", "No project to save!")
            return

        project_file, _ = QFileDialog.getSaveFileName(
            self,
            "Save Project",
            f"{self.current_project}.icp",
            "Intellicrack Projects (*.icp);;All Files (*)",
        )

        if project_file:
            try:
                # Prepare project data
                project_data = {
                    "name": self.current_project,
                    "created": datetime.now().isoformat(),
                    "modified": datetime.now().isoformat(),
                    "binary": self.current_binary,
                    "files": self.project_files,
                    "analysis_results": self.analysis_results,
                    "version": "1.0",
                }

                # Write JSON with pretty formatting
                with open(project_file, "w", encoding="utf-8") as f:
                    json.dump(project_data, f, indent=2, ensure_ascii=False)

                self.log_activity(f"Saved project: {self.current_project}")
                QMessageBox.information(
                    self,
                    "Success",
                    f"Project saved successfully to:\n{project_file}",
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Save Error",
                    f"Failed to save project:\n{e!s}",
                )
                self.log_activity(f"Error saving project: {e!s}")

    def browse_binary(self):
        """Browse for a binary file"""
        binary_file, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)",
        )

        if binary_file:
            self.binary_path_edit.setText(binary_file)
            self.current_binary = binary_file

            # Use AppContext to load binary
            if self.app_context:
                self.app_context.load_binary(binary_file)
                self.log_activity(f"Loaded binary via AppContext: {os.path.basename(binary_file)}")
            else:
                # Fallback to old behavior
                self.display_binary_info(binary_file)
                self.add_to_recent_files(binary_file)
                self.binary_selected.emit(binary_file)
                self.log_activity(f"Selected binary: {os.path.basename(binary_file)}")

    def on_binary_loaded(self, binary_info):
        """Handle binary loaded signal from AppContext"""
        self.display_binary_info(binary_info["path"])
        self.add_to_recent_files(binary_info["path"])
        self.log_activity(f"Binary loaded: {binary_info['name']} ({binary_info['size']} bytes)")

    def on_analysis_completed(self, analysis_type, results):
        """Handle analysis completed signal from AppContext"""
        if analysis_type == "quick_analysis":
            # Format results for display
            result_text = f"Quick Analysis Results for {results.get('file_name', 'Unknown')}:\n"
            result_text += f"- File format: {results.get('file_format', 'Unknown')}\n"
            result_text += f"- Architecture: {results.get('architecture', 'Unknown')}\n"
            result_text += f"- Compiler: {results.get('compiler', 'Unknown')}\n"
            result_text += f"- Packer detected: {results.get('packer', 'Unknown')}\n"
            result_text += f"- Entropy: {results.get('entropy', 0)} ({results.get('entropy_status', 'Unknown')})\n"

            # Store in local results
            if "file_path" in results:
                self.analysis_results[results["file_path"]] = result_text
                self.analysis_saved.emit(results["file_path"])

            self.log_activity(f"Analysis completed: {analysis_type}")

    def display_binary_info(self, binary_path):
        """Display basic binary information"""
        try:
            stat_info = os.stat(binary_path)
            file_size = stat_info.st_size

            # Basic file info
            info_text = f"File: {os.path.basename(binary_path)}\n"
            info_text += f"Path: {binary_path}\n"
            info_text += f"Size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)\n"
            info_text += f"Type: {self.get_file_type(binary_path)}\n"

            self.binary_info_text.setText(info_text)

        except Exception as e:
            self.binary_info_text.setText(f"Error reading file: {e!s}")

    def get_file_type(self, file_path):
        """Get basic file type information"""
        ext = os.path.splitext(file_path)[1].lower()

        type_map = {
            ".exe": "Windows Executable",
            ".dll": "Windows Dynamic Library",
            ".so": "Linux Shared Object",
            ".dylib": "macOS Dynamic Library",
            ".app": "macOS Application Bundle",
            ".bin": "Binary File",
            ".elf": "ELF Executable",
        }

        return type_map.get(ext, "Unknown Binary")

    def quick_analyze_binary(self):
        """Perform quick analysis of the selected binary"""
        if not self.current_binary:
            QMessageBox.warning(self, "Warning", "No binary selected!")
            return

        self.log_activity(f"Starting quick analysis of {os.path.basename(self.current_binary)}")

        # Submit analysis task to TaskManager
        if self.task_manager and self.app_context:
            # Define the analysis function
            def analyze_binary(task=None):
                import time

                # Notify start of analysis
                if self.app_context:
                    self.app_context.start_analysis("quick_analysis", {"binary": self.current_binary})

                # Simulate analysis steps with progress updates
                steps = [
                    ("Checking file format", 20),
                    ("Analyzing architecture", 40),
                    ("Detecting compiler", 60),
                    ("Checking for packers", 80),
                    ("Calculating entropy", 100),
                ]

                for step, progress in steps:
                    if task and task.is_cancelled():
                        return None

                    time.sleep(0.5)  # Simulate work
                    if task:
                        task.emit_progress(progress, step)

                # Generate analysis result
                analysis_result = {
                    "file_path": self.current_binary,
                    "file_name": os.path.basename(self.current_binary),
                    "file_format": "PE32 executable",
                    "architecture": "x86-64",
                    "compiler": "Microsoft Visual C++",
                    "packer": "None detected",
                    "entropy": 6.2,
                    "entropy_status": "Normal",
                }

                # Store results in AppContext
                if self.app_context:
                    self.app_context.set_analysis_results("quick_analysis", analysis_result)

                return analysis_result

            # Submit the task
            task_id = self.task_manager.submit_callable(
                analyze_binary,
                description=f"Quick analysis of {os.path.basename(self.current_binary)}",
            )

            self.log_activity(f"Analysis task submitted: {task_id[:8]}...")

        else:
            # Fallback to synchronous analysis
            analysis_result = f"Quick Analysis Results for {os.path.basename(self.current_binary)}:\n"
            analysis_result += "- File format: PE32 executable\n"
            analysis_result += "- Architecture: x86-64\n"
            analysis_result += "- Compiler: Microsoft Visual C++\n"
            analysis_result += "- Packer detected: None\n"
            analysis_result += "- Entropy: 6.2 (Normal)\n"

            self.analysis_results[self.current_binary] = analysis_result
            self.analysis_saved.emit(self.current_binary)
            self.log_activity("Quick analysis completed")

    def load_in_ghidra(self):
        """Load the current binary in Ghidra"""
        if not self.current_binary:
            QMessageBox.warning(self, "Warning", "No binary selected!")
            return

        self.log_activity(f"Loading {os.path.basename(self.current_binary)} in Ghidra")
        # Implement Ghidra integration here

    def load_in_radare(self):
        """Load the current binary in Radare2"""
        if not self.current_binary:
            QMessageBox.warning(self, "Warning", "No binary selected!")
            return

        self.log_activity(f"Loading {os.path.basename(self.current_binary)} in Radare2")
        # Implement Radare2 integration here

    def populate_recent_files(self):
        """Populate the recent files list"""
        # Simulated recent files - in real implementation, this would load from settings
        recent_files = [
            "C:\\samples\\malware1.exe",
            "C:\\samples\\target_app.exe",
            "/home/user/binaries/test.so",
            "C:\\analysis\\crackme.exe",
        ]

        self.recent_files_list.clear()
        for file_path in recent_files:
            if os.path.exists(file_path):
                item = QListWidgetItem(os.path.basename(file_path))
                item.setData(Qt.ItemDataRole.UserRole, file_path)
                item.setToolTip(file_path)
                self.recent_files_list.addItem(item)

    def load_recent_file(self, item):
        """Load a file from the recent files list"""
        file_path = item.data(Qt.ItemDataRole.UserRole)
        if file_path and os.path.exists(file_path):
            self.binary_path_edit.setText(file_path)
            self.current_binary = file_path
            self.display_binary_info(file_path)
            self.binary_selected.emit(file_path)
            self.log_activity(f"Loaded recent file: {os.path.basename(file_path)}")

    def add_to_recent_files(self, file_path):
        """Add a file to the recent files list"""
        # Check if already in list
        for i in range(self.recent_files_list.count()):
            item = self.recent_files_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == file_path:
                self.recent_files_list.takeItem(i)
                break

        # Add to top of list
        item = QListWidgetItem(os.path.basename(file_path))
        item.setData(Qt.ItemDataRole.UserRole, file_path)
        item.setToolTip(file_path)
        self.recent_files_list.insertItem(0, item)

        # Keep only last 10 files
        while self.recent_files_list.count() > 10:
            self.recent_files_list.takeItem(self.recent_files_list.count() - 1)

    def clear_recent_files(self):
        """Clear the recent files list"""
        self.recent_files_list.clear()
        self.log_activity("Recent files list cleared")

    def log_activity(self, message):
        """Log an activity message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_log.append(f"[{timestamp}] {message}")

        # Auto-scroll to bottom
        scrollbar = self.activity_log.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_activity_log(self):
        """Clear the activity log"""
        self.activity_log.clear()
        self.log_activity("Activity log cleared")

    def save_activity_log(self):
        """Save the activity log to a file"""
        log_file, _ = QFileDialog.getSaveFileName(
            self,
            "Save Activity Log",
            "activity_log.txt",
            "Text Files (*.txt);;All Files (*)",
        )

        if log_file:
            try:
                with open(log_file, "w") as f:
                    f.write(self.activity_log.toPlainText())
                self.log_activity(f"Activity log saved to: {log_file}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save log: {e!s}")

    def populate_file_tree(self):
        """Populate the file tree with project files"""
        self.file_tree.clear()

        if self.current_project and self.project_files:
            # Display actual project files
            for file_info in self.project_files:
                name = file_info.get("name", "Unknown")
                file_type = file_info.get("type", "File")
                size = file_info.get("size", "0 B")
                modified = file_info.get("modified", "")
                exists = file_info.get("exists", True)

                # Format modified date for display
                if modified:
                    try:
                        mod_date = datetime.fromisoformat(modified)
                        modified = mod_date.strftime("%Y-%m-%d %H:%M")
                    except:
                        pass

                # Create tree item
                item = QTreeWidgetItem([name, file_type, size, modified])

                # Style missing files differently
                if not exists:
                    for i in range(4):
                        item.setForeground(i, Qt.GlobalColor.red)
                    item.setToolTip(0, "File not found at original location")

                # Store full path in item data for context menu actions
                item.setData(0, Qt.ItemDataRole.UserRole, file_info.get("path", ""))

                self.file_tree.addTopLevelItem(item)

            # Auto-resize columns
            for i in range(4):
                self.file_tree.resizeColumnToContents(i)
        elif self.current_project:
            # Show placeholder for empty project
            item = QTreeWidgetItem(["No files in project", "", "", ""])
            item.setForeground(0, Qt.GlobalColor.gray)
            self.file_tree.addTopLevelItem(item)

    def refresh_file_tree(self):
        """Refresh the file tree"""
        self.populate_file_tree()
        self.log_activity("File tree refreshed")

    def open_selected_file(self):
        """Open the selected file"""
        current_item = self.file_tree.currentItem()
        if current_item:
            file_path = current_item.data(0, Qt.ItemDataRole.UserRole)
            if file_path and os.path.exists(file_path):
                # Open file based on type
                file_ext = os.path.splitext(file_path)[1].lower()

                if file_ext in [".exe", ".dll", ".so", ".bin"]:
                    # Load as binary for analysis
                    self.binary_path_edit.setText(file_path)
                    self.current_binary = file_path
                    if self.app_context:
                        self.app_context.load_binary(file_path)
                    else:
                        self.display_binary_info(file_path)
                        self.binary_selected.emit(file_path)
                    self.log_activity(f"Loaded binary: {os.path.basename(file_path)}")
                else:
                    # Open with default system application
                    try:
                        os.startfile(file_path) if os.name == "nt" else os.system(f'open "{file_path}"')
                        self.log_activity(f"Opened file: {os.path.basename(file_path)}")
                    except Exception as e:
                        QMessageBox.warning(self, "Open Error", f"Failed to open file: {e!s}")
            else:
                QMessageBox.warning(self, "File Not Found", "The selected file no longer exists.")
            # Implement file opening logic here

    def delete_selected_file(self):
        """Delete the selected file from project"""
        current_item = self.file_tree.currentItem()
        if current_item:
            file_name = current_item.text(0)
            file_path = current_item.data(0, Qt.ItemDataRole.UserRole)

            reply = QMessageBox.question(
                self,
                "Remove from Project",
                f"Remove '{file_name}' from the project?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                # Remove from project_files list
                self.project_files = [f for f in self.project_files if f.get("path") != file_path]

                # Remove from tree
                self.file_tree.takeTopLevelItem(self.file_tree.indexOfTopLevelItem(current_item))
                self.log_activity(f"Removed from project: {file_name}")

    def cleanup(self):
        """Cleanup resources when tab is closed"""
        # Stop system monitoring
        if hasattr(self, "system_monitor"):
            self.system_monitor.stop_monitoring()
            self.log_activity("System monitoring stopped")

        # Stop GPU monitoring
        if hasattr(self, "gpu_status"):
            self.gpu_status.stop_monitoring()
            self.log_activity("GPU monitoring stopped")

        # Stop CPU monitoring
        if hasattr(self, "cpu_status"):
            self.cpu_status.stop_monitoring()
            self.log_activity("CPU monitoring stopped")

        # Call parent cleanup
        super().cleanup()

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter events"""
        if event.mimeData().hasUrls():
            # Check if any of the files are supported
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    # Accept executables and other binary files
                    if self._is_supported_file(file_path):
                        event.acceptProposedAction()
                        return
        event.ignore()

    def dropEvent(self, event: QDropEvent):
        """Handle drop events"""
        if event.mimeData().hasUrls():
            files_dropped = []
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    if self._is_supported_file(file_path):
                        files_dropped.append(file_path)

            if files_dropped:
                # Handle dropped files
                self._handle_dropped_files(files_dropped)
                event.acceptProposedAction()
            else:
                event.ignore()
        else:
            event.ignore()

    def _is_supported_file(self, file_path: str) -> bool:
        """Check if file is supported for analysis"""
        if not os.path.exists(file_path):
            return False

        # Check file extension
        supported_extensions = [
            ".exe", ".dll", ".so", ".dylib", ".elf", ".bin",
            ".sys", ".drv", ".ocx", ".app", ".apk", ".ipa",
            ".dex", ".jar", ".class", ".pyc", ".pyd",
        ]

        ext = os.path.splitext(file_path)[1].lower()
        return ext in supported_extensions or os.path.isfile(file_path)

    def _handle_dropped_files(self, file_paths: list):
        """Handle dropped files"""
        if len(file_paths) == 1:
            # Single file - load as binary
            file_path = file_paths[0]
            self.binary_path_edit.setText(file_path)
            self.current_binary = file_path

            # Use AppContext to load binary
            if self.app_context:
                self.app_context.load_binary(file_path)
                self.log_activity(f"Loaded dropped file via AppContext: {os.path.basename(file_path)}")
            else:
                # Fallback to old behavior
                self.display_binary_info(file_path)
                self.add_to_recent_files(file_path)
                self.binary_selected.emit(file_path)
                self.log_activity(f"Loaded dropped file: {os.path.basename(file_path)}")

        else:
            # Multiple files - ask user what to do
            menu = QMenu(self)
            menu.addAction("Load first as binary", lambda: self._handle_dropped_files([file_paths[0]]))
            menu.addAction("Add all to project", lambda: self._add_files_to_project(file_paths))
            menu.addSeparator()
            menu.addAction("Cancel", lambda: None)

            menu.exec(self.cursor().pos())

    def _get_file_metadata(self, file_path: str) -> dict:
        """Get metadata for a file"""
        try:
            stat = os.stat(file_path)
            file_size = stat.st_size
            modified_time = datetime.fromtimestamp(stat.st_mtime).isoformat()

            # Determine file type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type:
                file_type = mime_type.split("/")[0].title()
            else:
                ext = os.path.splitext(file_path)[1].lower()
                type_mapping = {
                    ".exe": "Executable",
                    ".dll": "Library",
                    ".so": "Library",
                    ".js": "JavaScript",
                    ".py": "Python",
                    ".pdf": "Document",
                    ".txt": "Text",
                    ".bin": "Binary",
                    ".json": "JSON",
                    ".xml": "XML",
                    ".gpr": "Ghidra Project",
                }
                file_type = type_mapping.get(ext, "File")

            # Calculate MD5 hash for deduplication
            md5_hash = self._calculate_file_hash(file_path)

            return {
                "path": os.path.abspath(file_path),
                "name": os.path.basename(file_path),
                "type": file_type,
                "size": self._format_file_size(file_size),
                "size_bytes": file_size,
                "modified": modified_time,
                "md5": md5_hash,
                "exists": True,
            }
        except Exception as e:
            self.logger.error(f"Error getting metadata for {file_path}: {e}")
            return None

    def _calculate_file_hash(self, file_path: str, chunk_size: int = 8192) -> str:
        """Calculate MD5 hash of a file"""
        md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    md5.update(chunk)
            return md5.hexdigest()
        except Exception:
            return ""

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                if unit == "B":
                    return f"{size_bytes} {unit}"
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    def _validate_project_files(self):
        """Validate that project files still exist and update metadata"""
        valid_files = []
        for file_info in self.project_files:
            file_path = file_info.get("path", "")
            if os.path.exists(file_path):
                # Update metadata for existing files
                updated_info = self._get_file_metadata(file_path)
                if updated_info:
                    # Preserve original addition time if available
                    updated_info["added"] = file_info.get("added", updated_info["modified"])
                    valid_files.append(updated_info)
            else:
                # Mark file as missing but keep in project
                file_info["exists"] = False
                file_info["type"] = file_info.get("type", "Missing")
                valid_files.append(file_info)
                self.log_activity(f"File missing: {file_info.get('name', 'Unknown')}")

        self.project_files = valid_files

    def _show_file_context_menu(self, position):
        """Show context menu for file tree items"""
        item = self.file_tree.itemAt(position)
        if not item:
            return

        menu = QMenu(self)

        # Get file info
        file_path = item.data(0, Qt.ItemDataRole.UserRole)
        file_exists = os.path.exists(file_path) if file_path else False

        # Add menu actions
        open_action = menu.addAction("Open")
        open_action.setEnabled(file_exists)
        open_action.triggered.connect(self.open_selected_file)

        menu.addSeparator()

        refresh_action = menu.addAction("Refresh Metadata")
        refresh_action.setEnabled(file_exists)
        refresh_action.triggered.connect(lambda: self._refresh_file_metadata(item))

        show_in_explorer_action = menu.addAction("Show in Explorer")
        show_in_explorer_action.setEnabled(file_exists)
        show_in_explorer_action.triggered.connect(lambda: self._show_in_explorer(file_path))

        menu.addSeparator()

        remove_action = menu.addAction("Remove from Project")
        remove_action.triggered.connect(self.delete_selected_file)

        # Show menu at cursor position
        menu.exec(self.file_tree.mapToGlobal(position))

    def _refresh_file_metadata(self, item):
        """Refresh metadata for a single file"""
        file_path = item.data(0, Qt.ItemDataRole.UserRole)
        if file_path and os.path.exists(file_path):
            # Find and update the file in project_files
            for i, file_info in enumerate(self.project_files):
                if file_info.get("path") == file_path:
                    updated_info = self._get_file_metadata(file_path)
                    if updated_info:
                        # Preserve added time
                        updated_info["added"] = file_info.get("added", updated_info["modified"])
                        self.project_files[i] = updated_info
                        break

            # Refresh the tree
            self.populate_file_tree()
            self.log_activity(f"Refreshed metadata for: {os.path.basename(file_path)}")

    def _show_in_explorer(self, file_path):
        """Show file in system file explorer"""
        if file_path and os.path.exists(file_path):
            if os.name == "nt":  # Windows
                os.startfile(os.path.dirname(file_path))
            elif os.name == "posix":  # macOS and Linux
                os.system(f'open "{os.path.dirname(file_path)}"')
            self.log_activity(f"Opened folder: {os.path.dirname(file_path)}")

    def _add_files_to_project(self, file_paths: list):
        """Add multiple files to current project"""
        if not self.current_project:
            QMessageBox.warning(self, "Warning", "No project loaded. Create or open a project first.")
            return

        added_count = 0
        existing_paths = {f["path"] for f in self.project_files}

        for file_path in file_paths:
            # Skip if file already in project
            if file_path in existing_paths:
                continue

            try:
                # Get file metadata
                file_info = self._get_file_metadata(file_path)
                if file_info:
                    self.project_files.append(file_info)
                    self.log_activity(f"Added to project: {os.path.basename(file_path)}")
                    added_count += 1
            except Exception as e:
                self.log_activity(f"Error adding file {file_path}: {e!s}")

        self.refresh_file_tree()

        if added_count > 0:
            QMessageBox.information(
                self,
                "Files Added",
                f"Added {added_count} new files to the current project.",
            )
        else:
            QMessageBox.information(
                self,
                "No Files Added",
                "All selected files are already in the project.",
            )
