from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QSplitter, QGroupBox,
    QLabel, QPushButton, QLineEdit, QTextEdit, QListWidget,
    QListWidgetItem, QTreeWidget, QTreeWidgetItem, QInputDialog,
    QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from .base_tab import BaseTab
import os


class DashboardTab(BaseTab):
    """
    Dashboard Tab - Manages project files, binary information, and workspace overview.
    Consolidates functionality from the previous Project & Dashboard tab.
    """
    
    binary_selected = pyqtSignal(str)
    analysis_saved = pyqtSignal(str)
    project_opened = pyqtSignal(str)
    project_closed = pyqtSignal()
    
    def __init__(self, shared_context=None, parent=None):
        super().__init__(shared_context, parent)
        self.current_project = None
        self.current_binary = None
        self.analysis_results = {}
        
    def setup_content(self):
        """Setup the project workspace tab content"""
        layout = QHBoxLayout(self)
        
        # Left panel - Project and Binary controls
        left_panel = self.create_project_controls()
        
        # Right panel - Activity log and file management
        right_panel = self.create_activity_panel()
        
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
        self.binary_info_text.setMaximumHeight(120)
        self.binary_info_text.setReadOnly(True)
        self.binary_info_text.setPlaceholderText("Binary information will appear here...")
        binary_layout.addWidget(self.binary_info_text)
        
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
    
    def create_new_project(self):
        """Create a new project"""
        project_name, ok = QInputDialog.getText(self, "New Project", "Project Name:")
        
        if ok and project_name:
            self.current_project = project_name
            self.current_project_label.setText(f"Project: {project_name}")
            self.current_project_label.setStyleSheet("color: #0078d4; padding: 5px; font-weight: bold;")
            self.log_activity(f"Created new project: {project_name}")
            self.project_opened.emit(project_name)
    
    def open_project(self):
        """Open an existing project"""
        project_file, _ = QFileDialog.getOpenFileName(
            self,
            "Open Project",
            "",
            "Intellicrack Projects (*.icp);;All Files (*)"
        )
        
        if project_file:
            project_name = os.path.splitext(os.path.basename(project_file))[0]
            self.current_project = project_name
            self.current_project_label.setText(f"Project: {project_name}")
            self.current_project_label.setStyleSheet("color: #0078d4; padding: 5px; font-weight: bold;")
            self.log_activity(f"Opened project: {project_name}")
            self.project_opened.emit(project_file)
    
    def save_project(self):
        """Save the current project"""
        if not self.current_project:
            QMessageBox.warning(self, "Warning", "No project to save!")
            return
        
        project_file, _ = QFileDialog.getSaveFileName(
            self,
            "Save Project",
            f"{self.current_project}.icp",
            "Intellicrack Projects (*.icp);;All Files (*)"
        )
        
        if project_file:
            self.log_activity(f"Saved project: {self.current_project}")
            # Implement actual project saving logic here
    
    def browse_binary(self):
        """Browse for a binary file"""
        binary_file, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)"
        )
        
        if binary_file:
            self.binary_path_edit.setText(binary_file)
            self.current_binary = binary_file
            self.display_binary_info(binary_file)
            self.add_to_recent_files(binary_file)
            self.binary_selected.emit(binary_file)
            self.log_activity(f"Selected binary: {os.path.basename(binary_file)}")
    
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
            self.binary_info_text.setText(f"Error reading file: {str(e)}")
    
    def get_file_type(self, file_path):
        """Get basic file type information"""
        ext = os.path.splitext(file_path)[1].lower()
        
        type_map = {
            '.exe': 'Windows Executable',
            '.dll': 'Windows Dynamic Library',
            '.so': 'Linux Shared Object',
            '.dylib': 'macOS Dynamic Library',
            '.app': 'macOS Application Bundle',
            '.bin': 'Binary File',
            '.elf': 'ELF Executable'
        }
        
        return type_map.get(ext, 'Unknown Binary')
    
    def quick_analyze_binary(self):
        """Perform quick analysis of the selected binary"""
        if not self.current_binary:
            QMessageBox.warning(self, "Warning", "No binary selected!")
            return
        
        self.log_activity(f"Starting quick analysis of {os.path.basename(self.current_binary)}")
        
        # Simulate analysis (in real implementation, this would trigger actual analysis)
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
            "C:\\analysis\\crackme.exe"
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
        from datetime import datetime
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
            "Text Files (*.txt);;All Files (*)"
        )
        
        if log_file:
            try:
                with open(log_file, 'w') as f:
                    f.write(self.activity_log.toPlainText())
                self.log_activity(f"Activity log saved to: {log_file}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save log: {str(e)}")
    
    def populate_file_tree(self):
        """Populate the file tree with project files"""
        self.file_tree.clear()
        
        # Simulated project files
        if self.current_project:
            project_files = [
                ("analysis_report.pdf", "Document", "2.1 MB", "2024-01-15"),
                ("extracted_strings.txt", "Text", "45 KB", "2024-01-15"),
                ("ghidra_project.gpr", "Ghidra Project", "15 MB", "2024-01-14"),
                ("memory_dump.bin", "Binary", "128 MB", "2024-01-14"),
                ("frida_script.js", "JavaScript", "5 KB", "2024-01-13")
            ]
            
            for name, file_type, size, modified in project_files:
                item = QTreeWidgetItem([name, file_type, size, modified])
                self.file_tree.addTopLevelItem(item)
    
    def refresh_file_tree(self):
        """Refresh the file tree"""
        self.populate_file_tree()
        self.log_activity("File tree refreshed")
    
    def open_selected_file(self):
        """Open the selected file"""
        current_item = self.file_tree.currentItem()
        if current_item:
            file_name = current_item.text(0)
            self.log_activity(f"Opening file: {file_name}")
            # Implement file opening logic here
    
    def delete_selected_file(self):
        """Delete the selected file"""
        current_item = self.file_tree.currentItem()
        if current_item:
            file_name = current_item.text(0)
            reply = QMessageBox.question(
                self,
                "Delete File",
                f"Are you sure you want to delete '{file_name}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.file_tree.takeTopLevelItem(self.file_tree.indexOfTopLevelItem(current_item))
                self.log_activity(f"Deleted file: {file_name}")