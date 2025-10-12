"""Project workspace tab for Intellicrack.

This module provides the project workspace interface for file management,
project organization, and workspace-specific operations.

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

from intellicrack.handlers.pyqt6_handler import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    Qt,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from .base_tab import BaseTab


class DashboardTab(BaseTab):
    """Dashboard Tab - Manages project files, binary information, and workspace overview.

    Consolidates functionality from the previous Project & Dashboard tab.
    """

    binary_selected = pyqtSignal(str)
    analysis_saved = pyqtSignal(str)

    def __init__(self, shared_context=None, parent=None):
        """Initialize project workspace tab with file management and workspace overview."""
        super().__init__(shared_context, parent)
        self.current_binary_path = None
        self.recent_files = []

    def setup_content(self):
        """Setup the complete Project Workspace tab content."""
        main_layout = QVBoxLayout(self)

        # Create horizontal splitter for left and right panels
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Project Controls
        left_panel = self.create_project_controls_panel()
        splitter.addWidget(left_panel)

        # Right panel - Dashboard Overview
        right_panel = self.create_dashboard_overview_panel()
        splitter.addWidget(right_panel)

        # Set splitter proportions (30% left, 70% right)
        splitter.setSizes([300, 700])

        main_layout.addWidget(splitter)

    def create_project_controls_panel(self):
        """Create the project controls panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Project Management section
        project_mgmt_group = QGroupBox("Project Management")
        project_mgmt_layout = QVBoxLayout(project_mgmt_group)

        # New Project button
        new_project_btn = QPushButton("New Project")
        new_project_btn.clicked.connect(self.create_new_project)

        # Open Project button
        open_project_btn = QPushButton("Open Project")
        open_project_btn.clicked.connect(self.open_project)

        # Save Project button
        save_project_btn = QPushButton("Save Project")
        save_project_btn.clicked.connect(self.save_project)

        project_mgmt_layout.addWidget(new_project_btn)
        project_mgmt_layout.addWidget(open_project_btn)
        project_mgmt_layout.addWidget(save_project_btn)

        # Binary Controls section
        binary_controls_group = QGroupBox("Binary Controls")
        binary_controls_layout = QVBoxLayout(binary_controls_group)

        # Open Binary button
        open_binary_btn = QPushButton("Open Binary...")
        open_binary_btn.clicked.connect(self.select_binary)

        # Recent Files button with menu
        recent_files_btn = QPushButton("Recent Files")
        self.recent_files_menu = QMenu(recent_files_btn)
        recent_files_btn.setMenu(self.recent_files_menu)
        self.update_recent_files_menu()

        # Close Binary button
        close_binary_btn = QPushButton("Close Binary")
        close_binary_btn.clicked.connect(self.close_binary)

        binary_controls_layout.addWidget(open_binary_btn)
        binary_controls_layout.addWidget(recent_files_btn)
        binary_controls_layout.addWidget(close_binary_btn)

        # Analysis Controls section
        analysis_controls_group = QGroupBox("Analysis Controls")
        analysis_controls_layout = QVBoxLayout(analysis_controls_group)

        # Save Analysis Results button
        save_analysis_btn = QPushButton("Save Analysis Results...")
        save_analysis_btn.clicked.connect(self.save_analysis_results)

        # Export Results button
        export_results_btn = QPushButton("Export Results...")
        export_results_btn.clicked.connect(self.export_results)

        # Clear Analysis button
        clear_analysis_btn = QPushButton("Clear Analysis")
        clear_analysis_btn.clicked.connect(self.clear_analysis)

        analysis_controls_layout.addWidget(save_analysis_btn)
        analysis_controls_layout.addWidget(export_results_btn)
        analysis_controls_layout.addWidget(clear_analysis_btn)

        # Add all groups to main layout
        layout.addWidget(project_mgmt_group)
        layout.addWidget(binary_controls_group)
        layout.addWidget(analysis_controls_group)
        layout.addStretch()  # Push everything to top

        return panel

    def create_dashboard_overview_panel(self):
        """Create the dashboard overview panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Binary Information section
        binary_info_group = QGroupBox("Binary Information")
        binary_info_layout = QVBoxLayout(binary_info_group)

        # Binary icon and info layout
        binary_header_layout = QHBoxLayout()

        # Binary icon
        self.binary_icon_label = QLabel()
        self.binary_icon_label.setFixedSize(64, 64)
        self.binary_icon_label.setStyleSheet("border: 1px solid gray;")
        binary_header_layout.addWidget(self.binary_icon_label)

        # Binary information
        self.binary_info_label = QLabel("No binary loaded")
        self.binary_info_label.setWordWrap(True)
        binary_header_layout.addWidget(self.binary_info_label)

        binary_info_layout.addLayout(binary_header_layout)

        # Quick Statistics section
        quick_stats_group = QGroupBox("Quick Statistics")
        quick_stats_layout = QVBoxLayout(quick_stats_group)

        # Statistics labels
        self.file_size_label = QLabel("File Size: -")
        self.architecture_label = QLabel("Architecture: -")
        self.entry_point_label = QLabel("Entry Point: -")
        self.vulns_found_label = QLabel("Vulnerabilities Found: 0")
        self.protections_label = QLabel("Protections Detected: None")
        self.patches_label = QLabel("Patches: 0/0 (Applied/Pending)")

        quick_stats_layout.addWidget(self.file_size_label)
        quick_stats_layout.addWidget(self.architecture_label)
        quick_stats_layout.addWidget(self.entry_point_label)
        quick_stats_layout.addWidget(self.vulns_found_label)
        quick_stats_layout.addWidget(self.protections_label)
        quick_stats_layout.addWidget(self.patches_label)

        # Project Activity Log section
        activity_log_group = QGroupBox("Project Activity Log")
        activity_log_layout = QVBoxLayout(activity_log_group)

        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMaximumHeight(200)

        # Clear log button
        clear_log_btn = QPushButton("Clear Log")
        clear_log_btn.clicked.connect(self.clear_activity_log)

        activity_log_layout.addWidget(self.activity_log)
        activity_log_layout.addWidget(clear_log_btn)

        # Add all groups to main layout
        layout.addWidget(binary_info_group)
        layout.addWidget(quick_stats_group)
        layout.addWidget(activity_log_group)
        layout.addStretch()  # Push everything to top

        return panel

    def create_new_project(self):
        """Create a new project."""
        self.log_activity("Creating new project...")
        # Implementation would go here

    def open_project(self):
        """Open an existing project."""
        file_dialog = QFileDialog()
        project_file, _ = file_dialog.getOpenFileName(
            self,
            "Open Project",
            "",
            "Intellicrack Projects (*.icp);;All Files (*)",
        )
        if project_file:
            self.log_activity(f"Opening project: {project_file}")
            # Implementation would go here

    def save_project(self):
        """Save the current project."""
        if not self.current_binary_path:
            QMessageBox.information(self, "Save Project", "No binary loaded to save.")
            return

        file_dialog = QFileDialog()
        project_file, _ = file_dialog.getSaveFileName(
            self,
            "Save Project",
            "",
            "Intellicrack Projects (*.icp);;All Files (*)",
        )
        if project_file:
            self.log_activity(f"Saving project: {project_file}")
            # Implementation would go here

    def select_binary(self):
        """Select a binary file for analysis."""
        file_dialog = QFileDialog()
        binary_file, _ = file_dialog.getOpenFileName(
            self,
            "Select Binary",
            "",
            "All Files (*)",
        )
        if binary_file:
            self.load_binary(binary_file)

    def load_binary(self, file_path):
        """Load a binary file and update the UI."""
        self.current_binary_path = file_path
        self.add_to_recent_files(file_path)

        # Update binary information
        import os

        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        self.binary_info_label.setText(f"File: {file_name}\nPath: {file_path}")
        self.file_size_label.setText(f"File Size: {self.format_file_size(file_size)}")

        # Emit signal for other components
        self.binary_selected.emit(file_path)

        self.log_activity(f"Loaded binary: {file_name}")

    def close_binary(self):
        """Close the current binary."""
        if self.current_binary_path:
            file_name = os.path.basename(self.current_binary_path)
            self.current_binary_path = None

            # Reset UI
            self.binary_info_label.setText("No binary loaded")
            self.file_size_label.setText("File Size: -")
            self.architecture_label.setText("Architecture: -")
            self.entry_point_label.setText("Entry Point: -")

            self.log_activity(f"Closed binary: {file_name}")

    def add_to_recent_files(self, file_path):
        """Add file to recent files list."""
        if file_path in self.recent_files:
            self.recent_files.remove(file_path)
        self.recent_files.insert(0, file_path)
        self.recent_files = self.recent_files[:10]  # Keep only last 10
        self.update_recent_files_menu()

    def update_recent_files_menu(self):
        """Update the recent files menu."""
        self.recent_files_menu.clear()
        for file_path in self.recent_files:
            import os

            file_name = os.path.basename(file_path)
            action = self.recent_files_menu.addAction(file_name)
            action.triggered.connect(lambda checked, path=file_path: self.load_binary(path))

    def save_analysis_results(self):
        """Save analysis results."""
        if not self.current_binary_path:
            QMessageBox.information(self, "Save Results", "No binary loaded to save results for.")
            return

        file_dialog = QFileDialog()
        results_file, _ = file_dialog.getSaveFileName(
            self,
            "Save Analysis Results",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if results_file:
            self.log_activity(f"Saving analysis results: {results_file}")
            self.analysis_saved.emit(results_file)

    def export_results(self):
        """Export results in various formats."""
        self.log_activity("Exporting results...")
        # Implementation would go here

    def clear_analysis(self):
        """Clear current analysis results."""
        reply = QMessageBox.question(
            self,
            "Clear Analysis",
            "Are you sure you want to clear all analysis results?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.log_activity("Cleared analysis results")
            # Implementation would go here

    def clear_activity_log(self):
        """Clear the activity log."""
        self.activity_log.clear()

    def log_activity(self, message):
        """Log activity to the activity log."""
        from datetime import datetime

        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_log.append(f"[{timestamp}] {message}")

        # Also call parent log method
        super().log_activity(message)

    def format_file_size(self, size_bytes):
        """Format file size in human readable format."""
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB"]
        import math

        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
