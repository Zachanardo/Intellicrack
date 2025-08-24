"""Smart Program Selector Dialog for Intellicrack.

Provides intelligent program discovery from desktop shortcuts, executables,
and installation folders with automatic licensing analysis integration.

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

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from intellicrack.handlers.pyqt6_handler import (
    HAS_PYQT,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStyle,
    Qt,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

logger = logging.getLogger(__name__)


class FileSelectionPage(QWizardPage):
    """First wizard page for file selection."""

    def __init__(self, wizard):
        """Initialize the file selection page."""
        super().__init__()
        self.wizard = wizard
        self.setTitle("Select Program File")
        self.setSubTitle("Choose the executable file or shortcut you want to analyze.")

        # Setup UI
        layout = QVBoxLayout()

        # File selection group
        file_group = QGroupBox("Program File Selection")
        file_layout = QVBoxLayout()

        # Instructions
        instructions = QLabel(
            "Select an executable file (.exe, .dll, .so, .dylib) or a shortcut to analyze.\n"
            "The wizard will analyze the installation folder for licensing files."
        )
        instructions.setWordWrap(True)
        file_layout.addWidget(instructions)

        # File path input
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("File Path:"))

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select a file or enter path manually...")
        self.file_path_edit.textChanged.connect(self.validate_file_path)
        path_layout.addWidget(self.file_path_edit)

        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self.browse_for_file)
        if HAS_PYQT:
            self.browse_btn.setIcon(
                self.style().standardIcon(QStyle.SP_FileDialogDetailedView)
            )
        path_layout.addWidget(self.browse_btn)

        file_layout.addLayout(path_layout)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        layout.addStretch()
        self.setLayout(layout)

    def browse_for_file(self):
        """Open file dialog to select a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Program File",
            "",
            "All Executables (*.exe *.dll *.so *.dylib *.bin);;Windows (*.exe *.dll *.sys);;Linux (*.so *.bin);;macOS (*.dylib *.app);;All Files (*)"
        )

        if file_path:
            self.file_path_edit.setText(file_path)

    def validate_file_path(self):
        """Validate the selected file path."""
        file_path = self.file_path_edit.text().strip()

        if not file_path:
            self.setCommitPage(False)
            return

        if not os.path.exists(file_path):
            self.setCommitPage(False)
            return

        if not os.path.isfile(file_path):
            self.setCommitPage(False)
            return

        # Valid file selected
        self.wizard.selected_program = file_path
        self.setCommitPage(True)

    def get_selected_file(self):
        """Get the selected file path."""
        return self.file_path_edit.text().strip()

    def isComplete(self):
        """Check if the page is complete."""
        file_path = self.file_path_edit.text().strip()
        return bool(file_path and os.path.exists(file_path) and os.path.isfile(file_path))


class AnalysisPage(QWizardPage):
    """Second wizard page for displaying analysis results."""

    def __init__(self, wizard):
        """Initialize the analysis page."""
        super().__init__()
        self.wizard = wizard
        self.setTitle("Installation Analysis")
        self.setSubTitle("Analysis of the selected program's installation folder.")
        self.setFinalPage(True)

        self.licensing_files = []

        # Setup UI
        layout = QVBoxLayout()

        # Program info section
        info_group = QGroupBox("Program Information")
        info_layout = QVBoxLayout()

        self.program_info = QLabel("No program selected")
        self.program_info.setWordWrap(True)
        info_layout.addWidget(self.program_info)

        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # Licensing analysis section
        licensing_group = QGroupBox("Licensing Files Analysis")
        licensing_layout = QVBoxLayout()

        licensing_info = QLabel(
            "The following licensing-related files were found in the installation folder:"
        )
        licensing_layout.addWidget(licensing_info)

        # Licensing files tree
        self.licensing_tree = QTreeWidget()
        self.licensing_tree.setHeaderLabels(["File", "Type", "Size", "Priority"])
        if HAS_PYQT:
            self.licensing_tree.header().setStretchLastSection(False)
            self.licensing_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
            self.licensing_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self.licensing_tree.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            self.licensing_tree.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.licensing_tree.itemDoubleClicked.connect(self.open_licensing_file)
        licensing_layout.addWidget(self.licensing_tree)

        licensing_group.setLayout(licensing_layout)
        layout.addWidget(licensing_group)

        self.setLayout(layout)

    def initializePage(self):
        """Initialize the page when it becomes active."""
        if self.wizard.selected_program:
            # Update program info
            file_path = Path(self.wizard.selected_program)
            self.program_info.setText(f"""
<b>Program:</b> {file_path.name}<br>
<b>Path:</b> {file_path}<br>
<b>Size:</b> {self.format_file_size(file_path.stat().st_size)}<br>
<b>Directory:</b> {file_path.parent}
            """)

            # Analyze installation folder
            self.analyze_installation_folder(str(file_path.parent))

    def analyze_installation_folder(self, folder_path):
        """Analyze the installation folder for licensing files."""
        self.licensing_tree.clear()
        self.licensing_files = []

        try:
            folder = Path(folder_path)
            if not folder.exists() or not folder.is_dir():
                return

            # Define licensing file patterns and their priorities
            licensing_patterns = {
                "license": {"priority": 1, "type": "License"},
                "licence": {"priority": 1, "type": "License"},
                "copying": {"priority": 2, "type": "Copyright"},
                "copyright": {"priority": 2, "type": "Copyright"},
                "readme": {"priority": 3, "type": "Documentation"},
                "eula": {"priority": 1, "type": "EULA"},
                "terms": {"priority": 2, "type": "Terms"},
                "legal": {"priority": 2, "type": "Legal"},
                "patent": {"priority": 3, "type": "Patent"},
                "trademark": {"priority": 3, "type": "Trademark"},
                "notice": {"priority": 3, "type": "Notice"},
            }

            # Search for licensing files
            for file_path in folder.rglob("*"):
                if file_path.is_file():
                    filename_lower = file_path.name.lower()
                    for pattern, info in licensing_patterns.items():
                        if pattern in filename_lower:
                            file_info = {
                                "path": str(file_path),
                                "name": file_path.name,
                                "type": info["type"],
                                "priority": info["priority"],
                                "size": file_path.stat().st_size
                            }
                            self.licensing_files.append(file_info)

                            self.add_licensing_file_to_tree(
                                file_path,
                                info["type"],
                                info["priority"]
                            )
                            break

        except Exception as e:
            logger.error(f"Error analyzing installation folder: {e}")

    def add_licensing_file_to_tree(self, file_path, file_type, priority):
        """Add a licensing file to the tree widget."""
        try:
            file_path = Path(file_path)
            file_size = self.format_file_size(file_path.stat().st_size)

            item = QTreeWidgetItem([
                str(file_path.name),
                file_type,
                file_size,
                f"Priority {priority}"
            ])

            # Store full path for opening
            item.setData(0, Qt.UserRole, str(file_path))

            # Set icon based on file type
            if HAS_PYQT:
                if file_type == "License":
                    item.setIcon(0, self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
                else:
                    item.setIcon(0, self.style().standardIcon(QStyle.SP_FileIcon))

            self.licensing_tree.addTopLevelItem(item)

        except Exception as e:
            logger.error(f"Error adding licensing file to tree: {e}")

    def format_file_size(self, size):
        """Format file size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def get_licensing_files(self):
        """Get the list of discovered licensing files."""
        return self.licensing_files

    def open_licensing_file(self, item):
        """Open the selected licensing file."""
        try:
            file_path = item.data(0, Qt.UserRole)
            if file_path and os.path.exists(file_path):
                if sys.platform.startswith('win'):
                    os.startfile(file_path)  # noqa: S606  # Legitimate program file opening for security research target selection
                elif sys.platform.startswith('darwin'):
                    open_path = shutil.which('open')
                    if open_path:
                        subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                            [open_path, file_path], shell=False
                        )
                else:
                    xdg_open_path = shutil.which('xdg-open')
                    if xdg_open_path:
                        subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                            [xdg_open_path, file_path], shell=False
                        )
        except Exception as e:
            logger.error(f"Error opening licensing file: {e}")
            QMessageBox.warning(self, "Error", f"Could not open file: {e}")


class ProgramSelectorDialog(QWizard):
    """Program Selector Dialog with intelligent shortcut resolution
    and installation folder discovery.
    """

    def __init__(self, parent=None):
        """Initialize program selector wizard."""
        super().__init__(parent)
        self.setWindowTitle("Program Selection Wizard")
        self.setMinimumSize(800, 600)

        # State management
        self.selected_program = None
        self.analysis_results = {}

        # File filters
        self.file_filters = {
            "All Executables": ["*.exe", "*.dll", "*.so", "*.dylib", "*.bin"],
            "Windows": ["*.exe", "*.dll", "*.sys"],
            "Linux": ["*.so", "*.bin"],
            "macOS": ["*.dylib", "*.app"],
        }

        # Create wizard pages
        self.file_selection_page = FileSelectionPage(self)
        self.analysis_page = AnalysisPage(self)

        # Add pages to wizard
        self.addPage(self.file_selection_page)
        self.addPage(self.analysis_page)

        # Configure wizard
        self.setWizardStyle(QWizard.ModernStyle)
        self.setOption(QWizard.HaveHelpButton, False)

    def get_selected_program_data(self):
        """Get data for the wizard results."""
        file_path = self.file_selection_page.get_selected_file()
        if not file_path:
            return None

        return {
            "program_info": {"name": os.path.basename(file_path), "path": file_path},
            "installation_folder": os.path.dirname(file_path),
            "licensing_files": self.analysis_page.get_licensing_files(),
            "auto_analyze": True,
        }


# Convenience function for creating and showing the dialog
def show_program_selector(parent=None):
    """Show the program selector dialog and return selected data."""
    dialog = ProgramSelectorDialog(parent)
    if dialog.exec() == QDialog.Accepted:
        return dialog.get_selected_program_data()
    return None


# Backward compatibility alias
show_smart_program_selector = show_program_selector
