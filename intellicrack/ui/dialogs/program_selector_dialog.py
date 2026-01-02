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

import contextlib
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

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
    QWidget,
    QWizard,
    QWizardPage,
)


logger = logging.getLogger(__name__)


class FileSelectionPage(QWizardPage):
    """First wizard page for file selection."""

    def __init__(self, wizard: "ProgramSelectorDialog") -> None:
        """Initialize the file selection page.

        Args:
            wizard: The parent QWizard instance managing the dialog pages.

        """
        super().__init__()
        self._wizard_instance: ProgramSelectorDialog = wizard
        self.file_path_edit: QLineEdit
        self.browse_btn: QPushButton
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
            "The wizard will analyze the installation folder for licensing files.",
        )
        instructions.setWordWrap(True)
        file_layout.addWidget(instructions)

        # File path input
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("File Path:"))

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setToolTip("Select a file or enter path manually (e.g., C:\\Program Files\\App\\app.exe)")
        self.file_path_edit.textChanged.connect(self.validate_file_path)
        path_layout.addWidget(self.file_path_edit)

        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self.browse_for_file)
        if HAS_PYQT:
            try:
                style = self.style()
                if style is not None:
                    self.browse_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
            except AttributeError:
                with contextlib.suppress(AttributeError):
                    style = self.style()
                    if style is not None:
                        self.browse_btn.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon))
        path_layout.addWidget(self.browse_btn)

        file_layout.addLayout(path_layout)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        layout.addStretch()
        self.setLayout(layout)

    def browse_for_file(self) -> None:
        """Open file dialog to select a file.

        Displays a file selection dialog and updates the file path edit field
        with the user's selection if a valid file is chosen.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Program File",
            "",
            "All Executables (*.exe *.dll *.so *.dylib *.bin);;Windows (*.exe *.dll *.sys);;Linux (*.so *.bin);;macOS (*.dylib *.app);;All Files (*)",
        )

        if file_path:
            self.file_path_edit.setText(file_path)

    def validate_file_path(self) -> None:
        """Validate the selected file path.

        Checks if the file path exists and is a valid file, updating the commit
        page state accordingly to enable or disable wizard progression.
        """
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
        self._wizard_instance.selected_program = file_path
        self.setCommitPage(True)

    def get_selected_file(self) -> str:
        """Get the selected file path.

        Returns:
            The file path entered or selected by the user, stripped of whitespace.

        """
        return self.file_path_edit.text().strip()

    def isComplete(self) -> bool:
        """Check if the page is complete.

        Returns:
            True if a valid file path has been selected, False otherwise.

        """
        file_path = self.file_path_edit.text().strip()
        return bool(file_path and os.path.exists(file_path) and os.path.isfile(file_path))


class AnalysisPage(QWizardPage):
    """Second wizard page for displaying analysis results."""

    def __init__(self, wizard: "ProgramSelectorDialog") -> None:
        """Initialize the analysis page.

        Args:
            wizard: The parent QWizard instance managing the dialog pages.

        """
        super().__init__()
        self._wizard_instance: ProgramSelectorDialog = wizard
        self.licensing_files: list[dict[str, Any]] = []
        self.program_info: QLabel
        self.licensing_tree: QTreeWidget
        self.setTitle("Installation Analysis")
        self.setSubTitle("Analysis of the selected program's installation folder.")
        self.setFinalPage(True)

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

        licensing_info = QLabel("The following licensing-related files were found in the installation folder:")
        licensing_layout.addWidget(licensing_info)

        # Licensing files tree
        self.licensing_tree = QTreeWidget()
        self.licensing_tree.setHeaderLabels(["File", "Type", "Size", "Priority"])
        if HAS_PYQT:
            header = self.licensing_tree.header()
            if header is not None:
                header.setStretchLastSection(False)
                header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
                header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
                header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
                header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        self.licensing_tree.itemDoubleClicked.connect(self.open_licensing_file)
        licensing_layout.addWidget(self.licensing_tree)

        licensing_group.setLayout(licensing_layout)
        layout.addWidget(licensing_group)

        self.setLayout(layout)

    def initializePage(self) -> None:
        """Initialize the page when it becomes active.

        Updates the program information display and performs licensing file
        analysis on the selected program's installation folder.
        """
        if self._wizard_instance.selected_program:
            # Update program info
            file_path = Path(self._wizard_instance.selected_program)
            self.program_info.setText(f"""
<b>Program:</b> {file_path.name}<br>
<b>Path:</b> {file_path}<br>
<b>Size:</b> {self.format_file_size(file_path.stat().st_size)}<br>
<b>Directory:</b> {file_path.parent}
            """)

            # Analyze installation folder
            self.analyze_installation_folder(str(file_path.parent))

    def analyze_installation_folder(self, folder_path: str) -> None:
        """Analyze the installation folder for licensing files.

        Recursively searches the installation folder for files matching common
        licensing patterns (license, eula, copyright, etc.) and populates the
        licensing tree widget with discovered files.

        Args:
            folder_path: Path to the installation folder to analyze.

        """
        self.licensing_tree.clear()
        self.licensing_files = []

        try:
            folder = Path(folder_path)
            if not folder.exists() or not folder.is_dir():
                return

            # Define licensing file patterns and their priorities
            licensing_patterns: dict[str, dict[str, str | int]] = {
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
                                "size": file_path.stat().st_size,
                            }
                            self.licensing_files.append(file_info)

                            self.add_licensing_file_to_tree(file_path, str(info["type"]), int(info["priority"]))
                            break

        except Exception as e:
            logger.exception("Error analyzing installation folder: %s", e)

    def add_licensing_file_to_tree(self, file_path: str | Path, file_type: str, priority: int) -> None:
        """Add a licensing file to the tree widget.

        Creates a QTreeWidgetItem for the given licensing file and adds it to
        the licensing tree display with appropriate icon and metadata.

        Args:
            file_path: Path to the licensing file to add (str or Path object).
            file_type: Classification of the file type (e.g., "License", "EULA", "Copyright").
            priority: Priority level of the licensing file (lower values = higher priority).
        """
        try:
            file_path = Path(file_path)
            file_size = self.format_file_size(file_path.stat().st_size)

            item = QTreeWidgetItem([file_path.name, file_type, file_size, f"Priority {priority}"])

            # Store full path for opening
            item.setData(0, Qt.ItemDataRole.UserRole, str(file_path))

            if HAS_PYQT:
                style = self.style()
                if style is not None:
                    if file_type == "License":
                        try:
                            item.setIcon(
                                0,
                                style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView),
                            )
                        except AttributeError:
                            with contextlib.suppress(AttributeError):
                                item.setIcon(0, style.standardIcon(QStyle.StandardPixmap.SP_DirOpenIcon))
                    else:
                        with contextlib.suppress(AttributeError):
                            item.setIcon(0, style.standardIcon(QStyle.StandardPixmap.SP_FileIcon))

            self.licensing_tree.addTopLevelItem(item)

        except Exception as e:
            logger.exception("Error adding licensing file to tree: %s", e)

    def format_file_size(self, size: float) -> str:
        """Format file size in human-readable format.

        Converts a file size in bytes to a human-readable format with appropriate
        units (B, KB, MB, GB, TB).

        Args:
            size: The file size in bytes.

        Returns:
            A formatted string representation of the file size (e.g., "1.5 MB").

        """
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def get_licensing_files(self) -> list[dict[str, Any]]:
        """Get the list of discovered licensing files.

        Returns:
            A list of dictionaries, each containing licensing file metadata with keys:
            'path', 'name', 'type', 'priority', and 'size'.

        """
        return self.licensing_files

    def open_licensing_file(self, item: QTreeWidgetItem) -> None:
        """Open the selected licensing file.

        Attempts to open the selected licensing file using the system's default
        file viewer based on the platform (Windows, macOS, or Linux).

        Args:
            item: The QTreeWidgetItem representing the selected licensing file.
        """
        try:
            file_path = item.data(0, Qt.ItemDataRole.UserRole)
            if file_path and os.path.exists(file_path):
                if sys.platform.startswith("win"):
                    os.startfile(file_path)  # noqa: S606  # Legitimate program file opening for security research target selection
                elif sys.platform.startswith("darwin"):
                    if open_path := shutil.which("open"):
                        subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                            [open_path, file_path],
                            shell=False,
                        )
                elif xdg_open_path := shutil.which("xdg-open"):
                    subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                        [xdg_open_path, file_path],
                        shell=False,
                    )
        except Exception as e:
            logger.exception("Error opening licensing file: %s", e)
            QMessageBox.warning(self, "Error", f"Could not open file: {e}")


class ProgramSelectorDialog(QWizard):
    """Program Selector Dialog with intelligent shortcut resolution.

    and installation folder discovery.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize program selector wizard.

        Args:
            parent: The parent widget (typically None for standalone dialogs).

        """
        super().__init__(parent)
        self.selected_program: str | None = None
        self.analysis_results: dict[str, Any] = {}
        self.file_filters: dict[str, list[str]]
        self.file_selection_page: FileSelectionPage
        self.analysis_page: AnalysisPage
        self.setWindowTitle("Program Selection Wizard")
        self.setMinimumSize(800, 600)

        # State management

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
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setOption(QWizard.WizardOption.HaveHelpButton, False)

    def get_selected_program(self) -> str | None:
        """Get the selected program file path for compatibility with dashboard.

        Returns:
            The file path of the selected program, or None if no program is selected.

        """
        if self.file_selection_page:
            return self.file_selection_page.get_selected_file()
        return None

    def get_selected_program_data(self) -> dict[str, Any] | None:
        """Get data for the wizard results.

        Returns:
            A dictionary containing program information, installation folder path,
            discovered licensing files, and auto-analyze flag, or None if no program
            is selected. The dictionary structure includes:
            - program_info: Dict with 'name' and 'path' keys
            - installation_folder: Path to the installation directory
            - licensing_files: List of discovered licensing file metadata
            - auto_analyze: Boolean flag for automatic analysis

        """
        if file_path := self.file_selection_page.get_selected_file():
            return {
                "program_info": {"name": os.path.basename(file_path), "path": file_path},
                "installation_folder": os.path.dirname(file_path),
                "licensing_files": self.analysis_page.get_licensing_files(),
                "auto_analyze": True,
            }
        else:
            return None


# Convenience function for creating and showing the dialog
def show_program_selector(parent: QWidget | None = None) -> dict[str, Any] | None:
    """Show the program selector dialog and return selected data.

    Creates and displays a modal ProgramSelectorDialog wizard. If the user
    completes the wizard and accepts the selection, returns the selected
    program data; otherwise returns None.

    Args:
        parent: The parent widget for the dialog (typically None for standalone use).

    Returns:
        A dictionary with program information and licensing file metadata if the
        user accepts the dialog, or None if the user cancels or doesn't select
        a valid program.

    """
    dialog = ProgramSelectorDialog(parent)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        return dialog.get_selected_program_data()
    return None


# Backward compatibility alias
show_smart_program_selector = show_program_selector
