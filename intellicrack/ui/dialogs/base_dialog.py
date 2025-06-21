"""
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

import os
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog, QLabel, QLineEdit, QMessageBox
from PyQt5.QtCore import Qt


class BinarySelectionDialog(QDialog):
    """Dialog for selecting binary files for analysis."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_binary = None
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Select Binary File")
        self.setModal(True)
        self.resize(500, 200)
        
        layout = QVBoxLayout()
        
        # Instructions
        instructions = QLabel("Select a binary file for analysis:")
        layout.addWidget(instructions)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Path to binary file...")
        
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        
        ok_button.clicked.connect(self.accept_selection)
        cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def browse_file(self):
        """Open file browser to select binary."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)"
        )
        
        if file_path:
            self.file_path_edit.setText(file_path)
            
    def accept_selection(self):
        """Accept the selected file."""
        file_path = self.file_path_edit.text().strip()
        
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a binary file.")
            return
            
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "Warning", "Selected file does not exist.")
            return
            
        self.selected_binary = file_path
        self.accept()
        
    def get_selected_binary(self):
        """Get the selected binary path."""
        return self.selected_binary


class BaseTemplateDialog(QDialog):
    """Base dialog class for template-based dialogs."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setModal(True)
        self.setMinimumWidth(800)
        self.setMinimumHeight(600)


__all__ = ['BinarySelectionDialog', 'BaseTemplateDialog']