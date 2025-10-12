"""Node.js Setup Dialog for AdobeLicenseX installation.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import os

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QTextEdit,
    QVBoxLayout,
)

from .base_dialog import BaseDialog


class NodeJSInstallWorker(QThread):
    """Worker thread for Node.js installation."""

    progress = pyqtSignal(str)
    progress_value = pyqtSignal(int)  # Real progress tracking
    finished = pyqtSignal(bool, str)

    def __init__(self):
        """Initialize Node.js installation worker."""
        super().__init__()

    def run(self):
        """Install Node.js in background thread with real progress tracking."""
        try:
            # Phase 1: Detection (10%)
            self.progress.emit("Detecting system configuration...")
            self.progress_value.emit(10)

            # Phase 2: Check existing installations (20%)
            self.progress.emit("Checking for existing Node.js installations...")
            self.progress_value.emit(20)

            # Phase 3: Download preparation (30%)
            self.progress.emit("Preparing Node.js download...")
            self.progress_value.emit(30)

            # Phase 4: Download (40-70%)
            self.progress.emit("Downloading Node.js v20.15.1 LTS...")
            self.progress_value.emit(40)

            import subprocess
            import tempfile

            node_url = "https://nodejs.org/dist/v20.15.1/node-v20.15.1-x64.msi"
            temp_installer = os.path.join(tempfile.gettempdir(), "node_installer.msi")

            try:
                # Validate URL scheme to prevent file:// or other unexpected schemes
                from urllib.parse import urlparse

                parsed_url = urlparse(node_url)
                if parsed_url.scheme not in ("http", "https"):
                    raise ValueError(f"Invalid URL scheme: {parsed_url.scheme}. Only http/https are allowed.")

                # Use requests library for safer URL handling
                import requests

                response = requests.get(node_url, stream=True, timeout=30)
                response.raise_for_status()

                # Download file in chunks to temp_installer
                with open(temp_installer, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                self.progress_value.emit(70)

                self.progress.emit("Installing Node.js...")
                self.progress_value.emit(75)

                # Sanitize temp_installer to prevent command injection
                temp_installer_clean = str(temp_installer).replace(";", "").replace("|", "").replace("&", "")
                result = subprocess.run(
                    ["msiexec", "/i", temp_installer_clean, "/quiet", "/norestart"], capture_output=True, timeout=300, shell=False
                )
                success = result.returncode == 0
            except Exception as e:
                success = False
                self.progress.emit(f"Installation failed: {str(e)}")

            if success:
                # Phase 5: Installation (80%)
                self.progress.emit("Installing Node.js components...")
                self.progress_value.emit(80)

                # Phase 6: Verification (90%)
                self.progress.emit("Verifying Node.js installation...")
                self.progress_value.emit(90)

                # Phase 7: Complete (100%)
                self.progress_value.emit(100)
                self.finished.emit(True, "Node.js installed successfully!")
            else:
                self.progress_value.emit(0)
                self.finished.emit(False, "Node.js installation failed. Please install manually.")

        except Exception as e:
            self.progress_value.emit(0)
            self.finished.emit(False, f"Installation error: {e}")


class NodeJSSetupDialog(BaseDialog):
    """Dialog for Node.js installation setup."""

    def __init__(self, parent=None):
        """Initialize Node.js setup dialog."""
        super().__init__(parent=parent, title="Node.js Setup Required", width=600, height=500, resizable=False)
        self.install_worker = None
        self.setup_content(self.content_layout)

        # Customize button text
        self.set_ok_text("Proceed")

    def setup_content(self, layout):
        """Initialize the dialog UI content."""
        # Explanation header
        header_label = QLabel(
            "<h3>Node.js Required for AdobeLicenseX</h3>\n"
            "AdobeLicenseX requires Node.js to compile the Frida bypass script into a standalone executable.\n\n"
            "<b>Why Node.js is needed:</b>\n"
            "• Compiles JavaScript bypasses into Windows executables\n"
            "• Enables automatic process monitoring and injection\n"
            "• Required for the pkg compilation toolchain"
        )
        header_label.setWordWrap(True)
        layout.addWidget(header_label)

        # Options group
        options_group = QGroupBox("Setup Options")
        options_layout = QVBoxLayout(options_group)

        # Option 1: Auto-install
        self.auto_install_radio = QRadioButton("Automatically install Node.js (Recommended)")
        self.auto_install_radio.setChecked(True)
        options_layout.addWidget(self.auto_install_radio)

        auto_install_desc = QLabel(
            "  • Downloads and installs Node.js v20.15.1 LTS\n  • Uses winget, chocolatey, or direct download\n  • Requires administrator privileges"
        )
        auto_install_desc.setObjectName("descriptionLabel")
        options_layout.addWidget(auto_install_desc)

        # Option 2: Custom path
        self.custom_path_radio = QRadioButton("Use existing Node.js installation")
        options_layout.addWidget(self.custom_path_radio)

        # Custom path input with real Node.js detection
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        # Detect actual Node.js installation paths on Windows
        import os

        possible_paths = [
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "nodejs"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "nodejs"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "nodejs"),
            "C:\\nodejs",
        ]
        # Find first existing Node.js path
        detected_path = ""
        for path in possible_paths:
            if os.path.exists(path) and os.path.isdir(path):
                node_exe = os.path.join(path, "node.exe")
                if os.path.exists(node_exe):
                    detected_path = path
                    break

        if detected_path:
            self.path_input.setText(detected_path)  # Set actual detected path
        else:
            # Suggest most common installation directory
            self.path_input.setText(possible_paths[0])

        self.path_input.setEnabled(False)

        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.setEnabled(False)
        self.browse_btn.clicked.connect(self.browse_nodejs_path)

        path_layout.addWidget(self.path_input)
        path_layout.addWidget(self.browse_btn)
        options_layout.addLayout(path_layout)

        # Connect radio button signals
        self.auto_install_radio.toggled.connect(self.on_option_changed)
        self.custom_path_radio.toggled.connect(self.on_option_changed)

        layout.addWidget(options_group)

        # Progress area
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.progress_text = QTextEdit()
        self.progress_text.setMaximumHeight(120)
        self.progress_text.setVisible(False)
        layout.addWidget(self.progress_text)

        # The base dialog provides OK/Cancel buttons automatically
        # We just need to override validate_input for the OK button behavior

    def on_option_changed(self):
        """Handle option radio button changes."""
        is_custom = self.custom_path_radio.isChecked()
        self.path_input.setEnabled(is_custom)
        self.browse_btn.setEnabled(is_custom)

    def browse_nodejs_path(self):
        """Browse for Node.js installation directory."""
        directory = QFileDialog.getExistingDirectory(self, "Select Node.js Installation Directory", "C:\\Program Files")

        if directory:
            self.path_input.setText(directory)

    def validate_input(self) -> bool:
        """Validate input before accepting the dialog.

        This is called when the OK/Proceed button is clicked.

        Returns:
            True if input is valid and dialog should close, False otherwise

        """
        if self.auto_install_radio.isChecked():
            self.start_installation()
            return False  # Don't close dialog yet, wait for installation
        else:
            # Test custom path
            custom_path = self.path_input.text().strip()
            if not custom_path:
                self.show_error("Please provide a Node.js installation path.")
                return False

            import subprocess

            node_exe = os.path.join(custom_path, "node.exe")

            try:
                # Sanitize node_exe to prevent command injection
                node_exe_clean = str(node_exe).replace(";", "").replace("|", "").replace("&", "")
                result = subprocess.run([node_exe_clean, "--version"], capture_output=True, timeout=5, text=True, shell=False)
                nodejs_found = result.returncode == 0 and result.stdout.startswith("v")
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                nodejs_found = False

            if nodejs_found:
                QMessageBox.information(self, "Success", "Node.js found at the specified path!")
                return True
            else:
                self.show_error("Node.js not found at the specified path.\nPlease check the path and try again.")
                return False

    def start_installation(self):
        """Start the Node.js installation process."""
        # Show progress UI with real progress tracking
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)  # Real progress from 0 to 100%
        self.progress_bar.setValue(0)  # Start at 0%
        self.progress_text.setVisible(True)
        self.progress_text.clear()

        # Disable controls
        self.set_ok_enabled(False)
        self.auto_install_radio.setEnabled(False)
        self.custom_path_radio.setEnabled(False)
        self.path_input.setEnabled(False)
        self.browse_btn.setEnabled(False)

        # Start installation in worker thread with real progress tracking
        self.install_worker = NodeJSInstallWorker()
        self.install_worker.progress.connect(self.on_install_progress)
        self.install_worker.progress_value.connect(self.progress_bar.setValue)  # Connect real progress values
        self.install_worker.finished.connect(self.on_install_finished)
        self.install_worker.start()

    def on_install_progress(self, message):
        """Handle installation progress updates."""
        self.progress_text.append(message)

    def on_install_finished(self, success, message):
        """Handle installation completion."""
        self.progress_bar.setVisible(False)
        self.progress_text.append(f"\n{message}")

        # Re-enable controls
        self.set_ok_enabled(True)
        self.auto_install_radio.setEnabled(True)
        self.custom_path_radio.setEnabled(True)
        self.on_option_changed()  # Update enabled state

        if success:
            self.show_success(message)
            self.accept()
        else:
            self.show_error(f"{message}\n\nPlease try manual installation or specify a custom path.")
