"""First Run Setup Dialog.

Automatically configures Intellicrack on first run.

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

import logging
import subprocess
import sys

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    Qt,
    QTextEdit,
    QThread,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)


logger = logging.getLogger(__name__)


class SetupWorker(QThread):
    """Worker thread for setup tasks."""

    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool)

    def __init__(self, tasks: list[str]) -> None:
        """Initialize the SetupWorker.

        Args:
            tasks: List of task identifiers to execute during setup.

        Returns:
            None
        """
        super().__init__()
        self.tasks = tasks
        self.success = True

    def run(self) -> None:
        """Execute setup tasks in sequence.

        Iterates through all registered tasks, emits progress signals, and
        handles any errors that occur during installation.

        Returns:
            None
        """
        total_tasks = len(self.tasks)

        for i, task in enumerate(self.tasks):
            progress_percent = int((i / total_tasks) * 100)
            self.progress.emit(progress_percent)

            if task == "install_flask":
                self.status.emit("Installing Flask for GGUF server...")
                self._install_package("flask flask-cors")

            elif task == "install_llama":
                self.status.emit("Installing llama-cpp-python...")
                self._install_package("llama-cpp-python")

        self.progress.emit(100)
        self.status.emit("Setup complete!")
        self.finished.emit(self.success)

    def _install_package(self, package: str) -> None:
        """Install a Python package via pip.

        Executes pip install command for the specified package(s) and logs
        any errors that occur during installation.

        Args:
            package: Package name or space-separated list of package names
                to install.

        Returns:
            None

        Raises:
            Exception: Any exception during subprocess execution is caught
                and logged without propagation.
        """
        try:
            cmd = [sys.executable, "-m", "pip", "install", *package.split()]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            if result.returncode != 0:
                logger.error("Failed to install %s: %s", package, result.stderr)
                self.success = False
        except Exception as e:
            logger.exception("Error installing %s: %s", package, e)
            self.success = False


class FirstRunSetupDialog(QDialog):
    """Dialog for first-run setup."""

    def __init__(self, missing_components: dict[str, bool], parent: QWidget | None = None) -> None:
        """Initialize the FirstRunSetupDialog.

        Creates a dialog for configuring missing components on first run of
        Intellicrack, allowing users to install or skip component setup.

        Args:
            missing_components: Dictionary mapping component names to boolean
                flags indicating if they are missing.
            parent: Parent widget for the dialog.

        Returns:
            None
        """
        super().__init__(parent)
        self.missing_components = missing_components
        self.setup_complete = False
        self.init_ui()

    def init_ui(self) -> None:
        """Initialize the user interface.

        Constructs the dialog layout with title, description, component
        selection checkboxes, progress indicators, and action buttons.

        Returns:
            None
        """
        self.setWindowTitle("First Run Setup - Intellicrack")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)

        layout = QVBoxLayout()

        # Title
        title = QLabel("Welcome to Intellicrack!")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Description
        desc = QLabel("Some components need to be set up for optimal functionality.")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Missing components
        components_group = QGroupBox("Components to Install")
        components_layout = QVBoxLayout()

        self.component_checks = {}

        if not self.missing_components.get("Flask", True):
            check = QCheckBox("Flask - Local GGUF model server")
            check.setChecked(True)
            self.component_checks["install_flask"] = check
            components_layout.addWidget(check)

        if not self.missing_components.get("llama-cpp-python", True):
            check = QCheckBox("llama-cpp-python - LLM support")
            check.setChecked(True)
            self.component_checks["install_llama"] = check
            components_layout.addWidget(check)

        components_group.setLayout(components_layout)
        layout.addWidget(components_group)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setVisible(False)
        layout.addWidget(self.status_label)

        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        self.log_output.setVisible(False)
        layout.addWidget(self.log_output)

        # Buttons
        button_layout = QHBoxLayout()

        self.skip_button = QPushButton("Skip")
        self.skip_button.clicked.connect(self.reject)
        button_layout.addWidget(self.skip_button)

        button_layout.addStretch()

        self.setup_button = QPushButton("Install Components")
        self.setup_button.clicked.connect(self.start_setup)
        self.setup_button.setDefault(True)
        button_layout.addWidget(self.setup_button)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def start_setup(self) -> None:
        """Start the component installation process.

        Gathers selected components from checkboxes, shows progress UI
        elements, disables buttons, and launches the SetupWorker thread
        to execute installations.

        Returns:
            None
        """
        tasks = [task_id for task_id, checkbox in self.component_checks.items() if checkbox.isChecked()]
        if not tasks:
            self.accept()
            return

        # Show progress elements
        self.progress_bar.setVisible(True)
        self.status_label.setVisible(True)
        self.log_output.setVisible(True)

        # Disable buttons
        self.setup_button.setEnabled(False)
        self.skip_button.setEnabled(False)

        # Start worker
        self.worker = SetupWorker(tasks)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.status.connect(self.update_status)
        self.worker.finished.connect(self.setup_finished)
        self.worker.start()

    def update_status(self, status: str) -> None:
        """Update status label and log output.

        Displays the provided status message in the status label widget and
        appends it to the log output text area for user visibility.

        Args:
            status: Status message to display.

        Returns:
            None
        """
        self.status_label.setText(status)
        self.log_output.append(status)

    def setup_finished(self, success: bool) -> None:
        """Handle setup completion and update UI accordingly.

        Updates the dialog UI based on setup success or failure, enabling
        the setup button with appropriate text and enabling/disabling the
        skip button based on outcome.

        Args:
            success: Flag indicating whether setup completed successfully.

        Returns:
            None
        """
        self.setup_complete = True

        if success:
            self.status_label.setText("Setup completed successfully!")
            self.setup_button.setText("Continue")
            self.setup_button.setEnabled(True)
            self.setup_button.clicked.disconnect()
            self.setup_button.clicked.connect(self.accept)
        else:
            self.status_label.setText("Setup completed with some errors.")
            self.setup_button.setText("Continue Anyway")
            self.setup_button.setEnabled(True)
            self.skip_button.setEnabled(True)
