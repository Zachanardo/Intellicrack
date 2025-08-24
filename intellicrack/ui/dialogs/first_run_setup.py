"""First Run Setup Dialog.

Automatically configures Intellicrack on first run.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
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
    pyqtSignal,
)

logger = logging.getLogger(__name__)


class SetupWorker(QThread):
    """Worker thread for setup tasks."""

    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool)

    def __init__(self, tasks: list[str]):
        """Initialize the SetupWorker with default values."""
        super().__init__()
        self.tasks = tasks
        self.success = True

    def run(self):
        """Run setup tasks."""
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

    def _install_package(self, package: str):
        """Install a Python package."""
        try:
            cmd = [sys.executable, "-m", "pip", "install"] + package.split()
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
            if result.returncode != 0:
                logger.error(f"Failed to install {package}: {result.stderr}")
                self.success = False
        except Exception as e:
            logger.error(f"Error installing {package}: {e}")
            self.success = False


class FirstRunSetupDialog(QDialog):
    """Dialog for first-run setup."""

    def __init__(self, missing_components: dict[str, bool], parent=None):
        """Initialize the FirstRunSetupDialog with default values."""
        super().__init__(parent)
        self.missing_components = missing_components
        self.setup_complete = False
        self.init_ui()

    def init_ui(self):
        """Initialize the UI."""
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

    def start_setup(self):
        """Start the setup process."""
        # Get selected tasks
        tasks = []
        for task_id, checkbox in self.component_checks.items():
            if checkbox.isChecked():
                tasks.append(task_id)

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

    def update_status(self, status: str):
        """Update status label."""
        self.status_label.setText(status)
        self.log_output.append(status)

    def setup_finished(self, success: bool):
        """Handle setup completion."""
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
