"""Node.js Setup Dialog for AdobeLicenseX installation."""

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

from intellicrack.core.patching.adobe_compiler import AdobeLicenseCompiler

from .base_dialog import BaseDialog


class NodeJSInstallWorker(QThread):
    """Worker thread for Node.js installation."""

    progress = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, compiler):
        """Initialize Node.js installation worker with compiler instance."""
        super().__init__()
        self.compiler = compiler

    def run(self):
        """Install Node.js in background thread."""
        try:
            self.progress.emit("Starting Node.js installation...")
            success = self.compiler.install_nodejs()

            if success:
                self.finished.emit(True, "Node.js installed successfully!")
            else:
                self.finished.emit(False, "Node.js installation failed. Please install manually.")

        except Exception as e:
            self.finished.emit(False, f"Installation error: {e}")


class NodeJSSetupDialog(BaseDialog):
    """Dialog for Node.js installation setup."""

    def __init__(self, parent=None):
        """Initialize Node.js setup dialog."""
        super().__init__(parent=parent, title="Node.js Setup Required", width=600, height=500, resizable=False)
        self.compiler = AdobeLicenseCompiler()
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

        # Custom path input
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("C:\\Program Files\\nodejs")
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

            if self.compiler.check_nodejs(custom_path):
                QMessageBox.information(self, "Success", "Node.js found at the specified path!")
                return True
            else:
                self.show_error("Node.js not found at the specified path.\nPlease check the path and try again.")
                return False

    def start_installation(self):
        """Start the Node.js installation process."""
        # Show progress UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.progress_text.setVisible(True)
        self.progress_text.clear()

        # Disable controls
        self.set_ok_enabled(False)
        self.auto_install_radio.setEnabled(False)
        self.custom_path_radio.setEnabled(False)
        self.path_input.setEnabled(False)
        self.browse_btn.setEnabled(False)

        # Start installation in worker thread
        self.install_worker = NodeJSInstallWorker(self.compiler)
        self.install_worker.progress.connect(self.on_install_progress)
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
