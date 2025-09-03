"""Keygen dialog for generating license keys and serial numbers."""

import json
import os
import platform
import subprocess
import time

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QColor,
    QComboBox,
    QFileDialog,
    QFont,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QThread,
    QTimer,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.logger import logger

from ..icon_manager import set_button_icon
from .base_dialog import BinarySelectionDialog

"""
Professional Keygen Dialog for Intellicrack.

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


class KeygenWorker(QThread):
    """Background worker for keygen operations."""

    key_generated = pyqtSignal(dict)
    batch_progress = pyqtSignal(int, int)
    batch_completed = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, binary_path: str, operation: str, **kwargs):
        """Initialize the KeygenWorker with default values."""
        super().__init__()
        self.binary_path = binary_path
        self.operation = operation
        self.kwargs = kwargs
        self.should_stop = False

    def run(self):
        """Execute the keygen operation."""
        try:
            if self.operation == "single":
                self._generate_single_key()
            elif self.operation == "batch":
                self._generate_batch_keys()
            elif self.operation == "analyze":
                self._analyze_binary()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in keygen_dialog: %s", e)
            self.error_occurred.emit(str(e))

    def _generate_single_key(self):
        """Generate a single license key."""
        from ...utils.exploitation import generate_license_key

        result = generate_license_key(
            self.binary_path,
            algorithm=self.kwargs.get("algorithm", "auto"),
            format_type=self.kwargs.get("format_type", "auto"),
            custom_length=self.kwargs.get("custom_length"),
            validation_check=self.kwargs.get("validation_check", False),
        )
        self.key_generated.emit(result)

    def _generate_batch_keys(self):
        """Generate multiple license keys."""
        count = self.kwargs.get("count", 10)
        keys = []

        for _i in range(count):
            if self.should_stop:
                break

            try:
                from ...utils.exploitation import generate_license_key

                result = generate_license_key(
                    self.binary_path,
                    algorithm=self.kwargs.get("algorithm", "auto"),
                    format_type=self.kwargs.get("format_type", "auto"),
                    custom_length=self.kwargs.get("custom_length"),
                    validation_check=False,  # Skip validation for batch to speed up
                )
                result["batch_id"] = _i + 1
                keys.append(result)
                self.batch_progress.emit(_i + 1, count)
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in keygen_dialog: %s", e)
                keys.append(
                    {
                        "batch_id": _i + 1,
                        "key": "",
                        "error": str(e),
                        "algorithm": self.kwargs.get("algorithm", "auto"),
                        "format": self.kwargs.get("format_type", "auto"),
                    }
                )

        self.batch_completed.emit(keys)

    def _analyze_binary(self):
        """Analyze binary for algorithm detection."""
        from ...utils.exploitation import _detect_key_format, _detect_license_algorithm

        algorithm, analysis = _detect_license_algorithm(self.binary_path)
        format_type = _detect_key_format(self.binary_path)

        result = {
            "algorithm": algorithm,
            "format": format_type,
            "analysis": analysis,
        }
        self.key_generated.emit(result)

    def stop(self):
        """Stop the worker thread."""
        self.should_stop = True


class KeygenDialog(BinarySelectionDialog):
    """Professional Keygen Dialog with advanced features."""

    def __init__(self, parent=None, binary_path: str = ""):
        """Initialize the KeygenDialog with default values."""
        # Initialize UI attributes
        self.analysis_display = None
        self.analyze_keys_btn = None
        self.batch_algorithm_combo = None
        self.batch_clear_btn = None
        self.batch_count_spin = None
        self.batch_export_btn = None
        self.batch_format_combo = None
        self.batch_generate_btn = None
        self.batch_progress = None
        self.batch_stop_btn = None
        self.batch_table = None
        self.copy_btn = None
        self.existing_keys_input = None
        self.generate_btn = None
        self.key_analysis_display = None
        self.key_display = None
        self.results_display = None
        self.save_single_btn = None
        super().__init__(parent)
        self.binary_path = binary_path
        self.worker = None
        self.generated_keys = []
        self.current_analysis = {}
        self.last_generated_key = ""
        self.last_generated_result = {}

        self.setWindowTitle("Professional License Key Generator")
        self.setMinimumSize(900, 700)
        self.setModal(True)

        self.setup_ui()
        self.connect_signals()

        # Auto-analyze if binary path provided
        if self.binary_path and os.path.exists(self.binary_path):
            self.auto_analyze_binary()

    def setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)

        # Title and binary selection
        self.setup_header(layout)

        # Main tabs
        self.setup_tabs(layout)

        # Status and controls
        self.setup_footer(layout)

    def setup_header(self, layout):
        """Setup header with binary selection."""
        # Use the base class method with analyze button
        super().setup_header(layout, show_label=True, extra_buttons=[("Analyze Binary", self.analyze_binary)])

    def setup_tabs(self, layout):
        """Setup main tab widget."""
        self.tabs = QTabWidget()

        # Single Key Generation Tab
        self.setup_single_tab()

        # Batch Generation Tab
        self.setup_batch_tab()

        # Analysis Tab
        self.setup_analysis_tab()

        # Key Management Tab
        self.setup_management_tab()

        layout.addWidget(self.tabs)

    def setup_single_tab(self):
        """Setup single key generation tab."""
        single_widget = QWidget()
        layout = QVBoxLayout(single_widget)

        # Configuration section
        config_group = QGroupBox("Key Generation Configuration")
        config_layout = QGridLayout(config_group)

        # Algorithm selection
        config_layout.addWidget(QLabel("Algorithm:"), 0, 0)
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(
            [
                "Auto-Detect",
                "Simple",
                "Formatted",
                "RSA",
                "AES",
                "Checksum",
                "Hardware-Locked",
            ]
        )
        config_layout.addWidget(self.algorithm_combo, 0, 1)

        # Format selection
        config_layout.addWidget(QLabel("Format:"), 1, 0)
        self.format_combo = QComboBox()
        self.format_combo.addItems(
            [
                "Auto-Detect",
                "Alphanumeric",
                "Formatted",
                "Hex",
                "Base64",
            ]
        )
        config_layout.addWidget(self.format_combo, 1, 1)

        # Custom length
        config_layout.addWidget(QLabel("Custom Length:"), 2, 0)
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 256)
        self.length_spin.setValue(25)
        self.length_spin.setSpecialValueText("Auto")
        config_layout.addWidget(self.length_spin, 2, 1)

        # Validation checkbox
        self.validation_check = QCheckBox("Test Key Validation (Experimental)")
        config_layout.addWidget(self.validation_check, 3, 0, 1, 2)

        layout.addWidget(config_group)

        # Generation section
        gen_group = QGroupBox("Key Generation")
        gen_layout = QVBoxLayout(gen_group)

        # Generate button
        self.generate_btn = QPushButton("Generate License Key")
        self.generate_btn.clicked.connect(self.generate_single_key)
        self.generate_btn.setObjectName("generateButton")
        set_button_icon(self.generate_btn, "action_generate")
        gen_layout.addWidget(self.generate_btn)

        # Generated key display
        self.key_display = QTextEdit()
        self.key_display.setMaximumHeight(100)
        self.key_display.setFont(QFont("Consolas", 12))
        gen_layout.addWidget(QLabel("Generated Key:"))
        gen_layout.addWidget(self.key_display)

        # Action buttons layout
        actions_layout = QHBoxLayout()

        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self.copy_key)

        self.save_single_btn = QPushButton("Save Key")
        self.save_single_btn.clicked.connect(self.save_single_key)
        self.save_single_btn.setEnabled(False)  # Enable after key generation

        actions_layout.addWidget(self.copy_btn)
        actions_layout.addWidget(self.save_single_btn)

        gen_layout.addLayout(actions_layout)

        layout.addWidget(gen_group)

        # Results section
        results_group = QGroupBox("Generation Results")
        results_layout = QVBoxLayout(results_group)

        self.results_display = QTextEdit()
        self.results_display.setMaximumHeight(150)
        self.results_display.setFont(QFont("Consolas", 10))
        results_layout.addWidget(self.results_display)

        layout.addWidget(results_group)

        self.tabs.addTab(single_widget, "Single Key")

    def setup_batch_tab(self):
        """Setup batch generation tab."""
        batch_widget = QWidget()
        layout = QVBoxLayout(batch_widget)

        # Batch configuration
        config_group = QGroupBox("Batch Configuration")
        config_layout = QGridLayout(config_group)

        config_layout.addWidget(QLabel("Number of Keys:"), 0, 0)
        self.batch_count_spin = QSpinBox()
        self.batch_count_spin.setRange(1, 1000)
        self.batch_count_spin.setValue(10)
        config_layout.addWidget(self.batch_count_spin, 0, 1)

        config_layout.addWidget(QLabel("Algorithm:"), 1, 0)
        self.batch_algorithm_combo = QComboBox()
        self.batch_algorithm_combo.addItems(
            [
                "Auto-Detect",
                "Simple",
                "Formatted",
                "RSA",
                "AES",
                "Checksum",
                "Hardware-Locked",
            ]
        )
        config_layout.addWidget(self.batch_algorithm_combo, 1, 1)

        config_layout.addWidget(QLabel("Format:"), 2, 0)
        self.batch_format_combo = QComboBox()
        self.batch_format_combo.addItems(
            [
                "Auto-Detect",
                "Alphanumeric",
                "Formatted",
                "Hex",
                "Base64",
            ]
        )
        config_layout.addWidget(self.batch_format_combo, 2, 1)

        layout.addWidget(config_group)

        # Generation controls
        controls_layout = QHBoxLayout()

        self.batch_generate_btn = QPushButton("Generate Batch")
        self.batch_generate_btn.clicked.connect(self.generate_batch_keys)
        self.batch_generate_btn.setObjectName("batchGenerateButton")
        set_button_icon(self.batch_generate_btn, "action_generate")

        self.batch_stop_btn = QPushButton("Stop")
        self.batch_stop_btn.clicked.connect(self.stop_batch_generation)
        self.batch_stop_btn.setEnabled(False)
        set_button_icon(self.batch_stop_btn, "action_stop")

        self.batch_clear_btn = QPushButton("Clear Results")
        self.batch_clear_btn.clicked.connect(self.clear_batch_results)
        set_button_icon(self.batch_clear_btn, "edit_delete")

        self.batch_export_btn = QPushButton("Export Keys")
        self.batch_export_btn.clicked.connect(self.export_batch_keys)
        set_button_icon(self.batch_export_btn, "file_export")

        controls_layout.addWidget(self.batch_generate_btn)
        controls_layout.addWidget(self.batch_stop_btn)
        controls_layout.addWidget(self.batch_clear_btn)
        controls_layout.addWidget(self.batch_export_btn)
        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        # Progress bar
        self.batch_progress = QProgressBar()
        layout.addWidget(self.batch_progress)

        # Results table
        self.batch_table = QTableWidget()
        self.batch_table.setColumnCount(5)
        self.batch_table.setHorizontalHeaderLabels(
            [
                "ID",
                "Generated Key",
                "Algorithm",
                "Format",
                "Status",
            ]
        )

        # Set column widths
        header = self.batch_table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # Key column stretches

        layout.addWidget(self.batch_table)

        self.tabs.addTab(batch_widget, "Batch Generation")

    def setup_analysis_tab(self):
        """Setup binary analysis tab."""
        analysis_widget = QWidget()
        layout = QVBoxLayout(analysis_widget)

        # Analysis results
        self.analysis_display = QTextEdit()
        self.analysis_display.setFont(QFont("Consolas", 10))

        layout.addWidget(QLabel("Binary Analysis Results:"))
        layout.addWidget(self.analysis_display)

        self.tabs.addTab(analysis_widget, "Binary Analysis")

    def setup_management_tab(self):
        """Setup key management tab."""
        management_widget = QWidget()
        layout = QVBoxLayout(management_widget)

        # Key input section
        input_group = QGroupBox("Analyze Existing Keys")
        input_layout = QVBoxLayout(input_group)

        self.existing_keys_input = QTextEdit()
        self.existing_keys_input.setMaximumHeight(100)
        self.existing_keys_input.setPlaceholderText("Paste existing license keys (one per line) to analyze patterns...")
        input_layout.addWidget(self.existing_keys_input)

        self.analyze_keys_btn = QPushButton("Analyze Key Patterns")
        self.analyze_keys_btn.clicked.connect(self.analyze_existing_keys)
        input_layout.addWidget(self.analyze_keys_btn)

        layout.addWidget(input_group)

        # Analysis results
        self.key_analysis_display = QTextEdit()
        self.key_analysis_display.setFont(QFont("Consolas", 10))

        layout.addWidget(QLabel("Key Pattern Analysis:"))
        layout.addWidget(self.key_analysis_display)

        self.tabs.addTab(management_widget, "Key Management")

    def setup_footer(self, layout):
        """Setup footer with status and close button."""
        from ..dialog_utils import setup_footer

        setup_footer(self, layout)

    def connect_signals(self):
        """Connect internal signals."""
        from ..dialog_utils import connect_binary_signals

        connect_binary_signals(self)

    def on_binary_path_changed(self, text):
        """Handle binary path change."""
        from ..dialog_utils import on_binary_path_changed

        on_binary_path_changed(self, text)

    def auto_analyze_binary(self):
        """Automatically analyze binary on startup."""
        if self.binary_path and os.path.exists(self.binary_path):
            QTimer.singleShot(500, self.analyze_binary)  # Delay for UI setup

    def analyze_binary(self):
        """Analyze binary for algorithm detection."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid binary file first.")
            return

        self.status_label.setText("Analyzing binary...")
        self.analyze_btn.setEnabled(False)

        # Start worker thread
        self.worker = KeygenWorker(self.binary_path, "analyze")
        self.worker.key_generated.connect(self.on_analysis_completed)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_analysis_completed(self, result):
        """Handle analysis completion."""
        self.current_analysis = result

        # Update UI with detected values
        if "algorithm" in result:
            algo_map = {
                "simple": "Simple",
                "formatted": "Formatted",
                "rsa": "RSA",
                "aes": "AES",
                "checksum": "Checksum",
                "hardware": "Hardware-Locked",
            }
            algo_text = algo_map.get(result["algorithm"], "Simple")

            # Update combo boxes
            self.algorithm_combo.setCurrentText(algo_text)
            self.batch_algorithm_combo.setCurrentText(algo_text)

        if "format" in result:
            format_map = {
                "alphanumeric": "Alphanumeric",
                "formatted": "Formatted",
                "hex": "Hex",
                "base64": "Base64",
            }
            format_text = format_map.get(result["format"], "Alphanumeric")

            self.format_combo.setCurrentText(format_text)
            self.batch_format_combo.setCurrentText(format_text)

        # Display analysis results
        analysis_text = self.format_analysis_results(result)
        self.analysis_display.setPlainText(analysis_text)

        # Switch to analysis tab
        self.tabs.setCurrentIndex(2)

        self.status_label.setText("Analysis completed")
        self.analyze_btn.setEnabled(True)

    def format_analysis_results(self, result):
        """Format analysis results for display."""
        text = f"Binary Analysis Results for: {os.path.basename(self.binary_path)}\n"
        text += "=" * 60 + "\n\n"

        text += f"Detected Algorithm: {result.get('algorithm', 'unknown').upper()}\n"
        text += f"Detected Format: {result.get('format', 'unknown').upper()}\n\n"

        if "analysis" in result:
            analysis = result["analysis"]

            text += f"Detection Confidence: {analysis.get('confidence', 0):.1%}\n\n"

            if analysis.get("detected_algorithms"):
                text += "Detected Algorithms:\n"
                for _algo in analysis["detected_algorithms"]:
                    text += f"  • {_algo}\n"
                text += "\n"

            if analysis.get("patterns_found"):
                text += "Patterns Found:\n"
                for pattern, count in analysis["patterns_found"].items():
                    text += f"  • {pattern}: {count} occurrences\n"
                text += "\n"

            if analysis.get("entropy_analysis"):
                entropy = analysis["entropy_analysis"].get("entropy", 0)
                text += f"File Entropy: {entropy:.2f}\n"
                if entropy > 7.5:
                    text += "  → High entropy detected, likely encrypted/packed\n"
                text += "\n"

            if analysis.get("string_analysis"):
                text += "License-related Strings Found:\n"
                for _string_type in analysis["string_analysis"]:
                    text += f"  • {_string_type}\n"
                text += "\n"

        return text

    def generate_single_key(self):
        """Generate a single license key."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid binary file first.")
            return

        self.status_label.setText("Generating key...")
        self.generate_btn.setEnabled(False)

        # Get configuration
        algorithm_map = {
            "Auto-Detect": "auto",
            "Simple": "simple",
            "Formatted": "formatted",
            "RSA": "rsa",
            "AES": "aes",
            "Checksum": "checksum",
            "Hardware-Locked": "hardware",
        }

        format_map = {
            "Auto-Detect": "auto",
            "Alphanumeric": "alphanumeric",
            "Formatted": "formatted",
            "Hex": "hex",
            "Base64": "base64",
        }

        algorithm = algorithm_map.get(self.algorithm_combo.currentText(), "auto")
        format_type = format_map.get(self.format_combo.currentText(), "auto")
        custom_length = None if self.length_spin.value() == 8 else self.length_spin.value()
        validation_check = self.validation_check.isChecked()

        # Start worker thread
        self.worker = KeygenWorker(
            self.binary_path,
            "single",
            algorithm=algorithm,
            format_type=format_type,
            custom_length=custom_length,
            validation_check=validation_check,
        )
        self.worker.key_generated.connect(self.on_single_key_generated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_single_key_generated(self, result):
        """Handle single key generation completion."""
        # Display the key
        self.key_display.setPlainText(result.get("key", "Error generating key"))

        # Display detailed results
        results_text = self.format_single_key_results(result)
        self.results_display.setPlainText(results_text)

        # Store for potential copying and saving
        self.last_generated_key = result.get("key", "")
        self.last_generated_result = result

        # Enable save button if key was generated successfully
        self.save_single_btn.setEnabled(bool(self.last_generated_key))

        self.status_label.setText("Key generated successfully")
        self.generate_btn.setEnabled(True)

    def format_single_key_results(self, result):
        """Format single key results for display."""
        text = "Key Generation Results\n"
        text += "=" * 30 + "\n\n"

        text += f"Generated Key: {result.get('key', 'Error')}\n"
        text += f"Algorithm Used: {result.get('algorithm', 'unknown').upper()}\n"
        text += f"Format Used: {result.get('format', 'unknown').upper()}\n\n"

        if "validation" in result and result["validation"]["tested"]:
            validation = result["validation"]
            text += "Validation Results:\n"
            text += f"  Valid: {'YES' if validation['valid'] else 'NO'}\n"
            text += f"  Confidence: {validation['confidence']:.1%}\n"
            text += f"  Method: {validation['method']}\n"

            if validation.get("notes"):
                text += "  Notes:\n"
                for _note in validation["notes"]:
                    text += f"    • {_note}\n"
            text += "\n"

        if "analysis" in result:
            analysis = result["analysis"]
            text += f"Detection Confidence: {analysis.get('confidence', 0):.1%}\n"

            if analysis.get("detected_algorithms"):
                text += f"Detected Algorithms: {', '.join(analysis['detected_algorithms'])}\n"

        if "error" in result:
            text += f"\nError: {result['error']}\n"

        return text

    def copy_key(self):
        """Copy generated key to clipboard."""
        key = self.key_display.toPlainText().strip()
        if key:
            try:
                from intellicrack.handlers.pyqt6_handler import QApplication

                QApplication.clipboard().setText(key)
                self.status_label.setText("Key copied to clipboard")
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in keygen_dialog: %s", e)
                QMessageBox.information(self, "Copy", f"Key: {key}")

    def save_single_key(self):
        """Save the generated key to file."""
        if not self.last_generated_key:
            QMessageBox.warning(self, "Warning", "No key to save. Generate a key first.")
            return

        try:
            # Create generated_keys directory if it doesn't exist
            save_dir = os.path.join(os.getcwd(), "generated_keys")
            os.makedirs(save_dir, exist_ok=True)

            # Get binary name for filename
            binary_name = "unknown"
            if self.binary_path:
                binary_name = os.path.splitext(os.path.basename(self.binary_path))[0]

            # Generate filename with timestamp
            timestamp = int(time.time())
            algorithm = getattr(self, "last_generated_result", {}).get("algorithm", "unknown")
            filename = f"{binary_name}_{algorithm}_{timestamp}.key"

            file_path = os.path.join(save_dir, filename)

            # Prepare content to save
            result = getattr(self, "last_generated_result", {})
            content = "# License Key Generated by Intellicrack Professional Keygen\n"
            content += f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            content += f"# Binary: {os.path.basename(self.binary_path) if self.binary_path else 'N/A'}\n"
            content += f"# Algorithm: {result.get('algorithm', 'unknown')}\n"
            content += f"# Format: {result.get('format', 'unknown')}\n"

            if "analysis" in result:
                analysis = result["analysis"]
                content += f"# Detection Confidence: {analysis.get('confidence', 0):.1%}\n"
                if analysis.get("detected_algorithms"):
                    content += f"# Detected Algorithms: {', '.join(analysis['detected_algorithms'])}\n"

            content += f"\n# License Key:\n{self.last_generated_key}\n"

            # Add validation info if available
            if "validation" in result and result["validation"]["tested"]:
                validation = result["validation"]
                content += "\n# Validation Results:\n"
                content += f"# Valid: {'YES' if validation['valid'] else 'NO'}\n"
                content += f"# Confidence: {validation['confidence']:.1%}\n"
                content += f"# Method: {validation['method']}\n"
                if validation.get("notes"):
                    for _note in validation["notes"]:
                        content += f"# Note: {_note}\n"

            # Save the file
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            self.status_label.setText(f"Key saved to generated_keys/{filename}")

            # Show success message with option to open folder
            reply = QMessageBox.question(
                self,
                "Key Saved",
                f"Key saved successfully to:\n{file_path}\n\nWould you like to open the generated_keys folder?",
                QMessageBox.Yes | QMessageBox.No,
            )

            if reply == QMessageBox.Yes:
                # Open the generated_keys folder
                try:
                    if platform.system() == "Windows":
                        subprocess.run(["explorer", save_dir], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603, S607
                    elif platform.system() == "Darwin":  # macOS
                        subprocess.run(["open", save_dir], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603, S607
                    else:  # Linux
                        subprocess.run(["xdg-open", save_dir], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603, S607
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in keygen_dialog: %s", e)
                    QMessageBox.information(self, "Folder Location", f"Keys saved to: {save_dir}")

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in keygen_dialog: %s", e)
            QMessageBox.critical(self, "Save Error", f"Failed to save key: {e!s}")
            self.status_label.setText("Error saving key")

    def generate_batch_keys(self):
        """Generate batch of license keys."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid binary file first.")
            return

        count = self.batch_count_spin.value()
        if count > 100:
            reply = QMessageBox.question(
                self,
                "Large Batch",
                f"You're about to generate {count} keys. This may take a while. Continue?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

        self.status_label.setText(f"Generating {count} keys...")
        self.batch_generate_btn.setEnabled(False)
        self.batch_stop_btn.setEnabled(True)
        self.batch_progress.setValue(0)
        self.batch_progress.setMaximum(count)

        # Clear previous results
        self.batch_table.setRowCount(0)

        # Get configuration
        algorithm_map = {
            "Auto-Detect": "auto",
            "Simple": "simple",
            "Formatted": "formatted",
            "RSA": "rsa",
            "AES": "aes",
            "Checksum": "checksum",
            "Hardware-Locked": "hardware",
        }

        format_map = {
            "Auto-Detect": "auto",
            "Alphanumeric": "alphanumeric",
            "Formatted": "formatted",
            "Hex": "hex",
            "Base64": "base64",
        }

        algorithm = algorithm_map.get(self.batch_algorithm_combo.currentText(), "auto")
        format_type = format_map.get(self.batch_format_combo.currentText(), "auto")

        # Start worker thread
        self.worker = KeygenWorker(
            self.binary_path,
            "batch",
            count=count,
            algorithm=algorithm,
            format_type=format_type,
        )
        self.worker.batch_progress.connect(self.on_batch_progress)
        self.worker.batch_completed.connect(self.on_batch_completed)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_batch_progress(self, current, total):
        """Handle batch generation progress."""
        self.batch_progress.setValue(current)
        self.status_label.setText(f"Generating keys: {current}/{total}")

    def on_batch_completed(self, keys):
        """Handle batch generation completion."""
        self.generated_keys = keys

        # Populate table
        self.batch_table.setRowCount(len(keys))

        for i, key_data in enumerate(keys):
            # ID
            self.batch_table.setItem(i, 0, QTableWidgetItem(str(key_data.get("batch_id", i + 1))))

            # Key
            key_text = key_data.get("key", "Error")
            self.batch_table.setItem(i, 1, QTableWidgetItem(key_text))

            # Algorithm
            self.batch_table.setItem(i, 2, QTableWidgetItem(key_data.get("algorithm", "unknown")))

            # Format
            self.batch_table.setItem(i, 3, QTableWidgetItem(key_data.get("format", "unknown")))

            # Status
            if "error" in key_data:
                status = "Error"
                status_item = QTableWidgetItem(status)
                status_item.setBackground(QColor(255, 200, 200))  # Light red
            else:
                status = "Generated"
                status_item = QTableWidgetItem(status)
                status_item.setBackground(QColor(200, 255, 200))  # Light green

            self.batch_table.setItem(i, 4, status_item)

        # Switch to batch tab
        self.tabs.setCurrentIndex(1)

        self.status_label.setText(f"Generated {len(keys)} keys successfully")
        self.batch_generate_btn.setEnabled(True)
        self.batch_stop_btn.setEnabled(False)
        self.batch_progress.setValue(self.batch_progress.maximum())

    def stop_batch_generation(self):
        """Stop batch generation."""
        if self.worker:
            self.worker.stop()
            self.worker.wait()

        self.batch_generate_btn.setEnabled(True)
        self.batch_stop_btn.setEnabled(False)
        self.status_label.setText("Batch generation stopped")

    def clear_batch_results(self):
        """Clear batch results."""
        self.batch_table.setRowCount(0)
        self.generated_keys = []
        self.batch_progress.setValue(0)
        self.status_label.setText("Batch results cleared")

    def export_batch_keys(self):
        """Export batch keys to file."""
        if not self.generated_keys:
            QMessageBox.warning(self, "Warning", "No keys to export. Generate keys first.")
            return

        # Default to generated_keys directory
        default_dir = os.path.join(os.getcwd(), "generated_keys")
        os.makedirs(default_dir, exist_ok=True)

        default_filename = f"keygen_batch_{int(time.time())}.txt"
        default_path = os.path.join(default_dir, default_filename)

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Keys",
            default_path,
            "Text Files (*.txt);;JSON Files (*.json);;CSV Files (*.csv)",
        )

        if file_path:
            try:
                if file_path.endswith(".json"):
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(self.generated_keys, f, indent=2)
                elif file_path.endswith(".csv"):
                    import csv

                    with open(file_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(["ID", "Key", "Algorithm", "Format", "Status"])
                        for _key_data in self.generated_keys:
                            writer.writerow(
                                [
                                    _key_data.get("batch_id", ""),
                                    _key_data.get("key", ""),
                                    _key_data.get("algorithm", ""),
                                    _key_data.get("format", ""),
                                    "Error" if "error" in _key_data else "Generated",
                                ]
                            )
                else:  # txt
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(f"License Keys Generated from: {os.path.basename(self.binary_path)}\n")
                        f.write("=" * 60 + "\n\n")
                        for _key_data in self.generated_keys:
                            if "error" not in _key_data:
                                f.write(f"{_key_data.get('key', '')}\n")

                self.status_label.setText(f"Keys exported to {os.path.basename(file_path)}")

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in keygen_dialog: %s", e)
                QMessageBox.critical(self, "Export Error", f"Failed to export keys: {e!s}")

    def analyze_existing_keys(self):
        """Analyze existing keys for patterns."""
        keys_text = self.existing_keys_input.toPlainText().strip()
        if not keys_text:
            QMessageBox.warning(self, "Warning", "Please enter some existing keys to analyze.")
            return

        keys = [_key.strip() for _key in keys_text.split("\n") if _key.strip()]

        try:
            from ...utils.exploitation import analyze_existing_keys

            analysis = analyze_existing_keys(keys)

            # Format results
            analysis_text = "Key Pattern Analysis\n"
            analysis_text += "=" * 30 + "\n\n"

            analysis_text += f"Total Keys Analyzed: {analysis['count']}\n\n"

            if analysis.get("formats"):
                analysis_text += "Format Distribution:\n"
                for fmt, count in analysis["formats"].items():
                    percentage = (count / analysis["count"]) * 100
                    analysis_text += f"  • {fmt.title()}: {count} ({percentage:.1f}%)\n"
                analysis_text += "\n"

            if analysis.get("patterns"):
                analysis_text += "Length Statistics:\n"
                analysis_text += f"  • Average Length: {analysis['patterns'].get('avg_length', 0):.1f}\n"
                analysis_text += f"  • Min Length: {analysis['patterns'].get('min_length', 0)}\n"
                analysis_text += f"  • Max Length: {analysis['patterns'].get('max_length', 0)}\n\n"

            if analysis.get("recommendations"):
                analysis_text += "Recommendations for Key Generation:\n"
                analysis_text += f"  • Suggested Format: {analysis['recommendations'].get('format', 'alphanumeric').title()}\n"
                analysis_text += f"  • Suggested Length: {analysis['recommendations'].get('length', 25)}\n"

            self.key_analysis_display.setPlainText(analysis_text)

            # Switch to management tab
            self.tabs.setCurrentIndex(3)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in keygen_dialog: %s", e)
            QMessageBox.critical(self, "Analysis Error", f"Failed to analyze keys: {e!s}")

    def on_error(self, error_msg):
        """Handle worker thread errors."""
        QMessageBox.critical(self, "Error", f"An error occurred: {error_msg}")
        self.status_label.setText("Error occurred")
        self.generate_btn.setEnabled(True)
        self.batch_generate_btn.setEnabled(True)
        self.batch_stop_btn.setEnabled(False)
        self.analyze_btn.setEnabled(True)

    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        event.accept()


# Convenience function for main app integration
def show_keygen_dialog(parent=None, binary_path: str = ""):
    """Show the keygen dialog."""
    dialog = KeygenDialog(parent, binary_path)
    return dialog.exec()
