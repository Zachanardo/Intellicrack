"""Keygen dialog for generating license keys and serial numbers."""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QCloseEvent,
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
from intellicrack.utils.logger import logger

from ..icon_manager import set_button_icon
from .base_dialog import BaseDialog


if TYPE_CHECKING:
    from collections.abc import Callable


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

    def __init__(self, binary_path: str, operation: str, **kwargs: Any) -> None:
        """Initialize the KeygenWorker with default values.

        Args:
            binary_path: Path to the binary file for key generation.
            operation: Type of operation (single, batch, analyze).
            **kwargs: Additional keyword arguments for the operation.

        """
        super().__init__()
        self.binary_path = binary_path
        self.operation = operation
        self.kwargs: dict[str, Any] = dict(kwargs)
        self.should_stop = False
        self._logger = logging.getLogger(__name__)

    def run(self) -> None:
        """Execute the keygen operation."""
        try:
            if self.operation == "single":
                self._generate_single_key()
            elif self.operation == "batch":
                self._generate_batch_keys()
            elif self.operation == "analyze":
                self._analyze_binary()
        except (OSError, ValueError, RuntimeError) as e:
            self._logger.exception("Error in keygen_dialog: %s", e)
            self.error_occurred.emit(str(e))

    def _generate_single_key(self) -> None:
        """Generate a single license key."""
        from ...utils.exploitation import generate_license_key

        algorithm_val = self.kwargs.get("algorithm", "auto")
        format_val = self.kwargs.get("format_type", "auto")
        custom_length_val = self.kwargs.get("custom_length")
        validation_val = self.kwargs.get("validation_check", False)

        kwargs_for_keygen: dict[str, Any] = {
            "algorithm": str(algorithm_val) if algorithm_val is not None else "auto",
            "format_type": str(format_val) if format_val is not None else "auto",
            "validation_check": bool(validation_val),
        }
        if custom_length_val is not None:
            kwargs_for_keygen["custom_length"] = int(custom_length_val)
        result: dict[str, Any] = generate_license_key(self.binary_path, **kwargs_for_keygen)
        self.key_generated.emit(result)

    def _generate_batch_keys(self) -> None:
        """Generate multiple license keys."""
        count_val = self.kwargs.get("count", 10)
        count: int = int(count_val) if count_val is not None else 10
        keys: list[dict[str, Any]] = []

        algorithm_val = self.kwargs.get("algorithm", "auto")
        format_val = self.kwargs.get("format_type", "auto")
        custom_length_val = self.kwargs.get("custom_length")

        for i in range(count):
            if self.should_stop:
                break

            try:
                from ...utils.exploitation import generate_license_key

                batch_kwargs: dict[str, Any] = {
                    "algorithm": str(algorithm_val) if algorithm_val is not None else "auto",
                    "format_type": str(format_val) if format_val is not None else "auto",
                    "validation_check": False,
                }
                if custom_length_val is not None:
                    batch_kwargs["custom_length"] = int(custom_length_val)
                result: dict[str, Any] = generate_license_key(self.binary_path, **batch_kwargs)
                result["batch_id"] = i + 1
                keys.append(result)
                self.batch_progress.emit(i + 1, count)
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in keygen_dialog: %s", e)
                keys.append(
                    {
                        "batch_id": i + 1,
                        "key": "",
                        "error": str(e),
                        "algorithm": str(algorithm_val) if algorithm_val is not None else "auto",
                        "format": str(format_val) if format_val is not None else "auto",
                    },
                )

        self.batch_completed.emit(keys)

    def _analyze_binary(self) -> None:
        """Analyze binary for algorithm detection."""
        from ...utils.exploitation import _detect_key_format, _detect_license_algorithm

        algorithm, analysis = _detect_license_algorithm(self.binary_path)
        format_type = _detect_key_format(self.binary_path)

        result: dict[str, Any] = {
            "algorithm": algorithm,
            "format": format_type,
            "analysis": analysis,
        }
        self.key_generated.emit(result)

    def stop(self) -> None:
        """Stop the worker thread."""
        self.should_stop = True


class KeygenDialog(BaseDialog):
    """Professional Keygen Dialog with advanced features."""

    analysis_display: QTextEdit | None
    analyze_keys_btn: QPushButton | None
    analyze_btn: QPushButton | None
    batch_algorithm_combo: QComboBox | None
    batch_clear_btn: QPushButton | None
    batch_count_spin: QSpinBox | None
    batch_export_btn: QPushButton | None
    batch_format_combo: QComboBox | None
    batch_generate_btn: QPushButton | None
    batch_progress: QProgressBar | None
    batch_stop_btn: QPushButton | None
    batch_table: QTableWidget | None
    copy_btn: QPushButton | None
    existing_keys_input: QTextEdit | None
    generate_btn: QPushButton | None
    key_analysis_display: QTextEdit | None
    key_display: QTextEdit | None
    results_display: QTextEdit | None
    save_single_btn: QPushButton | None
    worker: KeygenWorker | None
    generated_keys: list[dict[str, Any]]
    current_analysis: dict[str, Any]
    last_generated_result: dict[str, Any]
    _logger: logging.Logger

    def __init__(self, parent: QWidget | None = None, binary_path: str = "") -> None:
        """Initialize the KeygenDialog with default values.

        Args:
            parent: Parent widget for the dialog.
            binary_path: Path to binary file for analysis.

        """
        self.analysis_display = None
        self.analyze_keys_btn = None
        self.analyze_btn = None
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
        self._logger = logging.getLogger(__name__)

        self.setWindowTitle("Professional License Key Generator")
        self.setMinimumSize(900, 700)
        self.setModal(True)

        self.setup_ui()
        self.connect_signals()

        # Auto-analyze if binary path provided
        if self.binary_path and os.path.exists(self.binary_path):
            self.auto_analyze_binary()

    def setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)

        # Title and binary selection
        self.setup_header(layout)

        # Main tabs
        self.setup_tabs(layout)

        # Status and controls
        self.setup_footer(layout)

    def setup_header(
        self,
        layout: QVBoxLayout,
        show_label: bool = True,
        extra_buttons: list[tuple[str, Callable[[], None]]] | None = None,
    ) -> None:
        """Set up header with binary selection.

        Args:
            layout: Main layout widget.
            show_label: Whether to show the binary label.
            extra_buttons: Optional list of extra buttons to add.

        """
        buttons: list[tuple[str, Callable[[], None]]] = [("Analyze Binary", self.analyze_binary)]
        if extra_buttons:
            buttons.extend(extra_buttons)
        super().setup_header(layout, show_label=show_label, extra_buttons=buttons)
        self.analyze_btn = None
        for i in range(layout.count()):
            item = layout.itemAt(i)
            if item is not None:
                sub_layout = item.layout()
                if sub_layout is not None:
                    for j in range(sub_layout.count()):
                        sub_item = sub_layout.itemAt(j)
                        if sub_item is not None:
                            widget = sub_item.widget()
                            if isinstance(widget, QPushButton) and widget.text() == "Analyze Binary":
                                self.analyze_btn = widget
                                break

    def setup_tabs(self, layout: QVBoxLayout) -> None:
        """Set up main tab widget.

        Args:
            layout: Main layout widget.

        """
        self.tabs = QTabWidget()

        self.setup_single_tab()

        self.setup_batch_tab()

        self.setup_analysis_tab()

        self.setup_management_tab()

        layout.addWidget(self.tabs)

    def setup_single_tab(self) -> None:
        """Set up single key generation tab."""
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
            ],
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
            ],
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

    def setup_batch_tab(self) -> None:
        """Set up batch generation tab."""
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
            ],
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
            ],
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
            ],
        )

        header = self.batch_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.batch_table)

        self.tabs.addTab(batch_widget, "Batch Generation")

    def setup_analysis_tab(self) -> None:
        """Set up binary analysis tab."""
        analysis_widget = QWidget()
        layout = QVBoxLayout(analysis_widget)

        # Analysis results
        self.analysis_display = QTextEdit()
        self.analysis_display.setFont(QFont("Consolas", 10))

        layout.addWidget(QLabel("Binary Analysis Results:"))
        layout.addWidget(self.analysis_display)

        self.tabs.addTab(analysis_widget, "Binary Analysis")

    def setup_management_tab(self) -> None:
        """Set up key management tab."""
        management_widget = QWidget()
        layout = QVBoxLayout(management_widget)

        # Key input section
        input_group = QGroupBox("Analyze Existing Keys")
        input_layout = QVBoxLayout(input_group)

        self.existing_keys_input = QTextEdit()
        self.existing_keys_input.setMaximumHeight(100)
        self.existing_keys_input.setToolTip("Enter existing license keys to analyze their patterns and characteristics")
        instruction_label = QLabel("Paste existing license keys (one per line) to analyze patterns and detect key generation algorithms:")
        input_layout.insertWidget(0, instruction_label)
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

    def setup_footer(self, layout: QVBoxLayout) -> None:
        """Set up footer with status and close button.

        Args:
            layout: Main layout widget.

        """
        from ..dialog_utils import setup_footer

        setup_footer(self, layout)

    def connect_signals(self) -> None:
        """Connect internal signals."""
        from ..dialog_utils import connect_binary_signals

        connect_binary_signals(self)

    def on_binary_path_changed(self, text: str) -> None:
        """Handle binary path change.

        Args:
            text: New binary path text.

        """
        from ..dialog_utils import on_binary_path_changed

        on_binary_path_changed(self, text)

    def auto_analyze_binary(self) -> None:
        """Automatically analyze binary on startup."""
        if self.binary_path and os.path.exists(self.binary_path):
            QTimer.singleShot(500, self.analyze_binary)  # Delay for UI setup

    def analyze_binary(self) -> None:
        """Analyze binary for algorithm detection."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid binary file first.")
            return

        self.status_label.setText("Analyzing binary...")
        if self.analyze_btn is not None:
            self.analyze_btn.setEnabled(False)

        self.worker = KeygenWorker(self.binary_path, "analyze")
        self.worker.key_generated.connect(self.on_analysis_completed)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def on_analysis_completed(self, result: dict[str, Any]) -> None:
        """Handle analysis completion.

        Args:
            result: Analysis result dictionary with algorithm and format detection.

        """
        self.current_analysis = result

        if "algorithm" in result:
            algo_map = {
                "simple": "Simple",
                "formatted": "Formatted",
                "rsa": "RSA",
                "aes": "AES",
                "checksum": "Checksum",
                "hardware": "Hardware-Locked",
            }
            algo_text = algo_map.get(str(result["algorithm"]), "Simple")

            self.algorithm_combo.setCurrentText(algo_text)
            if self.batch_algorithm_combo is not None:
                self.batch_algorithm_combo.setCurrentText(algo_text)

        if "format" in result:
            format_map = {
                "alphanumeric": "Alphanumeric",
                "formatted": "Formatted",
                "hex": "Hex",
                "base64": "Base64",
            }
            format_text = format_map.get(str(result["format"]), "Alphanumeric")

            self.format_combo.setCurrentText(format_text)
            if self.batch_format_combo is not None:
                self.batch_format_combo.setCurrentText(format_text)

        analysis_text = self.format_analysis_results(result)
        if self.analysis_display is not None:
            self.analysis_display.setPlainText(analysis_text)

        self.tabs.setCurrentIndex(2)

        self.status_label.setText("Analysis completed")
        if self.analyze_btn is not None:
            self.analyze_btn.setEnabled(True)

    def format_analysis_results(self, result: dict[str, Any]) -> str:
        """Format analysis results for display.

        Args:
            result: Analysis result dictionary.

        Returns:
            Formatted analysis results as a string.

        """
        text = f"Binary Analysis Results for: {os.path.basename(self.binary_path)}\n"
        text += "=" * 60 + "\n\n"

        algo_val = result.get("algorithm", "unknown")
        format_val = result.get("format", "unknown")
        text += f"Detected Algorithm: {str(algo_val).upper()}\n"
        text += f"Detected Format: {str(format_val).upper()}\n\n"

        if "analysis" in result:
            analysis: dict[str, Any] = result["analysis"]

            text += f"Detection Confidence: {analysis.get('confidence', 0):.1%}\n\n"

            if analysis.get("detected_algorithms"):
                text += "Detected Algorithms:\n"
                for algo in analysis["detected_algorithms"]:
                    text += f"   {algo}\n"
                text += "\n"

            if analysis.get("patterns_found"):
                text += "Patterns Found:\n"
                for pattern, count in analysis["patterns_found"].items():
                    text += f"   {pattern}: {count} occurrences\n"
                text += "\n"

            if analysis.get("entropy_analysis"):
                entropy_data: dict[str, Any] = analysis["entropy_analysis"]
                entropy = entropy_data.get("entropy", 0)
                text += f"File Entropy: {entropy:.2f}\n"
                if isinstance(entropy, (int, float)) and entropy > 7.5:
                    text += "  -> High entropy detected, likely encrypted/packed\n"
                text += "\n"

            if analysis.get("string_analysis"):
                text += "License-related Strings Found:\n"
                for string_type in analysis["string_analysis"]:
                    text += f"   {string_type}\n"
                text += "\n"

        return text

    def generate_single_key(self) -> None:
        """Generate a single license key."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid binary file first.")
            return

        self.status_label.setText("Generating key...")
        if self.generate_btn is not None:
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

    def on_single_key_generated(self, result: dict[str, Any]) -> None:
        """Handle single key generation completion.

        Args:
            result: Key generation result dictionary.

        """
        key_val = result.get("key", "Error generating key")
        if self.key_display is not None:
            self.key_display.setPlainText(str(key_val))

        results_text = self.format_single_key_results(result)
        if self.results_display is not None:
            self.results_display.setPlainText(results_text)

        self.last_generated_key = str(result.get("key", ""))
        self.last_generated_result = result

        if self.save_single_btn is not None:
            self.save_single_btn.setEnabled(bool(self.last_generated_key))

        self.status_label.setText("Key generated successfully")
        if self.generate_btn is not None:
            self.generate_btn.setEnabled(True)

    def format_single_key_results(self, result: dict[str, Any]) -> str:
        """Format single key results for display.

        Args:
            result: Key generation result dictionary.

        Returns:
            Formatted key results as a string.

        """
        text = "Key Generation Results\n"
        text += "=" * 30 + "\n\n"

        text += f"Generated Key: {result.get('key', 'Error')}\n"
        algo_str = str(result.get("algorithm", "unknown")).upper()
        fmt_str = str(result.get("format", "unknown")).upper()
        text += f"Algorithm Used: {algo_str}\n"
        text += f"Format Used: {fmt_str}\n\n"

        if "validation" in result:
            validation_data: dict[str, Any] = result["validation"]
            if validation_data.get("tested"):
                text += "Validation Results:\n"
                text += f"  Valid: {'YES' if validation_data.get('valid') else 'NO'}\n"
                text += f"  Confidence: {validation_data.get('confidence', 0):.1%}\n"
                text += f"  Method: {validation_data.get('method', 'unknown')}\n"

                if validation_data.get("notes"):
                    text += "  Notes:\n"
                    for note in validation_data["notes"]:
                        text += f"     {note}\n"
                text += "\n"

        if "analysis" in result:
            analysis: dict[str, Any] = result["analysis"]
            text += f"Detection Confidence: {analysis.get('confidence', 0):.1%}\n"

            if analysis.get("detected_algorithms"):
                text += f"Detected Algorithms: {', '.join(analysis['detected_algorithms'])}\n"

        if "error" in result:
            text += f"\nError: {result['error']}\n"

        return text

    def copy_key(self) -> None:
        """Copy generated key to clipboard."""
        if self.key_display is None:
            return
        if key := self.key_display.toPlainText().strip():
            try:
                from intellicrack.handlers.pyqt6_handler import QApplication

                clipboard = QApplication.clipboard()
                if clipboard is not None:
                    clipboard.setText(key)
                self.status_label.setText("Key copied to clipboard")
            except (OSError, ValueError, RuntimeError) as e:
                self._logger.exception("Error in keygen_dialog: %s", e)
                QMessageBox.information(self, "Copy", f"Key: {key}")

    def save_single_key(self) -> None:
        """Save the generated key to file."""
        if not self.last_generated_key:
            QMessageBox.warning(self, "Warning", "No key to save. Generate a key first.")
            return

        try:
            # Create generated_keys directory if it doesn't exist
            save_dir = os.path.join(str(Path.cwd()), "generated_keys")
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
                    for note in validation["notes"]:
                        content += f"# Note: {note}\n"

            # Save the file
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            self.status_label.setText(f"Key saved to generated_keys/{filename}")

            reply = QMessageBox.question(
                self,
                "Key Saved",
                f"Key saved successfully to:\n{file_path}\n\nWould you like to open the generated_keys folder?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )

            if reply == QMessageBox.StandardButton.Yes:
                # Open the generated_keys folder
                try:
                    if platform.system() == "Windows":
                        subprocess.run(["explorer", save_dir], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    elif platform.system() == "Darwin":  # macOS
                        subprocess.run(["open", save_dir], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                    else:  # Linux
                        subprocess.run(["xdg-open", save_dir], check=False)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in keygen_dialog: %s", e)
                    QMessageBox.information(self, "Folder Location", f"Keys saved to: {save_dir}")

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in keygen_dialog: %s", e)
            QMessageBox.critical(self, "Save Error", f"Failed to save key: {e!s}")
            self.status_label.setText("Error saving key")

    def generate_batch_keys(self) -> None:
        """Generate batch of license keys."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid binary file first.")
            return

        if self.batch_count_spin is None:
            return
        count = self.batch_count_spin.value()
        if count > 100:
            reply = QMessageBox.question(
                self,
                "Large Batch",
                f"You're about to generate {count} keys. This may take a while. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self.status_label.setText(f"Generating {count} keys...")
        if self.batch_generate_btn is not None:
            self.batch_generate_btn.setEnabled(False)
        if self.batch_stop_btn is not None:
            self.batch_stop_btn.setEnabled(True)
        if self.batch_progress is not None:
            self.batch_progress.setValue(0)
            self.batch_progress.setMaximum(count)

        if self.batch_table is not None:
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

        algorithm = "auto"
        if self.batch_algorithm_combo is not None:
            algorithm = algorithm_map.get(self.batch_algorithm_combo.currentText(), "auto")
        format_type = "auto"
        if self.batch_format_combo is not None:
            format_type = format_map.get(self.batch_format_combo.currentText(), "auto")

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

    def on_batch_progress(self, current: int, total: int) -> None:
        """Handle batch generation progress.

        Args:
            current: Current number of keys generated.
            total: Total number of keys to generate.

        """
        if self.batch_progress is not None:
            self.batch_progress.setValue(current)
        self.status_label.setText(f"Generating keys: {current}/{total}")

    def on_batch_completed(self, keys: list[dict[str, Any]]) -> None:
        """Handle batch generation completion.

        Args:
            keys: List of generated key results.

        """
        self.generated_keys = keys

        if self.batch_table is not None:
            self.batch_table.setRowCount(len(keys))

            for i, key_data in enumerate(keys):
                self.batch_table.setItem(i, 0, QTableWidgetItem(str(key_data.get("batch_id", i + 1))))

                key_text = str(key_data.get("key", "Error"))
                self.batch_table.setItem(i, 1, QTableWidgetItem(key_text))

                self.batch_table.setItem(i, 2, QTableWidgetItem(str(key_data.get("algorithm", "unknown"))))

                self.batch_table.setItem(i, 3, QTableWidgetItem(str(key_data.get("format", "unknown"))))

                if "error" in key_data:
                    status_item = QTableWidgetItem("Error")
                    status_item.setBackground(QColor(255, 200, 200))
                else:
                    status_item = QTableWidgetItem("Generated")
                    status_item.setBackground(QColor(200, 255, 200))

                self.batch_table.setItem(i, 4, status_item)

        self.tabs.setCurrentIndex(1)

        self.status_label.setText(f"Generated {len(keys)} keys successfully")
        if self.batch_generate_btn is not None:
            self.batch_generate_btn.setEnabled(True)
        if self.batch_stop_btn is not None:
            self.batch_stop_btn.setEnabled(False)
        if self.batch_progress is not None:
            self.batch_progress.setValue(self.batch_progress.maximum())

    def stop_batch_generation(self) -> None:
        """Stop batch generation."""
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait()

        if self.batch_generate_btn is not None:
            self.batch_generate_btn.setEnabled(True)
        if self.batch_stop_btn is not None:
            self.batch_stop_btn.setEnabled(False)
        self.status_label.setText("Batch generation stopped")

    def clear_batch_results(self) -> None:
        """Clear batch results."""
        if self.batch_table is not None:
            self.batch_table.setRowCount(0)
        self.generated_keys = []
        if self.batch_progress is not None:
            self.batch_progress.setValue(0)
        self.status_label.setText("Batch results cleared")

    def export_batch_keys(self) -> None:
        """Export batch keys to file."""
        if not self.generated_keys:
            QMessageBox.warning(self, "Warning", "No keys to export. Generate keys first.")
            return

        # Default to generated_keys directory
        default_dir = os.path.join(str(Path.cwd()), "generated_keys")
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
                        for key_data in self.generated_keys:
                            writer.writerow(
                                [
                                    key_data.get("batch_id", ""),
                                    key_data.get("key", ""),
                                    key_data.get("algorithm", ""),
                                    key_data.get("format", ""),
                                    "Error" if "error" in key_data else "Generated",
                                ],
                            )
                else:  # txt
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(f"License Keys Generated from: {os.path.basename(self.binary_path)}\n")
                        f.write("=" * 60 + "\n\n")
                        for key_data in self.generated_keys:
                            if "error" not in key_data:
                                f.write(f"{key_data.get('key', '')}\n")

                self.status_label.setText(f"Keys exported to {os.path.basename(file_path)}")

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in keygen_dialog: %s", e)
                QMessageBox.critical(self, "Export Error", f"Failed to export keys: {e!s}")

    def analyze_existing_keys(self) -> None:
        """Analyze existing keys for patterns."""
        if self.existing_keys_input is None:
            return
        keys_text = self.existing_keys_input.toPlainText().strip()
        if not keys_text:
            QMessageBox.warning(self, "Warning", "Please enter some existing keys to analyze.")
            return

        keys = [key.strip() for key in keys_text.split("\n") if key.strip()]

        try:
            from ...utils.exploitation import analyze_existing_keys

            analysis = analyze_existing_keys(keys)

            analysis_text = "Key Pattern Analysis\n"
            analysis_text += "=" * 30 + "\n\n"

            analysis_text += f"Total Keys Analyzed: {analysis['count']}\n\n"

            if analysis.get("formats"):
                analysis_text += "Format Distribution:\n"
                for fmt, count in analysis["formats"].items():
                    percentage = (count / analysis["count"]) * 100
                    analysis_text += f"   {fmt.title()}: {count} ({percentage:.1f}%)\n"
                analysis_text += "\n"

            if analysis.get("patterns"):
                analysis_text += "Length Statistics:\n"
                analysis_text += f"   Average Length: {analysis['patterns'].get('avg_length', 0):.1f}\n"
                analysis_text += f"   Min Length: {analysis['patterns'].get('min_length', 0)}\n"
                analysis_text += f"   Max Length: {analysis['patterns'].get('max_length', 0)}\n\n"

            if analysis.get("recommendations"):
                analysis_text += "Recommendations for Key Generation:\n"
                analysis_text += f"   Suggested Format: {analysis['recommendations'].get('format', 'alphanumeric').title()}\n"
                analysis_text += f"   Suggested Length: {analysis['recommendations'].get('length', 25)}\n"

            if self.key_analysis_display is not None:
                self.key_analysis_display.setPlainText(analysis_text)

            self.tabs.setCurrentIndex(3)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in keygen_dialog: %s", e)
            QMessageBox.critical(self, "Analysis Error", f"Failed to analyze keys: {e!s}")

    def on_error(self, error_msg: str) -> None:
        """Handle worker thread errors.

        Args:
            error_msg: Error message describing what went wrong.

        """
        QMessageBox.critical(self, "Error", f"An error occurred: {error_msg}")
        self.status_label.setText("Error occurred")
        if self.generate_btn is not None:
            self.generate_btn.setEnabled(True)
        if self.batch_generate_btn is not None:
            self.batch_generate_btn.setEnabled(True)
        if self.batch_stop_btn is not None:
            self.batch_stop_btn.setEnabled(False)
        if self.analyze_btn is not None:
            self.analyze_btn.setEnabled(True)

    def closeEvent(self, event: QCloseEvent | None) -> None:
        """Handle dialog close event.

        Args:
            event: Close event from Qt framework.

        """
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        if event is not None:
            event.accept()


def show_keygen_dialog(parent: QWidget | None = None, binary_path: str = "") -> int:
    """Show the keygen dialog.

    Args:
        parent: Parent widget for the dialog.
        binary_path: Path to binary file for key generation.

    Returns:
        Dialog execution result code.

    """
    dialog = KeygenDialog(parent, binary_path)
    return dialog.exec()
