"""Serial Number Generator Dialog."""

import json
import os
import re
from datetime import datetime
from typing import Any, Dict

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.serial_generator import SerialConstraints, SerialFormat, SerialNumberGenerator


class SerialGeneratorWorker(QThread):
    """Worker thread for serial generation operations."""

    progress = pyqtSignal(str)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, generator: SerialNumberGenerator, operation: str, params: Dict[str, Any]) -> None:
        """Initialize the SerialGeneratorWorker with a generator, operation, and parameters."""
        super().__init__()
        self.generator = generator
        self.operation = operation
        self.params = params

    def run(self) -> None:
        """Execute serial generation operation in background thread."""
        try:
            if self.operation == "analyze":
                self.progress.emit("Analyzing serial patterns...")
                valid_serials = self.params["serials"]
                analysis = self.generator.analyze_serial_algorithm(valid_serials)
                self.result.emit({"operation": "analysis", "data": analysis})

            elif self.operation == "generate_single":
                self.progress.emit("Generating serial...")
                constraints = self.params["constraints"]
                seed = self.params.get("seed")
                serial = self.generator.generate_serial(constraints, seed)
                self.result.emit({"operation": "single_serial", "data": serial})

            elif self.operation == "generate_batch":
                self.progress.emit("Generating batch serials...")
                constraints = self.params["constraints"]
                count = self.params["count"]
                serials = []

                for i in range(count):
                    self.progress.emit(f"Generating serial {i + 1}/{count}...")
                    serial = self.generator.generate_serial(constraints)
                    serials.append(serial)

                self.result.emit({"operation": "batch_serials", "data": serials})

            elif self.operation == "validate":
                self.progress.emit("Validating serial...")
                serial = self.params["serial"]
                constraints = self.params.get("constraints")

                # Perform validation based on constraints
                is_valid = True
                validation_details = {}

                if constraints:
                    # Check format
                    if constraints.format == SerialFormat.NUMERIC:
                        is_valid = serial.replace("-", "").isdigit()
                        validation_details["format_check"] = is_valid

                    # Check length
                    clean_serial = serial.replace("-", "")
                    if len(clean_serial) != constraints.length:
                        is_valid = False
                        validation_details["length_check"] = False

                    # Check checksum if specified
                    if constraints.checksum_algorithm:
                        checksum_func = self.generator.checksum_functions.get(constraints.checksum_algorithm)
                        if checksum_func:
                            checksum_valid = self.generator._verify_checksum(serial, checksum_func)
                            is_valid = is_valid and checksum_valid
                            validation_details["checksum_check"] = checksum_valid

                self.result.emit(
                    {"operation": "validation", "data": {"serial": serial, "is_valid": is_valid, "details": validation_details}},
                )

            elif self.operation == "crack_pattern":
                self.progress.emit("Analyzing pattern for cracking...")
                samples = self.params["samples"]

                # Analyze the samples to determine the pattern
                analysis = self.generator.analyze_serial_algorithm(samples)

                # Generate new serials based on detected pattern
                if analysis["format"] and analysis["length"]:
                    constraints = SerialConstraints(
                        length=analysis["length"]["most_common"],
                        format=analysis["format"],
                        checksum_algorithm=analysis.get("checksum", {}).get("algorithm"),
                    )

                    # Generate some test serials
                    test_serials = []
                    for _ in range(10):
                        serial = self.generator.generate_serial(constraints)
                        test_serials.append(serial)

                    self.result.emit({"operation": "pattern_crack", "data": {"analysis": analysis, "generated_serials": test_serials}})

        except Exception as e:
            self.error.emit(str(e))


class SerialGeneratorDialog(QDialog):
    """Comprehensive serial number generator interface."""

    def __init__(self, parent=None) -> None:
        """Initialize the SerialNumberGeneratorDialog with an optional parent."""
        super().__init__(parent)
        self.generator = SerialNumberGenerator()
        self.generated_serials = []
        self.analyzed_pattern = None
        self.worker = None

        self.init_ui()
        self.load_presets()

    def init_ui(self) -> None:
        """Initialize the user interface."""
        self.setWindowTitle("Serial Number Generator")
        self.setMinimumSize(900, 650)

        # Main layout
        layout = QVBoxLayout()

        # Create tab widget
        self.tabs = QTabWidget()

        # Add tabs
        self.tabs.addTab(self.create_generation_tab(), "Generate")
        self.tabs.addTab(self.create_analysis_tab(), "Analyze")
        self.tabs.addTab(self.create_batch_tab(), "Batch")
        self.tabs.addTab(self.create_validation_tab(), "Validate")
        self.tabs.addTab(self.create_patterns_tab(), "Patterns")
        self.tabs.addTab(self.create_presets_tab(), "Presets")

        layout.addWidget(self.tabs)

        # Console output
        self.console = QTextEdit()
        self.console.setMaximumHeight(120)
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 9))
        layout.addWidget(self.console)

        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def create_generation_tab(self):
        """Create serial generation tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Format selection
        format_group = QGroupBox("Serial Format")
        format_layout = QVBoxLayout()

        format_select_layout = QHBoxLayout()
        format_select_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        for fmt in SerialFormat:
            self.format_combo.addItem(fmt.value)
        self.format_combo.currentTextChanged.connect(self.on_format_changed)
        format_select_layout.addWidget(self.format_combo)

        format_select_layout.addWidget(QLabel("Length:"))
        self.length_spin = QSpinBox()
        self.length_spin.setRange(4, 64)
        self.length_spin.setValue(16)
        format_select_layout.addWidget(self.length_spin)

        format_select_layout.addWidget(QLabel("Groups:"))
        self.groups_spin = QSpinBox()
        self.groups_spin.setRange(1, 10)
        self.groups_spin.setValue(1)
        format_select_layout.addWidget(self.groups_spin)

        format_select_layout.addWidget(QLabel("Separator:"))
        self.separator_input = QLineEdit("-")
        self.separator_input.setMaximumWidth(50)
        format_select_layout.addWidget(self.separator_input)

        format_select_layout.addStretch()
        format_layout.addLayout(format_select_layout)

        # Custom alphabet (for custom format)
        self.custom_alphabet_widget = QWidget()
        alphabet_layout = QHBoxLayout()
        alphabet_layout.addWidget(QLabel("Custom Alphabet:"))
        self.custom_alphabet_input = QLineEdit("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        alphabet_layout.addWidget(self.custom_alphabet_input)
        self.custom_alphabet_widget.setLayout(alphabet_layout)
        self.custom_alphabet_widget.setVisible(False)
        format_layout.addWidget(self.custom_alphabet_widget)

        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        # Checksum settings
        checksum_group = QGroupBox("Checksum")
        checksum_layout = QHBoxLayout()

        self.enable_checksum = QCheckBox("Enable Checksum")
        checksum_layout.addWidget(self.enable_checksum)

        checksum_layout.addWidget(QLabel("Algorithm:"))
        self.checksum_combo = QComboBox()
        self.checksum_combo.addItems(
            ["none", "luhn", "verhoeff", "damm", "crc16", "crc32", "fletcher16", "fletcher32", "adler32", "mod11", "mod37", "mod97"],
        )
        self.checksum_combo.setEnabled(False)
        self.enable_checksum.toggled.connect(self.checksum_combo.setEnabled)
        checksum_layout.addWidget(self.checksum_combo)

        checksum_layout.addStretch()
        checksum_group.setLayout(checksum_layout)
        layout.addWidget(checksum_group)

        # Constraints
        constraints_group = QGroupBox("Constraints")
        constraints_layout = QVBoxLayout()

        # Must contain
        must_layout = QHBoxLayout()
        must_layout.addWidget(QLabel("Must Contain:"))
        self.must_contain_input = QLineEdit()
        self.must_contain_input.setToolTip("Comma-separated patterns that must be present")
        must_layout.addWidget(self.must_contain_input)
        constraints_layout.addLayout(must_layout)

        # Cannot contain
        cannot_layout = QHBoxLayout()
        cannot_layout.addWidget(QLabel("Cannot Contain:"))
        self.cannot_contain_input = QLineEdit()
        self.cannot_contain_input.setToolTip("Comma-separated patterns that must not be present")
        cannot_layout.addWidget(self.cannot_contain_input)
        constraints_layout.addLayout(cannot_layout)

        # Blacklist patterns
        blacklist_layout = QHBoxLayout()
        blacklist_layout.addWidget(QLabel("Blacklist Patterns:"))
        self.blacklist_input = QLineEdit()
        self.blacklist_input.setToolTip("Regex patterns to exclude")
        blacklist_layout.addWidget(self.blacklist_input)
        constraints_layout.addLayout(blacklist_layout)

        constraints_group.setLayout(constraints_layout)
        layout.addWidget(constraints_group)

        # Generation buttons
        gen_layout = QHBoxLayout()
        self.btn_generate = QPushButton("Generate Serial")
        self.btn_generate.clicked.connect(self.generate_single_serial)
        gen_layout.addWidget(self.btn_generate)

        self.btn_copy = QPushButton("Copy to Clipboard")
        self.btn_copy.clicked.connect(self.copy_serial)
        self.btn_copy.setEnabled(False)
        gen_layout.addWidget(self.btn_copy)

        self.btn_save = QPushButton("Save Serial")
        self.btn_save.clicked.connect(self.save_serial)
        self.btn_save.setEnabled(False)
        gen_layout.addWidget(self.btn_save)

        gen_layout.addStretch()
        layout.addLayout(gen_layout)

        # Generated serial output
        output_group = QGroupBox("Generated Serial")
        output_layout = QVBoxLayout()

        self.serial_output = QLineEdit()
        self.serial_output.setFont(QFont("Consolas", 14))
        self.serial_output.setReadOnly(True)
        output_layout.addWidget(self.serial_output)

        # Serial details
        self.serial_details = QTextEdit()
        self.serial_details.setMaximumHeight(100)
        self.serial_details.setReadOnly(True)
        self.serial_details.setFont(QFont("Consolas", 9))
        output_layout.addWidget(self.serial_details)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_analysis_tab(self):
        """Create serial analysis tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Input group
        input_group = QGroupBox("Sample Serials")
        input_layout = QVBoxLayout()

        btn_layout = QHBoxLayout()
        self.btn_load_samples = QPushButton("Load from File")
        self.btn_load_samples.clicked.connect(self.load_sample_serials)
        btn_layout.addWidget(self.btn_load_samples)

        self.btn_clear_samples = QPushButton("Clear")
        self.btn_clear_samples.clicked.connect(lambda: self.samples_input.clear())
        btn_layout.addWidget(self.btn_clear_samples)

        self.btn_analyze = QPushButton("Analyze Pattern")
        self.btn_analyze.clicked.connect(self.analyze_serials)
        btn_layout.addWidget(self.btn_analyze)

        btn_layout.addStretch()
        input_layout.addLayout(btn_layout)

        self.samples_input = QPlainTextEdit()
        self.samples_input.setToolTip("Enter valid serial numbers, one per line")
        self.samples_input.setFont(QFont("Consolas", 10))
        input_layout.addWidget(self.samples_input)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # Analysis results
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()

        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setFont(QFont("Consolas", 9))
        results_layout.addWidget(self.analysis_output)

        # Generate based on analysis
        gen_layout = QHBoxLayout()
        self.btn_generate_from_analysis = QPushButton("Generate Similar Serials")
        self.btn_generate_from_analysis.clicked.connect(self.generate_from_analysis)
        self.btn_generate_from_analysis.setEnabled(False)
        gen_layout.addWidget(self.btn_generate_from_analysis)

        gen_layout.addStretch()
        results_layout.addLayout(gen_layout)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        widget.setLayout(layout)
        return widget

    def create_batch_tab(self):
        """Create batch generation tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Batch settings
        settings_group = QGroupBox("Batch Settings")
        settings_layout = QVBoxLayout()

        # Count
        count_layout = QHBoxLayout()
        count_layout.addWidget(QLabel("Number of Serials:"))
        self.batch_count = QSpinBox()
        self.batch_count.setRange(1, 10000)
        self.batch_count.setValue(100)
        count_layout.addWidget(self.batch_count)

        count_layout.addWidget(QLabel("Prefix:"))
        self.batch_prefix = QLineEdit()
        count_layout.addWidget(self.batch_prefix)

        count_layout.addWidget(QLabel("Suffix:"))
        self.batch_suffix = QLineEdit()
        count_layout.addWidget(self.batch_suffix)

        count_layout.addStretch()
        settings_layout.addLayout(count_layout)

        # Uniqueness
        unique_layout = QHBoxLayout()
        self.ensure_unique = QCheckBox("Ensure Uniqueness")
        self.ensure_unique.setChecked(True)
        unique_layout.addWidget(self.ensure_unique)

        self.sequential = QCheckBox("Sequential")
        unique_layout.addWidget(self.sequential)

        unique_layout.addStretch()
        settings_layout.addLayout(unique_layout)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # Generation controls
        control_layout = QHBoxLayout()
        self.btn_generate_batch = QPushButton("Generate Batch")
        self.btn_generate_batch.clicked.connect(self.generate_batch_serials)
        control_layout.addWidget(self.btn_generate_batch)

        self.btn_export_batch = QPushButton("Export to File")
        self.btn_export_batch.clicked.connect(self.export_batch)
        self.btn_export_batch.setEnabled(False)
        control_layout.addWidget(self.btn_export_batch)

        self.btn_clear_batch = QPushButton("Clear Results")
        self.btn_clear_batch.clicked.connect(self.clear_batch)
        control_layout.addWidget(self.btn_clear_batch)

        control_layout.addStretch()
        layout.addLayout(control_layout)

        # Batch output
        output_group = QGroupBox("Generated Serials")
        output_layout = QVBoxLayout()

        self.batch_output = QPlainTextEdit()
        self.batch_output.setFont(QFont("Consolas", 10))
        self.batch_output.setReadOnly(True)
        output_layout.addWidget(self.batch_output)

        # Statistics
        self.batch_stats = QLabel("No serials generated")
        output_layout.addWidget(self.batch_stats)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        widget.setLayout(layout)
        return widget

    def create_validation_tab(self):
        """Create serial validation tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Validation input
        input_group = QGroupBox("Serial Validation")
        input_layout = QVBoxLayout()

        serial_layout = QHBoxLayout()
        serial_layout.addWidget(QLabel("Serial Number:"))
        self.validation_input = QLineEdit()
        self.validation_input.setFont(QFont("Consolas", 12))
        serial_layout.addWidget(self.validation_input)
        input_layout.addLayout(serial_layout)

        # Validation method
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Validation Method:"))
        self.validation_method = QComboBox()
        self.validation_method.addItems(["Auto-detect", "Luhn", "Verhoeff", "Damm", "CRC32", "Mod97", "Custom Pattern"])
        method_layout.addWidget(self.validation_method)

        self.btn_validate = QPushButton("Validate")
        self.btn_validate.clicked.connect(self.validate_serial)
        method_layout.addWidget(self.btn_validate)

        method_layout.addStretch()
        input_layout.addLayout(method_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # Validation results
        results_group = QGroupBox("Validation Results")
        results_layout = QVBoxLayout()

        self.validation_output = QTextEdit()
        self.validation_output.setReadOnly(True)
        self.validation_output.setFont(QFont("Consolas", 10))
        results_layout.addWidget(self.validation_output)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        # Batch validation
        batch_group = QGroupBox("Batch Validation")
        batch_layout = QVBoxLayout()

        batch_btn_layout = QHBoxLayout()
        self.btn_load_validation_batch = QPushButton("Load Serials from File")
        self.btn_load_validation_batch.clicked.connect(self.load_validation_batch)
        batch_btn_layout.addWidget(self.btn_load_validation_batch)

        self.btn_validate_batch = QPushButton("Validate All")
        self.btn_validate_batch.clicked.connect(self.validate_batch)
        self.btn_validate_batch.setEnabled(False)
        batch_btn_layout.addWidget(self.btn_validate_batch)

        batch_btn_layout.addStretch()
        batch_layout.addLayout(batch_btn_layout)

        self.batch_validation_input = QPlainTextEdit()
        self.batch_validation_input.setMaximumHeight(150)
        self.batch_validation_input.setToolTip("Paste serials here or load from file")
        self.batch_validation_input.setFont(QFont("Consolas", 9))
        batch_layout.addWidget(self.batch_validation_input)

        batch_group.setLayout(batch_layout)
        layout.addWidget(batch_group)

        widget.setLayout(layout)
        return widget

    def create_patterns_tab(self):
        """Create pattern library tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Known patterns
        patterns_group = QGroupBox("Known Serial Patterns")
        patterns_layout = QVBoxLayout()

        self.patterns_table = QTableWidget(0, 4)
        self.patterns_table.setHorizontalHeaderLabels(["Software", "Format", "Length", "Algorithm"])
        self.patterns_table.horizontalHeader().setStretchLastSection(True)
        self.patterns_table.setAlternatingRowColors(True)

        # Add known patterns
        known_patterns = [
            ("Microsoft Windows", "MICROSOFT", "25", "Mod7 + Digital Signature"),
            ("Microsoft Office", "MICROSOFT", "25", "Polynomial + Checksum"),
            ("VMware Workstation", "ALPHANUMERIC", "20", "RSA Signature"),
            ("WinRAR", "NUMERIC", "10", "Custom Algorithm"),
            ("Sublime Text", "HEXADECIMAL", "32", "SHA256 Based"),
            ("JetBrains IDEs", "BASE32", "20", "ECDSA Signature"),
            ("Autodesk Products", "ALPHANUMERIC", "16", "Luhn Checksum"),
            ("MATLAB", "NUMERIC", "20", "Custom Polynomial"),
            ("SolidWorks", "ALPHANUMERIC", "24", "CRC16 + Date Lock"),
        ]

        for software, format_type, length, algorithm in known_patterns:
            row = self.patterns_table.rowCount()
            self.patterns_table.insertRow(row)
            self.patterns_table.setItem(row, 0, QTableWidgetItem(software))
            self.patterns_table.setItem(row, 1, QTableWidgetItem(format_type))
            self.patterns_table.setItem(row, 2, QTableWidgetItem(length))
            self.patterns_table.setItem(row, 3, QTableWidgetItem(algorithm))

        patterns_layout.addWidget(self.patterns_table)

        # Pattern actions
        action_layout = QHBoxLayout()
        self.btn_use_pattern = QPushButton("Use Selected Pattern")
        self.btn_use_pattern.clicked.connect(self.use_selected_pattern)
        action_layout.addWidget(self.btn_use_pattern)

        self.btn_export_patterns = QPushButton("Export Patterns")
        self.btn_export_patterns.clicked.connect(self.export_patterns)
        action_layout.addWidget(self.btn_export_patterns)

        self.btn_import_patterns = QPushButton("Import Patterns")
        self.btn_import_patterns.clicked.connect(self.import_patterns)
        action_layout.addWidget(self.btn_import_patterns)

        action_layout.addStretch()
        patterns_layout.addLayout(action_layout)

        patterns_group.setLayout(patterns_layout)
        layout.addWidget(patterns_group)

        # Custom pattern builder
        builder_group = QGroupBox("Pattern Builder")
        builder_layout = QVBoxLayout()

        builder_text = QLabel(
            "Build custom serial patterns using the generation tab settings.\nTest your patterns with sample data before deployment.",
        )
        builder_layout.addWidget(builder_text)

        builder_group.setLayout(builder_layout)
        layout.addWidget(builder_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_presets_tab(self):
        """Create presets management tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Preset list
        presets_group = QGroupBox("Saved Presets")
        presets_layout = QVBoxLayout()

        self.presets_list = QListWidget()
        self.presets_list.itemSelectionChanged.connect(self.on_preset_selected)
        presets_layout.addWidget(self.presets_list)

        # Preset actions
        action_layout = QHBoxLayout()
        self.btn_load_preset = QPushButton("Load Preset")
        self.btn_load_preset.clicked.connect(self.load_preset)
        action_layout.addWidget(self.btn_load_preset)

        self.btn_save_preset = QPushButton("Save Current Settings")
        self.btn_save_preset.clicked.connect(self.save_preset)
        action_layout.addWidget(self.btn_save_preset)

        self.btn_delete_preset = QPushButton("Delete Preset")
        self.btn_delete_preset.clicked.connect(self.delete_preset)
        action_layout.addWidget(self.btn_delete_preset)

        action_layout.addStretch()
        presets_layout.addLayout(action_layout)

        presets_group.setLayout(presets_layout)
        layout.addWidget(presets_group)

        # Preset details
        details_group = QGroupBox("Preset Details")
        details_layout = QVBoxLayout()

        self.preset_details = QTextEdit()
        self.preset_details.setReadOnly(True)
        self.preset_details.setFont(QFont("Consolas", 9))
        details_layout.addWidget(self.preset_details)

        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

        widget.setLayout(layout)
        return widget

    def on_format_changed(self, format_str: str) -> None:
        """Handle format change."""
        if format_str == "custom":
            self.custom_alphabet_widget.setVisible(True)
        else:
            self.custom_alphabet_widget.setVisible(False)

        # Set default values for specific formats
        if format_str == "microsoft":
            self.length_spin.setValue(25)
            self.groups_spin.setValue(5)
        elif format_str == "uuid":
            self.length_spin.setValue(32)
            self.groups_spin.setValue(5)

    def generate_single_serial(self) -> None:
        """Generate a single serial number."""
        try:
            constraints = self.build_constraints()

            self.worker = SerialGeneratorWorker(self.generator, "generate_single", {"constraints": constraints})
            self.worker.progress.connect(self.log)
            self.worker.result.connect(self.handle_worker_result)
            self.worker.error.connect(self.handle_worker_error)
            self.worker.start()
        except Exception as e:
            self.handle_worker_error(str(e))

    def build_constraints(self) -> SerialConstraints:
        """Build constraints from UI settings."""
        format_str = self.format_combo.currentText()
        format_enum = SerialFormat(format_str)

        checksum_algo = None
        if self.enable_checksum.isChecked():
            checksum_algo = self.checksum_combo.currentText()
            if checksum_algo == "none":
                checksum_algo = None

        must_contain = []
        if self.must_contain_input.text():
            must_contain = [s.strip() for s in self.must_contain_input.text().split(",")]

        cannot_contain = []
        if self.cannot_contain_input.text():
            cannot_contain = [s.strip() for s in self.cannot_contain_input.text().split(",")]

        blacklist = []
        if self.blacklist_input.text():
            blacklist = [s.strip() for s in self.blacklist_input.text().split(",")]

        custom_alphabet = None
        if format_enum == SerialFormat.CUSTOM:
            custom_alphabet = self.custom_alphabet_input.text()

        return SerialConstraints(
            length=self.length_spin.value(),
            format=format_enum,
            groups=self.groups_spin.value(),
            group_separator=self.separator_input.text(),
            checksum_algorithm=checksum_algo,
            custom_alphabet=custom_alphabet,
            blacklist_patterns=blacklist,
            must_contain=must_contain,
            cannot_contain=cannot_contain,
        )

    def analyze_serials(self) -> None:
        """Analyze sample serials."""
        text = self.samples_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Warning", "Please enter sample serials")
            return

        serials = [s.strip() for s in text.split("\n") if s.strip()]
        if len(serials) < 2:
            QMessageBox.warning(self, "Warning", "Please provide at least 2 sample serials")
            return

        self.worker = SerialGeneratorWorker(self.generator, "analyze", {"serials": serials})
        self.worker.progress.connect(self.log)
        self.worker.result.connect(self.handle_worker_result)
        self.worker.error.connect(self.handle_worker_error)
        self.worker.start()

    def generate_from_analysis(self) -> None:
        """Generate serials based on analysis."""
        if not self.analyzed_pattern:
            return

        # Build constraints from analyzed pattern
        constraints = SerialConstraints(
            length=self.analyzed_pattern["length"]["most_common"],
            format=self.analyzed_pattern["format"],
            checksum_algorithm=self.analyzed_pattern.get("checksum", {}).get("algorithm"),
        )

        self.worker = SerialGeneratorWorker(self.generator, "generate_batch", {"constraints": constraints, "count": 10})
        self.worker.progress.connect(self.log)
        self.worker.result.connect(self.handle_worker_result)
        self.worker.error.connect(self.handle_worker_error)
        self.worker.start()

    def generate_batch_serials(self) -> None:
        """Generate batch of serials."""
        count = self.batch_count.value()
        constraints = self.build_constraints()

        # Apply prefix/suffix if specified
        prefix = self.batch_prefix.text()
        suffix = self.batch_suffix.text()

        self.worker = SerialGeneratorWorker(
            self.generator,
            "generate_batch",
            {
                "constraints": constraints,
                "count": count,
                "prefix": prefix,
                "suffix": suffix,
                "ensure_unique": self.ensure_unique.isChecked(),
                "sequential": self.sequential.isChecked(),
            },
        )
        self.worker.progress.connect(self.log)
        self.worker.result.connect(self.handle_worker_result)
        self.worker.error.connect(self.handle_worker_error)
        self.worker.start()

    def validate_serial(self) -> None:
        """Validate a serial number."""
        serial = self.validation_input.text().strip()
        if not serial:
            QMessageBox.warning(self, "Warning", "Please enter a serial number")
            return

        method = self.validation_method.currentText()

        # Build constraints if we have them
        constraints = None
        if method != "Auto-detect":
            constraints = SerialConstraints(
                length=len(serial.replace("-", "")),
                format=SerialFormat.ALPHANUMERIC,
                checksum_algorithm=method.lower() if method != "Custom Pattern" else None,
            )

        self.worker = SerialGeneratorWorker(self.generator, "validate", {"serial": serial, "constraints": constraints})
        self.worker.progress.connect(self.log)
        self.worker.result.connect(self.handle_worker_result)
        self.worker.error.connect(self.handle_worker_error)
        self.worker.start()

    def copy_serial(self) -> None:
        """Copy generated serial to clipboard."""
        serial = self.serial_output.text()
        if serial:
            clipboard = QApplication.clipboard()
            clipboard.setText(serial)
            self.log("Serial copied to clipboard")

    def save_serial(self) -> None:
        """Save generated serial to file."""
        serial = self.serial_output.text()
        if not serial:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Serial", f"serial_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "Text Files (*.txt);;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(serial)
                    if self.serial_details.toPlainText():
                        f.write("\n\n" + self.serial_details.toPlainText())
                self.log(f"Serial saved to {file_path}")
            except Exception as e:
                self.handle_worker_error(f"Failed to save: {e}")

    def export_batch(self) -> None:
        """Export batch serials to file."""
        text = self.batch_output.toPlainText()
        if not text:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Serials",
            f"serials_batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;CSV Files (*.csv);;All Files (*.*)",
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(text)
                self.log(f"Batch exported to {file_path}")
            except Exception as e:
                self.handle_worker_error(f"Failed to export: {e}")

    def clear_batch(self) -> None:
        """Clear batch output."""
        self.batch_output.clear()
        self.batch_stats.setText("No serials generated")
        self.generated_serials.clear()
        self.btn_export_batch.setEnabled(False)

    def load_sample_serials(self) -> None:
        """Load sample serials from file."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Sample Serials", "", "Text Files (*.txt);;All Files (*.*)")

        if file_path:
            try:
                with open(file_path) as f:
                    content = f.read()
                self.samples_input.setPlainText(content)
                self.log(f"Loaded samples from {file_path}")
            except Exception as e:
                self.handle_worker_error(f"Failed to load: {e}")

    def load_validation_batch(self) -> None:
        """Load serials for batch validation."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Serials for Validation", "", "Text Files (*.txt);;All Files (*.*)")

        if file_path:
            try:
                with open(file_path) as f:
                    content = f.read()
                self.batch_validation_input.setPlainText(content)
                self.btn_validate_batch.setEnabled(True)
                self.log(f"Loaded validation batch from {file_path}")
            except Exception as e:
                self.handle_worker_error(f"Failed to load: {e}")

    def validate_batch(self) -> None:
        """Validate batch of serials."""
        text = self.batch_validation_input.toPlainText().strip()
        if not text:
            return

        serials = [s.strip() for s in text.split("\n") if s.strip()]

        results = []
        for serial in serials:
            # Simple validation for now
            is_valid = bool(re.match(r"^[A-Z0-9-]+$", serial))
            results.append(f"{serial}: {'VALID' if is_valid else 'INVALID'}")

        self.validation_output.setText("\n".join(results))
        self.log(f"Validated {len(serials)} serials")

    def use_selected_pattern(self) -> None:
        """Use selected pattern from patterns table."""
        current_row = self.patterns_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select a pattern")
            return

        format_str = self.patterns_table.item(current_row, 1).text()
        length_str = self.patterns_table.item(current_row, 2).text()

        # Switch to generation tab
        self.tabs.setCurrentIndex(0)

        # Set format
        for i in range(self.format_combo.count()):
            if self.format_combo.itemText(i).upper() == format_str:
                self.format_combo.setCurrentIndex(i)
                break

        # Set length
        self.length_spin.setValue(int(length_str))

        self.log(f"Applied pattern for {self.patterns_table.item(current_row, 0).text()}")

    def export_patterns(self) -> None:
        """Export patterns to file."""
        patterns = []
        for row in range(self.patterns_table.rowCount()):
            patterns.append(
                {
                    "software": self.patterns_table.item(row, 0).text(),
                    "format": self.patterns_table.item(row, 1).text(),
                    "length": self.patterns_table.item(row, 2).text(),
                    "algorithm": self.patterns_table.item(row, 3).text(),
                },
            )

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Patterns", "serial_patterns.json", "JSON Files (*.json);;All Files (*.*)")

        if file_path:
            try:
                with open(file_path, "w") as f:
                    json.dump(patterns, f, indent=2)
                self.log(f"Patterns exported to {file_path}")
            except Exception as e:
                self.handle_worker_error(f"Failed to export: {e}")

    def import_patterns(self) -> None:
        """Import patterns from file."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Patterns", "", "JSON Files (*.json);;All Files (*.*)")

        if file_path:
            try:
                with open(file_path) as f:
                    patterns = json.load(f)

                # Clear existing patterns
                self.patterns_table.setRowCount(0)

                # Add imported patterns
                for pattern in patterns:
                    row = self.patterns_table.rowCount()
                    self.patterns_table.insertRow(row)
                    self.patterns_table.setItem(row, 0, QTableWidgetItem(pattern["software"]))
                    self.patterns_table.setItem(row, 1, QTableWidgetItem(pattern["format"]))
                    self.patterns_table.setItem(row, 2, QTableWidgetItem(pattern["length"]))
                    self.patterns_table.setItem(row, 3, QTableWidgetItem(pattern["algorithm"]))

                self.log(f"Imported {len(patterns)} patterns")
            except Exception as e:
                self.handle_worker_error(f"Failed to import: {e}")

    def save_preset(self) -> None:
        """Save current settings as preset."""
        from PyQt6.QtWidgets import QInputDialog

        name, ok = QInputDialog.getText(self, "Save Preset", "Preset Name:")
        if ok and name:
            preset = {
                "name": name,
                "format": self.format_combo.currentText(),
                "length": self.length_spin.value(),
                "groups": self.groups_spin.value(),
                "separator": self.separator_input.text(),
                "checksum_enabled": self.enable_checksum.isChecked(),
                "checksum_algorithm": self.checksum_combo.currentText(),
                "custom_alphabet": self.custom_alphabet_input.text(),
                "must_contain": self.must_contain_input.text(),
                "cannot_contain": self.cannot_contain_input.text(),
                "blacklist": self.blacklist_input.text(),
                "created": datetime.now().isoformat(),
            }

            # Save to file
            presets_file = "serial_generator_presets.json"
            presets = {}

            if os.path.exists(presets_file):
                try:
                    with open(presets_file) as f:
                        presets = json.load(f)
                except (FileNotFoundError, json.JSONDecodeError, PermissionError):
                    pass

            presets[name] = preset

            try:
                with open(presets_file, "w") as f:
                    json.dump(presets, f, indent=2)

                self.load_presets()
                self.log(f"Preset '{name}' saved")
            except Exception as e:
                self.handle_worker_error(f"Failed to save preset: {e}")

    def load_preset(self) -> None:
        """Load selected preset."""
        current_item = self.presets_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Warning", "Please select a preset")
            return

        name = current_item.text()

        presets_file = "serial_generator_presets.json"
        if os.path.exists(presets_file):
            try:
                with open(presets_file) as f:
                    presets = json.load(f)

                if name in presets:
                    preset = presets[name]

                    # Apply preset values
                    for i in range(self.format_combo.count()):
                        if self.format_combo.itemText(i) == preset["format"]:
                            self.format_combo.setCurrentIndex(i)
                            break

                    self.length_spin.setValue(preset["length"])
                    self.groups_spin.setValue(preset["groups"])
                    self.separator_input.setText(preset["separator"])
                    self.enable_checksum.setChecked(preset["checksum_enabled"])

                    for i in range(self.checksum_combo.count()):
                        if self.checksum_combo.itemText(i) == preset["checksum_algorithm"]:
                            self.checksum_combo.setCurrentIndex(i)
                            break

                    self.custom_alphabet_input.setText(preset.get("custom_alphabet", ""))
                    self.must_contain_input.setText(preset.get("must_contain", ""))
                    self.cannot_contain_input.setText(preset.get("cannot_contain", ""))
                    self.blacklist_input.setText(preset.get("blacklist", ""))

                    self.log(f"Preset '{name}' loaded")
            except Exception as e:
                self.handle_worker_error(f"Failed to load preset: {e}")

    def delete_preset(self) -> None:
        """Delete selected preset."""
        current_item = self.presets_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Warning", "Please select a preset")
            return

        name = current_item.text()

        reply = QMessageBox.question(
            self, "Confirm Delete", f"Delete preset '{name}'?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            presets_file = "serial_generator_presets.json"
            if os.path.exists(presets_file):
                try:
                    with open(presets_file) as f:
                        presets = json.load(f)

                    if name in presets:
                        del presets[name]

                        with open(presets_file, "w") as f:
                            json.dump(presets, f, indent=2)

                        self.load_presets()
                        self.log(f"Preset '{name}' deleted")
                except Exception as e:
                    self.handle_worker_error(f"Failed to delete preset: {e}")

    def load_presets(self) -> None:
        """Load saved presets."""
        self.presets_list.clear()

        presets_file = "serial_generator_presets.json"
        if os.path.exists(presets_file):
            try:
                with open(presets_file) as f:
                    presets = json.load(f)

                for name in presets:
                    self.presets_list.addItem(name)
            except (AttributeError, KeyError, TypeError):
                pass

    def on_preset_selected(self) -> None:
        """Handle preset selection."""
        current_item = self.presets_list.currentItem()
        if not current_item:
            self.preset_details.clear()
            return

        name = current_item.text()

        presets_file = "serial_generator_presets.json"
        if os.path.exists(presets_file):
            try:
                with open(presets_file) as f:
                    presets = json.load(f)

                if name in presets:
                    preset = presets[name]
                    details = json.dumps(preset, indent=2)
                    self.preset_details.setText(details)
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass

    def handle_worker_result(self, result: dict) -> None:
        """Handle worker thread results."""
        operation = result.get("operation")
        data = result.get("data")

        if operation == "single_serial":
            serial = data
            self.serial_output.setText(serial.serial)

            details = f"""Format: {serial.format.value}
Algorithm: {serial.algorithm_used}
Confidence: {serial.confidence:.1%}
Validation: {json.dumps(serial.validation_data, indent=2)}"""

            self.serial_details.setText(details)
            self.btn_copy.setEnabled(True)
            self.btn_save.setEnabled(True)
            self.log(f"Generated serial: {serial.serial}")

        elif operation == "analysis":
            self.analyzed_pattern = data

            output = f"""Serial Pattern Analysis:
=====================================
Format: {data["format"].value if data["format"] else "Unknown"}
Length: {data["length"]}
Structure: {json.dumps(data["structure"], indent=2)}
Checksum: {json.dumps(data["checksum"], indent=2)}
Patterns: {json.dumps(data["patterns"], indent=2)}
Confidence: {data["confidence"]:.1%}
"""
            self.analysis_output.setText(output)
            self.btn_generate_from_analysis.setEnabled(True)
            self.log("Serial pattern analysis complete")

        elif operation == "batch_serials":
            serials = data
            self.generated_serials = serials

            output = []
            for i, serial in enumerate(serials, 1):
                output.append(f"{i:04d}: {serial.serial}")

            self.batch_output.setPlainText("\n".join(output))
            self.batch_stats.setText(f"Generated {len(serials)} unique serials")
            self.btn_export_batch.setEnabled(True)
            self.log(f"Generated {len(serials)} serials")

        elif operation == "validation":
            serial = data["serial"]
            is_valid = data["is_valid"]
            details = data["details"]

            output = f"""Serial Validation Result:
=====================================
Serial: {serial}
Valid: {"YES" if is_valid else "NO"}

Details:
{json.dumps(details, indent=2)}
"""
            self.validation_output.setText(output)
            self.log(f"Validation result: {is_valid}")

        elif operation == "pattern_crack":
            analysis = data["analysis"]
            test_serials = data["generated_serials"]

            output = f"""Pattern Cracking Results:
=====================================
Detected Format: {analysis["format"].value if analysis["format"] else "Unknown"}
Algorithm: {analysis.get("algorithm", "Unknown")}
Confidence: {analysis["confidence"]:.1%}

Generated Test Serials:
"""
            for serial in test_serials:
                output += f"\n  {serial.serial}"

            self.analysis_output.setText(output)
            self.log("Pattern cracking complete")

    def handle_worker_error(self, error: str) -> None:
        """Handle worker thread errors."""
        self.log(f"Error: {error}")
        QMessageBox.critical(self, "Error", error)

    def log(self, message: str) -> None:
        """Log message to console."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {message}")

        # Auto-scroll to bottom
        scrollbar = self.console.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())


if __name__ == "__main__":
    import sys

    from PyQt6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    dialog = SerialGeneratorDialog()
    dialog.show()
    sys.exit(app.exec())
