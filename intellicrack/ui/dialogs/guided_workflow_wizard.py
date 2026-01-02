"""Guided workflow wizard for step-by-step analysis assistance.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import datetime
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QIcon,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPixmap,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QSpinBox,
    Qt,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)
from intellicrack.utils.logger import logger
from intellicrack.utils.resource_helper import get_resource_path


if TYPE_CHECKING:
    from typing import Protocol

    class ParentWidget(Protocol):
        binary_path: str

        def update_output(self) -> Any: ...
        def load_binary(self, path: str) -> None: ...
        def run_static_analysis(self) -> None: ...
        def run_dynamic_analysis(self) -> None: ...
        def switch_tab(self) -> Any: ...


"""
Guided Workflow Wizard

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


try:
    from intellicrack.handlers.pefile_handler import pefile

    HAS_PEFILE = True
except ImportError as e:
    logger.error("Import error in guided_workflow_wizard: %s", e)
    HAS_PEFILE = False

__all__ = ["GuidedWorkflowWizard"]


class GuidedWorkflowWizard(QWizard):
    """Guided workflow wizard for new users.

    Provides a step-by-step interface for configuring and starting
    binary analysis and patching operations.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the guided workflow wizard.

        Args:
            parent: Parent widget (typically the main application).

        """
        super().__init__(parent)
        self._parent_widget: QWidget | None = parent
        self.summary_text: QTextEdit

        # Set up wizard properties
        self.setWindowTitle("Intellicrack Guided Workflow")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)

        icon_path = get_resource_path("assets/icon.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # Set minimum size
        self.setMinimumSize(800, 600)

        # Add wizard pages
        self.addPage(self.create_intro_page())
        self.addPage(self.create_file_selection_page())
        self.addPage(self.create_protection_detection_page())
        self.addPage(self.create_analysis_options_page())
        self.addPage(self.create_advanced_analysis_page())
        self.addPage(self.create_vulnerability_options_page())
        self.addPage(self.create_patching_options_page())
        self.addPage(self.create_network_options_page())
        self.addPage(self.create_ai_options_page())
        self.addPage(self.create_conclusion_page())

        # Connect signals
        self.finished.connect(self.on_finished)

    def create_intro_page(self) -> QWizardPage:
        """Create the introduction page.

        Returns:
            Introduction wizard page with welcome text and image.

        """
        page = QWizardPage()
        page.setTitle("Welcome to Intellicrack")
        page.setSubTitle("This wizard will guide you through analyzing and patching your first binary")

        layout = QVBoxLayout()

        # Add introduction text
        intro_text = QLabel(
            "Intellicrack helps you analyze and patch software protection and licensing mechanisms. "
            "This guided workflow will walk you through the basic steps:\n\n"
            "1. Selecting a binary file to analyze\n"
            "2. Configuring analysis options\n"
            "3. Reviewing analysis results\n"
            "4. Creating and applying patches\n\n"
            "You can cancel this wizard at any time and use the application manually.",
        )
        intro_text.setWordWrap(True)
        layout.addWidget(intro_text)

        # Add image if available
        splash_path = get_resource_path("assets/splash.png")
        if os.path.exists(splash_path):
            image_label = QLabel()
            pixmap = QPixmap(splash_path).scaled(
                400,
                300,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            image_label.setPixmap(pixmap)
            image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(image_label)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        page.setLayout(layout)
        return page

    def create_file_selection_page(self) -> QWizardPage:
        """Create the file selection page.

        Returns:
            File selection wizard page for choosing a binary to analyze.

        """
        page = QWizardPage()
        page.setTitle("Select Binary File")
        page.setSubTitle("Choose the executable file you want to analyze")

        layout = QVBoxLayout()

        # File selection widgets
        file_group = QGroupBox("Binary File")
        file_layout = QVBoxLayout()

        # File path widgets
        path_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setText("No binary selected")
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setToolTip("Path to the binary file for analysis")

        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_file)

        path_layout.addWidget(self.file_path_edit)
        path_layout.addWidget(browse_button)
        file_layout.addLayout(path_layout)

        # File info widgets
        self.file_info_label = QLabel("No file selected")
        self.file_info_label.setWordWrap(True)
        file_layout.addWidget(self.file_info_label)

        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # Add explanation
        hint_label = QLabel(
            "Tip: For best results, select an executable file that has licensing or protection mechanisms. "
            "Common examples include software trials, licensed applications, or games with anti-piracy protections.",
        )
        hint_label.setWordWrap(True)
        hint_label.setStyleSheet("font-style: italic; color: #666;")
        layout.addWidget(hint_label)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Register fields
        page.registerField("binary_path*", self.file_path_edit)

        page.setLayout(layout)
        return page

    def create_protection_detection_page(self) -> QWizardPage:
        """Create the protection detection page.

        Returns:
            Protection detection wizard page for selecting which protection mechanisms to detect.

        """
        page = QWizardPage()
        page.setTitle("Protection Detection")
        page.setSubTitle("Select which protection mechanisms to detect in the binary")

        layout = QVBoxLayout()

        # Protection detection options
        protection_group = QGroupBox("Protection Types to Detect")
        protection_layout = QVBoxLayout()

        self.detect_commercial_cb = QCheckBox("Commercial Protections (VMProtect, Themida, etc.)")
        self.detect_commercial_cb.setChecked(True)

        self.detect_packing_cb = QCheckBox("Packing/Obfuscation")
        self.detect_packing_cb.setChecked(True)

        self.detect_dongle_cb = QCheckBox("Hardware Dongles")
        self.detect_dongle_cb.setChecked(True)

        self.detect_tpm_cb = QCheckBox("TPM Protection")

        self.detect_network_cb = QCheckBox("Network License Verification")
        self.detect_network_cb.setChecked(True)

        self.detect_antidebug_cb = QCheckBox("Anti-debugging Techniques")
        self.detect_antidebug_cb.setChecked(True)

        self.detect_checksum_cb = QCheckBox("Checksum/Integrity Checks")

        self.detect_time_cb = QCheckBox("Time-based Limitations")
        self.detect_time_cb.setChecked(True)

        protection_layout.addWidget(self.detect_commercial_cb)
        protection_layout.addWidget(self.detect_packing_cb)
        protection_layout.addWidget(self.detect_dongle_cb)
        protection_layout.addWidget(self.detect_tpm_cb)
        protection_layout.addWidget(self.detect_network_cb)
        protection_layout.addWidget(self.detect_antidebug_cb)
        protection_layout.addWidget(self.detect_checksum_cb)
        protection_layout.addWidget(self.detect_time_cb)

        protection_group.setLayout(protection_layout)
        layout.addWidget(protection_group)

        # Add hint
        hint_label = QLabel(
            "Tip: Detecting protections first helps optimize the analysis and patching strategies. "
            "More protections detected means a more thorough but slower analysis.",
        )
        hint_label.setWordWrap(True)
        hint_label.setStyleSheet("font-style: italic; color: #666;")
        layout.addWidget(hint_label)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Register fields
        page.registerField("detect_commercial", self.detect_commercial_cb)
        page.registerField("detect_packing", self.detect_packing_cb)
        page.registerField("detect_dongle", self.detect_dongle_cb)
        page.registerField("detect_tpm", self.detect_tpm_cb)
        page.registerField("detect_network", self.detect_network_cb)
        page.registerField("detect_antidebug", self.detect_antidebug_cb)
        page.registerField("detect_checksum", self.detect_checksum_cb)
        page.registerField("detect_time", self.detect_time_cb)

        page.setLayout(layout)
        return page

    def create_analysis_options_page(self) -> QWizardPage:
        """Create the analysis options page.

        Returns:
            Analysis options wizard page for configuring analysis types and parameters.

        """
        page = QWizardPage()
        page.setTitle("Analysis Options")
        page.setSubTitle("Configure how you want to analyze the selected binary")

        layout = QVBoxLayout()

        # Analysis options
        options_group = QGroupBox("Analysis Types")
        options_layout = QVBoxLayout()

        self.static_analysis_cb = QCheckBox("Static Analysis")
        self.static_analysis_cb.setChecked(True)
        self.static_analysis_cb.setToolTip("Analyze the binary without executing it")

        self.dynamic_analysis_cb = QCheckBox("Dynamic Analysis")
        self.dynamic_analysis_cb.setChecked(True)
        self.dynamic_analysis_cb.setToolTip("Analyze the binary during execution")

        self.symbolic_execution_cb = QCheckBox("Symbolic Execution")
        self.symbolic_execution_cb.setToolTip("Use symbolic execution to explore multiple code paths")

        self.ml_analysis_cb = QCheckBox("ML-assisted Analysis")
        self.ml_analysis_cb.setToolTip("Use machine learning to identify potential vulnerabilities")

        options_layout.addWidget(self.static_analysis_cb)
        options_layout.addWidget(self.dynamic_analysis_cb)
        options_layout.addWidget(self.symbolic_execution_cb)
        options_layout.addWidget(self.ml_analysis_cb)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Advanced options
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QFormLayout()

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 3600)
        self.timeout_spin.setValue(300)
        self.timeout_spin.setSuffix(" seconds")
        advanced_layout.addRow("Analysis Timeout:", self.timeout_spin)

        self.detect_protections_cb = QCheckBox("Detect Protections")
        self.detect_protections_cb.setChecked(True)
        advanced_layout.addRow("", self.detect_protections_cb)

        self.detect_vm_cb = QCheckBox("Detect VM/Debugging Evasions")
        self.detect_vm_cb.setChecked(True)
        advanced_layout.addRow("", self.detect_vm_cb)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Register fields
        page.registerField("static_analysis", self.static_analysis_cb)
        page.registerField("dynamic_analysis", self.dynamic_analysis_cb)
        page.registerField("symbolic_execution", self.symbolic_execution_cb)
        page.registerField("ml_analysis", self.ml_analysis_cb)
        page.registerField("timeout", self.timeout_spin)
        page.registerField("detect_protections", self.detect_protections_cb)
        page.registerField("detect_vm", self.detect_vm_cb)

        page.setLayout(layout)
        return page

    def create_patching_options_page(self) -> QWizardPage:
        """Create the patching options page.

        Returns:
            Patching options wizard page for configuring patch methods and targets.

        """
        page = QWizardPage()
        page.setTitle("Patching Options")
        page.setSubTitle("Configure how you want to patch the binary")

        layout = QVBoxLayout()

        # Patching options
        patching_group = QGroupBox("Patching Types")
        patching_layout = QVBoxLayout()

        self.auto_patch_cb = QCheckBox("Automatic Patching")
        self.auto_patch_cb.setChecked(True)
        self.auto_patch_cb.setToolTip("Attempt to automatically generate patches")

        self.interactive_patch_cb = QCheckBox("Interactive Patching")
        self.interactive_patch_cb.setToolTip("Interactively create and apply patches with guidance")

        self.function_hooking_cb = QCheckBox("Function Hooking")
        self.function_hooking_cb.setToolTip("Hook functions at runtime to modify behavior")

        self.memory_patching_cb = QCheckBox("Memory Patching")
        self.memory_patching_cb.setChecked(True)
        self.memory_patching_cb.setToolTip("Patch memory during execution")

        patching_layout.addWidget(self.auto_patch_cb)
        patching_layout.addWidget(self.interactive_patch_cb)
        patching_layout.addWidget(self.function_hooking_cb)
        patching_layout.addWidget(self.memory_patching_cb)

        patching_group.setLayout(patching_layout)
        layout.addWidget(patching_group)

        # Patch targets
        targets_group = QGroupBox("Patch Targets")
        targets_layout = QVBoxLayout()

        self.license_check_cb = QCheckBox("License Validation")
        self.license_check_cb.setChecked(True)

        self.time_limit_cb = QCheckBox("Time Limitations")
        self.time_limit_cb.setChecked(True)

        self.feature_unlock_cb = QCheckBox("Feature Unlocking")
        self.feature_unlock_cb.setChecked(True)

        self.anti_debug_cb = QCheckBox("Anti-debugging Measures")

        targets_layout.addWidget(self.license_check_cb)
        targets_layout.addWidget(self.time_limit_cb)
        targets_layout.addWidget(self.feature_unlock_cb)
        targets_layout.addWidget(self.anti_debug_cb)

        targets_group.setLayout(targets_layout)
        layout.addWidget(targets_group)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Register fields
        page.registerField("auto_patch", self.auto_patch_cb)
        page.registerField("interactive_patch", self.interactive_patch_cb)
        page.registerField("function_hooking", self.function_hooking_cb)
        page.registerField("memory_patching", self.memory_patching_cb)
        page.registerField("license_check", self.license_check_cb)
        page.registerField("time_limit", self.time_limit_cb)
        page.registerField("feature_unlock", self.feature_unlock_cb)
        page.registerField("anti_debug", self.anti_debug_cb)

        page.setLayout(layout)
        return page

    def create_advanced_analysis_page(self) -> QWizardPage:
        """Create the advanced analysis options page.

        Returns:
            Advanced analysis wizard page for configuring advanced analysis techniques.

        """
        page = QWizardPage()
        page.setTitle("Advanced Analysis")
        page.setSubTitle("Configure advanced analysis techniques")

        layout = QVBoxLayout()

        # Advanced analysis options
        advanced_group = QGroupBox("Advanced Analysis Techniques")
        advanced_layout = QVBoxLayout()

        self.cfg_analysis_cb = QCheckBox("Control Flow Graph Analysis")
        self.cfg_analysis_cb.setChecked(True)
        self.cfg_analysis_cb.setToolTip("Analyze program control flow structure")

        self.taint_analysis_cb = QCheckBox("Taint Analysis")
        self.taint_analysis_cb.setToolTip("Track data flow from sources to sinks")

        self.concolic_execution_cb = QCheckBox("Concolic Execution")
        self.concolic_execution_cb.setToolTip("Combined concrete and symbolic execution")

        self.rop_gadgets_cb = QCheckBox("ROP Gadget Search")
        self.rop_gadgets_cb.setToolTip("Find Return-Oriented Programming gadgets")

        self.binary_similarity_cb = QCheckBox("Binary Similarity Search")
        self.binary_similarity_cb.setToolTip("Find similar code patterns in database")

        self.section_analysis_cb = QCheckBox("Section Analysis (Entropy, Permissions)")
        self.section_analysis_cb.setToolTip("Analyze binary sections for anomalies")

        self.import_export_cb = QCheckBox("Import/Export Table Analysis")
        self.import_export_cb.setChecked(True)
        self.import_export_cb.setToolTip("Analyze imported and exported functions")

        advanced_layout.addWidget(self.cfg_analysis_cb)
        advanced_layout.addWidget(self.taint_analysis_cb)
        advanced_layout.addWidget(self.concolic_execution_cb)
        advanced_layout.addWidget(self.rop_gadgets_cb)
        advanced_layout.addWidget(self.binary_similarity_cb)
        advanced_layout.addWidget(self.section_analysis_cb)
        advanced_layout.addWidget(self.import_export_cb)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        # External tools
        tools_group = QGroupBox("External Tool Integration")
        tools_layout = QVBoxLayout()

        self.ghidra_analysis_cb = QCheckBox("Ghidra Headless Analysis")
        self.ghidra_analysis_cb.setToolTip("Use Ghidra for advanced decompilation")

        self.radare2_analysis_cb = QCheckBox("Radare2 Analysis")
        self.radare2_analysis_cb.setToolTip("Use Radare2 for disassembly")

        tools_layout.addWidget(self.ghidra_analysis_cb)
        tools_layout.addWidget(self.radare2_analysis_cb)

        tools_group.setLayout(tools_layout)
        layout.addWidget(tools_group)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Register fields
        page.registerField("cfg_analysis", self.cfg_analysis_cb)
        page.registerField("taint_analysis", self.taint_analysis_cb)
        page.registerField("concolic_execution", self.concolic_execution_cb)
        page.registerField("rop_gadgets", self.rop_gadgets_cb)
        page.registerField("binary_similarity", self.binary_similarity_cb)
        page.registerField("section_analysis", self.section_analysis_cb)
        page.registerField("import_export", self.import_export_cb)
        page.registerField("ghidra_analysis", self.ghidra_analysis_cb)
        page.registerField("radare2_analysis", self.radare2_analysis_cb)

        page.setLayout(layout)
        return page

    def create_vulnerability_options_page(self) -> QWizardPage:
        """Create the vulnerability detection page.

        Returns:
            Vulnerability detection wizard page for configuring vulnerability scanning options.

        """
        page = QWizardPage()
        page.setTitle("Vulnerability Detection")
        page.setSubTitle("Configure vulnerability detection options")

        layout = QVBoxLayout()

        # Vulnerability detection
        vuln_group = QGroupBox("Vulnerability Detection Methods")
        vuln_layout = QVBoxLayout()

        self.static_vuln_scan_cb = QCheckBox("Advanced Static Vulnerability Scan")
        self.static_vuln_scan_cb.setChecked(True)

        self.ml_vuln_prediction_cb = QCheckBox("ML-Based Vulnerability Prediction")
        self.ml_vuln_prediction_cb.setToolTip("Use machine learning models to predict vulnerabilities")

        self.buffer_overflow_cb = QCheckBox("Buffer Overflow Detection")
        self.buffer_overflow_cb.setChecked(True)

        self.format_string_cb = QCheckBox("Format String Vulnerability Detection")

        self.race_condition_cb = QCheckBox("Race Condition Detection")

        vuln_layout.addWidget(self.static_vuln_scan_cb)
        vuln_layout.addWidget(self.ml_vuln_prediction_cb)
        vuln_layout.addWidget(self.buffer_overflow_cb)
        vuln_layout.addWidget(self.format_string_cb)
        vuln_layout.addWidget(self.race_condition_cb)

        vuln_group.setLayout(vuln_layout)
        layout.addWidget(vuln_group)

        # Exploitation options
        exploit_group = QGroupBox("Exploitation Options")
        exploit_layout = QVBoxLayout()

        self.generate_exploits_cb = QCheckBox("Generate Proof-of-Concept Exploits")
        self.rop_chain_cb = QCheckBox("Generate ROP Chains")
        self.shellcode_cb = QCheckBox("Generate Shellcode")

        exploit_layout.addWidget(self.generate_exploits_cb)
        exploit_layout.addWidget(self.rop_chain_cb)
        exploit_layout.addWidget(self.shellcode_cb)

        exploit_group.setLayout(exploit_layout)
        layout.addWidget(exploit_group)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Register fields
        page.registerField("static_vuln_scan", self.static_vuln_scan_cb)
        page.registerField("ml_vuln_prediction", self.ml_vuln_prediction_cb)
        page.registerField("buffer_overflow", self.buffer_overflow_cb)
        page.registerField("format_string", self.format_string_cb)
        page.registerField("race_condition", self.race_condition_cb)
        page.registerField("generate_exploits", self.generate_exploits_cb)
        page.registerField("rop_chain", self.rop_chain_cb)
        page.registerField("shellcode", self.shellcode_cb)

        page.setLayout(layout)
        return page

    def create_network_options_page(self) -> QWizardPage:
        """Create the network analysis options page.

        Returns:
            Network analysis wizard page for configuring network monitoring options.

        """
        page = QWizardPage()
        page.setTitle("Network Analysis")
        page.setSubTitle("Configure network analysis and monitoring options")

        layout = QVBoxLayout()

        # Network analysis options
        network_group = QGroupBox("Network Analysis")
        network_layout = QVBoxLayout()

        self.traffic_capture_cb = QCheckBox("Capture Network Traffic")
        self.traffic_capture_cb.setChecked(True)
        self.traffic_capture_cb.setToolTip("Monitor network communications during execution")

        self.protocol_fingerprint_cb = QCheckBox("Protocol Fingerprinting")
        self.protocol_fingerprint_cb.setToolTip("Identify license verification protocols")

        self.ssl_intercept_cb = QCheckBox("SSL/TLS Interception")
        self.ssl_intercept_cb.setToolTip("Decrypt and analyze HTTPS traffic")

        self.license_server_emulate_cb = QCheckBox("License Server Emulation")
        self.license_server_emulate_cb.setToolTip("Emulate license server responses")

        self.cloud_license_hook_cb = QCheckBox("Cloud License Hooking")
        self.cloud_license_hook_cb.setToolTip("Intercept cloud-based license checks")

        network_layout.addWidget(self.traffic_capture_cb)
        network_layout.addWidget(self.protocol_fingerprint_cb)
        network_layout.addWidget(self.ssl_intercept_cb)
        network_layout.addWidget(self.license_server_emulate_cb)
        network_layout.addWidget(self.cloud_license_hook_cb)

        network_group.setLayout(network_layout)
        layout.addWidget(network_group)

        # Add hint
        hint_label = QLabel(
            "Tip: Network analysis is crucial for software that uses online license verification. "
            "Enable SSL interception if the software uses HTTPS for license checks.",
        )
        hint_label.setWordWrap(True)
        hint_label.setStyleSheet("font-style: italic; color: #666;")
        layout.addWidget(hint_label)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Register fields
        page.registerField("traffic_capture", self.traffic_capture_cb)
        page.registerField("protocol_fingerprint", self.protocol_fingerprint_cb)
        page.registerField("ssl_intercept", self.ssl_intercept_cb)
        page.registerField("license_server_emulate", self.license_server_emulate_cb)
        page.registerField("cloud_license_hook", self.cloud_license_hook_cb)

        page.setLayout(layout)
        return page

    def create_ai_options_page(self) -> QWizardPage:
        """Create the AI/ML options page.

        Returns:
            AI and machine learning wizard page for configuring AI-powered features.

        """
        page = QWizardPage()
        page.setTitle("AI & Machine Learning")
        page.setSubTitle("Configure AI-powered analysis and automation features")

        layout = QVBoxLayout()

        # AI options
        ai_group = QGroupBox("AI-Powered Features")
        ai_layout = QVBoxLayout()

        self.ai_comprehensive_cb = QCheckBox("Comprehensive AI Analysis")
        self.ai_comprehensive_cb.setChecked(True)
        self.ai_comprehensive_cb.setToolTip("Use AI to analyze all aspects of the binary")

        self.ai_patch_suggest_cb = QCheckBox("AI Patch Suggestions")
        self.ai_patch_suggest_cb.setChecked(True)
        self.ai_patch_suggest_cb.setToolTip("Let AI suggest optimal patching strategies")

        self.ai_code_explain_cb = QCheckBox("AI Code Explanation")
        self.ai_code_explain_cb.setToolTip("Use AI to explain complex code sections")

        self.ml_pattern_learn_cb = QCheckBox("ML Pattern Learning")
        self.ml_pattern_learn_cb.setToolTip("Learn from analysis to improve future results")

        self.ai_assisted_mode_cb = QCheckBox("AI-Assisted Mode")
        self.ai_assisted_mode_cb.setToolTip("Let AI analyze and suggest patches for review")

        ai_layout.addWidget(self.ai_comprehensive_cb)
        ai_layout.addWidget(self.ai_patch_suggest_cb)
        ai_layout.addWidget(self.ai_code_explain_cb)
        ai_layout.addWidget(self.ml_pattern_learn_cb)
        ai_layout.addWidget(self.ai_assisted_mode_cb)

        ai_group.setLayout(ai_layout)
        layout.addWidget(ai_group)

        # Processing options
        processing_group = QGroupBox("Processing Options")
        processing_layout = QVBoxLayout()

        self.distributed_processing_cb = QCheckBox("Enable Distributed Processing")
        self.distributed_processing_cb.setToolTip("Use multiple cores/machines for faster analysis")

        self.gpu_acceleration_cb = QCheckBox("Enable GPU Acceleration")
        self.gpu_acceleration_cb.setToolTip("Use GPU for ML and analysis acceleration")

        processing_layout.addWidget(self.distributed_processing_cb)
        processing_layout.addWidget(self.gpu_acceleration_cb)

        processing_group.setLayout(processing_layout)
        layout.addWidget(processing_group)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Register fields
        page.registerField("ai_comprehensive", self.ai_comprehensive_cb)
        page.registerField("ai_patch_suggest", self.ai_patch_suggest_cb)
        page.registerField("ai_code_explain", self.ai_code_explain_cb)
        page.registerField("ml_pattern_learn", self.ml_pattern_learn_cb)
        page.registerField("ai_assisted_mode", self.ai_assisted_mode_cb)
        page.registerField("distributed_processing", self.distributed_processing_cb)
        page.registerField("gpu_acceleration", self.gpu_acceleration_cb)

        page.setLayout(layout)
        return page

    def create_conclusion_page(self) -> QWizardPage:
        """Create the conclusion page.

        Returns:
            Conclusion wizard page displaying summary of selections.

        """

        class ConclusionPage(QWizardPage):
            """Wizard page that displays the final summary of all user selections.

            This page shows a comprehensive summary of protection detection options,
            analysis configurations, patching settings, and AI features that the user
            has selected through the wizard workflow. It serves as a final review
            before executing the analysis and patching operations.
            """

            def __init__(self, wizard: GuidedWorkflowWizard) -> None:
                """Initialize the conclusion page.

                Args:
                    wizard: The parent wizard instance containing configuration.

                """
                super().__init__()
                self._wizard = wizard
                self.setTitle("Ready to Start")
                self.setSubTitle("Your workflow has been configured and is ready to start")

                layout = QVBoxLayout()

                summary_label = QLabel("Summary of your selections:")
                layout.addWidget(summary_label)

                wizard.summary_text = QTextEdit()
                wizard.summary_text.setReadOnly(True)
                layout.addWidget(wizard.summary_text)

                instructions_label = QLabel(
                    "Click 'Finish' to begin analyzing and patching the selected binary. "
                    "The application will guide you through the rest of the process and "
                    "show you the results of each step.",
                )
                instructions_label.setWordWrap(True)
                layout.addWidget(instructions_label)

                self.setLayout(layout)

            def initializePage(self) -> None:
                """Initialize the page when it becomes active.

                Updates the summary text widget with current user selections from all
                previous wizard pages, including protection detection options, analysis
                settings, patching configurations, network options, and AI features.

                """
                self._wizard.update_summary()

        return ConclusionPage(self)

    def _build_protection_section(self) -> str:
        """Build the Protection Detection section for the summary display.

        Constructs an HTML list of protection mechanisms selected by the user,
        including commercial protections, packing/obfuscation, hardware dongles,
        TPM protection, network license verification, anti-debugging techniques,
        checksum/integrity checks, and time-based limitations.

        Returns:
            HTML string containing protection detection selections formatted as
            an HTML unordered list with section heading.

        """
        protection_fields = [
            ("detect_commercial", "Commercial Protections"),
            ("detect_packing", "Packing/Obfuscation"),
            ("detect_dongle", "Hardware Dongles"),
            ("detect_tpm", "TPM Protection"),
            ("detect_network", "Network License Verification"),
            ("detect_antidebug", "Anti-debugging Techniques"),
            ("detect_checksum", "Checksum/Integrity Checks"),
            ("detect_time", "Time-based Limitations"),
        ]

        if items := [f"<li>{display_name}</li>\n" for field_name, display_name in protection_fields if self.field(field_name)]:
            return "<h3>Protection Detection</h3>\n<ul>\n" + "".join(items) + "</ul>\n\n"
        return "<h3>Protection Detection</h3>\n<ul>\n</ul>\n\n"

    def _build_analysis_section(self) -> str:
        """Build the Analysis Options section for the summary display.

        Constructs an HTML list of analysis configurations selected by the user,
        including static analysis, dynamic analysis, symbolic execution, ML-assisted
        analysis, protection detection, VM/debugging evasion detection, and the
        configured analysis timeout value.

        Returns:
            HTML string containing analysis options selections formatted as an HTML
            unordered list with section heading.

        """
        analysis_fields = [
            ("static_analysis", "Static Analysis"),
            ("dynamic_analysis", "Dynamic Analysis"),
            ("symbolic_execution", "Symbolic Execution"),
            ("ml_analysis", "ML-assisted Analysis"),
            ("detect_protections", "Detect Protections"),
            ("detect_vm", "Detect VM/Debugging Evasions"),
        ]

        items = [f"<li>{display_name}</li>\n" for field_name, display_name in analysis_fields if self.field(field_name)]
        # Always add timeout
        items.append(f"<li>Timeout: {self.field('timeout')} seconds</li>\n")

        return "<h3>Analysis Options</h3>\n<ul>\n" + "".join(items) + "</ul>\n\n"

    def _build_advanced_analysis_section(self) -> str:
        """Build the Advanced Analysis section for the summary display.

        Constructs an HTML list of advanced analysis techniques selected by the user,
        including control flow graph analysis, taint analysis, concolic execution,
        ROP gadget search, binary similarity search, section analysis, import/export
        table analysis, Ghidra headless analysis, and Radare2 analysis.

        Returns:
            HTML string containing advanced analysis selections formatted as an HTML
            unordered list with section heading.

        """
        advanced_fields = [
            ("cfg_analysis", "Control Flow Graph Analysis"),
            ("taint_analysis", "Taint Analysis"),
            ("concolic_execution", "Concolic Execution"),
            ("rop_gadgets", "ROP Gadget Search"),
            ("binary_similarity", "Binary Similarity Search"),
            ("section_analysis", "Section Analysis"),
            ("import_export", "Import/Export Table Analysis"),
            ("ghidra_analysis", "Ghidra Headless Analysis"),
            ("radare2_analysis", "Radare2 Analysis"),
        ]

        if items := [f"<li>{display_name}</li>\n" for field_name, display_name in advanced_fields if self.field(field_name)]:
            return "<h3>Advanced Analysis</h3>\n<ul>\n" + "".join(items) + "</ul>\n\n"
        return "<h3>Advanced Analysis</h3>\n<ul>\n</ul>\n\n"

    def _build_vulnerability_section(self) -> str:
        """Build the Vulnerability Detection section for the summary display.

        Constructs an HTML list of vulnerability detection and exploitation options
        selected by the user, including static vulnerability scanning, ML-based
        vulnerability prediction, buffer overflow detection, format string
        vulnerability detection, race condition detection, proof-of-concept exploit
        generation, ROP chain generation, and shellcode generation.

        Returns:
            HTML string containing vulnerability detection selections formatted as
            an HTML unordered list with section heading.

        """
        vuln_fields = [
            ("static_vuln_scan", "Static Vulnerability Scan"),
            ("ml_vuln_prediction", "ML-Based Vulnerability Prediction"),
            ("buffer_overflow", "Buffer Overflow Detection"),
            ("format_string", "Format String Vulnerability Detection"),
            ("race_condition", "Race Condition Detection"),
            ("generate_exploits", "Generate Proof-of-Concept Exploits"),
            ("rop_chain", "Generate ROP Chains"),
            ("shellcode", "Generate Shellcode"),
        ]

        if items := [f"<li>{display_name}</li>\n" for field_name, display_name in vuln_fields if self.field(field_name)]:
            return "<h3>Vulnerability Detection</h3>\n<ul>\n" + "".join(items) + "</ul>\n\n"
        return "<h3>Vulnerability Detection</h3>\n<ul>\n</ul>\n\n"

    def _build_patching_section(self) -> str:
        """Build the Patching Options section for the summary display.

        Constructs an HTML list of patching methods selected by the user,
        including automatic patching, interactive patching, function hooking,
        and memory patching techniques.

        Returns:
            HTML string containing patching options selections formatted as an HTML
            unordered list with section heading.

        """
        patching_fields = [
            ("auto_patch", "Automatic Patching"),
            ("interactive_patch", "Interactive Patching"),
            ("function_hooking", "Function Hooking"),
            ("memory_patching", "Memory Patching"),
        ]

        if items := [f"<li>{display_name}</li>\n" for field_name, display_name in patching_fields if self.field(field_name)]:
            return "<h3>Patching Options</h3>\n<ul>\n" + "".join(items) + "</ul>\n\n"
        return "<h3>Patching Options</h3>\n<ul>\n</ul>\n\n"

    def _build_patch_targets_section(self) -> str:
        """Build the Patch Targets section for the summary display.

        Constructs an HTML list of patch targets selected by the user,
        including license validation, time limitations, feature unlocking,
        and anti-debugging measure targets.

        Returns:
            HTML string containing patch target selections formatted as an HTML
            unordered list with section heading.

        """
        target_fields = [
            ("license_check", "License Validation"),
            ("time_limit", "Time Limitations"),
            ("feature_unlock", "Feature Unlocking"),
            ("anti_debug", "Anti-debugging Measures"),
        ]

        if items := [f"<li>{display_name}</li>\n" for field_name, display_name in target_fields if self.field(field_name)]:
            return "<h3>Patch Targets</h3>\n<ul>\n" + "".join(items) + "</ul>\n\n"
        return "<h3>Patch Targets</h3>\n<ul>\n</ul>\n\n"

    def _build_network_section(self) -> str:
        """Build the Network Analysis section for the summary display.

        Constructs an HTML list of network analysis and monitoring options selected
        by the user, including network traffic capture, protocol fingerprinting,
        SSL/TLS interception, license server emulation, and cloud license hooking.

        Returns:
            HTML string containing network analysis selections formatted as an HTML
            unordered list with section heading.

        """
        network_fields = [
            ("traffic_capture", "Capture Network Traffic"),
            ("protocol_fingerprint", "Protocol Fingerprinting"),
            ("ssl_intercept", "SSL/TLS Interception"),
            ("license_server_emulate", "License Server Emulation"),
            ("cloud_license_hook", "Cloud License Hooking"),
        ]

        if items := [f"<li>{display_name}</li>\n" for field_name, display_name in network_fields if self.field(field_name)]:
            return "<h3>Network Analysis</h3>\n<ul>\n" + "".join(items) + "</ul>\n\n"
        return "<h3>Network Analysis</h3>\n<ul>\n</ul>\n\n"

    def _build_ai_ml_section(self) -> str:
        """Build the AI & Machine Learning section for the summary display.

        Constructs an HTML list of AI-powered and machine learning features selected
        by the user, including comprehensive AI analysis, AI patch suggestions,
        AI code explanation, ML pattern learning, AI-assisted mode, distributed
        processing, and GPU acceleration.

        Returns:
            HTML string containing AI and machine learning selections formatted as
            an HTML unordered list with section heading.

        """
        ai_fields = [
            ("ai_comprehensive", "Comprehensive AI Analysis"),
            ("ai_patch_suggest", "AI Patch Suggestions"),
            ("ai_code_explain", "AI Code Explanation"),
            ("ml_pattern_learn", "ML Pattern Learning"),
            ("ai_assisted_mode", "AI-Assisted Mode"),
            ("distributed_processing", "Distributed Processing"),
            ("gpu_acceleration", "GPU Acceleration"),
        ]

        if items := [f"<li>{display_name}</li>\n" for field_name, display_name in ai_fields if self.field(field_name)]:
            return "<h3>AI & Machine Learning</h3>\n<ul>\n" + "".join(items) + "</ul>"
        return "<h3>AI & Machine Learning</h3>\n<ul>\n</ul>"

    def update_summary(self) -> None:
        """Update the summary text with the selected options.

        Builds comprehensive HTML summary of all wizard selections from every page,
        including binary file path, protection detection options, analysis
        configurations, advanced analysis settings, vulnerability detection options,
        patching methods, patch targets, network analysis options, and AI/ML
        features. The formatted HTML is displayed in the conclusion page's summary
        text widget for final user review before execution.

        """
        binary_path = self.field("binary_path")

        # Build header
        summary = "<h3>Selected File</h3>\n"
        summary += f"<p>{binary_path}</p>\n\n"

        # Build each section using handler methods
        summary += self._build_protection_section()
        summary += self._build_analysis_section()
        summary += self._build_advanced_analysis_section()
        summary += self._build_vulnerability_section()
        summary += self._build_patching_section()
        summary += self._build_patch_targets_section()
        summary += self._build_network_section()
        summary += self._build_ai_ml_section()

        self.summary_text.setHtml(summary)

    def browse_file(self) -> None:
        """Browse for a binary file to analyze.

        Opens a native file dialog that allows the user to select an executable file
        (.exe, .dll, .so, .dylib, or any file). Once a file is selected, the file
        path is displayed in the file path field and detailed file information
        (size, modification date, architecture, compilation date) is retrieved
        and displayed in the file information label.

        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)",
        )

        if file_path:
            self.file_path_edit.setText(file_path)
            self.update_file_info(file_path)

    def update_file_info(self, file_path: str) -> None:
        """Update the file information label with binary details.

        Retrieves and displays detailed information about the selected binary file,
        including file size, modification timestamp, and architecture information
        (x86/32-bit or x64/64-bit). For PE format binaries, also attempts to extract
        compilation timestamp using pefile library. Falls back to filename-based
        architecture detection on Windows if pefile fails.

        Args:
            file_path: Path to the binary executable file to analyze and extract
                information from.

        """
        try:
            file_size = os.path.getsize(file_path)
            file_mod_time = datetime.datetime.fromtimestamp(Path(file_path).stat().st_mtime)

            info_text = f"<b>File:</b> {os.path.basename(file_path)}<br>"
            info_text += f"<b>Size:</b> {self.format_size(file_size)}<br>"
            info_text += f"<b>Modified:</b> {file_mod_time.strftime('%Y-%m-%d %H:%M:%S')}<br>"

            # Try to get architecture info
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(file_path)
                    machine_type = getattr(pe.FILE_HEADER, "Machine", 0)

                    machine_types = {
                        0x014C: "x86 (32-bit)",
                        0x0200: "IA64",
                        0x8664: "x64 (64-bit)",
                    }

                    arch = machine_types.get(machine_type, f"Unknown ({hex(machine_type)})")
                    info_text += f"<b>Architecture:</b> {arch}<br>"

                    # Try to get timestamp
                    try:
                        timestamp = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
                        compile_time = datetime.datetime.fromtimestamp(timestamp)
                        info_text += f"<b>Compiled:</b> {compile_time.strftime('%Y-%m-%d %H:%M:%S')}<br>"
                    except (OSError, ValueError, RuntimeError) as e:
                        logger.error("Error in guided_workflow_wizard: %s", e)

                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("Error in guided_workflow_wizard: %s", e)
                    # If pefile fails, try a simpler approach
                    if os.name == "nt":  # Windows
                        if "64" in file_path.lower() or "x64" in file_path.lower():
                            info_text += "<b>Architecture:</b> Likely x64 (based on filename)<br>"
                        elif "32" in file_path.lower() or "x86" in file_path.lower():
                            info_text += "<b>Architecture:</b> Likely x86 (based on filename)<br>"

            self.file_info_label.setText(info_text)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in guided_workflow_wizard: %s", e)
            self.file_info_label.setText(f"Error getting file info: {e!s}")

    def format_size(self, size_bytes: int) -> str:
        """Format a file size in bytes to a human-readable string.

        Converts raw byte size into human-readable format with appropriate units
        (bytes, KB, MB, GB) using the standard binary notation. Delegates to
        the centralized format_bytes utility function from the string_utils module.

        Args:
            size_bytes: File size in bytes to format.

        Returns:
            Human-readable file size string with unit suffix (e.g., "1.5 MB").

        """
        from ...utils.core.string_utils import format_bytes

        return format_bytes(size_bytes)

    def on_finished(self, result: int) -> None:
        """Handle wizard completion and configure the parent application.

        Processes the wizard completion by extracting all user selections and
        configuring the parent application widget accordingly. If the wizard
        was accepted (not cancelled), this method updates the parent widget's
        binary path, loads the selected binary, and initiates static and dynamic
        analysis if they were enabled in the wizard workflow. Emits status messages
        to the parent widget's output signal and displays a completion message to
        the user.

        Args:
            result: Result code from the wizard dialog indicating acceptance
                or cancellation (QDialog.DialogCode.Accepted or Rejected).

        """
        if result != QDialog.DialogCode.Accepted or self._parent_widget is None:
            return

        binary_path_value = self.field("binary_path")
        if not isinstance(binary_path_value, str):
            return

        settings: dict[str, Any] = {
            "binary_path": binary_path_value,
            "analysis": {
                "static": self.field("static_analysis"),
                "dynamic": self.field("dynamic_analysis"),
                "symbolic": self.field("symbolic_execution"),
                "ml": self.field("ml_analysis"),
                "timeout": self.field("timeout"),
                "detect_protections": self.field("detect_protections"),
                "detect_vm": self.field("detect_vm"),
            },
            "patching": {
                "auto": self.field("auto_patch"),
                "interactive": self.field("interactive_patch"),
                "function_hooking": self.field("function_hooking"),
                "memory_patching": self.field("memory_patching"),
                "targets": {
                    "license_check": self.field("license_check"),
                    "time_limit": self.field("time_limit"),
                    "feature_unlock": self.field("feature_unlock"),
                    "anti_debug": self.field("anti_debug"),
                },
            },
        }

        if not os.path.exists(binary_path_value):
            return

        if hasattr(self._parent_widget, "binary_path"):
            self._parent_widget.binary_path = binary_path_value

        if hasattr(self._parent_widget, "update_output"):
            update_output_attr = self._parent_widget.update_output
            if hasattr(update_output_attr, "emit"):
                update_output_attr.emit(f"[Wizard] Set binary path: {binary_path_value}")

        if hasattr(self._parent_widget, "load_binary"):
            load_binary_method = self._parent_widget.load_binary
            if callable(load_binary_method):
                load_binary_method(binary_path_value)

        if hasattr(self._parent_widget, "update_output"):
            update_output_attr = self._parent_widget.update_output
            if hasattr(update_output_attr, "emit"):
                update_output_attr.emit("[Wizard] Configured analysis options")

        analysis_settings = settings.get("analysis")
        if isinstance(analysis_settings, dict) and analysis_settings.get("static") and hasattr(self._parent_widget, "run_static_analysis"):
            if hasattr(self._parent_widget, "update_output"):
                update_output_attr = self._parent_widget.update_output
                if hasattr(update_output_attr, "emit"):
                    update_output_attr.emit("[Wizard] Starting static analysis...")
            run_static = self._parent_widget.run_static_analysis
            if callable(run_static):
                run_static()

        if (
            isinstance(analysis_settings, dict)
            and analysis_settings.get("dynamic")
            and hasattr(self._parent_widget, "run_dynamic_analysis")
        ):
            if hasattr(self._parent_widget, "update_output"):
                update_output_attr = self._parent_widget.update_output
                if hasattr(update_output_attr, "emit"):
                    update_output_attr.emit("[Wizard] Starting dynamic analysis...")
            run_dynamic = self._parent_widget.run_dynamic_analysis
            if callable(run_dynamic):
                run_dynamic()

        if hasattr(self._parent_widget, "switch_tab"):
            switch_tab_attr = self._parent_widget.switch_tab
            if hasattr(switch_tab_attr, "emit"):
                switch_tab_attr.emit(1)

        if hasattr(self._parent_widget, "update_output"):
            update_output_attr = self._parent_widget.update_output
            if hasattr(update_output_attr, "emit"):
                update_output_attr.emit("[Wizard] Guided workflow completed")

        QMessageBox.information(
            self._parent_widget,
            "Guided Workflow",
            "The guided workflow has been set up and started.\nYou can monitor the analysis progress in the output panel.",
        )

    def get_settings(self) -> dict[str, Any]:
        """Get the current wizard settings from all pages.

        Retrieves all user-selected settings from the wizard's wizard fields,
        organizing them into a structured nested dictionary containing binary path,
        analysis configurations (static, dynamic, symbolic, ML-assisted),
        patching options (automatic, interactive, function hooking, memory patching),
        and patching targets (license check, time limits, feature unlock,
        anti-debug). This method provides a programmatic way to access all
        configured options without navigating the wizard pages.

        Returns:
            Dictionary containing all current wizard settings organized into top-level
            keys for binary_path, analysis, and patching, with nested configuration
            values for each analysis type, patching method, and target.

        """
        return {
            "binary_path": self.field("binary_path"),
            "analysis": {
                "static": self.field("static_analysis"),
                "dynamic": self.field("dynamic_analysis"),
                "symbolic": self.field("symbolic_execution"),
                "ml": self.field("ml_analysis"),
                "timeout": self.field("timeout"),
                "detect_protections": self.field("detect_protections"),
                "detect_vm": self.field("detect_vm"),
            },
            "patching": {
                "auto": self.field("auto_patch"),
                "interactive": self.field("interactive_patch"),
                "function_hooking": self.field("function_hooking"),
                "memory_patching": self.field("memory_patching"),
                "targets": {
                    "license_check": self.field("license_check"),
                    "time_limit": self.field("time_limit"),
                    "feature_unlock": self.field("feature_unlock"),
                    "anti_debug": self.field("anti_debug"),
                },
            },
        }


def create_guided_workflow_wizard(parent: QWidget | None = None) -> GuidedWorkflowWizard:
    """Create and configure a GuidedWorkflowWizard instance.

    Factory function that instantiates a new GuidedWorkflowWizard with the
    specified parent widget. This provides a convenient API for creating
    properly initialized wizard instances that guide users through binary
    analysis and software protection patching workflows.

    Args:
        parent: Parent widget for the wizard dialog (typically the main
            application window). Defaults to None for top-level window.

    Returns:
        Fully initialized GuidedWorkflowWizard instance ready for display
        and user interaction.

    """
    return GuidedWorkflowWizard(parent)
