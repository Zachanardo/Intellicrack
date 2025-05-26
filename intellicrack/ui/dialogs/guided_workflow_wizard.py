"""
Guided Workflow Wizard

This module provides a step-by-step wizard for new users to get started
with binary analysis and patching using Intellicrack.
"""

import datetime
import os
from typing import Optional, Dict, Any

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtWidgets import (
    QWizard, QWizardPage, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox,
    QGroupBox, QTextEdit, QFileDialog, QSpacerItem, QSizePolicy,
    QDialog, QMessageBox
)

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

__all__ = ['GuidedWorkflowWizard']


class GuidedWorkflowWizard(QWizard):
    """
    Guided workflow wizard for new users.
    
    Provides a step-by-step interface for configuring and starting
    binary analysis and patching operations.
    """

    def __init__(self, parent=None):
        """
        Initialize the guided workflow wizard.

        Args:
            parent: Parent widget (typically the main application)
        """
        super().__init__(parent)
        self.parent = parent

        # Set up wizard properties
        self.setWindowTitle("Intellicrack Guided Workflow")
        self.setWizardStyle(QWizard.ModernStyle)

        if os.path.exists("assets/icon.ico"):
            self.setWindowIcon(QIcon("assets/icon.ico"))

        # Set minimum size
        self.setMinimumSize(800, 600)

        # Add wizard pages
        self.addPage(self.create_intro_page())
        self.addPage(self.create_file_selection_page())
        self.addPage(self.create_analysis_options_page())
        self.addPage(self.create_patching_options_page())
        self.addPage(self.create_conclusion_page())

        # Connect signals
        self.finished.connect(self.on_finished)

    def create_intro_page(self) -> QWizardPage:
        """Create the introduction page."""
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
            "You can cancel this wizard at any time and use the application manually."
        )
        intro_text.setWordWrap(True)
        layout.addWidget(intro_text)

        # Add image if available
        if os.path.exists("assets/splash.png"):
            image_label = QLabel()
            pixmap = QPixmap("assets/splash.png").scaled(400, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            image_label.setPixmap(pixmap)
            image_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(image_label)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        page.setLayout(layout)
        return page

    def create_file_selection_page(self) -> QWizardPage:
        """Create the file selection page."""
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
        self.file_path_edit.setPlaceholderText("Select a binary file...")
        self.file_path_edit.setReadOnly(True)

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
            "Common examples include software trials, licensed applications, or games with anti-piracy protections."
        )
        hint_label.setWordWrap(True)
        hint_label.setStyleSheet("font-style: italic; color: #666;")
        layout.addWidget(hint_label)

        # Add spacer
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Register fields
        page.registerField("binary_path*", self.file_path_edit)

        page.setLayout(layout)
        return page

    def create_analysis_options_page(self) -> QWizardPage:
        """Create the analysis options page."""
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
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

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
        """Create the patching options page."""
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
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

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

    def create_conclusion_page(self) -> QWizardPage:
        """Create the conclusion page."""
        page = QWizardPage()
        page.setTitle("Ready to Start")
        page.setSubTitle("Your workflow has been configured and is ready to start")

        layout = QVBoxLayout()

        # Summary label
        summary_label = QLabel("Summary of your selections:")
        layout.addWidget(summary_label)

        # Summary text
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        layout.addWidget(self.summary_text)

        # Connect page-shown signal to update summary
        page.initializePage = self.update_summary

        # Add final instructions
        instructions_label = QLabel(
            "Click 'Finish' to begin analyzing and patching the selected binary. "
            "The application will guide you through the rest of the process and "
            "show you the results of each step."
        )
        instructions_label.setWordWrap(True)
        layout.addWidget(instructions_label)

        page.setLayout(layout)
        return page

    def update_summary(self) -> None:
        """Update the summary text with the selected options."""
        binary_path = self.field("binary_path")

        summary = f"<h3>Selected File</h3>\n"
        summary += f"<p>{binary_path}</p>\n\n"

        summary += "<h3>Analysis Options</h3>\n<ul>\n"
        if self.field("static_analysis"):
            summary += "<li>Static Analysis</li>\n"
        if self.field("dynamic_analysis"):
            summary += "<li>Dynamic Analysis</li>\n"
        if self.field("symbolic_execution"):
            summary += "<li>Symbolic Execution</li>\n"
        if self.field("ml_analysis"):
            summary += "<li>ML-assisted Analysis</li>\n"
        summary += f"<li>Timeout: {self.field('timeout')} seconds</li>\n"
        if self.field("detect_protections"):
            summary += "<li>Detect Protections</li>\n"
        if self.field("detect_vm"):
            summary += "<li>Detect VM/Debugging Evasions</li>\n"
        summary += "</ul>\n\n"

        summary += "<h3>Patching Options</h3>\n<ul>\n"
        if self.field("auto_patch"):
            summary += "<li>Automatic Patching</li>\n"
        if self.field("interactive_patch"):
            summary += "<li>Interactive Patching</li>\n"
        if self.field("function_hooking"):
            summary += "<li>Function Hooking</li>\n"
        if self.field("memory_patching"):
            summary += "<li>Memory Patching</li>\n"
        summary += "</ul>\n\n"

        summary += "<h3>Patch Targets</h3>\n<ul>\n"
        if self.field("license_check"):
            summary += "<li>License Validation</li>\n"
        if self.field("time_limit"):
            summary += "<li>Time Limitations</li>\n"
        if self.field("feature_unlock"):
            summary += "<li>Feature Unlocking</li>\n"
        if self.field("anti_debug"):
            summary += "<li>Anti-debugging Measures</li>\n"
        summary += "</ul>"

        self.summary_text.setHtml(summary)

    def browse_file(self) -> None:
        """Browse for a binary file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)"
        )

        if file_path:
            self.file_path_edit.setText(file_path)
            self.update_file_info(file_path)

    def update_file_info(self, file_path: str) -> None:
        """Update the file information label."""
        try:
            file_size = os.path.getsize(file_path)
            file_mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))

            info_text = f"<b>File:</b> {os.path.basename(file_path)}<br>"
            info_text += f"<b>Size:</b> {self.format_size(file_size)}<br>"
            info_text += f"<b>Modified:</b> {file_mod_time.strftime('%Y-%m-%d %H:%M:%S')}<br>"

            # Try to get architecture info
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(file_path)
                    machine_type = pe.FILE_HEADER.Machine

                    machine_types = {
                        0x014c: "x86 (32-bit)",
                        0x0200: "IA64",
                        0x8664: "x64 (64-bit)"
                    }

                    arch = machine_types.get(machine_type, f"Unknown ({hex(machine_type)})")
                    info_text += f"<b>Architecture:</b> {arch}<br>"

                    # Try to get timestamp
                    try:
                        timestamp = pe.FILE_HEADER.TimeDateStamp
                        compile_time = datetime.datetime.fromtimestamp(timestamp)
                        info_text += f"<b>Compiled:</b> {compile_time.strftime('%Y-%m-%d %H:%M:%S')}<br>"
                    except Exception:
                        pass

                except Exception:
                    # If pefile fails, try a simpler approach
                    if os.name == "nt":  # Windows
                        if "64" in file_path.lower() or "x64" in file_path.lower():
                            info_text += "<b>Architecture:</b> Likely x64 (based on filename)<br>"
                        elif "32" in file_path.lower() or "x86" in file_path.lower():
                            info_text += "<b>Architecture:</b> Likely x86 (based on filename)<br>"

            self.file_info_label.setText(info_text)

        except Exception as e:
            self.file_info_label.setText(f"Error getting file info: {str(e)}")

    def format_size(self, size_bytes: int) -> str:
        """Format a file size in bytes to a human-readable string."""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def on_finished(self, result: int) -> None:
        """Handle wizard completion."""
        if result == QDialog.Accepted and self.parent:
            # Collect all the settings from the wizard fields
            settings = {
                "binary_path": self.field("binary_path"),
                "analysis": {
                    "static": self.field("static_analysis"),
                    "dynamic": self.field("dynamic_analysis"),
                    "symbolic": self.field("symbolic_execution"),
                    "ml": self.field("ml_analysis"),
                    "timeout": self.field("timeout"),
                    "detect_protections": self.field("detect_protections"),
                    "detect_vm": self.field("detect_vm")
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
                        "anti_debug": self.field("anti_debug")
                    }
                }
            }

            # Apply settings to parent app
            binary_path = settings["binary_path"]
            if os.path.exists(binary_path):
                self.parent.binary_path = binary_path
                
                # Emit signals if available
                if hasattr(self.parent, 'update_output'):
                    self.parent.update_output.emit(f"[Wizard] Set binary path: {binary_path}")

                # Load the binary in the UI
                if hasattr(self.parent, 'load_binary'):
                    self.parent.load_binary(binary_path)

                # Configure analysis options
                if hasattr(self.parent, 'update_output'):
                    self.parent.update_output.emit("[Wizard] Configured analysis options")

                # Start analysis if auto-analyze is enabled
                if settings["analysis"]["static"] and hasattr(self.parent, 'run_static_analysis'):
                    if hasattr(self.parent, 'update_output'):
                        self.parent.update_output.emit("[Wizard] Starting static analysis...")
                    self.parent.run_static_analysis()

                if settings["analysis"]["dynamic"] and hasattr(self.parent, 'run_dynamic_analysis'):
                    if hasattr(self.parent, 'update_output'):
                        self.parent.update_output.emit("[Wizard] Starting dynamic analysis...")
                    self.parent.run_dynamic_analysis()

                # Switch to the Analysis tab if available
                if hasattr(self.parent, 'switch_tab'):
                    self.parent.switch_tab.emit(1)  # Assuming Analysis tab is index 1

                # Record that the guided workflow has been completed
                if hasattr(self.parent, 'update_output'):
                    self.parent.update_output.emit("[Wizard] Guided workflow completed")

                # Show notification
                QMessageBox.information(
                    self.parent,
                    "Guided Workflow",
                    "The guided workflow has been set up and started.\n"
                    "You can monitor the analysis progress in the output panel."
                )

    def get_settings(self) -> Dict[str, Any]:
        """
        Get the current wizard settings.
        
        Returns:
            Dictionary containing all current settings
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
                "detect_vm": self.field("detect_vm")
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
                    "anti_debug": self.field("anti_debug")
                }
            }
        }


def create_guided_workflow_wizard(parent=None) -> GuidedWorkflowWizard:
    """
    Factory function to create a GuidedWorkflowWizard.
    
    Args:
        parent: Parent widget
        
    Returns:
        Configured wizard instance
    """
    return GuidedWorkflowWizard(parent)
