"""
Advanced Analysis Wizard

Guided workflow configuration for complex analysis tasks with step-by-step
setup, intelligent recommendations, and backend integration.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QPixmap, QIcon, QPalette, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar,
    QGroupBox, QWizard, QWizardPage, QRadioButton, QCheckBox,
    QComboBox, QSpinBox, QSlider, QPushButton, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QLineEdit, QFileDialog, QMessageBox, QFormLayout, QGridLayout,
    QScrollArea, QFrame, QButtonGroup, QListWidget, QListWidgetItem,
    QTabWidget, QSplitter, QHeaderView
)

from ...core.analysis.analysis_orchestrator import AnalysisOrchestrator
from ...protection.unified_protection_engine import UnifiedProtectionEngine
from ...ai.ai_script_generator import AIScriptGenerator
from ...utils.logger import get_logger

logger = get_logger(__name__)


class WelcomePage(QWizardPage):
    """Welcome page for the analysis wizard."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Welcome to Advanced Analysis Wizard")
        self.setSubTitle("This wizard will guide you through configuring comprehensive binary analysis")
        
        layout = QVBoxLayout(self)
        
        # Welcome message
        welcome_text = QLabel("""
        <h3>Advanced Binary Analysis Configuration</h3>
        <p>This wizard will help you set up a comprehensive analysis workflow tailored to your specific needs.</p>
        
        <p><b>What this wizard will configure:</b></p>
        <ul>
        <li>Target binary selection and validation</li>
        <li>Analysis engine selection and prioritization</li>
        <li>Protection detection and bypass strategies</li>
        <li>AI-powered script generation settings</li>
        <li>Output and reporting preferences</li>
        <li>Performance and resource optimization</li>
        </ul>
        
        <p><b>Estimated time:</b> 5-10 minutes</p>
        <p><b>Required:</b> Target binary file</p>
        """)
        welcome_text.setWordWrap(True)
        
        layout.addWidget(welcome_text)
        layout.addStretch()


class BinarySelectionPage(QWizardPage):
    """Page for selecting and validating the target binary."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Target Binary Selection")
        self.setSubTitle("Select and configure the binary file for analysis")
        
        self.binary_path = ""
        self.binary_info = {}
        
        layout = QVBoxLayout(self)
        
        # File selection
        file_group = QGroupBox("Binary File Selection")
        file_layout = QVBoxLayout(file_group)
        
        # File path input
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Binary Path:"))
        
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Select a binary file for analysis...")
        self.path_edit.textChanged.connect(self.validate_binary)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_binary)
        
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(browse_btn)
        
        file_layout.addLayout(path_layout)
        
        # Binary information display
        self.info_text = QTextEdit()
        self.info_text.setMaximumHeight(150)
        self.info_text.setReadOnly(True)
        self.info_text.setPlaceholderText("Binary information will appear here...")
        file_layout.addWidget(self.info_text)
        
        # Analysis scope options
        scope_group = QGroupBox("Analysis Scope")
        scope_layout = QVBoxLayout(scope_group)
        
        self.full_analysis_radio = QRadioButton("Complete Analysis (Recommended)")
        self.full_analysis_radio.setChecked(True)
        self.quick_analysis_radio = QRadioButton("Quick Analysis")
        self.custom_analysis_radio = QRadioButton("Custom Analysis")
        
        scope_layout.addWidget(self.full_analysis_radio)
        scope_layout.addWidget(self.quick_analysis_radio)
        scope_layout.addWidget(self.custom_analysis_radio)
        
        layout.addWidget(file_group)
        layout.addWidget(scope_group)
        
        # Register fields for wizard navigation
        self.registerField("binary_path*", self.path_edit)
        
    def browse_binary(self):
        """Open file dialog to select binary."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Binary File", "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*)"
        )
        
        if file_path:
            self.path_edit.setText(file_path)
            
    def validate_binary(self, path):
        """Validate the selected binary file."""
        if not path:
            self.binary_info = {}
            self.info_text.clear()
            return False
            
        try:
            if not os.path.exists(path):
                self.info_text.setText("Error: File does not exist")
                return False
                
            # Get basic file information
            file_size = os.path.getsize(path)
            file_mtime = datetime.fromtimestamp(os.path.getmtime(path))
            
            # Try to determine file type
            file_type = "Unknown"
            architecture = "Unknown"
            
            with open(path, 'rb') as f:
                header = f.read(64)
                
                if header.startswith(b'MZ'):
                    file_type = "PE (Windows Executable)"
                    # Check for PE signature
                    if len(header) >= 64:
                        pe_offset = int.from_bytes(header[60:64], 'little')
                        if pe_offset < file_size:
                            f.seek(pe_offset)
                            pe_sig = f.read(4)
                            if pe_sig == b'PE\\x00\\x00':
                                # Read architecture from PE header
                                machine = f.read(2)
                                machine_type = int.from_bytes(machine, 'little')
                                if machine_type == 0x014c:
                                    architecture = "x86 (32-bit)"
                                elif machine_type == 0x8664:
                                    architecture = "x64 (64-bit)"
                                    
                elif header.startswith(b'\\x7fELF'):
                    file_type = "ELF (Linux/Unix Executable)"
                    if len(header) > 4:
                        if header[4] == 1:
                            architecture = "32-bit"
                        elif header[4] == 2:
                            architecture = "64-bit"
                            
                elif header.startswith(b'\\xcf\\xfa\\xed\\xfe') or header.startswith(b'\\xfe\\xed\\xfa\\xcf'):
                    file_type = "Mach-O (macOS Executable)"
                    
            self.binary_info = {
                'path': path,
                'size': file_size,
                'type': file_type,
                'architecture': architecture,
                'modified': file_mtime
            }
            
            # Display information
            info_text = f"""File: {os.path.basename(path)}
Path: {path}
Size: {file_size:,} bytes
Type: {file_type}
Architecture: {architecture}
Modified: {file_mtime.strftime('%Y-%m-%d %H:%M:%S')}"""

            self.info_text.setText(info_text)
            self.binary_path = path
            
            return True
            
        except Exception as e:
            self.info_text.setText(f"Error analyzing file: {e}")
            return False
            
    def get_binary_info(self):
        """Get the binary information for use by other pages."""
        return self.binary_info


class EngineConfigurationPage(QWizardPage):
    """Page for configuring analysis engines."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Analysis Engine Configuration")
        self.setSubTitle("Select and configure the analysis engines to use")
        
        self.engine_configs = {}
        
        layout = QVBoxLayout(self)
        
        # Engine selection
        engine_group = QGroupBox("Available Analysis Engines")
        engine_layout = QVBoxLayout(engine_group)
        
        # Create checkboxes for each engine
        self.engine_checkboxes = {}
        engines = [
            ("binary_analyzer", "Binary Analyzer", "Static analysis of binary structure", True),
            ("entropy_analyzer", "Entropy Analyzer", "Entropy analysis for packed/encrypted sections", True),
            ("protection_detector", "Protection Detector", "Detection of protections and packers", True),
            ("dynamic_analyzer", "Dynamic Analyzer", "Runtime behavior analysis", False),
            ("ghidra_decompiler", "Ghidra Decompiler", "Code decompilation and analysis", False),
            ("radare2_integration", "Radare2 Integration", "Disassembly and reverse engineering", True),
            ("vulnerability_scanner", "Vulnerability Scanner", "Security vulnerability detection", False),
            ("yara_pattern_engine", "YARA Pattern Engine", "Pattern matching and signature detection", True),
            ("obfuscation_analyzer", "Obfuscation Analyzer", "Obfuscation and anti-analysis detection", True),
            ("ai_script_generator", "AI Script Generator", "AI-powered exploit script generation", False)
        ]
        
        for engine_id, name, description, default in engines:
            checkbox = QCheckBox(f"{name}")
            checkbox.setChecked(default)
            checkbox.setToolTip(description)
            self.engine_checkboxes[engine_id] = checkbox
            engine_layout.addWidget(checkbox)
            
        # Engine priority configuration
        priority_group = QGroupBox("Engine Priority")
        priority_layout = QVBoxLayout(priority_group)
        
        priority_info = QLabel("Engines will be executed in priority order. Drag to reorder:")
        self.priority_list = QListWidget()
        self.priority_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        
        # Populate priority list
        for engine_id, name, _, default in engines:
            if default:
                item = QListWidgetItem(name)
                item.setData(Qt.ItemDataRole.UserRole, engine_id)
                self.priority_list.addItem(item)
                
        priority_layout.addWidget(priority_info)
        priority_layout.addWidget(self.priority_list)
        
        # Engine-specific settings
        settings_group = QGroupBox("Engine Settings")
        settings_layout = QVBoxLayout(settings_group)
        
        # Create tabs for different engine settings
        settings_tabs = QTabWidget()
        
        # Static analysis settings
        static_tab = QWidget()
        static_layout = QFormLayout(static_tab)
        
        self.deep_analysis_checkbox = QCheckBox("Enable deep analysis")
        self.deep_analysis_checkbox.setChecked(True)
        static_layout.addRow("Analysis Depth:", self.deep_analysis_checkbox)
        
        self.section_analysis_checkbox = QCheckBox("Analyze all sections")
        self.section_analysis_checkbox.setChecked(True)
        static_layout.addRow("Section Analysis:", self.section_analysis_checkbox)
        
        settings_tabs.addTab(static_tab, "Static Analysis")
        
        # Dynamic analysis settings
        dynamic_tab = QWidget()
        dynamic_layout = QFormLayout(dynamic_tab)
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 300)
        self.timeout_spin.setValue(60)
        self.timeout_spin.setSuffix(" seconds")
        dynamic_layout.addRow("Execution Timeout:", self.timeout_spin)
        
        self.sandbox_checkbox = QCheckBox("Use sandbox environment")
        self.sandbox_checkbox.setChecked(True)
        dynamic_layout.addRow("Sandbox:", self.sandbox_checkbox)
        
        settings_tabs.addTab(dynamic_tab, "Dynamic Analysis")
        
        # AI settings
        ai_tab = QWidget()
        ai_layout = QFormLayout(ai_tab)
        
        self.ai_model_combo = QComboBox()
        self.ai_model_combo.addItems(["GPT-4", "Claude-3", "Local Model", "Gemini Pro"])
        ai_layout.addRow("AI Model:", self.ai_model_combo)
        
        self.ai_creativity_slider = QSlider(Qt.Orientation.Horizontal)
        self.ai_creativity_slider.setRange(0, 100)
        self.ai_creativity_slider.setValue(70)
        ai_layout.addRow("Creativity Level:", self.ai_creativity_slider)
        
        settings_tabs.addTab(ai_tab, "AI Settings")
        
        settings_layout.addWidget(settings_tabs)
        
        layout.addWidget(engine_group)
        layout.addWidget(priority_group)
        layout.addWidget(settings_group)
        
        # Connect signals
        for checkbox in self.engine_checkboxes.values():
            checkbox.toggled.connect(self.update_engine_selection)
            
    def update_engine_selection(self):
        """Update engine selection and priority list."""
        # Clear priority list
        self.priority_list.clear()
        
        # Add enabled engines to priority list
        for engine_id, checkbox in self.engine_checkboxes.items():
            if checkbox.isChecked():
                # Find engine name
                engine_name = checkbox.text()
                item = QListWidgetItem(engine_name)
                item.setData(Qt.ItemDataRole.UserRole, engine_id)
                self.priority_list.addItem(item)
                
    def get_engine_configuration(self):
        """Get the current engine configuration."""
        config = {
            'enabled_engines': [],
            'engine_priority': [],
            'settings': {
                'deep_analysis': self.deep_analysis_checkbox.isChecked(),
                'section_analysis': self.section_analysis_checkbox.isChecked(),
                'timeout': self.timeout_spin.value(),
                'use_sandbox': self.sandbox_checkbox.isChecked(),
                'ai_model': self.ai_model_combo.currentText(),
                'ai_creativity': self.ai_creativity_slider.value() / 100.0
            }
        }
        
        # Get enabled engines
        for engine_id, checkbox in self.engine_checkboxes.items():
            if checkbox.isChecked():
                config['enabled_engines'].append(engine_id)
                
        # Get priority order
        for i in range(self.priority_list.count()):
            item = self.priority_list.item(i)
            engine_id = item.data(Qt.ItemDataRole.UserRole)
            config['engine_priority'].append(engine_id)
            
        return config


class ProtectionAnalysisPage(QWizardPage):
    """Page for configuring protection analysis and bypass strategies."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Protection Analysis Configuration")
        self.setSubTitle("Configure protection detection and bypass strategy generation")
        
        layout = QVBoxLayout(self)
        
        # Protection detection settings
        detection_group = QGroupBox("Protection Detection")
        detection_layout = QVBoxLayout(detection_group)
        
        # Detection modes
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Detection Mode:"))
        
        self.detection_mode_combo = QComboBox()
        self.detection_mode_combo.addItems([
            "Comprehensive (All methods)",
            "Fast (Signatures only)", 
            "Heuristic (Behavior-based)",
            "Deep (ML + Heuristics)"
        ])
        mode_layout.addWidget(self.detection_mode_combo)
        
        detection_layout.addLayout(mode_layout)
        
        # Confidence threshold
        conf_layout = QHBoxLayout()
        conf_layout.addWidget(QLabel("Confidence Threshold:"))
        
        self.confidence_slider = QSlider(Qt.Orientation.Horizontal)
        self.confidence_slider.setRange(30, 95)
        self.confidence_slider.setValue(70)
        
        self.confidence_label = QLabel("70%")
        self.confidence_slider.valueChanged.connect(
            lambda v: self.confidence_label.setText(f"{v}%")
        )
        
        conf_layout.addWidget(self.confidence_slider)
        conf_layout.addWidget(self.confidence_label)
        
        detection_layout.addLayout(conf_layout)
        
        # Protection types to detect
        types_group = QGroupBox("Protection Types to Detect")
        types_layout = QGridLayout(types_group)
        
        self.protection_checkboxes = {}
        protection_types = [
            ("packers", "Packers (UPX, ASPack, etc.)", True),
            ("crypters", "Crypters & Obfuscators", True),
            ("anti_debug", "Anti-Debugging", True),
            ("anti_vm", "Anti-VM Detection", True),
            ("license_check", "License Validation", True),
            ("trial_protection", "Trial Limitations", True),
            ("integrity_check", "Integrity Checks", False),
            ("network_protection", "Network Validation", False),
            ("hardware_lock", "Hardware Locking", False),
            ("code_injection", "Code Injection", False)
        ]
        
        for i, (prot_id, name, default) in enumerate(protection_types):
            checkbox = QCheckBox(name)
            checkbox.setChecked(default)
            self.protection_checkboxes[prot_id] = checkbox
            types_layout.addWidget(checkbox, i // 2, i % 2)
            
        # Bypass strategy configuration
        bypass_group = QGroupBox("Bypass Strategy Generation")
        bypass_layout = QVBoxLayout(bypass_group)
        
        # Strategy generation options
        self.generate_scripts_checkbox = QCheckBox("Generate bypass scripts automatically")
        self.generate_scripts_checkbox.setChecked(True)
        
        self.test_strategies_checkbox = QCheckBox("Test strategies in sandbox")
        self.test_strategies_checkbox.setChecked(False)
        
        self.prioritize_success_checkbox = QCheckBox("Prioritize by success probability")
        self.prioritize_success_checkbox.setChecked(True)
        
        bypass_layout.addWidget(self.generate_scripts_checkbox)
        bypass_layout.addWidget(self.test_strategies_checkbox)
        bypass_layout.addWidget(self.prioritize_success_checkbox)
        
        # Strategy types
        strategy_types_group = QGroupBox("Bypass Strategy Types")
        strategy_types_layout = QGridLayout(strategy_types_group)
        
        self.strategy_checkboxes = {}
        strategy_types = [
            ("memory_patching", "Memory Patching", True),
            ("api_hooking", "API Hooking", True),
            ("dll_injection", "DLL Injection", False),
            ("process_hollowing", "Process Hollowing", False),
            ("return_oriented", "Return-Oriented Programming", False),
            ("license_emulation", "License Server Emulation", True),
            ("key_generation", "Key Generation", False),
            ("time_manipulation", "Time Manipulation", True)
        ]
        
        for i, (strategy_id, name, default) in enumerate(strategy_types):
            checkbox = QCheckBox(name)
            checkbox.setChecked(default)
            self.strategy_checkboxes[strategy_id] = checkbox
            strategy_types_layout.addWidget(checkbox, i // 2, i % 2)
            
        layout.addWidget(detection_group)
        layout.addWidget(types_group)
        layout.addWidget(bypass_group)
        layout.addWidget(strategy_types_group)
        
    def get_protection_configuration(self):
        """Get the protection analysis configuration."""
        config = {
            'detection_mode': self.detection_mode_combo.currentText(),
            'confidence_threshold': self.confidence_slider.value() / 100.0,
            'enabled_protection_types': [],
            'generate_scripts': self.generate_scripts_checkbox.isChecked(),
            'test_strategies': self.test_strategies_checkbox.isChecked(),
            'prioritize_success': self.prioritize_success_checkbox.isChecked(),
            'enabled_strategy_types': []
        }
        
        # Get enabled protection types
        for prot_id, checkbox in self.protection_checkboxes.items():
            if checkbox.isChecked():
                config['enabled_protection_types'].append(prot_id)
                
        # Get enabled strategy types  
        for strategy_id, checkbox in self.strategy_checkboxes.items():
            if checkbox.isChecked():
                config['enabled_strategy_types'].append(strategy_id)
                
        return config


class OutputConfigurationPage(QWizardPage):
    """Page for configuring output and reporting."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Output Configuration")
        self.setSubTitle("Configure analysis output, reporting, and file generation")
        
        layout = QVBoxLayout(self)
        
        # Output directory
        output_group = QGroupBox("Output Directory")
        output_layout = QVBoxLayout(output_group)
        
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("Output Directory:"))
        
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setText(os.path.join(os.getcwd(), "analysis_output"))
        
        browse_dir_btn = QPushButton("Browse...")
        browse_dir_btn.clicked.connect(self.browse_output_dir)
        
        dir_layout.addWidget(self.output_dir_edit)
        dir_layout.addWidget(browse_dir_btn)
        
        output_layout.addLayout(dir_layout)
        
        # Report generation
        report_group = QGroupBox("Report Generation")
        report_layout = QVBoxLayout(report_group)
        
        # Report formats
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Report Formats:"))
        
        self.html_report_checkbox = QCheckBox("HTML Report")
        self.html_report_checkbox.setChecked(True)
        
        self.json_report_checkbox = QCheckBox("JSON Data")
        self.json_report_checkbox.setChecked(True)
        
        self.pdf_report_checkbox = QCheckBox("PDF Report")
        self.pdf_report_checkbox.setChecked(False)
        
        format_layout.addWidget(self.html_report_checkbox)
        format_layout.addWidget(self.json_report_checkbox)
        format_layout.addWidget(self.pdf_report_checkbox)
        
        report_layout.addLayout(format_layout)
        
        # Report detail level
        detail_layout = QHBoxLayout()
        detail_layout.addWidget(QLabel("Detail Level:"))
        
        self.detail_combo = QComboBox()
        self.detail_combo.addItems(["Summary", "Standard", "Detailed", "Comprehensive"])
        self.detail_combo.setCurrentText("Standard")
        
        detail_layout.addWidget(self.detail_combo)
        
        report_layout.addLayout(detail_layout)
        
        # File generation
        files_group = QGroupBox("Generated Files")
        files_layout = QVBoxLayout(files_group)
        
        self.save_scripts_checkbox = QCheckBox("Save generated scripts")
        self.save_scripts_checkbox.setChecked(True)
        
        self.save_logs_checkbox = QCheckBox("Save analysis logs")
        self.save_logs_checkbox.setChecked(True)
        
        self.save_memory_dumps_checkbox = QCheckBox("Save memory dumps")
        self.save_memory_dumps_checkbox.setChecked(False)
        
        self.save_network_capture_checkbox = QCheckBox("Save network captures")
        self.save_network_capture_checkbox.setChecked(False)
        
        files_layout.addWidget(self.save_scripts_checkbox)
        files_layout.addWidget(self.save_logs_checkbox)
        files_layout.addWidget(self.save_memory_dumps_checkbox)
        files_layout.addWidget(self.save_network_capture_checkbox)
        
        # Notification settings
        notification_group = QGroupBox("Notifications")
        notification_layout = QVBoxLayout(notification_group)
        
        self.notify_completion_checkbox = QCheckBox("Notify on completion")
        self.notify_completion_checkbox.setChecked(True)
        
        self.notify_critical_checkbox = QCheckBox("Notify on critical findings")
        self.notify_critical_checkbox.setChecked(True)
        
        self.email_reports_checkbox = QCheckBox("Email reports (if configured)")
        self.email_reports_checkbox.setChecked(False)
        
        notification_layout.addWidget(self.notify_completion_checkbox)
        notification_layout.addWidget(self.notify_critical_checkbox)
        notification_layout.addWidget(self.email_reports_checkbox)
        
        layout.addWidget(output_group)
        layout.addWidget(report_group)
        layout.addWidget(files_group)
        layout.addWidget(notification_group)
        
    def browse_output_dir(self):
        """Browse for output directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", self.output_dir_edit.text()
        )
        
        if dir_path:
            self.output_dir_edit.setText(dir_path)
            
    def get_output_configuration(self):
        """Get the output configuration."""
        return {
            'output_directory': self.output_dir_edit.text(),
            'report_formats': {
                'html': self.html_report_checkbox.isChecked(),
                'json': self.json_report_checkbox.isChecked(),
                'pdf': self.pdf_report_checkbox.isChecked()
            },
            'detail_level': self.detail_combo.currentText().lower(),
            'save_files': {
                'scripts': self.save_scripts_checkbox.isChecked(),
                'logs': self.save_logs_checkbox.isChecked(),
                'memory_dumps': self.save_memory_dumps_checkbox.isChecked(),
                'network_captures': self.save_network_capture_checkbox.isChecked()
            },
            'notifications': {
                'completion': self.notify_completion_checkbox.isChecked(),
                'critical_findings': self.notify_critical_checkbox.isChecked(),
                'email_reports': self.email_reports_checkbox.isChecked()
            }
        }


class SummaryPage(QWizardPage):
    """Final summary page showing configuration overview."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Configuration Summary")
        self.setSubTitle("Review your analysis configuration before starting")
        
        layout = QVBoxLayout(self)
        
        # Summary display
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 9))
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.save_config_btn = QPushButton("Save Configuration")
        self.save_config_btn.clicked.connect(self.save_configuration)
        
        self.load_config_btn = QPushButton("Load Configuration")
        self.load_config_btn.clicked.connect(self.load_configuration)
        
        button_layout.addWidget(self.save_config_btn)
        button_layout.addWidget(self.load_config_btn)
        button_layout.addStretch()
        
        layout.addWidget(self.summary_text)
        layout.addLayout(button_layout)
        
    def initializePage(self):
        """Initialize the summary page with current configuration."""
        wizard = self.wizard()
        
        # Get configurations from all pages
        binary_info = wizard.binary_page.get_binary_info()
        engine_config = wizard.engine_page.get_engine_configuration()
        protection_config = wizard.protection_page.get_protection_configuration()
        output_config = wizard.output_page.get_output_configuration()
        
        # Generate summary
        summary = self.generate_summary(binary_info, engine_config, protection_config, output_config)
        self.summary_text.setText(summary)
        
    def generate_summary(self, binary_info, engine_config, protection_config, output_config):
        """Generate configuration summary text."""
        summary = f"""
ANALYSIS CONFIGURATION SUMMARY
============================

TARGET BINARY:
  File: {binary_info.get('path', 'Not selected')}
  Type: {binary_info.get('type', 'Unknown')}
  Architecture: {binary_info.get('architecture', 'Unknown')}
  Size: {binary_info.get('size', 0):,} bytes

ANALYSIS ENGINES ({len(engine_config['enabled_engines'])} enabled):
"""
        
        for engine in engine_config['enabled_engines']:
            summary += f"  ✓ {engine.replace('_', ' ').title()}\\n"
            
        summary += f"""
PROTECTION ANALYSIS:
  Detection Mode: {protection_config['detection_mode']}
  Confidence Threshold: {protection_config['confidence_threshold']:.0%}
  Protection Types: {len(protection_config['enabled_protection_types'])} enabled
  Generate Scripts: {'Yes' if protection_config['generate_scripts'] else 'No'}
  Test Strategies: {'Yes' if protection_config['test_strategies'] else 'No'}

OUTPUT CONFIGURATION:
  Output Directory: {output_config['output_directory']}
  Report Formats: {', '.join(f for f, enabled in output_config['report_formats'].items() if enabled)}
  Detail Level: {output_config['detail_level'].title()}
  
ADVANCED SETTINGS:
  Deep Analysis: {'Enabled' if engine_config['settings']['deep_analysis'] else 'Disabled'}
  Section Analysis: {'Enabled' if engine_config['settings']['section_analysis'] else 'Disabled'}
  AI Model: {engine_config['settings']['ai_model']}
  Execution Timeout: {engine_config['settings']['timeout']} seconds
"""
        
        return summary
        
    def save_configuration(self):
        """Save the current configuration to file."""
        try:
            wizard = self.wizard()
            
            config = {
                'binary_info': wizard.binary_page.get_binary_info(),
                'engine_config': wizard.engine_page.get_engine_configuration(),
                'protection_config': wizard.protection_page.get_protection_configuration(),
                'output_config': wizard.output_page.get_output_configuration(),
                'created_at': datetime.now().isoformat(),
                'wizard_version': '1.0'
            }
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Configuration", "analysis_config.json",
                "JSON Files (*.json);;All Files (*)"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(config, f, indent=2, default=str)
                    
                QMessageBox.information(self, "Success", f"Configuration saved to {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {e}")
            
    def load_configuration(self):
        """Load configuration from file."""
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self, "Load Configuration", "",
                "JSON Files (*.json);;All Files (*)"
            )
            
            if filename:
                with open(filename, 'r') as f:
                    config = json.load(f)
                    
                # Apply configuration to wizard pages
                wizard = self.wizard()
                
                # Apply binary configuration
                if 'binary_info' in config and 'path' in config['binary_info']:
                    wizard.binary_page.path_edit.setText(config['binary_info']['path'])
                    
                QMessageBox.information(self, "Success", f"Configuration loaded from {filename}")
                
                # Refresh summary
                self.initializePage()
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load configuration: {e}")


class AdvancedAnalysisWizard(QWizard):
    """
    Advanced analysis wizard for guided configuration of complex analysis tasks.
    
    Provides step-by-step setup with intelligent recommendations and backend integration.
    """
    
    analysis_configured = pyqtSignal(dict)
    wizard_completed = pyqtSignal(dict)
    
    def __init__(self, shared_context=None, parent=None):
        """Initialize the advanced analysis wizard."""
        super().__init__(parent)
        self.shared_context = shared_context
        
        self.setWindowTitle("Advanced Analysis Wizard")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(800, 600)
        
        # Create wizard pages
        self.welcome_page = WelcomePage(self)
        self.binary_page = BinarySelectionPage(self)
        self.engine_page = EngineConfigurationPage(self)
        self.protection_page = ProtectionAnalysisPage(self)
        self.output_page = OutputConfigurationPage(self)
        self.summary_page = SummaryPage(self)
        
        # Add pages to wizard
        self.addPage(self.welcome_page)
        self.addPage(self.binary_page)
        self.addPage(self.engine_page)
        self.addPage(self.protection_page)
        self.addPage(self.output_page)
        self.addPage(self.summary_page)
        
        # Connect signals
        self.finished.connect(self.on_wizard_finished)
        
    def on_wizard_finished(self, result):
        """Handle wizard completion."""
        if result == QWizard.DialogCode.Accepted:
            # Collect all configuration
            final_config = {
                'binary_info': self.binary_page.get_binary_info(),
                'engine_config': self.engine_page.get_engine_configuration(),
                'protection_config': self.protection_page.get_protection_configuration(),
                'output_config': self.output_page.get_output_configuration(),
                'wizard_completed_at': datetime.now().isoformat()
            }
            
            # Emit signals
            self.analysis_configured.emit(final_config)
            self.wizard_completed.emit(final_config)
            
            # Start analysis if requested
            if hasattr(self.shared_context, 'start_analysis'):
                self.shared_context.start_analysis(final_config)
                
    def get_final_configuration(self):
        """Get the final wizard configuration."""
        return {
            'binary_info': self.binary_page.get_binary_info(),
            'engine_config': self.engine_page.get_engine_configuration(),
            'protection_config': self.protection_page.get_protection_configuration(),
            'output_config': self.output_page.get_output_configuration()
        }