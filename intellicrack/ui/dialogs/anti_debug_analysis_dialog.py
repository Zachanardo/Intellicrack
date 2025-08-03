"""
Anti-Debugging Analysis Dialog

GUI interface for comprehensive anti-debugging technique detection and analysis.
Provides an intuitive interface for configuring and running anti-debugging analysis.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
    QCheckBox, QComboBox, QGroupBox, QTabWidget, QWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QSpinBox,
    QFileDialog, QMessageBox, QSplitter, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtGui import QFont, QTextCursor, QIcon

from ...core.anti_analysis import AntiDebugDetectionEngine
from ...core.app_context import AppContext


class AntiDebugAnalysisWorker(QThread):
    """Worker thread for anti-debugging analysis to prevent GUI freezing."""
    
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    analysis_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, binary_path: str, analysis_options: Dict[str, Any]):
        super().__init__()
        self.binary_path = binary_path
        self.analysis_options = analysis_options
        self.engine = AntiDebugDetectionEngine()
        self.logger = logging.getLogger("IntellicrackLogger.AntiDebugWorker")
    
    def run(self):
        """Run the anti-debugging analysis in background."""
        try:
            self.status_updated.emit("Initializing anti-debugging analysis...")
            self.progress_updated.emit(10)
            
            # Simulate progress updates during analysis
            self.status_updated.emit("Performing dynamic detection...")
            self.progress_updated.emit(30)
            
            # Perform the actual analysis
            results = self.engine.analyze_binary(self.binary_path, self.analysis_options)
            
            self.progress_updated.emit(70)
            
            if 'error' in results:
                self.error_occurred.emit(results['error'])
                return
            
            self.status_updated.emit("Generating bypass recommendations...")
            self.progress_updated.emit(85)
            
            # Generate bypass recommendations
            bypass_info = self.engine.get_bypass_recommendations(results)
            
            if bypass_info.get('success', False):
                results['enhanced_bypass_info'] = bypass_info
            
            self.progress_updated.emit(100)
            self.status_updated.emit("Analysis completed successfully")
            
            self.analysis_completed.emit(results)
            
        except Exception as e:
            self.logger.error(f"Analysis worker failed: {e}", exc_info=True)
            self.error_occurred.emit(str(e))


class AntiDebugAnalysisDialog(QDialog):
    """
    Comprehensive anti-debugging analysis dialog.
    
    Provides GUI interface for:
    - Configuring analysis options
    - Running anti-debugging detection
    - Viewing detailed results
    - Generating bypass recommendations
    - Creating bypass scripts
    """
    
    def __init__(self, parent=None, app_context: Optional[AppContext] = None):
        super().__init__(parent)
        self.app_context = app_context
        self.logger = logging.getLogger("IntellicrackLogger.AntiDebugDialog")
        
        # Analysis state
        self.engine = AntiDebugDetectionEngine(app_context)
        self.current_results = None
        self.analysis_worker = None
        
        # Setup UI
        self.setWindowTitle("Anti-Debugging Analysis - Intellicrack")
        self.setModal(True)
        self.resize(1200, 800)
        
        self.setup_ui()
        self.setup_connections()
        
        self.logger.info("Anti-debugging analysis dialog initialized")
    
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # Left panel - Configuration
        config_widget = self.create_configuration_panel()
        splitter.addWidget(config_widget)
        
        # Right panel - Results
        results_widget = self.create_results_panel()
        splitter.addWidget(results_widget)
        
        # Set splitter proportions
        splitter.setSizes([400, 800])
        
        # Bottom buttons
        buttons_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start Analysis")
        self.start_button.clicked.connect(self.start_analysis)
        buttons_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Analysis")
        self.stop_button.clicked.connect(self.stop_analysis)
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_button)
        
        buttons_layout.addStretch()
        
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        buttons_layout.addWidget(self.export_button)
        
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        buttons_layout.addWidget(self.close_button)
        
        layout.addLayout(buttons_layout)
    
    def create_configuration_panel(self) -> QWidget:
        """Create the configuration panel."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Target selection
        target_group = QGroupBox("Analysis Target")
        target_layout = QVBoxLayout(target_group)
        
        # Binary file selection
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Binary File:"))
        
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select binary file to analyze...")
        file_layout.addWidget(self.file_path_edit)
        
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_button)
        
        target_layout.addLayout(file_layout)
        
        # Live process option
        process_layout = QHBoxLayout()
        process_layout.addWidget(QLabel("Or PID:"))
        
        self.pid_spinbox = QSpinBox()
        self.pid_spinbox.setRange(0, 65535)
        self.pid_spinbox.setSpecialValueText("Current Process")
        process_layout.addWidget(self.pid_spinbox)
        
        target_layout.addLayout(process_layout)
        
        layout.addWidget(target_group)
        
        # Analysis options
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout(options_group)
        
        self.static_analysis_cb = QCheckBox("Enable Static Analysis")
        self.static_analysis_cb.setChecked(True)
        self.static_analysis_cb.setToolTip("Analyze binary file for anti-debug patterns")
        options_layout.addWidget(self.static_analysis_cb)
        
        self.dynamic_analysis_cb = QCheckBox("Enable Dynamic Analysis")
        self.dynamic_analysis_cb.setChecked(True)
        self.dynamic_analysis_cb.setToolTip("Perform runtime anti-debug detection")
        options_layout.addWidget(self.dynamic_analysis_cb)
        
        self.aggressive_mode_cb = QCheckBox("Aggressive Detection")
        self.aggressive_mode_cb.setToolTip("Use aggressive detection methods (may affect performance)")
        options_layout.addWidget(self.aggressive_mode_cb)
        
        self.deep_scan_cb = QCheckBox("Deep Scan")
        self.deep_scan_cb.setToolTip("Perform comprehensive binary analysis")
        options_layout.addWidget(self.deep_scan_cb)
        
        self.cache_results_cb = QCheckBox("Cache Results")
        self.cache_results_cb.setChecked(True)
        self.cache_results_cb.setToolTip("Cache analysis results for faster repeated analysis")
        options_layout.addWidget(self.cache_results_cb)
        
        # Timeout setting
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (seconds):"))
        
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(5, 300)
        self.timeout_spinbox.setValue(30)
        timeout_layout.addWidget(self.timeout_spinbox)
        
        options_layout.addLayout(timeout_layout)
        
        layout.addWidget(options_group)
        
        # Detection categories
        categories_group = QGroupBox("Detection Categories")
        categories_layout = QVBoxLayout(categories_group)
        
        self.api_detection_cb = QCheckBox("API-Based Detection")
        self.api_detection_cb.setChecked(True)
        categories_layout.addWidget(self.api_detection_cb)
        
        self.peb_detection_cb = QCheckBox("PEB Manipulation Detection")
        self.peb_detection_cb.setChecked(True)
        categories_layout.addWidget(self.peb_detection_cb)
        
        self.exception_detection_cb = QCheckBox("Exception-Based Detection")
        self.exception_detection_cb.setChecked(True)
        categories_layout.addWidget(self.exception_detection_cb)
        
        self.timing_detection_cb = QCheckBox("Timing-Based Detection")
        self.timing_detection_cb.setChecked(True)
        categories_layout.addWidget(self.timing_detection_cb)
        
        self.env_detection_cb = QCheckBox("Environment Detection")
        self.env_detection_cb.setChecked(True)
        categories_layout.addWidget(self.env_detection_cb)
        
        self.advanced_detection_cb = QCheckBox("Advanced Techniques")
        self.advanced_detection_cb.setChecked(True)
        categories_layout.addWidget(self.advanced_detection_cb)
        
        layout.addWidget(categories_group)
        
        layout.addStretch()
        
        return widget
    
    def create_results_panel(self) -> QWidget:
        """Create the results panel."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready for analysis")
        layout.addWidget(self.status_label)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        
        # Overview tab
        self.overview_tab = self.create_overview_tab()
        self.results_tabs.addTab(self.overview_tab, "Overview")
        
        # Techniques tab
        self.techniques_tab = self.create_techniques_tab()
        self.results_tabs.addTab(self.techniques_tab, "Detected Techniques")
        
        # Bypass tab
        self.bypass_tab = self.create_bypass_tab()
        self.results_tabs.addTab(self.bypass_tab, "Bypass Recommendations")
        
        # Scripts tab
        self.scripts_tab = self.create_scripts_tab()
        self.results_tabs.addTab(self.scripts_tab, "Bypass Scripts")
        
        # Raw results tab
        self.raw_tab = self.create_raw_results_tab()
        self.results_tabs.addTab(self.raw_tab, "Raw Results")
        
        layout.addWidget(self.results_tabs)
        
        return widget
    
    def create_overview_tab(self) -> QWidget:
        """Create the overview results tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Summary group
        summary_group = QGroupBox("Analysis Summary")
        summary_layout = QGridLayout(summary_group)
        
        self.total_techniques_label = QLabel("0")
        summary_layout.addWidget(QLabel("Total Techniques Detected:"), 0, 0)
        summary_layout.addWidget(self.total_techniques_label, 0, 1)
        
        self.protection_score_label = QLabel("0.0")
        summary_layout.addWidget(QLabel("Protection Score:"), 1, 0)
        summary_layout.addWidget(self.protection_score_label, 1, 1)
        
        self.difficulty_label = QLabel("Unknown")
        summary_layout.addWidget(QLabel("Bypass Difficulty:"), 2, 0)
        summary_layout.addWidget(self.difficulty_label, 2, 1)
        
        self.highest_severity_label = QLabel("None")
        summary_layout.addWidget(QLabel("Highest Severity:"), 3, 0)
        summary_layout.addWidget(self.highest_severity_label, 3, 1)
        
        layout.addWidget(summary_group)
        
        # Categories breakdown
        categories_group = QGroupBox("Detection Categories")
        categories_layout = QVBoxLayout(categories_group)
        
        self.categories_tree = QTreeWidget()
        self.categories_tree.setHeaderLabels(["Category", "Count", "Score"])
        categories_layout.addWidget(self.categories_tree)
        
        layout.addWidget(categories_group)
        
        # Recommendations
        recommendations_group = QGroupBox("Recommended Actions")
        recommendations_layout = QVBoxLayout(recommendations_group)
        
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setMaximumHeight(150)
        self.recommendations_text.setReadOnly(True)
        recommendations_layout.addWidget(self.recommendations_text)
        
        layout.addWidget(recommendations_group)
        
        return widget
    
    def create_techniques_tab(self) -> QWidget:
        """Create the detected techniques tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.techniques_table = QTableWidget()
        self.techniques_table.setColumnCount(5)
        self.techniques_table.setHorizontalHeaderLabels([
            "Technique", "Category", "Severity", "Confidence", "Description"
        ])
        
        # Configure table
        header = self.techniques_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.techniques_table)
        
        return widget
    
    def create_bypass_tab(self) -> QWidget:
        """Create the bypass recommendations tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Bypass strategy
        strategy_group = QGroupBox("Bypass Strategy")
        strategy_layout = QVBoxLayout(strategy_group)
        
        self.strategy_text = QTextEdit()
        self.strategy_text.setMaximumHeight(100)
        self.strategy_text.setReadOnly(True)
        strategy_layout.addWidget(self.strategy_text)
        
        layout.addWidget(strategy_group)
        
        # Tools recommendations
        tools_group = QGroupBox("Recommended Tools")
        tools_layout = QVBoxLayout(tools_group)
        
        self.tools_table = QTableWidget()
        self.tools_table.setColumnCount(3)
        self.tools_table.setHorizontalHeaderLabels(["Tool", "Category", "Purpose"])
        
        tools_header = self.tools_table.horizontalHeader()
        tools_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        tools_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        tools_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        tools_layout.addWidget(self.tools_table)
        layout.addWidget(tools_group)
        
        # Step-by-step guide
        guide_group = QGroupBox("Step-by-Step Guide")
        guide_layout = QVBoxLayout(guide_group)
        
        self.guide_text = QTextEdit()
        self.guide_text.setReadOnly(True)
        guide_layout.addWidget(self.guide_text)
        
        layout.addWidget(guide_group)
        
        return widget
    
    def create_scripts_tab(self) -> QWidget:
        """Create the bypass scripts tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Script generation controls
        controls_layout = QHBoxLayout()
        
        controls_layout.addWidget(QLabel("Script Type:"))
        
        self.script_type_combo = QComboBox()
        self.script_type_combo.addItems(["Frida", "Python", "WinDbg"])
        controls_layout.addWidget(self.script_type_combo)
        
        self.generate_script_button = QPushButton("Generate Script")
        self.generate_script_button.clicked.connect(self.generate_bypass_script)
        self.generate_script_button.setEnabled(False)
        controls_layout.addWidget(self.generate_script_button)
        
        controls_layout.addStretch()
        
        self.save_script_button = QPushButton("Save Script")
        self.save_script_button.clicked.connect(self.save_script)
        self.save_script_button.setEnabled(False)
        controls_layout.addWidget(self.save_script_button)
        
        layout.addLayout(controls_layout)
        
        # Script content
        self.script_text = QTextEdit()
        self.script_text.setReadOnly(True)
        self.script_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.script_text)
        
        # Usage instructions
        instructions_group = QGroupBox("Usage Instructions")
        instructions_layout = QVBoxLayout(instructions_group)
        
        self.instructions_text = QTextEdit()
        self.instructions_text.setReadOnly(True)
        self.instructions_text.setMaximumHeight(100)
        instructions_layout.addWidget(self.instructions_text)
        
        layout.addWidget(instructions_group)
        
        return widget
    
    def create_raw_results_tab(self) -> QWidget:
        """Create the raw results tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.raw_results_text = QTextEdit()
        self.raw_results_text.setReadOnly(True)
        self.raw_results_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.raw_results_text)
        
        return widget
    
    def setup_connections(self):
        """Set up signal connections."""
        # Enable/disable controls based on selection
        self.file_path_edit.textChanged.connect(self.update_controls)
        self.pid_spinbox.valueChanged.connect(self.update_controls)
        
        # Update static analysis availability
        self.file_path_edit.textChanged.connect(self.update_static_analysis_availability)
    
    def update_controls(self):
        """Update control states based on user input."""
        has_file = bool(self.file_path_edit.text().strip())
        has_pid = self.pid_spinbox.value() > 0
        
        can_start = has_file or has_pid
        self.start_button.setEnabled(can_start and not self.is_analysis_running())
    
    def update_static_analysis_availability(self):
        """Update static analysis checkbox availability."""
        has_file = bool(self.file_path_edit.text().strip())
        self.static_analysis_cb.setEnabled(has_file)
        if not has_file:
            self.static_analysis_cb.setChecked(False)
    
    def is_analysis_running(self) -> bool:
        """Check if analysis is currently running."""
        return self.analysis_worker is not None and self.analysis_worker.isRunning()
    
    def browse_file(self):
        """Browse for binary file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "Executable Files (*.exe *.dll *.sys);;All Files (*.*)"
        )
        
        if file_path:
            self.file_path_edit.setText(file_path)
    
    def start_analysis(self):
        """Start the anti-debugging analysis."""
        try:
            # Get analysis options
            analysis_options = self.get_analysis_options()
            
            # Determine analysis target
            file_path = self.file_path_edit.text().strip()
            pid = self.pid_spinbox.value()
            
            if file_path and os.path.exists(file_path):
                # File analysis
                self.start_file_analysis(file_path, analysis_options)
            elif pid > 0:
                # Live process analysis
                self.start_live_analysis(pid, analysis_options)
            else:
                QMessageBox.warning(self, "Invalid Target", 
                                  "Please select a valid binary file or enter a process ID.")
                return
                
        except Exception as e:
            self.logger.error(f"Failed to start analysis: {e}")
            QMessageBox.critical(self, "Analysis Error", f"Failed to start analysis: {e}")
    
    def start_file_analysis(self, file_path: str, analysis_options: Dict[str, Any]):
        """Start file-based analysis."""
        self.analysis_worker = AntiDebugAnalysisWorker(file_path, analysis_options)
        
        # Connect worker signals
        self.analysis_worker.progress_updated.connect(self.update_progress)
        self.analysis_worker.status_updated.connect(self.update_status)
        self.analysis_worker.analysis_completed.connect(self.analysis_completed)
        self.analysis_worker.error_occurred.connect(self.analysis_error)
        
        # Update UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Start analysis
        self.analysis_worker.start()
        self.logger.info(f"Started file analysis: {file_path}")
    
    def start_live_analysis(self, pid: int, analysis_options: Dict[str, Any]):
        """Start live process analysis."""
        try:
            # Use the engine directly for live analysis
            self.update_status("Starting live process analysis...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(50)
            
            results = self.engine.analyze_live_process(pid, analysis_options)
            
            self.progress_bar.setValue(100)
            
            if results.get('success', True):
                self.analysis_completed(results)
            else:
                self.analysis_error(results.get('error', 'Unknown error'))
                
        except Exception as e:
            self.analysis_error(str(e))
    
    def stop_analysis(self):
        """Stop the running analysis."""
        if self.analysis_worker and self.analysis_worker.isRunning():
            self.analysis_worker.terminate()
            self.analysis_worker.wait(3000)  # Wait up to 3 seconds
            
            self.update_status("Analysis stopped by user")
            self.progress_bar.setVisible(False)
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
    
    def get_analysis_options(self) -> Dict[str, Any]:
        """Get analysis options from UI."""
        return {
            'enable_static_analysis': self.static_analysis_cb.isChecked(),
            'enable_dynamic_analysis': self.dynamic_analysis_cb.isChecked(),
            'aggressive_detection': self.aggressive_mode_cb.isChecked(),
            'deep_scan': self.deep_scan_cb.isChecked(),
            'cache_results': self.cache_results_cb.isChecked(),
            'timeout_seconds': self.timeout_spinbox.value()
        }
    
    def update_progress(self, value: int):
        """Update progress bar."""
        self.progress_bar.setValue(value)
    
    def update_status(self, status: str):
        """Update status label."""
        self.status_label.setText(status)
    
    def analysis_completed(self, results: Dict[str, Any]):
        """Handle completed analysis."""
        try:
            self.current_results = results
            
            # Update UI
            self.progress_bar.setVisible(False)
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.export_button.setEnabled(True)
            self.generate_script_button.setEnabled(True)
            
            # Populate results
            self.populate_overview_tab(results)
            self.populate_techniques_tab(results)
            self.populate_bypass_tab(results)
            self.populate_raw_results_tab(results)
            
            self.update_status("Analysis completed successfully")
            self.logger.info("Analysis completed and results populated")
            
        except Exception as e:
            self.logger.error(f"Failed to process results: {e}")
            self.analysis_error(f"Failed to process results: {e}")
    
    def analysis_error(self, error: str):
        """Handle analysis error."""
        self.progress_bar.setVisible(False)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        self.update_status(f"Analysis failed: {error}")
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed:\n{error}")
    
    def populate_overview_tab(self, results: Dict[str, Any]):
        """Populate the overview tab with results."""
        summary = results.get('detection_summary', {})
        
        # Update summary labels
        self.total_techniques_label.setText(str(summary.get('total_techniques_detected', 0)))
        self.protection_score_label.setText(f"{summary.get('overall_protection_score', 0.0):.1f}")
        self.difficulty_label.setText(summary.get('bypass_difficulty', 'Unknown').title())
        self.highest_severity_label.setText(summary.get('highest_severity_found', 'None').title())
        
        # Populate categories tree
        self.categories_tree.clear()
        
        categories = results.get('technique_categories', {})
        for category_name, category_data in categories.items():
            item = QTreeWidgetItem(self.categories_tree)
            item.setText(0, category_name.replace('_', ' ').title())
            item.setText(1, str(len(category_data.get('detected', []))))
            item.setText(2, f"{category_data.get('total_score', 0.0):.1f}")
            
            # Add detected techniques as children
            for technique in category_data.get('detected', []):
                child = QTreeWidgetItem(item)
                child.setText(0, technique.get('name', 'Unknown'))
                child.setText(1, "-")
                child.setText(2, f"{technique.get('confidence', 0.0):.2f}")
        
        self.categories_tree.expandAll()
        
        # Update recommendations
        recommendations = summary.get('recommended_actions', [])
        self.recommendations_text.clear()
        for i, rec in enumerate(recommendations, 1):
            self.recommendations_text.append(f"{i}. {rec}")
    
    def populate_techniques_tab(self, results: Dict[str, Any]):
        """Populate the techniques tab with detected techniques."""
        self.techniques_table.setRowCount(0)
        
        categories = results.get('technique_categories', {})
        row = 0
        
        for category_data in categories.values():
            for technique in category_data.get('detected', []):
                self.techniques_table.insertRow(row)
                
                self.techniques_table.setItem(row, 0, QTableWidgetItem(
                    technique.get('name', 'Unknown')
                ))
                self.techniques_table.setItem(row, 1, QTableWidgetItem(
                    technique.get('category', 'Unknown').replace('_', ' ').title()
                ))
                self.techniques_table.setItem(row, 2, QTableWidgetItem(
                    technique.get('severity', 'Unknown').title()
                ))
                self.techniques_table.setItem(row, 3, QTableWidgetItem(
                    f"{technique.get('confidence', 0.0):.2f}"
                ))
                self.techniques_table.setItem(row, 4, QTableWidgetItem(
                    technique.get('description', 'No description available')
                ))
                
                row += 1
    
    def populate_bypass_tab(self, results: Dict[str, Any]):
        """Populate the bypass recommendations tab."""
        # Strategy
        summary = results.get('detection_summary', {})
        difficulty = summary.get('bypass_difficulty', 'unknown')
        
        strategy_text = f"Bypass Difficulty: {difficulty.title()}\n"
        strategy_text += f"Recommended Approach: Use comprehensive anti-anti-debug solution"
        
        self.strategy_text.setText(strategy_text)
        
        # Tools (simplified for now)
        self.tools_table.setRowCount(0)
        tools = [
            ("ScyllaHide", "Anti-Anti-Debug", "Comprehensive debugger hiding"),
            ("API Monitor", "API Hooking", "Monitor and modify API calls"),
            ("x64dbg", "Debugger", "Advanced debugger with plugin support")
        ]
        
        for i, (tool, category, purpose) in enumerate(tools):
            self.tools_table.insertRow(i)
            self.tools_table.setItem(i, 0, QTableWidgetItem(tool))
            self.tools_table.setItem(i, 1, QTableWidgetItem(category))
            self.tools_table.setItem(i, 2, QTableWidgetItem(purpose))
        
        # Guide
        guide_text = "1. Install anti-anti-debug tools (ScyllaHide)\n"
        guide_text += "2. Configure debugger with hiding plugins\n"
        guide_text += "3. Hook critical APIs as needed\n"
        guide_text += "4. Use timing attack countermeasures if required"
        
        self.guide_text.setText(guide_text)
    
    def populate_raw_results_tab(self, results: Dict[str, Any]):
        """Populate the raw results tab."""
        formatted_results = json.dumps(results, indent=2)
        self.raw_results_text.setText(formatted_results)
    
    def generate_bypass_script(self):
        """Generate bypass script based on analysis results."""
        if not self.current_results:
            QMessageBox.warning(self, "No Results", "No analysis results available for script generation.")
            return
        
        try:
            script_type = self.script_type_combo.currentText().lower()
            
            script_results = self.engine.generate_bypass_scripts(
                self.current_results, 
                script_type
            )
            
            if script_results.get('success', False):
                scripts = script_results.get('scripts', {})
                instructions = script_results.get('usage_instructions', [])
                
                # Display main script
                if 'comprehensive_bypass' in scripts:
                    self.script_text.setText(scripts['comprehensive_bypass'])
                elif scripts:
                    # Use first available script
                    first_script = next(iter(scripts.values()))
                    self.script_text.setText(first_script)
                else:
                    self.script_text.setText("No script generated")
                
                # Display instructions
                self.instructions_text.setText('\n'.join(instructions))
                
                self.save_script_button.setEnabled(True)
                
            else:
                error = script_results.get('error', 'Unknown error')
                QMessageBox.warning(self, "Script Generation Failed", f"Failed to generate script: {error}")
                
        except Exception as e:
            self.logger.error(f"Script generation failed: {e}")
            QMessageBox.critical(self, "Script Generation Error", f"Script generation failed: {e}")
    
    def save_script(self):
        """Save the generated script to file."""
        script_content = self.script_text.toPlainText()
        
        if not script_content.strip():
            QMessageBox.warning(self, "No Script", "No script content to save.")
            return
        
        script_type = self.script_type_combo.currentText().lower()
        
        # Determine file extension
        extensions = {
            'frida': '.js',
            'python': '.py',
            'windbg': '.wds'
        }
        
        ext = extensions.get(script_type, '.txt')
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Bypass Script",
            f"anti_debug_bypass{ext}",
            f"Script Files (*{ext});;All Files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(script_content)
                
                QMessageBox.information(self, "Script Saved", f"Script saved to: {file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save script: {e}")
    
    def export_results(self):
        """Export analysis results to file."""
        if not self.current_results:
            QMessageBox.warning(self, "No Results", "No analysis results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Results",
            "anti_debug_analysis_results.json",
            "JSON Files (*.json);;All Files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.current_results, f, indent=2)
                
                QMessageBox.information(self, "Results Exported", f"Results exported to: {file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {e}")
    
    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.is_analysis_running():
            reply = QMessageBox.question(
                self, 
                "Analysis Running", 
                "Analysis is still running. Stop it and close?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_analysis()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()