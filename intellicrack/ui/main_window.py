"""
Main Application Window 

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


import os
from typing import Any, Dict, List, Optional

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (
    QAction,
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

# Local imports
from ..config import CONFIG
from ..core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
from ..core.analysis.vulnerability_engine import AdvancedVulnerabilityEngine
from ..utils.logger import get_logger

# Configure module logger
logger = get_logger(__name__)


class IntellicrackMainWindow(QMainWindow):
    """
    Main application window for Intellicrack - a comprehensive reverse engineering 
    and security analysis framework.

    This class provides the primary user interface with multiple tabs for different
    analysis capabilities including binary analysis, vulnerability detection,
    memory forensics, network monitoring, and report generation.
    """

    # PyQt signals for thread-safe communication
    update_output = pyqtSignal(str)
    update_status = pyqtSignal(str)
    update_progress = pyqtSignal(int)
    clear_output = pyqtSignal()

    def __init__(self):
        """Initialize the main Intellicrack application window."""
        super().__init__()

        # Initialize logger
        self.logger = logger
        self.logger.info("Initializing main application window")

        # Initialize core attributes
        self.binary_path: Optional[str] = None
        self.analyze_results: List[str] = []
        self.binary_info: Optional[Dict[str, Any]] = None

        # Initialize analyzers
        self.vulnerability_engine = AdvancedVulnerabilityEngine()
        self.binary_analyzer = MultiFormatBinaryAnalyzer()

        # Setup UI
        self._setup_ui()
        self._setup_signals()
        self._setup_status_bar()
        self._setup_menu_bar()

        # Apply initial settings
        self._apply_initial_settings()

        self.logger.info("Main window initialization completed")

    def _setup_ui(self):
        """Setup the main user interface."""
        self.setWindowTitle("Intellicrack - Advanced Binary Analysis Framework")
        self.setGeometry(100, 100, 1400, 900)

        # Central widget with tab system

        # Initialize UI attributes
        self.analysis_output = None
        self.auto_save_results_cb = None
        self.clear_results_button = None
        self.entropy_analysis_cb = None
        self.export_analysis_cb = None
        self.export_results_button = None
        self.import_analysis_cb = None
        self.info_display = None
        self.results_display = None
        self.verbose_logging_cb = None
        self.vulnerability_scan_cb = None
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Setup individual tabs
        self._setup_dashboard_tab()
        self._setup_analysis_tab()
        self._setup_results_tab()
        self._setup_settings_tab()

    def _setup_dashboard_tab(self):
        """Setup the main dashboard tab."""
        dashboard_widget = QWidget()
        layout = QVBoxLayout(dashboard_widget)

        # File selection section
        file_group = QGroupBox("Binary File Selection")
        file_layout = QHBoxLayout(file_group)

        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("font-weight: bold; color: #333;")

        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self._browse_for_file)

        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_path_label, 1)
        file_layout.addWidget(self.browse_button)

        layout.addWidget(file_group)

        # Quick actions section
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QVBoxLayout(actions_group)

        # Action buttons
        button_layout = QHBoxLayout()

        self.analyze_button = QPushButton("Analyze Binary")
        self.analyze_button.clicked.connect(self._run_analysis)
        self.analyze_button.setEnabled(False)

        self.scan_vulnerabilities_button = QPushButton("Scan Vulnerabilities")
        self.scan_vulnerabilities_button.clicked.connect(self._scan_vulnerabilities)
        self.scan_vulnerabilities_button.setEnabled(False)

        self.generate_report_button = QPushButton("Generate Report")
        self.generate_report_button.clicked.connect(self._generate_report)
        self.generate_report_button.setEnabled(False)

        button_layout.addWidget(self.analyze_button)
        button_layout.addWidget(self.scan_vulnerabilities_button)
        button_layout.addWidget(self.generate_report_button)

        actions_layout.addLayout(button_layout)
        layout.addWidget(actions_group)

        # Information display
        info_group = QGroupBox("Binary Information")
        info_layout = QVBoxLayout(info_group)

        self.info_display = QTextEdit()
        self.info_display.setReadOnly(True)
        self.info_display.setMaximumHeight(200)
        info_layout.addWidget(self.info_display)

        layout.addWidget(info_group)
        layout.addStretch()

        self.tab_widget.addTab(dashboard_widget, "Dashboard")

    def _setup_analysis_tab(self):
        """Setup the analysis tab."""
        analysis_widget = QWidget()
        layout = QVBoxLayout(analysis_widget)

        # Analysis options
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout(options_group)

        self.vulnerability_scan_cb = QCheckBox("Vulnerability Scanning")
        self.vulnerability_scan_cb.setChecked(True)

        self.entropy_analysis_cb = QCheckBox("Entropy Analysis")
        self.entropy_analysis_cb.setChecked(True)

        self.import_analysis_cb = QCheckBox("Import Table Analysis")
        self.import_analysis_cb.setChecked(True)

        self.export_analysis_cb = QCheckBox("Export Table Analysis")
        self.export_analysis_cb.setChecked(False)

        options_layout.addWidget(self.vulnerability_scan_cb)
        options_layout.addWidget(self.entropy_analysis_cb)
        options_layout.addWidget(self.import_analysis_cb)
        options_layout.addWidget(self.export_analysis_cb)

        layout.addWidget(options_group)

        # Analysis output
        output_group = QGroupBox("Analysis Output")
        output_layout = QVBoxLayout(output_group)

        self.analysis_output = QTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setFont(QFont("Consolas", 9))
        output_layout.addWidget(self.analysis_output)

        layout.addWidget(output_group)

        self.tab_widget.addTab(analysis_widget, "Analysis")

    def _setup_results_tab(self):
        """Setup the results tab."""
        results_widget = QWidget()
        layout = QVBoxLayout(results_widget)

        # Results display
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        self.results_display.setFont(QFont("Consolas", 9))
        layout.addWidget(self.results_display)

        # Action buttons
        button_layout = QHBoxLayout()

        self.clear_results_button = QPushButton("Clear Results")
        self.clear_results_button.clicked.connect(self._clear_results)

        self.export_results_button = QPushButton("Export Results")
        self.export_results_button.clicked.connect(self._export_results)

        button_layout.addWidget(self.clear_results_button)
        button_layout.addWidget(self.export_results_button)
        button_layout.addStretch()

        layout.addLayout(button_layout)

        self.tab_widget.addTab(results_widget, "Results")

    def _setup_settings_tab(self):
        """Setup the settings tab."""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)

        # Analysis settings
        analysis_group = QGroupBox("Analysis Settings")
        analysis_layout = QVBoxLayout(analysis_group)

        self.verbose_logging_cb = QCheckBox("Verbose Logging")
        self.verbose_logging_cb.setChecked(CONFIG.get("verbose_logging", False))

        self.auto_save_results_cb = QCheckBox("Auto-save Results")
        self.auto_save_results_cb.setChecked(CONFIG.get("auto_save_results", True))

        analysis_layout.addWidget(self.verbose_logging_cb)
        analysis_layout.addWidget(self.auto_save_results_cb)

        layout.addWidget(analysis_group)
        layout.addStretch()

        self.tab_widget.addTab(settings_widget, "Settings")

    def _setup_signals(self):
        """Setup signal connections."""
        self.update_output.connect(self._on_update_output)
        self.update_status.connect(self._on_update_status)
        self.update_progress.connect(self._on_update_progress)
        self.clear_output.connect(self._on_clear_output)

    def _setup_status_bar(self):
        """Setup the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready")
        self.status_bar.showMessage("Intellicrack initialized successfully")

    def _setup_menu_bar(self):
        """Setup the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu('File')

        open_action = QAction('Open Binary...', self)
        open_action.setShortcut('Ctrl+O')
        open_action.triggered.connect(self._browse_for_file)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Analysis menu
        analysis_menu = menubar.addMenu('Analysis')

        analyze_action = QAction('Analyze Binary', self)
        analyze_action.setShortcut('F5')
        analyze_action.triggered.connect(self._run_analysis)
        analysis_menu.addAction(analyze_action)

        vulnerability_action = QAction('Scan Vulnerabilities', self)
        vulnerability_action.setShortcut('F6')
        vulnerability_action.triggered.connect(self._scan_vulnerabilities)
        analysis_menu.addAction(vulnerability_action)

    def _apply_initial_settings(self):
        """Apply initial application settings."""
        # Set window icon if available
        icon_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'icon.png')
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

    # Slot methods for signal handling
    def _on_update_output(self, message: str):
        """Handle output updates."""
        self.analysis_output.append(message)
        self.analysis_output.ensureCursorVisible()

    def _on_update_status(self, message: str):
        """Handle status updates."""
        self.status_bar.showMessage(message)

    def _on_update_progress(self, value: int):
        """Handle progress updates."""
        self.progress_bar.setVisible(value > 0)
        self.progress_bar.setValue(value)
        if value >= 100:
            self.progress_bar.setVisible(False)

    def _on_clear_output(self):
        """Handle clear output requests."""
        self.analysis_output.clear()
        self.results_display.clear()

    # Action methods
    def _browse_for_file(self):
        """Browse for a binary file to analyze."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary File",
            "",
            "All Files (*)"
        )

        if file_path:
            self.binary_path = file_path
            self.file_path_label.setText(os.path.basename(file_path))
            self.file_path_label.setToolTip(file_path)

            # Enable analysis buttons
            self.analyze_button.setEnabled(True)
            self.scan_vulnerabilities_button.setEnabled(True)

            self.update_status.emit(f"Selected: {os.path.basename(file_path)}")
            self.logger.info("Selected binary file: %s", file_path)

    def _run_analysis(self):
        """Run binary analysis."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please select a binary file first.")
            return

        self.update_status.emit("Running binary analysis...")
        self.update_progress.emit(10)

        try:
            # Run multi-format analysis
            self.update_output.emit("=== BINARY ANALYSIS ===")
            self.update_output.emit(f"Analyzing: {self.binary_path}")

            # Identify format
            binary_format = self.binary_analyzer.identify_format(self.binary_path)
            self.update_output.emit(f"Detected format: {binary_format}")

            self.update_progress.emit(50)

            # Run analysis
            analysis_results = self.binary_analyzer.analyze_binary(self.binary_path)

            if 'error' in analysis_results:
                self.update_output.emit(f"Error: {analysis_results['error']}")
            else:
                self._display_analysis_results(analysis_results)
                self.generate_report_button.setEnabled(True)

            self.update_progress.emit(100)
            self.update_status.emit("Analysis completed")

        except (OSError, ValueError, RuntimeError) as e:
            self.update_output.emit(f"Analysis error: {str(e)}")
            self.update_status.emit("Analysis failed")
            self.logger.error(f"Analysis error: {str(e)}")

    def _scan_vulnerabilities(self):
        """Run vulnerability scanning."""
        if not self.binary_path:
            QMessageBox.warning(self, "Warning", "Please select a binary file first.")
            return

        self.update_status.emit("Scanning for vulnerabilities...")
        self.update_progress.emit(10)

        try:
            self.update_output.emit("=== VULNERABILITY SCAN ===")
            self.update_output.emit(f"Scanning: {self.binary_path}")

            self.update_progress.emit(30)

            # Run vulnerability scan
            vulnerabilities = self.vulnerability_engine.scan_binary(self.binary_path)

            self.update_progress.emit(80)

            if vulnerabilities:
                self.update_output.emit(f"Found {len(vulnerabilities)} vulnerabilities:")
                for _vuln in vulnerabilities:
                    self.update_output.emit(f"  - {_vuln.get('type', 'Unknown')}: {_vuln.get('risk', 'Unknown risk')}")
            else:
                self.update_output.emit("No vulnerabilities detected.")

            self.update_progress.emit(100)
            self.update_status.emit("Vulnerability scan completed")

        except (OSError, ValueError, RuntimeError) as e:
            self.update_output.emit(f"Vulnerability scan error: {str(e)}")
            self.update_status.emit("Vulnerability scan failed")
            self.logger.error(f"Vulnerability scan error: {str(e)}")

    def _generate_report(self):
        """Generate analysis report."""
        self.update_status.emit("Generating report...")
        self.update_output.emit("=== REPORT GENERATION ===")
        self.update_output.emit("Report generation not yet implemented in this refactored version.")
        self.update_status.emit("Ready")

    def _display_analysis_results(self, results: Dict[str, Any]):
        """Display analysis results in the results tab."""
        self.results_display.clear()

        # Format results for display
        result_text = "=== ANALYSIS RESULTS ===\\n"
        result_text += f"Format: {results.get('format', 'Unknown')}\\n"

        if 'machine' in results:
            result_text += f"Machine: {results['machine']}\\n"

        if 'timestamp' in results:
            result_text += f"Timestamp: {results['timestamp']}\\n"

        if 'sections' in results:
            result_text += f"\\nSections ({len(results['sections'])}):\\n"
            for _section in results['sections'][:10]:  # Limit to first 10
                result_text += f"  {_section.get('name', 'Unknown')}: {_section.get('virtual_size', 'N/A')} bytes\\n"

        if 'imports' in results:
            result_text += f"\\nImports ({len(results['imports'])}):\\n"
            for _imp in results['imports'][:5]:  # Limit to first 5
                result_text += f"  {_imp.get('dll', 'Unknown')}: {len(_imp.get('functions', []))} functions\\n"

        self.results_display.setPlainText(result_text)

        # Switch to results tab
        self.tab_widget.setCurrentIndex(2)

    def _clear_results(self):
        """Clear all results."""
        self.results_display.clear()
        self.analysis_output.clear()
        self.analyze_results.clear()
        self.update_status.emit("Results cleared")

    def _export_results(self):
        """Export results to file."""
        if not self.results_display.toPlainText():
            QMessageBox.information(self, "Information", "No results to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "analysis_results.txt",
            "Text Files (*.txt);;All Files (*)"
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.results_display.toPlainText())

                QMessageBox.information(self, "Success", f"Results exported to {file_path}")
                self.update_status.emit(f"Results exported to {os.path.basename(file_path)}")

            except (OSError, ValueError, RuntimeError) as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")
                self.logger.error(f"Export error: {str(e)}")


# Export the main window class
__all__ = ['IntellicrackMainWindow']
